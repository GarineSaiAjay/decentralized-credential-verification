//! Tests that run the real router against a real (throwaway) Postgres database, in-process.
//!
//! `#[sqlx::test]` creates an empty database per test and applies every migration, so these tests exercise the
//! SQL, the locking and the signature checks together. They need `DATABASE_URL` to point at a Postgres server
//! the user may create databases on (see the README, "Tests").
use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Method, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{auth, config::Config, keys, router, security::RateLimiter, AppState};

const PASSWORD: &str = "correct horse battery";

const ROLES: [(&str, &str); 5] = [
    ("faculty", "faculty"),
    ("examcell", "exam_cell"),
    ("registrar", "registrar"),
    ("admin", "university_admin"),
    ("auditor", "auditor"),
];

struct Api {
    app: Router,
    st: AppState,
}

struct Res {
    status: StatusCode,
    body: Value,
}

fn state(pool: PgPool) -> AppState {
    AppState {
        db: pool,
        cfg: Arc::new(Config::for_tests()),
        limiter: Arc::new(RateLimiter::default()),
        ts_lock: Arc::new(tokio::sync::Mutex::new(())),
        chain_cache: Arc::default(),
    }
}

/// Hashing is deliberately slow, so every test shares one hash of the test password.
fn password_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| auth::hash_password(PASSWORD).unwrap())
}

/// A started application: signing keys exist and one account per role (`faculty@t.test`, ...).
async fn start(pool: PgPool) -> Api {
    let st = state(pool);
    keys::ensure_initial_keys(&st).await.unwrap();
    for (name, role) in ROLES {
        sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)")
            .bind(Uuid::new_v4())
            .bind(format!("{name}@t.test"))
            .bind(password_hash())
            .bind(role)
            .execute(&st.db)
            .await
            .unwrap();
    }
    Api {
        app: router(st.clone()),
        st,
    }
}

impl Api {
    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Res {
        self.send_with(method, path, token, body, &Uuid::new_v4().to_string(), None)
            .await
    }

    async fn send_with(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        nonce: &str,
        timestamp: Option<i64>,
    ) -> Res {
        let mut req = Request::builder()
            .method(method.clone())
            .uri(format!("/api/v1{path}"))
            .header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if method == Method::POST {
            req = req.header("x-nonce", nonce).header(
                "x-timestamp",
                timestamp
                    .unwrap_or_else(|| chrono::Utc::now().timestamp())
                    .to_string(),
            );
        }
        let mut req = req
            .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "203.0.113.9:4000".parse::<SocketAddr>().unwrap(),
        ));
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        Res {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Res {
        self.send(Method::GET, path, token, None).await
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> Res {
        self.send(Method::POST, path, token, Some(body)).await
    }

    async fn login(&self, who: &str) -> String {
        let r = self
            .post(
                "/auth/login",
                None,
                json!({ "email": format!("{who}@t.test"), "password": PASSWORD }),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "login as {who}: {}", r.body);
        r.body["token"].as_str().unwrap().to_string()
    }

    /// Signs in as every role; returns the tokens in the order faculty, exam cell, registrar, admin, auditor.
    async fn everyone(&self) -> [String; 5] {
        [
            self.login("faculty").await,
            self.login("examcell").await,
            self.login("registrar").await,
            self.login("admin").await,
            self.login("auditor").await,
        ]
    }

    async fn create(&self, faculty: &str) -> String {
        let r = self.post("/credentials", Some(faculty), card()).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        r.body["id"].as_str().unwrap().to_string()
    }

    async fn verdict(&self, id: &str) -> String {
        let r = self.get(&format!("/verify/{id}"), None).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        r.body["verdict"].as_str().unwrap().to_string()
    }

    /// Takes a credential through every stage; returns its id.
    async fn issue(&self, t: &[String; 5]) -> String {
        let id = self.create(&t[0]).await;
        for token in &t[1..4] {
            let r = self
                .post(
                    &format!("/credentials/{id}/approve"),
                    Some(token),
                    json!({}),
                )
                .await;
            assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        }
        id
    }
}

/// Edits the database the way an attacker with direct access would. The append-only triggers refuse
/// ordinary edits (a test below checks that), so this switches them off for one connection.
async fn tamper(pool: &PgPool, sql: &str, id: Option<Uuid>) {
    let mut c = pool.acquire().await.unwrap();
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *c)
        .await
        .unwrap();
    let q = sqlx::query(sql);
    let q = if let Some(id) = id { q.bind(id) } else { q };
    q.execute(&mut *c).await.unwrap();
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *c)
        .await
        .unwrap();
}

fn card() -> Value {
    json!({
        "student_id": "STU-1", "student_name": "Ada Lovelace", "program": "BSc Mathematics",
        "graduation_date": "2025-05-15", "gpa": "3.9", "honors": "First class"
    })
}

// ---------------------------------------------------------------------------------------------------------
// The credential lifecycle
// ---------------------------------------------------------------------------------------------------------

#[sqlx::test]
async fn a_credential_goes_through_all_four_stages_and_verifies(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;

    let id = api.create(&t[0]).await;
    assert_eq!(api.verdict(&id).await, "PENDING");
    let mut expected = ["pending_registrar", "pending_university", "issued"].into_iter();
    for token in &t[1..4] {
        let r = api
            .post(
                &format!("/credentials/{id}/approve"),
                Some(token),
                json!({}),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["status"], expected.next().unwrap());
    }
    let v = api.get(&format!("/verify/{id}"), None).await.body;
    assert_eq!(v["verdict"], "VALID");
    assert_eq!(v["signatures"].as_array().unwrap().len(), 4);
    for check in ["hash_ok", "order_ok", "status_ok", "signatures_ok"] {
        assert_eq!(v["checks"][check], true, "{check}");
    }
    assert_eq!(v["credential"]["student_name"], "Ada Lovelace");
}

#[sqlx::test]
async fn only_the_role_whose_turn_it_is_can_approve(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.create(&t[0]).await;
    let path = format!("/credentials/{id}/approve");

    // Out of turn: registrar and admin before the exam cell; faculty and auditor never.
    for token in [&t[2], &t[3], &t[0], &t[4]] {
        let r = api.post(&path, Some(token), json!({})).await;
        assert!(
            r.status == StatusCode::CONFLICT || r.status == StatusCode::FORBIDDEN,
            "{}",
            r.status
        );
    }
    assert_eq!(api.verdict(&id).await, "PENDING");
    let status: (String,) = sqlx::query_as("SELECT status FROM credentials WHERE id = $1")
        .bind(Uuid::parse_str(&id).unwrap())
        .fetch_one(&api.st.db)
        .await
        .unwrap();
    assert_eq!(status.0, "pending_exam_cell", "nothing changed");

    // The right role works once; signing the same stage again is refused.
    assert_eq!(
        api.post(&path, Some(&t[1]), json!({})).await.status,
        StatusCode::OK
    );
    assert_eq!(
        api.post(&path, Some(&t[1]), json!({})).await.status,
        StatusCode::CONFLICT
    );
}

#[sqlx::test]
async fn who_may_do_what(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;

    // Only faculty create credentials.
    for token in &t[1..] {
        assert_eq!(
            api.post("/credentials", Some(token), card()).await.status,
            StatusCode::FORBIDDEN
        );
    }
    // Only administrators manage users, keys and the ledger.
    for token in [&t[0], &t[1], &t[2], &t[4]] {
        assert_eq!(
            api.get("/users", Some(token)).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            api.post("/ledger/seal", Some(token), json!({}))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            api.post("/keys/faculty/rotate", Some(token), json!({}))
                .await
                .status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(api.get("/users", Some(&t[3])).await.status, StatusCode::OK);
    // The audit log is for administrators and auditors only.
    assert_eq!(
        api.get("/audit", Some(&t[0])).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(api.get("/audit", Some(&t[4])).await.status, StatusCode::OK);
    // Signed-in routes need a token; verification and the chain check are public.
    assert_eq!(
        api.get("/credentials", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(api.get("/ledger/verify", None).await.status, StatusCode::OK);
    assert_eq!(
        api.get("/credentials", Some("not-a-token")).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn faculty_see_only_their_own_credentials(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,'other@t.test',$2,'faculty')")
        .bind(Uuid::new_v4())
        .bind(password_hash())
        .execute(&api.st.db)
        .await
        .unwrap();
    let other = api.login("other").await;

    let mine = api.create(&t[0]).await;
    assert_eq!(
        api.get(&format!("/credentials/{mine}"), Some(&other))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api.get(&format!("/credentials/{mine}"), Some(&t[0]))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        api.get("/credentials", Some(&other)).await.body["credentials"],
        json!([])
    );
    assert_eq!(
        api.get("/credentials", Some(&t[1])).await.body["credentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test]
async fn rejection_ends_the_credential_and_it_can_be_replaced(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.create(&t[0]).await;

    // A reason is required; faculty cannot reject.
    assert_eq!(
        api.post(
            &format!("/credentials/{id}/reject"),
            Some(&t[1]),
            json!({ "reason": "  " })
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api.post(
            &format!("/credentials/{id}/reject"),
            Some(&t[0]),
            json!({ "reason": "no" })
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let r = api
        .post(
            &format!("/credentials/{id}/reject"),
            Some(&t[1]),
            json!({ "reason": "grades missing" }),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(api.verdict(&id).await, "REJECTED");
    // Nobody can approve it any more.
    assert_eq!(
        api.post(
            &format!("/credentials/{id}/approve"),
            Some(&t[1]),
            json!({})
        )
        .await
        .status,
        StatusCode::CONFLICT
    );

    // Faculty re-issue it with a correction; the new one points back and starts again at stage two.
    let r = api
        .post(
            &format!("/credentials/{id}/reissue"),
            Some(&t[0]),
            json!({ "gpa": "3.8" }),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let new_id = r.body["id"].as_str().unwrap().to_string();
    let v = api.get(&format!("/verify/{new_id}"), None).await.body;
    assert_eq!(v["verdict"], "PENDING");
    assert_eq!(v["supersedes"], id.as_str());
    assert_eq!(
        v["credential"]["student_name"], "Ada Lovelace",
        "unchanged fields are copied"
    );
    assert_eq!(v["credential"]["gpa"], "3.8");
    assert_eq!(
        api.get(&format!("/verify/{id}"), None).await.body["superseded_by"]["id"],
        new_id.as_str()
    );
}

#[sqlx::test]
async fn a_valid_credential_cannot_be_reissued_until_it_is_revoked(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    assert_eq!(api.verdict(&id).await, "VALID");

    let reissue = format!("/credentials/{id}/reissue");
    assert_eq!(
        api.post(&reissue, Some(&t[0]), json!({})).await.status,
        StatusCode::CONFLICT
    );

    // Only an administrator revokes, with a reason, and only an issued credential.
    let revoke = format!("/credentials/{id}/revoke");
    assert_eq!(
        api.post(&revoke, Some(&t[2]), json!({ "reason": "x" }))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.post(&revoke, Some(&t[3]), json!({ "reason": "" }))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api.post(&revoke, Some(&t[3]), json!({ "reason": "issued in error" }))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        api.post(&revoke, Some(&t[3]), json!({ "reason": "again" }))
            .await
            .status,
        StatusCode::CONFLICT
    );

    let v = api.get(&format!("/verify/{id}"), None).await.body;
    assert_eq!(v["verdict"], "REVOKED");
    assert_eq!(v["credential"]["revoke_reason"], "issued in error");
    assert_eq!(
        api.post(&reissue, Some(&t[0]), json!({})).await.status,
        StatusCode::CREATED
    );
}

#[sqlx::test]
async fn editing_the_database_by_hand_is_detected(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    let uuid = Uuid::parse_str(&id).unwrap();
    assert_eq!(api.verdict(&id).await, "VALID");

    // Changing a signed field breaks the content hash.
    tamper(
        &api.st.db,
        "UPDATE credentials SET student_name = 'Mallory' WHERE id = $1",
        Some(uuid),
    )
    .await;
    let v = api.get(&format!("/verify/{id}"), None).await.body;
    assert_eq!(v["verdict"], "INVALID");
    assert_eq!(v["checks"]["hash_ok"], false);
    tamper(
        &api.st.db,
        "UPDATE credentials SET student_name = 'Ada Lovelace' WHERE id = $1",
        Some(uuid),
    )
    .await;
    assert_eq!(api.verdict(&id).await, "VALID");

    // Marking it revoked without a signed event is not enough.
    tamper(
        &api.st.db,
        "UPDATE credentials SET status = 'revoked' WHERE id = $1",
        Some(uuid),
    )
    .await;
    assert_eq!(api.verdict(&id).await, "INVALID");
    tamper(
        &api.st.db,
        "UPDATE credentials SET status = 'issued' WHERE id = $1",
        Some(uuid),
    )
    .await;

    // Dropping an approval leaves fewer signatures than the status needs.
    tamper(
        &api.st.db,
        "DELETE FROM approvals WHERE credential_id = $1 AND role = 'registrar'",
        Some(uuid),
    )
    .await;
    assert_eq!(api.verdict(&id).await, "INVALID");
}

#[sqlx::test]
async fn the_database_itself_refuses_to_rewrite_history(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = Uuid::parse_str(&api.issue(&t).await).unwrap();
    api.post(
        &format!("/credentials/{id}/revoke"),
        Some(&t[3]),
        json!({ "reason": "x" }),
    )
    .await;
    api.issue(&t).await;
    api.post("/ledger/seal", Some(&t[3]), json!({})).await;
    for sql in [
        "UPDATE credentials SET status = 'issued' WHERE id = $1",
        "UPDATE approvals SET signature = repeat('0', 128) WHERE credential_id = $1",
        "DELETE FROM approvals WHERE credential_id = $1",
        "UPDATE credential_events SET reason = 'edited' WHERE credential_id = $1",
        "DELETE FROM blocks WHERE height >= 1 AND $1 IS NOT NULL",
        "UPDATE audit_logs SET action = 'x' WHERE $1 IS NOT NULL",
    ] {
        let r = sqlx::query(sql).bind(id).execute(&api.st.db).await;
        assert!(r.is_err(), "should be refused: {sql}");
    }
}

#[sqlx::test]
async fn swapping_an_anchored_credential_breaks_the_chain(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = Uuid::parse_str(&api.issue(&t).await).unwrap();
    api.post("/ledger/seal", Some(&t[3]), json!({})).await;
    assert_eq!(api.get("/ledger/verify", None).await.body["ok"], true);
    tamper(
        &api.st.db,
        "UPDATE credentials SET credential_hash = repeat('a', 64) WHERE id = $1",
        Some(id),
    )
    .await;
    let chain = api.get("/ledger/verify", None).await.body;
    assert_eq!(chain["ok"], false);
    assert_eq!(chain["blocks"][0]["leaves_match_credentials"], false);
}

#[sqlx::test]
async fn input_is_validated(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let mut bad = vec![];
    for (field, value) in [
        ("student_name", json!("")),
        ("student_name", json!("x".repeat(500))),
        ("program", json!("   ")),
        ("graduation_date", json!("15/05/2025")),
        ("graduation_date", json!("2025-02-30")),
    ] {
        let mut c = card();
        c[field] = value.clone();
        let r = api.post("/credentials", Some(&t[0]), c).await;
        if r.status != StatusCode::BAD_REQUEST {
            bad.push(format!("{field}={value} gave {}", r.status));
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
    let r = api
        .post("/credentials", Some(&t[0]), json!({ "student_id": "x" }))
        .await;
    assert!(r.status.is_client_error());
    assert_eq!(
        api.get("/verify/not-a-uuid", None).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api.get(&format!("/verify/{}", Uuid::new_v4()), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------------------------------------

#[sqlx::test]
async fn sealing_anchors_issued_credentials_in_a_chain_that_verifies(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;

    assert_eq!(
        api.post("/ledger/seal", Some(&t[3]), json!({}))
            .await
            .status,
        StatusCode::CONFLICT,
        "nothing to seal yet"
    );
    let a = api.issue(&t).await;
    let b = api.issue(&t).await;
    let r = api.post("/ledger/seal", Some(&t[3]), json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        (r.body["height"].as_i64(), r.body["credentials"].as_i64()),
        (Some(1), Some(2))
    );

    let c = api.issue(&t).await;
    assert_eq!(
        api.post("/ledger/seal", Some(&t[3]), json!({})).await.body["height"],
        2
    );

    for id in [&a, &b, &c] {
        let v = api.get(&format!("/verify/{id}"), None).await.body;
        assert_eq!(v["verdict"], "VALID");
        assert!(v["anchor"]["ok"].as_bool().unwrap(), "{}", v["anchor"]);
    }
    let chain = api.get("/ledger/verify", None).await.body;
    assert_eq!(
        (chain["ok"].clone(), chain["length"].clone()),
        (json!(true), json!(2))
    );

    // Rewriting history is caught: change a leaf of block 1.
    tamper(
        &api.st.db,
        "UPDATE blocks SET merkle_root = repeat('0', 64) WHERE height = 1",
        None,
    )
    .await;
    assert_eq!(api.get("/ledger/verify", None).await.body["ok"], false);
}

// ---------------------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------------------

#[sqlx::test]
async fn rotating_a_key_keeps_old_credentials_valid(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let old = api.issue(&t).await;

    for role in ["faculty", "exam_cell", "registrar", "university"] {
        let r = api
            .post(&format!("/keys/{role}/rotate"), Some(&t[3]), json!({}))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{role}: {}", r.body);
    }
    assert_eq!(
        api.post("/keys/nonsense/rotate", Some(&t[3]), json!({}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api.verdict(&old).await,
        "VALID",
        "signed by retired keys, still trusted"
    );
    let new = api.issue(&t).await;
    assert_eq!(api.verdict(&new).await, "VALID");

    let (active, retired): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'active'), count(*) FILTER (WHERE status = 'retired') FROM signing_keys",
    )
    .fetch_one(&api.st.db)
    .await
    .unwrap();
    assert_eq!((active, retired), (4, 4));
}

#[sqlx::test]
async fn a_revoked_key_no_longer_vouches_for_its_signatures(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    let (key,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM signing_keys WHERE role = 'registrar' AND status = 'active'",
    )
    .fetch_one(&api.st.db)
    .await
    .unwrap();
    let r = api
        .post(
            &format!("/keys/{key}/revoke"),
            Some(&t[3]),
            json!({ "reason": "key was leaked" }),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(api.verdict(&id).await, "INVALID");
}

// ---------------------------------------------------------------------------------------------------------
// Accounts and sessions
// ---------------------------------------------------------------------------------------------------------

#[sqlx::test]
async fn sign_in_sign_out_and_failure_messages(pool: PgPool) {
    let api = start(pool).await;
    let token = api.login("faculty").await;
    let me = api.get("/auth/me", Some(&token)).await;
    assert_eq!(
        (me.status, me.body["role"].clone()),
        (StatusCode::OK, json!("faculty"))
    );

    // A wrong password and an unknown account look the same.
    let wrong = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "faculty@t.test", "password": "nope nope nope" }),
        )
        .await;
    let unknown = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "nobody@t.test", "password": "nope nope nope" }),
        )
        .await;
    assert_eq!(
        (wrong.status, unknown.status),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(wrong.body, unknown.body);

    // Signing out ends that token at once.
    assert_eq!(
        api.post("/auth/logout", Some(&token), json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        api.get("/auth/me", Some(&token)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test]
async fn too_many_wrong_passwords_lock_the_account_for_a_while(pool: PgPool) {
    let api = start(pool).await;
    let bad = json!({ "email": "faculty@t.test", "password": "wrong wrong wrong" });
    for _ in 0..5 {
        assert_eq!(
            api.post("/auth/login", None, bad.clone()).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    // The limit is per account, so even the right password waits, and the answer says how long.
    let r = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "faculty@t.test", "password": PASSWORD }),
        )
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Other accounts are unaffected.
    api.login("admin").await;
}

#[sqlx::test]
async fn a_deactivated_account_is_signed_out_and_cannot_return(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let (id,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = 'faculty@t.test'")
        .fetch_one(&api.st.db)
        .await
        .unwrap();
    let r = api
        .post(
            &format!("/users/{id}/active"),
            Some(&t[3]),
            json!({ "active": false }),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        api.get("/auth/me", Some(&t[0])).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "faculty@t.test", "password": PASSWORD }),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn administrators_cannot_lock_themselves_out_and_demotion_takes_effect(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id_of = |email: &'static str| {
        let db = api.st.db.clone();
        async move {
            let (id,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = $1")
                .bind(email)
                .fetch_one(&db)
                .await
                .unwrap();
            id
        }
    };
    let (faculty, admin) = (id_of("faculty@t.test").await, id_of("admin@t.test").await);

    // Nobody changes their own role or access.
    let own_role = api
        .post(
            &format!("/users/{admin}/role"),
            Some(&t[3]),
            json!({ "role": "auditor" }),
        )
        .await;
    assert_eq!(own_role.status, StatusCode::CONFLICT);
    let own_access = api
        .post(
            &format!("/users/{admin}/active"),
            Some(&t[3]),
            json!({ "active": false }),
        )
        .await;
    assert_eq!(own_access.status, StatusCode::CONFLICT);
    // An unknown role is refused.
    let bad = api
        .post(
            &format!("/users/{faculty}/role"),
            Some(&t[3]),
            json!({ "role": "emperor" }),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // Promote faculty; they can then demote the original administrator, who loses the rights at once.
    let up = api
        .post(
            &format!("/users/{faculty}/role"),
            Some(&t[3]),
            json!({ "role": "university_admin" }),
        )
        .await;
    assert_eq!(up.status, StatusCode::OK);
    let second = api.login("faculty").await;
    assert_eq!(
        api.get("/users", Some(&second)).await.status,
        StatusCode::OK
    );
    let down = api
        .post(
            &format!("/users/{admin}/role"),
            Some(&second),
            json!({ "role": "auditor" }),
        )
        .await;
    assert_eq!(down.status, StatusCode::OK);
    assert_eq!(
        api.get("/users", Some(&t[3])).await.status,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test]
async fn changing_a_password_enforces_the_rules_and_ends_other_sessions(pool: PgPool) {
    let api = start(pool).await;
    let a = api.login("faculty").await;
    let b = api.login("faculty").await;
    let change =
        |current: &str, new: &str| json!({ "current_password": current, "new_password": new });

    for weak in ["short", "password1234", "aaaaaaaaaaaaaa", "faculty@t.test"] {
        assert_eq!(
            api.post("/auth/password", Some(&a), change(PASSWORD, weak))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "{weak}"
        );
    }
    assert_eq!(
        api.post(
            "/auth/password",
            Some(&a),
            change("not my password", "a fresh passphrase")
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        api.post("/auth/password", Some(&a), change(PASSWORD, PASSWORD))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        api.post(
            "/auth/password",
            Some(&a),
            change(PASSWORD, "a fresh passphrase")
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        api.get("/auth/me", Some(&a)).await.status,
        StatusCode::OK,
        "this session continues"
    );
    assert_eq!(
        api.get("/auth/me", Some(&b)).await.status,
        StatusCode::UNAUTHORIZED,
        "the other one ended"
    );
    let old = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "faculty@t.test", "password": PASSWORD }),
        )
        .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn a_reset_link_works_once(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let (id,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = 'faculty@t.test'")
        .fetch_one(&api.st.db)
        .await
        .unwrap();
    assert_eq!(
        api.post(&format!("/users/{id}/reset-link"), Some(&t[0]), json!({}))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let link = api
        .post(&format!("/users/{id}/reset-link"), Some(&t[3]), json!({}))
        .await;
    assert_eq!(link.status, StatusCode::OK, "{}", link.body);
    let token = link.body["token"].as_str().unwrap().to_string();
    let stored: (Vec<u8>,) =
        sqlx::query_as("SELECT token_hash FROM password_resets WHERE user_id = $1")
            .bind(id)
            .fetch_one(&api.st.db)
            .await
            .unwrap();
    assert!(
        stored.0 != token.as_bytes() && stored.0.len() == 32,
        "only a SHA-256 hash is stored"
    );

    let weak = api
        .post(
            "/auth/reset-password",
            None,
            json!({ "token": token, "new_password": "password1234" }),
        )
        .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
    let ok = api
        .post(
            "/auth/reset-password",
            None,
            json!({ "token": token, "new_password": "a brand new passphrase" }),
        )
        .await;
    assert_eq!(
        ok.status,
        StatusCode::OK,
        "a weak attempt does not burn the link: {}",
        ok.body
    );
    let again = api
        .post(
            "/auth/reset-password",
            None,
            json!({ "token": token, "new_password": "another new passphrase" }),
        )
        .await;
    assert!(again.status.is_client_error(), "second use refused");
    assert_eq!(
        api.get("/auth/me", Some(&t[0])).await.status,
        StatusCode::UNAUTHORIZED,
        "earlier sessions ended"
    );
    let login = api
        .post(
            "/auth/login",
            None,
            json!({ "email": "faculty@t.test", "password": "a brand new passphrase" }),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------------------
// Request protection
// ---------------------------------------------------------------------------------------------------------

#[sqlx::test]
async fn a_repeated_nonce_or_a_stale_timestamp_is_refused(pool: PgPool) {
    let api = start(pool).await;
    let token = api.login("faculty").await;
    let nonce = Uuid::new_v4().to_string();

    let first = api
        .send_with(
            Method::POST,
            "/credentials",
            Some(&token),
            Some(card()),
            &nonce,
            None,
        )
        .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let replay = api
        .send_with(
            Method::POST,
            "/credentials",
            Some(&token),
            Some(card()),
            &nonce,
            None,
        )
        .await;
    assert_eq!(replay.status, StatusCode::CONFLICT);

    let stale = chrono::Utc::now().timestamp() - 600;
    let old = api
        .send_with(
            Method::POST,
            "/credentials",
            Some(&token),
            Some(card()),
            &Uuid::new_v4().to_string(),
            Some(stale),
        )
        .await;
    assert_eq!(old.status, StatusCode::BAD_REQUEST);
    let short = api
        .send_with(
            Method::POST,
            "/credentials",
            Some(&token),
            Some(card()),
            "short",
            None,
        )
        .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);

    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM credentials")
        .fetch_one(&api.st.db)
        .await
        .unwrap();
    assert_eq!(n.0, 1, "only the first request had any effect");
}

#[sqlx::test]
async fn responses_carry_the_security_headers(pool: PgPool) {
    let api = start(pool).await;
    let mut req = Request::builder()
        .uri("/api/v1/ledger/verify")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("203.0.113.9:1".parse::<SocketAddr>().unwrap()));
    let resp = api.app.clone().oneshot(req).await.unwrap();
    let h = resp.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["cache-control"], "no-store");
    assert!(h["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
}

#[sqlx::test]
async fn every_state_change_leaves_an_audit_record(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    api.post(
        &format!("/credentials/{id}/revoke"),
        Some(&t[3]),
        json!({ "reason": "test" }),
    )
    .await;

    let rows: Vec<(String,)> = sqlx::query_as("SELECT action FROM audit_logs ORDER BY id")
        .fetch_all(&api.st.db)
        .await
        .unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    for expected in [
        "CREDENTIAL_CREATED",
        "CREDENTIAL_SIGNED",
        "CREDENTIAL_REVOKED",
    ] {
        assert!(
            actions.contains(&expected),
            "{expected} missing from {actions:?}"
        );
    }
    assert_eq!(
        actions
            .iter()
            .filter(|a| **a == "CREDENTIAL_SIGNED")
            .count(),
        3
    );
    let leaked: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_logs WHERE details::text ILIKE '%' || $1 || '%'",
    )
    .bind(PASSWORD)
    .fetch_one(&api.st.db)
    .await
    .unwrap();
    assert_eq!(leaked.0, 0, "no password in the log");
}

// ---------------------------------------------------------------------------------------------------------
// Health, request ids and metrics
// ---------------------------------------------------------------------------------------------------------

async fn scrape(api: &Api) -> String {
    let app = Router::new()
        .route("/metrics", axum::routing::get(crate::metrics::render))
        .with_state(api.st.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

async fn raw_get(api: &Api, path: &str, request_id: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder().uri(path);
    if let Some(id) = request_id {
        req = req.header("x-request-id", id);
    }
    let mut req = req.body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("203.0.113.9:1".parse::<SocketAddr>().unwrap()));
    api.app.clone().oneshot(req).await.unwrap()
}

#[sqlx::test]
async fn liveness_ignores_the_database_but_readiness_needs_it(pool: PgPool) {
    let api = start(pool).await;
    assert_eq!(
        raw_get(&api, "/health", None).await.status(),
        StatusCode::OK
    );
    assert_eq!(raw_get(&api, "/ready", None).await.status(), StatusCode::OK);

    api.st.db.close().await;
    assert_eq!(
        raw_get(&api, "/health", None).await.status(),
        StatusCode::OK,
        "still alive"
    );
    let r = raw_get(&api, "/ready", None).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "but not ready");
}

#[sqlx::test]
async fn every_response_has_a_request_id_and_odd_ones_are_replaced(pool: PgPool) {
    let api = start(pool).await;
    let id =
        |r: &axum::response::Response| r.headers()["x-request-id"].to_str().unwrap().to_string();

    let r = raw_get(&api, "/health", Some("trace-1234.abcd")).await;
    assert_eq!(
        id(&r),
        "trace-1234.abcd",
        "a plain id from the proxy is kept"
    );
    let generated = id(&raw_get(&api, "/health", None).await);
    assert!(Uuid::parse_str(&generated).is_ok());
    for odd in [
        "short",
        "has spaces in it!",
        &"x".repeat(200),
        "semi;colon<>quote\"",
    ] {
        let got = id(&raw_get(&api, "/health", Some(odd)).await);
        assert_ne!(got, odd, "{odd:?} must not be echoed");
        assert!(Uuid::parse_str(&got).is_ok());
    }
    assert!(raw_get(&api, "/no/such/page", None)
        .await
        .headers()
        .contains_key("x-request-id"));
}

#[sqlx::test]
async fn metrics_count_what_happened_without_leaking_identifiers(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    api.get(&format!("/verify/{id}"), None).await;
    api.get("/no/such/page", None).await;
    // trip the per-account lock-out so a rate-limit counter moves
    for _ in 0..6 {
        api.post(
            "/auth/login",
            None,
            json!({ "email": "auditor@t.test", "password": "wrong wrong wrong" }),
        )
        .await;
    }

    let text = scrape(&api).await;
    let has = |needle: &str| assert!(text.contains(needle), "missing {needle}\n{text}");
    has(r#"acvs_http_requests_total{method="GET",route="/api/v1/verify/:id",status="200"}"#);
    has(
        r#"acvs_http_requests_total{method="POST",route="/api/v1/credentials/:id/approve",status="200"}"#,
    );
    has(r#"route="unmatched""#);
    has("acvs_http_request_duration_seconds_bucket");
    has(r#"acvs_audit_events_total{action="CREDENTIAL_CREATED"}"#);
    has(r#"acvs_audit_events_total{action="LOGIN_FAILED"}"#);
    has("acvs_db_up 1");
    has(r#"acvs_credentials{status="issued"} 1"#);
    has("acvs_credentials_waiting_for_seal 1");
    has("acvs_ledger_height 0");
    has("acvs_active_sessions 5");
    has("acvs_build_info{version=");
    assert!(
        !text.contains(&id),
        "a credential id must never become a label"
    );
    assert!(!text.contains("t.test"), "no e-mail address in the metrics");
    assert!(
        !text.contains("203.0.113.9"),
        "no client address in the metrics"
    );

    api.post("/ledger/seal", Some(&t[3]), json!({})).await;
    let text = scrape(&api).await;
    assert!(
        text.contains("acvs_ledger_height 1")
            && text.contains("acvs_credentials_waiting_for_seal 0")
    );
    assert!(text.contains("acvs_blocks_without_external_timestamp 1"));
}

#[sqlx::test]
async fn the_metrics_endpoint_is_not_part_of_the_public_router(pool: PgPool) {
    let api = start(pool).await;
    assert_eq!(
        raw_get(&api, "/metrics", None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        raw_get(&api, "/api/v1/metrics", None).await.status(),
        StatusCode::NOT_FOUND
    );
}

// ---------------------------------------------------------------------------------------------------------
// Paging and the whole-chain check
// ---------------------------------------------------------------------------------------------------------

fn ids(v: &Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect()
}

#[sqlx::test]
async fn credentials_are_listed_a_page_at_a_time_without_gaps_or_repeats(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let mut made = vec![];
    for n in 0..7 {
        let mut c = card();
        c["student_id"] = json!(if n % 2 == 0 { "EVEN" } else { "ODD" });
        let r = api.post("/credentials", Some(&t[0]), c).await;
        made.push(r.body["id"].as_str().unwrap().to_string());
    }

    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("/credentials?limit=3&before={c}"),
            None => "/credentials?limit=3".into(),
        };
        let r = api.get(&path, Some(&t[1])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        seen.extend(ids(&r.body, "credentials"));
        pages += 1;
        match r.body["next"].as_str() {
            Some(n) => cursor = Some(n.to_string()),
            None => break,
        }
    }
    assert_eq!(pages, 3, "7 items in pages of 3");
    let mut newest_first = made.clone();
    newest_first.reverse();
    assert_eq!(seen, newest_first, "every credential once, newest first");

    // A page that ends exactly at the end has no cursor (no empty extra page).
    let all = api.get("/credentials?limit=7", Some(&t[1])).await;
    assert_eq!(all.body["next"], Value::Null);
    // Sizes are clamped, not trusted.
    assert_eq!(
        ids(
            &api.get("/credentials?limit=0", Some(&t[1])).await.body,
            "credentials"
        )
        .len(),
        1
    );
    assert_eq!(
        ids(
            &api.get("/credentials?limit=99999", Some(&t[1])).await.body,
            "credentials"
        )
        .len(),
        7
    );
    // Filters work with paging.
    let even = api
        .get("/credentials?student_id=EVEN&limit=2", Some(&t[1]))
        .await
        .body;
    assert_eq!(ids(&even, "credentials").len(), 2);
    assert!(even["next"].is_string());
    assert_eq!(
        ids(
            &api.get("/credentials?student_id=NOBODY", Some(&t[1]))
                .await
                .body,
            "credentials"
        )
        .len(),
        0
    );
    // Junk cursors are refused rather than ignored.
    for junk in ["junk", "1.2", "1.00000000-0000-0000-0000-000000000000x"] {
        assert_eq!(
            api.get(&format!("/credentials?before={junk}"), Some(&t[1]))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "{junk}"
        );
    }
}

#[sqlx::test]
async fn paging_does_not_let_faculty_see_each_others_credentials(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,'other@t.test',$2,'faculty')")
        .bind(Uuid::new_v4())
        .bind(password_hash())
        .execute(&api.st.db)
        .await
        .unwrap();
    let other = api.login("other").await;
    for _ in 0..3 {
        api.create(&t[0]).await;
        api.create(&other).await;
    }
    let first = api.get("/credentials?limit=2", Some(&t[0])).await.body;
    let second = api
        .get(
            &format!(
                "/credentials?limit=2&before={}",
                first["next"].as_str().unwrap()
            ),
            Some(&t[0]),
        )
        .await
        .body;
    assert_eq!(
        ids(&first, "credentials").len() + ids(&second, "credentials").len(),
        3,
        "only their own three"
    );
    assert_eq!(second["next"], Value::Null);
}

#[sqlx::test]
async fn the_audit_log_pages_and_filters(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    for _ in 0..4 {
        api.create(&t[0]).await;
    }
    let p1 = api.get("/audit?limit=3", Some(&t[3])).await.body;
    assert_eq!(p1["logs"].as_array().unwrap().len(), 3);
    let cursor = p1["next"].as_i64().unwrap();
    let p2 = api
        .get(&format!("/audit?limit=3&before={cursor}"), Some(&t[3]))
        .await
        .body;
    let last_of_first = p1["logs"][2]["id"].as_i64().unwrap();
    assert!(p2["logs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l["id"].as_i64().unwrap() < last_of_first));
    let created = api
        .get("/audit?action=CREDENTIAL_CREATED&limit=500", Some(&t[3]))
        .await
        .body;
    assert_eq!(created["logs"].as_array().unwrap().len(), 4);
    assert!(created["logs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|l| l["action"] == "CREDENTIAL_CREATED"));
    assert_eq!(created["next"], Value::Null);
}

#[sqlx::test]
async fn blocks_are_listed_newest_first_a_page_at_a_time(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    for _ in 0..5 {
        api.issue(&t).await;
        assert_eq!(
            api.post("/ledger/seal", Some(&t[3]), json!({}))
                .await
                .status,
            StatusCode::OK
        );
    }
    let p1 = api.get("/ledger/blocks?limit=2", Some(&t[3])).await.body;
    let heights = |v: &Value| {
        v["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["height"].as_i64().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(heights(&p1), vec![5, 4]);
    let p2 = api
        .get(
            &format!("/ledger/blocks?limit=2&before={}", p1["next"]),
            Some(&t[3]),
        )
        .await
        .body;
    assert_eq!(heights(&p2), vec![3, 2]);
    let p3 = api
        .get(
            &format!("/ledger/blocks?limit=2&before={}", p2["next"]),
            Some(&t[3]),
        )
        .await
        .body;
    assert_eq!(heights(&p3), vec![1]);
    assert_eq!(p3["next"], Value::Null);
}

/// Writes `n` sealed blocks of one credential each straight into the database, signed by the real university key.
async fn forge_chain(api: &Api, n: i64) {
    let (key_id, seed) = keys::active_signer(&api.st, "university").await.unwrap();
    let (faculty,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE role = 'faculty'")
        .fetch_one(&api.st.db)
        .await
        .unwrap();
    let mut prev = "0".repeat(64);
    for h in 1..=n {
        let leaf = crate::crypto::sha256_hex(format!("leaf {h}").as_bytes());
        let root = crate::crypto::merkle::root(std::slice::from_ref(&leaf)).unwrap();
        let hash = crate::ledger::block_hash(h, &prev, &root, 1_700_000_000 + h, 1);
        sqlx::query("INSERT INTO blocks (height, prev_hash, merkle_root, leaves, ts, block_hash, signature, key_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(h).bind(&prev).bind(&root).bind(json!([leaf])).bind(1_700_000_000 + h).bind(&hash)
            .bind(crate::crypto::sign(&seed, hash.as_bytes())).bind(key_id)
            .execute(&api.st.db).await.unwrap();
        sqlx::query("INSERT INTO credentials (id, student_id, student_name, program, graduation_date, credential_hash, status, created_by, block_height, leaf_index) VALUES ($1,'S','N','P','2025-01-01',$2,'issued',$3,$4,0)")
            .bind(Uuid::new_v4()).bind(&leaf).bind(faculty).bind(h)
            .execute(&api.st.db).await.unwrap();
        prev = hash;
    }
}

#[sqlx::test]
async fn a_long_chain_is_checked_in_full_and_reported_a_window_at_a_time(pool: PgPool) {
    let api = start(pool).await;
    forge_chain(&api, 1200).await;

    let started = std::time::Instant::now();
    let v = api.get("/ledger/verify", None).await.body;
    let took = started.elapsed();
    assert_eq!(
        (
            v["ok"].clone(),
            v["length"].clone(),
            v["failed_total"].clone()
        ),
        (json!(true), json!(1200), json!(0))
    );
    assert_eq!(
        v["blocks"].as_array().unwrap().len(),
        100,
        "a window, not the whole chain"
    );
    assert_eq!(v["next_from"], 101);
    // Generous: ~0.6s locally, ~10s on a loaded CI runner in a debug build. It only has to catch the check going unbounded.
    assert!(took.as_secs() < 30, "1200 blocks took {took:?}");

    // Walk the windows: every block exactly once, all fine.
    let (mut from, mut count) = (1, 0);
    loop {
        let w = api
            .get(&format!("/ledger/verify?from={from}&limit=500"), None)
            .await
            .body;
        let blocks = w["blocks"].as_array().unwrap();
        assert!(blocks.iter().all(|b| b["ok"] == true));
        assert_eq!(blocks[0]["height"], from);
        count += blocks.len();
        match w["next_from"].as_i64() {
            Some(n) => from = n,
            None => break,
        }
    }
    assert_eq!(count, 1200);

    // Damage far inside the chain is found, named, and does not hide behind the window.
    tamper(
        &api.st.db,
        "UPDATE blocks SET merkle_root = repeat('f', 64) WHERE height = 777",
        None,
    )
    .await;
    let v = api.get("/ledger/verify", None).await.body;
    assert_eq!(
        (v["ok"].clone(), v["failed_blocks"].clone()),
        (json!(false), json!([777]))
    );
    let w = api.get("/ledger/verify?from=770&limit=10", None).await.body;
    let bad: Vec<i64> = w["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["ok"] == false)
        .map(|b| b["height"].as_i64().unwrap())
        .collect();
    assert_eq!(bad, vec![777]);
}

#[sqlx::test]
async fn a_missing_block_in_the_middle_is_detected_even_across_pages(pool: PgPool) {
    let api = start(pool).await;
    forge_chain(&api, 6).await;
    // Removing a block (and its credential link) leaves a gap: the next block no longer follows its neighbour.
    tamper(
        &api.st.db,
        "UPDATE credentials SET block_height = NULL, leaf_index = NULL WHERE block_height = 3",
        None,
    )
    .await;
    tamper(&api.st.db, "DELETE FROM blocks WHERE height = 3", None).await;
    let v = api.get("/ledger/verify", None).await.body;
    assert_eq!(v["ok"], false);
    assert_eq!(v["failed_blocks"], json!([4]));
}

#[sqlx::test]
async fn the_chain_check_is_cached_briefly_and_reset_by_a_new_block(pool: PgPool) {
    let st0 = state(pool.clone());
    let mut cfg = Config::for_tests();
    cfg.chain_cache_secs = 3600;
    let st = AppState {
        cfg: Arc::new(cfg),
        ..st0
    };
    keys::ensure_initial_keys(&st).await.unwrap();
    for (name, role) in ROLES {
        sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)")
            .bind(Uuid::new_v4())
            .bind(format!("{name}@t.test"))
            .bind(password_hash())
            .bind(role)
            .execute(&st.db)
            .await
            .unwrap();
    }
    let api = Api {
        app: router(st.clone()),
        st,
    };
    let t = api.everyone().await;
    api.issue(&t).await;
    api.post("/ledger/seal", Some(&t[3]), json!({})).await;

    let first = api.get("/ledger/verify", None).await.body;
    assert_eq!(
        (first["ok"].clone(), first["cached"].clone()),
        (json!(true), json!(false))
    );
    tamper(
        &api.st.db,
        "UPDATE blocks SET merkle_root = repeat('0', 64) WHERE height = 1",
        None,
    )
    .await;
    let second = api.get("/ledger/verify", None).await.body;
    assert_eq!(
        (second["ok"].clone(), second["cached"].clone()),
        (json!(true), json!(true)),
        "served from memory"
    );
    assert_eq!(second["checked_at"], first["checked_at"]);
    assert_eq!(
        second["blocks"][0]["ok"], false,
        "but the per-block window is always live"
    );

    // Sealing another block drops the cached answer, so the damage shows at once.
    api.issue(&t).await;
    api.post("/ledger/seal", Some(&t[3]), json!({})).await;
    let third = api.get("/ledger/verify", None).await.body;
    assert_eq!(
        (
            third["ok"].clone(),
            third["cached"].clone(),
            third["length"].clone()
        ),
        (json!(false), json!(false), json!(2))
    );
}

#[sqlx::test]
async fn old_nonces_are_purged_in_the_background_not_per_request(pool: PgPool) {
    let api = start(pool.clone()).await;
    let token = api.login("faculty").await;
    sqlx::query("INSERT INTO nonces (nonce, used_at) VALUES ('old-nonce-0000000000', now() - interval '10 minutes')")
        .execute(&pool)
        .await
        .unwrap();

    let r = api.post("/credentials", Some(&token), card()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM nonces WHERE nonce = 'old-nonce-0000000000'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(left, 1, "a request must not run the cleanup itself");

    assert_eq!(crate::security::purge_nonces(&pool).await.unwrap(), 1);
    let fresh: i64 = sqlx::query_scalar("SELECT count(*) FROM nonces")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(fresh >= 1, "recent nonces must be kept");
}

fn bulk_rows(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            json!({
                "student_id": format!("BULK-{i}"), "student_name": format!("Student Number {i}"),
                "program": "BSc Mathematics", "graduation_date": "2025-05-15"
            })
        })
        .collect()
}

#[sqlx::test]
async fn a_bulk_import_creates_every_row_signed_and_ready_for_the_next_stage(pool: PgPool) {
    let api = start(pool.clone()).await;
    let t = api.everyone().await;
    // 200 rows are well over the 16 KB limit that applies to every other request.
    let rows = bulk_rows(200);
    assert!(serde_json::to_vec(&rows).unwrap().len() > 16 * 1024);
    let r = api
        .post("/credentials/bulk", Some(&t[0]), json!({ "items": rows }))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.body["created"], 200);
    let ids = r.body["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 200);

    let signed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approvals a JOIN credentials c ON c.id = a.credential_id
         WHERE a.role = 'faculty' AND c.status = 'pending_exam_cell' AND c.student_id LIKE 'BULK-%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(signed, 200);

    // An imported credential continues through the ordinary stages and verifies.
    let id = ids[17].as_str().unwrap();
    for token in &t[1..4] {
        let a = api
            .post(
                &format!("/credentials/{id}/approve"),
                Some(token),
                json!({}),
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    }
    assert_eq!(api.verdict(id).await, "VALID");

    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE action = 'CREDENTIAL_CREATED' AND details->>'bulk' = 'true'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 200);
}

#[sqlx::test]
async fn one_bad_row_rejects_the_whole_import_and_is_named(pool: PgPool) {
    let api = start(pool.clone()).await;
    let faculty = api.login("faculty").await;
    let mut rows = bulk_rows(5);
    rows[2]["graduation_date"] = json!("15/05/2025");
    let r = api
        .post(
            "/credentials/bulk",
            Some(&faculty),
            json!({ "items": rows }),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body["error"].as_str().unwrap().contains("row 3"),
        "{}",
        r.body
    );

    let mut rows = bulk_rows(5);
    rows[4]["student_name"] = json!("  ");
    let r = api
        .post(
            "/credentials/bulk",
            Some(&faculty),
            json!({ "items": rows }),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.body["error"].as_str().unwrap().contains("row 5"),
        "{}",
        r.body
    );

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing is created when any row is rejected");
}

#[sqlx::test]
async fn bulk_import_is_faculty_only_and_bounded(pool: PgPool) {
    let api = start(pool.clone()).await;
    let t = api.everyone().await;
    for token in &t[1..] {
        let r = api
            .post(
                "/credentials/bulk",
                Some(token),
                json!({ "items": bulk_rows(1) }),
            )
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    let r = api
        .post("/credentials/bulk", None, json!({ "items": bulk_rows(1) }))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = api
        .post("/credentials/bulk", Some(&t[0]), json!({ "items": [] }))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = api
        .post(
            "/credentials/bulk",
            Some(&t[0]),
            json!({ "items": bulk_rows(crate::credentials::BULK_MAX + 1) }),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Over 1 MB is refused before it is read.
    let big = "x".repeat(1100 * 1024);
    let r = api
        .post(
            "/credentials/bulk",
            Some(&t[0]),
            json!({ "items": [], "pad": big }),
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // The single-credential route keeps its 16 KB limit.
    let r = api
        .post(
            "/credentials",
            Some(&t[0]),
            json!({ "pad": "x".repeat(20 * 1024) }),
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test]
async fn an_issued_credential_exports_as_a_verifiable_credential_whose_proofs_check_independently(
    pool: PgPool,
) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let id = api.issue(&t).await;
    let r = api.get(&format!("/credentials/{id}/export"), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let d = &r.body;
    assert_eq!(d["@context"][0], "https://www.w3.org/ns/credentials/v2");
    assert_eq!(
        d["type"],
        json!(["VerifiableCredential", "AcvsAcademicCredential"])
    );
    assert_eq!(d["id"], format!("urn:uuid:{id}"));
    assert_eq!(d["issuer"], "http://localhost:3000");
    assert_eq!(d["credentialSubject"]["studentName"], "Ada Lovelace");
    assert_eq!(d["credentialSubject"]["graduationDate"], "2025-05-15");
    assert_eq!(
        d["credentialStatus"]["id"],
        format!("http://localhost:3000/api/v1/verify/{id}")
    );
    assert!(
        !d.to_string().contains("STU-1"),
        "the student's own identifier must not be exported"
    );

    // Re-check every proof with nothing but the document: the message it names, its key and its signature.
    let hash = d["credentialHash"].as_str().unwrap();
    let proofs = d["proof"].as_array().unwrap();
    assert_eq!(proofs.len(), 4);
    for (p, stage) in proofs
        .iter()
        .zip(["faculty", "exam_cell", "registrar", "university"])
    {
        assert_eq!(p["stage"], stage);
        let msg = p["signedMessage"].as_str().unwrap();
        assert_eq!(msg, format!("ACVS-APPROVAL-v1|{id}|{stage}|{hash}"));
        let key = p["verificationMethod"]
            .as_str()
            .unwrap()
            .strip_prefix("urn:acvs:ed25519:")
            .unwrap();
        let sig = p["proofValue"].as_str().unwrap();
        assert!(
            crate::crypto::verify(key, sig, msg.as_bytes()),
            "{stage} proof must verify"
        );
        assert!(
            !crate::crypto::verify(key, sig, format!("{msg}x").as_bytes()),
            "and only for that message"
        );
    }

    // The context it names is served, and defines the custom terms.
    let c = api.get("/vc/context", None).await;
    assert_eq!(c.status, StatusCode::OK);
    assert!(c.body["@context"]["studentName"].is_string());
}

#[sqlx::test]
async fn only_a_valid_credential_can_be_exported(pool: PgPool) {
    let api = start(pool).await;
    let t = api.everyone().await;
    let pending = api.create(&t[0]).await;
    let r = api
        .get(&format!("/credentials/{pending}/export"), None)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["error"].as_str().unwrap().contains("PENDING"));

    let id = api.issue(&t).await;
    let rv = api
        .post(
            &format!("/credentials/{id}/revoke"),
            Some(&t[3]),
            json!({ "reason": "error in record" }),
        )
        .await;
    assert_eq!(rv.status, StatusCode::OK, "{}", rv.body);
    let r = api.get(&format!("/credentials/{id}/export"), None).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.body["error"].as_str().unwrap().contains("REVOKED"));

    let r = api
        .get(&format!("/credentials/{}/export", Uuid::new_v4()), None)
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------------------
// On-chain anchors (written by the separate acvs-chain worker; the backend only shows them)
// ---------------------------------------------------------------------------------------------------------

const CHAIN: i64 = 11155111;
const CONTRACT: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const REGISTRY: &str = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";

/// The same application and database, but configured to show on-chain anchors.
fn with_onchain(api: &Api) -> Api {
    let mut cfg = (*api.st.cfg).clone();
    cfg.onchain = Some(crate::config::OnchainConfig {
        chain_id: CHAIN,
        contract: CONTRACT.into(),
        explorer: Some("https://explorer.test".into()),
        issuer: Some(crate::config::IssuerRef {
            registry: REGISTRY.into(),
            issuer_id: 7,
        }),
    });
    let st = AppState {
        cfg: Arc::new(cfg),
        chain_cache: Arc::default(),
        ..api.st.clone()
    };
    Api {
        app: router(st.clone()),
        st,
    }
}

/// Writes a receipt the way the worker does. `hash` is what the contract is said to hold for the block.
async fn receipt(pool: &PgPool, chain_id: i64, contract: &str, height: i64, hash: Option<&str>) {
    sqlx::query(
        "INSERT INTO chain_anchors (chain_id, contract, block_height, block_hash, merkle_root, leaf_count, epoch, tx_hash, chain_block, anchored_at)
         SELECT $1, $2, height, coalesce($4, block_hash), merkle_root, jsonb_array_length(leaves), 1, '0xfeed' || height, 100 + height, now()
         FROM blocks WHERE height = $3",
    )
    .bind(chain_id)
    .bind(contract)
    .bind(height)
    .bind(hash)
    .execute(pool)
    .await
    .unwrap();
}

/// Two sealed blocks with one credential each; returns the credential ids.
async fn two_blocks(api: &Api, t: &[String; 5]) -> [String; 2] {
    let a = api.issue(t).await;
    assert_eq!(
        api.post("/ledger/seal", Some(&t[3]), json!({}))
            .await
            .status,
        StatusCode::OK
    );
    let b = api.issue(t).await;
    assert_eq!(
        api.post("/ledger/seal", Some(&t[3]), json!({}))
            .await
            .status,
        StatusCode::OK
    );
    [a, b]
}

#[sqlx::test]
async fn without_the_setting_nothing_about_a_chain_is_shown_even_if_receipts_exist(pool: PgPool) {
    let api = start(pool.clone()).await;
    let t = api.everyone().await;
    let [a, _] = two_blocks(&api, &t).await;
    let before = [
        api.get(&format!("/verify/{a}"), None).await.body,
        api.get("/ledger/blocks", Some(&t[3])).await.body,
        api.get("/ledger/verify", None).await.body,
    ];
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    receipt(&pool, CHAIN, CONTRACT, 2, Some(&"0".repeat(64))).await;

    let after = [
        api.get(&format!("/verify/{a}"), None).await.body,
        api.get("/ledger/blocks", Some(&t[3])).await.body,
        api.get("/ledger/verify", None).await.body,
    ];
    for (b, a) in before.iter().zip(&after) {
        let mut b = b.clone();
        let mut a = a.clone();
        // The only field that differs between two calls is the time of the check.
        for v in [&mut a, &mut b] {
            if let Some(o) = v.as_object_mut() {
                o.remove("checked_at");
            }
        }
        assert_eq!(a, b, "a response changed although on-chain display is off");
    }
    assert!(!after[0]["anchor"]
        .as_object()
        .unwrap()
        .contains_key("onchain"));
    assert!(!after[1].as_object().unwrap().contains_key("onchain"));
    assert!(!after[1]["blocks"][0]
        .as_object()
        .unwrap()
        .contains_key("onchain"));
    assert!(!after[2]["blocks"][0]
        .as_object()
        .unwrap()
        .contains_key("onchain"));
    assert_eq!(
        after[2]["ok"], true,
        "a stray receipt must not fail the chain check"
    );

    let r = api.get("/ledger/blocks/1/anchor", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body["error"].as_str().unwrap().contains("not configured"));
}

#[sqlx::test]
async fn a_block_without_a_receipt_is_simply_not_anchored_yet(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let [a, _] = two_blocks(&off, &t).await;
    let api = with_onchain(&off);

    let v = api.get(&format!("/verify/{a}"), None).await.body;
    assert_eq!(v["verdict"], "VALID");
    assert_eq!(v["anchor"]["onchain"], json!({ "status": "none" }));
    assert_eq!(v["anchor"]["ok"], true);

    let l = api.get("/ledger/blocks", Some(&t[3])).await.body;
    assert_eq!(l["blocks"][0]["onchain"]["status"], "none");
    assert_eq!(l["onchain"]["unanchored"], 2);
    assert_eq!(l["onchain"]["chain_id"], CHAIN);
    assert_eq!(l["onchain"]["contract"], CONTRACT);
    assert_eq!(l["onchain"]["open_incidents"], json!([]));

    let c = api.get("/ledger/verify", None).await.body;
    assert_eq!(c["ok"], true);
    assert_eq!(c["blocks"][0]["onchain"], "none");

    let r = api.get("/ledger/blocks/1/anchor", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body["error"]
        .as_str()
        .unwrap()
        .contains("not been anchored"));
    assert_eq!(
        api.get("/ledger/blocks/9/anchor", None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn a_receipt_is_shown_with_where_to_find_the_anchor(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let [a, b] = two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    // Receipts for another network or another contract say nothing about this one.
    receipt(&pool, 31337, CONTRACT, 2, None).await;
    receipt(
        &pool,
        CHAIN,
        "0x00000000000000000000000000000000000000aa",
        2,
        None,
    )
    .await;

    let v = api.get(&format!("/verify/{a}"), None).await.body;
    let o = &v["anchor"]["onchain"];
    assert_eq!(o["status"], "ok");
    assert_eq!(o["chain_id"], CHAIN);
    assert_eq!(o["contract"], CONTRACT);
    assert_eq!(o["epoch"], 1);
    assert_eq!(o["tx_hash"], "0xfeed1");
    assert_eq!(o["chain_block"], 101);
    assert_eq!(o["explorer_url"], "https://explorer.test/tx/0xfeed1");
    assert!(o["anchored_at"].is_string());
    assert_eq!(
        api.get(&format!("/verify/{b}"), None).await.body["anchor"]["onchain"],
        json!({ "status": "none" })
    );

    // Newest block first.
    let l = api.get("/ledger/blocks", Some(&t[3])).await.body;
    assert_eq!(l["blocks"][0]["onchain"]["status"], "none");
    assert_eq!(l["blocks"][1]["onchain"]["status"], "ok");
    assert_eq!(l["onchain"]["unanchored"], 1);
    assert_eq!(
        l["onchain"]["explorer_url"],
        format!("https://explorer.test/address/{CONTRACT}")
    );

    let c = api.get("/ledger/verify", None).await.body;
    assert_eq!(c["ok"], true);
    assert_eq!(
        (
            c["blocks"][0]["onchain"].clone(),
            c["blocks"][1]["onchain"].clone()
        ),
        (json!("ok"), json!("none"))
    );

    // Anyone may read a block's receipt, with the values the contract must hold.
    let r = api.get("/ledger/blocks/1/anchor", None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["status"], "ok");
    assert_eq!(r.body["height"], 1);
    assert_eq!(r.body["block"], r.body["anchored"]);
    assert_eq!(r.body["block"]["leaf_count"], 1);
    assert_eq!(r.body["block"]["block_hash"], v["anchor"]["block_hash"]);
}

#[sqlx::test]
async fn a_receipt_for_a_different_hash_fails_the_ledger_check_but_not_the_credential(
    pool: PgPool,
) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let [a, b] = two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    receipt(&pool, CHAIN, CONTRACT, 2, Some(&"0".repeat(64))).await;

    let c = api.get("/ledger/verify", None).await.body;
    assert_eq!(c["ok"], false);
    assert_eq!(c["failed_blocks"], json!([2]));
    assert_eq!(c["blocks"][0]["ok"], true);
    assert_eq!(c["blocks"][1]["ok"], false);
    assert_eq!(c["blocks"][1]["onchain"], "mismatch");
    // Everything else about that block is still in order: only the receipt disagrees.
    assert_eq!(c["blocks"][1]["block_ok"], true);
    assert_eq!(c["blocks"][1]["linked"], true);

    // The chain never changes a verdict.
    for id in [&a, &b] {
        assert_eq!(api.verdict(id).await, "VALID");
    }
    let v = api.get(&format!("/verify/{b}"), None).await.body;
    assert_eq!(v["anchor"]["onchain"]["status"], "mismatch");
    assert_eq!(v["anchor"]["ok"], true);

    let l = api.get("/ledger/blocks", Some(&t[3])).await.body;
    assert_eq!(l["blocks"][0]["onchain"]["status"], "mismatch");

    let r = api.get("/ledger/blocks/2/anchor", None).await.body;
    assert_eq!(r["status"], "mismatch");
    assert_ne!(r["block"]["block_hash"], r["anchored"]["block_hash"]);

    // With the display off, the same database still verifies.
    assert_eq!(off.get("/ledger/verify", None).await.body["ok"], true);
}

#[sqlx::test]
async fn an_incident_is_shown_until_the_worker_gets_past_it(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    sqlx::query(
        "INSERT INTO chain_incidents (chain_id, contract, kind, block_height, detail, fingerprint, created_at)
         VALUES ($1, $2, 'anchor_mismatch', 2, $3, 'f1', now() + interval '1 second'),
                (31337, $2, 'height_gap', 2, '{}', 'f2', now() + interval '1 second')",
    )
    .bind(CHAIN)
    .bind(CONTRACT)
    .bind(json!({ "note": "restored an older backup" }))
    .execute(&pool)
    .await
    .unwrap();

    let l = api.get("/ledger/blocks", Some(&t[3])).await.body;
    let open = l["onchain"]["open_incidents"].as_array().unwrap();
    assert_eq!(open.len(), 1, "only this chain's incident: {open:?}");
    assert_eq!(open[0]["kind"], "anchor_mismatch");
    assert_eq!(open[0]["height"], 2);
    assert_eq!(open[0]["note"], "restored an older backup");
    // An incident is about anchoring, not about the ledger itself.
    assert_eq!(api.get("/ledger/verify", None).await.body["ok"], true);

    // A receipt written after the incident means the worker is anchoring again.
    sqlx::query(
        "INSERT INTO chain_anchors (chain_id, contract, block_height, block_hash, merkle_root, leaf_count, epoch, tx_hash, chain_block, anchored_at, created_at)
         SELECT $1, $2, height, block_hash, merkle_root, 1, 2, '0xbeef', 200, now(), now() + interval '2 seconds' FROM blocks WHERE height = 2",
    )
    .bind(CHAIN)
    .bind(CONTRACT)
    .execute(&pool)
    .await
    .unwrap();
    let l = api.get("/ledger/blocks", Some(&t[3])).await.body;
    assert_eq!(l["onchain"]["open_incidents"], json!([]));
    assert_eq!(l["onchain"]["unanchored"], 0);
    assert_eq!(l["blocks"][0]["onchain"]["epoch"], 2);
}

#[sqlx::test]
async fn the_block_list_still_needs_a_sign_in_and_the_receipt_does_not(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    assert_eq!(
        api.get("/ledger/blocks", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api.get("/ledger/blocks/1/anchor", None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        api.get("/ledger/blocks/abc/anchor", None).await.status,
        StatusCode::BAD_REQUEST
    );
}

// ---------------------------------------------------------------------------------------------------------
// Exports for checking a credential without this server: on-chain evidence, the full export, did:web
// ---------------------------------------------------------------------------------------------------------

impl Api {
    /// A GET outside `/api/v1` (the DID document lives at the site root).
    async fn get_root(&self, uri: &str) -> Res {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "203.0.113.9:4000".parse::<SocketAddr>().unwrap(),
        ));
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        Res {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }
}

/// Recomputes a Merkle root the way the LedgerAnchor contract does: the side of each sibling follows from
/// the leaf's index and the number of leaves, not from anything the proof says.
fn root_like_the_contract(
    leaf_hex: &str,
    mut index: usize,
    mut width: usize,
    siblings: &[String],
) -> Option<String> {
    use sha2::{Digest, Sha256};
    let node = |prefix: u8, parts: &[&[u8]]| {
        let mut h = Sha256::new();
        h.update([prefix]);
        for p in parts {
            h.update(p);
        }
        h.finalize().to_vec()
    };
    let mut cur = node(0, &[&hex::decode(leaf_hex).ok()?]);
    let mut used = 0;
    while width > 1 {
        if (index ^ 1) < width {
            let sib = hex::decode(siblings.get(used)?).ok()?;
            used += 1;
            cur = if index & 1 == 1 {
                node(1, &[&sib, &cur])
            } else {
                node(1, &[&cur, &sib])
            };
        }
        index >>= 1;
        width = width.div_ceil(2);
    }
    (used == siblings.len()).then(|| hex::encode(cur))
}

#[sqlx::test]
async fn an_anchored_credential_exports_with_evidence_that_leads_to_the_anchored_root(
    pool: PgPool,
) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    // Three credentials in one block: an odd tree, so one proof skips a level.
    let ids = [
        off.issue(&t).await,
        off.issue(&t).await,
        off.issue(&t).await,
    ];
    assert_eq!(
        off.post("/ledger/seal", Some(&t[3]), json!({}))
            .await
            .status,
        StatusCode::OK
    );
    let api = with_onchain(&off);

    // Not anchored on-chain yet: the export is exactly what it is without the feature.
    let before = api
        .get(&format!("/credentials/{}/export", ids[0]), None)
        .await;
    assert_eq!(before.status, StatusCode::OK);
    assert!(before.body.get("evidence").is_none());
    assert_eq!(
        before.body,
        off.get(&format!("/credentials/{}/export", ids[0]), None)
            .await
            .body
    );

    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    for id in &ids {
        let d = api
            .get(&format!("/credentials/{id}/export"), None)
            .await
            .body;
        let e = &d["evidence"][0];
        assert_eq!(e["type"], "AcvsLedgerAnchor");
        assert_eq!(e["chainId"], CHAIN);
        assert_eq!(e["ledger"], CONTRACT);
        assert_eq!(e["registry"], REGISTRY);
        assert_eq!(e["issuerId"], 7);
        assert_eq!(e["epoch"], 1);
        assert_eq!(e["blockHeight"], 1);
        assert_eq!(e["transaction"], "0xfeed1");
        let siblings: Vec<String> = serde_json::from_value(e["merkleProof"].clone()).unwrap();
        let root = root_like_the_contract(
            d["credentialHash"].as_str().unwrap(),
            e["leafIndex"].as_u64().unwrap() as usize,
            3,
            &siblings,
        );
        assert_eq!(root.as_deref(), e["merkleRoot"].as_str(), "proof for {id}");
        // Everything that was in the export before is still there, unchanged.
        let mut without = d.clone();
        without.as_object_mut().unwrap().remove("evidence");
        assert_eq!(
            without,
            off.get(&format!("/credentials/{id}/export"), None)
                .await
                .body
        );
        assert!(!d.to_string().contains("STU-1"));
    }

    // The context defines the new terms only where they are used.
    let on = api.get("/vc/context", None).await.body;
    assert!(on["@context"]["merkleProof"].is_string());
    assert!(on["@context"]["hashedContent"].is_string());
    let plain = off.get("/vc/context", None).await.body;
    assert!(plain["@context"].get("merkleProof").is_none());
    assert!(plain["@context"]["studentName"].is_string());
}

#[sqlx::test]
async fn a_receipt_that_does_not_match_gives_no_evidence(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let [a, _] = two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, Some(&"0".repeat(64))).await;
    let d = api.get(&format!("/credentials/{a}/export"), None).await;
    assert_eq!(d.status, StatusCode::OK);
    assert!(d.body.get("evidence").is_none());
}

#[sqlx::test]
async fn the_full_export_is_for_staff_and_lets_the_hash_be_recomputed(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let [a, b] = two_blocks(&off, &t).await;
    let api = with_onchain(&off);
    receipt(&pool, CHAIN, CONTRACT, 1, None).await;
    let path = format!("/credentials/{a}/export-full");

    assert_eq!(api.get(&path, None).await.status, StatusCode::UNAUTHORIZED);
    // Without the feature there is no such export.
    assert_eq!(
        off.get(&path, Some(&t[2])).await.status,
        StatusCode::NOT_FOUND
    );

    let r = api.get(&path, Some(&t[2])).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let d = &r.body;
    assert_eq!(d["credentialSubject"]["studentId"], "STU-1");
    assert!(d["evidence"][0]["merkleProof"].is_array());

    // The text it carries hashes to the signed content hash, and says the same as the displayed fields.
    let text = d["hashedContent"].as_str().unwrap();
    assert_eq!(
        crate::crypto::sha256_hex(text.as_bytes()),
        d["credentialHash"]
    );
    let hashed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(hashed["id"], a);
    assert_eq!(hashed["student_id"], d["credentialSubject"]["studentId"]);
    assert_eq!(
        hashed["student_name"],
        d["credentialSubject"]["studentName"]
    );
    assert_eq!(hashed["program"], d["credentialSubject"]["program"]);
    assert_eq!(
        hashed["graduation_date"],
        d["credentialSubject"]["graduationDate"]
    );
    assert_eq!(hashed["gpa"], d["credentialSubject"]["gpa"]);
    assert_eq!(hashed["honors"], d["credentialSubject"]["honors"]);

    // Apart from those two additions it is the public export.
    let mut same = d.clone();
    same.as_object_mut().unwrap().remove("hashedContent");
    same["credentialSubject"]
        .as_object_mut()
        .unwrap()
        .remove("studentId");
    assert_eq!(
        same,
        api.get(&format!("/credentials/{a}/export"), None)
            .await
            .body
    );

    // Faculty reach only the credentials they created, as on the credential's own page.
    sqlx::query("INSERT INTO users (id, email, password_hash, role) VALUES ($1, 'other@t.test', $2, 'faculty')")
        .bind(Uuid::new_v4())
        .bind(password_hash())
        .execute(&pool)
        .await
        .unwrap();
    let other = api.login("other").await;
    assert_eq!(
        api.get(&path, Some(&other)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(api.get(&path, Some(&t[0])).await.status, StatusCode::OK);
    let page = api
        .get(&format!("/credentials/{a}"), Some(&t[2]))
        .await
        .body;
    assert_eq!(page["full_export"], true);
    assert!(off
        .get(&format!("/credentials/{a}"), Some(&t[2]))
        .await
        .body
        .get("full_export")
        .is_none());

    // Each download is on the audit log, with who took it.
    let (n, who): (i64, Option<String>) = sqlx::query_as(
        "SELECT count(*), max(actor_email) FROM audit_logs WHERE action = 'CREDENTIAL_EXPORTED_FULL' AND resource_id = $1",
    )
    .bind(&a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((n, who.as_deref()), (2, Some("registrar@t.test")));

    // A credential that is not anchored on-chain yet still exports in full, without evidence.
    let d2 = api
        .get(&format!("/credentials/{b}/export-full"), Some(&t[4]))
        .await;
    assert_eq!(d2.status, StatusCode::OK);
    assert!(d2.body.get("evidence").is_none());
    assert!(d2.body["hashedContent"].is_string());

    // Only a VALID credential, as for the public export.
    let rv = api
        .post(
            &format!("/credentials/{a}/revoke"),
            Some(&t[3]),
            json!({ "reason": "error in record" }),
        )
        .await;
    assert_eq!(rv.status, StatusCode::OK, "{}", rv.body);
    assert_eq!(
        api.get(&path, Some(&t[2])).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        api.get(
            &format!("/credentials/{}/export-full", Uuid::new_v4()),
            Some(&t[2])
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn the_did_document_lists_the_keys_that_are_still_trusted(pool: PgPool) {
    let off = start(pool.clone()).await;
    let t = off.everyone().await;
    let r = off.get_root("/.well-known/did.json").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let d = &r.body;
    assert_eq!(d["id"], "did:web:localhost%3A3000");
    let methods = d["verificationMethod"].as_array().unwrap();
    assert_eq!(methods.len(), 4);
    assert_eq!(d["assertionMethod"].as_array().unwrap().len(), 4);
    for m in methods {
        assert_eq!(m["type"], "Multikey");
        assert_eq!(m["controller"], d["id"]);
        assert_eq!(
            m["publicKeyMultibase"].as_str(),
            crate::vc::multikey(m["acvsPublicKeyHex"].as_str().unwrap()).as_deref()
        );
        assert!(m["publicKeyMultibase"]
            .as_str()
            .unwrap()
            .starts_with("z6Mk"));
        assert!(d["assertionMethod"].as_array().unwrap().contains(&m["id"]));
    }
    let stages: Vec<&str> = methods
        .iter()
        .map(|m| m["acvsStage"].as_str().unwrap())
        .collect();
    for s in ["faculty", "exam_cell", "registrar", "university"] {
        assert!(stages.contains(&s), "{s} key missing");
    }
    // No private material of any kind.
    assert!(!r.body.to_string().contains("private"));
    // Without on-chain anchoring only the verification service is named.
    assert_eq!(d["service"].as_array().unwrap().len(), 1);

    // A replaced key stays (what it signed is still good); a compromised key goes.
    let old: (Uuid, String) = sqlx::query_as(
        "SELECT id, public_key FROM signing_keys WHERE role = 'registrar' AND status = 'active'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let rot = off
        .post("/keys/registrar/rotate", Some(&t[3]), json!({}))
        .await;
    assert_eq!(rot.status, StatusCode::OK, "{}", rot.body);
    let d = off.get_root("/.well-known/did.json").await.body;
    let methods = d["verificationMethod"].as_array().unwrap();
    assert_eq!(methods.len(), 5);
    let retired = methods
        .iter()
        .find(|m| m["acvsPublicKeyHex"] == old.1)
        .unwrap();
    assert_eq!(retired["acvsStatus"], "retired");

    let rev = off
        .post(
            &format!("/keys/{}/revoke", old.0),
            Some(&t[3]),
            json!({ "reason": "laptop stolen" }),
        )
        .await;
    assert_eq!(rev.status, StatusCode::OK, "{}", rev.body);
    let d = off.get_root("/.well-known/did.json").await.body;
    assert_eq!(d["verificationMethod"].as_array().unwrap().len(), 4);
    assert!(!d.to_string().contains(&old.1));

    // With on-chain anchoring the document also says where the anchors and the registry entry are.
    let on = with_onchain(&off)
        .get_root("/.well-known/did.json")
        .await
        .body;
    let services: Vec<&str> = on["service"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["serviceEndpoint"].as_str().unwrap())
        .collect();
    assert!(services.contains(&format!("eip155:{CHAIN}:{CONTRACT}").as_str()));
    assert!(services.contains(&format!("eip155:{CHAIN}:{REGISTRY}#7").as_str()));
}
