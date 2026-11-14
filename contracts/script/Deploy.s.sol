// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";
import {LedgerAnchor} from "../src/LedgerAnchor.sol";

/// @notice Deploys the registry and one university's ledger, and lists the university in the registry.
///
/// Only the deployer's key signs here; it can be a throw-away key holding a little gas money. The issuer
/// admin key (kept offline) is named by address and is never needed for deployment.
///
/// Environment:
///   ISSUER_ADMIN    address of the offline issuer admin key (owner of the ledger, admin of the issuer)
///   ANCHORER        address of the worker's hot key
///   ISSUER_NAME     e.g. "Example University"
///   ISSUER_DID      e.g. "did:web:credentials.example.edu"
///   REGISTRY_OWNER  optional; who should own the registry afterwards (default: ISSUER_ADMIN)
///
/// The deployer owns the registry only long enough to list the issuer, then offers ownership to
/// REGISTRY_OWNER, who must accept it (`acceptOwnership`) for the hand-over to complete.
contract Deploy is Script {
    function run() external returns (IssuerRegistry registry, LedgerAnchor ledger, uint64 issuerId) {
        address admin = vm.envAddress("ISSUER_ADMIN");
        address anchorer = vm.envAddress("ANCHORER");
        string memory name = vm.envString("ISSUER_NAME");
        string memory did = vm.envString("ISSUER_DID");
        address registryOwner = vm.envOr("REGISTRY_OWNER", admin);

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        registry = new IssuerRegistry(deployer);
        ledger = new LedgerAnchor(admin, anchorer);
        issuerId = registry.registerIssuer(admin, name, did, address(ledger));
        if (registryOwner != deployer) registry.transferOwnership(registryOwner);
        vm.stopBroadcast();

        console.log("chain id         ", block.chainid);
        console.log("IssuerRegistry   ", address(registry));
        console.log("LedgerAnchor     ", address(ledger));
        console.log("issuer id        ", issuerId);
        console.log("issuer admin     ", admin);
        console.log("anchorer         ", anchorer);
        if (registryOwner != deployer) console.log("registry ownership offered to", registryOwner);
    }
}
