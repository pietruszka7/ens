// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ─────────────────────────────────────────────────────────────────────────────
//  Foundry PoC - Medium: owner() vs authorised() inconsistency
//  in ENSRegistryWithFallback
//
//  Drop into any Foundry test folder and run:
//    forge test --match-contract MediumInconsistencyTest -vv
//
//  Convention: FAIL = inconsistency confirmed (bug present)
//              PASS = behaviour is consistent (no bug)
// ─────────────────────────────────────────────────────────────────────────────

interface Vm {
    function startPrank(address sender) external;
    function stopPrank() external;
}

interface ENS {
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external returns (bytes32);
    function setOwner(bytes32 node, address owner) external;
    function setResolver(bytes32 node, address resolver) external;
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function recordExists(bytes32 node) external view returns (bool);
}

// ── Plain ENSRegistry (no fallback, no sentinel) ─────────────────────────────

contract ENSRegistry is ENS {
    struct Record { address owner; address resolver; uint64 ttl; }
    mapping(bytes32 => Record) internal records;
    mapping(address => mapping(address => bool)) internal operators;

    modifier authorised(bytes32 node) {
        address o = records[node].owner;
        require(o == msg.sender || operators[o][msg.sender]);
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
    function setOwner(bytes32 node, address o) external virtual override authorised(node) { _setOwner(node, o); }
    function setResolver(bytes32 node, address r) external virtual override authorised(node) { records[node].resolver = r; }
    function owner(bytes32 node) public virtual override view returns (address) {
        address addr = records[node].owner;
        if (addr == address(this)) return address(0);
        return addr;
    }
    function resolver(bytes32 node) public virtual override view returns (address) { return records[node].resolver; }
    function recordExists(bytes32 node) public virtual override view returns (bool) { return records[node].owner != address(0); }
    function _setOwner(bytes32 node, address o) internal virtual { records[node].owner = o; }
}

// ── ENSRegistryWithFallback (contains the inconsistency) ─────────────────────

contract ENSRegistryWithFallback is ENSRegistry {
    ENS public old;
    constructor(ENS _old) { old = _old; }

    function owner(bytes32 node) public override view returns (address) {
        if (!recordExists(node)) return old.owner(node);
        return super.owner(node);
    }
    function resolver(bytes32 node) public override view returns (address) {
        if (!recordExists(node)) return old.resolver(node);
        return super.resolver(node);
    }

    // Sentinel: address(0) → address(this)
    // owner() masks address(this) back to address(0)   ← external API
    // authorised() reads raw storage, sees address(this) ← access control
    // These two disagree - that is the bug.
    function _setOwner(bytes32 node, address o) internal override {
        if (o == address(0)) o = address(this);
        super._setOwner(node, o);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

contract MediumInconsistencyTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    ENSRegistry             internal old;
    ENSRegistryWithFallback internal reg;

    address internal constant ETH_TLD_MGR = address(0x1000000000000000000000000000000000000001);
    address internal constant ALICE       = address(0x1111111111111111111111111111111111111111);
    address internal constant RESOLVER_A  = address(0x4444444444444444444444444444444444444444);

    bytes32 internal constant ZERO_HASH = bytes32(0);
    bytes32 internal ethNode;
    bytes32 internal aliceNode;

    function setUp() public {
        old = new ENSRegistry();
        reg = new ENSRegistryWithFallback(ENS(address(old)));

        ethNode   = keccak256(abi.encodePacked(ZERO_HASH, keccak256(abi.encodePacked("eth"))));
        aliceNode = keccak256(abi.encodePacked(ethNode,   keccak256(abi.encodePacked("alice"))));

        reg.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), ETH_TLD_MGR);
        vm.startPrank(ETH_TLD_MGR);
        reg.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("alice")), ALICE);
        vm.stopPrank();
    }

    // ── MEDIUM-1: owner() i authorised() nie zgadzaja sie po setOwner(node, 0) ─
    //
    // owner() zwraca address(0) -> API mowi "brak wlasciciela"
    // authorised() czyta surowy storage -> widzi address(this) i zawsze revertuje
    //
    // W spójnym systemie: jesli owner(node) == address(0), to
    // kazdy kto staje sie wlascicielem przez inne mechanizmy powinien moc
    // wywolac setOwner(node, self). Ale nie moze - access control jest inny
    // niz to co zwraca publiczne API.
    //
    // FAIL = niespojnosc potwierdzona

    function test_MEDIUM1_OwnerReturnsZeroButAuthorisedReverts() public {
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // API mowi: brak wlasciciela
        address publicOwner = reg.owner(aliceNode);
        require(
            publicOwner == address(0),
            "setup: owner() must return address(0) after setOwner(node, 0)"
        );

        // Jesli owner(node) == address(0), spójny system pozwoliłby
        // przejac węzeł - np. przez wywolanie setOwner(node, ALICE).
        // BUG: authorised() czyta address(this) z surowego storage i revertuje.
        // Wywolanie nizej REVERTUJE nieoczekiwanie → TEST FAIL
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, ALICE);
        vm.stopPrank();
    }

    // ── MEDIUM-2: ENSRegistry (bez fallback) zachowuje sie inaczej ────────────
    //
    // W plain ENSRegistry setOwner(node, address(0)) zapisuje address(0)
    // bezposrednio - authorised() tez widzi address(0) - spójne.
    // ENSRegistryWithFallback psuje te spójnosc przez sentinel.
    //
    // PASS = plain registry jest spójny
    // Kontrast z MEDIUM-1 pokazuje ze to regresja w fallback wersji

    function test_MEDIUM2_PlainRegistryIsConsistent() public {
        // Uzyj plain ENSRegistry bez sentinela
        ENSRegistry plain = new ENSRegistry();
        plain.setSubnodeOwner(ZERO_HASH, keccak256(abi.encodePacked("eth")), ETH_TLD_MGR);
        vm.startPrank(ETH_TLD_MGR);
        plain.setSubnodeOwner(ethNode, keccak256(abi.encodePacked("alice")), ALICE);
        vm.stopPrank();

        vm.startPrank(ALICE);
        plain.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // owner() zwraca address(0) - tak samo jak w fallback wersji
        require(plain.owner(aliceNode) == address(0), "plain: owner() must be address(0)");

        // ALE w plain registry authorised jest spójny z owner():
        // records[node].owner = address(0) = address(0) → require(0 == msg.sender) → revert
        // To tez revertuje, ale Z INNEGO POWODU: address(0) != ALICE
        // W plain registry "nikt nie jest wlascicielem" jest prawda
        // W fallback registry "nikt nie jest wlascicielem" jest kłamstwem - sentinel tam siedzi

        // Kluczowy dowód: recordExists zachowuje sie inaczej
        bool plainExists    = plain.recordExists(aliceNode);  // false - node naprawde wyczyszczony
        bool fallbackExists = reg.recordExists(aliceNode);    // zobaczymy po zombie-lock w MEDIUM-1

        // Zombie-lock aliceNode w fallback registry zeby porownac
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        fallbackExists = reg.recordExists(aliceNode);

        // plain: recordExists == false (node naprawde usuniety)
        require(!plainExists, "MEDIUM-2: plain registry clears record correctly");

        // fallback: recordExists == true (zombie sentinel - node nie jest usuniety)
        require(fallbackExists, "MEDIUM-2: fallback registry leaves zombie - inconsistent with plain");
    }

    // ── MEDIUM-3: resolver ustawiony przed zombie-lock jest niedostepny ────────
    //
    // Alice ustawia resolver dla alice.eth, potem zombie-lockuje.
    // owner() zwraca address(0) - wyglada jakby node nie istnial.
    // Ale resolver() DALEJ zwraca stara wartosc z nowego registry
    // (bo recordExists == true blokuje fallback i czyta surowy storage).
    // Node wyglada martwy ale przechowuje dane - kolejna niespójnosc.
    //
    // FAIL = dane sa dostepne mimo ze node wyglada na usuniety

    function test_MEDIUM3_NodeAppearsDeadButStillHoldsData() public {
        // Alice ustawia resolver
        vm.startPrank(ALICE);
        reg.setResolver(aliceNode, RESOLVER_A);
        vm.stopPrank();

        require(reg.resolver(aliceNode) == RESOLVER_A, "setup: resolver must be set");

        // Alice zombie-lockuje
        vm.startPrank(ALICE);
        reg.setOwner(aliceNode, address(0));
        vm.stopPrank();

        // owner() mowi: brak wlasciciela - wyglada jakby node nie istnial
        require(reg.owner(aliceNode) == address(0), "MEDIUM-3: node appears dead");

        // Ale resolver() dalej zwraca dane - node nie jest naprawde martwy
        // W spojnym systemie: jesli owner()==0 i recordExists()==false,
        // resolver tez powinien zwracac 0 (lub dane z old registry przez fallback)
        // BUG: resolver zwraca RESOLVER_A mimo ze node "nie istnieje"
        // Ta niespójnosc sprawia ze node jest w stanie zombie:
        // wyglada usuniety, ale dane wciaz tam sa i sa readonly
        require(
            reg.resolver(aliceNode) != RESOLVER_A,
            "MEDIUM-3 CONFIRMED: resolver() returns stale data on a node that appears unowned"
        );
    }
}
