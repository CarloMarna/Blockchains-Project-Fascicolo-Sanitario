// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IIdentityRegistryForTrust {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface IOrganizationRegistryForTrust {
    function isActiveOrganization(address organizationAddress) external view returns (bool);
}

interface IAuditRegistryForTrust {
    function logEvent(
        address actor,
        bytes32 action,
        bytes32 targetId,
        bytes32 targetType,
        bytes32 result,
        bytes32 reasonCode
    ) external;
}

/**
 * @title TrustRegistry
 * @dev Registry degli issuer fidati per tipo di VC.
 *
 * Un DID issuer è autorizzabile solo se:
 * - il DID è attivo nell'IdentityRegistry;
 * - il controller Ethereum del DID è una organizzazione attiva.
 */
contract TrustRegistry {
    address public immutable bootstrapAdmin;
    address public governanceContract;
    bool public bootstrapLocked;

    IIdentityRegistryForTrust public identityRegistry;
    IOrganizationRegistryForTrust public organizationRegistry;
    IAuditRegistryForTrust public auditRegistry;

    // Associa ogni coppia issuer DID/tipo credenziale allo stato di issuer fidato
    mapping(bytes32 => mapping(bytes32 => bool)) private trustedIssuerForType;

    event GovernanceContractSet(address indexed governanceContract);
    event BootstrapLocked(uint256 timestamp);

    // Evento emesso quando un issuer DID viene autorizzato per uno specifico tipo di credenziale
    event TrustedIssuerAuthorized(
        bytes32 indexed issuerDID,
        bytes32 indexed credentialType,
        address indexed controller
    );
    // Evento emesso quando viene revocata l'autorizzazione di un issuer per uno specifico tipo di credenziale
    event TrustedIssuerRevoked(
        bytes32 indexed issuerDID,
        bytes32 indexed credentialType,
        address indexed revokedBy
    );

    modifier onlyBootstrapAdmin() {
        require(msg.sender == bootstrapAdmin, "Only bootstrap admin");
        _;
    }

    modifier onlyBootstrapOrGovernance() {
        bool duringBootstrap = !bootstrapLocked && msg.sender == bootstrapAdmin;
        bool byGovernance = governanceContract != address(0) && msg.sender == governanceContract;
        require(duringBootstrap || byGovernance, "Not authorized");
        _;
    }

    constructor(
        address identityRegistryAddress,
        address organizationRegistryAddress,
        address auditRegistryAddress
    ) {
        require(identityRegistryAddress != address(0), "Invalid identity registry");
        require(organizationRegistryAddress != address(0), "Invalid organization registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        bootstrapAdmin = msg.sender;
        identityRegistry = IIdentityRegistryForTrust(identityRegistryAddress);
        organizationRegistry = IOrganizationRegistryForTrust(organizationRegistryAddress);
        auditRegistry = IAuditRegistryForTrust(auditRegistryAddress);
    }

    // Configura il contratto di governance autorizzato a gestire il trust dopo il bootstrap
    function setGovernanceContract(address governanceContractAddress) external onlyBootstrapAdmin {
        require(!bootstrapLocked, "Bootstrap locked");
        require(governanceContractAddress != address(0), "Invalid governance contract");

        governanceContract = governanceContractAddress;
        emit GovernanceContractSet(governanceContractAddress);
    }

    function lockBootstrap() external onlyBootstrapAdmin {
        require(!bootstrapLocked, "Already locked");
        bootstrapLocked = true;
        emit BootstrapLocked(block.timestamp);
    }

    // Autorizza un issuer DID come fidato per uno specifico tipo di credenziale
    function authorizeIssuer(
        bytes32 issuerDID,
        bytes32 credentialType
    ) external onlyBootstrapOrGovernance {
        require(issuerDID != bytes32(0), "Invalid issuer DID");
        require(credentialType != bytes32(0), "Invalid credential type");
        require(identityRegistry.isActiveDID(issuerDID), "Issuer DID inactive");

        address issuerController = identityRegistry.controllerOf(issuerDID);
        require(
            organizationRegistry.isActiveOrganization(issuerController),
            "Issuer controller is not active organization"
        );

        trustedIssuerForType[issuerDID][credentialType] = true;

        emit TrustedIssuerAuthorized(issuerDID, credentialType, issuerController);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            keccak256(abi.encode(issuerDID, credentialType)),
            DataTypes.TARGET_TRUST,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_TRUSTED_ISSUER_AUTHORIZED
        );
    }

    // Revoca l’autorizzazione di un issuer DID per uno specifico tipo di credenziale
    function revokeIssuerAuthorization(
        bytes32 issuerDID,
        bytes32 credentialType
    ) external onlyBootstrapOrGovernance {
        require(trustedIssuerForType[issuerDID][credentialType], "Issuer not trusted");

        trustedIssuerForType[issuerDID][credentialType] = false;

        emit TrustedIssuerRevoked(issuerDID, credentialType, msg.sender);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            keccak256(abi.encode(issuerDID, credentialType)),
            DataTypes.TARGET_TRUST,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_TRUSTED_ISSUER_REVOKED
        );
    }

    function isTrustedIssuer(
        bytes32 issuerDID,
        bytes32 credentialType
    ) external view returns (bool) {
        return trustedIssuerForType[issuerDID][credentialType];
    }
}
