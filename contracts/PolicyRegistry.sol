// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IOrganizationRegistryForPolicies {
    function isActiveOrganization(address organizationAddress) external view returns (bool);
}

interface ICredentialStatusRegistryForPolicies {
    function isPresentedCredentialValidForSubject(
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 subjectDID
    ) external view returns (bool);
}

interface IAuditRegistryForPolicies {
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
 * @title PolicyRegistry
 * @dev Policy registry con ruoli derivati dalla VC presentata.
 *
 * La policy riceve una credenziale presentata in formato SD-JWT.
 * Il CredentialStatusRegistry deriva da stringhe i riferimenti on-chain:
 * - credentialId = keccak256(id);
 * - issuerDID = keccak256(issuer);
 * - subjectDID = keccak256(subject);
 * - credentialType = keccak256(credentialType).
 * La verifica crittografica della SD-JWT resta off-chain nel verifier/wallet;
 * on-chain si applicano stato, revoca, trust issuer, holder binding e policy.
 */
contract PolicyRegistry {
    address public immutable bootstrapAdmin;
    address public governanceContract;
    bool public bootstrapLocked;

    // Profondità massima corrente delle catene di delega
    uint256 public maxDelegationDepth;
    //Profondità massima consentita
    uint256 public constant ABSOLUTE_MAX_DELEGATION_DEPTH = 10;

    IOrganizationRegistryForPolicies public organizationRegistry;
    ICredentialStatusRegistryForPolicies public credentialRegistry;
    IAuditRegistryForPolicies public auditRegistry;

    // Mapping tra tipo di credenziale VC e ruolo applicativo derivato
    mapping(bytes32 => DataTypes.Role) private credentialTypeRoles;
    // Matrice delle autorizzazioni: role => documentType => action => allowed
    mapping(DataTypes.Role => mapping(bytes32 => mapping(bytes32 => bool))) private permissions;

    // Evento emesso quando un tipo di credenziale viene associato a un ruolo applicativo
    event CredentialTypeRoleSet(
        bytes32 indexed credentialType,
        DataTypes.Role role,
        address indexed setBy
    );

    // Evento emesso quando una policy globale viene impostata tramite governance
    event PermissionSet(
        DataTypes.Role role,
        bytes32 indexed documentType,
        bytes32 indexed action,
        bool allowed,
        bytes32 policyCID
    );

    event GovernanceContractSet(address indexed governanceContract);
    event BootstrapLocked(uint256 timestamp);

    event MaxDelegationDepthUpdated(
        uint256 oldValue,
        uint256 newValue,
        bytes32 policyCID
    );

    modifier onlyBootstrapAdmin() {
        require(msg.sender == bootstrapAdmin, "Only bootstrap admin");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governanceContract, "Only governance");
        _;
    }

    constructor(
        address organizationRegistryAddress,
        address credentialRegistryAddress,
        address auditRegistryAddress
    ) {
        require(organizationRegistryAddress != address(0), "Invalid organization registry");
        require(credentialRegistryAddress != address(0), "Invalid credential registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        bootstrapAdmin = msg.sender;
        maxDelegationDepth = 1;
        organizationRegistry = IOrganizationRegistryForPolicies(organizationRegistryAddress);
        credentialRegistry = ICredentialStatusRegistryForPolicies(credentialRegistryAddress);
        auditRegistry = IAuditRegistryForPolicies(auditRegistryAddress);
    }

    // Configura il contratto di governance autorizzato a modificare le policy dopo il bootstrap
    function setGovernanceContract(address governanceContractAddress) external onlyBootstrapAdmin {
        require(!bootstrapLocked, "Bootstrap locked");
        require(governanceContractAddress != address(0), "Invalid governance contract");

        governanceContract = governanceContractAddress;
        emit GovernanceContractSet(governanceContractAddress);
    }

    function lockBootstrap() external onlyBootstrapAdmin {
        require(governanceContract != address(0), "Governance not set");
        require(!bootstrapLocked, "Already locked");

        bootstrapLocked = true;
        emit BootstrapLocked(block.timestamp);
    }

    // Associa un tipo di credenziale a un ruolo applicativo durante la sola fase di bootstrap
    function setCredentialTypeRole(
        bytes32 credentialType,
        DataTypes.Role role
    ) external onlyBootstrapAdmin {
        require(!bootstrapLocked, "Bootstrap locked");
        require(credentialType != bytes32(0), "Invalid credential type");
        require(role != DataTypes.Role.None, "Invalid role");

        credentialTypeRoles[credentialType] = role;

        emit CredentialTypeRoleSet(credentialType, role, msg.sender);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            credentialType,
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_CREDENTIAL_TYPE_ROLE_SET
        );
    }

    // Imposta una policy globale di accesso dopo approvazione del processo di governance
    function setPermissionFromGovernance(
        DataTypes.Role role,
        bytes32 documentType,
        bytes32 action,
        bool allowed,
        bytes32 policyCID
    ) external onlyGovernance {
        require(role != DataTypes.Role.None, "Invalid role");
        require(documentType != bytes32(0), "Invalid documentType");
        require(action != bytes32(0), "Invalid action");
        require(policyCID != bytes32(0), "Invalid policyCID");

        permissions[role][documentType][action] = allowed;

        emit PermissionSet(role, documentType, action, allowed, policyCID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            policyCID,
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_POLICY_EXECUTED
        );
    }

    function setMaxDelegationDepthFromGovernance(
        uint256 newMaxDelegationDepth,
        bytes32 policyCID
    ) external onlyGovernance {
        require(newMaxDelegationDepth > 0, "Invalid depth");
        require(newMaxDelegationDepth <= ABSOLUTE_MAX_DELEGATION_DEPTH, "Depth too high");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 oldValue = maxDelegationDepth;
        maxDelegationDepth = newMaxDelegationDepth;

        emit MaxDelegationDepthUpdated(oldValue, newMaxDelegationDepth, policyCID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            policyCID,
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_POLICY_EXECUTED
        );
    }

    function getCredentialTypeRole(bytes32 credentialType) external view returns (DataTypes.Role) {
        return credentialTypeRoles[credentialType];
    }

    // Verifica se il DID richiedente, tramite la credenziale presentata, può eseguire l’azione richiesta
    function canPerformWithCredential(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentType,
        bytes32 action
    ) public view returns (bool) {
        if (requesterDID == bytes32(0) || bytes(presentedCredential.id).length == 0) {
            return false;
        }

        if (!credentialRegistry.isPresentedCredentialValidForSubject(presentedCredential, requesterDID)) {
            return false;
        }

        bytes32 credentialType = keccak256(bytes(presentedCredential.credentialType));
        DataTypes.Role role = credentialTypeRoles[credentialType];

        if (role == DataTypes.Role.None) {
            return false;
        }

        return permissions[role][documentType][action];
    }

    // Verifica direttamente se un ruolo può eseguire una certa azione su un tipo documentale
    function canRolePerform(
        DataTypes.Role role,
        bytes32 documentType,
        bytes32 action
    ) external view returns (bool) {
        return permissions[role][documentType][action];
    }
}
