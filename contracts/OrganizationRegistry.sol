// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfaccia minima
interface IAuditRegistryForOrganizations {
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
 * @title OrganizationRegistry
 * @dev Registro delle organizzazioni abilitate alla governance.
 *
 * Risoluzione del problema admin:
 * - bootstrapAdmin serve solo per inizializzare il prototipo;
 * - dopo il bootstrap, le modifiche sulle organizzazioni possono essere eseguite
 *   solo dal contratto PolicyGovernance dopo proposta, voto e quorum.
 */
contract OrganizationRegistry {
    //Organizzazione registrata
    struct OrganizationRecord {
        address organizationAddress;
        bytes32 organizationCID;
        DataTypes.OrganizationStatus status;
        uint256 createdAt;
        uint256 updatedAt;
    }

    address public immutable bootstrapAdmin;
    address public governanceContract;
    bool public bootstrapLocked;

    IAuditRegistryForOrganizations public auditRegistry;

    mapping(address => OrganizationRecord) private organizations;
    address[] private organizationList;

    //numero corrente organizzazioni attive
    uint256 public activeOrganizationCount;

    event OrganizationAdded(
        address indexed organization,
        bytes32 organizationCID
    );

    event OrganizationSuspended(
        address indexed organization
    );

    event OrganizationRevoked(
        address indexed organization
    );

    event OrganizationReactivated(
        address indexed organization
    );

    event GovernanceContractSet(
        address indexed governanceContract
    );

    event BootstrapLocked(uint256 timestamp);

    //limita alcune funzioni solo al bootstrap admin
    modifier onlyBootstrapAdmin() {
        require(msg.sender == bootstrapAdmin, "Only bootstrap admin");
        _;
    }

    //consente le modifiche durante il bootstrap o dopo il bootstrap solo dalla governance
    modifier onlyBootstrapOrGovernance() {
        bool duringBootstrap = !bootstrapLocked && msg.sender == bootstrapAdmin;
        bool byGovernance = governanceContract != address(0) && msg.sender == governanceContract;

        require(duringBootstrap || byGovernance, "Not authorized");
        _;
    }

    constructor(address auditRegistryAddress) {
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        bootstrapAdmin = msg.sender;
        auditRegistry = IAuditRegistryForOrganizations(auditRegistryAddress);
    }

    //configurazione del contratto di governance
    function setGovernanceContract(
        address governanceContractAddress
    ) external onlyBootstrapAdmin {
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

    //registra una nuova organizzazione
    function addOrganization(
        address organizationAddress,
        bytes32 organizationCID
    ) external onlyBootstrapOrGovernance {
        require(organizationAddress != address(0), "Invalid organization");
        require(organizationCID != bytes32(0), "Invalid organizationCID");

        require(
            organizations[organizationAddress].status == DataTypes.OrganizationStatus.None,
            "Organization already exists"
        );

        organizations[organizationAddress] = OrganizationRecord({
            organizationAddress: organizationAddress,
            organizationCID: organizationCID,
            status: DataTypes.OrganizationStatus.Active,
            createdAt: block.timestamp,
            updatedAt: block.timestamp
        });

        organizationList.push(organizationAddress);
        activeOrganizationCount += 1;

        emit OrganizationAdded(organizationAddress, organizationCID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            bytes32(uint256(uint160(organizationAddress))),
            DataTypes.TARGET_ORGANIZATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_ORGANIZATION_ADDED
        );
    }

    //sospende un'organizzazione attiva
    function suspendOrganization(
        address organizationAddress
    ) external onlyBootstrapOrGovernance {
        OrganizationRecord storage record = organizations[organizationAddress];

        require(
            record.status == DataTypes.OrganizationStatus.Active,
            "Organization not active"
        );

        record.status = DataTypes.OrganizationStatus.Suspended;
        record.updatedAt = block.timestamp;

        activeOrganizationCount -= 1;

        emit OrganizationSuspended(organizationAddress);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            bytes32(uint256(uint160(organizationAddress))),
            DataTypes.TARGET_ORGANIZATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_ORGANIZATION_SUSPENDED
        );
    }

    //revoca un'organizzazione escludendola stabilmente
    function revokeOrganization(
        address organizationAddress
    ) external onlyBootstrapOrGovernance {
        OrganizationRecord storage record = organizations[organizationAddress];

        require(
            record.status == DataTypes.OrganizationStatus.Active ||
            record.status == DataTypes.OrganizationStatus.Suspended,
            "Organization not revocable"
        );

        if (record.status == DataTypes.OrganizationStatus.Active) {
            activeOrganizationCount -= 1;
        }

        record.status = DataTypes.OrganizationStatus.Revoked;
        record.updatedAt = block.timestamp;

        emit OrganizationRevoked(organizationAddress);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            bytes32(uint256(uint160(organizationAddress))),
            DataTypes.TARGET_ORGANIZATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_ORGANIZATION_REVOKED
        );
    }

    //riattiva un'organizzazione sospesa
    function reactivateOrganization(
        address organizationAddress
    ) external onlyBootstrapOrGovernance {
        OrganizationRecord storage record = organizations[organizationAddress];

        require(
            record.status == DataTypes.OrganizationStatus.Suspended,
            "Organization not suspended"
        );

        record.status = DataTypes.OrganizationStatus.Active;
        record.updatedAt = block.timestamp;

        activeOrganizationCount += 1;

        emit OrganizationReactivated(organizationAddress);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            bytes32(uint256(uint160(organizationAddress))),
            DataTypes.TARGET_ORGANIZATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_ORGANIZATION_REACTIVATED
        );
    }

    function isActiveOrganization(
        address organizationAddress
    ) external view returns (bool) {
        return organizations[organizationAddress].status == DataTypes.OrganizationStatus.Active;
    }

    function getOrganization(
        address organizationAddress
    ) external view returns (OrganizationRecord memory) {
        require(
            organizations[organizationAddress].status != DataTypes.OrganizationStatus.None,
            "Organization not found"
        );

        return organizations[organizationAddress];
    }

    function getOrganizationCount() external view returns (uint256) {
        return organizationList.length;
    }

    function getOrganizationAt(uint256 index) external view returns (address) {
        require(index < organizationList.length, "Index out of bounds");

        return organizationList[index];
    }
}