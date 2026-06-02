// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IIdentityRegistryForDocuments {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface IPolicyRegistryForDocuments {
    function canPerformWithCredential(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentType,
        bytes32 action
    ) external view returns (bool);
}

interface IAuditRegistryForDocuments {
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
 * @title DocumentLifecycleRegistry
 * @dev Lifecycle documentale integrato con DID e credenziale presentata.
 *
 * Il documento resta off-chain/IPFS. On-chain sono salvati CID, stato,
 * versioni e DID del paziente/creator. La VC non viene salvata on-chain:
 * il creator presenta solo la porzione selettivamente rivelata necessaria.
 */
contract DocumentLifecycleRegistry {

    //Rappresenta una versione documentale
    struct DocumentRecord {
        bytes32 documentId;
        bytes32 patientDID;
        bytes32 creatorDID;
        bytes32 documentType;
        string CID;
        DataTypes.DocumentState state;
        uint256 versionNumber;
        uint256 previousVersionPointer;
        uint256 creationTimestamp;
    }

    IIdentityRegistryForDocuments public identityRegistry;
    IPolicyRegistryForDocuments public policyRegistry;
    IAuditRegistryForDocuments public auditRegistry;

    mapping(bytes32 => bool) public documentExists;
    mapping(bytes32 => uint256) public currentVersion;
    //Archivio delle versioni documentali indicizzate per documentId
    mapping(bytes32 => mapping(uint256 => DocumentRecord)) private documentVersions;

    event DocumentCreated(
        bytes32 indexed documentId,
        bytes32 indexed patientDID,
        bytes32 indexed creatorDID,
        bytes32 documentType,
        string CID,
        uint256 version
    );

    event DocumentVersionCreated(
        bytes32 indexed documentId,
        uint256 previousVersion,
        uint256 newVersion,
        string newCID
    );

    event DocumentRevoked(
        bytes32 indexed documentId,
        uint256 version,
        bytes32 indexed revokedByDID,
        address revokedByController
    );

    constructor(
        address identityRegistryAddress,
        address policyRegistryAddress,
        address auditRegistryAddress
    ) {
        require(identityRegistryAddress != address(0), "Invalid identity registry");
        require(policyRegistryAddress != address(0), "Invalid policy registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        identityRegistry = IIdentityRegistryForDocuments(identityRegistryAddress);
        policyRegistry = IPolicyRegistryForDocuments(policyRegistryAddress);
        auditRegistry = IAuditRegistryForDocuments(auditRegistryAddress);
    }

    // Crea la prima versione certificata di un documento associato a paziente, creator, tipo e CID
    function createDocument(
        bytes32 documentId,
        bytes32 patientDID,
        bytes32 creatorDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentType,
        string calldata CID
    ) external {
        require(documentId != bytes32(0), "Invalid documentId");
        require(patientDID != bytes32(0), "Invalid patientDID");
        require(creatorDID != bytes32(0), "Invalid creatorDID");
        require(documentType != bytes32(0), "Invalid documentType");
        require(bytes(CID).length != 0, "Invalid CID");
        require(!documentExists[documentId], "Document already exists");

        require(identityRegistry.isActiveDID(patientDID), "Patient DID inactive");
        require(identityRegistry.isActiveDID(creatorDID), "Creator DID inactive");
        require(identityRegistry.controllerOf(creatorDID) == msg.sender, "Not creator controller");

        require(
            policyRegistry.canPerformWithCredential(
                creatorDID,
                presentedCredential,
                documentType,
                DataTypes.ACTION_CREATE
            ),
            "Not authorized to create"
        );

        uint256 version = 1;
        documentExists[documentId] = true;
        currentVersion[documentId] = version;

        documentVersions[documentId][version] = DocumentRecord({
            documentId: documentId,
            patientDID: patientDID,
            creatorDID: creatorDID,
            documentType: documentType,
            CID: CID,
            state: DataTypes.DocumentState.Certified,
            versionNumber: version,
            previousVersionPointer: 0,
            creationTimestamp: block.timestamp
        });

        emit DocumentCreated(documentId, patientDID, creatorDID, documentType, CID, version);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            documentId,
            DataTypes.TARGET_DOCUMENT,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DOCUMENT_CREATED
        );
    }

    // Crea una nuova versione del documento archiviando la versione corrente certificata
    function createNewVersion(
        bytes32 documentId,
        bytes32 creatorDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        string calldata newCID
    ) external {
        require(documentExists[documentId], "Document does not exist");
        require(creatorDID != bytes32(0), "Invalid creatorDID");
        require(bytes(newCID).length != 0, "Invalid CID");
        require(identityRegistry.isActiveDID(creatorDID), "Creator DID inactive");
        require(identityRegistry.controllerOf(creatorDID) == msg.sender, "Not creator controller");

        uint256 oldVersion = currentVersion[documentId];
        DocumentRecord storage current = documentVersions[documentId][oldVersion];

        require(current.state == DataTypes.DocumentState.Certified, "Current version not certified");

        require(
            policyRegistry.canPerformWithCredential(
                creatorDID,
                presentedCredential,
                current.documentType,
                DataTypes.ACTION_UPDATE
            ),
            "Not authorized to update"
        );

        current.state = DataTypes.DocumentState.Archived;

        uint256 newVersion = oldVersion + 1;

        documentVersions[documentId][newVersion] = DocumentRecord({
            documentId: documentId,
            patientDID: current.patientDID,
            creatorDID: creatorDID,
            documentType: current.documentType,
            CID: newCID,
            state: DataTypes.DocumentState.Certified,
            versionNumber: newVersion,
            previousVersionPointer: oldVersion,
            creationTimestamp: block.timestamp
        });

        currentVersion[documentId] = newVersion;

        emit DocumentVersionCreated(documentId, oldVersion, newVersion, newCID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            documentId,
            DataTypes.TARGET_DOCUMENT,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DOCUMENT_VERSION_CREATED
        );
    }

    // Revoca la versione corrente del documento se il richiedente è autorizzato dalla policy globale
    function revokeDocument(
        bytes32 documentId,
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential
    ) external {
        require(documentExists[documentId], "Document does not exist");
        require(requesterDID != bytes32(0), "Invalid requester DID");
        require(identityRegistry.isActiveDID(requesterDID), "Requester DID inactive");
        require(identityRegistry.controllerOf(requesterDID) == msg.sender, "Not requester controller");

        uint256 version = currentVersion[documentId];
        DocumentRecord storage current = documentVersions[documentId][version];

        require(current.state == DataTypes.DocumentState.Certified, "Document not active");

        require(requesterDID != current.patientDID, "Patient cannot revoke documents");

        bool canRevoke = policyRegistry.canPerformWithCredential(
            requesterDID,
            presentedCredential,
            current.documentType,
            DataTypes.ACTION_REVOKE
        );

        require(canRevoke, "Not authorized to revoke");

        current.state = DataTypes.DocumentState.Revoked;

        emit DocumentRevoked(documentId, version, requesterDID, msg.sender);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            documentId,
            DataTypes.TARGET_DOCUMENT,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DOCUMENT_REVOKED
        );
    }

    function getCurrentDocument(bytes32 documentId) external view returns (DocumentRecord memory) {
        require(documentExists[documentId], "Document does not exist");
        return documentVersions[documentId][currentVersion[documentId]];
    }

    function getDocumentVersion(
        bytes32 documentId,
        uint256 version
    ) external view returns (DocumentRecord memory) {
        require(documentExists[documentId], "Document does not exist");
        require(version > 0, "Invalid version");
        require(version <= currentVersion[documentId], "Version does not exist");
        return documentVersions[documentId][version];
    }

    // Verifica che il CID fornito coincida con quello registrato per una specifica versione
    function verifyCID(
        bytes32 documentId,
        uint256 version,
        string calldata CID
    ) external view returns (bool) {
        if (!documentExists[documentId]) {
            return false;
        }

        if (version == 0 || version > currentVersion[documentId]) {
            return false;
        }

        return keccak256(abi.encodePacked(documentVersions[documentId][version].CID))
            == keccak256(abi.encodePacked(CID));
    }

    function isDocumentActive(bytes32 documentId) external view returns (bool) {
        if (!documentExists[documentId]) {
            return false;
        }

        return documentVersions[documentId][currentVersion[documentId]].state
            == DataTypes.DocumentState.Certified;
    }

    function getPatientDID(bytes32 documentId) external view returns (bytes32) {
        require(documentExists[documentId], "Document does not exist");
        return documentVersions[documentId][currentVersion[documentId]].patientDID;
    }

    function getDocumentType(bytes32 documentId) external view returns (bytes32) {
        require(documentExists[documentId], "Document does not exist");
        return documentVersions[documentId][currentVersion[documentId]].documentType;
    }

    function getCurrentCID(bytes32 documentId) external view returns (string memory) {
        require(documentExists[documentId], "Document does not exist");
        return documentVersions[documentId][currentVersion[documentId]].CID;
    }
}
