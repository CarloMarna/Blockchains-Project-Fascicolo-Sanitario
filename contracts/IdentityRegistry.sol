// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfaccia minima
interface IAuditRegistryForIdentities {
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
 * @title IdentityRegistry
 * @dev Registry DID coerente con il WP2.
 *
 * Il DID Document completo resta off-chain. Sul ledger vengono salvati solo:
 * - DID canonico come bytes32;
 * - controller Ethereum;
 * - CID/hash del DID Document off-chain;
 * - stato e versione.
 */
contract IdentityRegistry {

    //Identità DID registrata on chain
    struct DIDRecord {
        bytes32 did;
        address controller;
        bytes32 didDocumentCID;
        bytes32 didDocumentHash;
        DataTypes.DIDStatus status;
        uint256 version;
        uint256 createdAt;
        uint256 updatedAt;
        uint256 deactivatedAt;
    }

    IAuditRegistryForIdentities public auditRegistry;

    mapping(bytes32 => DIDRecord) private records;
    mapping(bytes32 => bool) public didExists;
    //associa ogni controller Etherum al proprio DID
    mapping(address => bytes32) private didByController;

    event DIDRegistered(
        bytes32 indexed did,
        address indexed controller,
        bytes32 didDocumentCID,
        bytes32 didDocumentHash,
        uint256 version
    );

    event DIDDocumentUpdated(
        bytes32 indexed did,
        address indexed controller,
        bytes32 didDocumentCID,
        bytes32 didDocumentHash,
        uint256 version
    );

    event DIDDeactivated(
        bytes32 indexed did,
        address indexed controller,
        uint256 deactivatedAt
    );

    //la funzione può essere eseguita solo dal controller del DID
    modifier onlyController(bytes32 did) {
        require(didExists[did], "DID not found");
        require(records[did].controller == msg.sender, "Not DID controller");
        _;
    }

    constructor(address auditRegistryAddress) {
        require(auditRegistryAddress != address(0), "Invalid audit registry");
        auditRegistry = IAuditRegistryForIdentities(auditRegistryAddress);
    }

    // Registra un nuovo DID associandolo al controller chiamante e al riferimento del DID Document off-chain
    function registerDID(
        bytes32 did,
        bytes32 didDocumentCID,
        bytes32 didDocumentHash
    ) external {
        require(did != bytes32(0), "Invalid DID");
        require(didDocumentCID != bytes32(0), "Invalid DID document CID");
        require(didDocumentHash != bytes32(0), "Invalid DID document hash");
        require(!didExists[did], "DID already registered");
        require(didByController[msg.sender] == bytes32(0), "Controller already has DID");

        records[did] = DIDRecord({
            did: did,
            controller: msg.sender,
            didDocumentCID: didDocumentCID,
            didDocumentHash: didDocumentHash,
            status: DataTypes.DIDStatus.Active,
            version: 1,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            deactivatedAt: 0
        });

        didExists[did] = true;
        didByController[msg.sender] = did;

        emit DIDRegistered(
            did,
            msg.sender,
            didDocumentCID,
            didDocumentHash,
            1
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            did,
            DataTypes.TARGET_IDENTITY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DID_REGISTERED
        );
    }

    //Aggiorna versione e riferimento a DID Document
    function updateDIDDocument(
        bytes32 did,
        bytes32 newDIDDocumentCID,
        bytes32 newDIDDocumentHash
    ) external onlyController(did) {
        require(isActiveDID(did), "DID inactive");
        require(newDIDDocumentCID != bytes32(0), "Invalid DID document CID");
        require(newDIDDocumentHash != bytes32(0), "Invalid DID document hash");

        DIDRecord storage record = records[did];
        record.didDocumentCID = newDIDDocumentCID;
        record.didDocumentHash = newDIDDocumentHash;
        record.version += 1;
        record.updatedAt = block.timestamp;

        emit DIDDocumentUpdated(
            did,
            msg.sender,
            newDIDDocumentCID,
            newDIDDocumentHash,
            record.version
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            did,
            DataTypes.TARGET_IDENTITY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DID_UPDATED
        );
    }

    function deactivateDID(bytes32 did) external onlyController(did) {
        require(isActiveDID(did), "DID inactive");

        DIDRecord storage record = records[did];
        record.status = DataTypes.DIDStatus.Deactivated;
        record.updatedAt = block.timestamp;
        record.deactivatedAt = block.timestamp;

        emit DIDDeactivated(did, msg.sender, block.timestamp);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            did,
            DataTypes.TARGET_IDENTITY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DID_DEACTIVATED
        );
    }

    //restrituisce il record completo associato al DID registrato
    function resolveDID(bytes32 did) external view returns (DIDRecord memory) {
        require(didExists[did], "DID not found");
        return records[did];
    }

    function isActiveDID(bytes32 did) public view returns (bool) {
        return didExists[did] && records[did].status == DataTypes.DIDStatus.Active;
    }

    function controllerOf(bytes32 did) public view returns (address) {
        if (!didExists[did]) {
            return address(0);
        }

        return records[did].controller;
    }

    function didOfController(address controller) external view returns (bytes32) {
        return didByController[controller];
    }

    function isController(bytes32 did, address account) external view returns (bool) {
        return didExists[did] && records[did].controller == account;
    }
}
