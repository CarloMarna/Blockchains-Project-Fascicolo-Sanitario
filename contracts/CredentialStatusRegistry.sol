// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IIdentityRegistryForCredentials {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface ITrustRegistryForCredentials {
    function isTrustedIssuer(bytes32 issuerDID, bytes32 credentialType) external view returns (bool);
}

interface IAuditRegistryForCredentials {
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
 * @title CredentialStatusRegistry
 * @dev Registry dello stato delle VC.
 *
 * Il registro conserva solo lo stato minimo necessario a revoca/sospensione:
 * - credentialId;
 * - issuerDID;
 * - credentialType;
 * - stato e validita' temporale.
 *
 * Il subjectDID e gli attributi arrivano dalla credenziale presentata
 * con selective disclosure e vengono verificati contro la firma dell'issuer.
 */
contract CredentialStatusRegistry {
    // Stato minimo on-chain di una VC, senza memorizzare il contenuto completo della credenziale
    struct CredentialStatus {
        bytes32 credentialId;
        bytes32 issuerDID;
        bytes32 credentialType;
        DataTypes.CredentialState state;
        uint256 validFrom;
        uint256 validUntil;
        uint256 issuedAt;
        uint256 updatedAt;
        uint256 revokedAt;
    }

    IIdentityRegistryForCredentials public identityRegistry;
    ITrustRegistryForCredentials public trustRegistry;
    IAuditRegistryForCredentials public auditRegistry;

    //mapping id credenziale -> stato credenziale
    mapping(bytes32 => CredentialStatus) private credentials;
    //mapping id credenziale -> bool registrazione
    mapping(bytes32 => bool) public credentialExists;
    //mapping issuerDID -> credenziali emesse
    mapping(bytes32 => bytes32[]) private credentialsByIssuer;

    // Evento emesso quando viene registrato lo stato iniziale di una nuova credenziale
    event CredentialIssued(
        bytes32 indexed credentialId,
        bytes32 indexed issuerDID,
        bytes32 indexed credentialType,
        uint256 validFrom,
        uint256 validUntil
    );

    // Evento emesso quando una credenziale attiva viene sospesa dall’issuer
    event CredentialSuspended(bytes32 indexed credentialId, bytes32 indexed issuerDID);
    // Evento emesso quando una credenziale sospesa viene riattivata dall’issuer
    event CredentialReactivated(bytes32 indexed credentialId, bytes32 indexed issuerDID);
    // Evento emesso quando una credenziale viene revocata definitivamente dall’issuer
    event CredentialRevoked(bytes32 indexed credentialId, bytes32 indexed issuerDID, uint256 revokedAt);

    constructor(
        address identityRegistryAddress,
        address trustRegistryAddress,
        address auditRegistryAddress
    ) {
        require(identityRegistryAddress != address(0), "Invalid identity registry");
        require(trustRegistryAddress != address(0), "Invalid trust registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        identityRegistry = IIdentityRegistryForCredentials(identityRegistryAddress);
        trustRegistry = ITrustRegistryForCredentials(trustRegistryAddress);
        auditRegistry = IAuditRegistryForCredentials(auditRegistryAddress);
    }

    // Registra lo stato minimo on-chain di una nuova credenziale
    function issueCredentialStatus(
        bytes32 credentialId,
        bytes32 issuerDID,
        bytes32 credentialType,
        uint256 validFrom,
        uint256 validUntil
    ) external {
        _issueCredentialStatus(credentialId, issuerDID, credentialType, validFrom, validUntil);
    }

    // Alias di issueCredentialStatus mantenuto per compatibilità con gli script di deploy
    function issueCredential(
        bytes32 credentialId,
        bytes32 issuerDID,
        bytes32 credentialType,
        uint256 validFrom,
        uint256 validUntil
    ) external {
        _issueCredentialStatus(credentialId, issuerDID, credentialType, validFrom, validUntil);
    }

    // Implementa la logica comune di emissione, verificando issuer, trust, unicità e validità temporale
    function _issueCredentialStatus(
        bytes32 credentialId,
        bytes32 issuerDID,
        bytes32 credentialType,
        uint256 validFrom,
        uint256 validUntil
    ) internal {
        require(credentialId != bytes32(0), "Invalid credential id");
        require(issuerDID != bytes32(0), "Invalid issuer DID");
        require(credentialType != bytes32(0), "Invalid credential type");
        require(!credentialExists[credentialId], "Credential already exists");
        require(validUntil > validFrom, "Invalid validity interval");
        require(validUntil > block.timestamp, "Credential already expired");

        require(identityRegistry.isActiveDID(issuerDID), "Issuer DID inactive");
        require(identityRegistry.controllerOf(issuerDID) == msg.sender, "Not issuer controller");
        require(trustRegistry.isTrustedIssuer(issuerDID, credentialType), "Issuer not trusted for type");

        credentials[credentialId] = CredentialStatus({
            credentialId: credentialId,
            issuerDID: issuerDID,
            credentialType: credentialType,
            state: DataTypes.CredentialState.Active,
            validFrom: validFrom,
            validUntil: validUntil,
            issuedAt: block.timestamp,
            updatedAt: block.timestamp,
            revokedAt: 0
        });

        credentialExists[credentialId] = true;
        credentialsByIssuer[issuerDID].push(credentialId);

        emit CredentialIssued(
            credentialId,
            issuerDID,
            credentialType,
            validFrom,
            validUntil
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            credentialId,
            DataTypes.TARGET_CREDENTIAL,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_CREDENTIAL_ISSUED
        );
    }

    function suspendCredential(bytes32 credentialId) external onlyIssuerController(credentialId) {
        CredentialStatus storage credential = credentials[credentialId];
        require(credential.state == DataTypes.CredentialState.Active, "Credential not active");

        credential.state = DataTypes.CredentialState.Suspended;
        credential.updatedAt = block.timestamp;

        emit CredentialSuspended(credentialId, credential.issuerDID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            credentialId,
            DataTypes.TARGET_CREDENTIAL,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_CREDENTIAL_SUSPENDED
        );
    }

    function reactivateCredential(bytes32 credentialId) external onlyIssuerController(credentialId) {
        CredentialStatus storage credential = credentials[credentialId];
        require(credential.state == DataTypes.CredentialState.Suspended, "Credential not suspended");
        require(block.timestamp <= credential.validUntil, "Credential expired");
        require(identityRegistry.isActiveDID(credential.issuerDID), "Issuer DID inactive");
        require(trustRegistry.isTrustedIssuer(credential.issuerDID, credential.credentialType), "Issuer not trusted");

        credential.state = DataTypes.CredentialState.Active;
        credential.updatedAt = block.timestamp;

        emit CredentialReactivated(credentialId, credential.issuerDID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            credentialId,
            DataTypes.TARGET_CREDENTIAL,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_CREDENTIAL_REACTIVATED
        );
    }

    function revokeCredential(bytes32 credentialId) external onlyIssuerController(credentialId) {
        CredentialStatus storage credential = credentials[credentialId];
        require(credential.state != DataTypes.CredentialState.Revoked, "Credential already revoked");

        credential.state = DataTypes.CredentialState.Revoked;
        credential.updatedAt = block.timestamp;
        credential.revokedAt = block.timestamp;

        emit CredentialRevoked(credentialId, credential.issuerDID, block.timestamp);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            credentialId,
            DataTypes.TARGET_CREDENTIAL,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_CREDENTIAL_REVOKED
        );
    }

    function getCredential(bytes32 credentialId) external view returns (CredentialStatus memory) {
        require(credentialExists[credentialId], "Credential not found");
        return credentials[credentialId];
    }

    function getCredentialType(bytes32 credentialId) external view returns (bytes32) {
        if (!credentialExists[credentialId]) {
            return bytes32(0);
        }

        return credentials[credentialId].credentialType;
    }

    function getIssuerDID(bytes32 credentialId) external view returns (bytes32) {
        if (!credentialExists[credentialId]) {
            return bytes32(0);
        }

        return credentials[credentialId].issuerDID;
    }

    function getCredentialsByIssuer(bytes32 issuerDID) external view returns (bytes32[] memory) {
        return credentialsByIssuer[issuerDID];
    }

    // Verifica se una credenziale registrata è attiva, temporalmente valida e ancora emessa da un issuer trusted
    function isCredentialValid(bytes32 credentialId) public view returns (bool) {
        if (!credentialExists[credentialId]) {
            return false;
        }

        CredentialStatus memory credential = credentials[credentialId];

        if (credential.state != DataTypes.CredentialState.Active) {
            return false;
        }

        if (block.timestamp < credential.validFrom || block.timestamp > credential.validUntil) {
            return false;
        }

        if (!identityRegistry.isActiveDID(credential.issuerDID)) {
            return false;
        }

        if (!trustRegistry.isTrustedIssuer(credential.issuerDID, credential.credentialType)) {
            return false;
        }

        return true;
    }

    // Verifica la coerenza tra credenziale presentata, subject atteso e stato on-chain della VC
    function isPresentedCredentialValidForSubject(
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 expectedSubjectDID
    ) external view returns (bool) {
        if (expectedSubjectDID == bytes32(0)) {
            return false;
        }

        if (!_isVcSdJwt(presentedCredential.format)) {
            return false;
        }

        if (bytes(presentedCredential.id).length == 0) {
            return false;
        }

        if (bytes(presentedCredential.issuer).length == 0) {
            return false;
        }

        if (bytes(presentedCredential.subject).length == 0) {
            return false;
        }

        if (bytes(presentedCredential.credentialType).length == 0) {
            return false;
        }

        if (bytes(presentedCredential.sdJwtCredential).length == 0) {
            return false;
        }

        bytes32 credentialId = _hashString(presentedCredential.id);
        bytes32 issuerDID = _hashString(presentedCredential.issuer);
        bytes32 subjectDID = _hashString(presentedCredential.subject);
        bytes32 credentialType = _hashString(presentedCredential.credentialType);

        if (subjectDID != expectedSubjectDID) {
            return false;
        }

        if (!credentialExists[credentialId]) {
            return false;
        }

        CredentialStatus memory status = credentials[credentialId];

        if (status.issuerDID != issuerDID) {
            return false;
        }

        if (status.credentialType != credentialType) {
            return false;
        }

        if (!isCredentialValid(credentialId)) {
            return false;
        }

        if (!identityRegistry.isActiveDID(subjectDID)) {
            return false;
        }

        return true;
    }

    function presentedCredentialDigest(
        DataTypes.PresentedCredential calldata presentedCredential
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                presentedCredential.format,
                presentedCredential.id,
                presentedCredential.issuer,
                presentedCredential.subject,
                presentedCredential.credentialType,
                presentedCredential.sdJwtCredential,
                presentedCredential.selectivelyDisclosableClaims
            )
        );
    }

    function deriveCredentialId(
        DataTypes.PresentedCredential calldata presentedCredential
    ) external pure returns (bytes32) {
        return _hashString(presentedCredential.id);
    }

    function deriveIssuerDID(
        DataTypes.PresentedCredential calldata presentedCredential
    ) external pure returns (bytes32) {
        return _hashString(presentedCredential.issuer);
    }

    function deriveSubjectDID(
        DataTypes.PresentedCredential calldata presentedCredential
    ) external pure returns (bytes32) {
        return _hashString(presentedCredential.subject);
    }

    function deriveCredentialType(
        DataTypes.PresentedCredential calldata presentedCredential
    ) external pure returns (bytes32) {
        return _hashString(presentedCredential.credentialType);
    }

    //funzioni di utility interne
    function _hashString(string memory value) internal pure returns (bytes32) {
        return keccak256(bytes(value));
    }

    function _isVcSdJwt(string memory value) internal pure returns (bool) {
        return keccak256(bytes(value)) == keccak256(bytes("vc+sd-jwt"));
    }

    modifier onlyIssuerController(bytes32 credentialId) {
        require(credentialExists[credentialId], "Credential not found");
        require(
            identityRegistry.controllerOf(credentials[credentialId].issuerDID) == msg.sender,
            "Not issuer controller"
        );
        _;
    }

    function _recoverEthSignedMessage(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return address(0);
        }

        bytes32 ethSignedDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        return ecrecover(ethSignedDigest, v, r, s);
    }
}
