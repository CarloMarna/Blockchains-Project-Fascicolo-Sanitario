// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime verso i registri necessari ai controlli

interface IIdentityRegistryForAccess {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface IDocumentLifecycleRegistryForAccess {
    function documentExists(bytes32 documentId) external view returns (bool);
    function isDocumentActive(bytes32 documentId) external view returns (bool);
    function getPatientDID(bytes32 documentId) external view returns (bytes32);
    function getDocumentType(bytes32 documentId) external view returns (bytes32);
}

interface IPolicyRegistryForAccess {
    function canPerformWithCredential(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentType,
        bytes32 action
    ) external view returns (bool);
}

interface IDelegationRegistryForAccess {
    function isDelegationValid(
        bytes32 delegateDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool);
}

interface IPatientDrivenPolicyRegistryForAccess {
    function isRestricted(
        bytes32 requesterDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool);

    function isAllowed(
        bytes32 requesterDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool);
}

interface IAuditRegistryForAccess {
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
 * @title AccessController
 * @dev Policy Engine con DID + credenziale presentata tramite selective disclosure.
 *
 * Ordine di valutazione:
 * 1. requesterDID attivo e controllato da msg.sender nella richiesta esecutiva;
 * 2. esistenza e stato corrente del documento;
 * 3. restrizioni patient-driven;
 * 4. paziente soggetto del documento;
 * 5. delega valida;
 * 6. VC presentata valida + policy globale.
 */
contract AccessController {
    IIdentityRegistryForAccess public identityRegistry;
    IDocumentLifecycleRegistryForAccess public documentRegistry;
    IPolicyRegistryForAccess public policyRegistry;
    IDelegationRegistryForAccess public delegationRegistry;
    IPatientDrivenPolicyRegistryForAccess public patientPolicyRegistry;
    IAuditRegistryForAccess public auditRegistry;

//evento per tracciare ogni richiesta d'accesso
    event AccessRequested(
        address indexed caller,
        bytes32 indexed requesterDID,
        bytes32 indexed documentId,
        bytes32 action,
        bytes32 purpose,
        bytes32 credentialId,
        bool allowed,
        bytes32 reasonCode
    );

    constructor(
        address identityRegistryAddress,
        address documentRegistryAddress,
        address policyRegistryAddress,
        address delegationRegistryAddress,
        address patientPolicyRegistryAddress,
        address auditRegistryAddress
    ) {
        require(identityRegistryAddress != address(0), "Invalid identity registry");
        require(documentRegistryAddress != address(0), "Invalid document registry");
        require(policyRegistryAddress != address(0), "Invalid policy registry");
        require(delegationRegistryAddress != address(0), "Invalid delegation registry");
        require(patientPolicyRegistryAddress != address(0), "Invalid patient policy registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        identityRegistry = IIdentityRegistryForAccess(identityRegistryAddress);
        documentRegistry = IDocumentLifecycleRegistryForAccess(documentRegistryAddress);
        policyRegistry = IPolicyRegistryForAccess(policyRegistryAddress);
        delegationRegistry = IDelegationRegistryForAccess(delegationRegistryAddress);
        patientPolicyRegistry = IPatientDrivenPolicyRegistryForAccess(patientPolicyRegistryAddress);
        auditRegistry = IAuditRegistryForAccess(auditRegistryAddress);
    }

// Valuta una richiesta di accesso in sola lettura senza produrre eventi né scrivere audit
    function canAccess(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) public view returns (bool) {
        (bool allowed, ) = _canAccessWithReason(
            requesterDID,
            presentedCredential,
            documentId,
            action,
            purpose
        );

        return allowed;
    }

    //Valuta una richiesta di accesso effettiva, verificando il controller del DID e registrando l’esito

    function requestAccess(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) public returns (bool) {
        require(identityRegistry.controllerOf(requesterDID) == msg.sender, "Not requester DID controller");

        (bool allowed, bytes32 reasonCode) = _canAccessWithReason(
            requesterDID,
            presentedCredential,
            documentId,
            action,
            purpose
        );

        emit AccessRequested(
            msg.sender,
            requesterDID,
            documentId,
            action,
            purpose,
            _credentialIdFromPresentedCredential(presentedCredential),
            allowed,
            reasonCode
        );

        auditRegistry.logEvent(
            msg.sender,
            action,
            documentId,
            DataTypes.TARGET_ACCESS,
            allowed ? DataTypes.RESULT_ALLOWED : DataTypes.RESULT_DENIED,
            reasonCode
        );

        return allowed;
    }


    function _credentialIdFromPresentedCredential(
        DataTypes.PresentedCredential calldata presentedCredential
    ) internal pure returns (bytes32) {
        if (bytes(presentedCredential.id).length == 0) {
            return bytes32(0);
        }

        return keccak256(bytes(presentedCredential.id));
    }

// Applica l’ordine decisionale del Policy Engine e restituisce esito e reason code
    function _canAccessWithReason(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) internal view returns (bool, bytes32) {
        //DID richiedente non nullo e attivo
        if (requesterDID == bytes32(0) || !identityRegistry.isActiveDID(requesterDID)) {
            return (false, DataTypes.REASON_INVALID_DID);
        }

        //verifica esistenza documento
        if (!documentRegistry.documentExists(documentId)) {
            return (false, DataTypes.REASON_DOCUMENT_NOT_FOUND);
        }

        //verifica documento attivo e accessibile
        if (!documentRegistry.isDocumentActive(documentId)) {
            return (false, DataTypes.REASON_DOCUMENT_NOT_ACTIVE);
        }

        //valutazione policy patient-driven
        bool restrictedByPatient = patientPolicyRegistry.isRestricted(
            requesterDID,
            documentId,
            action,
            purpose
        );

        if (restrictedByPatient) {
            return (false, DataTypes.REASON_PATIENT_RESTRICTION);
        }

        bytes32 patientDID = documentRegistry.getPatientDID(documentId);

        if (requesterDID == patientDID && action == DataTypes.ACTION_READ) {
            return (true, DataTypes.REASON_PATIENT_OWNER);
        }

        bool allowedByPatient = patientPolicyRegistry.isAllowed(
            requesterDID,
            documentId,
            action,
            purpose
        );

        if (allowedByPatient) {
            return (true, DataTypes.REASON_PATIENT_ALLOWANCE);
        }

        //valutazione delle deleghe
        bool allowedByDelegation = delegationRegistry.isDelegationValid(
            requesterDID,
            documentId,
            action,
            purpose
        );

        if (allowedByDelegation) {
            return (true, DataTypes.REASON_DELEGATION_VALID);
        }

        bytes32 documentType = documentRegistry.getDocumentType(documentId);

        //valutazione policy globali
        bool allowedByPolicy = policyRegistry.canPerformWithCredential(
            requesterDID,
            presentedCredential,
            documentType,
            action
        );

        if (allowedByPolicy) {
            return (true, DataTypes.REASON_POLICY_ALLOWED);
        }

        return (false, DataTypes.REASON_POLICY_NOT_SATISFIED);
    }
}
