// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IIdentityRegistryForPatientPolicies {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface IDocumentLifecycleRegistryForPatientPolicies {
    function documentExists(bytes32 documentId) external view returns (bool);
    function isDocumentActive(bytes32 documentId) external view returns (bool);
    function getPatientDID(bytes32 documentId) external view returns (bytes32);
}

interface IAuditRegistryForPatientPolicies {
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
 * @title PatientDrivenPolicyRegistry
 * @dev Restrizioni patient-driven espresse da un DID paziente.
 */
contract PatientDrivenPolicyRegistry {
    //Policy patient-driven, restrittiva o positiva, associata a paziente, documento e validità temporale
    struct PatientPolicy {
        uint256 policyId;
        bytes32 patientDID;
        bytes32 targetDocumentId;
        bytes32 restrictedUserDID;
        bytes32 restrictedAction;
        bytes32 allowedUserDID;
        bytes32 allowedAction;
        bytes32 purpose;
        uint256 validFrom;
        uint256 validUntil;
        bytes32 policyCID;
        bool revoked;
        uint256 revokedAt;
    }

    IIdentityRegistryForPatientPolicies public identityRegistry;
    IDocumentLifecycleRegistryForPatientPolicies public documentRegistry;
    IAuditRegistryForPatientPolicies public auditRegistry;

    uint256 public nextPolicyId;

    mapping(uint256 => PatientPolicy) private policies;
    mapping(uint256 => bool) public policyExists;
    // Indicizza le policy per documento, così da recuperare quelle applicabili in fase di accesso
    mapping(bytes32 => uint256[]) private policiesByDocument;

    event PatientPolicyRegistered(
        uint256 indexed policyId,
        bytes32 indexed patientDID,
        bytes32 indexed targetDocumentId,
        bytes32 restrictedUserDID,
        bytes32 restrictedAction,
        bytes32 allowedUserDID,
        bytes32 allowedAction,
        bytes32 purpose,
        uint256 validFrom,
        uint256 validUntil,
        bytes32 policyCID
    );

    event PatientPolicyRevoked(
        uint256 indexed policyId,
        bytes32 indexed patientDID,
        address indexed revokedByController,
        uint256 revokedAt
    );

    constructor(
        address identityRegistryAddress,
        address documentRegistryAddress,
        address auditRegistryAddress
    ) {
        require(
            identityRegistryAddress != address(0),
            "Invalid identity registry"
        );
        require(
            documentRegistryAddress != address(0),
            "Invalid document registry"
        );
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        identityRegistry = IIdentityRegistryForPatientPolicies(
            identityRegistryAddress
        );
        documentRegistry = IDocumentLifecycleRegistryForPatientPolicies(
            documentRegistryAddress
        );
        auditRegistry = IAuditRegistryForPatientPolicies(auditRegistryAddress);

        nextPolicyId = 1;
    }

    // Registra una policy patient-driven su un documento
    function registerRestriction(
        bytes32 targetDocumentId,
        bytes32 patientDID,
        bytes32 restrictedUserDID,
        bytes32 restrictedAction,
        bytes32 allowedUserDID,
        bytes32 allowedAction,
        bytes32 purpose,
        uint256 validFrom,
        uint256 validUntil,
        bytes32 policyCID
    ) external returns (uint256) {
        require(targetDocumentId != bytes32(0), "Invalid documentId");
        require(patientDID != bytes32(0), "Invalid patient DID");
        require(policyCID != bytes32(0), "Invalid policyCID");
        require(validUntil > validFrom, "Invalid time interval");
        require(validUntil > block.timestamp, "Policy already expired");

        require(
            documentRegistry.documentExists(targetDocumentId),
            "Document does not exist"
        );
        require(
            documentRegistry.isDocumentActive(targetDocumentId),
            "Document not active"
        );
        require(
            documentRegistry.getPatientDID(targetDocumentId) == patientDID,
            "Wrong patient DID"
        );
        require(
            identityRegistry.isActiveDID(patientDID),
            "Patient DID inactive"
        );
        require(
            identityRegistry.controllerOf(patientDID) == msg.sender,
            "Only document patient controller"
        );

        if (restrictedUserDID != bytes32(0)) {
            require(
                identityRegistry.isActiveDID(restrictedUserDID),
                "Restricted DID inactive"
            );
        }

        if (allowedUserDID != bytes32(0)) {
            require(
                identityRegistry.isActiveDID(allowedUserDID),
                "Allowed DID inactive"
            );
        }

        uint256 policyId = nextPolicyId;
        nextPolicyId += 1;

        policies[policyId] = PatientPolicy({
            policyId: policyId,
            patientDID: patientDID,
            targetDocumentId: targetDocumentId,
            restrictedUserDID: restrictedUserDID,
            restrictedAction: restrictedAction,
            allowedUserDID: allowedUserDID,
            allowedAction: allowedAction,
            purpose: purpose,
            validFrom: validFrom,
            validUntil: validUntil,
            policyCID: policyCID,
            revoked: false,
            revokedAt: 0
        });

        policyExists[policyId] = true;
        policiesByDocument[targetDocumentId].push(policyId);

        emit PatientPolicyRegistered(
            policyId,
            patientDID,
            targetDocumentId,
            restrictedUserDID,
            restrictedAction,
            allowedUserDID,
            allowedAction,
            purpose,
            validFrom,
            validUntil,
            policyCID
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            bytes32(policyId),
            DataTypes.TARGET_PATIENT_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_PATIENT_POLICY_REGISTERED
        );

        return policyId;
    }

    // Revoca una policy patient-driven esistente se il chiamante controlla il DID del paziente
    function revokePatientPolicy(uint256 policyId) external {
        require(policyExists[policyId], "Policy not found");

        PatientPolicy storage policy = policies[policyId];
        require(!policy.revoked, "Already revoked");
        require(
            identityRegistry.controllerOf(policy.patientDID) == msg.sender,
            "Only policy patient controller"
        );

        policy.revoked = true;
        policy.revokedAt = block.timestamp;

        emit PatientPolicyRevoked(
            policyId,
            policy.patientDID,
            msg.sender,
            block.timestamp
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            bytes32(policyId),
            DataTypes.TARGET_PATIENT_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_PATIENT_POLICY_REVOKED
        );
    }

    // Verifica se esiste una restrizione patient-driven applicabile
    function isRestricted(
        bytes32 requesterDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool) {
        uint256[] memory ids = policiesByDocument[documentId];

        for (uint256 i = 0; i < ids.length; i++) {
            PatientPolicy memory policy = policies[ids[i]];

            if (_matchesRestriction(policy, requesterDID, action, purpose)) {
                return true;
            }
        }

        return false;
    }

    // Verifica se esiste una policy patient-driven positiva applicabile
    function isAllowed(
        bytes32 requesterDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool) {
        uint256[] memory ids = policiesByDocument[documentId];

        for (uint256 i = 0; i < ids.length; i++) {
            PatientPolicy memory policy = policies[ids[i]];

            if (_matchesAllowance(policy, requesterDID, action, purpose)) {
                return true;
            }
        }

        return false;
    }

    function getPatientPolicy(
        uint256 policyId
    ) external view returns (PatientPolicy memory) {
        require(policyExists[policyId], "Policy not found");
        return policies[policyId];
    }

    function getPoliciesByDocument(
        bytes32 documentId
    ) external view returns (uint256[] memory) {
        return policiesByDocument[documentId];
    }

    // Verifica che una policy non sia revocata e sia temporalmente valida
    function _isPolicyActive(
        PatientPolicy memory policy
    ) internal view returns (bool) {
        if (policy.revoked) {
            return false;
        }

        if (
            block.timestamp < policy.validFrom ||
            block.timestamp > policy.validUntil
        ) {
            return false;
        }

        return true;
    }

    // Verifica se una policy restrittiva corrisponde a requester, azione e finalità della richiesta
    function _matchesRestriction(
        PatientPolicy memory policy,
        bytes32 requesterDID,
        bytes32 action,
        bytes32 purpose
    ) internal view returns (bool) {
        if (!_isPolicyActive(policy)) {
            return false;
        }

        if (
            policy.restrictedUserDID == bytes32(0) &&
            policy.restrictedAction == bytes32(0)
        ) {
            return false;
        }

        bool userMatches = policy.restrictedUserDID == bytes32(0) ||
            policy.restrictedUserDID == requesterDID;

        bool actionMatches = policy.restrictedAction == bytes32(0) ||
            policy.restrictedAction == action;

        bool purposeMatches = policy.purpose == bytes32(0) ||
            policy.purpose == purpose;

        return userMatches && actionMatches && purposeMatches;
    }

    // Verifica se una policy positiva corrisponde a requester, azione e finalità della richiesta
    function _matchesAllowance(
        PatientPolicy memory policy,
        bytes32 requesterDID,
        bytes32 action,
        bytes32 purpose
    ) internal view returns (bool) {
        if (!_isPolicyActive(policy)) {
            return false;
        }

        if (
            policy.allowedUserDID == bytes32(0) &&
            policy.allowedAction == bytes32(0)
        ) {
            return false;
        }

        bool userMatches = policy.allowedUserDID == bytes32(0) ||
            policy.allowedUserDID == requesterDID;

        bool actionMatches = policy.allowedAction == bytes32(0) ||
            policy.allowedAction == action;

        bool purposeMatches = policy.purpose == bytes32(0) ||
            policy.purpose == purpose;

        return userMatches && actionMatches && purposeMatches;
    }
}
