// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library DataTypes {
    enum DocumentState {
        None,
        Certified,
        Archived,
        Revoked
    }

    enum Role {
        None,
        Patient,
        Doctor,
        Nurse,
        Auditor,
        ExternalRequester,
        Technician
    }

    enum OrganizationStatus {
        None,
        Active,
        Suspended,
        Revoked
    }

    enum PolicyProposalStatus {
        Pending,
        Approved,
        Rejected,
        Executed
    }

    enum GovernanceActionType {
        SetGlobalPermission,
        AddOrganization,
        SuspendOrganization,
        RevokeOrganization,
        ReactivateOrganization,
        RegisterGovernancePolicy,
        SetMaxDelegationDepth
    }

    enum DelegationProposalStatus {
        None,
        Pending,
        Approved,
        Rejected,
        Expired
    }

    enum DIDStatus {
        None,
        Active,
        Deactivated
    }

    enum CredentialState {
        None,
        Active,
        Suspended,
        Revoked
    }

    /**
     * @dev Rappresentazione della credenziale presentata in formato SD-JWT.
     *
     * La SD-JWT completa resta una prova off-chain. Il contratto NON verifica
     * direttamente la firma EdDSA/JWT, ma usa i metadati rivelati per collegare
     * la presentazione allo stato on-chain della credenziale:
     * - id: identificativo testuale della VC/SD-JWT, hashato on-chain per ottenere
     *   il credentialId registrato nel CredentialStatusRegistry;
     * - issuer: DID testuale dell'issuer, hashato per ottenere issuerDID;
     * - subject: DID testuale del subject/holder, hashato per holder binding;
     * - credentialType: tipo testuale della credenziale, hashato per ottenere il
     *   credentialType usato da TrustRegistry e PolicyRegistry;
     * - sdJwtCredential: SD-JWT/VP off-chain presentata al verifier;
     * - selectivelyDisclosableClaims: elenco dei claim resi selettivamente
     *   disclosable/richiesti nella demo.
     *
     * Nota: nel prototipo la verifica crittografica SD-JWT avviene nello script
     * prima della chiamata ai contratti. On-chain si verificano stato, revoca,
     * issuer fidato, tipo credenziale e subject DID.
     */
    struct PresentedCredential {
        string format;
        string id;
        string issuer;
        string subject;
        string credentialType;
        string sdJwtCredential;
        string[] selectivelyDisclosableClaims;
    }

    // Azioni di sistema
    bytes32 internal constant ACTION_READ = keccak256("READ");
    bytes32 internal constant ACTION_CREATE = keccak256("CREATE");
    bytes32 internal constant ACTION_UPDATE = keccak256("UPDATE");
    bytes32 internal constant ACTION_REVOKE = keccak256("REVOKE");
    bytes32 internal constant ACTION_DELEGATE = keccak256("DELEGATE");

    // Target per audit
    bytes32 internal constant TARGET_DOCUMENT = keccak256("DOCUMENT");
    bytes32 internal constant TARGET_DELEGATION = keccak256("DELEGATION");
    bytes32 internal constant TARGET_POLICY = keccak256("POLICY");
    bytes32 internal constant TARGET_ORGANIZATION = keccak256("ORGANIZATION");
    bytes32 internal constant TARGET_ACCESS = keccak256("ACCESS");
    bytes32 internal constant TARGET_PATIENT_POLICY = keccak256("PATIENT_POLICY");
    bytes32 internal constant TARGET_IDENTITY = keccak256("IDENTITY");
    bytes32 internal constant TARGET_CREDENTIAL = keccak256("CREDENTIAL");
    bytes32 internal constant TARGET_TRUST = keccak256("TRUST");

    // Credential type WP2. La VC resta off-chain; on-chain si usa l'hash del tipo.
    bytes32 internal constant VC_MEDICAL_PROFESSIONAL = keccak256("MedicalProfessionalVC");
    bytes32 internal constant VC_NURSE_PROFESSIONAL = keccak256("NurseProfessionalVC");
    bytes32 internal constant VC_TECHNICIAN_PROFESSIONAL = keccak256("TechnicianProfessionalVC");
    bytes32 internal constant VC_AUDITOR_PROFESSIONAL = keccak256("AuditorProfessionalVC");
    bytes32 internal constant VC_EXTERNAL_REQUESTER = keccak256("ExternalRequesterVC");

    // Risultati audit
    bytes32 internal constant RESULT_SUCCESS = keccak256("SUCCESS");
    bytes32 internal constant RESULT_ALLOWED = keccak256("ALLOWED");
    bytes32 internal constant RESULT_DENIED = keccak256("DENIED");
    bytes32 internal constant RESULT_REJECTED = keccak256("REJECTED");

    // Reason code generali
    bytes32 internal constant REASON_BOOTSTRAP = keccak256("BOOTSTRAP");
    bytes32 internal constant REASON_ROLE_ASSIGNED = keccak256("ROLE_ASSIGNED");
    bytes32 internal constant REASON_ROLE_REVOKED = keccak256("ROLE_REVOKED");

    // Reason code DID / VC / Trust
    bytes32 internal constant REASON_DID_REGISTERED = keccak256("DID_REGISTERED");
    bytes32 internal constant REASON_DID_UPDATED = keccak256("DID_UPDATED");
    bytes32 internal constant REASON_DID_DEACTIVATED = keccak256("DID_DEACTIVATED");
    bytes32 internal constant REASON_INVALID_DID = keccak256("INVALID_DID");
    bytes32 internal constant REASON_CREDENTIAL_ISSUED = keccak256("CREDENTIAL_ISSUED");
    bytes32 internal constant REASON_CREDENTIAL_REVOKED = keccak256("CREDENTIAL_REVOKED");
    bytes32 internal constant REASON_CREDENTIAL_SUSPENDED = keccak256("CREDENTIAL_SUSPENDED");
    bytes32 internal constant REASON_CREDENTIAL_REACTIVATED = keccak256("CREDENTIAL_REACTIVATED");
    bytes32 internal constant REASON_INVALID_CREDENTIAL = keccak256("INVALID_CREDENTIAL");
    bytes32 internal constant REASON_TRUSTED_ISSUER_AUTHORIZED = keccak256("TRUSTED_ISSUER_AUTHORIZED");
    bytes32 internal constant REASON_TRUSTED_ISSUER_REVOKED = keccak256("TRUSTED_ISSUER_REVOKED");
    bytes32 internal constant REASON_CREDENTIAL_TYPE_ROLE_SET = keccak256("CREDENTIAL_TYPE_ROLE_SET");

    // Reason code documenti
    bytes32 internal constant REASON_DOCUMENT_CREATED = keccak256("DOCUMENT_CREATED");
    bytes32 internal constant REASON_DOCUMENT_VERSION_CREATED = keccak256("DOCUMENT_VERSION_CREATED");
    bytes32 internal constant REASON_DOCUMENT_REVOKED = keccak256("DOCUMENT_REVOKED");
    bytes32 internal constant REASON_DOCUMENT_NOT_FOUND = keccak256("DOCUMENT_NOT_FOUND");
    bytes32 internal constant REASON_DOCUMENT_NOT_ACTIVE = keccak256("DOCUMENT_NOT_ACTIVE");

    // Reason code deleghe
    bytes32 internal constant REASON_DELEGATION_PROPOSED = keccak256("DELEGATION_PROPOSED");
    bytes32 internal constant REASON_DELEGATION_APPROVED = keccak256("DELEGATION_APPROVED");
    bytes32 internal constant REASON_DELEGATION_REJECTED = keccak256("DELEGATION_REJECTED");
    bytes32 internal constant REASON_DELEGATION_CREATED = keccak256("DELEGATION_CREATED");
    bytes32 internal constant REASON_DELEGATION_REVOKED = keccak256("DELEGATION_REVOKED");
    bytes32 internal constant REASON_DELEGATION_VALID = keccak256("DELEGATION_VALID");

    // Reason code policy
    bytes32 internal constant REASON_POLICY_PROPOSED = keccak256("POLICY_PROPOSED");
    bytes32 internal constant REASON_POLICY_VOTED = keccak256("POLICY_VOTED");
    bytes32 internal constant REASON_POLICY_APPROVED = keccak256("POLICY_APPROVED");
    bytes32 internal constant REASON_POLICY_REJECTED = keccak256("POLICY_REJECTED");
    bytes32 internal constant REASON_POLICY_EXECUTED = keccak256("POLICY_EXECUTED");
    bytes32 internal constant REASON_POLICY_ALLOWED = keccak256("POLICY_ALLOWED");
    bytes32 internal constant REASON_POLICY_NOT_SATISFIED = keccak256("POLICY_NOT_SATISFIED");

    // Reason code patient-driven
    bytes32 internal constant REASON_PATIENT_OWNER = keccak256("PATIENT_OWNER");
    bytes32 internal constant REASON_PATIENT_RESTRICTION = keccak256("PATIENT_RESTRICTION");
    bytes32 internal constant REASON_PATIENT_ALLOWANCE = keccak256("PATIENT_ALLOWANCE");
    bytes32 internal constant REASON_PATIENT_POLICY_REGISTERED = keccak256("PATIENT_POLICY_REGISTERED");
    bytes32 internal constant REASON_PATIENT_POLICY_REVOKED = keccak256("PATIENT_POLICY_REVOKED");

    // Reason code organizzazioni
    bytes32 internal constant REASON_ORGANIZATION_ADDED = keccak256("ORGANIZATION_ADDED");
    bytes32 internal constant REASON_ORGANIZATION_SUSPENDED = keccak256("ORGANIZATION_SUSPENDED");
    bytes32 internal constant REASON_ORGANIZATION_REVOKED = keccak256("ORGANIZATION_REVOKED");
    bytes32 internal constant REASON_ORGANIZATION_REACTIVATED = keccak256("ORGANIZATION_REACTIVATED");
}
