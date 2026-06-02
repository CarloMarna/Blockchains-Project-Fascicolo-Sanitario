// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IIdentityRegistryForDelegations {
    function isActiveDID(bytes32 did) external view returns (bool);
    function controllerOf(bytes32 did) external view returns (address);
}

interface IDocumentLifecycleRegistryForDelegations {
    function documentExists(bytes32 documentId) external view returns (bool);
    function isDocumentActive(bytes32 documentId) external view returns (bool);
    function getPatientDID(bytes32 documentId) external view returns (bytes32);
    function getDocumentType(bytes32 documentId) external view returns (bytes32);
}

interface IPolicyRegistryForDelegations {
    function canPerformWithCredential(
        bytes32 requesterDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 documentType,
        bytes32 action
    ) external view returns (bool);
    function maxDelegationDepth() external view returns (uint256);
}

interface IAuditRegistryForDelegations {
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
 * @title DelegationRegistry
 * @dev Deleghe tra DID, approvate dal DID paziente. Il delegante presenta una VC selettivamente rivelata.
 */
contract DelegationRegistry {

    //Proposta di delega non ancora efficace
    struct DelegationProposal {
        uint256 proposalId;
        bytes32 delegatorDID;
        bytes32 delegateDID;
        bytes32 targetDocumentId;
        bytes32 delegatedAction;
        bytes32 purposeOfDelegation;
        uint256 parentDelegationId;
        uint256 depth;
        uint256 maxDelegationDepthAtCreation;
        uint256 validFrom;
        uint256 validUntil;
        DataTypes.DelegationProposalStatus status;
        uint256 createdAt;
        uint256 resultingDelegationId;
    }

    //Delega attiva approvata dal paziente
    struct Delegation {
        uint256 delegationId;
        uint256 proposalId;
        bytes32 delegatorDID;
        bytes32 delegateDID;
        bytes32 targetDocumentId;
        bytes32 delegatedAction;
        bytes32 purposeOfDelegation;
        uint256 parentDelegationId;
        uint256 depth;
        uint256 maxDelegationDepthAtCreation;
        uint256 validFrom;
        uint256 validUntil;
        bool revoked;
        uint256 revokedAt;
    }

    IIdentityRegistryForDelegations public identityRegistry;
    IDocumentLifecycleRegistryForDelegations public documentRegistry;
    IPolicyRegistryForDelegations public policyRegistry;
    IAuditRegistryForDelegations public auditRegistry;

    uint256 public nextProposalId;
    uint256 public nextDelegationId;

    // Proposte di delega registrate, indicizzate per ID
    mapping(uint256 => DelegationProposal) private proposals;
    // Indica se una proposta di delega esiste
    mapping(uint256 => bool) public proposalExists;
    // Deleghe attive o registrate, indicizzate per ID
    mapping(uint256 => Delegation) private delegations;
    //Indica se una delega esiste
    mapping(uint256 => bool) public delegationExists;
    // Raggruppa gli ID delle deleghe per chiave logica di ricerca
    mapping(bytes32 => uint256[]) private delegationsByKey;

    //Evento emesso quando viene creata una nuova proposta di delega
    event DelegationProposed(
        uint256 indexed proposalId,
        bytes32 indexed delegatorDID,
        bytes32 indexed delegateDID,
        bytes32 targetDocumentId,
        bytes32 delegatedAction,
        bytes32 purposeOfDelegation,
        uint256 validFrom,
        uint256 validUntil
    );

    //Evento emesso quando il paziente approva la proposta di delega
    event DelegationProposalApproved(
        uint256 indexed proposalId,
        uint256 indexed delegationId,
        bytes32 indexed patientDID
    );

    // Evento emesso quando il paziente rifiuta una proposta di delega
    event DelegationProposalRejected(
        uint256 indexed proposalId,
        bytes32 indexed patientDID
    );

    // Evento emesso quando una delega attiva viene revocata da un soggetto autorizzato
    event DelegationRevoked(
        uint256 indexed delegationId,
        bytes32 indexed revokedByDID,
        address indexed revokedByController,
        uint256 revokedAt
    );

    constructor(
        address identityRegistryAddress,
        address documentRegistryAddress,
        address policyRegistryAddress,
        address auditRegistryAddress
    ) {
        require(identityRegistryAddress != address(0), "Invalid identity registry");
        require(documentRegistryAddress != address(0), "Invalid document registry");
        require(policyRegistryAddress != address(0), "Invalid policy registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        identityRegistry = IIdentityRegistryForDelegations(identityRegistryAddress);
        documentRegistry = IDocumentLifecycleRegistryForDelegations(documentRegistryAddress);
        policyRegistry = IPolicyRegistryForDelegations(policyRegistryAddress);
        auditRegistry = IAuditRegistryForDelegations(auditRegistryAddress);

        nextProposalId = 1;
        nextDelegationId = 1;
    }

    //Crea una proposta di delega
    function proposeDelegation(
        bytes32 delegatorDID,
        bytes32 delegateDID,
        DataTypes.PresentedCredential calldata presentedCredential,
        bytes32 targetDocumentId,
        bytes32 delegatedAction,
        bytes32 purposeOfDelegation,
        uint256 validFrom,
        uint256 validUntil
    ) external returns (uint256) {
        require(delegatorDID != bytes32(0), "Invalid delegator DID");
        require(delegateDID != bytes32(0), "Invalid delegate DID");
        require(targetDocumentId != bytes32(0), "Invalid documentId");
        require(delegatedAction != bytes32(0), "Invalid action");
        require(purposeOfDelegation != bytes32(0), "Invalid purpose");
        require(validUntil > validFrom, "Invalid time interval");
        require(validUntil > block.timestamp, "Delegation already expired");

        require(identityRegistry.isActiveDID(delegatorDID), "Delegator DID inactive");
        require(identityRegistry.isActiveDID(delegateDID), "Delegate DID inactive");
        require(identityRegistry.controllerOf(delegatorDID) == msg.sender, "Not delegator controller");
        require(documentRegistry.documentExists(targetDocumentId), "Document does not exist");
        require(documentRegistry.isDocumentActive(targetDocumentId), "Document not active");

        bytes32 documentType = documentRegistry.getDocumentType(targetDocumentId);

        bool canDelegate = policyRegistry.canPerformWithCredential(
            delegatorDID,
            presentedCredential,
            documentType,
            DataTypes.ACTION_DELEGATE
        );

        require(canDelegate, "Not authorized to propose delegation");

        uint256 proposalId = nextProposalId;
        nextProposalId += 1;

        proposals[proposalId] = DelegationProposal({
            proposalId: proposalId,
            delegatorDID: delegatorDID,
            delegateDID: delegateDID,
            targetDocumentId: targetDocumentId,
            delegatedAction: delegatedAction,
            purposeOfDelegation: purposeOfDelegation,
            parentDelegationId: 0,
            depth: 1,
            maxDelegationDepthAtCreation: policyRegistry.maxDelegationDepth(),
            validFrom: validFrom,
            validUntil: validUntil,
            status: DataTypes.DelegationProposalStatus.Pending,
            createdAt: block.timestamp,
            resultingDelegationId: 0
        });

        proposalExists[proposalId] = true;

        emit DelegationProposed(
            proposalId,
            delegatorDID,
            delegateDID,
            targetDocumentId,
            delegatedAction,
            purposeOfDelegation,
            validFrom,
            validUntil
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_DELEGATE,
            bytes32(proposalId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DELEGATION_PROPOSED
        );

        return proposalId;
    }

    // Crea una proposta di delega derivata a partire da una delega padre ancora valida
    function proposeDerivedDelegation(
        uint256 parentDelegationId,
        bytes32 newDelegateDID,
        uint256 validFrom,
        uint256 validUntil
    ) external returns (uint256) {
        require(delegationExists[parentDelegationId], "Parent delegation not found");
        require(newDelegateDID != bytes32(0), "Invalid delegate DID");
        require(identityRegistry.isActiveDID(newDelegateDID), "New delegate DID inactive");
        require(validUntil > validFrom, "Invalid time interval");
        require(validUntil > block.timestamp, "Derived delegation already expired");

        Delegation storage parent = delegations[parentDelegationId];

        require(!parent.revoked, "Parent delegation revoked");
        require(block.timestamp >= parent.validFrom, "Parent delegation not active yet");
        require(block.timestamp <= parent.validUntil, "Parent delegation expired");
        require(identityRegistry.controllerOf(parent.delegateDID) == msg.sender, "Only parent delegate controller");
        require(validFrom >= parent.validFrom && validUntil <= parent.validUntil, "Derived delegation exceeds parent validity");
        require(documentRegistry.isDocumentActive(parent.targetDocumentId), "Document not active");

        uint256 newDepth = parent.depth + 1;
        uint256 maxDepth = policyRegistry.maxDelegationDepth();
        require(newDepth <= maxDepth, "Max delegation depth exceeded");

        uint256 proposalId = nextProposalId;
        nextProposalId += 1;

        proposals[proposalId] = DelegationProposal({
            proposalId: proposalId,
            delegatorDID: parent.delegateDID,
            delegateDID: newDelegateDID,
            targetDocumentId: parent.targetDocumentId,
            delegatedAction: parent.delegatedAction,
            purposeOfDelegation: parent.purposeOfDelegation,
            parentDelegationId: parentDelegationId,
            depth: newDepth,
            maxDelegationDepthAtCreation: maxDepth,
            validFrom: validFrom,
            validUntil: validUntil,
            status: DataTypes.DelegationProposalStatus.Pending,
            createdAt: block.timestamp,
            resultingDelegationId: 0
        });

        proposalExists[proposalId] = true;

        emit DelegationProposed(
            proposalId,
            parent.delegateDID,
            newDelegateDID,
            parent.targetDocumentId,
            parent.delegatedAction,
            parent.purposeOfDelegation,
            validFrom,
            validUntil
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_DELEGATE,
            bytes32(proposalId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DELEGATION_PROPOSED
        );

        return proposalId;
    }

    // Consente al paziente associato al documento di approvare una proposta e trasformarla in delega attiva
    function approveDelegationProposal(uint256 proposalId) external returns (uint256) {
        require(proposalExists[proposalId], "Proposal not found");

        DelegationProposal storage proposal = proposals[proposalId];
        require(proposal.status == DataTypes.DelegationProposalStatus.Pending, "Proposal not pending");
        require(block.timestamp <= proposal.validUntil, "Proposal expired");
        require(documentRegistry.isDocumentActive(proposal.targetDocumentId), "Document not active");

        bytes32 patientDID = documentRegistry.getPatientDID(proposal.targetDocumentId);
        require(identityRegistry.controllerOf(patientDID) == msg.sender, "Only patient controller can approve");

        uint256 delegationId = nextDelegationId;
        nextDelegationId += 1;

        delegations[delegationId] = Delegation({
            delegationId: delegationId,
            proposalId: proposalId,
            delegatorDID: proposal.delegatorDID,
            delegateDID: proposal.delegateDID,
            targetDocumentId: proposal.targetDocumentId,
            delegatedAction: proposal.delegatedAction,
            purposeOfDelegation: proposal.purposeOfDelegation,
            parentDelegationId: proposal.parentDelegationId,
            depth: proposal.depth,
            maxDelegationDepthAtCreation: proposal.maxDelegationDepthAtCreation,
            validFrom: proposal.validFrom,
            validUntil: proposal.validUntil,
            revoked: false,
            revokedAt: 0
        });

        delegationExists[delegationId] = true;
        proposal.status = DataTypes.DelegationProposalStatus.Approved;
        proposal.resultingDelegationId = delegationId;

        bytes32 key = _delegationKey(proposal.delegateDID, proposal.targetDocumentId, proposal.delegatedAction);
        delegationsByKey[key].push(delegationId);

        emit DelegationProposalApproved(proposalId, delegationId, patientDID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            bytes32(delegationId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DELEGATION_APPROVED
        );

        auditRegistry.logEvent(
            address(this),
            DataTypes.ACTION_CREATE,
            bytes32(delegationId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DELEGATION_CREATED
        );

        return delegationId;
    }

    // Consente al paziente associato al documento di rifiutare una proposta di delega ancora pendente
    function rejectDelegationProposal(uint256 proposalId) external {
        require(proposalExists[proposalId], "Proposal not found");

        DelegationProposal storage proposal = proposals[proposalId];
        require(proposal.status == DataTypes.DelegationProposalStatus.Pending, "Proposal not pending");

        bytes32 patientDID = documentRegistry.getPatientDID(proposal.targetDocumentId);
        require(identityRegistry.controllerOf(patientDID) == msg.sender, "Only patient controller can reject");

        proposal.status = DataTypes.DelegationProposalStatus.Rejected;

        emit DelegationProposalRejected(proposalId, patientDID);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            bytes32(proposalId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_REJECTED,
            DataTypes.REASON_DELEGATION_REJECTED
        );
    }

    function revokeDelegation(uint256 delegationId, bytes32 revokedByDID) external {
        require(delegationExists[delegationId], "Delegation not found");
        require(revokedByDID != bytes32(0), "Invalid revoker DID");
        require(identityRegistry.controllerOf(revokedByDID) == msg.sender, "Not DID controller");

        Delegation storage delegationRecord = delegations[delegationId];
        require(!delegationRecord.revoked, "Already revoked");

        bytes32 patientDID = documentRegistry.getPatientDID(delegationRecord.targetDocumentId);

        bool isDelegator = revokedByDID == delegationRecord.delegatorDID;
        bool isDelegate = revokedByDID == delegationRecord.delegateDID;
        bool isPatient = revokedByDID == patientDID;

        require(isDelegator || isDelegate || isPatient, "Not authorized to revoke");

        delegationRecord.revoked = true;
        delegationRecord.revokedAt = block.timestamp;

        emit DelegationRevoked(delegationId, revokedByDID, msg.sender, block.timestamp);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_REVOKE,
            bytes32(delegationId),
            DataTypes.TARGET_DELEGATION,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_DELEGATION_REVOKED
        );
    }

    function isDelegationValid(
        bytes32 delegateDID,
        bytes32 documentId,
        bytes32 action,
        bytes32 purpose
    ) external view returns (bool) {
        bytes32 key = _delegationKey(delegateDID, documentId, action);
        uint256[] memory ids = delegationsByKey[key];

        for (uint256 i = 0; i < ids.length; i++) {
            Delegation memory delegationRecord = delegations[ids[i]];

            if (_isDelegationChainValid(delegationRecord, purpose)) {
                return true;
            }
        }

        return false;
    }

    function getDelegationProposal(uint256 proposalId) external view returns (DelegationProposal memory) {
        require(proposalExists[proposalId], "Proposal not found");
        return proposals[proposalId];
    }

    function getDelegation(uint256 delegationId) external view returns (Delegation memory) {
        require(delegationExists[delegationId], "Delegation not found");
        return delegations[delegationId];
    }

    function getDelegationsByKey(
        bytes32 delegateDID,
        bytes32 documentId,
        bytes32 action
    ) external view returns (uint256[] memory) {
        return delegationsByKey[_delegationKey(delegateDID, documentId, action)];
    }

    // Calcola la chiave di indicizzazione delle deleghe a partire da delegato, documento e azione
    function _delegationKey(
        bytes32 delegateDID,
        bytes32 documentId,
        bytes32 action
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(delegateDID, documentId, action));
    }

    function _isDelegationCurrentlyValid(
        Delegation memory delegationRecord,
        bytes32 purpose
    ) internal view returns (bool) {
        if (delegationRecord.revoked) {
            return false;
        }

        if (block.timestamp < delegationRecord.validFrom) {
            return false;
        }

        if (block.timestamp > delegationRecord.validUntil) {
            return false;
        }

        if (purpose != bytes32(0) && delegationRecord.purposeOfDelegation != purpose) {
            return false;
        }

        if (delegationRecord.depth > policyRegistry.maxDelegationDepth()) {
            return false;
        }

        if (!documentRegistry.isDocumentActive(delegationRecord.targetDocumentId)) {
            return false;
        }

        if (!identityRegistry.isActiveDID(delegationRecord.delegateDID)) {
            return false;
        }

        return true;
    }

    //verifica ricorsiva della catena di deleghe
    function _isDelegationChainValid(
        Delegation memory delegationRecord,
        bytes32 purpose
    ) internal view returns (bool) {
        if (!_isDelegationCurrentlyValid(delegationRecord, purpose)) {
            return false;
        }

        if (delegationRecord.parentDelegationId != 0) {
            Delegation memory parentDelegation = delegations[delegationRecord.parentDelegationId];
            return _isDelegationChainValid(parentDelegation, purpose);
        }

        return true;
    }
}
