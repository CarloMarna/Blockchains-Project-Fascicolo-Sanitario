// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

//Interfacce minime
interface IOrganizationRegistryForGovernance {
    function isActiveOrganization(address organizationAddress) external view returns (bool);
    function activeOrganizationCount() external view returns (uint256);

    function addOrganization(address organizationAddress, bytes32 organizationCID) external;
    function suspendOrganization(address organizationAddress) external;
    function revokeOrganization(address organizationAddress) external;
    function reactivateOrganization(address organizationAddress) external;
}

interface IPolicyRegistryForGovernance {
    function setPermissionFromGovernance(
        DataTypes.Role role,
        bytes32 documentType,
        bytes32 action,
        bool allowed,
        bytes32 policyCID
    ) external;
    function setMaxDelegationDepthFromGovernance(
        uint256 newMaxDelegationDepth,
        bytes32 policyCID
    ) external;
}

interface IAuditRegistryForGovernance {
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
 * @title PolicyGovernance
 * @dev Governance multi-authority minimale per il WP4.
 *
 * Sostituisce il modello admin-centrico:
 * proposta -> voto -> quorum -> esecuzione.
 *
 * Quorum:
 * - policy globali di accesso: maggioranza semplice;
 * - policy di governance / organizzazioni: supermajority ceil(2n/3).
 */
contract PolicyGovernance {
    //Proposta di governance
    struct PolicyProposal {
        uint256 proposalId;
        DataTypes.GovernanceActionType actionType;
        address proposedBy;
        uint256 createdAt;
        DataTypes.PolicyProposalStatus status;

        DataTypes.Role role;
        bytes32 documentType;
        bytes32 action;
        bool allowed;

        address targetOrganization;
        bytes32 organizationCID;

        bytes32 policyCID;

        uint256 approvals;
        uint256 rejections;

        uint256 newMaxDelegationDepth;
    }

    IOrganizationRegistryForGovernance public organizationRegistry;
    IPolicyRegistryForGovernance public policyRegistry;
    IAuditRegistryForGovernance public auditRegistry;

    uint256 public nextProposalId;

    mapping(uint256 => PolicyProposal) private proposals;
    //mapping per evitare voti duplicati
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    mapping(uint256 => address[]) private approvers;
    mapping(uint256 => address[]) private rejecters;

    event PolicyProposalCreated(
        uint256 indexed proposalId,
        DataTypes.GovernanceActionType actionType,
        address indexed proposedBy,
        bytes32 policyCID
    );

    event PolicyVoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        bool support
    );

    event PolicyProposalFinalized(
        uint256 indexed proposalId,
        DataTypes.PolicyProposalStatus status,
        uint256 approvals,
        uint256 rejections
    );

    //solo le organizzazioni attive possono chiamare la funzione
    modifier onlyActiveOrganization() {
        require(
            organizationRegistry.isActiveOrganization(msg.sender),
            "Only active organization"
        );
        _;
    }

    constructor(
        address organizationRegistryAddress,
        address policyRegistryAddress,
        address auditRegistryAddress
    ) {
        require(organizationRegistryAddress != address(0), "Invalid organization registry");
        require(policyRegistryAddress != address(0), "Invalid policy registry");
        require(auditRegistryAddress != address(0), "Invalid audit registry");

        organizationRegistry = IOrganizationRegistryForGovernance(organizationRegistryAddress);
        policyRegistry = IPolicyRegistryForGovernance(policyRegistryAddress);
        auditRegistry = IAuditRegistryForGovernance(auditRegistryAddress);

        nextProposalId = 1;
    }

    // Crea una proposta per modificare una policy globale di accesso
    function proposeGlobalAccessPolicy(
        DataTypes.Role role,
        bytes32 documentType,
        bytes32 action,
        bool allowed,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(role != DataTypes.Role.None, "Invalid role");
        require(documentType != bytes32(0), "Invalid documentType");
        require(action != bytes32(0), "Invalid action");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.SetGlobalPermission,
            policyCID
        );

        PolicyProposal storage proposal = proposals[proposalId];

        proposal.role = role;
        proposal.documentType = documentType;
        proposal.action = action;
        proposal.allowed = allowed;

        return proposalId;
    }

    // Crea una proposta per aggiungere una nuova organizzazione al network
    function proposeAddOrganization(
        address organizationAddress,
        bytes32 organizationCID,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(organizationAddress != address(0), "Invalid organization");
        require(organizationCID != bytes32(0), "Invalid organizationCID");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.AddOrganization,
            policyCID
        );

        PolicyProposal storage proposal = proposals[proposalId];

        proposal.targetOrganization = organizationAddress;
        proposal.organizationCID = organizationCID;

        return proposalId;
    }

    // Crea una proposta per sospendere un’organizzazione registrata
    function proposeSuspendOrganization(
        address organizationAddress,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(organizationAddress != address(0), "Invalid organization");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.SuspendOrganization,
            policyCID
        );

        proposals[proposalId].targetOrganization = organizationAddress;

        return proposalId;
    }

    // Crea una proposta per revicare un’organizzazione registrata
    function proposeRevokeOrganization(
        address organizationAddress,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(organizationAddress != address(0), "Invalid organization");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.RevokeOrganization,
            policyCID
        );

        proposals[proposalId].targetOrganization = organizationAddress;

        return proposalId;
    }

    // Crea una proposta per riattivare un’organizzazione sospesa
    function proposeReactivateOrganization(
        address organizationAddress,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(organizationAddress != address(0), "Invalid organization");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.ReactivateOrganization,
            policyCID
        );

        proposals[proposalId].targetOrganization = organizationAddress;

        return proposalId;
    }

    // Crea una proposta per registrare e ancorare una policy di governance tramite policyCID
    function proposeGovernancePolicy(
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(policyCID != bytes32(0), "Invalid policyCID");

        return _createBaseProposal(
            DataTypes.GovernanceActionType.RegisterGovernancePolicy,
            policyCID
        );
    }

    // Crea una proposta per modificare la profondità massima delle deleghe
    function proposeSetMaxDelegationDepth(
        uint256 newMaxDelegationDepth,
        bytes32 policyCID
    ) external onlyActiveOrganization returns (uint256) {
        require(newMaxDelegationDepth > 0, "Invalid depth");
        require(policyCID != bytes32(0), "Invalid policyCID");

        uint256 proposalId = _createBaseProposal(
            DataTypes.GovernanceActionType.SetMaxDelegationDepth,
            policyCID
        );

        proposals[proposalId].newMaxDelegationDepth = newMaxDelegationDepth;

        return proposalId;
    }

    // Consente a un’organizzazione attiva di votare una proposta ancora pendente
    function vote(
        uint256 proposalId,
        bool support
    ) external onlyActiveOrganization {
        PolicyProposal storage proposal = proposals[proposalId];

        require(proposal.proposalId != 0, "Proposal not found");
        require(
            proposal.status == DataTypes.PolicyProposalStatus.Pending,
            "Proposal not pending"
        );
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        hasVoted[proposalId][msg.sender] = true;

        if (support) {
            proposal.approvals += 1;
            approvers[proposalId].push(msg.sender);
        } else {
            proposal.rejections += 1;
            rejecters[proposalId].push(msg.sender);
        }

        emit PolicyVoteCast(proposalId, msg.sender, support);

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_UPDATE,
            bytes32(proposalId),
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_POLICY_VOTED
        );
    }

    // Finalizza una proposta pendente verificando il quorum e, se approvata, ne esegue l’azione
    function finalize(uint256 proposalId) external {
        PolicyProposal storage proposal = proposals[proposalId];

        require(proposal.proposalId != 0, "Proposal not found");
        require(
            proposal.status == DataTypes.PolicyProposalStatus.Pending,
            "Proposal not pending"
        );

        uint256 quorum = getRequiredQuorum(proposal.actionType);

        if (proposal.approvals >= quorum) {
            proposal.status = DataTypes.PolicyProposalStatus.Approved;

            _executeProposal(proposal);

            proposal.status = DataTypes.PolicyProposalStatus.Executed;

            emit PolicyProposalFinalized(
                proposalId,
                DataTypes.PolicyProposalStatus.Executed,
                proposal.approvals,
                proposal.rejections
            );

            auditRegistry.logEvent(
                msg.sender,
                DataTypes.ACTION_UPDATE,
                bytes32(proposalId),
                DataTypes.TARGET_POLICY,
                DataTypes.RESULT_SUCCESS,
                DataTypes.REASON_POLICY_APPROVED
            );
        } else if (proposal.rejections >= quorum) {
            proposal.status = DataTypes.PolicyProposalStatus.Rejected;

            emit PolicyProposalFinalized(
                proposalId,
                DataTypes.PolicyProposalStatus.Rejected,
                proposal.approvals,
                proposal.rejections
            );

            auditRegistry.logEvent(
                msg.sender,
                DataTypes.ACTION_UPDATE,
                bytes32(proposalId),
                DataTypes.TARGET_POLICY,
                DataTypes.RESULT_REJECTED,
                DataTypes.REASON_POLICY_REJECTED
            );
        } else {
            revert("Quorum not reached");
        }
    }

    //Calcola il quorum richiesto
    function getRequiredQuorum(
        DataTypes.GovernanceActionType actionType
    ) public view returns (uint256) {
        uint256 n = organizationRegistry.activeOrganizationCount();

        require(n > 0, "No active organizations");

        if (actionType == DataTypes.GovernanceActionType.SetGlobalPermission) {
            return (n / 2) + 1;
        }

        return (2 * n + 2) / 3;
    }

    function getProposal(
        uint256 proposalId
    ) external view returns (PolicyProposal memory) {
        require(proposals[proposalId].proposalId != 0, "Proposal not found");

        return proposals[proposalId];
    }

    function getApprovers(
        uint256 proposalId
    ) external view returns (address[] memory) {
        require(proposals[proposalId].proposalId != 0, "Proposal not found");

        return approvers[proposalId];
    }

    function getRejecters(
        uint256 proposalId
    ) external view returns (address[] memory) {
        require(proposals[proposalId].proposalId != 0, "Proposal not found");

        return rejecters[proposalId];
    }

    // Crea la parte comune di ogni proposta
    function _createBaseProposal(
        DataTypes.GovernanceActionType actionType,
        bytes32 policyCID
    ) internal returns (uint256) {
        uint256 proposalId = nextProposalId;
        nextProposalId += 1;

        proposals[proposalId].proposalId = proposalId;
        proposals[proposalId].actionType = actionType;
        proposals[proposalId].proposedBy = msg.sender;
        proposals[proposalId].createdAt = block.timestamp;
        proposals[proposalId].status = DataTypes.PolicyProposalStatus.Pending;
        proposals[proposalId].policyCID = policyCID;

        emit PolicyProposalCreated(
            proposalId,
            actionType,
            msg.sender,
            policyCID
        );

        auditRegistry.logEvent(
            msg.sender,
            DataTypes.ACTION_CREATE,
            bytes32(proposalId),
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_POLICY_PROPOSED
        );

        return proposalId;
    }

    // Esegue l’azione prevista dalla proposta approvata
    function _executeProposal(
        PolicyProposal memory proposal
    ) internal {
        if (proposal.actionType == DataTypes.GovernanceActionType.SetGlobalPermission) {
            policyRegistry.setPermissionFromGovernance(
                proposal.role,
                proposal.documentType,
                proposal.action,
                proposal.allowed,
                proposal.policyCID
            );
        } else if (proposal.actionType == DataTypes.GovernanceActionType.AddOrganization) {
            organizationRegistry.addOrganization(
                proposal.targetOrganization,
                proposal.organizationCID
            );
        } else if (proposal.actionType == DataTypes.GovernanceActionType.SuspendOrganization) {
            organizationRegistry.suspendOrganization(proposal.targetOrganization);
        } else if (proposal.actionType == DataTypes.GovernanceActionType.RevokeOrganization) {
            organizationRegistry.revokeOrganization(proposal.targetOrganization);
        } else if (proposal.actionType == DataTypes.GovernanceActionType.ReactivateOrganization) {
            organizationRegistry.reactivateOrganization(proposal.targetOrganization);
        } else if (proposal.actionType == DataTypes.GovernanceActionType.RegisterGovernancePolicy) {
            // Nel prototipo WP4 la policy di governance approvata è ancorata tramite policyCID.
            // Non è necessaria un'ulteriore transizione automatica.
        }else if (proposal.actionType == DataTypes.GovernanceActionType.SetMaxDelegationDepth) {
            policyRegistry.setMaxDelegationDepthFromGovernance(
                proposal.newMaxDelegationDepth,
                proposal.policyCID
            );
        }else {
            revert("Unsupported governance action");
        }

        auditRegistry.logEvent(
            address(this),
            DataTypes.ACTION_UPDATE,
            proposal.policyCID,
            DataTypes.TARGET_POLICY,
            DataTypes.RESULT_SUCCESS,
            DataTypes.REASON_POLICY_EXECUTED
        );
    }
}