// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DataTypes.sol";

/**
 * @title AuditRegistry
 * @dev Registro di audit semplificato per il WP4.
 *
 * Nel design teorico del WP2, gli audit log completi sono aggregati in batch,
 * salvati off-chain e ancorati sul ledger tramite hash/CID.
 *
 * Nel prototipo WP4, invece, l'audit è implementato tramite eventi Solidity.
 * Solo i contratti autorizzati possono emettere eventi di audit.
 */
contract AuditRegistry {
    // Dati di bootstrap: amministratore iniziale, stato del bootstrap e mapping degli emitter autorizzati
    address public immutable bootstrapAdmin;
    bool public bootstrapLocked;

    mapping(address => bool) public authorizedEmitters;

    // Evento principale di audit usato per tracciare attore, azione, target, esito, motivo e timestamp
    event AuditEvent(
        address indexed actor,
        bytes32 indexed action,
        bytes32 indexed targetId,
        bytes32 targetType,
        bytes32 result,
        bytes32 reasonCode,
        uint256 timestamp
    );

    // Evento emesso quando un indirizzo viene autorizzato o rimosso dagli emitter di audit
    event AuthorizedEmitterSet(
        address indexed emitter,
        bool authorized
    );

    // Evento emesso quando la fase di bootstrap viene chiusa definitivamente
    event BootstrapLocked(uint256 timestamp);

    modifier onlyBootstrapAdmin() {
        require(msg.sender == bootstrapAdmin, "Only bootstrap admin");
        _;
    }

    modifier onlyDuringBootstrap() {
        require(!bootstrapLocked, "Bootstrap locked");
        _;
    }

    modifier onlyAuthorizedEmitter() {
        require(authorizedEmitters[msg.sender], "Not authorized emitter");
        _;
    }

    constructor() {
        bootstrapAdmin = msg.sender;
        authorizedEmitters[msg.sender] = true;
    }

    // Aggiunge o rimuove un indirizzo dagli emitter autorizzati durante la fase di bootstrap
    function setAuthorizedEmitter(
        address emitter,
        bool authorized
    ) external onlyBootstrapAdmin onlyDuringBootstrap {
        require(emitter != address(0), "Invalid emitter");

        authorizedEmitters[emitter] = authorized;

        emit AuthorizedEmitterSet(emitter, authorized);
    }

    function lockBootstrap() external onlyBootstrapAdmin onlyDuringBootstrap {
        bootstrapLocked = true;

        emit BootstrapLocked(block.timestamp);
    }

    // Registra un evento di audit Solidity per conto di un contratto autorizzato
    function logEvent(
        address actor,
        bytes32 action,
        bytes32 targetId,
        bytes32 targetType,
        bytes32 result,
        bytes32 reasonCode
    ) external onlyAuthorizedEmitter {
        emit AuditEvent(
            actor,
            action,
            targetId,
            targetType,
            result,
            reasonCode,
            block.timestamp
        );
    }
}