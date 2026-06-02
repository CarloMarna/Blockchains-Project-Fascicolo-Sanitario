<<<<<<< HEAD
PER ESEGUIRE LA VERSIONE LOCALE DI NDOE:
 1. SPOSTARSI NELLA CARTELLA DEL PROGETTO COL CMD
 2. LANCIARE: .\node-locale.cmd
 
 | Contratto | Entità corrispondente nel progetto | Cosa fa | A cosa serve |
|---|---|---|---|
| `DataTypes.sol` | Vocabolario comune del sistema | Definisce stati, ruoli, tipi di azione, tipi di risorsa, esiti e reason code usati dagli altri contratti. | Serve a rendere coerenti tutti i contratti, evitando che ogni registry usi codici diversi per gli stessi concetti, ad esempio `READ`, `CREATE`, `REVOKE`, `Certified`, `Archived`, `Revoked`, `Active`, `Suspended`. |
| `AuditRegistry.sol` | Audit Registry | Registra eventi di audit tramite eventi Solidity. Solo gli emitter autorizzati possono invocare `logEvent`. | Serve per accountability e ricostruzione ex post: permette di sapere chi ha fatto cosa, su quale risorsa, con quale esito e per quale motivo. |
| `OrganizationRegistry.sol` | Registro delle organizzazioni / autorità di governance | Registra le organizzazioni riconosciute dal sistema come indirizzi Ethereum, associando a ciascuna uno stato: attiva, sospesa o revocata. Mantiene anche `activeOrganizationCount`. | Serve a delimitare il perimetro della governance. Solo le organizzazioni attive possono proporre, votare e modificare le regole del sistema. |
| `PolicyGovernance.sol` | Meccanismo di governance multi-authority | Implementa il flusso proposta → voto → quorum → esecuzione. Permette alle organizzazioni attive di modificare policy globali, permessi, organizzazioni e profondità massima delle deleghe. | Serve a evitare che un singolo admin possa modificare unilateralmente le regole. Le modifiche rilevanti richiedono il quorum. |
| `PolicyRegistry.sol` | Global Policy Registry | Contiene le policy globali di accesso. I permessi sono definiti come combinazione tra ruolo applicativo, tipo di documento e azione. Collega anche il tipo di VC a un ruolo applicativo e conserva `maxDelegationDepth`. | Serve a stabilire se un soggetto, tramite una VC valida, può compiere una certa azione su una certa categoria documentale. |
| `DocumentLifecycleRegistry.sol` | Document Lifecycle Registry | Registra i documenti come record versionati: `documentId`, `patientDID`, `creatorDID`, tipo documento, CID, stato, versione corrente e riferimento alla versione precedente. | Serve a mantenere lo stato ufficiale del documento: esistenza, versione corrente, stato `Certified`/`Archived`/`Revoked`, CID e paziente associato. |
| `PatientDrivenPolicyRegistry.sol` | Patient-Driven Policy Registry | Implementa le restrizioni definite dal paziente. Una policy patient-driven può limitare l’accesso a uno specifico documento in base a utente, azione e finalità. | Serve a dare al paziente controllo restrittivo sui propri documenti. Non amplia i permessi globali, ma può solo restringerli. |
| `DelegationRegistry.sol` | Delegation Registry | Gestisce proposte di delega, approvazione o rifiuto da parte del paziente, creazione della delega, deleghe derivate, revoca e verifica della catena. | Serve a rappresentare diritti temporanei e derivati. Un utente può agire tramite delega solo se questa è valida, approvata, non scaduta e non revocata. |
| `AccessController.sol` | Policy Engine / decisione autorizzativa | Coordina `IdentityRegistry`, `DocumentLifecycleRegistry`, `PatientDrivenPolicyRegistry`, `DelegationRegistry`, `PolicyRegistry` e `AuditRegistry` per decidere se una richiesta di accesso è ammessa. | Serve a produrre la decisione finale `allow`/`deny`. Non recupera né decifra il documento: decide solo se l’accesso è autorizzato. |
| `IdentityRegistry.sol` | Identity Registry | Registra i DID degli attori del sistema. Per ogni DID conserva controller Ethereum, CID/hash del DID Document off-chain, stato e versione. | Serve a verificare l’identità tecnica degli attori e a controllare se un DID è attivo e associato al corretto controller Ethereum. |
| `CredentialStatusRegistry.sol` | Credential Status Registry | Registra lo stato delle Verifiable Credentials senza salvare la VC completa on-chain. Conserva `credentialId`, `issuerDID`, `subjectDID`, `credentialType`, hash, stato e validità temporale. | Serve a verificare se una credenziale è ancora utilizzabile. Una VC firmata può essere valida tecnicamente ma non accettabile se sospesa, revocata o scaduta. |
| `TrustRegistry.sol` | Trust Registry | Registra quali issuer DID sono autorizzati a emettere specifici tipi di credenziali. | Serve a evitare che qualunque organizzazione possa emettere qualsiasi VC. Una credenziale è accettata solo se l’issuer è riconosciuto per quello specifico `credentialType`. |
=======
# Blockchains-Project-Fascicolo-Sanitario -- Decentralized Document Lifecycle & Access Control

Progetto basato su **Solidity**, **Hardhat** e per la gestione decentralizzata del ciclo di vita di documenti sensibili e del controllo degli accessi.

Il sistema è pensato per un contesto **multi-organizzazione**, ad esempio sanitario, in cui più enti devono cooperare nella gestione di documenti, policy, deleghe, revoche e audit senza affidarsi a una singola autorità centrale.

## Obiettivo

L’obiettivo del progetto è realizzare un prototipo che permetta di:

- registrare documenti e versioni documentali;
- gestire il ciclo di vita dei documenti;
- definire policy di accesso;
- applicare restrizioni definite dal paziente;
- gestire deleghe e revoche;
- controllare le richieste di accesso;
- registrare eventi utili per audit e tracciabilità.

## Tecnologie utilizzate

- Solidity
- Hardhat
- TypeScript
- Node.js
- npm
- Hardhat Network

## Smart contract principali

Il progetto include diversi smart contract, tra cui:

- `DataTypes.sol`
- `AuditRegistry.sol`
- `OrganizationRegistry.sol`
- `PolicyGovernance.sol`
- `PolicyRegistry.sol`
- `DocumentLifecycleRegistry.sol`
- `PatientDrivenPolicyRegistry.sol`
- `DelegationRegistry.sol`
- `AccessController.sol`

Il contratto `AccessController.sol` è il componente principale per verificare se un utente può accedere a un determinato documento, considerando policy, credenziali, deleghe, revoche e stato del documento.

## Requisiti

Prima di eseguire il progetto è necessario avere installato:

- Node.js
- npm

Per verificare l’installazione:

```bash
node -v
npm -v
```

## Installazione

Entrare nella cartella del progetto:

```bash
cd .\node-locale
```

Installare le dipendenze:

```bash
npm install
```

## Compilazione

Per compilare gli smart contract:

```bash
npx hardhat compile
```

## Deploy

Per eseguire il deploy degli smart contract:

```bash
npx hardhat run scripts/deploy.ts
```

## Test

Per eseguire i test:

```bash
npx hardhat test
```

## Comandi principali

```bash
cd .\node-locale
npm install
npx hardhat compile
npx hardhat run scripts/deploy.ts
npx hardhat test
```

## Funzionamento generale

Il sistema utilizza smart contract per registrare informazioni relative a documenti, policy, deleghe, revoche e audit.

I documenti completi non vengono necessariamente salvati on-chain. La blockchain viene usata per conservare riferimenti, hash, stati e metadati verificabili, mentre i contenuti possono essere mantenuti off-chain.

Il controllo degli accessi viene effettuato verificando:

- identità dell’utente;
- ruolo e attributi;
- policy globali;
- eventuali restrizioni definite dal paziente;
- deleghe attive;
- revoche;
- stato corrente del documento.

## Note

Il progetto è un prototipo sviluppato a scopo accademico e sperimentale.

Non è pensato per l’utilizzo diretto in produzione, ma per dimostrare il funzionamento di un sistema decentralizzato per la gestione sicura di documenti sensibili.
>>>>>>> f6a4837a6f1a9e75c690849ad86f317a963f584e
