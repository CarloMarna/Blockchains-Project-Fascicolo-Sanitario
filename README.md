# Blockchains-Project-Fascicolo-Sanitario Decentralized Document Lifecycle & Access Control

Progetto basato su **Solidity**, **Hardhat** e **TypeScript** per la gestione decentralizzata del ciclo di vita di documenti sensibili e del controllo degli accessi.

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
