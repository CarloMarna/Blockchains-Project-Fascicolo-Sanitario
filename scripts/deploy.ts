import { network } from "hardhat";
import Crypto from "node:crypto";
import { SDJwtInstance } from "@sd-jwt/core";
import {
  addFile,
  getFileAsString,
  saveFileToDisk,
  stopNode,
} from "../ipfs/helia-node.js";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

async function main() {

  // ----------Inizializzazione dell'ambiente off-chain, IPFS, SD-JWT, account e costanti di test----------

  const IPFS_OUTPUT_DIR = path.join(process.cwd(), "ipfs-output");
  // =====================================================
  // SD-JWT OFF-CHAIN SETUP
  // =====================================================
  // Questo rappresenta il livello wallet/verifier off-chain.
  // Gli smart contract NON verificano direttamente SD-JWT.
  // La verifica SD-JWT avviene prima della chiamata ad AccessController.

  const {
    privateKey: sdJwtIssuerPrivateKey,
    publicKey: sdJwtIssuerPublicKey
  } = Crypto.generateKeyPairSync("ed25519");

  const sdjwt = new SDJwtInstance({
    signer: async (data: string) => {
      const signature = Crypto.sign(
        null,
        Buffer.from(data),
        sdJwtIssuerPrivateKey
      );

      return Buffer.from(signature).toString("base64url");
    },

    verifier: async (data: string, signature: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        sdJwtIssuerPublicKey,
        Buffer.from(signature, "base64url")
      );
    },

    signAlg: "EdDSA",

    hasher: async (data: string | Uint8Array, alg: string) => {
      if (alg !== "sha-256") {
        throw new Error(`Algoritmo hash non supportato: ${alg}`);
      }

      return new Uint8Array(
        Crypto.createHash("sha256").update(data).digest()
      );
    },

    hashAlg: "sha-256",

    saltGenerator: async () => {
      return Crypto.randomBytes(16).toString("base64url");
    }
  });

  const issuedSdJwtCredentials = new Map<string, any>();
  await mkdir(IPFS_OUTPUT_DIR, { recursive: true });

  const { ethers } = await network.connect();

  async function deployContract(name, args = []) {
    const Factory = await ethers.getContractFactory(name);
    const contract = await Factory.deploy(...args);
    await contract.waitForDeployment();

    const address = await contract.getAddress();
    console.log(`   Ok. ${name} deployed at: ${address}`);

    return contract;
  }

  function hash(value) {
    return ethers.keccak256(ethers.toUtf8Bytes(value));
  }

  function cidToBytes32(cid) {
    // Nel WP2 il CID completo resta off-chain/applicativo; on-chain salviamo un riferimento bytes32.
    return hash(`CID:${cid}`);
  }

  function printSection(title) {
    console.log("\n============================================================");
    console.log(title);
    console.log("============================================================");
  }

  function printStep(message) {
    console.log(`\n> ${message}`);
  }

  function printResult(message) {
    console.log(`   Ok. ${message}`);
  }

  function printCheck(message, value) {
    console.log(`   ${value ? "V" : "X"} ${message}: ${value}`);
  }

  async function authorizeEmitter(auditRegistry, emitter, label) {
    await (
      await auditRegistry.setAuthorizedEmitter(
        await emitter.getAddress(),
        true
      )
    ).wait();

    printResult(`Audit emitter autorizzato: ${label}`);
  }

  const offchainAssets = [];
  const globalPolicyRecords = [];
  const governancePolicyRecords = [];
  const patientPolicyRecords = [];
  const auditBatchRecords = [];

  async function addJsonToIPFS(label, payload, category = "generic-json") {
    const json = JSON.stringify(payload, null, 2);
    const cid = await addFile(json);
    const record = {
      category,
      label,
      contentType: "application/json",
      cid,
      cidHash: cidToBytes32(cid),
      contentHash: hash(json)
    };

    offchainAssets.push(record);
    console.log(`   CID IPFS ${label}: ${cid}`);

    return {
      ...record,
      json
    };
  }

  async function addTextToIPFS(label, text, category = "document") {
    const cid = await addFile(text);
    const record = {
      category,
      label,
      contentType: "text/plain",
      cid,
      cidHash: cidToBytes32(cid),
      contentHash: hash(text)
    };

    offchainAssets.push(record);
    console.log(`   CID IPFS ${label}: ${cid}`);

    return {
      ...record,
      text
    };
  }


  function safeFileName(value) {
    return String(value)
      .replace(/[^a-z0-9._-]+/gi, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 90);
  }

  const [
    deployer,
    organization1,
    organization2,
    organization3,
    doctor,
    patient,
    delegatedDoctor,
    secondDelegatedDoctor,
    auditor,
    unauthorizedUser,
    doctorD
  ] = await ethers.getSigners();

  const ROLE = {
    Patient: 1,
    Doctor: 2,
    Nurse: 3,
    Auditor: 4,
    ExternalRequester: 5,
    Technician: 6
  };

  const ACTION_READ = hash("READ");
  const ACTION_CREATE = hash("CREATE");
  const ACTION_UPDATE = hash("UPDATE");
  const ACTION_REVOKE = hash("REVOKE");
  const ACTION_DELEGATE = hash("DELEGATE");

  const DOCUMENT_TYPE_REFERTO = hash("REFERTO");
  const PURPOSE_CARE = hash("CONTINUITA_ASSISTENZIALE");

  const VC_MEDICAL_PROFESSIONAL = hash("MedicalProfessionalVC");
  const VC_AUDITOR_PROFESSIONAL = hash("AuditorProfessionalVC");

  const DID_ORG1 = hash("did:health:org:1");
  const DID_ORG2 = hash("did:health:org:2");
  const DID_ORG3 = hash("did:health:org:3");
  const DID_DOCTOR = hash("did:health:doctor:alice");
  const DID_PATIENT = hash("did:health:patient:bob");
  const DID_DELEGATED_DOCTOR = hash("did:health:doctor:charlie");
  const DID_SECOND_DELEGATED_DOCTOR = hash("did:health:doctor:diana");
  const DID_AUDITOR = hash("did:health:auditor:ana");
  const DID_UNAUTHORIZED = hash("did:health:unknown:eve");
  const DID_DOCTOR_D = hash("did:health:doctor:daniel");

  const CRED_DOCTOR = hash("vc:doctor:alice:medical-professional:v1");
  const CRED_DOCTOR_D = hash("vc:doctor:daniel:medical-professional:v1");
  const CRED_AUDITOR = hash("vc:auditor:ana:auditor-professional:v1");

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const EMPTY_PRESENTED_CREDENTIAL = {
    format: "",
    id: "",
    issuer: "",
    subject: "",
    credentialType: "",
    sdJwtCredential: "",
    selectivelyDisclosableClaims: []
  };

  const presentedCredentials = new Map<string, any>();

  function encodeDisclosedClaims(claims = {}) {
    const disclosedAttributeKeys = [];
    const disclosedAttributeValues = [];

    for (const [key, value] of Object.entries(claims)) {
      disclosedAttributeKeys.push(hash(key));
      disclosedAttributeValues.push(hash(String(value)));
    }

    return { disclosedAttributeKeys, disclosedAttributeValues };
  }

  function fullPresentedCredentialDigest(unsignedPresentedCredential) {
    return ethers.keccak256(
      abiCoder.encode(
        [
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32[]",
          "bytes32[]",
          "bytes32"
        ],
        [
          unsignedPresentedCredential.credentialId,
          unsignedPresentedCredential.issuerDID,
          unsignedPresentedCredential.subjectDID,
          unsignedPresentedCredential.credentialType,
          unsignedPresentedCredential.disclosedAttributeKeys,
          unsignedPresentedCredential.disclosedAttributeValues,
          unsignedPresentedCredential.presentationContext
        ]
      )
    );
  }

  async function buildPresentedCredential({
    credentialId,
    issuerDID,
    subjectDID,
    credentialType,
    presentationContext,
    issuerSigner,
    claims = {}
  }) {
    const { disclosedAttributeKeys, disclosedAttributeValues } =
      encodeDisclosedClaims(claims);

    const unsignedPresentedCredential = {
      credentialId,
      issuerDID,
      subjectDID,
      credentialType,
      disclosedAttributeKeys,
      disclosedAttributeValues,
      presentationContext
    };

    const credentialDigest = fullPresentedCredentialDigest(
      unsignedPresentedCredential
    );

    const issuerSignature = await issuerSigner.signMessage(
      ethers.getBytes(credentialDigest)
    );

    return {
      ...unsignedPresentedCredential,
      issuerSignature
    };
  }

  printSection("ACCOUNTS");

  console.log("Deployer / bootstrap admin:", deployer.address);
  console.log("Organization 1:", organization1.address);
  console.log("Organization 2:", organization2.address);
  console.log("Organization 3:", organization3.address);
  console.log("Doctor A:", doctor.address);
  console.log("Patient:", patient.address);
  console.log("Doctor B - delegated doctor:", delegatedDoctor.address);
  console.log("Doctor C - second-level delegated doctor:", secondDelegatedDoctor.address);
  console.log("Auditor:", auditor.address);
  console.log("Unauthorized user / possible Doctor D:", unauthorizedUser.address);
  console.log("Doctor D - patient allowed doctor:", doctorD.address);

// ---------Deploy dei registri di base---------

  printSection("1. DEPLOY DEI REGISTRI BASE");

  printStep("Deploy di AuditRegistry");
  const auditRegistry = await deployContract("AuditRegistry");

  printStep("Deploy di OrganizationRegistry");
  const organizationRegistry = await deployContract(
    "OrganizationRegistry",
    [await auditRegistry.getAddress()]
  );

  printStep("Deploy di IdentityRegistry");
  const identityRegistry = await deployContract(
    "IdentityRegistry",
    [await auditRegistry.getAddress()]
  );

  printSection("2. AUTORIZZAZIONE DEGLI AUDIT EMITTER INIZIALI");

  printStep("Autorizzo OrganizationRegistry a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, organizationRegistry, "OrganizationRegistry");

  printStep("Autorizzo IdentityRegistry a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, identityRegistry, "IdentityRegistry");

//---------Bootstrap delle organizzazioni---------

  printSection("3. BOOTSTRAP DELLE ORGANIZZAZIONI");

  printStep("Aggiungo Organization 1 come autorità attiva");
  await (
    await organizationRegistry.addOrganization(
      organization1.address,
      hash("Organization 1 metadata")
    )
  ).wait();

  printStep("Aggiungo Organization 2 come autorità attiva");
  await (
    await organizationRegistry.addOrganization(
      organization2.address,
      hash("Organization 2 metadata")
    )
  ).wait();

  printStep("Aggiungo Organization 3 come autorità attiva");
  await (
    await organizationRegistry.addOrganization(
      organization3.address,
      hash("Organization 3 metadata")
    )
  ).wait();

  const activeOrgCount = await organizationRegistry.activeOrganizationCount();
  printResult(`Organizzazioni attive: ${activeOrgCount.toString()}`);

  //---------Registrazione DID e DID Document---------

  printSection("4. REGISTRAZIONE DID E DID DOCUMENT SU IPFS");

  async function registerDIDWithDocument(signer, did, didString, roleLabel, controllerAddress) {
    printStep(`Creo DID Document off-chain per ${roleLabel}`);

    const didDocument = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: didString,
      controller: controllerAddress,
      verificationMethod: [
        {
          id: `${didString}#keys-1`,
          type: "EcdsaSecp256k1RecoveryMethod2020",
          controller: didString,
          blockchainAccountId: `eip155:31337:${controllerAddress}`
        }
      ],
      authentication: [`${didString}#keys-1`],
      assertionMethod: [`${didString}#keys-1`],
      service: [
        {
          id: `${didString}#health-service`,
          type: "HealthDocumentService",
          serviceEndpoint: `ipfs://metadata/${didString}`
        }
      ]
    };

    const storedDocument = await addJsonToIPFS(`DID Document ${roleLabel}`, didDocument, "did-document");

    await (
      await identityRegistry
        .connect(signer)
        .registerDID(
          did,
          storedDocument.cidHash,
          storedDocument.contentHash
        )
    ).wait();

    printResult(`DID registrato per ${roleLabel}`);

    return {
      did,
      didString,
      roleLabel,
      controller: controllerAddress,
      didDocumentCID: storedDocument.cid,
      didDocumentCIDHash: storedDocument.cidHash,
      didDocumentHash: storedDocument.contentHash
    };
  }

  const didRecords = {
    org1: await registerDIDWithDocument(organization1, DID_ORG1, "did:health:org:1", "Organization 1", organization1.address),
    org2: await registerDIDWithDocument(organization2, DID_ORG2, "did:health:org:2", "Organization 2", organization2.address),
    org3: await registerDIDWithDocument(organization3, DID_ORG3, "did:health:org:3", "Organization 3", organization3.address),
    doctor: await registerDIDWithDocument(doctor, DID_DOCTOR, "did:health:doctor:alice", "Doctor A", doctor.address),
    patient: await registerDIDWithDocument(patient, DID_PATIENT, "did:health:patient:bob", "Patient", patient.address),
    delegatedDoctor: await registerDIDWithDocument(delegatedDoctor, DID_DELEGATED_DOCTOR, "did:health:doctor:charlie", "Doctor B", delegatedDoctor.address),
    secondDelegatedDoctor: await registerDIDWithDocument(secondDelegatedDoctor, DID_SECOND_DELEGATED_DOCTOR, "did:health:doctor:diana", "Doctor C", secondDelegatedDoctor.address),
    auditor: await registerDIDWithDocument(auditor, DID_AUDITOR, "did:health:auditor:ana", "Auditor", auditor.address),
    unauthorizedUser: await registerDIDWithDocument(unauthorizedUser, DID_UNAUTHORIZED, "did:health:unknown:eve", "Unauthorized user / Doctor D", unauthorizedUser.address),
    doctorD: await registerDIDWithDocument(doctorD, DID_DOCTOR_D, "did:health:doctor:daniel", "Doctor D", doctorD.address)
  };

  printCheck("DID medico attivo", await identityRegistry.isActiveDID(DID_DOCTOR));
  printCheck("DID paziente attivo", await identityRegistry.isActiveDID(DID_PATIENT));
  printCheck("Controller DID medico corretto", (await identityRegistry.controllerOf(DID_DOCTOR)) === doctor.address);

  //---------Trust Registry e Credential Status Registry---------

  printSection("5. TRUST REGISTRY E CREDENTIAL STATUS REGISTRY");

  printStep("Deploy di TrustRegistry");
  const trustRegistry = await deployContract(
    "TrustRegistry",
    [
      await identityRegistry.getAddress(),
      await organizationRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Autorizzo TrustRegistry a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, trustRegistry, "TrustRegistry");

  printStep("Autorizzo il DID di Organization 1 come issuer fidato per le VC del dominio sanitario");
  await (await trustRegistry.authorizeIssuer(DID_ORG1, VC_MEDICAL_PROFESSIONAL)).wait();
  await (await trustRegistry.authorizeIssuer(DID_ORG1, VC_AUDITOR_PROFESSIONAL)).wait();

  printCheck(
    "Organization 1 è trusted issuer per MedicalProfessionalVC",
    await trustRegistry.isTrustedIssuer(DID_ORG1, VC_MEDICAL_PROFESSIONAL)
  );

  printStep("Deploy di CredentialStatusRegistry");
  const credentialRegistry = await deployContract(
    "CredentialStatusRegistry",
    [
      await identityRegistry.getAddress(),
      await trustRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Autorizzo CredentialStatusRegistry a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, credentialRegistry, "CredentialStatusRegistry");

  const latestBlockForCredentials = await ethers.provider.getBlock("latest");
  const validFromCredential = BigInt(latestBlockForCredentials.timestamp);
  const validUntilCredential = validFromCredential + 365n * 24n * 60n * 60n;

  async function issueVC(
    credentialId,
    issuerSigner,
    issuerDID,
    subjectDID,
    credentialType,
    label,
    attributes
  ) {
    printStep(`Creo VC off-chain per ${label} e salvo solo lo stato minimo on-chain`);

    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: label,
      type: ["VerifiableCredential", attributes.typeName],
      issuer: attributes.issuer,
      issuanceDate: new Date(Number(validFromCredential) * 1000).toISOString(),
      expirationDate: new Date(Number(validUntilCredential) * 1000).toISOString(),
      credentialSubject: {
        id: attributes.subject,
        ...attributes.claims
      }
    };

    let storedVC;
    let credentialFormat = "JSON-VC";

    storedVC = await addJsonToIPFS(
      `VC ${label}`,
      vcPayload,
      "verifiable-credential"
    );


    await (
      await credentialRegistry
        .connect(issuerSigner)
        .issueCredential(
          credentialId,
          issuerDID,
          credentialType,
          validFromCredential,
          validUntilCredential
        )
    ).wait();

    const presentedCredential = await buildPresentedCredential({
      credentialId,
      issuerDID,
      subjectDID,
      credentialType,
      presentationContext: hash(`presentation-context:${label}`),
      issuerSigner,
      claims: attributes.claims
    });

    presentedCredentials.set(credentialId, presentedCredential);

    printResult(`VC emessa: ${label} (${credentialFormat})`);

    return {
      credentialId,
      credentialCID: storedVC.cid,
      format: credentialFormat,
      presentedCredential,
      vcPayload
    };
  }
  async function issueVCSDJWT(
    credentialId,
    issuerSigner,
    issuerDID,
    subjectDID,
    credentialType,
    label,
    attributes
  ) {
    const jwtNow = Math.floor(Date.now() / 1000);
    const jwtValidFrom = jwtNow - 60; // tolleranza anti clock-skew
    const jwtValidUntil = jwtNow + 365 * 24 * 60 * 60;
    const sdJwtClaims = {
      iss: attributes.issuer,
      sub: attributes.subject,
      vct: attributes.typeName,
      jti: label,
      iat: jwtNow,
      nbf: jwtValidFrom,
      exp: jwtValidUntil,

      onChainCredentialId: credentialId,

      ...attributes.claims
    };

    const selectivelyDisclosableClaims =
      attributes.selectivelyDisclosableClaims ?? Object.keys(attributes.claims);

    const disclosureFrame = {
      _sd: selectivelyDisclosableClaims
    };

    const sdJwtCredential = await sdjwt.issue(
      sdJwtClaims,
      disclosureFrame
    );

    const sdJwtPackage = {
      format: "vc+sd-jwt",
      note: "Credential SD-JWT off-chain. On-chain viene salvato solo lo stato minimo: credentialId, issuer, tipo e validità. Subject e attributi vengono presentati con selective disclosure.",
      id: label,
      issuer: attributes.issuer,
      subject: attributes.subject,

      // Campo letto dalla struct Solidity
      credentialType: attributes.typeName,

      // Campo mantenuto solo per comodità lato TypeScript/off-chain
      type: attributes.typeName,

      sdJwtCredential,
      selectivelyDisclosableClaims
    };

    issuedSdJwtCredentials.set(credentialId, sdJwtPackage);

    return sdJwtPackage;
  }
  const vcRecords = {
    doctor: await issueVC(
      CRED_DOCTOR,
      organization1,
      DID_ORG1,
      DID_DOCTOR,
      VC_MEDICAL_PROFESSIONAL,
      "vc:doctor:alice:medical-professional:v1",
      {
        format: "SD-JWT",
        typeName: "MedicalProfessionalVC",
        issuer: "did:health:org:1",
        subject: "did:health:doctor:alice",
        selectivelyDisclosableClaims: [
          "role",
          "organization",
          "department"
        ],
        claims: {
          role: "Doctor",
          organization: "Organization 1",
          department: "Cardiology"
        }
      }
    ),
    auditor: await issueVC(
      CRED_AUDITOR,
      organization1,
      DID_ORG1,
      DID_AUDITOR,
      VC_AUDITOR_PROFESSIONAL,
      "vc:auditor:ana:auditor-professional:v1",
      {
        typeName: "AuditorProfessionalVC",
        issuer: "did:health:org:1",
        subject: "did:health:auditor:ana",
        claims: {
          role: "Auditor",
          scope: "healthcare-document-audit"
        }
      }
    ),
    doctorD: await issueVC(
    CRED_DOCTOR_D,
    organization1,
    DID_ORG1,
    DID_DOCTOR_D,
    VC_MEDICAL_PROFESSIONAL,
    "vc:doctor:daniel:medical-professional:v1",
    {
      format: "SD-JWT",
      typeName: "MedicalProfessionalVC",
      issuer: "did:health:org:1",
      subject: "did:health:doctor:daniel",
      selectivelyDisclosableClaims: [
        "role",
        "organization",
        "department"
      ],
      claims: {
        role: "Doctor",
        organization: "Organization 1",
        department: "Neurology"
      }
    }
  )
  };
  const vcSDJWTRecords = {
    doctor: await issueVCSDJWT(
      CRED_DOCTOR,
      organization1,
      DID_ORG1,
      DID_DOCTOR,
      VC_MEDICAL_PROFESSIONAL,
      "vc:doctor:alice:medical-professional:v1",
      {
        typeName: "MedicalProfessionalVC",
        issuer: "did:health:org:1",
        subject: "did:health:doctor:alice",
        selectivelyDisclosableClaims: [
          "role",
          "organization",
          "department"
        ],
        claims: {
          role: "Doctor",
          organization: "Organization 1",
          department: "Cardiology"
        }
      }
    ),
    auditor: await issueVCSDJWT(
      CRED_AUDITOR,
      organization1,
      DID_ORG1,
      DID_AUDITOR,
      VC_AUDITOR_PROFESSIONAL,
      "vc:auditor:ana:auditor-professional:v1",
      {
        typeName: "AuditorProfessionalVC",
        issuer: "did:health:org:1",
        subject: "did:health:auditor:ana",
        claims: {
          role: "Auditor",
          scope: "healthcare-document-audit"
        }
      }
    ),
    doctorD: await issueVCSDJWT(
      CRED_DOCTOR_D,
      organization1,
      DID_ORG1,
      DID_DOCTOR_D,
      VC_MEDICAL_PROFESSIONAL,
      "vc:doctor:daniel:medical-professional:v1",
      {
        typeName: "MedicalProfessionalVC",
        issuer: "did:health:org:1",
        subject: "did:health:doctor:daniel",
        selectivelyDisclosableClaims: [
          "role",
          "organization",
          "department"
        ],
        claims: {
          role: "Doctor",
          organization: "Organization 1",
          department: "Neurology"
        }
      }
    )

  };

  const doctorPresentedCredential = vcSDJWTRecords.doctor;
  const auditorPresentedCredential = vcSDJWTRecords.auditor;
  const doctorDPresentedCredential = vcSDJWTRecords.doctorD;

  printCheck(
    "VC medico presentata valida per il DID del medico",
    await credentialRegistry.isPresentedCredentialValidForSubject(
      doctorPresentedCredential,
      DID_DOCTOR
    )
  );

  printCheck(
    "VC Doctor D presentata valida per il DID di Doctor D",
    await credentialRegistry.isPresentedCredentialValidForSubject(
      doctorDPresentedCredential,
      DID_DOCTOR_D
    )
  );

  console.log("\nNota demo:");
  console.log(" - Doctor B e Doctor C non ricevono una VC professionale globale.");
  console.log(" - Potranno accedere solo se esiste una delega DID valida.");

//---------Policy Registry e Policy Governance---------

  printSection("6. DEPLOY DI POLICY REGISTRY E GOVERNANCE");

  printStep("Deploy di PolicyRegistry");
  const policyRegistry = await deployContract(
    "PolicyRegistry",
    [
      await organizationRegistry.getAddress(),
      await credentialRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Autorizzo PolicyRegistry a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, policyRegistry, "PolicyRegistry");

  printStep("Configuro mapping CredentialType -> Role applicativo");
  await (await policyRegistry.setCredentialTypeRole(VC_MEDICAL_PROFESSIONAL, ROLE.Doctor)).wait();
  await (await policyRegistry.setCredentialTypeRole(VC_AUDITOR_PROFESSIONAL, ROLE.Auditor)).wait();
  printResult("MedicalProfessionalVC -> Doctor, AuditorProfessionalVC -> Auditor");

  printStep("Deploy di PolicyGovernance");
  const policyGovernance = await deployContract(
    "PolicyGovernance",
    [
      await organizationRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Autorizzo PolicyGovernance a scrivere eventi di audit");
  await authorizeEmitter(auditRegistry, policyGovernance, "PolicyGovernance");

  printSection("7. COLLEGAMENTO DELLA GOVERNANCE");

  printStep("Collego PolicyGovernance a OrganizationRegistry");
  await (
    await organizationRegistry.setGovernanceContract(
      await policyGovernance.getAddress()
    )
  ).wait();
  printResult("PolicyGovernance può ora modificare lo stato delle organizzazioni dopo quorum");

  printStep("Collego PolicyGovernance a PolicyRegistry");
  await (
    await policyRegistry.setGovernanceContract(
      await policyGovernance.getAddress()
    )
  ).wait();
  printResult("PolicyGovernance può ora modificare le policy globali dopo quorum");

  printStep("Collego PolicyGovernance a TrustRegistry");
  await (
    await trustRegistry.setGovernanceContract(
      await policyGovernance.getAddress()
    )
  ).wait();
  printResult("TrustRegistry ha un governanceContract configurato");

  //---------Contratti operativi---------

  printSection("8. DEPLOY DEI CONTRATTI OPERATIVI");

  printStep("Deploy di DocumentLifecycleRegistry");
  const documentLifecycleRegistry = await deployContract(
    "DocumentLifecycleRegistry",
    [
      await identityRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Deploy di PatientDrivenPolicyRegistry");
  const patientDrivenPolicyRegistry = await deployContract(
    "PatientDrivenPolicyRegistry",
    [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Deploy di DelegationRegistry");
  const delegationRegistry = await deployContract(
    "DelegationRegistry",
    [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printStep("Deploy di AccessController");
  const accessController = await deployContract(
    "AccessController",
    [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await delegationRegistry.getAddress(),
      await patientDrivenPolicyRegistry.getAddress(),
      await auditRegistry.getAddress()
    ]
  );

  printSection("9. AUTORIZZAZIONE DEGLI AUDIT EMITTER OPERATIVI");

  printStep("Autorizzo DocumentLifecycleRegistry");
  await authorizeEmitter(auditRegistry, documentLifecycleRegistry, "DocumentLifecycleRegistry");

  printStep("Autorizzo PatientDrivenPolicyRegistry");
  await authorizeEmitter(auditRegistry, patientDrivenPolicyRegistry, "PatientDrivenPolicyRegistry");

  printStep("Autorizzo DelegationRegistry");
  await authorizeEmitter(auditRegistry, delegationRegistry, "DelegationRegistry");

  printStep("Autorizzo AccessController");
  await authorizeEmitter(auditRegistry, accessController, "AccessController");

  printResult("Tutti i registri operativi possono produrre audit");

  printSection("10. LOCK DEL BOOTSTRAP");

  printStep("Blocco il bootstrap di OrganizationRegistry");
  await (await organizationRegistry.lockBootstrap()).wait();

  printStep("Blocco il bootstrap di PolicyRegistry");
  await (await policyRegistry.lockBootstrap()).wait();

  printStep("Blocco il bootstrap di TrustRegistry");
  await (await trustRegistry.lockBootstrap()).wait();

  printStep("Blocco il bootstrap di AuditRegistry");
  await (await auditRegistry.lockBootstrap()).wait();

  printResult("Da questo momento le modifiche critiche passano dalla governance o dagli owner/controller dei DID");

  async function approveGlobalPolicy(role, documentType, action, allowed, label) {
    printStep(`Creo policy globale off-chain su IPFS: ${label}`);

    const policyPayload = {
      type: "GlobalAccessPolicy",
      label,
      role: role.toString(),
      documentType,
      action,
      allowed,
      proposedBy: {
        organizationDID: "did:health:org:1",
        controller: organization1.address
      },
      storageModel: "full policy off-chain on IPFS; CID hash anchored on-chain through governance proposal",
      createdAt: new Date().toISOString()
    };

    const storedPolicy = await addJsonToIPFS(`Global Policy ${label}`, policyPayload, "global-policy");
    const policyCID = storedPolicy.cidHash;
    globalPolicyRecords.push({
      label,
      cid: storedPolicy.cid,
      cidHash: storedPolicy.cidHash,
      contentHash: storedPolicy.contentHash
    });

    const proposalId = await policyGovernance.nextProposalId();

    await (
      await policyGovernance
        .connect(organization1)
        .proposeGlobalAccessPolicy(
          role,
          documentType,
          action,
          allowed,
          policyCID
        )
    ).wait();

    console.log(`   Proposta creata con proposalId = ${proposalId.toString()}`);

    printStep("Organization 1 vota a favore");
    await (
      await policyGovernance
        .connect(organization1)
        .vote(proposalId, true)
    ).wait();

    printStep("Organization 2 vota a favore");
    await (
      await policyGovernance
        .connect(organization2)
        .vote(proposalId, true)
    ).wait();

    printStep("Finalizzo la proposta");
    await (
      await policyGovernance.finalize(proposalId)
    ).wait();

    printResult(`Policy approvata ed eseguita: ${label}`);
  }

  async function approveMaxDelegationDepth(newDepth, label) {
    printStep(`Creo policy di governance off-chain su IPFS: ${label}`);

    const policyPayload = {
      type: "GovernancePolicy",
      policyName: "MaxDelegationDepth",
      label,
      newDepth: newDepth.toString(),
      proposedBy: {
        organizationDID: "did:health:org:1",
        controller: organization1.address
      },
      storageModel: "full governance policy off-chain on IPFS; CID hash anchored on-chain through governance proposal",
      createdAt: new Date().toISOString()
    };

    const storedPolicy = await addJsonToIPFS(`Governance Policy ${label}`, policyPayload, "governance-policy");
    const policyCID = storedPolicy.cidHash;
    governancePolicyRecords.push({
      label,
      cid: storedPolicy.cid,
      cidHash: storedPolicy.cidHash,
      contentHash: storedPolicy.contentHash
    });

    const proposalId = await policyGovernance.nextProposalId();

    await (
      await policyGovernance
        .connect(organization1)
        .proposeSetMaxDelegationDepth(
          newDepth,
          policyCID
        )
    ).wait();

    console.log(`   Proposta creata con proposalId = ${proposalId.toString()}`);

    printStep("Organization 1 vota a favore della profondità massima");
    await (
      await policyGovernance
        .connect(organization1)
        .vote(proposalId, true)
    ).wait();

    printStep("Organization 2 vota a favore della profondità massima");
    await (
      await policyGovernance
        .connect(organization2)
        .vote(proposalId, true)
    ).wait();

    printStep("Finalizzo la proposta di profondità massima");
    await (
      await policyGovernance.finalize(proposalId)
    ).wait();

    const currentDepth = await policyRegistry.maxDelegationDepth();

    printResult(`${label}. Valore attuale nel PolicyRegistry = ${currentDepth.toString()}`);
  }

//---------FLUSSI OPERATIVI---------

//---------Definizione delle policy di governance---------  

printSection("11. GOVERNANCE DELLE POLICY GLOBALI");

  console.log("Le policy non vengono impostate da un admin.");
  console.log("Ogni policy viene proposta da una organizzazione e approvata con voto multi-authority.");
  console.log("Il ruolo usato dalla policy deriva ora dalla VC valida presentata dal DID richiedente.");

  await approveGlobalPolicy(
    ROLE.Doctor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_CREATE,
    true,
    "Doctor can CREATE REFERTO"
  );

  await approveGlobalPolicy(
    ROLE.Doctor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_READ,
    true,
    "Doctor can READ REFERTO"
  );

  await approveGlobalPolicy(
    ROLE.Doctor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_UPDATE,
    true,
    "Doctor can UPDATE REFERTO"
  );

  await approveGlobalPolicy(
    ROLE.Doctor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_REVOKE,
    true,
    "Doctor can REVOKE REFERTO"
  );

  await approveGlobalPolicy(
    ROLE.Doctor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_DELEGATE,
    true,
    "Doctor can DELEGATE REFERTO"
  );

  /*await approveGlobalPolicy(
    ROLE.Auditor,
    DOCUMENT_TYPE_REFERTO,
    ACTION_READ,
    true,
    "Auditor can READ REFERTO"
  );*/

  printStep("Verifico che le policy globali complete siano recuperabili da IPFS");
  const firstGlobalPolicy = globalPolicyRecords[0];
  const recoveredFirstGlobalPolicy = await getFileAsString(firstGlobalPolicy.cid);
  printCheck(
    "Prima policy globale recuperata da IPFS",
    recoveredFirstGlobalPolicy.length > 0
  );

  printCheck(
    "Doctor A può CREATE grazie a DID attivo + VC valida + policy globale",
    await policyRegistry.canPerformWithCredential(
      DID_DOCTOR,
      doctorPresentedCredential,
      DOCUMENT_TYPE_REFERTO,
      ACTION_CREATE
    )
  );

  printSection("12. GOVERNANCE DELLA PROFONDITÀ MASSIMA DELLE DELEGHE");

  console.log("La profondità massima delle deleghe è una policy di governance.");
  console.log("Non è decisa dal medico e non è decisa da un admin.");
  console.log("Le organizzazioni votano maxDelegationDepth = 2.");
  console.log("Questo consente: Doctor A -> Doctor B -> Doctor C.");
  console.log("Doctor C non potrà delegare ulteriormente.");

  await approveMaxDelegationDepth(
    2,
    "MaxDelegationDepth is 2"
  );

  //---------Gestione ciclo di vita documenti---------

  printSection("13. CREAZIONE E VERSIONING DEL DOCUMENTO CON IPFS + DID + VC");

  const documentId = hash("DOCUMENT-001");

  const documentTextV1 = "Referto clinico versione 1";

  printStep("Carico la versione 1 del documento su IPFS/Helia");
  const storedDocumentV1 = await addTextToIPFS("Documento sanitario DOCUMENT-001 versione 1", documentTextV1, "health-document");
  const documentCIDV1 = storedDocumentV1.cid;

  printStep("Doctor A crea un documento clinico associato al DID del paziente usando la sua VC");
  await (
    await documentLifecycleRegistry
      .connect(doctor)
      .createDocument(
        documentId,
        DID_PATIENT,
        DID_DOCTOR,
        doctorPresentedCredential,
        DOCUMENT_TYPE_REFERTO,
        documentCIDV1
      )
  ).wait();

  printResult("Documento creato. Il registro on-chain contiene il CID IPFS del payload off-chain");

  let currentDocument = await documentLifecycleRegistry.getCurrentDocument(documentId);

  console.log(`   Versione corrente: ${currentDocument.versionNumber.toString()}`);
  console.log(`   Stato corrente: ${currentDocument.state.toString()} (1 = Certified)`);
  console.log(`   Patient DID: ${currentDocument.patientDID}`);
  console.log(`   Creator DID: ${currentDocument.creatorDID}`);
  console.log(`   CID corrente letto dal registro: ${currentDocument.CID}`);

  printStep("Recupero da IPFS la versione 1 usando il CID salvato on-chain");
  const recoveredTextV1 = await getFileAsString(currentDocument.CID);

  printCheck(
    "Contenuto IPFS versione 1 uguale al documento originale",
    recoveredTextV1 === documentTextV1
  );

  const savedPathV1 = path.join(IPFS_OUTPUT_DIR, "documento_v1_recuperato.txt");

  await saveFileToDisk(currentDocument.CID, savedPathV1);

  console.log(`   Documento versione 1 salvato su disco in: ${savedPathV1}`);

  const documentTextV2 = "Referto clinico versione 2";

  printStep("Carico la versione 2 del documento su IPFS/Helia");
  const storedDocumentV2 = await addTextToIPFS("Documento sanitario DOCUMENT-001 versione 2", documentTextV2, "health-document");
  const documentCIDV2 = storedDocumentV2.cid;

  printStep("Doctor A crea una nuova versione del documento usando DID + VC");
  await (
    await documentLifecycleRegistry
      .connect(doctor)
      .createNewVersion(
        documentId,
        DID_DOCTOR,
        doctorPresentedCredential,
        documentCIDV2
      )
  ).wait();

  printResult("Nuova versione creata");

  const version1 = await documentLifecycleRegistry.getDocumentVersion(documentId, 1);
  const version2 = await documentLifecycleRegistry.getDocumentVersion(documentId, 2);

  console.log(`   Stato versione 1: ${version1.state.toString()} (2 = Archived)`);
  console.log(`   CID versione 1: ${version1.CID}`);
  console.log(`   Stato versione 2: ${version2.state.toString()} (1 = Certified)`);
  console.log(`   CID versione 2: ${version2.CID}`);

  printStep("Recupero da IPFS la versione 2 usando il CID salvato on-chain");
  const recoveredTextV2 = await getFileAsString(version2.CID);

  printCheck(
    "Contenuto IPFS versione 2 uguale al documento originale",
    recoveredTextV2 === documentTextV2
  );

  const savedPathV2 = path.join(IPFS_OUTPUT_DIR, "documento_v2_recuperato.txt");

  await saveFileToDisk(version2.CID, savedPathV2);

  console.log(`   Documento versione 2 salvato su disco in: ${savedPathV2}`);

  const verifyCIDV2 = await documentLifecycleRegistry.verifyCID(
    documentId,
    2,
    documentCIDV2
  );

  printCheck("Verifica CID IPFS della versione 2", verifyCIDV2);

  //---------Selective Disclosure Credenziali---------

  printSection("14A. PRESENTAZIONE SELETTIVA SD-JWT OFF-CHAIN");

  console.log("Prima di chiamare AccessController, il wallet del medico costruisce una presentazione selettiva.");
  console.log("Il verifier richiede solo role e department.");
  console.log("Il claim organization resta nascosto.");

  const doctorSdJwtRecord = issuedSdJwtCredentials.get(CRED_DOCTOR);

  if (!doctorSdJwtRecord) {
    throw new Error("La MedicalProfessionalVC del Doctor A non è stata emessa in formato SD-JWT");
  }

  const presentationRequirement = {
    aud: "did:health:verifier:access-controller",
    nonce: Crypto.randomBytes(16).toString("base64url"),
    requestedAt: Math.floor(Date.now() / 1000),
    holderDid: "did:health:doctor:alice",
    documentId,
    action: "READ",
    actionHash: ACTION_READ,
    purpose: "CONTINUITA_ASSISTENZIALE",
    purposeHash: PURPOSE_CARE,
    requiredClaimKeys: [
      "role",
      "department"
    ],
    hiddenClaimKeys: [
      "organization"
    ]
  };

  printStep("Il wallet crea una presentazione SD-JWT rivelando solo role e department");

  const sdJwtPresentation = await sdjwt.present(
    doctorSdJwtRecord.sdJwtCredential,
    {
      role: true,
      department: true,

      // Questo claim esiste nella credential, ma non viene rivelato.
      organization: false
    }
  );

  const presentationEnvelope = {
    format: "sd-jwt-vp-demo",
    aud: presentationRequirement.aud,
    nonce: presentationRequirement.nonce,
    requestedAt: presentationRequirement.requestedAt,
    holderDid: presentationRequirement.holderDid,
    documentId,
    action: presentationRequirement.action,
    actionHash: ACTION_READ,
    purpose: presentationRequirement.purpose,
    purposeHash: PURPOSE_CARE,
    sdJwtPresentationHash: hash(sdJwtPresentation)
  };

  const presentationEnvelopeDigest = hash(
    JSON.stringify(presentationEnvelope)
  );

  const holderSignature = await doctor.signMessage(
    ethers.getBytes(presentationEnvelopeDigest)
  );

  const recoveredHolderController = ethers.verifyMessage(
    ethers.getBytes(presentationEnvelopeDigest),
    holderSignature
  );

  printStep("Il verifier verifica firma issuer, disclosure e claim richiesti");

  const verifiedSdJwtPresentation = await sdjwt.verify(
    sdJwtPresentation,
    {
      requiredClaimKeys: presentationRequirement.requiredClaimKeys
    }
  );

  const disclosedPayload = verifiedSdJwtPresentation.payload as Record<string, any>;

  console.log("   Payload rivelato al verifier:");
  console.log({
    iss: disclosedPayload.iss,
    sub: disclosedPayload.sub,
    vct: disclosedPayload.vct,
    role: disclosedPayload.role,
    department: disclosedPayload.department,
    organization: disclosedPayload.organization ?? "<non rivelato>"
  });

  const issuerMatches =
    disclosedPayload.iss === "did:health:org:1";

  const subjectMatches =
    disclosedPayload.sub === "did:health:doctor:alice";

  const credentialTypeMatches =
    disclosedPayload.vct === "MedicalProfessionalVC";

  const requiredClaimsOk =
    disclosedPayload.role === "Doctor" &&
    disclosedPayload.department === "Cardiology";

  const organizationIsHidden =
    !Object.prototype.hasOwnProperty.call(disclosedPayload, "organization");

  const holderBindingOk =
    recoveredHolderController === doctor.address;

  const nonceFreshOk =
    presentationEnvelope.nonce === presentationRequirement.nonce &&
    Math.floor(Date.now() / 1000) - presentationRequirement.requestedAt <= 120;

  const issuerTrustedOnChain = await trustRegistry.isTrustedIssuer(
    DID_ORG1,
    VC_MEDICAL_PROFESSIONAL
  );

  const credentialValidOnChain =
    await credentialRegistry.isPresentedCredentialValidForSubject(
      doctorPresentedCredential,
      DID_DOCTOR
    );

  printCheck("Issuer SD-JWT corrisponde a Organization 1", issuerMatches);
  printCheck("Subject SD-JWT corrisponde al Doctor A", subjectMatches);
  printCheck("Tipo credenziale SD-JWT corretto", credentialTypeMatches);
  printCheck("Claim richiesti rivelati correttamente", requiredClaimsOk);
  printCheck("Claim organization non rivelato", organizationIsHidden);
  printCheck("Holder binding tramite firma del controller DID", holderBindingOk);
  printCheck("Nonce fresco contro replay attack", nonceFreshOk);
  printCheck("Issuer trusted verificato on-chain", issuerTrustedOnChain);
  printCheck("Credential valida verificata on-chain", credentialValidOnChain);

  const selectiveDisclosureAccepted =
    issuerMatches &&
    subjectMatches &&
    credentialTypeMatches &&
    requiredClaimsOk &&
    organizationIsHidden &&
    holderBindingOk &&
    nonceFreshOk &&
    issuerTrustedOnChain &&
    credentialValidOnChain;

  if (!selectiveDisclosureAccepted) {
    throw new Error(
      "Presentazione selettiva SD-JWT rifiutata: accesso on-chain non invocato"
    );
  }

  printResult("Presentazione selettiva SD-JWT accettata dal verifier off-chain");

  await addJsonToIPFS(
    "Selective disclosure presentation Doctor A READ DOCUMENT-001",
    {
      type: "SelectiveDisclosurePresentationEvidence",
      note: "Evidenza off-chain della verifica SD-JWT prima della chiamata ad AccessController.",
      presentationRequirement,
      presentationEnvelope,
      holderController: doctor.address,
      recoveredHolderController,
      holderSignature,
      verifierResult: "ACCEPTED",
      disclosedClaims: {
        role: disclosedPayload.role,
        department: disclosedPayload.department
      },
      hiddenClaims: [
        "organization"
      ],
      onChainChecks: {
        issuerTrustedOnChain,
        credentialValidOnChain
      },
      nextStep: "AccessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE)"
    },
    "selective-disclosure-presentation"
  );

//---------Valutazione degli accessi---------

  printSection("14. ACCESSO CONSENTITO DA POLICY GLOBALE + VC");

  printStep("Doctor A richiede accesso READ al documento presentando la VC MedicalProfessionalVC");
  const doctorCanRead = await accessController.canAccess(
    DID_DOCTOR,
    doctorPresentedCredential,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor A può leggere grazie a DID + VC + policy globale", doctorCanRead);

  printStep("Registro la richiesta di accesso del Doctor A nell'audit");
  await (
    await accessController
      .connect(doctor)
      .requestAccess(
        DID_DOCTOR,
        doctorPresentedCredential,
        documentId,
        ACTION_READ,
        PURPOSE_CARE
      )
  ).wait();
  printResult("Accesso del Doctor A auditato");

  printStep("Auditor prova a leggere un referto.");
  const auditorCanReadReferto = await accessController.canAccess(
    DID_AUDITOR,
    auditorPresentedCredential,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Auditor può leggere un referto ", auditorCanReadReferto);

  printStep("Registro nell'audit il tentativo negato dell'Auditor");
  await (
    await accessController
      .connect(auditor)
      .requestAccess(
        DID_AUDITOR,
        auditorPresentedCredential,
        documentId,
        ACTION_READ,
        PURPOSE_CARE
      )
  ).wait();

  printResult("Tentativo negato dell'Auditor auditato");

  printSection("14B. CREAZIONE POLICY PATIENT-DRIVEN POSITIVA PER DOCTOR D"); 

  const latestBlockForDoctorDAllowance = await ethers.provider.getBlock("latest");
  const validFromDoctorDAllowance = BigInt(latestBlockForDoctorDAllowance.timestamp);
  const validUntilDoctorDAllowance = validFromDoctorDAllowance + 7n * 24n * 60n * 60n;

  const doctorDAllowancePayload = {
    type: "PatientDrivenAllowance",
    label: "Patient allowance: Doctor D can read DOCUMENT-001",
    meaning:
      "Il paziente autorizza esplicitamente Doctor D a leggere questo documento.",
    documentId,
    patientDID: DID_PATIENT,
    allowedUserDID: DID_DOCTOR_D,
    allowedAction: ACTION_READ,
    purpose: PURPOSE_CARE,
    validFrom: validFromDoctorDAllowance.toString(),
    validUntil: validUntilDoctorDAllowance.toString(),
    createdAt: new Date().toISOString()
  };

  const storedDoctorDAllowancePolicy = await addJsonToIPFS(
    "Patient-driven allowance Doctor D READ DOCUMENT-001",
    doctorDAllowancePayload,
    "patient-driven-policy"
  );

  const doctorDAllowancePolicyCID = storedDoctorDAllowancePolicy.cidHash;

  patientPolicyRecords.push({
    label: doctorDAllowancePayload.label,
    cid: storedDoctorDAllowancePolicy.cid,
    cidHash: storedDoctorDAllowancePolicy.cidHash,
    contentHash: storedDoctorDAllowancePolicy.contentHash
  });
    
  await (
    await patientDrivenPolicyRegistry
      .connect(patient)
      .registerRestriction(
        documentId,
        DID_PATIENT,
        ethers.ZeroHash,
        ethers.ZeroHash,
        DID_DOCTOR_D,
        ACTION_READ,
        PURPOSE_CARE,
        validFromDoctorDAllowance,
        validUntilDoctorDAllowance,
        doctorDAllowancePolicyCID
      )
  ).wait();

  printResult("Policy patient-driven positiva registrata per Doctor D");

  const doctorDIsAllowedByPatient =
    await patientDrivenPolicyRegistry.isAllowed(
      DID_DOCTOR_D,
      documentId,
      ACTION_READ,
      PURPOSE_CARE
    );

  printCheck(
    "Doctor D è autorizzato dal paziente tramite policy patient-driven positiva",
    doctorDIsAllowedByPatient
  );

    printStep("Doctor D richiede accesso READ al documento dopo allow patient-driven positiva");

    const doctorDCanReadAfterPatientAllowance =
      await accessController.canAccess(
        DID_DOCTOR_D,
        doctorDPresentedCredential,
        documentId,
        ACTION_READ,
        PURPOSE_CARE
      );

    printCheck(
      "Doctor D può leggere tramite AccessController dopo allow patient-driven positiva",
      doctorDCanReadAfterPatientAllowance
    );

    printStep("Registro nell'audit l'accesso di Doctor D");

    await (
      await accessController
        .connect(doctorD)
        .requestAccess(
          DID_DOCTOR_D,
          doctorDPresentedCredential,
          documentId,
          ACTION_READ,
          PURPOSE_CARE
        )
    ).wait();

    printResult("Accesso di Doctor D auditato");

  //---------Gestione delle deleghe---------

  printSection("15. DELEGA DIRETTA: DOCTOR A -> DOCTOR B");

  printStep("Doctor B prova a leggere prima di ricevere una delega e senza VC professionale");
  const doctorBCanReadBeforeDelegation = await accessController.canAccess(
    DID_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor B può leggere prima della delega", doctorBCanReadBeforeDelegation);

  const latestBlockForDelegation = await ethers.provider.getBlock("latest");
  const validFromDelegation = BigInt(latestBlockForDelegation.timestamp);
  const validUntilDelegation = validFromDelegation + 24n * 60n * 60n;

  printStep("Doctor A crea una proposta di delega diretta verso Doctor B usando DID + VC");
  const directProposalId = await delegationRegistry.nextProposalId();

  await (
    await delegationRegistry
      .connect(doctor)
      .proposeDelegation(
        DID_DOCTOR,
        DID_DELEGATED_DOCTOR,
        doctorPresentedCredential,
        documentId,
        ACTION_READ,
        PURPOSE_CARE,
        validFromDelegation,
        validUntilDelegation
      )
  ).wait();

  console.log(`   Proposta di delega diretta creata con proposalId = ${directProposalId.toString()}`);

  printStep("Il paziente approva la proposta di delega diretta tramite controller del proprio DID");
  const directDelegationId = await delegationRegistry.nextDelegationId();

  await (
    await delegationRegistry
      .connect(patient)
      .approveDelegationProposal(directProposalId)
  ).wait();

  console.log(`   Delega diretta attiva con delegationId = ${directDelegationId.toString()}`);

  const directDelegation = await delegationRegistry.getDelegation(directDelegationId);
  console.log(`   Depth della delega diretta: ${directDelegation.depth.toString()}`);

  printStep("Doctor B prova a leggere dopo approvazione della delega");
  const doctorBCanReadAfterDelegation = await accessController.canAccess(
    DID_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor B può leggere dopo delega diretta", doctorBCanReadAfterDelegation);

  printStep("Registro accesso delegato di Doctor B nell'audit");
  await (
    await accessController
      .connect(delegatedDoctor)
      .requestAccess(
        DID_DELEGATED_DOCTOR,
        EMPTY_PRESENTED_CREDENTIAL,
        documentId,
        ACTION_READ,
        PURPOSE_CARE
      )
  ).wait();

  printResult("Accesso di Doctor B auditato");

  printSection("16. DELEGA DERIVATA: DOCTOR B -> DOCTOR C");

  console.log("Poiché maxDelegationDepth = 2, Doctor B può creare una sotto-delega verso Doctor C.");
  console.log("Doctor C potrà leggere, ma non potrà delegare ulteriormente.");

  printStep("Doctor C prova a leggere prima della delega derivata");
  const doctorCCanReadBeforeDerivedDelegation = await accessController.canAccess(
    DID_SECOND_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor C può leggere prima della delega derivata", doctorCCanReadBeforeDerivedDelegation);

  const latestBlockForDerivedDelegation = await ethers.provider.getBlock("latest");
  const validFromDerivedDelegation = BigInt(latestBlockForDerivedDelegation.timestamp);
  const validUntilDerivedDelegation = validFromDerivedDelegation + 12n * 60n * 60n;

  printStep("Doctor B crea una proposta di delega derivata verso Doctor C");
  const derivedProposalId = await delegationRegistry.nextProposalId();

  await (
    await delegationRegistry
      .connect(delegatedDoctor)
      .proposeDerivedDelegation(
        directDelegationId,
        DID_SECOND_DELEGATED_DOCTOR,
        validFromDerivedDelegation,
        validUntilDerivedDelegation
      )
  ).wait();

  console.log(`   Proposta di delega derivata creata con proposalId = ${derivedProposalId.toString()}`);

  printStep("Il paziente approva la proposta di delega derivata");
  const derivedDelegationId = await delegationRegistry.nextDelegationId();

  await (
    await delegationRegistry
      .connect(patient)
      .approveDelegationProposal(derivedProposalId)
  ).wait();

  console.log(`   Delega derivata attiva con delegationId = ${derivedDelegationId.toString()}`);

  const derivedDelegation = await delegationRegistry.getDelegation(derivedDelegationId);
  console.log(`   ParentDelegationId della delega derivata: ${derivedDelegation.parentDelegationId.toString()}`);
  console.log(`   Depth della delega derivata: ${derivedDelegation.depth.toString()}`);

  printStep("Doctor C prova a leggere dopo approvazione della delega derivata");
  const doctorCCanReadAfterDerivedDelegation = await accessController.canAccess(
    DID_SECOND_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor C può leggere dopo delega derivata", doctorCCanReadAfterDerivedDelegation);

  printStep("Registro accesso delegato di Doctor C nell'audit");
  await (
    await accessController
      .connect(secondDelegatedDoctor)
      .requestAccess(
        DID_SECOND_DELEGATED_DOCTOR,
        EMPTY_PRESENTED_CREDENTIAL,
        documentId,
        ACTION_READ,
        PURPOSE_CARE
      )
  ).wait();

  printResult("Accesso di Doctor C auditato");

  printSection("17. TENTATIVO DI SUPERARE LA PROFONDITÀ MASSIMA");

  console.log("Ora Doctor C prova a creare una terza delega verso un altro utente.");
  console.log("Poiché maxDelegationDepth = 2, questa operazione deve fallire.");

  try {
    const latestBlockForInvalidDelegation = await ethers.provider.getBlock("latest");
    const validFromInvalidDelegation = BigInt(latestBlockForInvalidDelegation.timestamp);
    const validUntilInvalidDelegation = validFromInvalidDelegation + 6n * 60n * 60n;

    await (
      await delegationRegistry
        .connect(secondDelegatedDoctor)
        .proposeDerivedDelegation(
          derivedDelegationId,
          DID_UNAUTHORIZED,
          validFromInvalidDelegation,
          validUntilInvalidDelegation
        )
    ).wait();

    console.log("   X ERRORE: la terza delega è stata creata, ma non doveva essere consentita.");
  } catch (error) {
    console.log("   V La terza delega è stata correttamente bloccata");
    console.log("   Motivo atteso: Max delegation depth exceeded");
  }

  printSection("18. REVOCA DELLA DELEGA PADRE E INVALIDAZIONE DELLA CATENA");

  console.log("Ora il paziente revoca la delega diretta Doctor A -> Doctor B.");
  console.log("La delega derivata Doctor B -> Doctor C non viene cancellata,");
  console.log("ma deve diventare inutilizzabile perché la catena padre non è più valida.");

  printStep("Il paziente revoca la delega diretta usando il proprio DID");
  await (
    await delegationRegistry
      .connect(patient)
      .revokeDelegation(directDelegationId, DID_PATIENT)
  ).wait();

  printResult("Delega diretta revocata");

  printStep("Doctor B prova a leggere dopo revoca della delega diretta");
  const doctorBCanReadAfterParentRevocation = await accessController.canAccess(
    DID_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor B può leggere dopo revoca della delega diretta", doctorBCanReadAfterParentRevocation);

  printStep("Doctor C prova a leggere dopo revoca della delega padre");
  const doctorCCanReadAfterParentRevocation = await accessController.canAccess(
    DID_SECOND_DELEGATED_DOCTOR,
    EMPTY_PRESENTED_CREDENTIAL,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor C può leggere dopo revoca della delega padre", doctorCCanReadAfterParentRevocation);

  //---------Revoca accesso documento---------

  printSection("19. REVOCA DEL CONSENSO / ACCESSO PATIENT-DRIVEN");

  console.log("Il paziente non revoca il referto clinico.");
  console.log("Il referto resta Certified nel DocumentLifecycleRegistry.");
  console.log("Il paziente revoca invece il consenso/accesso di Doctor A tramite una restrizione patient-driven.");

  const latestBlockForDoctorAccessRevocation = await ethers.provider.getBlock("latest");
  const validFromDoctorAccessRevocation = BigInt(latestBlockForDoctorAccessRevocation.timestamp);
  const validUntilDoctorAccessRevocation =
    validFromDoctorAccessRevocation + 7n * 24n * 60n * 60n;

  printStep("Creo off-chain la policy patient-driven che revoca l'accesso di Doctor A");

  const patientDoctorAccessRevocationPayload = {
    type: "PatientDrivenRestriction",
    label: "Patient restriction: Doctor A cannot read DOCUMENT-001 anymore",
    meaning: "Il paziente revoca il consenso/accesso di Doctor A al referto. Il documento resta Certified.",
    documentId,
    documentType: "REFERTO",
    patient: {
      did: "did:health:patient:bob",
      didHash: DID_PATIENT,
      controller: patient.address
    },
    restrictedUser: {
      did: "did:health:doctor:alice",
      didHash: DID_DOCTOR,
      controller: doctor.address
    },
    action: "READ",
    actionHash: ACTION_READ,
    purpose: "CONTINUITA_ASSISTENZIALE",
    purposeHash: PURPOSE_CARE,
    validFrom: validFromDoctorAccessRevocation.toString(),
    validUntil: validUntilDoctorAccessRevocation.toString(),
    storageModel: "full patient-driven restriction off-chain on IPFS; CID hash anchored on-chain in PatientDrivenPolicyRegistry",
    createdAt: new Date().toISOString()
  };

  const storedDoctorAccessRevocationPolicy = await addJsonToIPFS(
    "Patient-driven Policy restriction Doctor A READ DOCUMENT-001",
    patientDoctorAccessRevocationPayload,
    "patient-driven-policy"
  );

  const doctorAccessRevocationPolicyCID = storedDoctorAccessRevocationPolicy.cidHash;

  patientPolicyRecords.push({
    label: patientDoctorAccessRevocationPayload.label,
    cid: storedDoctorAccessRevocationPolicy.cid,
    cidHash: storedDoctorAccessRevocationPolicy.cidHash,
    contentHash: storedDoctorAccessRevocationPolicy.contentHash
  });

  printStep("Il paziente registra la restrizione patient-driven usando il proprio DID");

  await (
    await patientDrivenPolicyRegistry
      .connect(patient)
      .registerRestriction(
        documentId,
        DID_PATIENT,
        DID_DOCTOR,
        ACTION_READ,
        ethers.ZeroHash,
        ethers.ZeroHash,
        PURPOSE_CARE,
        validFromDoctorAccessRevocation,
        validUntilDoctorAccessRevocation,
        doctorAccessRevocationPolicyCID
      )
  ).wait();

  printResult("Accesso di Doctor A revocato tramite restrizione patient-driven");

  printStep("Verifico che il referto NON sia stato revocato nel lifecycle");

  const currentDocumentAfterAccessRevocation =
    await documentLifecycleRegistry.getCurrentDocument(documentId);

  const documentStillActiveAfterAccessRevocation =
    await documentLifecycleRegistry.isDocumentActive(documentId);

  printCheck(
    "Il referto resta attivo/certified nel DocumentLifecycleRegistry",
    documentStillActiveAfterAccessRevocation
  );

  console.log(
    `   Stato corrente documento: ${currentDocumentAfterAccessRevocation.state.toString()} (1 = Certified, 3 = Revoked)`
  );

  printStep("Verifico che la restrizione patient-driven blocchi Doctor A");

  const doctorAIsRestrictedByPatient =
    await patientDrivenPolicyRegistry.isRestricted(
      DID_DOCTOR,
      documentId,
      ACTION_READ,
      PURPOSE_CARE
    );

  printCheck(
    "Doctor A è ristretto dal paziente per READ su questo referto",
    doctorAIsRestrictedByPatient
  );

  printStep("Doctor A prova a leggere dopo la revoca del consenso/accesso");

  const doctorCanReadAfterPatientAccessRevocation =
    await accessController.canAccess(
      DID_DOCTOR,
      doctorPresentedCredential,
      documentId,
      ACTION_READ,
      PURPOSE_CARE
    );

  printCheck(
    "Doctor A può leggere dopo revoca del consenso/accesso patient-driven",
    doctorCanReadAfterPatientAccessRevocation
  );

  printSection("20. REVOCA DEL DOCUMENTO DA PARTE DEL MEDICO");

  console.log("Doctor A revoca il referto clinico usando DID attivo, VC valida e policy globale REVOKE.");
  console.log("Questa è una revoca del documento nel lifecycle, diversa dalla revoca del consenso/accesso patient-driven.");

  printStep("Doctor A revoca il documento clinico");

  await (
    await documentLifecycleRegistry
      .connect(doctor)
      .revokeDocument(
        documentId,
        DID_DOCTOR,
        doctorPresentedCredential
      )
  ).wait();

  printResult("Documento revocato dal medico");

  const currentDocumentAfterDocumentRevocation =
    await documentLifecycleRegistry.getCurrentDocument(documentId);

  const documentActiveAfterDocumentRevocation =
    await documentLifecycleRegistry.isDocumentActive(documentId);

  console.log(
    `   Stato documento dopo revoca: ${currentDocumentAfterDocumentRevocation.state.toString()} (3 = Revoked)`
  );

  printCheck(
    "Il documento non è più attivo dopo la revoca del medico",
    !documentActiveAfterDocumentRevocation
  );

  printSection("21. REVOCA VC DEL MEDICO");

  console.log("L'organizzazione issuer revoca la MedicalProfessionalVC del Doctor A.");
  console.log("Dopo la revoca, Doctor A non deve più passare la policy globale tramite VC.");

  printStep("Organization 1 revoca la VC del medico");
  await (
    await credentialRegistry
      .connect(organization1)
      .revokeCredential(CRED_DOCTOR)
  ).wait();

  printCheck("VC medico revocata", !(await credentialRegistry.isCredentialValid(CRED_DOCTOR)));

  const doctorCanReadAfterVCRevocation = await accessController.canAccess(
    DID_DOCTOR,
    doctorPresentedCredential,
    documentId,
    ACTION_READ,
    PURPOSE_CARE
  );

  printCheck("Doctor A può leggere dopo revoca della VC", doctorCanReadAfterVCRevocation);

//---------Audit degli eventi---------

  printSection("22. AUDIT BATCH OFF-CHAIN");

  const latestBlockForAuditBatch = await ethers.provider.getBlock("latest");
  const auditBatchPayload = {
    type: "AuditBatch",
    batchId: "audit-batch-demo-001",
    createdAt: new Date().toISOString(),
    blockNumber: latestBlockForAuditBatch.number,
    blockTimestamp: latestBlockForAuditBatch.timestamp.toString(),
    note: "Demo batch off-chain. Gli eventi ufficiali sono comunque emessi anche da AuditRegistry come Solidity events.",
    actors: {
      organization1: { did: "did:health:org:1", controller: organization1.address },
      doctorA: { did: "did:health:doctor:alice", controller: doctor.address },
      patient: { did: "did:health:patient:bob", controller: patient.address },
      auditor: { did: "did:health:auditor:ana", controller: auditor.address }
    },
    targets: {
      documentId,
      documentType: "REFERTO",
      documentV1CID: documentCIDV1,
      documentV2CID: documentCIDV2
    },
    operations: [
      "DID registration",
      "VC issuance",
      "global policy approval",
      "max delegation depth approval",
      "document creation",
      "document versioning",
      "access request",
      "patient-driven restriction",
      "delegation creation",
      "derived delegation creation",
      "delegation revocation",
      "patient-driven access revocation",
      "VC revocation"
    ],
    offchainReferences: offchainAssets.map((asset) => ({
      category: asset.category,
      label: asset.label,
      cid: asset.cid,
      cidHash: asset.cidHash,
      contentHash: asset.contentHash
    }))
  };

  const storedAuditBatch = await addJsonToIPFS(
    "Audit batch demo 001",
    auditBatchPayload,
    "audit-batch"
  );

  auditBatchRecords.push({
    label: auditBatchPayload.batchId,
    cid: storedAuditBatch.cid,
    cidHash: storedAuditBatch.cidHash,
    contentHash: storedAuditBatch.contentHash
  });

  printSection("23. DEPLOYMENT SUMMARY");

  const summary = {
    accounts: {
      deployer: deployer.address,
      organization1: organization1.address,
      organization2: organization2.address,
      organization3: organization3.address,
      doctorA: doctor.address,
      patient: patient.address,
      doctorB_delegated: delegatedDoctor.address,
      doctorC_secondLevel: secondDelegatedDoctor.address,
      auditor: auditor.address,
      unauthorizedUser_possibleDoctorD: unauthorizedUser.address
    },
    dids: {
      organization1: DID_ORG1,
      organization2: DID_ORG2,
      organization3: DID_ORG3,
      doctorA: DID_DOCTOR,
      patient: DID_PATIENT,
      doctorB_delegated: DID_DELEGATED_DOCTOR,
      doctorC_secondLevel: DID_SECOND_DELEGATED_DOCTOR,
      auditor: DID_AUDITOR,
      unauthorizedUser_possibleDoctorD: DID_UNAUTHORIZED
    },
    contracts: {
      AuditRegistry: await auditRegistry.getAddress(),
      OrganizationRegistry: await organizationRegistry.getAddress(),
      IdentityRegistry: await identityRegistry.getAddress(),
      TrustRegistry: await trustRegistry.getAddress(),
      CredentialStatusRegistry: await credentialRegistry.getAddress(),
      PolicyRegistry: await policyRegistry.getAddress(),
      PolicyGovernance: await policyGovernance.getAddress(),
      DocumentLifecycleRegistry: await documentLifecycleRegistry.getAddress(),
      PatientDrivenPolicyRegistry: await patientDrivenPolicyRegistry.getAddress(),
      DelegationRegistry: await delegationRegistry.getAddress(),
      AccessController: await accessController.getAddress()
    },
    ipfs: {
      didDocuments: Object.fromEntries(
        Object.entries(didRecords).map(([key, value]) => [key, value.didDocumentCID])
      ),
      credentials: Object.fromEntries(
        Object.entries(vcRecords).map(([key, value]) => [key, value.credentialCID])
      ),
      documents: {
        documentV1: documentCIDV1,
        documentV2: documentCIDV2
      },
      globalPolicies: globalPolicyRecords,
      governancePolicies: governancePolicyRecords,
      patientDrivenPolicies: patientPolicyRecords,
      auditBatches: auditBatchRecords,
      allOffchainAssets: offchainAssets.map((asset) => ({
        category: asset.category,
        label: asset.label,
        cid: asset.cid,
        cidHash: asset.cidHash,
        contentHash: asset.contentHash
      })),
      recoveredFiles: {
        documentV1: savedPathV1,
        documentV2: savedPathV2
      }
    },
    demoResults: {
      maxDelegationDepth: (await policyRegistry.maxDelegationDepth()).toString(),
      didDoctorActive: await identityRegistry.isActiveDID(DID_DOCTOR),
      vcDoctorValidAfterRevocation: await credentialRegistry.isCredentialValid(CRED_DOCTOR),
      documentHashVerified: verifyCIDV2,
      doctorAReadByPolicyBeforeVCRevocation: doctorCanRead,
      auditorReadAfterRestriction: auditorCanReadReferto,
      doctorBReadBeforeDelegation: doctorBCanReadBeforeDelegation,
      doctorBReadAfterDelegation: doctorBCanReadAfterDelegation,
      doctorCReadBeforeDerivedDelegation: doctorCCanReadBeforeDerivedDelegation,
      doctorCReadAfterDerivedDelegation: doctorCCanReadAfterDerivedDelegation,
      doctorBReadAfterParentRevocation: doctorBCanReadAfterParentRevocation,
      doctorCReadAfterParentRevocation: doctorCCanReadAfterParentRevocation,
      doctorAReadAfterVCRevocation: doctorCanReadAfterVCRevocation,
      doctorAReadAfterPatientAccessRevocation: doctorCanReadAfterPatientAccessRevocation
    }
  };

  console.log(summary);

  const storedDeploymentSummary = await addJsonToIPFS(
    "Deployment summary completo",
    summary,
    "deployment-summary"
  );
  printResult(`Deployment summary salvato su IPFS: ${storedDeploymentSummary.cid}`);

  printSection("24. ESPORTAZIONE LOCALE DEGLI ASSET OFF-CHAIN");

  printStep("Recupero da IPFS tutti gli asset off-chain e li salvo in ipfs-output");

  for (const asset of offchainAssets) {
    const extension = asset.contentType === "application/json" ? ".json" : ".txt";
    const fileName =
      `${safeFileName(asset.category)}__` +
      `${safeFileName(asset.label)}__` +
      `${asset.cid.slice(0, 16)}${extension}`;

    const outputPath = path.join(IPFS_OUTPUT_DIR, fileName);
    await saveFileToDisk(asset.cid, outputPath);
  }

  const offchainAssetsIndexPath = path.join(IPFS_OUTPUT_DIR, "offchain-assets-index.json");
  await writeFile(
    offchainAssetsIndexPath,
    JSON.stringify(summary.ipfs.allOffchainAssets, null, 2),
    "utf8"
  );

  const deploymentSummaryPath = path.join(IPFS_OUTPUT_DIR, "deployment-summary.json");
  await saveFileToDisk(storedDeploymentSummary.cid, deploymentSummaryPath);

  printSection("DEMO COMPLETATA");

  console.log("La demo ha mostrato:");
  console.log(" 1. governance multi-authority per policy globali;");
  console.log(" 2. DID registrati con DID Document off-chain su IPFS;");
  console.log(" 3. VC complete off-chain; on-chain solo stato minimo, validità e revoca;");
  console.log(" 4. policy globali e policy di governance complete off-chain su IPFS;");
  console.log(" 5. policy patient-driven completa off-chain su IPFS;");
  console.log(" 6. audit batch demo off-chain su IPFS;");
  console.log(" 7. ruolo applicativo derivato da VC valida e trusted issuer;");
  console.log(" 8. maxDelegationDepth votata dalle organizzazioni;");
  console.log(" 9. lifecycle documentale con versioning IPFS;");
  console.log(" 10. verifica hash/CID del documento;");
  console.log(" 11. accesso tramite policy globale + VC;");
  console.log(" 12. restrizione patient-driven su DID;");
  console.log(" 13. delega diretta approvata dal paziente;");
  console.log(" 14. delega derivata entro la profondità massima;");
  console.log(" 15. blocco della delega oltre profondità massima;");
  console.log(" 16. invalidazione della catena dopo revoca della delega padre;");
  console.log(" 17. revoca del consenso/accesso patient-driven senza revocare il referto;");
  console.log(" 18. revoca VC e blocco degli accessi basati su VC.");
}

main()
  .then(async () => {
    await stopNode();
  })
  .catch(async (error) => {
    console.error(error);
    await stopNode();
    process.exitCode = 1;
  });
