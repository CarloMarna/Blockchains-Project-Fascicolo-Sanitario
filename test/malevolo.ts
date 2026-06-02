import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";

/**
 * Test malevoli/minacce per la versione con PresentedCredential.
 * Questo file contiene un setup ridotto uguale a quello funzionale, ma i casi
 * si concentrano su abuso di firma, subject binding, controller DID e revoche.
 */
describe("VC selective disclosure - test malevoli", async function () {
  async function setupSystem(options: { lockTrustBootstrap?: boolean } = {}) {
    const { lockTrustBootstrap = true } = options;
    const { ethers } = await network.connect();

    const [
      deployer,
      organization1,
      organization2,
      organization3,
      doctorA,
      patient,
      doctorB,
      doctorC,
      auditor,
      attacker,
    ] = await ethers.getSigners();

    function hash(value: string): string {
      return ethers.keccak256(ethers.toUtf8Bytes(value));
    }

    async function deployContract(name: string, args: any[] = []) {
      const Factory = await ethers.getContractFactory(name);
      const contract = await Factory.deploy(...args);
      await contract.waitForDeployment();
      return contract;
    }

    async function tx(promise: Promise<any>) {
      const response = await promise;
      await response.wait();
      return response;
    }

    function emptyPresentedCredential() {
      return {
        format: "",
        id: "",
        issuer: "",
        subject: "",
        credentialType: "",
        sdJwtCredential: "",
        selectivelyDisclosableClaims: [],
      };
    }

    async function buildPresentedCredential({
      id,
      issuer,
      subject,
      credentialType,
      claims,
      label,
    }: {
      id: string;
      issuer: string;
      subject: string;
      credentialType: string;
      claims: Record<string, string>;
      label: string;
    }) {
      const sdJwtPayload = {
        iss: issuer,
        sub: subject,
        vct: credentialType,
        jti: id,
        ...claims,
      };

      return {
        format: "vc+sd-jwt",
        id,
        issuer,
        subject,
        credentialType,
        sdJwtCredential: `mock-sd-jwt:${label}:${hash(JSON.stringify(sdJwtPayload))}`,
        selectivelyDisclosableClaims: Object.keys(claims),
      };
    }

    const ROLE = {
      Patient: 1,
      Doctor: 2,
      Nurse: 3,
      Auditor: 4,
      ExternalRequester: 5,
      Technician: 6,
    } as const;

    const ACTION_READ = hash("READ");
    const ACTION_CREATE = hash("CREATE");
    const ACTION_UPDATE = hash("UPDATE");
    const ACTION_REVOKE = hash("REVOKE");
    const ACTION_DELEGATE = hash("DELEGATE");

    const DOCUMENT_TYPE_REFERTO = hash("REFERTO");
    const PURPOSE_CARE = hash("CONTINUITA_ASSISTENZIALE");

    const VC_MEDICAL_PROFESSIONAL_STRING = "MedicalProfessionalVC";
    const VC_AUDITOR_PROFESSIONAL_STRING = "AuditorProfessionalVC";

    const VC_MEDICAL_PROFESSIONAL = hash(VC_MEDICAL_PROFESSIONAL_STRING);
    const VC_AUDITOR_PROFESSIONAL = hash(VC_AUDITOR_PROFESSIONAL_STRING);

    const DID_ORG1_STRING = "did:health:org:1";
    const DID_ORG2_STRING = "did:health:org:2";
    const DID_ORG3_STRING = "did:health:org:3";
    const DID_DOCTOR_STRING = "did:health:doctor:alice";
    const DID_PATIENT_STRING = "did:health:patient:bob";
    const DID_DOCTOR_B_STRING = "did:health:doctor:charlie";
    const DID_DOCTOR_C_STRING = "did:health:doctor:diana";
    const DID_AUDITOR_STRING = "did:health:auditor:ana";
    const DID_ATTACKER_STRING = "did:health:unknown:eve";

    const DID_ORG1 = hash(DID_ORG1_STRING);
    const DID_ORG2 = hash(DID_ORG2_STRING);
    const DID_ORG3 = hash(DID_ORG3_STRING);
    const DID_DOCTOR = hash(DID_DOCTOR_STRING);
    const DID_PATIENT = hash(DID_PATIENT_STRING);
    const DID_DOCTOR_B = hash(DID_DOCTOR_B_STRING);
    const DID_DOCTOR_C = hash(DID_DOCTOR_C_STRING);
    const DID_AUDITOR = hash(DID_AUDITOR_STRING);
    const DID_ATTACKER = hash(DID_ATTACKER_STRING);

    const CRED_DOCTOR_STRING = "vc:doctor:alice:medical-professional:v1";
    const CRED_AUDITOR_STRING = "vc:auditor:ana:auditor-professional:v1";

    const CRED_DOCTOR = hash(CRED_DOCTOR_STRING);
    const CRED_AUDITOR = hash(CRED_AUDITOR_STRING);

    const auditRegistry = await deployContract("AuditRegistry");
    const organizationRegistry = await deployContract("OrganizationRegistry", [await auditRegistry.getAddress()]);
    const identityRegistry = await deployContract("IdentityRegistry", [await auditRegistry.getAddress()]);

    await tx(auditRegistry.setAuthorizedEmitter(await organizationRegistry.getAddress(), true));
    await tx(auditRegistry.setAuthorizedEmitter(await identityRegistry.getAddress(), true));

    await tx(organizationRegistry.addOrganization(organization1.address, hash("Organization 1 metadata")));
    await tx(organizationRegistry.addOrganization(organization2.address, hash("Organization 2 metadata")));
    await tx(organizationRegistry.addOrganization(organization3.address, hash("Organization 3 metadata")));

    async function registerDID(signer: any, did: string, label: string) {
      await tx(identityRegistry.connect(signer).registerDID(did, hash(`CID:DID:${label}`), hash(`DID-DOCUMENT:${label}`)));
    }

    await registerDID(organization1, DID_ORG1, "org1");
    await registerDID(organization2, DID_ORG2, "org2");
    await registerDID(organization3, DID_ORG3, "org3");
    await registerDID(doctorA, DID_DOCTOR, "doctorA");
    await registerDID(patient, DID_PATIENT, "patient");
    await registerDID(doctorB, DID_DOCTOR_B, "doctorB");
    await registerDID(doctorC, DID_DOCTOR_C, "doctorC");
    await registerDID(auditor, DID_AUDITOR, "auditor");
    await registerDID(attacker, DID_ATTACKER, "attacker");

    const trustRegistry = await deployContract("TrustRegistry", [
      await identityRegistry.getAddress(),
      await organizationRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await tx(auditRegistry.setAuthorizedEmitter(await trustRegistry.getAddress(), true));
    await tx(trustRegistry.authorizeIssuer(DID_ORG1, VC_MEDICAL_PROFESSIONAL));
    await tx(trustRegistry.authorizeIssuer(DID_ORG1, VC_AUDITOR_PROFESSIONAL));

    const credentialRegistry = await deployContract("CredentialStatusRegistry", [
      await identityRegistry.getAddress(),
      await trustRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await tx(auditRegistry.setAuthorizedEmitter(await credentialRegistry.getAddress(), true));

    const nowBlock = await ethers.provider.getBlock("latest");
    const validFrom = BigInt(nowBlock!.timestamp);
    const validUntil = validFrom + 365n * 24n * 60n * 60n;

    await tx(credentialRegistry.connect(organization1).issueCredential(CRED_DOCTOR, DID_ORG1, VC_MEDICAL_PROFESSIONAL, validFrom, validUntil));
    await tx(credentialRegistry.connect(organization1).issueCredential(CRED_AUDITOR, DID_ORG1, VC_AUDITOR_PROFESSIONAL, validFrom, validUntil));

    const doctorPresentedCredential = await buildPresentedCredential({
      id: CRED_DOCTOR_STRING,
      issuer: DID_ORG1_STRING,
      subject: DID_DOCTOR_STRING,
      credentialType: VC_MEDICAL_PROFESSIONAL_STRING,
      claims: { role: "Doctor", organization: "Organization 1", department: "Cardiology" },
      label: "doctorA-medical-v1",
    });

    const auditorPresentedCredential = await buildPresentedCredential({
      id: CRED_AUDITOR_STRING,
      issuer: DID_ORG1_STRING,
      subject: DID_AUDITOR_STRING,
      credentialType: VC_AUDITOR_PROFESSIONAL_STRING,
      claims: { role: "Auditor", scope: "healthcare-document-audit" },
      label: "auditor-ana-v1",
    });

    const policyRegistry = await deployContract("PolicyRegistry", [
      await organizationRegistry.getAddress(),
      await credentialRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await tx(auditRegistry.setAuthorizedEmitter(await policyRegistry.getAddress(), true));
    await tx(policyRegistry.setCredentialTypeRole(VC_MEDICAL_PROFESSIONAL, ROLE.Doctor));
    await tx(policyRegistry.setCredentialTypeRole(VC_AUDITOR_PROFESSIONAL, ROLE.Auditor));

    const policyGovernance = await deployContract("PolicyGovernance", [
      await organizationRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await tx(auditRegistry.setAuthorizedEmitter(await policyGovernance.getAddress(), true));
    await tx(organizationRegistry.setGovernanceContract(await policyGovernance.getAddress()));
    await tx(policyRegistry.setGovernanceContract(await policyGovernance.getAddress()));
    await tx(trustRegistry.setGovernanceContract(await policyGovernance.getAddress()));

    const documentLifecycleRegistry = await deployContract("DocumentLifecycleRegistry", [
      await identityRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const patientDrivenPolicyRegistry = await deployContract("PatientDrivenPolicyRegistry", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const delegationRegistry = await deployContract("DelegationRegistry", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const accessController = await deployContract("AccessController", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await delegationRegistry.getAddress(),
      await patientDrivenPolicyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await tx(auditRegistry.setAuthorizedEmitter(await documentLifecycleRegistry.getAddress(), true));
    await tx(auditRegistry.setAuthorizedEmitter(await patientDrivenPolicyRegistry.getAddress(), true));
    await tx(auditRegistry.setAuthorizedEmitter(await delegationRegistry.getAddress(), true));
    await tx(auditRegistry.setAuthorizedEmitter(await accessController.getAddress(), true));

    await tx(organizationRegistry.lockBootstrap());
    await tx(policyRegistry.lockBootstrap());

    if (lockTrustBootstrap) {
      await tx(trustRegistry.lockBootstrap());
    }

    await tx(auditRegistry.lockBootstrap());

    async function approveGlobalPolicy(role: number, documentType: string, action: string, allowed: boolean, label: string) {
      const proposalId = await policyGovernance.nextProposalId();
      await tx(policyGovernance.connect(organization1).proposeGlobalAccessPolicy(role, documentType, action, allowed, hash(`policy:${label}`)));
      await tx(policyGovernance.connect(organization1).vote(proposalId, true));
      await tx(policyGovernance.connect(organization2).vote(proposalId, true));
      await tx(policyGovernance.finalize(proposalId));
    }

    async function approveMaxDelegationDepth(newDepth: number) {
      const proposalId = await policyGovernance.nextProposalId();
      await tx(policyGovernance.connect(organization1).proposeSetMaxDelegationDepth(newDepth, hash(`max-depth:${newDepth}`)));
      await tx(policyGovernance.connect(organization1).vote(proposalId, true));
      await tx(policyGovernance.connect(organization2).vote(proposalId, true));
      await tx(policyGovernance.finalize(proposalId));
    }

    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_CREATE, true, "Doctor CREATE REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_READ, true, "Doctor READ REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_DELEGATE, true, "Doctor DELEGATE REFERTO");
    await approveGlobalPolicy(ROLE.Auditor, DOCUMENT_TYPE_REFERTO, ACTION_READ, true, "Auditor READ REFERTO");
    await approveMaxDelegationDepth(2);

    async function createDefaultDocument() {
      const documentId = hash(`DOCUMENT-SECURITY-${Math.random()}`);
      await tx(
        documentLifecycleRegistry
          .connect(doctorA)
          .createDocument(documentId, DID_PATIENT, DID_DOCTOR, doctorPresentedCredential, DOCUMENT_TYPE_REFERTO, "bafy-security-v1"),
      );
      return documentId;
    }

    return {
      ethers,
      accounts: { deployer, organization1, organization2, organization3, doctorA, patient, doctorB, doctorC, auditor, attacker },
      contracts: { auditRegistry, organizationRegistry, identityRegistry, trustRegistry, credentialRegistry, policyRegistry, policyGovernance, documentLifecycleRegistry, patientDrivenPolicyRegistry, delegationRegistry, accessController },
      constants: { ROLE, ACTION_READ, ACTION_CREATE, ACTION_DELEGATE, DOCUMENT_TYPE_REFERTO, PURPOSE_CARE, VC_MEDICAL_PROFESSIONAL, VC_AUDITOR_PROFESSIONAL, DID_ORG1, DID_DOCTOR, DID_PATIENT, DID_DOCTOR_B, DID_DOCTOR_C, DID_AUDITOR, DID_ATTACKER, CRED_DOCTOR },
      credentials: { doctorPresentedCredential, auditorPresentedCredential, emptyPresentedCredential: emptyPresentedCredential() },
      helpers: { hash, tx, buildPresentedCredential, createDefaultDocument },
    };
  }

  it("impedisce a un attacker di chiamare requestAccess usando il DID del medico", async function () {
    const s = await setupSystem({ lockTrustBootstrap: false });
    const { accessController } = s.contracts;
    const { attacker } = s.accounts;
    const { doctorPresentedCredential } = s.credentials;
    const { DID_DOCTOR, ACTION_READ, PURPOSE_CARE } = s.constants;
    const { createDefaultDocument, tx } = s.helpers;

    const documentId = await createDefaultDocument();

    await assert.rejects(
      async () => {
        await tx(
          accessController
            .connect(attacker)
            .requestAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
        );
      },
      /Not requester DID controller/,
      "solo il controller del requesterDID deve poter invocare requestAccess",
    );
  });

  it("rifiuta creazione documento se la PresentedCredential è stata manipolata", async function () {
    const s = await setupSystem();
    const { documentLifecycleRegistry } = s.contracts;
    const { doctorA } = s.accounts;
    const { doctorPresentedCredential } = s.credentials;
    const { DID_PATIENT, DID_DOCTOR, DOCUMENT_TYPE_REFERTO } = s.constants;
    const { hash, tx } = s.helpers;

    const tamperedCredential = {
      ...doctorPresentedCredential,
      subject: "did:health:doctor:charlie",
    };

    await assert.rejects(
      async () => {
        await tx(
          documentLifecycleRegistry
            .connect(doctorA)
            .createDocument(
              hash("DOCUMENT-TAMPERED-CREDENTIAL"),
              DID_PATIENT,
              DID_DOCTOR,
              tamperedCredential,
              DOCUMENT_TYPE_REFERTO,
              "bafy-tampered",
            ),
        );
      },
      /Not authorized to create/,
      "se il subject della SD-JWT viene alterato, la credenziale non deve autorizzare",
    );
  });

  it("impedisce a Doctor B senza VC globale di proporre una delega diretta", async function () {
    const s = await setupSystem();
    const { delegationRegistry } = s.contracts;
    const { doctorB } = s.accounts;
    const { emptyPresentedCredential } = s.credentials;
    const { DID_DOCTOR_B, DID_DOCTOR_C, ACTION_READ, PURPOSE_CARE } = s.constants;
    const { createDefaultDocument, tx } = s.helpers;

    const documentId = await createDefaultDocument();
    const block = await s.ethers.provider.getBlock("latest");
    const validFrom = BigInt(block!.timestamp);
    const validUntil = validFrom + 3600n;

    await assert.rejects(
      async () => {
        await tx(
          delegationRegistry
            .connect(doctorB)
            .proposeDelegation(
              DID_DOCTOR_B,
              DID_DOCTOR_C,
              emptyPresentedCredential,
              documentId,
              ACTION_READ,
              PURPOSE_CARE,
              validFrom,
              validUntil,
            ),
        );
      },
      /Not authorized to propose delegation/,
      "Doctor B non ha VC professionale globale e non deve poter creare deleghe dirette autonome",
    );
  });

  it("impedisce al paziente di revocare direttamente un documento", async function () {
    const s = await setupSystem();
    const { documentLifecycleRegistry } = s.contracts;
    const { patient } = s.accounts;
    const { emptyPresentedCredential } = s.credentials;
    const { DID_PATIENT } = s.constants;
    const { createDefaultDocument, tx } = s.helpers;

    const documentId = await createDefaultDocument();

    await assert.rejects(
      async () => {
        await tx(
          documentLifecycleRegistry
            .connect(patient)
            .revokeDocument(
              documentId,
              DID_PATIENT,
              emptyPresentedCredential,
            ),
        );
      },
      /Patient cannot revoke documents/,
      "il paziente non deve poter revocare documenti tramite DocumentLifecycleRegistry",
    );

    assert.equal(
      await documentLifecycleRegistry.isDocumentActive(documentId),
      true,
      "il documento deve restare attivo dopo il tentativo di revoca del paziente",
    );
  });

  it("impedisce a un non-paziente di approvare una proposta di delega", async function () {
    const s = await setupSystem();
    const { delegationRegistry } = s.contracts;
    const { doctorA, attacker } = s.accounts;
    const { doctorPresentedCredential } = s.credentials;
    const { DID_DOCTOR, DID_DOCTOR_B, ACTION_READ, PURPOSE_CARE } = s.constants;
    const { createDefaultDocument, tx } = s.helpers;

    const documentId = await createDefaultDocument();
    const block = await s.ethers.provider.getBlock("latest");
    const validFrom = BigInt(block!.timestamp);
    const validUntil = validFrom + 3600n;

    const proposalId = await delegationRegistry.nextProposalId();
    await tx(
      delegationRegistry
        .connect(doctorA)
        .proposeDelegation(
          DID_DOCTOR,
          DID_DOCTOR_B,
          doctorPresentedCredential,
          documentId,
          ACTION_READ,
          PURPOSE_CARE,
          validFrom,
          validUntil,
        ),
    );

    await assert.rejects(
      async () => {
        await tx(delegationRegistry.connect(attacker).approveDelegationProposal(proposalId));
      },
      /Only patient controller can approve/,
      "solo il controller del DID paziente associato al documento deve approvare la delega",
    );
  });

  it("la revoca della trust authorization dell'issuer invalida la PresentedCredential", async function () {
    const s = await setupSystem({ lockTrustBootstrap: false });
    const { trustRegistry, credentialRegistry, accessController } = s.contracts;
    const { doctorPresentedCredential } = s.credentials;
    const { DID_ORG1, VC_MEDICAL_PROFESSIONAL, DID_DOCTOR, ACTION_READ, PURPOSE_CARE } = s.constants;
    const { createDefaultDocument, tx } = s.helpers;

    const documentId = await createDefaultDocument();

    assert.equal(await credentialRegistry.isPresentedCredentialValidForSubject(doctorPresentedCredential, DID_DOCTOR), true);
    assert.equal(await accessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE), true);

    await tx(trustRegistry.revokeIssuerAuthorization(DID_ORG1, VC_MEDICAL_PROFESSIONAL));

    assert.equal(
      await credentialRegistry.isPresentedCredentialValidForSubject(doctorPresentedCredential, DID_DOCTOR),
      false,
      "se l'issuer non è più trusted per quel tipo, la credenziale presentata non deve essere accettata",
    );

    assert.equal(
      await accessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      false,
      "l'accesso basato su VC deve fallire dopo revoca della trust authorization",
    );
  });
});
