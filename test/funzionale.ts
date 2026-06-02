import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { network } from "hardhat";

type MetricRecord = {
  group: string;
  operation: string;
  kind: "deploy" | "tx" | "view" | "expected-revert";
  ms: number;
  gasUsed?: string;
  success: boolean;
  notes?: string;
};

describe("VC selective disclosure - performance report", async function () {
  it("misura tempi e gas delle principali operazioni del prototipo", async function () {
    const { ethers } = await network.connect();

    const records: MetricRecord[] = [];

    function pushRecord(record: MetricRecord) {
      records.push({
        ...record,
        ms: Number(record.ms.toFixed(3)),
      });
    }

    async function measureView<T>(
      operation: string,
      fn: () => Promise<T>,
      group = "workflow",
      notes = "",
    ): Promise<T> {
      const startedAt = performance.now();
      try {
        const result = await fn();
        const endedAt = performance.now();
        pushRecord({
          group,
          operation,
          kind: "view",
          ms: endedAt - startedAt,
          success: true,
          notes,
        });
        return result;
      } catch (error) {
        const endedAt = performance.now();
        pushRecord({
          group,
          operation,
          kind: "view",
          ms: endedAt - startedAt,
          success: false,
          notes: `${notes} ${String(error)}`.trim(),
        });
        throw error;
      }
    }

    async function measureTx(
      operation: string,
      fn: () => Promise<any>,
      group = "workflow",
      notes = "",
    ) {
      const startedAt = performance.now();
      try {
        const response = await fn();
        const receipt = await response.wait();
        const endedAt = performance.now();
        pushRecord({
          group,
          operation,
          kind: "tx",
          ms: endedAt - startedAt,
          gasUsed: receipt?.gasUsed?.toString?.(),
          success: true,
          notes,
        });
        return { response, receipt };
      } catch (error) {
        const endedAt = performance.now();
        pushRecord({
          group,
          operation,
          kind: "tx",
          ms: endedAt - startedAt,
          success: false,
          notes: `${notes} ${String(error)}`.trim(),
        });
        throw error;
      }
    }

    async function measureExpectedRevert(
      operation: string,
      fn: () => Promise<any>,
      expectedReason: RegExp,
      group = "workflow",
      notes = "",
    ) {
      const startedAt = performance.now();
      try {
        const response = await fn();
        await response.wait();
        const endedAt = performance.now();
        pushRecord({
          group,
          operation,
          kind: "expected-revert",
          ms: endedAt - startedAt,
          success: false,
          notes: `${notes} ERRORE: la transazione non e' fallita`.trim(),
        });
        assert.fail(`${operation}: expected revert`);
      } catch (error) {
        const endedAt = performance.now();
        const text = String(error);
        const matches = expectedReason.test(text);
        pushRecord({
          group,
          operation,
          kind: "expected-revert",
          ms: endedAt - startedAt,
          success: matches,
          notes: `${notes} ${matches ? "revert atteso" : text}`.trim(),
        });
        if (!matches) throw error;
      }
    }

    async function deployMeasured(name: string, args: any[] = []) {
      const Factory = await ethers.getContractFactory(name);
      const startedAt = performance.now();
      const contract = await Factory.deploy(...args);
      const deploymentTx = contract.deploymentTransaction();
      const receipt = deploymentTx ? await deploymentTx.wait() : undefined;
      await contract.waitForDeployment();
      const endedAt = performance.now();
      pushRecord({
        group: "deploy",
        operation: `deploy ${name}`,
        kind: "deploy",
        ms: endedAt - startedAt,
        gasUsed: receipt?.gasUsed?.toString?.(),
        success: true,
        notes: await contract.getAddress(),
      });
      return contract;
    }

    function hash(value: string): string {
      return ethers.keccak256(ethers.toUtf8Bytes(value));
    }

    function emptyPresentedCredential() {
      return {
        format: "",
        id: "",
        issuer: "",
        subject: "",
        credentialType: "",
        sdJwtCredential: "",
        selectivelyDisclosableClaims: [] as string[],
      };
    }

    function assertHashMatches(label: string, plainValue: string, expectedHash: string) {
      assert.equal(
        hash(plainValue),
        expectedHash,
        `${label}: il valore testuale non corrisponde al bytes32 registrato on-chain`,
      );
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
        selectivelyDisclosableClaims: Object.keys(claims),
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
      doctorD,
    ] = await ethers.getSigners();

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

    const VC_MEDICAL_PROFESSIONAL_TEXT = "MedicalProfessionalVC";
    const VC_AUDITOR_PROFESSIONAL_TEXT = "AuditorProfessionalVC";

    const DID_ORG1_TEXT = "did:health:org:1";
    const DID_ORG2_TEXT = "did:health:org:2";
    const DID_ORG3_TEXT = "did:health:org:3";
    const DID_DOCTOR_TEXT = "did:health:doctor:alice";
    const DID_PATIENT_TEXT = "did:health:patient:bob";
    const DID_DOCTOR_B_TEXT = "did:health:doctor:charlie";
    const DID_DOCTOR_C_TEXT = "did:health:doctor:diana";
    const DID_AUDITOR_TEXT = "did:health:auditor:ana";
    const DID_ATTACKER_TEXT = "did:health:unknown:eve";
    const DID_DOCTOR_D_TEXT = "did:health:doctor:daniel";

    const CRED_DOCTOR_TEXT = "vc:doctor:alice:medical-professional:v1";
    const CRED_AUDITOR_TEXT = "vc:auditor:ana:auditor-professional:v1";
    const CRED_DOCTOR_D_TEXT = "vc:doctor:daniel:medical-professional:v1";

    const VC_MEDICAL_PROFESSIONAL = hash(VC_MEDICAL_PROFESSIONAL_TEXT);
    const VC_AUDITOR_PROFESSIONAL = hash(VC_AUDITOR_PROFESSIONAL_TEXT);

    const DID_ORG1 = hash(DID_ORG1_TEXT);
    const DID_ORG2 = hash(DID_ORG2_TEXT);
    const DID_ORG3 = hash(DID_ORG3_TEXT);
    const DID_DOCTOR = hash(DID_DOCTOR_TEXT);
    const DID_PATIENT = hash(DID_PATIENT_TEXT);
    const DID_DOCTOR_B = hash(DID_DOCTOR_B_TEXT);
    const DID_DOCTOR_C = hash(DID_DOCTOR_C_TEXT);
    const DID_AUDITOR = hash(DID_AUDITOR_TEXT);
    const DID_ATTACKER = hash(DID_ATTACKER_TEXT);
    const DID_DOCTOR_D = hash(DID_DOCTOR_D_TEXT);

    const CRED_DOCTOR = hash(CRED_DOCTOR_TEXT);
    const CRED_AUDITOR = hash(CRED_AUDITOR_TEXT);
    const CRED_DOCTOR_D = hash(CRED_DOCTOR_D_TEXT);

    const auditRegistry = await deployMeasured("AuditRegistry");
    const organizationRegistry = await deployMeasured("OrganizationRegistry", [
      await auditRegistry.getAddress(),
    ]);
    const identityRegistry = await deployMeasured("IdentityRegistry", [
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize OrganizationRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await organizationRegistry.getAddress(), true),
      "setup",
    );
    await measureTx(
      "authorize IdentityRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await identityRegistry.getAddress(), true),
      "setup",
    );

    await measureTx(
      "add Organization 1",
      async () => organizationRegistry.addOrganization(organization1.address, hash("Organization 1 metadata")),
      "setup",
    );
    await measureTx(
      "add Organization 2",
      async () => organizationRegistry.addOrganization(organization2.address, hash("Organization 2 metadata")),
      "setup",
    );
    await measureTx(
      "add Organization 3",
      async () => organizationRegistry.addOrganization(organization3.address, hash("Organization 3 metadata")),
      "setup",
    );

    async function registerDID(signer: any, did: string, label: string) {
      await measureTx(
        `register DID ${label}`,
        () =>
          identityRegistry
            .connect(signer)
            .registerDID(did, hash(`CID:DID:${label}`), hash(`DID-DOCUMENT:${label}`)),
        "identity",
      );
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
    await registerDID(doctorD, DID_DOCTOR_D, "doctorD");

    const trustRegistry = await deployMeasured("TrustRegistry", [
      await identityRegistry.getAddress(),
      await organizationRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize TrustRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await trustRegistry.getAddress(), true),
      "setup",
    );

    await measureTx(
      "authorize issuer Org1 for MedicalProfessionalVC",
      () => trustRegistry.authorizeIssuer(DID_ORG1, VC_MEDICAL_PROFESSIONAL),
      "trust",
    );
    await measureTx(
      "authorize issuer Org1 for AuditorProfessionalVC",
      () => trustRegistry.authorizeIssuer(DID_ORG1, VC_AUDITOR_PROFESSIONAL),
      "trust",
    );

    const credentialRegistry = await deployMeasured("CredentialStatusRegistry", [
      await identityRegistry.getAddress(),
      await trustRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize CredentialStatusRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await credentialRegistry.getAddress(), true),
      "setup",
    );

    const nowBlock = await ethers.provider.getBlock("latest");
    const validFrom = BigInt(nowBlock!.timestamp);
    const validUntil = validFrom + 365n * 24n * 60n * 60n;

    async function issueCredential({
      credentialId,
      issuerSigner,
      issuerDID,
      subjectDID,
      credentialType,
      id,
      issuer,
      subject,
      credentialTypeName,
      claims,
      label,
    }: {
      credentialId: string;
      issuerSigner: any;
      issuerDID: string;
      subjectDID: string;
      credentialType: string;
      id: string;
      issuer: string;
      subject: string;
      credentialTypeName: string;
      claims: Record<string, string>;
      label: string;
    }) {
      assertHashMatches(`credentialId ${label}`, id, credentialId);
      assertHashMatches(`issuerDID ${label}`, issuer, issuerDID);
      assertHashMatches(`subjectDID ${label}`, subject, subjectDID);
      assertHashMatches(`credentialType ${label}`, credentialTypeName, credentialType);

      await measureTx(
        `issue credential ${label}`,
        () =>
          credentialRegistry
            .connect(issuerSigner)
            .issueCredential(credentialId, issuerDID, credentialType, validFrom, validUntil),
        "credential",
      );

      const startedAt = performance.now();
      const presentedCredential = await buildPresentedCredential({
        id,
        issuer,
        subject,
        credentialType: credentialTypeName,
        claims,
        label,
      });
      const endedAt = performance.now();
      pushRecord({
        group: "credential-offchain",
        operation: `build SD-JWT PresentedCredential ${label}`,
        kind: "view",
        ms: endedAt - startedAt,
        success: true,
        notes: "operazione off-chain simulata: costruzione pacchetto vc+sd-jwt compatibile con la struct Solidity",
      });

      return presentedCredential;
    }

    const doctorPresentedCredential = await issueCredential({
      credentialId: CRED_DOCTOR,
      issuerSigner: organization1,
      issuerDID: DID_ORG1,
      subjectDID: DID_DOCTOR,
      credentialType: VC_MEDICAL_PROFESSIONAL,
      id: CRED_DOCTOR_TEXT,
      issuer: DID_ORG1_TEXT,
      subject: DID_DOCTOR_TEXT,
      credentialTypeName: VC_MEDICAL_PROFESSIONAL_TEXT,
      label: "doctorA-medical-v1",
      claims: {
        role: "Doctor",
        organization: "Organization 1",
        department: "Cardiology",
      },
    });

    const auditorPresentedCredential = await issueCredential({
      credentialId: CRED_AUDITOR,
      issuerSigner: organization1,
      issuerDID: DID_ORG1,
      subjectDID: DID_AUDITOR,
      credentialType: VC_AUDITOR_PROFESSIONAL,
      id: CRED_AUDITOR_TEXT,
      issuer: DID_ORG1_TEXT,
      subject: DID_AUDITOR_TEXT,
      credentialTypeName: VC_AUDITOR_PROFESSIONAL_TEXT,
      label: "auditor-ana-v1",
      claims: {
        role: "Auditor",
        scope: "healthcare-document-audit",
      },
    });

    const doctorDPresentedCredential = await issueCredential({
      credentialId: CRED_DOCTOR_D,
      issuerSigner: organization1,
      issuerDID: DID_ORG1,
      subjectDID: DID_DOCTOR_D,
      credentialType: VC_MEDICAL_PROFESSIONAL,
      id: CRED_DOCTOR_D_TEXT,
      issuer: DID_ORG1_TEXT,
      subject: DID_DOCTOR_D_TEXT,
      credentialTypeName: VC_MEDICAL_PROFESSIONAL_TEXT,
      label: "doctorD-medical-v1",
      claims: {
        role: "Doctor",
        organization: "Organization 1",
        department: "Neurology",
      },
    });

    const policyRegistry = await deployMeasured("PolicyRegistry", [
      await organizationRegistry.getAddress(),
      await credentialRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize PolicyRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await policyRegistry.getAddress(), true),
      "setup",
    );

    await measureTx(
      "map MedicalProfessionalVC to Doctor role",
      () => policyRegistry.setCredentialTypeRole(VC_MEDICAL_PROFESSIONAL, ROLE.Doctor),
      "policy",
    );
    await measureTx(
      "map AuditorProfessionalVC to Auditor role",
      () => policyRegistry.setCredentialTypeRole(VC_AUDITOR_PROFESSIONAL, ROLE.Auditor),
      "policy",
    );

    const policyGovernance = await deployMeasured("PolicyGovernance", [
      await organizationRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize PolicyGovernance as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await policyGovernance.getAddress(), true),
      "setup",
    );

    await measureTx(
      "set OrganizationRegistry governance contract",
      async () => organizationRegistry.setGovernanceContract(await policyGovernance.getAddress()),
      "governance-setup",
    );
    await measureTx(
      "set PolicyRegistry governance contract",
      async () => policyRegistry.setGovernanceContract(await policyGovernance.getAddress()),
      "governance-setup",
    );
    await measureTx(
      "set TrustRegistry governance contract",
      async () => trustRegistry.setGovernanceContract(await policyGovernance.getAddress()),
      "governance-setup",
    );

    const documentLifecycleRegistry = await deployMeasured("DocumentLifecycleRegistry", [
      await identityRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const patientDrivenPolicyRegistry = await deployMeasured("PatientDrivenPolicyRegistry", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const delegationRegistry = await deployMeasured("DelegationRegistry", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    const accessController = await deployMeasured("AccessController", [
      await identityRegistry.getAddress(),
      await documentLifecycleRegistry.getAddress(),
      await policyRegistry.getAddress(),
      await delegationRegistry.getAddress(),
      await patientDrivenPolicyRegistry.getAddress(),
      await auditRegistry.getAddress(),
    ]);

    await measureTx(
      "authorize DocumentLifecycleRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await documentLifecycleRegistry.getAddress(), true),
      "setup",
    );
    await measureTx(
      "authorize PatientDrivenPolicyRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await patientDrivenPolicyRegistry.getAddress(), true),
      "setup",
    );
    await measureTx(
      "authorize DelegationRegistry as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await delegationRegistry.getAddress(), true),
      "setup",
    );
    await measureTx(
      "authorize AccessController as audit emitter",
      async () => auditRegistry.setAuthorizedEmitter(await accessController.getAddress(), true),
      "setup",
    );

    await measureTx("lock OrganizationRegistry bootstrap", () => organizationRegistry.lockBootstrap(), "setup");
    await measureTx("lock PolicyRegistry bootstrap", () => policyRegistry.lockBootstrap(), "setup");
    await measureTx("lock TrustRegistry bootstrap", () => trustRegistry.lockBootstrap(), "setup");
    await measureTx("lock AuditRegistry bootstrap", () => auditRegistry.lockBootstrap(), "setup");

    async function approveGlobalPolicy(
      role: number,
      documentType: string,
      action: string,
      allowed: boolean,
      label: string,
    ) {
      const policyCID = hash(`Policy:${label}`);
      const proposalId = await measureView(
        `read nextProposalId for ${label}`,
        () => policyGovernance.nextProposalId(),
        "governance",
      );

      await measureTx(
        `propose global policy: ${label}`,
        () =>
          policyGovernance
            .connect(organization1)
            .proposeGlobalAccessPolicy(role, documentType, action, allowed, policyCID),
        "governance",
      );
      await measureTx(
        `vote org1 for global policy: ${label}`,
        () => policyGovernance.connect(organization1).vote(proposalId, true),
        "governance",
      );
      await measureTx(
        `vote org2 for global policy: ${label}`,
        () => policyGovernance.connect(organization2).vote(proposalId, true),
        "governance",
      );
      await measureTx(
        `finalize global policy: ${label}`,
        () => policyGovernance.finalize(proposalId),
        "governance",
      );
    }

    async function approveMaxDelegationDepth(newDepth: number) {
      const policyCID = hash(`MaxDelegationDepth:${newDepth}`);
      const proposalId = await measureView(
        "read nextProposalId for maxDelegationDepth",
        () => policyGovernance.nextProposalId(),
        "governance",
      );

      await measureTx(
        `propose maxDelegationDepth = ${newDepth}`,
        () => policyGovernance.connect(organization1).proposeSetMaxDelegationDepth(newDepth, policyCID),
        "governance",
      );
      await measureTx(
        `vote org1 for maxDelegationDepth = ${newDepth}`,
        () => policyGovernance.connect(organization1).vote(proposalId, true),
        "governance",
      );
      await measureTx(
        `vote org2 for maxDelegationDepth = ${newDepth}`,
        () => policyGovernance.connect(organization2).vote(proposalId, true),
        "governance",
      );
      await measureTx(
        `finalize maxDelegationDepth = ${newDepth}`,
        () => policyGovernance.finalize(proposalId),
        "governance",
      );
    }

    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_CREATE, true, "Doctor CREATE REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_READ, true, "Doctor READ REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_UPDATE, true, "Doctor UPDATE REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_REVOKE, true, "Doctor REVOKE REFERTO");
    await approveGlobalPolicy(ROLE.Doctor, DOCUMENT_TYPE_REFERTO, ACTION_DELEGATE, true, "Doctor DELEGATE REFERTO");
    await approveMaxDelegationDepth(2);

    const credentialValid = await measureView(
      "verify PresentedCredential for Doctor A",
      () => credentialRegistry.isPresentedCredentialValidForSubject(doctorPresentedCredential, DID_DOCTOR),
      "credential",
    );
    assert.equal(credentialValid, true);

    const doctorDCredentialValid = await measureView(
      "verify PresentedCredential for Doctor D",
      () => credentialRegistry.isPresentedCredentialValidForSubject(doctorDPresentedCredential, DID_DOCTOR_D),
      "credential",
    );
    assert.equal(doctorDCredentialValid, true);

    const canCreate = await measureView(
      "canPerformWithCredential Doctor CREATE REFERTO",
      () =>
        policyRegistry.canPerformWithCredential(
          DID_DOCTOR,
          doctorPresentedCredential,
          DOCUMENT_TYPE_REFERTO,
          ACTION_CREATE,
        ),
      "policy",
    );
    assert.equal(canCreate, true);

    const documentId = hash("DOCUMENT-PERFORMANCE-001");

    await measureTx(
      "create document v1",
      () =>
        documentLifecycleRegistry
          .connect(doctorA)
          .createDocument(
            documentId,
            DID_PATIENT,
            DID_DOCTOR,
            doctorPresentedCredential,
            DOCUMENT_TYPE_REFERTO,
            "bafy-perf-referto-v1",
          ),
      "document-lifecycle",
    );

    await measureExpectedRevert(
      "patient cannot revoke document",
      () =>
        documentLifecycleRegistry
          .connect(patient)
          .revokeDocument(
            documentId,
            DID_PATIENT,
            emptyPresentedCredential(),
          ),
      /Patient cannot revoke documents/,
      "document-lifecycle",
    );

    const currentDocument = await measureView(
      "get current document after create",
      () => documentLifecycleRegistry.getCurrentDocument(documentId),
      "document-lifecycle",
    );
    assert.equal(currentDocument.versionNumber, 1n);
    assert.equal(currentDocument.state, 1n);

    await measureTx(
      "create document v2",
      () =>
        documentLifecycleRegistry
          .connect(doctorA)
          .createNewVersion(documentId, DID_DOCTOR, doctorPresentedCredential, "bafy-perf-referto-v2"),
      "document-lifecycle",
    );

    const cidOk = await measureView(
      "verify CID document v2",
      () => documentLifecycleRegistry.verifyCID(documentId, 2, "bafy-perf-referto-v2"),
      "document-lifecycle",
    );
    assert.equal(cidOk, true);

    const doctorCanRead = await measureView(
      "canAccess Doctor A READ by global policy + VC",
      () => accessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(doctorCanRead, true);

    await measureTx(
      "requestAccess Doctor A READ by global policy + VC",
      () =>
        accessController
          .connect(doctorA)
          .requestAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );

    const auditorCanReadReferto = await measureView(
      "canAccess Auditor read REFERTO",
      () => accessController.canAccess(DID_AUDITOR, auditorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(auditorCanReadReferto, false);

    const doctorDAllowanceBlock = await ethers.provider.getBlock("latest");
    const doctorDAllowanceValidFrom = BigInt(doctorDAllowanceBlock!.timestamp);
    const doctorDAllowanceValidUntil = doctorDAllowanceValidFrom + 7n * 24n * 60n * 60n;

    await measureTx(
      "register patient-driven allowance for Doctor D READ",
      () =>
        patientDrivenPolicyRegistry
          .connect(patient)
          .registerRestriction(
            documentId,
            DID_PATIENT,
            ethers.ZeroHash,
            ethers.ZeroHash,
            DID_DOCTOR_D,
            ACTION_READ,
            PURPOSE_CARE,
            doctorDAllowanceValidFrom,
            doctorDAllowanceValidUntil,
            hash("patient-policy:allow-doctor-d-read:perf"),
          ),
      "patient-driven-policy",
    );

    const doctorDIsAllowedByPatient = await measureView(
      "isAllowed Doctor D READ by patient-driven positive policy",
      () =>
        patientDrivenPolicyRegistry.isAllowed(
          DID_DOCTOR_D,
          documentId,
          ACTION_READ,
          PURPOSE_CARE,
        ),
      "patient-driven-policy",
    );
    assert.equal(doctorDIsAllowedByPatient, true);

    const doctorDCanReadAfterPatientAllowance = await measureView(
      "canAccess Doctor D after patient-driven positive allowance",
      () =>
        accessController.canAccess(
          DID_DOCTOR_D,
          doctorDPresentedCredential,
          documentId,
          ACTION_READ,
          PURPOSE_CARE,
        ),
      "access-control",
    );

    assert.equal(doctorDCanReadAfterPatientAllowance, true);

    await measureTx(
      "requestAccess Doctor D after patient-driven positive allowance",
      () =>
        accessController
          .connect(doctorD)
          .requestAccess(
            DID_DOCTOR_D,
            doctorDPresentedCredential,
            documentId,
            ACTION_READ,
            PURPOSE_CARE,
          ),
      "access-control",
    );

    const delegationBlock = await ethers.provider.getBlock("latest");
    const delegationValidFrom = BigInt(delegationBlock!.timestamp);
    const delegationValidUntil = delegationValidFrom + 24n * 60n * 60n;

    const directProposalId = await measureView(
      "read nextProposalId for direct delegation",
      () => delegationRegistry.nextProposalId(),
      "delegation",
    );

    await measureTx(
      "propose direct delegation Doctor A -> Doctor B",
      () =>
        delegationRegistry
          .connect(doctorA)
          .proposeDelegation(
            DID_DOCTOR,
            DID_DOCTOR_B,
            doctorPresentedCredential,
            documentId,
            ACTION_READ,
            PURPOSE_CARE,
            delegationValidFrom,
            delegationValidUntil,
          ),
      "delegation",
    );

    const bCanReadPending = await measureView(
      "canAccess Doctor B while delegation is Pending",
      () => accessController.canAccess(DID_DOCTOR_B, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(bCanReadPending, false);

    const directDelegationId = await measureView(
      "read nextDelegationId for direct delegation",
      () => delegationRegistry.nextDelegationId(),
      "delegation",
    );

    await measureTx(
      "approve direct delegation by patient",
      () => delegationRegistry.connect(patient).approveDelegationProposal(directProposalId),
      "delegation",
    );

    const bCanReadAfterDelegation = await measureView(
      "canAccess Doctor B after direct delegation",
      () => accessController.canAccess(DID_DOCTOR_B, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(bCanReadAfterDelegation, true);

    await measureTx(
      "requestAccess Doctor B through direct delegation",
      () =>
        accessController
          .connect(doctorB)
          .requestAccess(DID_DOCTOR_B, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );

    const derivedProposalId = await measureView(
      "read nextProposalId for derived delegation",
      () => delegationRegistry.nextProposalId(),
      "delegation",
    );

    await measureTx(
      "propose derived delegation Doctor B -> Doctor C",
      () =>
        delegationRegistry
          .connect(doctorB)
          .proposeDerivedDelegation(directDelegationId, DID_DOCTOR_C, delegationValidFrom, delegationValidUntil),
      "delegation",
    );

    const derivedDelegationId = await measureView(
      "read nextDelegationId for derived delegation",
      () => delegationRegistry.nextDelegationId(),
      "delegation",
    );

    await measureTx(
      "approve derived delegation by patient",
      () => delegationRegistry.connect(patient).approveDelegationProposal(derivedProposalId),
      "delegation",
    );

    const cCanReadAfterDerivedDelegation = await measureView(
      "canAccess Doctor C after derived delegation",
      () => accessController.canAccess(DID_DOCTOR_C, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(cCanReadAfterDerivedDelegation, true);

    await measureExpectedRevert(
      "reject third-level delegation above maxDepth",
      () =>
        delegationRegistry
          .connect(doctorC)
          .proposeDerivedDelegation(derivedDelegationId, DID_ATTACKER, delegationValidFrom, delegationValidUntil),
      /Max delegation depth exceeded/,
      "delegation-security",
    );

    await measureTx(
      "revoke parent direct delegation by patient",
      () => delegationRegistry.connect(patient).revokeDelegation(directDelegationId, DID_PATIENT),
      "delegation",
    );

    const bCanReadAfterParentRevocation = await measureView(
      "canAccess Doctor B after parent delegation revocation",
      () => accessController.canAccess(DID_DOCTOR_B, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(bCanReadAfterParentRevocation, false);

    const cCanReadAfterParentRevocation = await measureView(
      "canAccess Doctor C after parent delegation revocation",
      () => accessController.canAccess(DID_DOCTOR_C, emptyPresentedCredential(), documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(cCanReadAfterParentRevocation, false);

    const doctorRestrictionBlock = await ethers.provider.getBlock("latest");
    const doctorRestrictionValidFrom = BigInt(doctorRestrictionBlock!.timestamp);
    const doctorRestrictionValidUntil = doctorRestrictionValidFrom + 7n * 24n * 60n * 60n;

    await measureTx(
      "register patient-driven access revocation for Doctor A READ",
      () =>
        patientDrivenPolicyRegistry
          .connect(patient)
          .registerRestriction(
            documentId,
            DID_PATIENT,
            DID_DOCTOR,
            ACTION_READ,
            ethers.ZeroHash,
            ethers.ZeroHash,
            PURPOSE_CARE,
            doctorRestrictionValidFrom,
            doctorRestrictionValidUntil,
            hash("patient-policy:restrict-doctor-a-read:perf"),
          ),
      "patient-driven-policy",
    );

    const documentStillActive = await measureView(
      "isDocumentActive after patient-driven access revocation",
      () => documentLifecycleRegistry.isDocumentActive(documentId),
      "document-lifecycle",
    );
    assert.equal(documentStillActive, true);

    const doctorCanReadAfterPatientRestriction = await measureView(
      "canAccess Doctor A after patient-driven access revocation",
      () => accessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(doctorCanReadAfterPatientRestriction, false);

    await measureTx(
      "revoke Doctor A VC by issuer",
      () => credentialRegistry.connect(organization1).revokeCredential(CRED_DOCTOR),
      "credential",
    );

    const doctorCredentialValidAfterRevocation = await measureView(
      "isCredentialValid Doctor A after VC revocation",
      () => credentialRegistry.isCredentialValid(CRED_DOCTOR),
      "credential",
    );
    assert.equal(doctorCredentialValidAfterRevocation, false);

    const doctorCanReadAfterVCRevocation = await measureView(
      "canAccess Doctor A after VC revocation",
      () => accessController.canAccess(DID_DOCTOR, doctorPresentedCredential, documentId, ACTION_READ, PURPOSE_CARE),
      "access-control",
    );
    assert.equal(doctorCanReadAfterVCRevocation, false);

    const outputDir = path.join(process.cwd(), "performance-results");
    await mkdir(outputDir, { recursive: true });

    const totalMs = records.reduce((sum, record) => sum + record.ms, 0);
    const txRecords = records.filter((record) => record.kind === "tx" || record.kind === "deploy");
    const totalGas = txRecords.reduce((sum, record) => sum + BigInt(record.gasUsed ?? "0"), 0n);

    const report = {
      generatedAt: new Date().toISOString(),
      environment: {
        network: "hardhat local node/test network",
        note:
          "I tempi sono wall-clock locali misurati con performance.now(): includono esecuzione Hardhat/EVM locale e attesa receipt. Non rappresentano latenze di una rete permissioned reale.",
      },
      totals: {
        operationsMeasured: records.length,
        totalMeasuredMs: Number(totalMs.toFixed(3)),
        txOrDeployOperations: txRecords.length,
        totalGasUsed: totalGas.toString(),
      },
      records,
    };

    const jsonPath = path.join(outputDir, "vc-performance-report.json");
    const csvPath = path.join(outputDir, "vc-performance-report.csv");

    await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf8");

    const csvHeader = "group,operation,kind,ms,gasUsed,success,notes\n";
    const escapeCsv = (value: unknown) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const csvRows = records
      .map((record) =>
        [
          record.group,
          record.operation,
          record.kind,
          record.ms,
          record.gasUsed ?? "",
          record.success,
          record.notes ?? "",
        ]
          .map(escapeCsv)
          .join(","),
      )
      .join("\n");

    await writeFile(csvPath, csvHeader + csvRows + "\n", "utf8");

    console.log("\nPerformance report written to:");
    console.log(` - ${jsonPath}`);
    console.log(` - ${csvPath}`);

    console.table(
      records
        .filter((record) => record.group !== "deploy" && record.group !== "setup")
        .map((record) => ({
          group: record.group,
          operation: record.operation,
          kind: record.kind,
          ms: record.ms,
          gasUsed: record.gasUsed ?? "",
          success: record.success,
        })),
    );
  });
});