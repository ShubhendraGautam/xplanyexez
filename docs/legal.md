# Legal, authorization, privacy, and disclosure checklist

Last primary-source review: 2026-08-09. This document is an engineering gate,
not legal advice. Law depends on location, ownership, contract, target type,
data, radio emissions, and what is later shared. Re-check the current law and
obtain qualified advice before Level 2+ work, publication, import/export, or work
for another party.

## Mandatory authorization record

Before probing anything beyond the operator's personally owned, isolated device:

- [ ] Identify the legal owner, operator, data owner, network owner, account
  owner, spectrum/license holder, and facility owner; these may differ.
- [ ] Obtain written authorization from every relevant authority.
- [ ] Record target serials/IDs, locations, networks, accounts, interfaces, and
  excluded assets—“our network” or “a model of laptop” is not precise scope.
- [ ] Record allowed probe levels, methods, credentials, data, hours, traffic,
  outage/data-loss tolerance, physical access, and publication rights.
- [ ] Record start/end dates, named operators, emergency contacts, stop authority,
  incident notification, and evidence retention/deletion requirements.
- [ ] Confirm the authorizer can legally grant the requested permissions.
- [ ] Check employment, university, cloud, lease, financing, warranty, support,
  insurance, EULA, NDA, acceptable-use, bug-bounty, and export obligations.
- [ ] Confirm third-party/user data is absent, separately authorized, or protected
  under an approved data-handling plan.
- [ ] Re-authorize any material scope change. Discovery of a reachable target is
  not permission to probe it.

## India-focused gate

The initial lab is assumed to be in India; verify that assumption per run.

- [ ] **Computer access and damage:** review the Information Technology Act,
  particularly sections 43 (access/damage without permission), 65 (source
  document tampering), 66 (computer-related offences), 70 (protected systems),
  72 (confidentiality/privacy), and 72A (disclosure in breach of lawful contract).
  The official [India Code index](https://www.indiacode.nic.in/handle/123456789/1999?sam_handle=123456789%2F1362&view_type=search)
  links the current provisions. Ownership of one component does not authorize
  access to another person's account, service, network, or protected system.
- [ ] **Copyright/reverse engineering:** confirm the copy is lawful and the exact
  use fits applicable law and contract. Section 52 of the Copyright Act includes
  limited treatment for a lawful possessor concerning interoperability,
  observation/study/testing during supplied functions, backup, and certain
  personal use; it is not a blanket exemption for distribution or every
  circumvention. Use the official [Copyright Office text](https://copyright.gov.in/Copyright_Act_1957/chapter_xi.html).
- [ ] **Personal data:** hardware reports can contain names, asset tags, MACs,
  UUIDs, location, user content, and identifiers. Apply minimization, purpose,
  consent/other lawful basis, access control, breach response, retention, erasure,
  and transfer rules as applicable. Check the [Digital Personal Data Protection
  Act 2023](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf)
  and the phased [DPDP Rules 2025](https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa?hl=en-US)
  effective dates before each release.
- [ ] **Radio and telecommunications:** receive-only or low-power indoor operation
  is not automatically exempt. Confirm equipment possession, frequency
  assignment, license-exempt conditions, power, antenna, location, emissions,
  import, and testing rules. India's WPC provides an [Experimental and Technology
  Trial License](https://eservices.dot.gov.in/experimental-and-technology-trial-license)
  process for non-radiating indoor and radiating trials. Also check the current
  [Telecommunications Act 2023](https://eservices.dot.gov.in/sites/default/files/circular-notifications/Telecommunications-Act-2023.pdf)
  and implementing rules.
- [ ] **Critical infrastructure and communications:** never probe notified
  protected systems or intercept messages/traffic without specific lawful
  authority. A personally owned radio or computer does not confer rights over
  signals, networks, or data belonging to others.
- [ ] **Import/export and publication:** classify debug equipment, high-speed
  electronics, cryptography, FPGA/ASIC technology, firmware, vulnerability data,
  and technical assistance before cross-border transfer or public release. Check
  current DGFT SCOMET controls and sanctions/end-use/end-user restrictions.
- [ ] **Waste and hazardous work:** damaged batteries, boards, chemicals, solder,
  and destructively tested samples need an approved handling/disposal route. The
  official [E-Waste (Management) Rules 2022](https://moef.gov.in/uploads/2022/11/E-Waste-Management-Rules-2022.pdf)
  apply to relevant producers/refurbishers/dismantlers/recyclers; verify later
  amendments and whether the activity triggers additional requirements.

## Cross-border gate

When code, evidence, firmware, equipment, or technical help crosses a border,
the laws of more than one place can apply.

- [ ] **Unauthorized access:** verify local computer-misuse law even when the
  physical device was lawfully acquired. In the United States, for example,
  [18 U.S.C. §1030](https://uscode.house.gov/view.xhtml?edition=2023&num=0&req=granuleid%3AUSC-2023-title18-section1030)
  covers categories of unauthorized access and damage.
- [ ] **Technological protection measures:** check anti-circumvention separately
  from copyright infringement. The current U.S. good-faith security-research
  exemption requires, among other conditions, a lawfully acquired device or
  owner/operator authorization and an environment designed to avoid harm; it
  expressly is not immunity from other laws. See
  [37 C.F.R. §201.40(b)(18)](https://www.copyright.gov/title37/201/37cfr201-40.html).
- [ ] **EU software interoperability:** if EU law applies, review the limited
  conditions for observation/testing and decompilation for interoperability in
  [Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32009L0024),
  including restrictions on how obtained information may be used.
- [ ] **Radio:** follow the national regulator. In the United States, modified or
  experimental intentional radiators may require authorization; FCC Part 5
  includes experimental authorizations. Use the official [FCC Experimental
  Licensing System](https://apps.fcc.gov/oetcf/els/forms/442Dashboard.cfm) and
  current rules rather than assuming certification follows a modified unit.
- [ ] **Export controls:** public Git hosting and access by a foreign collaborator
  can constitute a controlled transfer in some regimes. U.S. EAR rules, for
  example, specifically address technology/source code, releases to foreign
  persons, and encryption. Start from the official [BIS EAR](https://www.bis.gov/ear)
  and obtain classification advice when applicable.
- [ ] Check patents, semiconductor mask-work/topography rights, trade secrets,
  database rights, consumer protection, product certification, environmental,
  workplace safety, surveillance/wiretapping, and sector rules for the actual
  jurisdiction and target.

## Data-handling gate

- [ ] Classify each evidence field as public, project, personal, secret,
  credential/key, vendor-confidential, export-controlled, or regulated.
- [ ] Default-deny collection of memory contents, storage sectors, packet payloads,
  microphone/camera samples, biometrics, TPM secrets, credentials, and keys.
- [ ] Collect only what the hypothesis requires; inventory does not justify a
  full memory, disk, firmware, or network-content dump.
- [ ] Encrypt raw evidence at rest and in transit; separate decryption keys and
  audit access.
- [ ] Use per-field redaction and pseudonymous device IDs in shared reports.
- [ ] Define retention and secure deletion dates before collection.
- [ ] Keep proprietary firmware/specifications out of the public repository
  unless redistribution rights are verified.
- [ ] Treat crash dumps and debug traces as potentially containing user data and
  secrets.
- [ ] Review every export bundle; automation can assist but cannot certify that a
  binary blob is legally shareable.

## Vulnerability and publication gate

- [ ] Confirm whether the observation creates security, safety, privacy, RF,
  reliability, or supply-chain risk.
- [ ] Preserve a minimal reproducer and evidence privately.
- [ ] Stop testing if further work would expose uninvolved users or systems.
- [ ] Identify vendor/coordinator contacts and follow a documented coordinated
  disclosure timeline appropriate to severity and active exploitation.
- [ ] Agree on handling of embargoed details, CVE/CERT coordination, credit, and
  affected-version information where practical.
- [ ] Do not release private keys, credentials, personal data, copyrighted
  firmware, export-controlled material, or turnkey abuse tooling.
- [ ] Publication must state scope, uncertainty, tested versions, mitigations,
  and reproducibility without implying all devices are affected.
- [ ] If the vendor is silent, risk to users and the public still governs the
  disclosure decision; obtain legal/security review rather than automatically
  publishing everything.

## Automatic stop conditions

Stop the run and preserve logs when any of these becomes true:

- authorization is absent, expired, disputed, or narrower than the discovered
  target/action;
- the target is a protected/critical, life-safety, in-motion, public-service,
  shared-tenant, or uninvolved third-party system;
- the probe begins collecting third-party communications, credentials, keys,
  biometrics, personal content, or data outside the approved plan;
- RF transmission lacks confirmed authorization or escapes the approved fixture;
- the operation would bypass a safety interlock or conceal activity from the
  lawful owner/operator;
- export, anti-circumvention, NDA, license, privacy, or disclosure obligations are
  unresolved;
- the observed blast radius exceeds the approved radius.
