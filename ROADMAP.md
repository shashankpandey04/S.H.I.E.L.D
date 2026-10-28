# S.H.I.E.L.D.
### AI Email Threat Detection & Forensic Intelligence

**Security & Header Inspection for Email, Logging & Diagnostics**

> Every email has a story. Uncover it.

S.H.I.E.L.D. is an AI-powered email threat detection and digital forensics platform designed to transform raw email (`.eml`) files into automated, explainable forensic investigations. Rather than operating as a binary phishing classifier, the platform implements an **Evidence-Centric Email Investigation (ECEI)** framework that combines rigorous email header forensics, cryptographic authentication analysis, multi-modal artificial intelligence, dynamic threat intelligence, and heterogeneous graph-based campaign correlation. Through uncertainty-aware evidence fusion, S.H.I.E.L.D. aims to calculate explainable threat scores, identify probable email origins, correlate related attack infrastructure, and generate provenance-backed investigative reports. Its central principle is simple: security conclusions must be supported by traceable evidence, reproducible analysis, and explicit uncertainty rather than opaque predictions.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Motivation](#motivation)
- [Proposed Solution](#proposed-solution)
- [Objectives](#objectives)
- [Target Users](#target-users)
- [Core Features](#core-features)
- [System Workflow](#system-workflow)
- [System Architecture](#system-architecture)
- [Detailed Modules](#detailed-modules)
- [Evidence-Centric Email Investigation](#evidence-centric-email-investigation-ecei)
- [Evidence Model](#evidence-model)
- [Email Header Forensics](#email-header-forensics)
- [AI Threat Detection](#ai-threat-detection)
- [IOC Extraction and Threat Intelligence](#ioc-extraction-and-threat-intelligence)
- [Relay and Origin Analysis](#relay-and-origin-analysis)
- [Evidence Graph and Campaign Correlation](#evidence-graph-and-campaign-correlation)
- [Evidence Fusion and Risk Scoring](#evidence-fusion-and-risk-scoring)
- [Explainability](#explainability)
- [Case Management](#case-management)
- [Chain of Custody](#chain-of-custody)
- [Forensic Report Generation](#forensic-report-generation)
- [Dashboard](#dashboard)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Configuration](#configuration)
- [API Overview](#api-overview)
- [Output and Reporting](#output-and-reporting)
- [Security and Privacy](#security-and-privacy)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Research Foundation](#research-foundation)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Email remains one of the most widely exploited attack vectors in cybersecurity. Phishing, business email compromise (BEC), impersonation, credential harvesting, malicious attachments, and infrastructure-based attacks continue to challenge conventional email security systems.

S.H.I.E.L.D. approaches email security as a digital investigation rather than a classification problem.

The platform decomposes an email into independently verifiable artifacts, including message headers, authentication results, routing hops, URLs, domains, IP addresses, attachments, cryptographic hashes, and semantic indicators. These artifacts become evidence objects that can be enriched with external intelligence, connected through a heterogeneous graph, and evaluated using uncertainty-aware evidence fusion.

Every investigative conclusion is designed to answer four questions:

1. **What was observed?** — The extracted technical or semantic evidence.
2. **Why does it matter?** — The security significance of that evidence.
3. **How confident is the conclusion?** — The strength, reliability, and uncertainty of the supporting evidence.
4. **Can the conclusion be reproduced?** — The provenance and audit history of the analysis.

The ultimate objective is to provide security analysts with actionable investigative context instead of an isolated malicious-or-benign prediction.

## Problem Statement

Contemporary email security systems frequently rely on binary classification models that attempt to determine whether a message is malicious or benign. While useful for large-scale filtering, this approach often provides insufficient context for forensic investigation and incident response.

Security analysts need to understand the technical evidence behind an alert, distinguish legitimate forwarding behavior from suspicious relay activity, evaluate authentication failures, identify related infrastructure, and investigate connections between apparently unrelated messages.

The growing use of large language models by threat actors also makes linguistic quality a less reliable indicator of malicious intent. Phishing messages can be grammatically correct, personalized, and contextually convincing while retaining suspicious technical or infrastructural characteristics.

Consequently, there is a need for an investigative platform that combines deterministic forensic analysis, authentication verification, artificial intelligence, threat intelligence, and graph-based correlation into a unified and auditable workflow.

S.H.I.E.L.D. addresses this need through an evidence-centric architecture in which model predictions contribute to the investigation but do not independently determine its final outcome.

## Motivation

An investigator needs actionable context, not merely a probability score.

When evaluating a suspicious email, security teams must understand:

- Whether the sender's identity can be authenticated.
- Whether SPF, DKIM, or DMARC verification succeeded.
- Whether message headers reveal suspicious routing or identity inconsistencies.
- Which URLs, domains, IP addresses, and attachments are associated with the message.
- Whether external threat intelligence identifies relevant indicators.
- Whether the message shares infrastructure or behavioral characteristics with other investigations.
- Which evidence supports the final threat assessment.
- How much uncertainty remains.
- Whether the investigation can be independently reproduced and audited.

S.H.I.E.L.D. aims to evolve email security from:

**"Is this email malicious?"**

to:

**"What evidence supports the conclusion, what infrastructure may be involved, how confident are we, and can the investigation be independently audited?"**

## Proposed Solution

S.H.I.E.L.D. implements the **Evidence-Centric Email Investigation (ECEI)** framework.

The framework decomposes an email into technical, semantic, and infrastructural artifacts. Each artifact is represented as an evidence object containing its value, source, timestamp, reliability, severity, provenance, and relationships to other evidence.

The platform then combines multiple analytical layers:

- Deterministic email parsing and header forensics.
- SPF, DKIM, DMARC, and ARC analysis.
- AI-assisted phishing, fraud, and impersonation detection.
- Indicator of Compromise (IOC) extraction.
- External IP, domain, DNS, and reputation enrichment.
- Relay reconstruction and probable-origin assessment.
- Heterogeneous evidence graphs and campaign correlation.
- Uncertainty-aware evidence fusion.
- Explainable risk scoring.
- Case management and forensic report generation.

The resulting investigation connects every major conclusion to the evidence that supports it.

The platform is designed to preserve the distinction between observed facts, externally reported claims, model-generated inferences, and analyst conclusions.

## Objectives

The primary objectives of S.H.I.E.L.D. are:

1. Automate the extraction and normalization of heterogeneous email artifacts.
2. Preserve the integrity of original evidence and maintain a reproducible analytical history.
3. Identify suspicious sender identities, header anomalies, routing inconsistencies, and authentication failures.
4. Evaluate AI-generated threat indicators alongside deterministic forensic evidence.
5. Extract and enrich IOCs using external intelligence sources.
6. Reconstruct probable email relay paths while accounting for forwarding and intermediary infrastructure.
7. Model relationships between emails, domains, IP addresses, URLs, attachments, and campaigns.
8. Identify potential connections between investigations through graph-based correlation.
9. Combine conflicting evidence using uncertainty-aware mathematical methods.
10. Produce explainable threat scores with explicit evidence references.
11. Generate structured investigation reports suitable for further analysis and incident response.
12. Support case management, auditability, and evidence provenance.

## Target Users

S.H.I.E.L.D. is intended for:

- **Security Operations Center (SOC) Analysts:** Investigating suspicious email alerts and prioritizing incidents.
- **Digital Forensics and Incident Response (DFIR) Investigators:** Examining email artifacts, reconstructing message paths, and documenting findings.
- **Cyber Threat Intelligence (CTI) Researchers:** Correlating indicators and investigating shared attack infrastructure.
- **Enterprise Email Security Administrators:** Reviewing authentication failures, spoofing attempts, and suspicious delivery patterns.
- **Cybersecurity Researchers and Students:** Experimenting with explainable threat detection, evidence fusion, and graph-based security analytics.

---

## Core Features

### Email Analysis

- Upload and parse `.eml` files.
- Extract standard email headers and metadata.
- Inspect plain-text and HTML message bodies.
- Extract attachment metadata and calculate cryptographic hashes.
- Preserve the original file's SHA-256 hash for integrity verification.

### Header and Authentication Forensics

- Analyze sender and recipient identities.
- Inspect `Received` headers and reconstruct relay sequences.
- Identify potential `From`, `Reply-To`, and envelope-sender inconsistencies.
- Inspect SPF, DKIM, DMARC, and ARC-related headers.
- Perform DNS lookups for published authentication policies and DKIM public keys.
- Distinguish reported authentication results from independently verified results.

### AI-Assisted Threat Detection

- Analyze suspicious language, urgency, and impersonation patterns.
- Detect potential business email compromise and credential harvesting.
- Evaluate structural anomalies and cross-field inconsistencies.
- Treat model predictions as evidence rather than unquestionable verdicts.

### IOC Extraction and Enrichment

- Extract IP addresses, domains, URLs, and cryptographic hashes.
- Enrich indicators using configured external intelligence providers.
- Record source reliability and observation timestamps.
- Preserve enrichment provenance.

### Evidence Correlation

- Represent extracted artifacts and analytical results as evidence objects.
- Construct relationships between emails and their associated indicators.
- Identify potential shared infrastructure across investigations.
- Group related evidence into candidate campaign clusters.

### Explainable Threat Assessment

- Generate an evidence-backed threat score.
- Track confidence separately from threat severity.
- Preserve uncertainty and conflicting evidence.
- Link investigative conclusions to individual evidence IDs.

### Forensic Reporting

- Export structured JSON reports.
- Generate human-readable investigation summaries.
- Support PDF report generation.
- Provide a foundation for STIX 2.1 threat intelligence exports.

### Case Management

- Organize investigations into unique cases.
- Maintain evidence inventories and audit histories.
- Support investigation status tracking.
- Enable pivots between related indicators and cases.

---

## System Workflow

The proposed end-to-end workflow is:

```text
                EMAIL INGESTION
                       |
                       v
               Parse Raw EML
                       |
                       v
             Extract Email Artifacts
                       |
          +------------+------------+
          |            |            |
          v            v            v
      Headers        Content     Attachments
          |            |            |
          v            v            v
    Header Analysis  AI Analysis  Hashing
          |            |            |
          +------------+------------+
                       |
                       v
              Extract IOCs
                       |
                       v
             Threat Intelligence
                  Enrichment
                       |
                       v
          SPF / DKIM / DMARC / ARC
                  Evaluation
                       |
                       v
             Relay Reconstruction
                       |
                       v
              Build Evidence Graph
                       |
                       v
             Campaign Correlation
                       |
                       v
              Evidence Fusion
                       |
                       v
             Uncertainty-Aware
                Risk Scoring
                       |
                       v
             Explainable Findings
                       |
                       v
             Investigation Case
                       |
                       v
             Forensic Report
              JSON / PDF / STIX
```

The platform follows the principle:

**Email → Evidence → Inference → Forensic Reasoning → Explainable Conclusion**

---

## System Architecture

S.H.I.E.L.D. uses a modular architecture that separates ingestion, forensic processing, intelligence enrichment, machine learning, evidence persistence, and presentation.

### Frontend Layer

The frontend provides an investigation dashboard through which analysts can upload emails, inspect extracted evidence, review authentication results, visualize relationships, and export reports.

**Technologies:**

- Next.js
- React
- TypeScript
- Tailwind CSS
- Interactive graph visualization libraries

### API and Processing Layer

The backend manages email ingestion, processing workflows, analysis orchestration, and report generation.

**Technologies:**

- Python
- FastAPI
- Python standard-library email package
- `dnspython`
- `dkimpy`

### AI and Graph Intelligence Layer

This layer evaluates semantic and structural indicators, models relationships between artifacts, and supports campaign correlation.

**Technologies:**

- PyTorch
- PyTorch Geometric
- Hugging Face Transformers
- scikit-learn
- DistilBERT or RoBERTa-based models

### Persistence Layer

The persistence layer stores cases, evidence objects, indicators, audit events, and investigation relationships.

**Technologies:**

- PostgreSQL
- Neo4j or an alternative graph storage solution
- Object storage for retained evidence, where configured

### Forensic Integrity Layer

The forensic integrity layer supports evidence hashing, provenance tracking, versioned analysis records, and reproducible reports.

**Technologies:**

- SHA-256
- Append-only audit records
- Explicit parser and model versions
- Controlled evidence storage

---

## Detailed Modules

### 1. Email Upload and Parsing

This module accepts raw `.eml` files and extracts the information required for downstream analysis.

Artifacts include:

- Message headers.
- Sender and recipient information.
- Subject and message identifiers.
- Plain-text and HTML bodies.
- MIME structure.
- Attachment metadata.
- Embedded URLs.
- Original-file hash.

The parser should preserve the original artifact and avoid silently modifying the evidence being analyzed.

### 2. Email Header Forensics

This module examines message metadata and routing information.

It evaluates:

- `From`, `Sender`, `Reply-To`, and `Return-Path` relationships.
- `Received` header sequences.
- Suspicious or inconsistent header values.
- Authentication-related headers.
- Potential spoofing indicators.
- Message identifiers and timestamps.
- ARC-related authentication information.

Header anomalies should be treated as indicators requiring context rather than definitive proof of malicious activity.

### 3. AI Phishing and Fraud Detection

The AI module analyzes semantic and structural characteristics associated with suspicious emails.

Potential detection targets include:

- Credential harvesting.
- Business email compromise.
- Financial fraud.
- Executive impersonation.
- Urgency and social engineering.
- Suspicious requests for payment or sensitive information.
- Contextual inconsistencies between sender identity, message content, and linked resources.

Transformer-based models such as DistilBERT or RoBERTa can provide semantic features and classification signals.

The system must not assume that polished language implies legitimacy or that unusual language independently establishes malicious intent.

### 4. IOC Extraction and Analysis

The IOC module extracts potentially relevant indicators from email content and metadata.

Supported indicator types include:

- IPv4 and IPv6 addresses.
- Domains and subdomains.
- URLs.
- Attachment hashes.
- Embedded file hashes, where extracted safely.
- Email addresses associated with suspicious activity.

Each indicator should be normalized, assigned an evidence ID, and associated with its extraction source.

### 5. IP and Domain Intelligence

This module enriches extracted indicators with external information.

Potential enrichment sources include:

- DNS records.
- IP geolocation.
- Autonomous System Number (ASN) information.
- WHOIS and RDAP registration data.
- Domain age and registration metadata, where available.
- Certificate transparency data.
- Configured threat intelligence feeds.
- Historical reputation sources.

External data must be recorded with its source, retrieval timestamp, and reliability assessment.

Geolocation and registration data are contextual clues, not proof of an attacker's identity or physical location.

### 6. Email Origin and Relay Tracing

This module reconstructs the probable path taken by an email using its routing headers.

It analyzes:

- `Received` header ordering.
- Timestamps and timezone differences.
- Relay hostnames and IP addresses.
- Authentication results associated with individual hops.
- Forwarding and mailing-list behavior.
- ARC headers, when present and validatable.

The output identifies probable origin candidates and their supporting evidence.

The system must distinguish the earliest observed relay from the actual originating client. A `Received` chain may be incomplete, manipulated, or contain infrastructure that cannot be independently verified.

### 7. Threat Intelligence Correlation

This module compares extracted indicators against external threat intelligence sources.

Each match becomes a separate evidence object containing:

- The indicator.
- The source of the assertion.
- The reported classification.
- The retrieval timestamp.
- The source's configured reliability.
- Supporting metadata.
- The associated confidence and severity.

Threat intelligence is treated as contextual evidence rather than an unquestionable source of truth.

### 8. Graph-Based Investigation

This module models the relationships between emails and their associated artifacts.

A heterogeneous graph allows different node types and relationship types to be represented explicitly.

Potential node types include:

- `Email`
- `Sender`
- `Recipient`
- `Domain`
- `IP`
- `URL`
- `Attachment`
- `Relay_Hop`
- `ASN`
- `Campaign`
- `Evidence`
- `Threat_Intelligence_Source`

Potential relationships include:

- Email contains URL.
- Email contains attachment.
- Email was relayed by IP.
- IP resolves to domain.
- Domain hosts URL.
- Email shares an indicator with another email.
- Email belongs to a candidate campaign.
- Threat intelligence source reports an indicator.
- Evidence supports an investigative conclusion.

PyTorch Geometric's `HeteroData` can represent these heterogeneous relationships for graph-based machine learning.

Graph construction and campaign clustering must account for shared infrastructure that may be legitimate, including cloud hosting, content delivery networks, and public email providers.

### 9. Risk Scoring and Explainability

The risk assessment module combines evidence from multiple analytical sources.

Potential inputs include:

- SPF, DKIM, and DMARC outcomes.
- Header anomalies.
- Relay inconsistencies.
- AI-generated threat signals.
- IOC reputation.
- Attachment indicators.
- Campaign relationships.
- Evidence reliability.
- Uncertainty associated with incomplete or conflicting information.

The system produces a threat score alongside a separate confidence or uncertainty measure.

The score must be traceable to its contributing evidence and should not be presented as a calibrated probability unless it has been appropriately validated.

### 10. Investigation Dashboard

The dashboard provides a unified interface for reviewing investigation results.

It displays:

- Threat severity.
- Confidence and uncertainty.
- SPF, DKIM, and DMARC results.
- Sender and recipient information.
- Routing timelines.
- Extracted IOCs.
- Attachment information.
- Evidence inventories.
- Graph-based relationships.
- Campaign associations.
- Explainable findings.
- Investigation history.

### 11. Forensic Report Generation

This module produces structured investigation reports.

Reports may include:

- Executive summary.
- Original file hash.
- Email metadata.
- Header analysis.
- Authentication evaluation.
- IOC inventory.
- Threat intelligence findings.
- Relay and origin assessments.
- Graph correlation results.
- Threat score and uncertainty.
- Evidence references.
- Processing history.
- Limitations and unresolved questions.

Supported export formats are planned to include JSON, PDF, and STIX 2.1 bundles.

### 12. Case Management and Evidence

This module organizes investigations into persistent case records.

Each case can contain:

- Original email artifacts.
- Evidence objects.
- Extracted indicators.
- Analysis results.
- Threat intelligence observations.
- Evidence graphs.
- Reports.
- Audit records.
- Case status and investigator annotations.

Case management enables analysts to pivot between investigations using shared indicators while retaining the provenance of each observation.

---

## Evidence-Centric Email Investigation (ECEI)

ECEI is the central investigative principle behind S.H.I.E.L.D.

Traditional classification systems often follow this model:

```text
Email → Prediction → Verdict
```

ECEI follows a more transparent model:

```text
Email
  |
  v
Evidence Extraction
  |
  v
Evidence Validation
  |
  v
Contextual Enrichment
  |
  v
Relationship Analysis
  |
  v
Evidence Fusion
  |
  v
Forensic Reasoning
  |
  v
Explainable Conclusion
```

The framework requires that investigative conclusions be traceable to supporting artifacts, analytical operations, or external observations.

For example, an AI model may identify a message as suspicious. Instead of accepting that prediction as the final verdict, S.H.I.E.L.D. evaluates it alongside sender inconsistencies, authentication results, URL reputation, routing evidence, and related campaign indicators.

Conflicting observations remain visible rather than being silently discarded.

The system also distinguishes between:

- **Observed evidence:** Directly extracted from an artifact or data source.
- **Derived evidence:** Produced by deterministic analysis or a documented transformation.
- **Model inference:** Generated by an AI or statistical model.
- **External assertion:** Reported by a third-party intelligence source.
- **Analyst conclusion:** A reasoned interpretation supported by the available evidence.

This distinction is essential for reproducibility and meaningful forensic review.

## Evidence Model

Every extracted artifact or analytical output is represented as an evidence object.

A proposed evidence object contains:

| Field | Description |
|---|---|
| `evidence_id` | Unique evidence identifier |
| `case_id` | Associated investigation case |
| `evidence_type` | Type of evidence |
| `evidence_value` | Extracted or derived value |
| `source` | Parser, model, analyst, or external source |
| `observed_at` | Time the evidence was observed |
| `reliability` | Assessment of the source's reliability |
| `severity` | Security significance of the observation |
| `provenance` | Record of how the evidence was produced |
| `relationships` | Links to related evidence IDs |
| `confidence` | Confidence associated with the assessment, where applicable |
| `limitations` | Known limitations or qualifications |

A conceptual example:

```json
{
  "evidence_id": "EVIDENCE-001",
  "case_id": "CASE-0001",
  "evidence_type": "email_authentication",
  "evidence_value": {
    "mechanism": "spf",
    "reported_result": "fail"
  },
  "source": "authentication_analysis",
  "observed_at": "2026-10-28T10:30:00Z",
  "reliability": 0.95,
  "severity": "medium",
  "provenance": {
    "artifact": "original-email.eml",
    "operation": "authentication_header_analysis"
  },
  "relationships": [],
  "limitations": [
    "Reported result has not been independently reproduced"
  ]
}
```

The example is illustrative. Reliability and severity values must be supported by a documented scoring policy rather than assigned arbitrarily.

## Email Header Forensics

Email authentication is an important component of the investigative process.

### SPF — Sender Policy Framework

SPF evaluates whether a sending IP address is authorized by the relevant domain's published policy.

S.H.I.E.L.D. aims to distinguish between:

- An SPF result reported by a receiving server.
- The existence and validity of the published SPF record.
- An independently reproduced SPF evaluation, where sufficient information is available.

A DNS record lookup alone does not establish that a specific message passed SPF.

### DKIM — DomainKeys Identified Mail

DKIM uses a cryptographic signature to associate selected message content with a signing domain.

The system aims to inspect:

- `DKIM-Signature` headers.
- Signing domains.
- Selectors.
- Published public-key records.
- Reported verification outcomes.
- Cryptographic signature validity, where implemented.

Finding a public key in DNS does not prove that the message's signature is valid. Independent verification requires the message data and correct canonicalization and signature-validation logic.

### DMARC — Domain-based Message Authentication, Reporting, and Conformance

DMARC evaluates whether SPF or DKIM authentication aligns with the domain visible in the message's `From` header and applies the domain's published policy.

S.H.I.E.L.D. aims to report:

- Published DMARC policy.
- Reported DMARC result.
- SPF and DKIM alignment.
- Relevant organizational or subdomain policy.
- Potential policy and identity inconsistencies.

The existence of a DMARC record does not prove that a particular email passed DMARC.

### ARC — Authenticated Received Chain

ARC preserves authentication-related information across forwarding and intermediary delivery systems.

S.H.I.E.L.D. aims to inspect ARC headers and validate ARC chains where supported.

ARC results must be interpreted in context. A valid ARC chain provides evidence about intermediary assertions; it does not automatically establish that the original message is trustworthy.

---

## AI Threat Detection

S.H.I.E.L.D. uses AI as one component of a broader investigative framework.

### Proposed Models

Potential model families include:

- DistilBERT for efficient transformer-based text classification.
- RoBERTa for contextual semantic analysis.
- scikit-learn models for structured feature classification.
- Custom neural models for combining heterogeneous forensic features.

### Analytical Signals

The AI layer may examine:

- Suspicious requests and calls to action.
- Credential-harvesting language.
- Executive or vendor impersonation.
- Financial fraud patterns.
- Contextual inconsistencies.
- Relationships between message text and extracted URLs.
- Structural anomalies across sender, recipient, and message metadata.

### Explainability Requirements

AI outputs should include:

- Model identifier and version.
- Prediction or score.
- Relevant model confidence information.
- Input provenance.
- Known model limitations.
- Supporting evidence references.

Model confidence must not be confused with the probability that an email is malicious.

The platform should also be evaluated against AI-generated phishing messages, legitimate business emails, multilingual content, and distribution shifts.

---

## IOC Extraction and Threat Intelligence

An Indicator of Compromise is an artifact that may be associated with malicious activity.

S.H.I.E.L.D. extracts and correlates indicators including IP addresses, domains, URLs, and cryptographic hashes.

### Enrichment Workflow

```text
Extract Indicator
       |
       v
Normalize Value
       |
       v
Record Evidence ID
       |
       v
Query Configured Intelligence Sources
       |
       v
Record Source and Timestamp
       |
       v
Evaluate Reliability
       |
       v
Correlate with Existing Evidence
```

### Reliability-Aware Intelligence

A threat intelligence match is recorded as an assertion with its own provenance.

For example, if an intelligence source identifies a domain as malicious, S.H.I.E.L.D. records the source, timestamp, indicator, and reported classification.

The platform does not automatically treat every external match as definitive proof.

Enrichment providers may include public or commercial reputation services, DNS sources, RDAP services, and configured threat intelligence feeds.

External requests must follow provider terms, privacy requirements, and rate limits.

---

## Relay and Origin Analysis

Email relay analysis reconstructs the probable path of a message using routing headers and associated metadata.

The system parses `Received` headers and evaluates their chronological relationships, recording inconsistencies and potential origin candidates.

### Analytical Considerations

- The trustworthiness of each observed relay.
- Timestamp consistency.
- IP address and hostname relationships.
- Internal versus external infrastructure.
- Forwarding and mailing-list behavior.
- Authentication results at different hops.
- ARC validation outcomes.
- Missing or potentially manipulated routing information.

### Origin Estimation

S.H.I.E.L.D. aims to estimate probable origin candidates with explicit confidence and supporting evidence.

It does not assume that the earliest visible IP address is necessarily the original sender's IP address.

Origin estimates are investigative hypotheses, not definitive attribution of an attack to a person or organization.

---

## Evidence Graph and Campaign Correlation

S.H.I.E.L.D. represents relationships between forensic artifacts using a heterogeneous evidence graph.

### Graph Nodes

| Node Type | Purpose |
|---|---|
| Email | Represents an analyzed message |
| Sender | Represents a sender identity |
| Recipient | Represents a recipient identity |
| Domain | Represents a domain or subdomain |
| IP | Represents an IP address |
| URL | Represents an extracted URL |
| Attachment | Represents an attachment artifact |
| Relay Hop | Represents an observed mail relay |
| ASN | Represents an autonomous system |
| Campaign | Represents a candidate related attack cluster |
| Evidence | Represents an individual observation or inference |
| Intelligence Source | Represents a source of external threat information |

### Graph Relationships

Examples include:

```text
Email ──contains──────────> URL
Email ──contains──────────> Attachment
Email ──relayed_by────────> IP
IP ────associated_with───> ASN
Domain ──resolves_to──────> IP
URL ────uses──────────────> Domain
Email ──supported_by──────> Evidence
Evidence ──reported_by────> Intelligence Source
Email ──candidate_member──> Campaign
```

The exact direction and meaning of each relationship must be defined consistently in the graph schema.

### Graph Learning

PyTorch Geometric's `HeteroData` can represent node types and edge types explicitly.

Potential future approaches include:

- Heterogeneous graph neural networks.
- Temporal graph analysis.
- Graph embeddings.
- Similarity-based candidate clustering.
- Subgraph comparison.
- Infrastructure relationship analysis.

### Campaign Correlation

Potential campaign signals include:

- Repeated malicious URLs.
- Shared attachment hashes.
- Reused sender infrastructure.
- Overlapping relay IP addresses.
- Similar domain registration patterns.
- Related message templates.
- Temporal proximity.
- Similar semantic embeddings.

A shared indicator alone is insufficient to prove that messages belong to the same campaign. Correlation results should be presented as candidate relationships with supporting evidence.

---

## Evidence Fusion and Risk Scoring

S.H.I.E.L.D. proposes using **Subjective Logic** to combine heterogeneous evidence while explicitly representing uncertainty.

This is intended to address a key limitation of simplistic scoring systems: conflicting or incomplete evidence should not automatically produce false certainty.

### Subjective Logic Representation

A binomial opinion can be represented as:

\[
\omega = (b, d, u, a)
\]

where:

- \(b\) is the belief mass.
- \(d\) is the disbelief mass.
- \(u\) is the epistemic uncertainty.
- \(a\) is the base rate or prior probability.

The opinion satisfies:

\[
b + d + u = 1
\]

The projected probability is:

\[
P = b + a \cdot u
\]

Here, \(P\) is the projected probability of the proposition under the opinion model. It should not automatically be interpreted as a calibrated probability that the email is malicious.

### Evidence Sources

Potential inputs include:

- SPF, DKIM, and DMARC evaluation.
- Header inconsistencies.
- Suspicious routing evidence.
- AI-generated phishing indicators.
- IOC reputation.
- Attachment analysis.
- Threat intelligence assertions.
- Campaign correlation.
- Historical reliability of evidence sources.

### Fusion Requirements

The implementation must define:

1. How raw observations are converted into opinions.
2. How source reliability is estimated.
3. How dependent or duplicated evidence is identified.
4. Which fusion operators are appropriate for each evidence relationship.
5. How conflicting evidence is handled.
6. How uncertainty propagates through the investigation.
7. How the resulting scores are calibrated and evaluated.

Correlated evidence must not be treated as independent merely because it originates from separate modules.

For example, an AI prediction and a rule-based detector may both respond to the same suspicious URL. Counting them as fully independent signals could artificially inflate the final score.

### Threat Score and Confidence

The proposed dashboard separates:

- **Threat score:** The assessed severity of the email's potential maliciousness.
- **Confidence:** The strength of the available evidence supporting the assessment.
- **Uncertainty:** The degree to which the conclusion remains unresolved.

The final score should be generated through a documented and validated scoring pipeline rather than an arbitrary sum of indicators.

---

## Explainability

S.H.I.E.L.D. prioritizes evidence-backed explanations over unexplained model predictions.

Every major investigative conclusion should reference the evidence that supports it.

Example:

```text
Assessment: HIGH RISK
Threat Score: 91/100
Confidence: 0.84

Supporting Evidence:

EVIDENCE-001
Reported SPF result: FAIL
Source: Authentication-Results header

EVIDENCE-014
Reply-To domain differs from the visible sender domain
Source: Header consistency analysis

EVIDENCE-032
Message shares infrastructure with a candidate suspicious cluster
Source: Evidence graph correlation

Limitations:

- SPF failure has not been independently reproduced.
- Shared infrastructure does not independently prove campaign membership.
- Origin attribution remains inconclusive.
```

The values and evidence IDs above are illustrative.

The explanation system should distinguish between direct observations, reported results, derived indicators, and analytical hypotheses.

It should also explain material counterevidence and unresolved uncertainty instead of displaying only evidence supporting the highest-risk conclusion.

---

## Case Management

Each investigation is represented as a distinct case.

A case may contain:

- Original `.eml` file metadata.
- Original-file SHA-256 hash.
- Extracted email artifacts.
- Evidence objects.
- Authentication results.
- AI inference records.
- IOC enrichment records.
- Graph relationships.
- Threat assessments.
- Reports.
- Analyst notes.
- Audit events.

### Proposed Case Lifecycle

```text
NEW
 |
 v
INGESTED
 |
 v
ANALYZING
 |
 v
UNDER_REVIEW
 |
 +-------> ESCALATED
 |
 +-------> RESOLVED
 |
 v
ARCHIVED
```

Case status transitions should be validated and recorded.

Future collaboration features may support investigator assignments, analyst annotations, shared evidence, and cross-case indicator searches.

---

## Chain of Custody

S.H.I.E.L.D. is designed to support forensic evidence integrity through hashing, provenance tracking, and audit logging.

Upon ingestion, the system calculates a SHA-256 hash of the original `.eml` file.

The original hash can later be recalculated to check whether the retained artifact has changed.

### Proposed Integrity Workflow

```text
Receive Original EML
        |
        v
Calculate SHA-256
        |
        v
Record Ingestion Metadata
        |
        v
Preserve Original Artifact
        |
        v
Execute Versioned Analysis
        |
        v
Record Processing Events
        |
        v
Link Findings to Evidence IDs
        |
        v
Generate Reproducible Report
```

### Audit Records

Audit events should record:

- Event identifier.
- Case identifier.
- Timestamp.
- Operation performed.
- Input artifact hashes.
- Parser and analysis versions.
- Model identifiers and versions.
- External data sources consulted.
- Evidence IDs created or updated.
- Output artifact hashes.
- Processing status and errors.

An append-only audit log, appropriate access controls, and protected storage are necessary to reduce the risk of undetected modification.

**Important:** A SHA-256 hash alone does not establish a complete chain of custody or prove when an artifact was originally obtained. Reliable forensic handling also requires controlled acquisition, documented custody transfers, access controls, and preservation of the original evidence.

The platform's controls should be evaluated against applicable forensic practices, including ISO/IEC 27037. Conformance must not be claimed until it has been independently assessed.

---

## Forensic Report Generation

S.H.I.E.L.D. aims to generate comprehensive reports for investigators and incident response teams.

### Report Contents

1. Investigation identification and metadata.
2. Executive summary.
3. Original email file hash.
4. Sender and recipient information.
5. Header and routing analysis.
6. SPF, DKIM, DMARC, and ARC findings.
7. Extracted IOC inventory.
8. External threat intelligence observations.
9. Attachment metadata and hashes.
10. AI analysis results.
11. Evidence graph relationships.
12. Campaign correlation findings.
13. Threat score and uncertainty.
14. Evidence-backed explanations.
15. Counterevidence and unresolved questions.
16. Analysis provenance and audit history.
17. Limitations and recommended follow-up actions.

### Export Formats

**JSON**

Machine-readable representation of the investigation, evidence objects, analytical results, and provenance.

**PDF**

Human-readable report suitable for review, case documentation, and incident response workflows.

**STIX 2.1**

Structured threat intelligence export for supported indicators and relationships.

STIX exports should use the standard's object types and relationship semantics. Internal evidence objects and confidence values must be mapped carefully rather than exported as if every internal field had a direct STIX equivalent.

---

## Dashboard

The S.H.I.E.L.D. dashboard is the primary interface for reviewing investigative results.

### Proposed Dashboard Sections

**Overview**

- Threat score.
- Confidence and uncertainty.
- Investigation status.
- Key findings.
- Processing summary.

**Email Intelligence**

- Sender and recipient metadata.
- Subject and message identifiers.
- Message body inspection.
- Attachment inventory.

**Authentication**

- SPF status.
- DKIM status.
- DMARC status.
- ARC status, where supported.
- Reported results versus independent verification.

**Routing Analysis**

- Chronological relay timeline.
- Observed IP addresses and hostnames.
- Suspicious routing observations.
- Probable origin candidates.

**IOC Intelligence**

- Extracted URLs.
- Domains and IP addresses.
- Cryptographic hashes.
- Enrichment results.
- Source reliability.

**Evidence Graph**

- Interactive nodes and relationships.
- Related messages.
- Shared indicators.
- Candidate campaign clusters.

**Forensic Findings**

- Evidence-backed explanations.
- Conflicting observations.
- Uncertainty indicators.
- Suggested follow-up investigations.

**Reports and Cases**

- Downloadable reports.
- Evidence inventory.
- Case history.
- Audit events.

The interface should make uncertainty and provenance visible without overwhelming investigators with raw technical data.

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Frontend | Next.js | Web application and dashboard |
| UI Framework | React | Interactive user interface |
| Frontend Language | TypeScript | Type-safe frontend development |
| Styling | Tailwind CSS | Responsive interface styling |
| Backend | Python | Email processing and analysis |
| API Framework | FastAPI | Backend API and workflow orchestration |
| Email Parsing | Python `email` package | MIME and header parsing |
| DNS Analysis | `dnspython` | DNS record queries |
| DKIM Verification | `dkimpy` | DKIM signature verification |
| Machine Learning | PyTorch | Model development and inference |
| Graph Machine Learning | PyTorch Geometric | Heterogeneous graph processing |
| NLP | Hugging Face Transformers | Transformer-based text analysis |
| Traditional ML | scikit-learn | Classification and feature processing |
| Relational Database | PostgreSQL | Cases, evidence, and audit metadata |
| Graph Database | Neo4j | Graph persistence and traversal |
| Integrity | SHA-256 | Evidence integrity checks |
| Report Generation | JSON, PDF libraries | Structured and human-readable exports |
| Threat Intelligence | Configurable providers | IOC enrichment and correlation |

The stack is modular. Individual technologies may be introduced incrementally as the corresponding features are implemented.

---

## Project Structure

The proposed repository structure is:

```text
S.H.I.E.L.D/
│
├── frontend/
│   ├── app/
│   │   ├── dashboard/
│   │   ├── investigations/
│   │   ├── api/
│   │   ├── layout.tsx
│   │   └── page.tsx
│   │
│   ├── components/
│   │   ├── dashboard/
│   │   ├── email/
│   │   ├── evidence/
│   │   ├── graph/
│   │   ├── reports/
│   │   └── ui/
│   │
│   ├── lib/
│   ├── types/
│   ├── public/
│   ├── package.json
│   └── tsconfig.json
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── forensic/
│   │   ├── authentication/
│   │   ├── intelligence/
│   │   ├── ai/
│   │   ├── graph/
│   │   ├── scoring/
│   │   ├── cases/
│   │   ├── reports/
│   │   └── main.py
│   │
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
│
├── docs/
│   ├── architecture.md
│   ├── evidence-model.md
│   ├── threat-scoring.md
│   └── api.md
│
├── samples/
├── .gitignore
├── LICENSE
└── README.md
```

This structure describes the intended architecture. Modules should be added as implementation progresses rather than treating every listed directory as an already completed feature.

---

## Installation and Setup

S.H.I.E.L.D. is designed to use a Next.js frontend and a Python FastAPI backend.

### Prerequisites

Install the following:

- Node.js and npm.
- Python 3.11 or a compatible supported version.
- Git.
- A virtual environment tool.
- PostgreSQL when persistent case storage is enabled.
- Neo4j when graph database persistence is enabled.

Machine-learning dependencies may require additional configuration depending on the operating system, available hardware, and selected PyTorch build.

### Clone the Repository

```bash
git clone <repository-url>
cd S.H.I.E.L.D.
```

Replace `<repository-url>` with the actual repository URL.

### Backend Setup

```bash
cd backend

python -m venv .venv
```

Activate the virtual environment.

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux or macOS:

```bash
source .venv/bin/activate
```

Install the backend dependencies:

```bash
pip install -r requirements.txt
```

Start the development server:

```bash
uvicorn app.main:app --reload --port 8000
```

When configured, the FastAPI API documentation is available at:

```text
http://localhost:8000/docs
```

### Frontend Setup

Open a second terminal:

```bash
cd frontend
npm install
```

Create a `.env.local` file containing the backend API base URL:

```env
BACKEND_API_URL=http://localhost:8000
```

Start the Next.js development server:

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

The exact commands and environment variables may change as the application is implemented.

---

## Configuration

S.H.I.E.L.D. may require environment variables for backend configuration, database connections, external intelligence providers, and model selection.

Example configuration:

```env
APP_ENV=development
LOG_LEVEL=INFO

DATABASE_URL=postgresql://user:password@localhost:5432/shield

NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=change-me

THREAT_INTELLIGENCE_API_KEY=

MODEL_NAME=
MODEL_VERSION=

BACKEND_API_URL=http://localhost:8000
```

This is an illustrative configuration template. Variables must be implemented and validated by the relevant application modules before they can be used.

Never commit real credentials, API keys, database passwords, or production secrets to version control.

---

## API Overview

The backend is intended to expose REST endpoints for email analysis, case management, evidence retrieval, and report generation.

Proposed endpoints include:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Check backend availability |
| `POST` | `/api/v1/emails/analyze` | Upload and analyze an email |
| `GET` | `/api/v1/cases` | Retrieve investigation cases |
| `POST` | `/api/v1/cases` | Create an investigation case |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve case details |
| `GET` | `/api/v1/cases/{case_id}/evidence` | Retrieve case evidence |
| `GET` | `/api/v1/cases/{case_id}/graph` | Retrieve evidence graph data |
| `GET` | `/api/v1/cases/{case_id}/report` | Retrieve a structured report |
| `GET` | `/api/v1/cases/{case_id}/report.pdf` | Export a PDF report |

These are proposed API contracts, not a claim that every endpoint is currently implemented.

The analysis endpoint should validate file type and size, preserve the original artifact as configured, calculate its hash, and return a case identifier and processing status.

For potentially expensive AI inference and graph analysis, asynchronous processing with a job identifier may be preferable to holding an HTTP request open until the entire investigation finishes.

---

## Output and Reporting

The principal machine-readable output is a structured JSON investigation report.

A conceptual report structure is:

```json
{
  "case": {
    "case_id": "CASE-0001",
    "status": "completed",
    "created_at": "2026-10-28T10:30:00Z"
  },
  "artifact": {
    "filename": "sample.eml",
    "sha256": "<sha256-hash>"
  },
  "email": {
    "from": "sender@example.com",
    "to": [
      "recipient@example.com"
    ],
    "subject": "Example message"
  },
  "authentication": {
    "spf": {
      "reported_result": "pass",
      "independently_verified": false
    },
    "dkim": {
      "reported_result": "pass",
      "signature_verified": false
    },
    "dmarc": {
      "reported_result": "pass",
      "alignment_verified": false
    }
  },
  "assessment": {
    "threat_score": null,
    "confidence": null,
    "uncertainty": null,
    "status": "not_assessed"
  },
  "evidence": [],
  "indicators": [],
  "relationships": [],
  "findings": [],
  "limitations": [],
  "audit_log": []
}
```

This schema is illustrative. Actual authentication outcomes, threat scores, and verification flags must be populated only after the corresponding analysis has been performed.

A missing result must not be silently converted into a pass or fail.

---

## Security and Privacy

Because S.H.I.E.L.D. processes potentially sensitive communications, security and privacy are core design requirements.

### File Upload Security

- Restrict uploads to supported email formats.
- Enforce upload size limits.
- Validate file content rather than relying solely on filenames.
- Process untrusted MIME structures defensively.
- Sanitize filenames before saving attachments.
- Prevent path traversal and arbitrary file writes.
- Avoid automatically opening or executing attachments.
- Isolate risky file-processing operations where appropriate.

### Network Security

- Apply timeouts and response-size limits to external requests.
- Restrict backend network access where feasible.
- Prevent user-controlled URLs from triggering unrestricted server-side requests.
- Protect against DNS rebinding and server-side request forgery.
- Avoid fetching embedded URLs automatically unless a controlled analysis service is explicitly configured.
- Rate-limit externally accessible analysis endpoints.

### Evidence Integrity

- Calculate SHA-256 hashes for original artifacts.
- Keep originals separate from derived outputs.
- Record processing versions and timestamps.
- Preserve audit history.
- Restrict unauthorized evidence modification.
- Document custody and retention operations.

### Privacy

- Minimize unnecessary storage of email bodies and personal information.
- Avoid sending sensitive email content to external AI services without explicit authorization.
- Document which third-party providers receive extracted indicators or message content.
- Apply retention and deletion policies.
- Restrict access to cases and reports.
- Protect credentials and API keys.

### Operational Safety

S.H.I.E.L.D. is intended for defensive email analysis and authorized security investigations. Its results should assist qualified investigators rather than replace human review.

---

## Limitations

S.H.I.E.L.D. is designed to support forensic investigations, but several limitations must be acknowledged.

- Email headers may be incomplete or manipulated.
- Authentication results reported in headers may be untrusted.
- DNS records can change over time.
- Historical DNS and reputation data may be unavailable.
- Forwarding and mailing-list systems complicate authentication analysis.
- AI models may generate false positives and false negatives.
- External threat intelligence can contain outdated or incorrect assertions.
- Shared infrastructure does not necessarily imply shared malicious intent.
- Graph relationships may reflect coincidental similarities.
- Origin estimation cannot reliably identify a human attacker from email metadata alone.
- Subjective Logic does not eliminate the need for validated evidence models and careful treatment of dependence.
- Hashing alone does not establish a complete forensic chain of custody.

The platform should report these limitations explicitly and preserve uncertainty when evidence is insufficient.

---

## Roadmap

The project is planned to evolve incrementally.

### Phase 1 — Core Email Forensics

- [ ] `.eml` upload and parsing.
- [ ] Header and MIME extraction.
- [ ] Attachment metadata extraction.
- [ ] Original-file SHA-256 hashing.
- [ ] Received-chain inspection.
- [ ] SPF, DKIM, and DMARC DNS checks.
- [ ] Authentication results extracted from headers.
- [ ] JSON report generation.

### Phase 2 — Web Application

- [ ] Next.js and TypeScript dashboard.
- [ ] Drag-and-drop email upload.
- [ ] Analysis status and error handling.
- [ ] Email metadata viewer.
- [ ] Authentication results dashboard.
- [ ] Routing timeline.
- [ ] Evidence inventory.
- [ ] JSON report download.

### Phase 3 — Advanced Authentication

- [ ] Independent SPF evaluation.
- [ ] Cryptographic DKIM signature verification.
- [ ] DMARC alignment evaluation.
- [ ] ARC chain validation.
- [ ] Forwarding-aware authentication analysis.
- [ ] Authentication test fixtures and regression tests.

### Phase 4 — IOC Intelligence

- [ ] URL and domain extraction.
- [ ] IP address extraction and normalization.
- [ ] Attachment hash inventory.
- [ ] DNS and RDAP enrichment.
- [ ] Configurable threat intelligence providers.
- [ ] Source reliability tracking.
- [ ] IOC provenance.

### Phase 5 — AI Threat Detection

- [ ] Baseline phishing classifier.
- [ ] Transformer-based semantic analysis.
- [ ] BEC and impersonation detection.
- [ ] Structural anomaly analysis.
- [ ] Evaluation dataset and metrics.
- [ ] False-positive analysis.
- [ ] Model versioning and inference provenance.

### Phase 6 — Evidence and Risk Fusion

- [ ] Formal evidence object schema.
- [ ] Evidence dependency tracking.
- [ ] Subjective Logic implementation.
- [ ] Evidence fusion operators.
- [ ] Threat score and uncertainty calculation.
- [ ] Calibration and evaluation.
- [ ] Evidence-backed explanations.

### Phase 7 — Graph Intelligence

- [ ] Heterogeneous evidence graph.
- [ ] PostgreSQL and/or Neo4j persistence.
- [ ] Graph visualization.
- [ ] Cross-case indicator relationships.
- [ ] Candidate campaign clustering.
- [ ] Temporal correlation.
- [ ] Graph machine-learning experiments.

### Phase 8 — Investigation Management

- [ ] Case creation and lifecycle.
- [ ] Evidence inventories.
- [ ] Audit logging.
- [ ] Analyst notes.
- [ ] Investigation history.
- [ ] Reproducible analysis records.
- [ ] Controlled evidence retention.

### Phase 9 — Advanced Reporting

- [ ] PDF investigation reports.
- [ ] STIX 2.1 export.
- [ ] Evidence-linked executive summaries.
- [ ] Origin assessment reports.
- [ ] Campaign correlation reports.
- [ ] Report integrity checks.

### Phase 10 — Production Readiness

- [ ] Authentication and authorization.
- [ ] Role-based access control.
- [ ] Rate limiting.
- [ ] Secure file-processing isolation.
- [ ] Database migrations and backups.
- [ ] Audit-log protection.
- [ ] Monitoring and operational logging.
- [ ] Security testing.
- [ ] Documented retention and privacy policies.

Features are considered complete only after implementation and appropriate testing.

---

## Research Foundation

S.H.I.E.L.D. brings together ideas from several research areas.

### Email Authentication and Standards

- RFC 5322 — Internet Message Format.
- RFC 7208 — Sender Policy Framework (SPF).
- RFC 6376 — DomainKeys Identified Mail (DKIM).
- RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC).
- RFC 8617 — The Authenticated Received Chain (ARC) Protocol.

### Digital Forensics

- ISO/IEC 27037 — Guidelines for identification, collection, acquisition, and preservation of digital evidence.
- SHA-256 and cryptographic integrity verification.
- Evidence provenance and audit logging.

### Artificial Intelligence

- Transformer-based language models.
- Contextual semantic classification.
- Feature-based anomaly detection.
- Model calibration and uncertainty assessment.
- Explainable machine learning.

### Graph Intelligence

- Heterogeneous graph representation.
- Temporal graph analysis.
- Graph neural networks.
- Infrastructure and campaign correlation.
- Relationship-based threat intelligence.

### Evidence Fusion

- Subjective Logic.
- Belief, disbelief, and uncertainty modeling.
- Evidence reliability estimation.
- Dependency-aware evidence aggregation.
- Probability calibration.

These standards and research areas provide a foundation for the architecture. Implementations should be evaluated against the relevant specifications and literature before compliance, forensic validity, or detection performance is claimed.

---

## Contributing

Contributions are welcome as the project evolves.

Potential contribution areas include:

- Email parsing and normalization.
- Authentication verification.
- IOC extraction and enrichment.
- Threat intelligence integrations.
- AI model evaluation.
- Evidence fusion.
- Graph analysis.
- Dashboard development.
- Report generation.
- Security testing.
- Documentation.

### Contribution Guidelines

1. Discuss significant architectural changes before implementation.
2. Keep forensic observations separate from inferred conclusions.
3. Include tests for new parsing and analysis logic.
4. Avoid committing real emails containing personal or confidential information.
5. Never commit credentials or API keys.
6. Document new evidence fields and their provenance.
7. Explain limitations and expected failure modes.
8. Ensure new features do not silently transform unknown results into definitive verdicts.

---

## License

The project license has not yet been selected.

A license should be added before distributing the project publicly. The chosen license should reflect the intended use, contribution model, and any applicable dependencies or research requirements.

---

## Project Philosophy

S.H.I.E.L.D. is built around one fundamental principle:

**A threat assessment is only as useful as the evidence behind it.**

The objective is not simply to label emails as malicious or benign. It is to reconstruct what happened, identify what can be verified, connect related observations, quantify uncertainty, and present conclusions that investigators can independently examine.

By combining email forensics, AI-assisted analysis, threat intelligence, graph correlation, and evidence-centric reasoning, S.H.I.E.L.D. aims to transform email threat detection into a transparent, reproducible, and explainable investigative process.

**Inspect the evidence. Trace the connections. Understand the threat.**

*Every email has a story. Uncover it.*