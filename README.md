# S.H.I.E.L.D. 🛡️

### AI Email Threat Detection & Forensic Intelligence

**Security & Header Inspection for Email, Logging & Diagnostics**

> Every email has a story. Uncover it.

S.H.I.E.L.D. is a backend-first email security and digital-forensics project intended to turn raw `.eml` files into explainable investigations. Its **Evidence-Centric Email Investigation (ECEI)** approach prioritizes traceable observations, transparent reasoning, uncertainty, and reproducible analysis over an unexplained binary phishing verdict.

> **Status:** Under active development. This README documents the intended architecture and analytical methods. A feature should only be considered implemented when it exists and works in the current repository.

## Contents

- [Goals and principles](#goals-and-principles)
- [Investigation workflow](#investigation-workflow)
- [Evidence model](#evidence-model)
- [Formula-based risk scoring](#formula-based-risk-scoring)
- [Subjective Logic and uncertainty](#subjective-logic-and-uncertainty)
- [Avoiding double-counting](#avoiding-double-counting)
- [Forensic modules](#forensic-modules)
- [Authentication and authorization](#authentication-and-authorization)
- [Evidence relationships and campaign correlation](#evidence-relationships-and-campaign-correlation)
- [Origin estimation](#origin-estimation)
- [Integrity and chain of custody](#integrity-and-chain-of-custody)
- [Technology stack](#technology-stack)
- [Architecture](#architecture)
- [Setup](#setup)
- [Environment configuration](#environment-configuration)
- [API overview](#api-overview)
- [Assessment response](#assessment-response)
- [Security and privacy](#security-and-privacy)
- [Research evaluation](#research-evaluation)
- [Roadmap and limitations](#roadmap-and-limitations)

## Goals and principles

S.H.I.E.L.D. aims to:

1. Parse `.eml` files and preserve original bytes.
2. Analyze headers and SPF/DKIM/DMARC-related information.
3. Extract URLs, domains, IP addresses, email addresses, and attachment hashes.
4. Normalize observations into evidence objects with provenance.
5. Calculate explainable risk contributions and an overall score.
6. Represent uncertainty, contradictory findings, and missing information.
7. Correlate indicators and infrastructure across investigations.
8. Estimate possible relay paths and origin candidates without unsupported attribution.
9. Protect private emails and investigations with backend-enforced authentication and ownership checks.
10. Produce structured findings suitable for investigation and reporting.

Core principles:

- **Evidence before verdicts:** significant findings must link to supporting evidence.
- **Observation is not conclusion:** a mismatch or heuristic is not automatically proof of maliciousness.
- **Uncertainty is explicit:** unavailable data is not silently treated as negative evidence.
- **Provenance matters:** record the source and method that produced each finding.
- **Risk is not probability:** a score of 80/100 does not mean an 80% probability of phishing.
- **Avoid double-counting:** correlated observations are not automatically independent confirmations.
- **Preserve original artifacts:** analysis must not modify the original uploaded message.
- **Privacy by default:** authorization is enforced by the backend, not the frontend.

## Investigation workflow

```text
Original .eml bytes
  -> Validate upload and calculate SHA-256
  -> Store original artifact privately
  -> Parse headers, body, MIME parts, and attachments
  -> Analyze headers and authentication
  -> Extract URLs and other IOCs
  -> Enrich indicators using configured providers
  -> Normalize findings into evidence objects
  -> Establish evidence relationships and dependencies
  -> Calculate risk contributions and aggregate risk
  -> Build uncertainty-aware assessment where justified
  -> Analyze relay/origin candidates and campaign relationships
  -> Persist investigation, provenance, and audit events
  -> Return explainable findings and report data
```

Optional provider failures should not fabricate results or necessarily stop other safe analysis. The response should distinguish completed, failed, unavailable, and skipped checks.

## Evidence model

Each normalized evidence record should include, where applicable:

| Field | Meaning |
|---|---|
| `evidence_id` | Stable unique identifier |
| `investigation_id` | Associated investigation |
| `type` / `category` | Finding type and category |
| `observation` | Raw or normalized fact actually observed |
| `source` | Parser, verifier, rule, model, or external provider |
| `source_artifact` | Relevant header, URL, attachment, or message reference |
| `method` | How the result was produced or verified |
| `observed_at` | Observation timestamp |
| `severity` | Normalized strength or severity |
| `reliability` | Reliability metadata for the source/method |
| `direction` | Supports threat, supports benign explanation, or inconclusive |
| `status` | Verified, reported, heuristic, unavailable, error, etc. |
| `explanation` | Interpretation and limitations |
| `related_evidence_ids` | Related or potentially dependent evidence |
| `risk_contribution` | Contribution, if applicable |
| `provenance` | Details needed to trace the finding |

Distinguish **observed**, **reported**, **inferred**, and **independently verified** findings. For example, an `Authentication-Results` header is a receiver-reported result; independent DKIM verification is a separate result.

## Formula-based risk scoring

The proposed per-evidence contribution formula is:

\[
\boxed{c_i = w_i \times s_i \times r_i}
\]

Where:

- \(c_i\): contribution of evidence item \(i\) to the risk assessment.
- \(w_i\): configurable weight for its evidence category.
- \(s_i\): normalized severity or strength of the finding.
- \(r_i\): reliability of the underlying observation or detection method.

A practical starting convention is:

\[
0 \leq s_i \leq 1,\qquad 0 \leq r_i \leq 1
\]

Weights should have documented, configurable ranges. The scoring configuration should identify whether an evidence type supports a threat hypothesis, supports a benign explanation, or is inconclusive. Negative or contradictory evidence must be handled explicitly rather than silently discarded.

### Illustrative example

Given \(w_i=8\), \(s_i=0.75\), and \(r_i=0.90\):

\[
c_i = 8 \times 0.75 \times 0.90 = 5.4
\]

This is an illustrative contribution of 5.4 scoring units—not a probability.

### Aggregating contributions

The contribution equation alone does **not** define the final risk score. The aggregation stage must:

1. Combine evidence contributions using a documented, reproducible rule.
2. Distinguish supporting, contradictory, and inconclusive evidence.
3. Avoid letting repeated low-quality signals dominate.
4. Account for shared sources and correlated observations where possible.
5. Normalize the result to a 0–100 score using an explicit function.
6. Return the contribution and rationale for each important finding.
7. Keep risk score, confidence, evidence coverage, and uncertainty separate.

A possible initial configurable risk-band scheme is:

| Score | Label |
|---:|---|
| 0–19 | Low |
| 20–39 | Guarded |
| 40–59 | Elevated |
| 60–79 | High |
| 80–100 | Critical |

These are proposed thresholds, not validated scientific boundaries. Calibrate them against labeled data. Do not describe a score as a probability unless a separate probability model has been appropriately calibrated and evaluated.

## Subjective Logic and uncertainty

The proposed uncertainty-aware representation is a Subjective Logic opinion:

\[
\boxed{\omega=(b,d,u,a)}
\]

Where:

- \(b\): belief in a specified proposition.
- \(d\): disbelief in that proposition.
- \(u\): uncertainty or uncommitted belief mass.
- \(a\): base rate for the proposition.

For a standard binomial opinion:

\[
\boxed{b+d+u=1}
\]

with:

\[
0\leq b,d,u,a\leq1
\]

The projected probability is:

\[
\boxed{P=b+(a\times u)}
\]

The projection allocates the uncertain portion according to the chosen base rate. It is **not automatically a calibrated real-world phishing probability**. Its meaning depends on the opinion construction, base rate, and assumptions.

### Mapping evidence to opinions

The implementation must explicitly document how evidence is mapped to belief, disbelief, and uncertainty. It must not arbitrarily convert a risk score into an opinion and claim that the result is statistically valid.

The mapping should consider source reliability, evidence strength, relevance, coverage, contradictory findings, missing data, and dependencies. Parameters should be configurable or versioned so an assessment can be reproduced.

### Fusion

Use a mathematically appropriate Subjective Logic fusion operator only when its assumptions are satisfied. Do not assume evidence independence without justification. If dependencies are unknown, preserve separate opinions or use a method with clearly documented assumptions rather than manufacturing certainty.

Keep the formula-based risk score and Subjective Logic output conceptually distinct in API responses.

## Avoiding double-counting

The same underlying URL could trigger a suspicious-keyword rule, a hostname heuristic, and an ML prediction. Those are not necessarily three independent confirmations. Evidence should record provenance and dependency references, and scoring/fusion should account for shared source artifacts and overlapping detection logic.

Similarly, a `From` / `Return-Path` mismatch can occur with legitimate mailing services. It is an observation requiring context, not decisive proof of spoofing. Missing DNS data, an absent DKIM signature, a failed signature, and a DNS timeout are distinct conditions.

## Forensic modules

### Email and MIME parsing

Use Python's email parsing facilities to extract headers, body parts, metadata, and attachment information. Treat all message content as untrusted. Handle malformed or deeply nested MIME structures defensively.

### Header forensics

Analyze fields such as `From`, `Sender`, `Reply-To`, `Return-Path`, `Message-ID`, `Date`, `Received`, `Authentication-Results`, and ARC headers when present. Each finding should include the actual values and explain the limitations of the rule.

### SPF, DKIM, DMARC, and ARC

Represent pass, fail, absent, not evaluated, insufficient data, and network/DNS error distinctly.

- SPF evaluation requires relevant connecting-IP and envelope-sender context.
- DKIM signature presence is not proof of signature validity.
- DMARC depends on applicable authentication results and domain alignment.
- Receiver-reported `Authentication-Results` should be recorded separately from independent verification.
- ARC headers may be parsed, but do not claim cryptographic ARC validation unless implemented.

A DNS error must not be mislabeled as a definitive cryptographic failure.

### URLs and domains

Extract URLs from plain text and relevant HTML attributes. Use proper URL parsing and registrable-domain/public-suffix-aware processing. Do not treat a brand name appearing somewhere in a hostname as proof of impersonation: `paypal.example.com` is not a PayPal-owned domain merely because the hostname contains `paypal`.

Do not automatically open arbitrary URLs from emails. Active fetching creates SSRF risk; any such capability requires strict destination and redirect validation.

### Attachments

Extract filename, MIME type, size, and hash where possible. Flag suspicious extension/MIME mismatches as heuristics. Never execute attachments. Do not claim malware detection unless an actual scanning integration is configured and working.

### IOC and threat-intelligence enrichment

Normalize URLs, domains, IPs, email addresses, and hashes. For each provider result, record provider, lookup time, indicator, response/status, and provider-supplied reputation or confidence when available. Handle missing API keys, timeouts, and rate limits honestly. Never invent reputation values.

### Relay and origin analysis

Analyze `Received` headers with explicit trust-boundary limitations because some earlier headers may be forged. Return ranked origin candidates only where supported, along with supporting evidence IDs, reasons, uncertainty, and limitations. Do not claim a sender's physical location from IP geolocation alone.

## Authentication and authorization

The intended backend authentication system includes persistent user accounts, normalized unique email addresses, secure password hashing, short-lived access tokens, rotating refresh tokens stored as hashes, refresh-token expiration/revocation, logout, current-user retrieval, and server-side role checks.

Target endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Register an account |
| `POST` | `/api/v1/auth/login` | Authenticate and issue tokens |
| `POST` | `/api/v1/auth/refresh` | Rotate refresh token and issue a new access token |
| `POST` | `/api/v1/auth/logout` | Revoke the current refresh session |
| `GET` | `/api/v1/auth/me` | Return the authenticated user's safe profile |

These are target contracts; verify actual route definitions before assuming they are implemented. Public registration must not permit users to assign themselves an admin role. Password hashes and raw refresh tokens must never be returned. Protected email records, investigations, and reports must be owner-scoped in the backend. A frontend-only access check is insufficient.

## Evidence relationships and campaign correlation

Represent relationships among emails, senders, recipients, domains, IPs, URLs, attachment hashes, relay hops, ASNs, threat-intelligence indicators, and evidence objects.

Relationships should record their type, endpoints, supporting evidence IDs, provenance, and timestamps where available. Campaign correlation should be conservative and explainable. A shared popular email provider, CDN, or hosting service alone must not group unrelated messages into a campaign.

The initial relationship model can use the existing MongoDB architecture. Neo4j or graph ML is optional and should only be introduced when justified by a real implementation need.

## Integrity and chain of custody

Calculate the hash from the original uploaded bytes:

\[
\boxed{H=\operatorname{SHA256}(\text{original email bytes})}
\]

Preserve the original `.eml` separately from parsed data. Where implemented, record the hash, size, uploader, upload time, storage reference, analysis/parser version, and important investigation actions.

A hash helps establish that two byte sequences match; it does not independently prove authorship, when an email was created, or legal admissibility. Keep storage private and do not log full sensitive email contents, passwords, tokens, or secrets.

## Technology stack

The table distinguishes the current implementation direction from optional research extensions. Confirm actual dependencies and code before treating an item as implemented.

| Layer | Technology / approach | Notes |
|---|---|---|
| API | Python, FastAPI | Core backend framework |
| Database | MongoDB and async Python driver | Existing implementation direction |
| Original artifact storage | Supabase Storage, private bucket | Existing integration direction |
| Configuration | Environment variables, Pydantic Settings | Follow current config schema |
| Parsing | Python `email` package | Core analysis |
| DNS | `dnspython` | For applicable checks |
| DKIM | `dkimpy` | Verification depends on actual implementation |
| Authentication | Secure password hashing, JWT access tokens, rotating refresh tokens | Backend target |
| Scoring | Configurable evidence contributions and documented aggregation | Core analysis design |
| Uncertainty | Subjective Logic opinions and appropriate fusion | Research/implementation target |
| Graph relationships | Database-backed relationships initially | Separate graph DB not required initially |
| ML | PyTorch, Hugging Face Transformers, scikit-learn | Optional, only with a real model pipeline |
| Graph ML | PyTorch Geometric | Optional research extension |
| Optional databases | PostgreSQL, Neo4j | Not required when MongoDB is the active initial stack |
| Integrity | SHA-256 | Original artifact fingerprint |

Avoid using multiple databases for the same purpose without a clear architectural reason.

## Architecture

```text
                 Client / Future Frontend
                           |
                           v
                     FastAPI REST API
                           |
             +-------------+-------------+
             |                           |
             v                           v
     Authentication &               Email API
      Authorization                     |
                                        v
                              Parse Original .eml
                                        |
                        +---------------+---------------+
                        |               |               |
                        v               v               v
                     Headers       URLs / IOCs      Attachments
                        |               |               |
                        +---------------+---------------+
                                        |
                           Authentication / Enrichment
                                        |
                                        v
                                  Evidence Engine
                                        |
                              +---------+---------+
                              |                   |
                              v                   v
                         Risk Scoring        Uncertainty
                                             / Fusion
                              |                   |
                              +---------+---------+
                                        |
                              Explainable Assessment
                                        |
                       +----------------+----------------+
                       |                                 |
                       v                                 v
                MongoDB Records                    Private Storage
                and Relationships                Original .eml files
                       |
                       v
              Investigations, Audit, Reports
```

## Setup

### Prerequisites

- Python 3.11+ or the version supported by the project's dependencies.
- Git.
- MongoDB configured for the backend.
- Supabase Storage credentials if the current backend uses Supabase for original-email storage.
- Node.js/npm only when running the separate frontend.

Clone the repository:

```bash
git clone <repository-url>
cd S.H.I.E.L.D.
```

Set up the backend:

```bash
cd backend
python -m venv .venv
```

Activate the environment.

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create a local `.env` based on `.env.example` and configure required services. Start Uvicorn using the import path that actually exists in the repository. For example, if `main.py` is directly inside `backend/`:

```bash
uvicorn main:app --reload --port 8000
```

If the application entry point is `app.main:app`, use that path instead. Inspect the repository rather than assuming the module path.

Interactive API documentation is usually available at `http://localhost:8000/docs` when enabled. Do not expose a development server directly to the public internet.

## Environment configuration

Use the actual names defined by the backend settings module. Example settings may include:

```dotenv
APP_NAME=S.H.I.E.L.D.
APP_VERSION=0.1.0
API_V1_PREFIX=/api/v1
DEBUG=true

MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=shield

SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
SUPABASE_EMAILS_BUCKET=emails

MAX_UPLOAD_SIZE_MB=20

JWT_SECRET_KEY=
JWT_ISSUER=shield
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
```

These are example values, not a guarantee that every variable already exists. Align names with `backend/core/config.py` and `.env.example`. Never commit actual secrets or overwrite the real `.env`.

For production, use a strong unique signing secret or managed signing key, disable debug mode, restrict database/storage permissions, use HTTPS, keep storage private, and configure rate limiting and monitoring. Optional intelligence/AI integrations should only be enabled with real credentials.

## API overview

Target API outline; verify actual routes and response contracts in the repository.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/health/` | Health check |
| `POST` | `/api/v1/auth/register` | Register |
| `POST` | `/api/v1/auth/login` | Login |
| `POST` | `/api/v1/auth/refresh` | Rotate refresh token |
| `POST` | `/api/v1/auth/logout` | Revoke refresh session |
| `GET` | `/api/v1/auth/me` | Current user |
| `POST` | `/api/v1/emails/upload` | Upload and analyze `.eml` |
| `GET` | `/api/v1/emails/` | List accessible email records |
| `GET` | `/api/v1/emails/{email_id}` | Retrieve an authorized email |
| `GET` | `/api/v1/investigations/{investigation_id}` | Retrieve an investigation |
| `GET` | `/api/v1/investigations/{investigation_id}/evidence` | Retrieve evidence |
| `GET` | `/api/v1/investigations/{investigation_id}/report` | Retrieve/export report, if implemented |

Private resources must enforce authorization and ownership in the backend. Paginate list endpoints and avoid exposing arbitrary database query capabilities.

## Assessment response

A completed investigation should provide structured data such as the following. This is a **schema illustration only**, not a hardcoded result or a claim about the current API response.

```json
{
  "investigation_id": "example-id",
  "status": "completed",
  "artifact": {
    "sha256": "computed-from-original-email-bytes",
    "size_bytes": 12345
  },
  "assessment": {
    "risk_score": 42,
    "risk_level": "Elevated",
    "score_is_probability": false,
    "confidence": null,
    "uncertainty": null,
    "evidence_coverage": null
  },
  "findings": [
    {
      "finding_id": "example-finding",
      "title": "Illustrative finding",
      "observation": "Observed fact",
      "interpretation": "Qualified interpretation",
      "direction": "inconclusive",
      "evidence_ids": [],
      "risk_contribution": null,
      "limitations": [
        "Illustrative placeholder, not a real analysis result"
      ]
    }
  ],
  "limitations": [
    "Report only checks that actually ran as completed."
  ]
}
```

Use real calculated values. Represent unavailable fields consistently and state which checks ran. Never invent evidence, confidence, provider reputation, or origin candidates to fill a response.

## Security and privacy

- Treat headers, message bodies, filenames, URLs, and attachments as untrusted.
- Enforce upload and parsing limits.
- Never execute attachments.
- Keep source artifacts and reports private.
- Enforce owner-based authorization on every protected resource.
- Hash passwords with a maintained password-hashing library.
- Store refresh tokens as hashes and rotate them securely.
- Never expose secrets, signing keys, database credentials, or service-role keys.
- Avoid logging tokens or full sensitive messages.
- Apply timeouts to external services.
- Prevent SSRF if active URL fetching is ever implemented, including validation of redirects and resolved IP destinations.
- Distinguish reported authentication headers from independently verified results.
- Do not claim legal admissibility based only on hashes and audit logs.

S.H.I.E.L.D. is intended for defensive security analysis and authorized investigations. Findings should support, not replace, investigator judgment.

## Research evaluation

The formula and uncertainty model should be evaluated rather than assumed effective.

When suitable labeled datasets are available, measure:

- Precision, recall, F1, false-positive rate, and false-negative rate.
- Probability calibration only for outputs intended as probabilities.
- Whether uncertainty increases appropriately with missing or contradictory evidence.
- Robustness to AI-generated phishing, malformed headers, and unusual URL structures.
- Temporal and cross-dataset generalization.
- Campaign-correlation quality where ground truth exists.
- Explanation traceability and the effect of ablation studies.
- The impact of removing individual evidence sources or fusion components.

Do not call weights, risk thresholds, opinions, or fusion methods scientifically validated until evaluated. Novelty and patentability claims require separate prior-art research and professional review.

## Roadmap and limitations

Suggested implementation order:

1. Reliable parsing, storage, API configuration, and error handling.
2. Persistent authentication, token rotation/revocation, and ownership enforcement.
3. Evidence objects, provenance, and dependency relationships.
4. Transparent scoring, aggregation, and explanation generation.
5. Subjective Logic opinion construction and justified fusion.
6. Header/authentication forensics, URL/domain analysis, attachment metadata, and available enrichment.
7. Investigations, graph-like relationships, campaign correlation, and origin candidates.
8. Structured reports and audit history.
9. Research evaluation, calibration, ablations, and temporal/cross-dataset testing.
10. Optional AI and graph-learning integration where a real model and evaluation plan exist.

Important limitations:

- Headers may be forged or rewritten by forwarding and mailing infrastructure.
- Authentication and reputation data may be incomplete or unavailable.
- URL heuristics can produce false positives.
- Shared infrastructure does not prove a shared campaign.
- Origin estimates are constrained by trust boundaries and available artifacts.
- Risk scores are not calibrated probabilities unless separately calibrated and evaluated.
- Subjective Logic results depend on valid opinion construction and justified fusion assumptions.
- AI models can be wrong or poorly calibrated.
- A hash supports byte-level integrity comparison but does not independently prove authorship or legal admissibility.

## Contributing

Contributions, bug reports, and security-focused improvements are welcome. Avoid committing real emails containing sensitive or personal information; use sanitized artifacts or minimal reproducible examples.

## License

The project license is yet to be determined.

---

**S.H.I.E.L.D. — Inspect the evidence. Trace the connections. Understand the threat.**
