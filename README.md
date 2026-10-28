# S.H.I.E.L.D. 🛡️

### AI Email Threat Detection & Forensic Intelligence

**Security & Header Inspection for Email, Logging & Diagnostics**

> Every email has a story. Uncover it.

## Overview

S.H.I.E.L.D. is an AI-powered email security and digital forensics platform that transforms raw `.eml` files into explainable security investigations. It combines email header analysis, SPF/DKIM/DMARC verification, AI-powered threat detection, Indicator of Compromise (IOC) extraction, threat intelligence, and forensic evidence correlation to help investigators understand not just whether an email is suspicious, but *why*.

Built around the **Evidence-Centric Email Investigation (ECEI)** framework, S.H.I.E.L.D. prioritizes traceable evidence, transparent reasoning, and uncertainty-aware threat assessment over black-box classification.

## Features

- **Email Forensics** — Extract email headers, message bodies, attachments, and metadata.
- **Authentication Analysis** — Evaluate SPF, DKIM, DMARC, and ARC-related information.
- **AI Threat Detection** — Identify potential phishing, business email compromise (BEC), fraud, and impersonation.
- **IOC Extraction** — Extract URLs, domains, IP addresses, and cryptographic hashes.
- **Threat Intelligence** — Enrich indicators using external intelligence sources.
- **Relay Analysis** — Reconstruct email routing paths and investigate potential origins.
- **Evidence Correlation** — Connect related indicators and identify potential attack campaigns.
- **Explainable Risk Scoring** — Generate threat assessments supported by traceable evidence.
- **Investigation Dashboard** — Explore email metadata, authentication results, and forensic findings.
- **Forensic Reports** — Export structured investigation results in JSON, with PDF and STIX 2.1 support planned.
- **Evidence Integrity** — Calculate SHA-256 hashes and maintain investigation provenance.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | Next.js, React, TypeScript, Tailwind CSS |
| Backend | Python, FastAPI |
| Machine Learning | PyTorch, Hugging Face Transformers, scikit-learn |
| Graph Intelligence | PyTorch Geometric |
| Database | PostgreSQL, Neo4j |
| Email Analysis | Python `email` package, `dnspython`, `dkimpy` |
| Evidence Integrity | SHA-256 |

*Technologies and features will be integrated incrementally as development progresses.*

## Architecture

```text
                   ┌─────────────────────┐
                   │     Next.js UI      │
                   │   Investigation     │
                   │      Dashboard      │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │     FastAPI API     │
                   └──────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
       ┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐
       │   Email    │  │    AI &    │  │   Threat   │
       │  Forensics │  │   Evidence │  │Intelligence│
       └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                   ┌──────────▼──────────┐
                   │ Evidence Correlation│
                   │  Risk Assessment    │
                   │  Report Generation  │
                   └─────────────────────┘
```

## Getting Started

### Prerequisites

- Node.js and npm
- Python 3.11+
- Git

PostgreSQL, Neo4j, and additional machine-learning dependencies may be required as their respective modules are implemented.

### Installation

Clone the repository:

```bash
git clone <repository-url>
cd S.H.I.E.L.D.
```

### Backend

```bash
cd backend

python -m venv .venv
```

Activate the virtual environment.

**Windows:**
```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

Open a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

*Setup commands may change as the project structure evolves.*

## Project Structure

```text
S.H.I.E.L.D/
├── frontend/       # Next.js application
├── backend/        # FastAPI backend
├── docs/           # Technical documentation
├── samples/        # Test email samples
├── ROADMAP.md      # Development roadmap
├── README.md
└── LICENSE
```

## Core Principle: Evidence-Centric Investigation

S.H.I.E.L.D. follows a simple investigative model:

**Email → Evidence → Analysis → Correlation → Explainable Findings**

AI predictions are treated as one source of evidence, not as definitive verdicts. Authentication results, routing artifacts, extracted indicators, and external intelligence contribute to an investigation whose conclusions should remain traceable and reproducible.

## Project Status

🚧 **Under active development.**

S.H.I.E.L.D. is being developed incrementally, beginning with email parsing, header forensics, authentication analysis, and structured report generation before expanding into AI detection and graph-based investigation.

See [`ROADMAP.md`](ROADMAP.md) for planned features and development milestones.

## Security & Privacy

- Treat uploaded emails and attachments as untrusted input.
- Never execute attachments during analysis.
- Protect sensitive email content and investigation reports.
- Secure API credentials and external intelligence keys.
- Validate authentication results rather than blindly trusting email headers.
- Preserve original artifacts and document analytical limitations.

S.H.I.E.L.D. is intended for defensive security analysis and authorized investigations. Its findings should support, not replace, investigator judgment.

## Contributing

Contributions, bug reports, feature suggestions, and security-focused improvements are welcome.

Please include appropriate tests for new functionality and avoid submitting real emails containing sensitive or personal information.

## License

The project license is yet to be determined.

---

**S.H.I.E.L.D. — Inspect the evidence. Trace the connections. Understand the threat.**