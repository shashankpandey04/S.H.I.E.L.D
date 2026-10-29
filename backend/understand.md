# S.H.I.E.L.D. Backend --- Understand It From Zero

> **Purpose of this document:** Explain what the S.H.I.E.L.D. backend
> does, how an email moves through it, what its rules mean, and what the
> current system can---and cannot---claim.
>
> This guide is based on the implementation summary provided for the
> project. It is not an independent code audit. If code behavior differs
> from this description, the code is the source of truth and this
> document should be updated.

------------------------------------------------------------------------

## 1. What is S.H.I.E.L.D.?

**S.H.I.E.L.D.** stands for **Security & Header Inspection for Email,
Logging & Diagnostics**.

It is an email investigation platform. A user provides an email, and the
backend examines its technical details, records observations, estimates
risk, and helps organize the findings into an investigation.

Think of it as a digital evidence examiner for email.

It does not magically know whether an email is dangerous. It gathers
clues, applies programmed checks, and explains what those clues may
mean.

### The important distinction

-   **Observation:** Something the system directly found in the email or
    its analysis.
-   **Interpretation:** What that observation may indicate.
-   **Conclusion:** The system's overall assessment based on the
    available evidence.

For example:

-   Observation: A message contains a URL whose displayed domain differs
    from the destination domain.
-   Interpretation: The mismatch may be an attempt to disguise the
    destination.
-   Conclusion: This is one suspicious signal that may increase the
    email's assessed risk.

A suspicious signal is not automatically proof of a phishing attack.

------------------------------------------------------------------------

## 2. The big picture

At a high level, the backend has these responsibilities:

1.  **Receive and parse an email.**
2.  **Extract useful technical details**, such as headers, URLs, and
    attachments.
3.  **Run forensic checks** on those details.
4.  **Convert findings into a consistent evidence format.**
5.  **Calculate an explainable risk score.**
6.  **Represent uncertainty** rather than pretending every finding is
    certain.
7.  **Connect related entities** such as emails, domains, URLs, IP
    addresses, and attachment hashes.
8.  **Store investigations and generate reports.**
9.  **Authenticate users and control access** to protected API
    operations.

A simplified flow is:

``` text
User / Client
    |
    v
FastAPI routes
    |
    v
Email parsing
    |
    +--> Header and authentication checks
    +--> URL and attachment checks
    +--> Received-header / relay analysis
    |
    v
Evidence normalization
    |
    +--> Formula-based risk scoring
    +--> Subjective Logic / uncertainty representation
    +--> Evidence graph and campaign correlation
    |
    v
Stored results, investigations, and reports
```

This is a conceptual overview. Exact call order, optional steps, and
failure behavior should be confirmed against the current code.

------------------------------------------------------------------------

## 3. What is the backend built with?

The implementation summary identifies these technologies:

-   **Python:** Main programming language.
-   **FastAPI:** Web framework that exposes API endpoints.
-   **MongoDB:** Database for application data, users, tokens, evidence,
    and investigations.
-   **Python's email parser:** Reads email message structure.
-   **DNS tooling:** Supports DNS-based email authentication checks when
    DNS access is available.
-   **DKIM tooling:** Supports cryptographic DKIM verification when the
    required message data and DNS key are available.
-   **JWT:** Used for signed access tokens.
-   **PBKDF2-HMAC-SHA256:** Used for password hashing.
-   **SHA-256 and MD5:** Used to calculate attachment hashes.

The exact availability of external DNS, reputation services, and other
network-dependent checks depends on the deployment environment and
configuration.

------------------------------------------------------------------------

## 4. What happens when an email is analyzed?

### Step 1: The backend receives the email

The email upload API receives an email file or message according to the
endpoint's accepted input format.

The backend should preserve the original message where configured and
record a cryptographic hash when supported. A hash can help establish
whether two files contain identical bytes.

**Important:** A matching hash does not prove who created a file or
whether the email is authentic. It proves byte-level equality for the
data that was hashed.

### Step 2: The email is parsed

Parsing means turning the raw email into fields the program can inspect.

Common items include:

-   Sender and recipient fields
-   Subject
-   Message body
-   Email headers
-   URLs in the message
-   Attachment names, content types, and bytes when available

Email parsing is not the same as deciding whether an email is malicious.
Parsing extracts information; later checks interpret it.

### Step 3: The backend runs checks

Depending on the available data and implementation, checks can include:

-   Header consistency checks
-   SPF, DKIM, and DMARC-related checks
-   URL heuristics
-   Attachment metadata and hashing
-   `Received`-header relay analysis
-   Other deterministic rules implemented in the backend

A check may be unable to reach a conclusion. For example, a DNS lookup
may fail because the environment has no outbound DNS access. That should
not automatically be treated as proof that an email is malicious or
legitimate.

### Step 4: Findings become evidence objects

Different checks may return different kinds of results. The evidence
normalizer converts supported findings into a common structure.

An evidence record is intended to separate:

-   **Raw observation:** What was actually observed.
-   **Interpretation:** What the observation might mean.
-   **Conclusion or direction:** How the finding contributes to the
    assessment.
-   **Category:** The type of finding.
-   **Severity:** How strongly the configured rule treats the finding.
-   **Reliability:** How trustworthy the detection method is considered
    to be.
-   **Weight:** How important that evidence category is in the scoring
    configuration.
-   **Source and method:** Which component produced the finding and how.

This structure makes it easier to explain where an assessment came from.

### Step 5: Evidence contributes to a risk assessment

The formula-based scorer combines configured evidence contributions into
an overall score and a risk band.

The score is a result of the project's configured rules. Unless it has
been calibrated and evaluated against representative labelled emails, it
must **not** be described as a statistically validated probability that
the email is malicious.

### Step 6: Results can be connected to investigations

The graph service can represent entities and relationships---for
example, an email containing a URL, using a domain, or carrying an
attachment with a particular SHA-256 hash.

The investigation system can organize analysis into cases, support
status updates and notes, and produce structured forensic reports.

------------------------------------------------------------------------

## 5. Email authentication: SPF, DKIM, and DMARC

These mechanisms answer different questions. None of them alone proves
that an email's content is safe.

### SPF

**Sender Policy Framework** checks whether the sending server is
authorized by a domain's SPF policy to send mail for a relevant
envelope-sender domain.

A successful SPF result does not by itself prove that the visible `From`
address is trustworthy.

### DKIM

**DomainKeys Identified Mail** uses a digital signature to help verify
that signed parts of a message have not changed and that the signing
domain takes responsibility for the signature.

Verification needs the relevant signature data and public key. A missing
key, unavailable DNS, malformed message, or failed verification can have
different meanings and should not be casually collapsed into one result.

### DMARC

**Domain-based Message Authentication, Reporting, and Conformance**
evaluates alignment between the visible `From` domain and SPF and/or
DKIM authentication, using the domain's DMARC policy.

A message can pass one check and fail another. The backend should retain
the individual results and their context instead of treating all email
authentication as a single yes/no test.

### A crucial limitation

A legitimate service can send a suspicious-looking email, and an
attacker can abuse a legitimate service. Authentication results are
evidence---not a complete verdict on intent or safety.

------------------------------------------------------------------------

## 6. Understanding `Received` headers and relay analysis

Email often passes through multiple mail servers. Servers may add
`Received` headers to describe parts of that journey.

The relay analyzer examines these headers to derive possible transport
information, such as:

-   IP addresses mentioned in relay records
-   Relationships between hops
-   Time differences between timestamps when parseable
-   Potentially inconsistent or unusual timing
-   Candidate origin information

### Why "candidate origin" matters

The oldest-looking or earliest visible IP is not automatically the true
origin of an email. Headers can be incomplete, and some header lines may
be untrusted or inserted by systems outside the recipient's trusted mail
infrastructure.

Private IP addresses, such as addresses used inside local networks,
generally are not globally routable public source addresses. Seeing one
in a relay chain does not by itself identify the sender's public
location.

Negative or implausible hop delays can be anomalies, but timestamp
errors, clock differences, or malformed headers can also explain them.

**Treat relay results as leads for investigation, not definitive
attribution.**

------------------------------------------------------------------------

## 7. How the formula-based risk score works

The documented contribution formula is:

``` text
c_i = w_i × s_i × r_i
```

Read it as:

> Evidence contribution = category weight × finding severity × method
> reliability.

The terms mean:

-   `c_i`: Contribution of one finding to the score.
-   `w_i`: Configured importance of the evidence category.
-   `s_i`: Configured severity assigned to this finding.
-   `r_i`: Configured reliability assigned to the detection method.

These values do not appear by magic. The program obtains them from code,
rules, or configuration. Unless they were learned or calibrated using
suitable data, they are engineering choices---not experimentally proven
truths.

### A made-up example

Suppose a rule is configured as follows:

``` text
Category weight = 8
Finding severity = 0.75
Method reliability = 0.90

Contribution = 8 × 0.75 × 0.90 = 5.4
```

The number `5.4` is the arithmetic result of those chosen inputs. It
does **not** mean the email has a 5.4% chance of being malicious.

The numbers above are illustrative. Consult the actual scoring
implementation and its configuration for the values currently used by
the application.

### Supporting and contradictory evidence

The scoring design distinguishes findings that support a malicious
interpretation from findings that support a legitimate interpretation.
The documented conceptual calculation is:

``` text
Supporting contribution = sum of malicious-supporting contributions
Contradictory contribution = sum of legitimate-supporting contributions

Raw score = max(0, supporting contribution
                   - contradiction factor × contradictory contribution)
```

A later normalization step maps the result to a bounded score, described
in the implementation summary as a 0--100 scale, and assigns a risk
band.

The exact contradiction factor, normalization method, saturation
behavior, uncertainty penalty, and thresholds must be read from the
current `formula_scorer.py`. They are implementation-specific. Do not
assume the simple conceptual formula above captures every detail of the
code.

### Risk bands

The implementation summary lists these bands:

-   Low
-   Guarded
-   Elevated
-   High
-   Critical

The boundaries between bands are configured thresholds. They are not
universal standards. Their usefulness must be evaluated on
representative emails, especially to understand false positives and
false negatives.

### Why avoid double-counting?

One underlying problem can trigger multiple related rules. For example,
several URL rules might all react to the same suspicious URL.

If every related signal is treated as independent evidence, the final
score can exaggerate the strength of the case. Related findings should
be reviewed for overlap and dependence.

------------------------------------------------------------------------

## 8. What is Subjective Logic doing here?

Subjective Logic is a framework for representing belief while explicitly
accounting for uncertainty.

The project describes a binomial opinion as:

``` text
ω = (b, d, u, a)
```

Where:

-   `b`: Belief in a proposition.
-   `d`: Disbelief in the proposition.
-   `u`: Uncertainty.
-   `a`: Base rate, or prior expectation for the proposition.

The belief, disbelief, and uncertainty values are constrained by:

``` text
b + d + u = 1
```

A projected probability-like value can be calculated as:

``` text
P(ω) = b + a × u
```

This projection incorporates the base rate into the uncertainty portion.
It is meaningful only when the opinion components and base rate are
constructed according to a suitable model.

### What Subjective Logic does not do

It does not automatically make the system accurate, and it does not turn
arbitrary risk-score values into valid probabilities.

The way evidence is converted into opinions, the base rate, and the
method used to combine opinions all require justification. In
particular, independent consensus fusion should only be used when its
independence assumptions are reasonable. When findings depend on one
another, treating them as independent can overstate confidence.

------------------------------------------------------------------------

## 9. What does "uncertainty" mean in practice?

A forensic system should distinguish between a negative result and a
check that could not be completed.

Examples:

-   **Pass:** The check ran and its defined success condition was met.
-   **Fail:** The check ran and its defined failure condition was
    observed.
-   **Not present:** The relevant item was not found.
-   **Not evaluated:** The check was not run.
-   **Insufficient data:** The input lacked information needed for a
    meaningful result.
-   **Timeout / provider unavailable:** An external dependency did not
    respond or could not be reached.
-   **Parse error:** The input could not be interpreted as expected.
-   **Inconclusive:** The available evidence did not support a clear
    result.

These states are not interchangeable. For example, being unable to query
a domain's DNS records is not the same as proving that the domain has no
relevant records.

The exact status values used in the code should be checked before
relying on this list as the backend's definitive enum.

------------------------------------------------------------------------

## 10. Evidence graphs and campaign correlation

An evidence graph represents entities and relationships as connected
records.

The implementation summary lists node types such as:

-   Email
-   Sender
-   Domain
-   URL
-   IP address
-   Attachment SHA-256 hash

It also lists relationships such as:

-   `SENT_FROM`
-   `BELONGS_TO_DOMAIN`
-   `CONTAINS_URL`
-   `ORIGINATED_AT`
-   `HAS_ATTACHMENT`

### Example

``` text
Email A ──CONTAINS_URL──> URL X
Email A ──SENT_FROM─────> Sender Y
Sender Y ──BELONGS_TO_DOMAIN──> Domain Z

Email B ──CONTAINS_URL──> URL X
```

If two emails share a URL, that is a relationship worth investigating.
It does not automatically prove that both emails belong to the same
criminal campaign. Shared infrastructure can be used by legitimate and
malicious actors alike.

The reported campaign correlation checks include shared binaries, URLs,
and originating IPs. The result should be treated as a correlation lead,
with the rationale visible to the analyst.

------------------------------------------------------------------------

## 11. Investigations and forensic reports

An investigation is a case for organizing email-analysis work.

The implementation summary describes support for:

-   Creating and retrieving cases
-   Filtering investigations
-   Updating investigation status
-   Adding analyst notes
-   Generating structured JSON reports

A report is useful when it lets another analyst understand:

1.  What was analyzed.
2.  Which observations were found.
3.  Which checks produced those observations.
4.  How each finding was interpreted.
5.  How the score was calculated.
6.  What remains uncertain or was not checked.
7.  Why related emails or indicators were connected.

A report should not present a guess as a confirmed fact. It should make
the evidence trail and limitations clear.

------------------------------------------------------------------------

## 12. Authentication and account security

The backend includes user authentication endpoints according to the
implementation summary.

  -----------------------------------------------------------------------
  Endpoint                            Intended purpose
  ----------------------------------- -----------------------------------
  `POST /api/v1/auth/register`        Create an account

  `POST /api/v1/auth/login`           Authenticate and issue tokens

  `POST /api/v1/auth/refresh`         Refresh access credentials and
                                      rotate the refresh token

  `POST /api/v1/auth/logout`          Revoke the relevant refresh token
                                      or session

  `GET /api/v1/auth/me`               Return the current authenticated
                                      user's profile
  -----------------------------------------------------------------------

The summary describes:

-   Password hashing with PBKDF2-HMAC-SHA256
-   JWT access tokens signed with HS256
-   Refresh tokens stored as hashes
-   Refresh-token rotation
-   Replay detection and token-family revocation

### Plain-English explanation

A password should not be stored as readable text. Password hashing
stores a derived value that can be checked when the user logs in.

An access token lets the client prove its authenticated identity to
protected endpoints for a limited period. A refresh token is used to
obtain new access credentials. Rotating refresh tokens means an old
refresh token should not continue to be reusable after it has been
exchanged.

### What still needs to be tested

A list of security features is not proof that every security property is
correct. Test authorization on every protected resource, refresh-token
replay behavior, token expiration, logout, password handling, secret
configuration, and isolation between different users' records.

Never commit real passwords, JWT secrets, database credentials, or API
keys to source control. Production secrets should come from secure
deployment configuration.

------------------------------------------------------------------------

## 13. API routes at a glance

The implementation summary reports these API groups:

-   `/api/v1/health` --- service health
-   `/api/v1/emails` --- upload, list, and retrieve email-analysis
    records
-   `/api/v1/auth` --- registration, login, refresh, logout, and
    current-user profile
-   `/api/v1/investigations` --- case management and report generation

The exact HTTP methods, request schemas, response shapes, access
requirements, and error responses should be checked in the FastAPI route
definitions and OpenAPI documentation. This section is a map, not a
substitute for the live API schema.

------------------------------------------------------------------------

## 14. Current limitations

The implementation summary identifies several important limitations.

### Network-dependent checks

DNS-based SPF/DMARC lookups and cryptographic DKIM verification may be
limited in restricted environments without outbound DNS or internet
access. Deployment tests should confirm the actual behavior.

### No dynamic malware sandbox

Attachment analysis is described as deterministic inspection of metadata
and file hashes. It does not dynamically execute suspicious attachments
inside an isolated malware-analysis sandbox.

A hash can help identify a known file, but hashing alone does not
determine whether a file is malicious.

### No external threat-intelligence integration by default

The reported graph correlates information already in the application's
internal data. External reputation providers would require separately
configured integrations and credentials.

### No trained AI model

The described scoring system is rule-based. It does not become a
machine-learning model just because it uses mathematical formulas.

A future ML model could learn patterns from labelled data, but it should
be trained and evaluated separately before its output is integrated into
the risk assessment.

### Tests do not establish real-world accuracy

Unit tests can demonstrate that code behaves as expected for selected
test cases. They cannot, by themselves, establish detection accuracy on
real-world email traffic or prove that the system is production-ready.

------------------------------------------------------------------------

## 15. What do the reported 52 passing tests tell us?

The implementation report states that 52 unit tests passed:

-   31 existing backend tests
-   21 additional forensic and authentication tests

The reported test areas include email parsing, URL extraction,
authentication-related logic, relay analysis, evidence normalization,
scoring, Subjective Logic operations, graph correlation, report
generation, and investigation management.

That is encouraging evidence that the tested code paths work for the
tested cases.

It does **not** automatically establish:

-   That every endpoint works in a deployed environment.
-   That DNS and other external services work in production.
-   That the score is accurate on previously unseen emails.
-   That authentication and authorization cannot be bypassed.
-   That the system can safely handle hostile files or very large
    inputs.
-   That every forensic conclusion is correct.

The tests should be rerun in the actual development environment, and
integration/security testing should complement unit tests.

------------------------------------------------------------------------

## 16. How to explain S.H.I.E.L.D. in 30 seconds

> S.H.I.E.L.D. is a rule-based email forensics platform built with
> Python and FastAPI. It parses emails, examines authentication and
> transport clues, extracts URLs and attachment metadata, and converts
> findings into structured evidence. It combines configured evidence
> contributions into an explainable risk assessment, represents
> uncertainty, links related indicators in an evidence graph, and
> organizes cases into forensic reports. It currently uses deterministic
> rules rather than a trained AI model, so its numerical scoring and
> detection accuracy need to be validated against representative
> labelled email data.

------------------------------------------------------------------------

## 17. Suggested reading order for a new developer

If you're new to the repository, read the code in this order:

1.  **Application entry point** --- understand how FastAPI starts and
    registers routers.
2.  **API router and email endpoint** --- see what happens when a
    request arrives.
3.  **Email parser** --- understand how raw email data becomes
    structured fields.
4.  **Individual analyzers** --- learn what each check observes.
5.  **Evidence schema and normalizer** --- see how different findings
    become a consistent format.
6.  **Formula scorer** --- follow the exact scoring rules and
    configuration values.
7.  **Subjective Logic service** --- understand how the system
    represents uncertainty and combines opinions.
8.  **Graph service** --- see how entities and relationships are stored
    and correlated.
9.  **Investigation and report services** --- understand case management
    and output generation.
10. **Authentication service and security utilities** --- understand how
    users and tokens are handled.
11. **Tests** --- learn which behavior is explicitly covered and what
    remains untested.

Use the actual source code to confirm exact numeric values, rule
conditions, error behavior, and route permissions.

------------------------------------------------------------------------

## 18. Final principle

**S.H.I.E.L.D. should explain what it observed, why that observation
matters, how it influenced the assessment, and what it could not
verify.**

That is the difference between a useful forensic aid and a tool that
simply labels an email "safe" or "dangerous" without showing its work.
