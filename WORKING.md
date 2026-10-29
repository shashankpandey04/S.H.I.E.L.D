# S.H.I.E.L.D. — WORKING.md

## Mathematical and Operational Specification

**Project:** S.H.I.E.L.D. — Security & Header Inspection for Email, Logging & Diagnostics  
**Core methodology:** Evidence-Centric Email Investigation (ECEI)  
**Purpose:** Define how observations become numeric parameters, how formulas use those parameters, what each result means, and which deterministic rules or empirical methods justify every value.

---

# 1. Purpose of This Document

This document defines the operational mathematics behind S.H.I.E.L.D.'s email investigation engine.

It is intended to guide implementation of:

1. Evidence extraction and normalization.
2. Deterministic evidence classification.
3. Evidence severity and reliability.
4. Formula-based risk contributions.
5. Overall risk aggregation and normalization.
6. Subjective Logic opinions and uncertainty.
7. Evidence fusion and dependency management.
8. Risk interpretation and explanation generation.
9. Missing-data and conflicting-evidence handling.
10. Reproducibility and evaluation.

The implementation must follow the definitions in this document rather than inventing numeric values independently.

## 1.1 Fundamental rule

Every numeric parameter must be one of the following:

- **Deterministically derived:** calculated from a documented rule applied to observable input.
- **Configuration-defined:** selected through explicit, versioned configuration.
- **Empirically estimated:** learned or calibrated using documented training or validation data.
- **Externally reported:** supplied by an identifiable external provider, with its provenance retained.
- **Unavailable:** not calculated because the necessary information is missing or the required method failed.

These categories must never be silently mixed.

For example, a deterministic URL rule may produce a severity value of `0.6` because the rule explicitly maps a particular condition to that value. That does not mean there is a 60% probability that the URL is malicious.

Likewise, a threat-intelligence provider's reputation score is not automatically the probability that an email is malicious.

## 1.2 No arbitrary mathematics

The backend must not:

- Generate random severity or reliability values.
- Assign confidence based solely on intuition.
- Treat a missing lookup as evidence of maliciousness.
- Convert a risk score directly into a probability without a validated model.
- Add multiple correlated findings as though they were independent confirmations.
- Claim that a formula is scientifically validated merely because it is mathematically defined.
- Claim that the original sender or physical origin has been conclusively identified without sufficient evidence.

---

# 2. The Analysis Model

S.H.I.E.L.D. separates the investigation into six conceptual stages.

### Stage 1: Observation

Extract facts from the original email.

Examples:

- A DKIM signature exists.
- A DKIM signature fails independent verification.
- A URL uses an IP address as its hostname.
- A message contains an attachment.
- A `Received` header identifies a relay.
- A DNS lookup timed out.

These are observations, not necessarily conclusions.

### Stage 2: Interpretation

Apply a documented rule to an observation.

Examples:

- An IP-literal URL may be suspicious.
- A failed DKIM signature may indicate message modification, a signing problem, or another authentication issue.
- A `From` and `Return-Path` mismatch may be normal for mailing infrastructure.

### Stage 3: Evidence normalization

Convert supported interpretations into structured evidence records with consistent parameters.

### Stage 4: Risk scoring

Calculate each evidence item's contribution and aggregate contributions using a documented rule.

### Stage 5: Uncertainty reasoning

Where the required evidence and assumptions are available, construct Subjective Logic opinions and combine them using an appropriate fusion method.

### Stage 6: Explanation

Return the observed facts, interpretation, calculation, limitations, and provenance behind the assessment.

The system must preserve these stages in its data model. A downstream model must not erase the distinction between an observation and an interpretation.

---

# 3. Parameter Provenance

Every calculated parameter must have a documented source.

| Parameter | Meaning | Permitted origin |
|---|---|---|
| `w_i` | Evidence category weight | Versioned configuration or empirical calibration |
| `s_i` | Evidence severity/strength | Deterministic rule mapping or validated model |
| `r_i` | Observation reliability | Method-specific reliability policy or empirical validation |
| `c_i` | Evidence contribution | Calculated from `w_i`, `s_i`, and `r_i` |
| `C_support` | Aggregated supporting evidence | Documented aggregation function |
| `C_contradict` | Aggregated contradictory evidence | Documented aggregation function |
| `R_raw` | Raw aggregate risk | Calculated from documented supporting and contradictory evidence |
| `R` | Normalized risk score | Documented normalization function |
| `b` | Belief mass | Defined evidence-to-opinion mapping |
| `d` | Disbelief mass | Defined evidence-to-opinion mapping |
| `u` | Uncertainty mass | Defined evidence-to-opinion mapping |
| `a` | Base rate | Empirically estimated prior or explicitly configured prior |
| `P` | Projected probability from an opinion | Subjective Logic projection |
| `confidence` | Confidence in a stated result | Must have its own defined meaning and method |
| `evidence_coverage` | Proportion of applicable checks completed | Deterministic calculation from an explicit checklist |

The implementation must retain parameter provenance and a version identifier for the configuration or method used.

---

# 4. Evidence Contribution Formula

The initial evidence contribution formula is:

\[
\boxed{c_i=w_i\times s_i\times r_i}
\]

Where:

- \(c_i\): contribution of evidence item \(i\) to the risk assessment.
- \(w_i\): configured weight of the evidence category.
- \(s_i\): normalized severity or strength of the finding.
- \(r_i\): reliability of the observation method.

This formula makes the contribution traceable to three explicit factors.

It does not independently define the overall risk score or a probability of maliciousness.

## 4.1 Weight: \(w_i\)

### Meaning

The weight defines the maximum relative influence assigned to an evidence category under the chosen scoring configuration.

For example, an independently verified authentication failure might receive a different category weight from a weak URL-shape heuristic.

### How is the value determined?

There are two legitimate approaches.

**Approach A: Initial configured weights**

Define explicit category weights in a version-controlled configuration file.

Example configuration:

| Evidence category | Illustrative weight |
|---|---:|
| Authentication integrity | 10 |
| Domain/URL indicators | 8 |
| Header anomalies | 5 |
| Content heuristics | 4 |
| Attachment metadata heuristics | 5 |
| External reputation | 7 |

These values are illustrative starting points only. They are not established truths about the relative importance of the categories.

The implementation must not silently present them as empirically validated.

**Approach B: Empirically calibrated weights**

Use a labeled training dataset to estimate which evidence categories improve detection.

A possible method is to train a regularized logistic regression or another interpretable model using normalized category features.

The resulting coefficients may help estimate relative influence, but they are not automatically equivalent to the weights in the contribution formula. Any transformation into non-negative category weights must be explicitly defined, justified, and evaluated.

Weights must be calibrated using training/validation data, then assessed on a separate held-out test set.

### Important constraint

Do not update weights automatically from an email currently being investigated.

That would make the calculation unstable and potentially attacker-manipulable.

Weights must remain fixed for a given configuration version during a reproducible investigation.

---

## 4.2 Severity: \(s_i\)

### Meaning

Severity describes how strongly a particular finding should contribute to the configured risk score.

It is not the probability that the finding is true and is not the probability that the email is malicious.

### Numeric range

Use:

\[
\boxed{0\leq s_i\leq1}
\]

### How is severity determined?

Use explicit rule-to-value mappings.

For example, a URL-analysis rule might use the following initial configuration:

| Observation | Illustrative severity |
|---|---:|
| Unusual but valid URL structure | 0.20 |
| Multiple suspicious structural characteristics | 0.45 |
| IP-literal URL with additional suspicious context | 0.65 |
| Independently confirmed malicious URL reputation | 0.95 |

These are example mappings, not universally correct values.

Each actual rule must specify:

1. The exact triggering condition.
2. The normalized severity assigned.
3. Why that severity is appropriate.
4. The limitations of the observation.
5. Whether other rules may describe the same underlying condition.
6. How the value will be evaluated and revised.

Severity must not be inferred from an unexplained label such as "high risk."

### Deterministic severity

If a rule assigns severity `0.65` whenever a specified condition is satisfied, the result is deterministic with respect to that rule and its input.

However, the choice of `0.65` is a policy/configuration decision until empirical evidence supports it.

**Deterministic does not mean scientifically proven.**

---

## 4.3 Reliability: \(r_i\)

### Meaning

Reliability represents how much trust the scoring system places in the underlying observation or method.

It concerns the reliability of the evidence-generating process, not the maliciousness of the email.

### Numeric range

Use:

\[
\boxed{0\leq r_i\leq1}
\]

### How is reliability determined?

Reliability must be assigned according to the method that generated the observation.

The initial implementation may use a versioned method-reliability registry.

Example:

| Evidence-generation method | Illustrative reliability |
|---|---:|
| Successfully parsed raw header field | 0.98 |
| Successful independent cryptographic verification | 0.99 |
| Deterministic URL structure rule | 0.90 |
| External provider response with verified indicator association | 0.85 |
| Heuristic interpretation of a domain name | 0.60 |
| Malformed or ambiguous input | Not automatically scored |

These are illustrative values only. They must not be described as measured reliability until validated.

### Empirical reliability

Where sufficient labeled data exists, estimate reliability from the observed performance of the method on a representative validation set.

For a binary detector, one possible estimate is its observed precision:

\[
\text{Precision}=\frac{TP}{TP+FP}
\]

Where:

- \(TP\): true positives.
- \(FP\): false positives.

A raw precision estimate can be unstable on small samples. If empirical reliability is based on precision, the implementation should use an appropriate uncertainty estimate or smoothing method, document the sample size, and avoid treating a tiny sample as definitive.

Precision is also conditional on the evaluated dataset and prevalence. It should not be treated as a universal property of a detector.

### Critical distinction

A parser can be highly reliable at identifying a URL without the URL being malicious.

Likewise, a verified DKIM failure may be a reliable observation without conclusively proving phishing.

Reliability and severity must therefore remain separate.

---

# 5. Worked Evidence Contribution Example

Suppose an investigation contains one URL finding.

The configured parameters are:

\[
w_i=8
\]

\[
s_i=0.75
\]

\[
r_i=0.90
\]

Then:

\[
c_i=w_i\times s_i\times r_i
\]

\[
c_i=8\times0.75\times0.90
\]

\[
\boxed{c_i=5.4}
\]

The result is 5.4 contribution units.

It does not mean:

- A 5.4% probability of phishing.
- A 54% probability of phishing.
- A 90% probability of phishing.
- A scientifically validated severity of 75%.

The number is meaningful only within the configured scoring system.

Every API finding should retain the values used:

```json
{
  "evidence_id": "example-evidence-id",
  "category": "url_analysis",
  "rule_id": "suspicious_url_structure",
  "observation": "URL matches the configured structural heuristic",
  "weight": 8.0,
  "severity": 0.75,
  "reliability": 0.9,
  "contribution": 5.4,
  "configuration_version": "risk-v1"
}
```

This is an illustrative response shape, not an actual finding.

---

# 6. Aggregating Evidence into an Overall Risk Score

The per-evidence formula is only the first stage. The system also needs an explicit aggregation function.

## 6.1 Why a simple sum is insufficient

Consider one URL that triggers three rules:

- A suspicious hostname rule.
- A suspicious keyword rule.
- A machine-learning URL classifier.

If all three rules examine the same hostname, adding all three contributions may exaggerate the importance of a single underlying observation.

Therefore, the aggregation stage must group or otherwise account for dependent evidence.

## 6.2 Initial deterministic aggregation

For an initial version, divide evidence into:

- Supporting evidence: \(S\).
- Contradictory or mitigating evidence: \(D\).
- Inconclusive evidence: \(I\).

Inconclusive evidence should be retained for explanation but should not automatically add to or subtract from maliciousness risk.

After dependency handling, define:

\[
C_S=\sum_{i\in S}c_i
\]

\[
C_D=\sum_{j\in D}c_j
\]

These sums must operate on the contributions retained by the documented dependency-handling policy, not blindly on every generated finding.

A simple transparent raw score is:

\[
\boxed{R_{\text{raw}}=\max(0,C_S-\lambda C_D)}
\]

Where:

- \(C_S\): aggregated supporting contribution.
- \(C_D\): aggregated contradictory contribution.
- \(\lambda\): configured mitigation factor.

For the initial implementation, \(\lambda\) must be explicitly configured. An illustrative value is \(1.0\), meaning a contribution classified as contradictory reduces the raw score by the same number of units as an equivalent supporting contribution adds.

This is a policy choice, not a scientific law.

Contradictory evidence must be relevant to the same hypothesis. A valid SPF result, for example, does not necessarily cancel a malicious URL.

## 6.3 Normalizing to 0–100

If the configured scoring system has a documented maximum possible raw score \(M>0\), use:

\[
\boxed{R=\min\left(100,\frac{100R_{\text{raw}}}{M}\right)}
\]

Where:

- \(R_{\text{raw}}\): raw risk score.
- \(M\): documented maximum raw score for the scoring configuration.
- \(R\): normalized score from 0 to 100.

The configuration must define how \(M\) is obtained. It must not be guessed at runtime.

For example, \(M\) may be derived from the sum of the maximum permitted contributions of the distinct evidence groups under a fixed configuration. If evidence counts are unbounded, the implementation must define caps or use another explicit bounded normalization method.

If \(M=0\), the score must be marked unavailable or handled through an explicit zero-evidence policy; the implementation must not divide by zero.

### Limitation

This normalization creates a bounded score, not a probability.

A score of 80 means the configured formula produced a normalized risk score of 80/100. It does not mean an 80% chance that the message is malicious.

## 6.4 Risk bands

An initial configurable scheme may be:

| Score | Label |
|---:|---|
| 0–19 | Low |
| 20–39 | Guarded |
| 40–59 | Elevated |
| 60–79 | High |
| 80–100 | Critical |

These thresholds are initial policy settings, not validated scientific cutoffs.

Thresholds should eventually be selected based on validation data and operational requirements, including the cost of false positives and false negatives.

The backend must expose the score, label, scoring configuration version, and principal contributing evidence.

---

# 7. Evidence Dependencies and Duplicate Findings

Dependency handling is essential because email analysis produces overlapping signals.

Examples include:

- A URL hostname triggers several heuristics.
- A threat-intelligence provider reports a reputation result that another provider has copied.
- A model and a rule use the same underlying feature.
- SPF and DMARC results depend partly on overlapping authentication data.
- A receiver-reported DKIM failure and an independently verified DKIM failure refer to the same signature.

Each evidence record should include:

- `source_artifact_id`
- `rule_id` or `method_id`
- `provider_id`, where applicable
- `related_evidence_ids`
- `dependency_group_id`, where known

A practical initial deterministic policy is to group findings that describe the same underlying artifact and apply a documented group aggregation rule.

For example, if a dependency group contains multiple heuristic contributions, the initial policy might retain the maximum contribution within that group rather than summing every heuristic. This is conservative and transparent, but it can discard useful independent information; the policy must be evaluated.

Do not assume all evidence in the same category is dependent, and do not assume all evidence from different categories is independent.

When dependencies cannot be established reliably, preserve the uncertainty and avoid claiming independent confirmation.

---

# 8. Subjective Logic

Formula-based risk scoring and Subjective Logic serve different purposes.

- Risk scoring produces a transparent, configurable risk index.
- Subjective Logic represents belief, disbelief, and uncertainty about a defined proposition.

One must not be substituted for the other without a documented mapping.

## 8.1 Opinion tuple

A standard binomial Subjective Logic opinion is:

\[
\boxed{\omega=(b,d,u,a)}
\]

Where:

- \(b\): belief mass.
- \(d\): disbelief mass.
- \(u\): uncertainty mass.
- \(a\): base rate.

For a valid opinion:

\[
\boxed{b+d+u=1}
\]

Each mass must satisfy:

\[
0\leq b,d,u\leq1
\]

The base rate must satisfy:

\[
0\leq a\leq1
\]

The opinion must refer to a clearly defined proposition, for example:

> H: The analyzed email is malicious.

An opinion about "the DKIM signature is valid" is a different proposition from an opinion about "the email is malicious."

Do not combine opinions about different propositions as though they represented the same claim.

## 8.2 Projected probability

The projected probability is:

\[
\boxed{P=b+(a\times u)}
\]

The formula allocates the uncertain mass according to the base rate.

Example:

\[
b=0.60,\quad d=0.20,\quad u=0.20,\quad a=0.10
\]

The opinion is valid because:

\[
0.60+0.20+0.20=1
\]

The projected probability is:

\[
P=0.60+(0.10\times0.20)
\]

\[
\boxed{P=0.62}
\]

This gives a projected probability of 0.62 under the specified opinion and base-rate assumptions.

It must not automatically be reported as a calibrated 62% real-world probability of phishing. That interpretation requires valid opinion construction and empirical calibration.

---

# 9. How Are \(b\), \(d\), and \(u\) Determined?

These parameters must not be assigned arbitrary values.

A standard Subjective Logic evidence model can derive them from positive and negative evidence weights.

One commonly used mapping is based on a binomial opinion with prior weight \(W\).

Let:

- \(r\): accumulated positive evidence weight.
- \(s\): accumulated negative evidence weight.
- \(W\): documented prior weight or non-evidential strength parameter.

Then:

\[
\boxed{b=\frac{r}{r+s+W}}
\]

\[
\boxed{d=\frac{s}{r+s+W}}
\]

\[
\boxed{u=\frac{W}{r+s+W}}
\]

These equations are appropriate only when the evidence weights have been constructed according to the selected Subjective Logic model and its assumptions.

The implementation must not assume that arbitrary risk contributions automatically qualify as valid \(r\) and \(s\) values.

## 9.1 Positive evidence weight: \(r\)

This is the accumulated weight of evidence supporting the proposition.

For the proposition "the email is malicious," supporting observations may include independently confirmed malicious infrastructure or a verified malicious attachment indicator.

A weak heuristic must not receive the same evidential weight as a highly reliable independent confirmation without justification.

## 9.2 Negative evidence weight: \(s\)

This is the accumulated weight of evidence against the proposition.

For the same proposition, evidence against maliciousness may include a relevant benign explanation or verified contextual information.

A valid SPF result does not necessarily constitute evidence that an email is benign; the result must be relevant to the proposition.

## 9.3 Prior weight: \(W\)

This parameter controls how much uncertainty remains relative to the accumulated evidence.

A larger \(W\) produces more uncertainty for fixed \(r\) and \(s\).

The exact interpretation and value of \(W\) depend on the selected opinion model. It must be documented and consistently applied.

It is not the same parameter as the base rate \(a\).

## 9.4 Example

Suppose the evidence model has:

\[
r=6,\quad s=2,\quad W=2
\]

Then:

\[
b=\frac{6}{6+2+2}=0.60
\]

\[
d=\frac{2}{6+2+2}=0.20
\]

\[
u=\frac{2}{6+2+2}=0.20
\]

The masses sum to one.

With \(a=0.10\):

\[
P=0.60+(0.10\times0.20)=0.62
\]

The arithmetic is deterministic. However, the evidential meaning of the result depends on how \(r\), \(s\), \(W\), and \(a\) were defined.

**Do not directly substitute \(c_i\) into \(r\) or \(s\) unless the conversion is explicitly justified and validated.**

The risk contribution formula and the Subjective Logic evidence mapping are separate components.

---

# 10. Determining the Base Rate \(a\)

The base rate represents the prior probability of the proposition before incorporating the evidence used in the opinion.

For the proposition "the email is malicious," possible sources include:

1. A representative labeled dataset matching the intended deployment environment.
2. A documented prior estimate from an applicable population.
3. An explicit configuration default used during early development.

The base rate must not be selected merely because it makes results look plausible.

## 10.1 Empirical estimate

If the labeled dataset contains \(N_M\) malicious messages out of \(N\) messages, a simple estimate is:

\[
\hat{a}=\frac{N_M}{N}
\]

This estimate is only appropriate when the dataset reasonably represents the target population.

A dataset deliberately balanced between benign and malicious emails may not reflect real-world prevalence. Its raw class proportion should not automatically be used as the deployment base rate.

For small datasets, a documented smoothing or Bayesian estimation method may be preferable to a raw ratio.

## 10.2 Configuration

The base rate should be associated with:

- The proposition.
- The target population.
- The dataset or source used.
- The estimation method.
- The date and version.
- The conditions under which it is applicable.

If no defensible prior is available, use a clearly documented provisional base rate and disclose that the resulting projected probability is not calibrated.

---

# 11. Fusion of Subjective Opinions

Combining evidence opinions requires more than applying the projection formula.

The fusion operator depends on the relationship between evidence sources and the assumptions of the selected Subjective Logic variant.

Before fusing opinions, establish:

1. Whether they concern the same proposition.
2. Whether they derive from distinct evidence.
3. Whether one source copied or depends on another.
4. Whether the source reliabilities are accounted for.
5. Whether the selected fusion operator's assumptions hold.
6. How contradictory evidence is represented.
7. How unavailable evidence is handled.

Do not use a consensus operator that assumes independent evidence when the observations are correlated.

If independence cannot be justified, retain separate opinions or use a suitable dependence-aware method with documented assumptions.

The implementation should name the chosen operator, document its assumptions, and include a reproducible worked example in code documentation.

No fusion operator should be described as universally correct.

---

# 12. Confidence, Uncertainty, and Evidence Coverage

These are separate concepts.

## 12.1 Uncertainty

In a Subjective Logic opinion, \(u\) is the uncommitted belief mass under the specified opinion model.

A higher \(u\) generally means that more belief mass remains uncommitted.

It does not automatically measure every possible source of model or data uncertainty.

## 12.2 Confidence

The word `confidence` must not be used as a generic number that duplicates the risk score.

If the API reports confidence, its definition must be explicit.

Possible definitions include:

- A model's calibrated probability for a specified class.
- A documented reliability estimate for a particular detector.
- A separately defined measure of support for a conclusion.

These are different quantities and must not share a field without a clear contract.

## 12.3 Evidence coverage

Evidence coverage can be calculated deterministically from an explicit checklist of applicable checks.

For example:

\[
\boxed{\text{Coverage}=\frac{N_{\text{completed applicable checks}}}{N_{\text{applicable checks}}}}
\]

If 8 of 10 applicable checks complete successfully:

\[
\text{Coverage}=\frac{8}{10}=0.8
\]

Coverage is 80%.

The checklist must define what counts as applicable and what counts as completed. An unavailable external provider should be marked unavailable rather than silently counted as a successful check.

Coverage is not confidence and is not a probability of maliciousness.

If no checks are applicable, coverage should be reported as unavailable or handled by an explicit documented rule rather than dividing by zero.

---

# 13. Missing Data and Failed Checks

The system must distinguish:

- `pass`
- `fail`
- `not_present`
- `not_evaluated`
- `insufficient_data`
- `timeout`
- `provider_unavailable`
- `parse_error`
- `inconclusive`

These states must not collapse into a single boolean.

Examples:

- No DKIM signature is not the same as a failed DKIM signature.
- A DNS timeout is not the same as an SPF failure.
- An unavailable threat-intelligence provider is not a benign reputation result.
- A malformed header is not automatic proof of maliciousness.
- A missing attachment scanner does not imply an attachment is safe.

If the evidence required for a numeric parameter is unavailable, the parameter should remain unavailable or follow a documented conservative policy. It must not be assigned a fake value simply to complete a formula.

---

# 14. Deterministic Findings and External Intelligence

## 14.1 Deterministic findings

Examples include:

- URL parses to an IP-literal hostname.
- A hostname contains a configured suspicious structural pattern.
- A header field is absent.
- Two normalized domain strings differ.
- A message's SHA-256 digest is calculated from its bytes.
- A signature verification function returns a specific status.

A deterministic rule must define the exact condition and result.

The fact that a rule is deterministic does not establish that its interpretation is always correct.

## 14.2 External intelligence

External services may return:

- Reputation scores.
- Malicious/benign classifications.
- Known phishing indicators.
- Malware hashes.
- Domain or IP intelligence.

For each result, retain the provider, lookup timestamp, queried indicator, response status, and source-provided values.

Do not treat a provider's score as a universal probability. Normalize provider data only through a documented mapping.

If a provider's numeric scale is unknown or incompatible, retain its original value and do not force it into the same numeric range without justification.

## 14.3 Machine-learning outputs

An ML model may return a raw score or probability-like output.

The backend must record:

- Model identifier and version.
- Feature-processing version.
- Output type.
- Training/evaluation context, where available.
- Calibration status.
- Limitations.

A raw model score is not necessarily a probability. If probability calibration is required, use a suitable calibration method on validation data and assess it on held-out data.

---

# 15. Worked End-to-End Example

Consider an illustrative message with two findings:

1. A URL matches a suspicious structural heuristic.
2. A separately verified finding supports a benign explanation.

Assume the configured values are:

| Parameter | Finding A | Finding B |
|---|---:|---:|
| Weight | 8 | 5 |
| Severity | 0.75 | 0.60 |
| Reliability | 0.90 | 0.80 |

Finding A contributes:

\[
c_A=8\times0.75\times0.90=5.4
\]

Finding B contributes:

\[
c_B=5\times0.60\times0.80=2.4
\]

If Finding A supports the maliciousness hypothesis and Finding B is genuinely relevant contradictory evidence:

\[
C_S=5.4,\quad C_D=2.4
\]

With the illustrative mitigation factor \(\lambda=1\):

\[
R_{\text{raw}}=\max(0,5.4-2.4)=3.0
\]

If the configured maximum raw score is \(M=20\):

\[
R=\min\left(100,\frac{100\times3.0}{20}\right)
\]

\[
\boxed{R=15}
\]

This would map to the initial Low band.

However, the result is valid only if:

- The evidence directions are correctly assigned.
- The findings are not incorrectly treated as independent.
- The configured weights and severity mappings are appropriate.
- The maximum raw score is defined consistently.
- The example's illustrative values are not mistaken for validated parameters.

This example demonstrates the arithmetic, not the scientific validity of the chosen values.

A separate Subjective Logic opinion must be constructed using its own documented evidence model. The score of 15 must not simply be converted to \(b=0.15\) without a validated mapping.

---

# 16. Reproducibility

Each investigation should record enough information to reproduce its calculations.

At minimum:

- Original artifact SHA-256.
- Analysis timestamp.
- Parser version.
- Rule-set version.
- Risk configuration version.
- Evidence-generation method versions.
- Model version, if applicable.
- External-provider results and timestamps.
- Evidence dependencies.
- Scoring formula version.
- Subjective Logic mapping and fusion method version, if used.
- Base-rate source and version.
- Any missing or failed checks.
- Final calculation inputs and outputs.

The same artifact analyzed with the same configuration and the same recorded external results should produce the same deterministic results, except where an explicitly documented nondeterministic component exists.

Do not silently change the weights, thresholds, or model versions used for a stored historical assessment.

---

# 17. Evaluation and Calibration

The system must validate its parameters using suitable data rather than relying on intuition.

## 17.1 Detection metrics

Where labeled data is available, measure:

\[
\text{Precision}=\frac{TP}{TP+FP}
\]

\[
\text{Recall}=\frac{TP}{TP+FN}
\]

\[
F_1=2\times\frac{\text{Precision}\times\text{Recall}}{\text{Precision}+\text{Recall}}
\]

Where:

- \(TP\): true positives.
- \(FP\): false positives.
- \(FN\): false negatives.

The implementation must handle zero denominators explicitly.

## 17.2 Calibration

If the system produces probability estimates, evaluate whether predictions correspond to observed frequencies using appropriate calibration methods and metrics.

Do not calibrate on the final test set.

## 17.3 Ablation studies

Compare the system with components removed:

- Without URL heuristics.
- Without authentication analysis.
- Without external intelligence.
- Without evidence dependency handling.
- Without Subjective Logic.
- Without ML, where an ML component exists.

This helps establish whether a component improves results rather than merely increasing system complexity.

## 17.4 Temporal and cross-dataset evaluation

Test whether results remain useful across different datasets and time periods.

Email campaigns, sender infrastructure, and attacker techniques change over time. A model or rule set that performs well on one dataset may not generalize.

## 17.5 Weight and threshold selection

Use training/validation data for selecting weights and thresholds. Keep a held-out test set for final evaluation.

Document the selected objective, such as minimizing false positives subject to an acceptable recall level, rather than optimizing a metric without considering operational costs.

---

# 18. Required Backend Behavior

The implementation should satisfy the following operational requirements.

1. Every risk-scored finding has a documented rule or method.
2. Every numeric parameter has a recorded origin.
3. Severity and reliability remain separate.
4. Every contribution can be recomputed from its stored inputs.
5. Overall aggregation and normalization are explicit and versioned.
6. Risk scores are not presented as probabilities.
7. Subjective Logic opinions satisfy the required constraints.
8. The mapping from evidence to opinions is documented.
9. The base rate has a documented source or is explicitly provisional.
10. Fusion operators are chosen according to documented assumptions.
11. Correlated evidence is not automatically double-counted.
12. Missing data is represented explicitly.
13. External-provider failures do not create fabricated findings.
14. Findings explain both their interpretation and their limitations.
15. Private investigations are protected by backend authorization.
16. Historical analyses retain the configuration and method versions used.
17. No fake confidence, reputation, or probability values are returned.
18. The backend remains useful when optional ML or external services are unavailable.

---

# 19. Implementation Priority

Implement the mathematics in the following order.

### Phase 1: Evidence normalization

Create a consistent evidence schema with observation, source, method, status, severity, reliability, direction, provenance, and dependency references.

### Phase 2: Deterministic parameters

Create versioned configuration for rule severity and category weights. Create a method-reliability registry and explicitly mark provisional values.

### Phase 3: Contribution calculation

Implement:

\[
c_i=w_i\times s_i\times r_i
\]

Return the inputs and result for every scored finding.

### Phase 4: Aggregation

Implement dependency handling, supporting/contradictory evidence, raw score aggregation, and explicit normalization to 0–100.

### Phase 5: Explanations

Generate explanations directly from actual findings and calculations. Do not use fabricated values to fill missing fields.

### Phase 6: Subjective Logic

Implement opinion construction only after defining the proposition, evidence mapping, prior weight, base rate, and fusion assumptions.

### Phase 7: Evaluation

Validate severity mappings, reliability estimates, weights, risk thresholds, uncertainty behavior, and calibration using suitable data.

### Phase 8: Reproducibility

Store configuration and method versions with each analysis so historical assessments can be understood and recalculated.

---

# 20. Final Principle

S.H.I.E.L.D. is not intended to be a collection of arbitrary heuristics wrapped in mathematical notation.

Its value comes from making every conclusion traceable:

**Observed fact → documented rule → numeric parameters → explicit calculation → qualified interpretation.**

The evidence contribution formula provides transparency. The aggregation layer turns contributions into a bounded risk index. Subjective Logic represents uncertainty under explicit assumptions. Empirical evaluation determines whether these mechanisms are actually useful.

No numeric value is scientifically justified merely because it appears in an equation.

**Every parameter must have a defined origin, every formula must have a clear meaning, every assumption must be documented, and every conclusion must remain traceable to its evidence.**