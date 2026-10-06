# Web Security Header Audit Tool

A defensive Python security tool for auditing HTTP response headers against a defined set of common web security controls.

**Author:** Ian Kipkorir  
**Project type:** Independent cybersecurity portfolio project  
**Language:** Python  
**Status:** Reference implementation

## Overview

Web applications rely on HTTP response headers to communicate security-related policies to browsers.

Missing or improperly configured security headers can increase exposure to risks such as clickjacking, content injection, MIME-type confusion, excessive referrer disclosure, and unnecessary browser feature access.

This project provides a small, transparent audit tool that evaluates supplied HTTP response headers against a predefined security checklist.

The tool produces:

- A security-header score from 0–100.
- An overall configuration rating.
- Individual findings for each checked header.
- Severity classifications.
- Security recommendations.

The project is intentionally designed as a **defensive assessment tool**. It analyzes supplied header data and does not attempt to exploit systems or perform unauthorized scanning.

## Security Headers Evaluated

The current implementation checks six security controls:

| Header | Purpose | Severity |
|---|---|---|
| `Content-Security-Policy` | Helps restrict permitted content sources and reduce certain injection risks. | High |
| `Strict-Transport-Security` | Helps enforce HTTPS connections. | High |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing. | Medium |
| `X-Frame-Options` | Helps control framing and reduce clickjacking risk. | Medium |
| `Referrer-Policy` | Controls referrer information sent with requests. | Low |
| `Permissions-Policy` | Controls access to selected browser capabilities. | Low |

## How It Works

The workflow is intentionally simple:

```text
HTTP header dataset
        |
        v
Header normalization
        |
        v
Security control checks
        |
        v
Findings and severity classification
        |
        v
Security score and recommendations

The tool does not automatically determine whether a website is secure. Instead, it provides a repeatable first-level configuration assessment that can be reviewed by a security professional.

Project Structure
web-security-header-audit/
├── README.md
├── LICENSE
├── .gitignore
├── examples/
│   └── sample_headers.json
└── src/
    └── header_auditor.py
Requirements
Python 3.8 or later
No third-party Python packages are required.

The project uses Python's standard library.

Running the Audit

From the repository root, run:

python src/header_auditor.py examples/sample_headers.json

The tool reads the supplied JSON header dataset and generates a human-readable security assessment.

Example Input

The sample dataset contains representative HTTP security headers:

{
  "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Referrer-Policy": "strict-origin-when-cross-origin"
}

Permissions-Policy is intentionally omitted from the sample so that the tool demonstrates how a missing security control is reported.

Example Assessment

A typical result includes:

Web Security Header Audit
============================================================
Security header score: 83.33/100
Overall rating: Good
Headers present: 5/6

Findings:
------------------------------------------------------------
Header: content-security-policy
Status: Present
Severity: High

Header: strict-transport-security
Status: Present
Severity: High

Header: x-content-type-options
Status: Present
Severity: Medium

Header: x-frame-options
Status: Present
Severity: Medium

Header: referrer-policy
Status: Present
Severity: Low

Header: permissions-policy
Status: Missing
Severity: Low

The exact output may change as the dataset or assessment logic evolves.

Scoring Model

The score represents the proportion of the defined security controls that are present.

score = (security controls present / security controls checked) × 100

The current rating thresholds are:

Score	Rating
90–100	Strong
75–89.99	Good
50–74.99	Needs Improvement
0–49.99	Weak

The score is an assessment aid and should not be interpreted as a complete security rating.

Security Assessment Methodology

The project follows a simple defensive methodology:

1. Normalize

Header names are converted to lowercase so that comparisons are case-insensitive.

2. Identify Controls

The supplied headers are compared against the project's defined security-control checklist.

3. Classify Findings

Each control is classified as either present or missing and assigned a predefined severity.

4. Generate Recommendations

Missing controls receive a recommendation for review and appropriate configuration.

5. Produce an Overall Assessment

The tool calculates a transparent score based on the number of controls present.

Security Considerations

This project is deliberately limited in scope.

It does not:

exploit vulnerabilities;
perform penetration testing;
attempt authentication bypass;
execute JavaScript from external websites;
download arbitrary web content;
perform unauthorized network scanning;
collect credentials;
require API keys or secrets.

The input is treated as data rather than executable content.

Limitations

Security headers alone cannot establish that an application is secure.

For example:

A present Content-Security-Policy may still be poorly designed.
Strict-Transport-Security configuration depends on deployment requirements.
X-Frame-Options and CSP framing controls may need to be considered together.
A missing header does not automatically mean that a vulnerability exists.
The tool does not inspect application code, server configuration, TLS settings, authentication, authorization, or business logic.

Therefore, this tool should be considered a configuration-assessment aid, not a complete vulnerability scanner.

Responsible Use

This project is intended for:

security education;
defensive security assessment;
development and security review;
controlled testing environments;
portfolio demonstration.

Only assess systems for which you have authorization.

The sample data in this repository is synthetic and is not presented as evidence of testing a third-party production system.

Future Improvements

Potential future improvements include:

Additional security-header checks.
Configurable security policies.
More detailed CSP analysis.
Automated unit and integration tests.
Structured JSON reporting.
HTML report generation.
Evidence and remediation tracking.
CI-based regression testing.
Optional analysis of authorized HTTP response data.
Integration with secure development workflows.
Professional Relevance

This project demonstrates practical experience with:

Python security tooling.
HTTP security controls.
Security configuration assessment.
Risk classification.
Defensive security practices.
Input validation.
Automated reporting.
Security documentation.
Responsible and authorized security testing.
Disclaimer

This is an independent cybersecurity portfolio project created for educational and professional demonstration purposes.

It does not represent a security assessment performed for an employer, customer, vendor, or third party unless explicitly stated elsewhere with supporting authorization and documentation.

Author

Ian Kipkorir
