# Email Risk Assessor

A Gmail Add-on that analyzes opened emails and returns an explainable phishing-risk score.

The add-on extracts security-relevant email metadata, sends it to an AWS Lambda backend, and displays a clear risk score, verdict, reasoning, and recommendation directly inside Gmail.

## Architecture

Gmail Add-on → Google Apps Script → AWS Lambda → Rule-based phishing scorer

## Features

- Gmail Add-on UI shown directly inside an opened email
- AWS Lambda backend for serverless email risk analysis
- Explainable rule-based phishing score
- Clear verdict, score, color, reasons, and recommendation
- Shared-secret protection between Apps Script and Lambda
- Safe handling of untrusted email input with text-length limits

## Detection Signals

The scorer currently checks for:

- SPF, DKIM, and DMARC authentication failures
- External URL reputation checks using Google Safe Browsing
- Urgent or social-engineering language
- Shortened URLs
- Risky attachment types
- Sender-name impersonation
- Lookalike / typosquat sender domains
- Brand spoofing inside link URLs
- Sender vs Reply-To domain mismatch

## Security Considerations

- Email data is treated as untrusted input.
- The add-on follows a data minimization approach: the raw email body is not sent to the backend.
- URL reputation checks may send extracted URLs to Google Safe Browsing as an external threat-intelligence signal.
- Urgent/social-engineering language is detected in the Google Apps Script layer, and only a boolean signal is sent to AWS Lambda.
- Text fields are clamped to maximum lengths before analysis.
- The backend does not store email content.
- The Lambda endpoint requires a shared secret sent in the `X-Addon-Secret` header.
- Secrets are stored in Apps Script Properties and Lambda environment variables, not in source code.
- Logs avoid printing full email content or full request payloads.

## Response Format

The backend returns:

```json
{
  "score": 65,
  "verdict": "Suspicious",
  "color": "#EF6C00",
  "reasons": [
    "Contains social engineering / urgent language"
  ],
  "recommendation": "Exercise caution. Do not click links or download files unless verified."
}


## Project Structure

```text
backend/
  lambda_function.py
  scorer.py

apps-script/
  Code.gs
  appsscript.json

README.md
.gitignore
```

## Limitations

- The system is rule-based and does not use machine learning.
- Gmail Add-ons cannot analyze messages already blocked by Gmail as spam or suspicious.
- Link analysis checks the URL itself, but does not compare visible link text against the actual href.
- Google Safe Browsing is used as an optional external signal; if the API is unavailable, the system fails open and continues with local rules.
- The shared secret is suitable for this MVP, but a production system would use stronger authentication and authorization.

## Future Improvements

- Add CI/CD with GitHub Actions for automatic Lambda deployment.
- Add clasp-based deployment for Apps Script.
- Add richer URL reputation checks.
- Add optional storage of anonymized aggregate metrics.
- Add a more detailed dashboard for triggered indicators.

## Status

The add-on is deployed to a real Gmail account and the backend runs on AWS Lambda.