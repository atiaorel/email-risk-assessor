# Email Risk Assessor

A Gmail Add-on that analyzes opened emails and returns an explainable phishing-risk score.

The add-on extracts selected security-relevant email metadata, sends it to an AWS Lambda backend, and displays a clear risk score, verdict, reasoning, and recommendation directly inside Gmail.

## Architecture

```text
Gmail Add-on
  - Runs inside Gmail when the user opens an email
  - Displays the phishing-risk result in the Gmail side panel
  - Renders the score, verdict, recommendation, and reasons

        ↓

Google Apps Script Layer
  - Extracts selected email metadata
  - Detects urgent/social-engineering language locally
  - Sends a minimal JSON payload to the backend
  - Adds the X-Addon-Secret header to authorize the request

        ↓

AWS Lambda Backend
  - Validates the shared secret before analysis
  - Runs the rule-based phishing scoring engine
  - Checks sender authentication, links, attachments, and domain signals
  - Returns an explainable JSON result
```

The add-on focuses on email extraction and user-facing presentation, while AWS Lambda owns request validation and phishing-risk scoring. This separation keeps the Gmail UI lightweight and allows the backend detection logic to evolve independently.

## Features

- Gmail Add-on UI shown directly inside an opened email.
- AWS Lambda backend for serverless email risk analysis.
- Explainable rule-based phishing score.
- Clear verdict, score, color, reasons, and recommendation.
- Shared-secret protection between Apps Script and Lambda.
- Data minimization: the raw email body is not sent to the backend.
- Safe handling of untrusted email input with text-length limits.

## Detection Signals

The scorer currently checks for:

- SPF, DKIM, and DMARC authentication failures.
- External URL reputation using Google Safe Browsing.
- Urgent or social-engineering language.
- Shortened URLs.
- Risky attachment types.
- Sender-name impersonation.
- Lookalike / typosquat sender domains.
- Brand spoofing inside link URLs.
- Sender vs Reply-To domain mismatch.

## Security Considerations

- Email data is treated as untrusted input.
- The add-on follows a data minimization approach: the raw email body is not sent to the backend.
- Urgent/social-engineering language is detected in the Google Apps Script layer, and only a boolean signal is sent to AWS Lambda.
- URL reputation checks may send extracted URLs to an external threat-intelligence provider.
- Text fields are clamped to maximum lengths before analysis.
- The backend does not store email content.
- The Lambda endpoint requires a shared secret sent in the `X-Addon-Secret` header.
- Secrets are stored in Apps Script Properties and Lambda environment variables, not in source code.
- Logs avoid printing full email content or full request payloads.

## Design Decisions and Trade-offs

### Rule-based scoring instead of machine learning

I chose a rule-based scoring engine for the MVP because explainability was more important than model complexity. In a phishing-risk add-on, the user should not only see a score, but also understand why the email was flagged. A rule-based approach makes each verdict traceable to concrete indicators such as authentication failures, shortened URLs, risky attachments, sender impersonation, Safe Browsing matches, and Reply-To mismatches.

The trade-off is that rule-based detection is less adaptive than a machine learning model and may miss more subtle attacks. With more time, I would add reputation-based and ML-based signals as additional layers, while keeping the explanations visible to the user.

### Separation between the Gmail Add-on and the backend

I separated the Gmail Add-on from the backend so each layer has a clear responsibility. The add-on extracts selected email metadata and presents the result inside Gmail, while AWS Lambda owns the scoring logic, request validation, and backend security checks.

This separation keeps the UI lightweight, allows the backend logic to evolve independently, and avoids putting all detection logic directly inside the add-on layer. It also makes it easier to add future backend capabilities such as richer URL reputation checks, metrics, rate limiting, or stronger authentication.

### Shared secret instead of full user authentication

For this MVP, I used a shared secret between Apps Script and AWS Lambda. The add-on sends the secret in the `X-Addon-Secret` header, and Lambda compares it against an environment variable before analyzing the request.

This is a pragmatic protection layer for a small assignment: it prevents unauthenticated random access to the public Lambda Function URL without adding the complexity of a full identity system. The trade-off is that a shared secret does not identify individual users and would not be sufficient for a production multi-user system. In production, I would replace or complement it with stronger authentication, request signing, per-user authorization, and rate limiting.

### Data minimization trade-off

I applied a data minimization approach by moving urgent/social-engineering keyword detection into the Google Apps Script layer. Instead of sending the raw email body to AWS Lambda, the add-on sends only a boolean signal: `has_urgent_language`.

This reduces sensitive email content exposure and keeps the backend from receiving unnecessary raw message text. The trade-off is that part of the detection logic now lives in the add-on layer, which is less ideal for hiding detection rules and makes future advanced text analysis harder. I accepted this trade-off because privacy and minimal data exposure were more important for this MVP.

### External URL reputation trade-off

I added Google Safe Browsing as an external URL reputation signal. This improves detection by checking whether extracted URLs are known to be potentially unsafe.

The trade-off is that URLs may be sent to a third-party service for reputation checks. To keep the system reliable, Safe Browsing is implemented as an optional signal with a short timeout and fail-open behavior: if the API is unavailable, the system continues with the local rule-based checks.

## Scoring Model

The backend uses an additive, explainable scoring model. Each triggered phishing indicator contributes a predefined number of points to the total score. Examples of signals include authentication failures, urgent language, shortened URLs, risky attachments, sender impersonation, URL brand spoofing, Google Safe Browsing matches, and Reply-To mismatches.

The final score is capped at 100 and mapped to a user-facing verdict:

- `0–30`: Low Risk
- `31–65`: Suspicious
- `66–100`: High Risk

The goal of this model is not only to classify the email, but also to explain the classification. Every score is accompanied by a list of reasons, so the user can understand which indicators affected the result.

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
```

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

- The system is rule-based and does not use machine learning. This makes the output explainable, but less adaptive to novel or subtle phishing techniques.
- Gmail Add-ons cannot analyze messages already blocked by Gmail as spam or suspicious.
- Link analysis checks the URL itself, but does not compare visible link text against the actual href.
- Google Safe Browsing is used as an optional external signal. If the API is unavailable, the system fails open and continues with local rules.
- Google Safe Browsing fail-open behavior is silent. If the external reputation check is skipped because of timeout, missing API key, or API failure, the user is not explicitly notified.
- The current MVP does not implement request rate limiting. The Lambda endpoint is protected by a shared secret, but a production system should add rate limiting, abuse detection, and possibly API Gateway or WAF-level protections.
- The shared secret is suitable for this MVP, but a production system would use stronger authentication and authorization.

## Future Improvements

- Add CI/CD with GitHub Actions for automatic Lambda deployment.
- Add clasp-based deployment for Apps Script.
- Add stronger authentication and per-user authorization.
- Add API Gateway or WAF-level rate limiting and abuse protection.
- Add richer URL and domain reputation checks.
- Strip or normalize sensitive URL query parameters before external reputation checks where possible.
- Add optional storage of anonymized aggregate metrics.
- Add a more detailed dashboard for triggered indicators.
- Add visible-link-text vs actual-href mismatch detection.

## Status

The add-on is deployed to a real Gmail account and the backend runs on AWS Lambda.