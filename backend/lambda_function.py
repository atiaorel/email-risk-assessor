import base64
import hmac
import json
import logging
import os

from scorer import analyze_email


logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_ENV_NAME = "ADDON_SECRET"
SECRET_HEADER_NAME = "x-addon-secret"


def build_response(status_code, payload):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(payload, ensure_ascii=False)
    }


def get_header(event, header_name):
    headers = event.get("headers", {}) if isinstance(event, dict) else {}

    if not isinstance(headers, dict):
        return ""

    wanted_header = header_name.lower()

    for key, value in headers.items():
        if str(key).lower() == wanted_header:
            return str(value)

    return ""


def is_authorized(event):
    expected_secret = os.environ.get(SECRET_ENV_NAME, "")
    provided_secret = get_header(event, SECRET_HEADER_NAME)

    if not expected_secret:
        logger.warning("Request rejected: ADDON_SECRET is not configured")
        return False

    return hmac.compare_digest(provided_secret, expected_secret)


def parse_json_body(event):
    body = event.get("body", "") if isinstance(event, dict) else ""

    if not body:
        return {}

    if event.get("isBase64Encoded", False):
        body = base64.b64decode(body).decode("utf-8")

    if isinstance(body, str):
        return json.loads(body)

    if isinstance(body, dict):
        return body

    return {}


def lambda_handler(event, context):
    logger.info("Email risk assessment request received")

    if not is_authorized(event):
        logger.warning("Request rejected: unauthorized")
        return build_response(401, {
            "error": "Unauthorized"
        })

    try:
        input_data = parse_json_body(event)
        result = analyze_email(input_data)

        triggered_indicators = []
        for reason in result.get("reasons", []):
            if isinstance(reason, str):
                triggered_indicators.append(reason[:80])

        logger.info(
            "Email risk assessment completed | score=%s | indicators=%s",
            result.get("score", "unknown"),
            " | ".join(triggered_indicators)
        )

        return build_response(200, result)

    except json.JSONDecodeError:
        logger.warning("Request rejected: invalid JSON body")
        return build_response(400, {
            "error": "Invalid JSON body"
        })

    except Exception:
        logger.exception("Email risk assessment failed without logging email content")
        return build_response(500, {
            "error": "Internal server error"
        })