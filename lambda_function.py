"""
Complete rewrite in 2025 by dizzybeaver.
Version: 1
Subversion:8-2025
Varient: Requires no Amazon Secret

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
    
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os
import json
import logging
import urllib3
from typing import Dict, Any

# ------------------------
# 🌐 Constants
# ------------------------
# Using constants for "magic strings" improves readability and maintainability.
SUPPORTED_PAYLOAD_VERSION = '3'
HEADER_CONTENT_TYPE = 'application/json'

# ------------------------
# 🌐 Configuration & Setup
# ------------------------

# Load environment variables with sensible defaults.
BASE_URL = os.environ.get('BASE_URL')
LONG_LIVED_ACCESS_TOKEN = os.environ.get('LONG_LIVED_ACCESS_TOKEN')
# Default to verifying SSL; only disable if NOT_VERIFY_SSL is explicitly '1' or 'true'.
VERIFY_SSL = os.environ.get('NOT_VERIFY_SSL', 'false').lower() not in ('true', '1')
DEBUG_MODE = os.environ.get('DEBUG', 'false').lower() in ('true', '1')

# Validate essential environment variables upon cold start.
if not BASE_URL:
    # Use ValueError for configuration errors that should fail the Lambda container initialization.
    raise ValueError('Missing required environment variable: BASE_URL')
if not LONG_LIVED_ACCESS_TOKEN:
    raise ValueError('Missing required environment variable: LONG_LIVED_ACCESS_TOKEN')

# --- Logger Setup ---
# AWS Lambda's runtime pre-configures the root logger.
# We just need to get it and set the desired level.
logger = logging.getLogger()
logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

# --- Connection Pooling (PERFORMANCE) ---
# This http object is created once per Lambda container (during a "cold start").
# It is then reused across subsequent invocations ("warm starts"), which is a
# critical performance optimization as it avoids the overhead of re-establishing
# TCP connections and SSL/TLS handshakes for every request.
try:
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED' if VERIFY_SSL else 'CERT_NONE',
        timeout=urllib3.Timeout(connect=2.0, read=10.0),
        retries=urllib3.Retry(total=3, backoff_factor=0.2)
    )
    if not VERIFY_SSL:
        # Suppress the InsecureRequestWarning if SSL verification is disabled.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception as e:
    logger.critical("Failed to initialize urllib3.PoolManager: %s", e)
    # If the pool manager fails to init, the function is non-operational.
    http = None

# ------------------------
# 🚀 Lambda Handler
# ------------------------

def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """
    Handles incoming Alexa Smart Home directives by proxying them to a
    Home Assistant instance.
    """
    if not http:
        # If the PoolManager failed to initialize, return a service unavailable error.
        return _create_error_response('INTERNAL_ERROR', 'The service is temporarily unavailable due to a configuration issue.')

    # Use .get() with default empty dicts for safe, nested access.
    directive = event.get('directive', {})
    header = directive.get('header', {})
    endpoint = directive.get('endpoint', {})
    payload = directive.get('payload', {})

    if DEBUG_MODE:
        # Use json.dumps for structured logging of the event.
        logger.debug("Received event: %s", json.dumps(event))

    # --- Input Validation ---
    if header.get('payloadVersion') != SUPPORTED_PAYLOAD_VERSION:
        message = f"Unsupported payloadVersion. Expected '{SUPPORTED_PAYLOAD_VERSION}', got '{header.get('payloadVersion')}'."
        logger.error(message)
        # Return a structured error, don't raise an exception that causes a 502.
        return _create_error_response('INVALID_DIRECTIVE', message)

    # --- Authorization ---
    # Gracefully handle various locations for the scope/token.
    scope = endpoint.get('scope') or payload.get('scope') or payload.get('grantee', {})
    token = scope.get('token')
    
    # In debug mode, allow fallback to the environment variable for local testing.
    if DEBUG_MODE and not token:
        token = LONG_LIVED_ACCESS_TOKEN

    if not token or scope.get('type') != 'BearerToken':
        logger.warning("Authorization failed: Missing or invalid BearerToken.")
        return _create_error_response('INVALID_AUTHORIZATION_CREDENTIAL', 'Missing or invalid BearerToken.')

    # --- Prepare and Send Request ---
    request_headers = {
        'Content-Type': HEADER_CONTENT_TYPE,
        'Authorization': f'Bearer {token}'
    }
    url = f'{BASE_URL}/api/alexa/smart_home'
    encoded_body = json.dumps(event).encode('utf-8')

    try:
        response = http.request(
            'POST',
            url,
            body=encoded_body,
            headers=request_headers
        )
        response_data = response.data.decode('utf-8')
        if DEBUG_MODE:
            logger.debug("Response Status: %s", response.status)
            logger.debug("Response Data: %s", response_data)

    except urllib3.exceptions.MaxRetryError as e:
        logger.exception("Request failed after multiple retries: %s", e.reason)
        return _create_error_response('ENDPOINT_UNREACHABLE', 'The target endpoint is unreachable.')
    except urllib3.exceptions.RequestError as e:
        logger.exception("An unhandled request error occurred.")
        return _create_error_response('INTERNAL_ERROR', f'A network error occurred: {e}')

    # --- Handle Response ---
    if response.status >= 400:
        if response.status in (401, 403):
            error_type = 'INVALID_AUTHORIZATION_CREDENTIAL'
            logger.warning("Home Assistant returned 401/403 Unauthorized.")
        else:
            error_type = 'INTERNAL_ERROR'
            logger.error("Home Assistant returned HTTP %d: %s", response.status, response_data)
        return _create_error_response(error_type, f'Upstream server returned status {response.status}')

    try:
        # The successful response from Home Assistant is the response of our Lambda.
        return json.loads(response_data)
    except json.JSONDecodeError:
        logger.exception("Failed to decode JSON response from Home Assistant.")
        return _create_error_response('INTERNAL_ERROR', 'The upstream server returned an invalid JSON response.')

# ------------------------
# ❌ Error Response Helper
# ------------------------

def _create_error_response(error_type: str, message: str) -> Dict[str, Any]:
    """Constructs a valid Alexa error response message."""
    return {
        'event': {
            'header': {
                # Consider adding a messageId and other relevant header fields if available from the request
                "namespace": "Alexa",
                "name": "ErrorResponse",
                "payloadVersion": "3"
            },
            'payload': {
                'type': error_type,
                'message': message
            }
        }
    }

# ------------------------
# 🧪 Local Debug Harness
# ------------------------

if __name__ == '__main__':
    # Set environment variables for local testing
    os.environ['BASE_URL'] = 'http://localhost:8123' # Use a real test instance
    os.environ['LONG_LIVED_ACCESS_TOKEN'] = 'your-long-lived-token-for-testing'
    os.environ['DEBUG'] = '1'
    os.environ['NOT_VERIFY_SSL'] = '1'  # Common for local Home Assistant instances

    # Example test event
    test_event = {
      "directive": {
        "header": {
          "namespace": "Alexa.Discovery",
          "name": "Discover",
          "payloadVersion": "3",
          "messageId": "1bd5d003-31b9-476f-ad03-71d471922820"
        },
        "payload": {
          "scope": {
            "type": "BearerToken",
            "token": "access-token-from-skill"
          }
        }
      }
    }

    print("🔧 Running local test...")
    result = lambda_handler(test_event, None)
    print("\n✅ Test Result:")
    print(json.dumps(result, indent=2))
