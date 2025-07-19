"""
Original Script is Copyright 2019 Jason Hu <awaregit at gmail.com>
Modified in 2025 by dizzybeaver with the assistance of AI for enhanced responce time and lower latency.


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

# ------------------------
# 🌐 Configuration & Setup
# ------------------------

# Load environment variables
BASE_URL = os.environ.get('BASE_URL')
LONG_LIVED_ACCESS_TOKEN = os.environ.get('LONG_LIVED_ACCESS_TOKEN')
NOT_VERIFY_SSL = os.environ.get('NOT_VERIFY_SSL', '0') == '1'
VERIFY_SSL = not NOT_VERIFY_SSL
DEBUG_MODE = os.environ.get('DEBUG', '0') == '1'

# Validate environment variables
if not BASE_URL:
    raise EnvironmentError('Missing BASE_URL environment variable')
if not LONG_LIVED_ACCESS_TOKEN:
    raise EnvironmentError('Missing LONG_LIVED_ACCESS_TOKEN environment variable')

# Configure logger
logger = logging.getLogger('HomeAssistant-SmartHome')
logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.WARNING)
logger.propagate = False
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())

# Initialize urllib3 PoolManager with SSL verification setting
http = urllib3.PoolManager(
    num_pools=10,
    maxsize=10,
    retries=urllib3.Retry(3),
    timeout=urllib3.Timeout(connect=2.0, read=10.0),
    cert_reqs='CERT_REQUIRED' if VERIFY_SSL else 'CERT_NONE'
)

# ------------------------
# 🚀 Lambda Handler
# ------------------------

def lambda_handler(event, context=None):
    if DEBUG_MODE:
        logger.debug('Received event: %s', json.dumps(event, indent=2))
    
    # Validate payload version
    payload_version = event.get('directive', {}).get('header', {}).get('payloadVersion', '')
    if payload_version != '3':
        raise ValueError('Only payloadVersion 3 is supported')
        
    directive = event['directive']
    endpoint = directive.get('endpoint', {})
    payload = directive.get('payload', {})

    # Extract scope and token
    scope = endpoint.get('scope') or payload.get('scope') or payload.get('grantee')
    if not scope or scope.get('type') != 'BearerToken':
        return _error_response('INVALID_AUTHORIZATION_CREDENTIAL', 'Missing or unsupported scope')

    token = scope.get('token') or (DEBUG_MODE and LONG_LIVED_ACCESS_TOKEN)
    if not token:
        return _error_response('INVALID_AUTHORIZATION_CREDENTIAL', 'Missing token')

    # Prepare headers with token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    url = f'{BASE_URL}/api/alexa/smart_home'

    # Perform request
    try:
        response = http.request(
            'POST',
            url,
            body=json.dumps(event),
            headers=headers,
            timeout=urllib3.Timeout(connect=2.0, read=10.0)
            # Removed verify, SSL handled by PoolManager setup
        )
        if DEBUG_MODE:
            logger.debug('Response status: %s', response.status)
            logger.debug('Response data: %s', response.data.decode('utf-8'))
    except urllib3.exceptions.RequestError as e:
        logger.exception('Request to Home Assistant failed')
        return _error_response('INTERNAL_ERROR', str(e))
    
    # Handle HTTP errors
    if response.status >= 400:
        error_type = 'INVALID_AUTHORIZATION_CREDENTIAL' if response.status in (401, 403) else 'INTERNAL_ERROR'
        return _error_response(error_type, response.data.decode('utf-8'))

    # Parse JSON response
    try:
        return json.loads(response.data.decode('utf-8'))
    except json.JSONDecodeError:
        return _error_response('INTERNAL_ERROR', 'Invalid JSON response from server')

# ------------------------
# ❌ Error Response Helper
# ------------------------

def _error_response(error_type, message):
    return {
        'event': {
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
    os.environ['BASE_URL'] = 'https://your-home-assistant-url.com'
    os.environ['LONG_LIVED_ACCESS_TOKEN'] = 'your-long-lived-token'
    os.environ['DEBUG'] = '1'
    # os.environ['NOT_VERIFY_SSL'] = '1'  # Uncomment if self-signed SSL

    # Example test event
    test_event = {
        "directive": {
            "header": {
                "namespace": "Alexa",
                "name": "ReportState",
                "payloadVersion": "3",
                "messageId": "abc-123"
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": "debug-token-if-in-debug"
                },
                "endpointId": "endpoint-001"
            },
            "payload": {}
        }
    }

    print("🔧 Running local test...")
    result = lambda_handler(test_event)
    print(json.dumps(result, indent=2))
