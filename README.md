# HA_LAMBDA_CODE
Last verified version Python working: 3.13
Tip: Set runtime to ARM for an up to 20% performance boost.

My setup is:
Cloudflare Tunnel - Make sure to disable Bot Fight mode on domain or it will block all your requests.
Amazon AWS and Alexa developer

What is needed in AWS:

The following variables are declared at the global (module) level and are necessary for the script to function properly:

Environment Variables (configuration):

BASE_URL: The base URL for the API (os.environ.get('BASE_URL')) 
Example: https://my.domain.name

LONG_LIVED_ACCESS_TOKEN: The access token (os.environ.get('LONG_LIVED_ACCESS_TOKEN'))
This variable is only used when DEBUG_MODE is set to '1'

NOT_VERIFY_SSL: Boolean flag indicating whether to skip SSL verification (os.environ.get('NOT_VERIFY_SSL', '0') == '1')

DEBUG_MODE: Boolean for debug logging (os.environ.get('DEBUG', '0') == '1')

While in AWS and in code view, please Test the script after deployment. If you get a successful result you should have no issues linking in the Alexa App.

After setting these variables and doing any other setup required for the original script, you should be able to successfully link thru your Alexa app and discover devices.

Optional:
1. Set runtime to 
