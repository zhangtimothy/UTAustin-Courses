import json
import time
import urllib.parse as urlparse

from .utils import *

FORM_ENC_HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

class OAuthClient:

	def __init__(self, client_id):
		self.client_id = client_id
		self.grant_type = 'authorization_code'
		self.redirect_uri = None
		self.scope = None
		self.state_token = None
		self.code = None
		self.expires_in = None
		self.expires_at = None
		self.access_token = None
		self.token_type = None

	def prepare_authorization_request_uri(self, uri, redirect_uri, scope, state_token):
		"""Prepare the authorization code request URI."""
	    # 1. Prepare a list of tuples with all the parameters
	    #    to be added to the request.
	    #    These parameters are : response_type, client_id,
	    #                           redirect_uri, scope, state
	    # 2. Use urlparse.urlparse to extract the query from the uri input
	    # 3. Use add_params_to_qs() to add parameters to the query
	    # 4. Use urlparse.urlunparse to construct the uri again
	    # 5. Take care to populate the necessary member variables during processing.
	    #    See the unpopulated variables in the __init__ function.
		params = [(('response_type', 'code')),
		      	  (('client_id', self.client_id))]
		#STUDENT TODO : START
		params.extend( [(('redirect_uri', redirect_uri)), (('scope', scope)), (('state', state_token))] )
		self.redirect_uri = redirect_uri
		self.scope = scope
		self.state_token = state_token
		url_parsed_obj = urlparse.urlparse(uri)
		query = url_parsed_obj.query
		self.expires_at = self.expires_in + time.time()
		sch = url_parsed_obj.scheme
		net = url_parsed_obj.netloc
		path = url_parsed_obj.path
		par = url_parsed_obj.params
		fra = url_parsed_obj.fragment
		query = add_params_to_qs(query, params)
		#STUDENT TODO : END
		return urlparse.urlunparse((sch, net, path, par, query, fra))

	def prepare_token_request(self, token_url, code):
		"""Prepare a token creation request."""
		# 1. Create a list of tuples with all the parameters
		#    to be added to the request
		#    These parameters include : grant_type, redirect_uri, code
		# 2. Use add_params_to_qs with an empty query to generate the body
		#    of the POST request to be sent afterwards
		# 3. The headers of the POST request are already provided to you
		#    See FORM_ENC_HEADERS at the top
		# 4. Take care to populate the necessary member variables during processing.
	        #    See the unpopulated variables in the __init__ function.
		params = [('grant_type', self.grant_type)]
		#STUDENT TODO : START
		params.extend( [('redirect_uri', self.redirect_uri), ('code', code)] )
		self.code = code
		self.access_token = token_url
		body = add_params_to_qs('', params)

		#STUDENT TODO : END
		return token_url, FORM_ENC_HEADERS, body

	def parse_request_body_response(self, body):
		"""Parse the JSON response body."""
		# Load the body using json.loads() and extract all the relevant
		# variables to populate any remaining member variables.
		# See the unpopulated variables in the __init__ function.
		# If you encounter key errors on accessing values in params, add corresponding
		# IF-ELSE statements to check the existence of the keys
		params = {}
		#STUDENT TODO : START
		params = json.loads(body)
		if 'client_id' in params:
			self.client_id = params['client_id']
		if 'grant_type' in params:
			self.grant_type = params['grant_type']
		if 'redirect_uri' in params:
			self.redirect_uri = params['redirect_uri']
		if 'scope' in params:
			self.scope = params['scope']
		if 'state_token' in params:
			self.state_token = params['state_token']
		if 'code' in params:
			self.code = params['code']
		if 'expires_in' in params:
			self.expires_in = params['expires_in']
			self.expires_at = self.expires_in + time.time()
		if 'expires_at' in params:
			self.expires_at = params['expires_at']
		if 'access_token' in params:
			self.access_token = params['access_token']
		if 'token_type' in params:
			self.token_type = params['token_type']

		#STUDENT TODO : END
		return params

	def add_token(self):
		"""Add token to the request authorization header."""
		# Create a dictionary to store the headers for the request
		# to fetch information from the user info endpoint
		# Set the 'Authorization' key of the headers dictionary to the concatenation
		# of the token type of the access token, along with the access token
		headers = {}
		#STUDENT TODO : START
		headers['Authorization'] = self.token_type + self.access_token
		#STUDENT TODO : END

		return headers

	def print(self,):
		print("Client ID", self.client_id)
		print("Grant Type", self.grant_type)
		print("Redirect URI", self.redirect_uri)
		print("Scope", self.scope)
		print("State Token", self.state_token)
		print("Code", self.code)
		print("Expires In", self.expires_in)
		print("Expires At", self.expires_at)
		print("Access Token", self.access_token)
		print("Token Type", self.token_type)
