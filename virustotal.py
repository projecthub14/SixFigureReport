# standard library
import json
import urllib

# 3rd party libraries
import requests

# project libraries

class VirusTotal():
	def __init__(self, key):
		self.api_key = key
		self.base_url = 'https://www.virustotal.com/vtapi/v2'

	def _get_default_params(self):
		"""
		Return the default parameters required for all VirusTotal API requests
		"""
		return {
			'apikey': self.api_key,
			}

	def _make_http_request(self, url, params):
		"""
		Make an HTTP request to the specified VirusTotal API endpoint
		"""
		r = requests.get(url, params=params)
		if r.ok:
			return r.text
		else:
			return None

	def search_hash(self, h):
		"""
		Search VirusTotal for all information about the specified hash
		"""
		results = None

		url = "{}/file/report".format(self.base_url)
		params = self._get_default_params()
		params['resource'] = h
		response = self._make_http_request(url, params)

		if response:
			doc = json.loads(response)
			results = doc

		return results
	
	def search_ip(self, ip):
		"""
		Search VirusTotal for information about the specified URL
		"""
		results = None

		url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
		parameters = {'ip': ip, 'apikey': '9ca790fe3dde490e8fbb5190aa2b2b2ab2406f31e174eb51c37f74a8f88ef1a6'}
		response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()

		if response:
			doc = json.loads(response)
			results = doc

		return results

	def search_behaviour(self, h):
		"""
		Search VirusTotal for behavioural information about the specified hash

		* Only works with private API keys
		"""
		results = None

		url = "{}/file/behaviour".format(self.base_url)
		params = self._get_default_params()
		params['hash'] = h
		response = self._make_http_request(url, params)

		if response:
			doc = json.loads(response)
			results = doc

		return results
	
	def search_domain(self, domain):
		"""
		Search VirusTotal for information about the specified URL
		"""
		results = None

		url = 'https://www.virustotal.com/vtapi/v2/domain/report'
		params = self._get_default_params()
		params['domain'] = domain
		response = self._make_http_request(url, params)

		if response:
			doc = json.loads(response)
			results = doc

		return results

	def search_url(self, urls):
		"""
		Search VirusTotal for information about the specified URL
		"""
		results = None

		url = 'https://www.virustotal.com/vtapi/v2/url/report'
		params = self._get_default_params()
		params['resource'] = 'http://{}'.format(urls) if not urls.startswith('http') else urls
		response = self._make_http_request(url, params)

		if response:
			doc = json.loads(response)
			results = doc

		return results

# *********************************************************************
# required plugin functions
# *********************************************************************
def search(vector, update, config, queue):
	"""
	Search VirusTotal for the details of the specified vector
	"""
	results = {}
	
	if not config.has_key('api_key'):
		queue.put(results)
		return

	api = VirusTotal(config['api_key'])
	
	if vector['type'].startswith('hash'):
		try:
			results['file_report'] = api.search_hash(vector['value'])
		except Exception, err:
			update("Could not get the file report from VirusTotal for vector [{}]".format(vector['value']), 'error', err)

		if config.has_key('virustotal_private_access'):
			try:
				results['file_behaviour'] = api.search_behaviour(vector['value'])
			except Exception, err:
				update("Could not get the file behaviour from VirusTotal for vector [{}]".format(vector['value']), 'error', err)
	elif vector['type'] in ['url', 'domain']:
		try:
			results['url'] = api.search_url(vector['value'])
		except Exception, err:
			update("Could not get the URL report from VirusTotal for vector [{}]".format(vector['value']), 'error', err)
	
	queue.put(results)
	return

def setup(update, register, controller=None):
	"""
	Register the included inputs, vectors, transforms, and APIs 
	with the specified controller
	"""
	update("Initializing the VirusTotal plugin [{}]".format(__file__))
	register('apis', { 'virustotal': search })
	register('map_apis', { 'url': 'virustotal', 'domain': 'virustotal', 'hash': 'virustotal' })

def teardown(update, deregister):
	"""
	Deregister the included inputs, vectors, transforms, and APIs 
	with the specified controller
	"""
	update("Tearing down the VirusTotal plugin [{}]".format(__file__))
	deregister('apis', { 'virustotal': search })
	deregister('map_apis', { 'url': 'virustotal', 'domain': 'virustotal', 'hash': 'virustotal' })