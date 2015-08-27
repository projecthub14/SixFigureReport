# standard libraries
import os
import subprocess

# 3rd party libraries
import shodan
# project libraries

# *********************************************************************
# required plugin functions
# *********************************************************************
def search(vector, update, config, queue):
	"""
	Search SHODAN for the details of the specified vector
	"""
	results = {}
        print "Querying Shodan API"
	
	if not type(config.user_properties) == type({}) or \
	   not config.user_properties.has_key('shodan') or \
	   not config.user_properties['shodan'].has_key('api_key'):
		queue.put(results)
		return
		
	api = shodan.Shodan(config.user_properties['shodan']['api_key'])
	if vector['type'] == 'ip':
		try:
		    results['shodan'] = api.host(vector['value'])

		except Exception, err:
		    update("Could not get the info from SHODAN for vector [{}]".format(vector['value']), 'error', err)
	elif vector['type'] == 'domain':
		try:
                    tmp = api.search('hostname:{}'.format(vector['value']))
                    results['shodan'] = []
                    for dct in tmp['matches']:
                        for host in dct['hostnames']:
                            print host
                            if host==vector['value']:
                                results['shodan'].append(dct)
                                break
		    '''results['shodan'] = api.search('hostname:{}'.format(vector['value']))'''
		except Exception, err:
		    update("Could not get the info from SHODAN for vector [{}]".format(vector['value']), 'error', err)

	queue.put(results)
	return

def register(update, register, deregister=None):
	"""
	Setup or teardown the included inputs, vectors, transforms, and APIs 
	with the specified controller
	"""
	verb = 'Initializing'
	func = register

	if deregister:
		verb = 'Tearing down'
		func = deregister

	update("{} the {} plugin [{}]".format(verb, __file__.replace('.py', ''), __file__))
	func('apis', { 'shodanapi': search })
	func('map_apis', { 'ip': 'shodanapi', 'domain': 'shodanapi' })
