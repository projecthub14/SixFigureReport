#!/usr/bin/env python

import httplib
import urlparse
import urllib
import urllib2
import simplejson as json
import time
import re
import logging
import datetime



class OTXv2(object):
    def __init__(self, key, server="http://otx.alienvault.com"):
        self.key = key
        self.server = server 

    def get(self, url):
        request = urllib2.build_opener()
        request.addheaders = [('X-OTX-API-KEY', self.key)]
        response = None
        try:
            response = request.open(url)
        except urllib2.URLError, e:
            if e.code == 403:
                raise InvalidAPIKey("Invalid API Key")
            elif e.code == 400:
                raise BadRequest("Bad Request")
        data = response.read()
        json_data = json.loads(data)
        return json_data

    def getall(self, limit=20):
        pulses = []
        next = "%s/api/v1/pulses/subscribed?limit=%d" % (self.server, limit)
        while next:
            json_data = self.get(next)
            for r in json_data["results"]:
                pulses.append(r)
            next = json_data["next"]
        return pulses

    def getall_iter(self, limit=20):
        pulses = []
        next = "%s/api/v1/pulses/subscribed?limit=%d" % (self.server, limit)
        while next:
            json_data = self.get(next)
            for r in json_data["results"]:
                yield r
            next = json_data["next"]
            
    def getsince(self, mytimestamp, limit=20):
        pulses = []
        next = "%s/api/v1/pulses/subscribed?limit=%d&modified_since=%s" % (self.server, limit, mytimestamp)
        while next:
            json_data = self.get(next)
            for r in json_data["results"]:
                pulses.append(r)
            next = json_data["next"]
        return pulses

    def getsince_iter(self, mytimestamp, limit=20):
        pulses = []
        next = "%s/api/v1/pulses/subscribed?limit=%d&modified_since=%s" % (self.server, limit, mytimestamp)
        while next:
                json_data = self.get(next)
                for r in json_data["results"]:
                    yield r
                next = json_data["next"]
        

    def getevents_since(self, mytimestamp, limit=20):
        events = []
        next = "%s/api/v1/pulses/events?limit=%d&since=%s" % (self.server, limit, mytimestamp)
        while next:
            json_data = self.get(next)
            for r in json_data["results"]:
                events.append(r)
            next = json_data["next"]
        return events

    def get_search_results(self, query, limit=20):
        results = []
        next = "%s/otxapi/search/?q=%s&sort=null&limit=%d" % (self.server, query, limit)
        while next:
            json_data = self.get(next)
            for r in json_data["results"]:
                results.append(r)
            next = json_data["next"]
        for r in results:
            pulse_id = r["id"]
            json_data = self.get("%s/otxapi/pulses/%s/indicators/?limit=9000" % (self.server, pulse_id))
            identifiers = json_data["results"]
            r["indicators"] = identifiers
        return results

def search(vector, update, config, queue):
    print "Querying alienvault"
    results = {}

    if not type(config.user_properties) == type({}) or \
        not config.user_properties.has_key('alienvault') or \
        not config.user_properties['virustotal'].has_key('api_key'):
            return queue.put(results)

    api = OTXv2(config.user_properties['alienvault']['api_key'])

    if vector:
        try:
            res = {}
            res[vector['value']] = api.get_search_results(vector['value'])
            results['alienvault'] = res
        except Exception, err:
            update("Could not get results from Alienvault servers for query [{}]".format(vector['value']), 'error', err)

    queue.put(results)
    return

def register(update, register, deregister=None):
    verb = 'Initializing'
    func = register

    if deregister:
        verb = 'Tearing down'
        func = deregister

    update("{} the {} plugin [{}]".format(verb, __file__.replace('.py', ''), __file__))
    func('apis', { 'alienvault': search })
    func('map_apis', { 'url': 'alienvault', 'domain': 'alienvault',
                       'hash': 'alienvault', 'ip': 'alienvault'})
