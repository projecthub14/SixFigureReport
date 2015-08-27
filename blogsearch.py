# standard library
import json, os
from bs4 import BeautifulSoup

# 3rd party libraries
import requests, hashlib

# project libraries

class BlogSearch():
    def __init__(self, verbose = False):
        self.base_url = 'https://blog.opendns.com/all-opendns-blog-posts/'
        self.verbose = verbose
        self._create_repo()

    def _log(self, s):
        if self.verbose:
            print s

    def _create_repo(self):
        if not os.path.isdir('./articles'):
            os.mkdir('articles')
        links = self._get_blog_posts()
        for link in links:
            m = hashlib.md5()
            m.update(link)
            md5 = m.hexdigest()
            if not os.path.isfile(os.path.join('./articles', md5+'.txt')):
                self._handle_new_article(link, md5)

    def _handle_new_article(self, link, md5):
        self._log('Creating local copy of %s' % link)
        text, links = self._get_article_data(link)
        with open(os.path.join('./articles',md5+'.txt'), 'w') as w:
            w.write(link.encode('ascii', 'ignore')+"\n")
            w.write(text.encode('ascii', 'ignore')+"\n")
            for l in links:
                w.write(l.encode('ascii', 'ignore')+",")

    def _make_http_request(self, url, params={}):
        r = requests.get(url, params=params)
        if r.ok:
            return r.text
        else:
            return None

    def _get_blog_posts(self):
        response = self._make_http_request(self.base_url)
        soup = BeautifulSoup(response)
        content_grid = soup.find('div', {'class':'entry-content grid'})
        links = []
        for link in content_grid.find_all('a'):
            if link.has_attr('href'):
                links.append(str(link['href']))
        return links

    def _search_article(self, text, query):
        return query in text

    def _search_list(self, lst, query, case_sensitive = False):
        if not case_sensitive:
            query = query.lower()
            for string in lst:
                if query in string.lower():
                    return True
        else:
            for string in lst:
                if query in string:
                    return True
        return False

    def _get_article_data(self, article_link):
        response = self._make_http_request(article_link)
        soup = BeautifulSoup(response)
        content = soup.find('div', {'class': 'entry-content grid'})
        graphs = content.find_all('p')
        text = ''
        links = []
        for graph in graphs:
            text += graph.get_text()
            for link in graph.find_all('a'):
                if link.has_attr('href'):
                    links.append(str(link['href']))
        return (text, links)

    def search_single_article(self, article, query):
        query_present = False
        with open(article, "r") as r:
            link = r.readline().strip()
            self._log('Searching through %s' % link)
            current_line = r.readline()
            while (current_line != ""):
                current_line = current_line.strip()
                if query in current_line:
                    query_present = True
                current_line = r.readline()
        return link, query_present

    def search_for(self, query):
        articles = [f for f in os.listdir('./articles/') if os.path.isfile(os.path.join('./articles',f))]
        contained_in = []
        for article in articles:
            link, query_present =  self.search_single_article(os.path.join('./articles', article), query)
            if query_present:
                self._log('[+] Query found in %s' % link)
                contained_in.append(link)
        return contained_in

def search(vector, update, config, queue):
    results = {}

    api = BlogSearch(verbose=True)

    print vector
    if (vector['type'] == 'ip' or vector['type'] == 'url' or vector['type'] == 'domain'):
        try:
            res = {}
            res[vector['value']] = api.search_for(vector['value'])
            results['blog_search'] = res
        except Exception, err:
            update("Could not get info from OpenDNS blogs for query [{}]".format(vector['value']), 'error', err)

    queue.put(results)
    return

def register(update, register, deregister=None):
    verb = 'Initializing'
    func = register

    if deregister:
        verb = 'Tearing down'
        func = deregister
    
    update("{} the {} plugin [{}]".format(verb, __file__.replace('.py', ''), __file__))
    func('apis', { 'blogsearch': search})
    func('map_apis', { 'url': 'blogsearch', 'domain': 'blogsearch', 'ip': 'blogsearch' })
