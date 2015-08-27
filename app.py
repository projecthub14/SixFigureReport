from investigate import Investigate
from flask import Flask, render_template, request, redirect, url_for, abort, session
from datetime import datetime
import json
import shodan
from virustotal import VirusTotal
from blogsearch import BlogSearch
from bs4 import BeautifulSoup
from alienvault import OTXv2

app = Flask(__name__)
app.config['SECRET_KEY'] = 'F34TF$($e34D';


api = shodan.Shodan('**********************************')
virus_total = VirusTotal('****************************')
blog = BlogSearch(verbose=True)


@app.route('/')
def index():    
        return render_template('home.html')   

@app.route('/home_post', methods=['POST'])
def home_post():
    session['domain'] = request.form['domain']
    #session['checkbox'] = request.values
    formData = request.values 
    for item in formData.items() :
      check = item
    if 'investigate' in check:
      return redirect(url_for('investigate'))
    if 'shodan' in check:
      return redirect(url_for('shodan'))
    if 'virustotal' in check:
      return redirect(url_for('virustotal', link = session['domain']))
    if 'blogsearch' in check:
      return redirect(url_for('blogsearch'))
    if 'in_alien' in check:
      return redirect(url_for('alienvault'))
    
    return check
                     

@app.route('/shodan')
def shodan():
  shodan_obj = []
  domain = session['domain']
  shodan_obj = api.search(domain)
  
       
  
  for index in range(len(shodan_obj['matches'])):
        domains = str(shodan_obj['matches'][index]['domains']) 
        hostnames = domains.replace('[','').replace('u','',1).replace('\'','').replace(']','')
        shodan_obj['matches'][index]['domains'] = hostnames
            
            
  return render_template('shodan.html',shodan_obj=shodan_obj,domain=session['domain'])
  
@app.route('/blogsearch')
def blogsearch():
     domain = session['domain']
     blogsearch_obj = blog.search_for(domain)

     for index in range(len(blogsearch_obj)):
           print blogsearch_obj[index]

     return render_template('blogsearch.html',blogsearch_obj=blogsearch_obj,domain=session['domain'])

@app.route('/virustotal/<link>')
def virustotal(link):
    
    domain=session['domain']
    results_domain = virus_total.search_domain(link) 
    if 'whois' in results_domain:
       session['whois'] = results_domain['whois']           
    
    return render_template('virustotal.html',results_domain= results_domain,
                                             whois = session['whois'] , domain=link)

@app.route('/virustotalIp/<link>')
def virustotalIp(link):
    
    domain=session['domain']
    results_domain = virus_total.search_ip(link) 
    
    return render_template('virustotalIp.html',results_domain= results_domain,
                                              domain=link)

alien_obj = OTXv2('******************') 
         
@app.route('/alienvault')
def alienvault():
     domain = session['domain']
     alienvault_obj = alien_obj.get_search_results(domain)        
                      
     return render_template('alienvault.html',alienvault_obj = alienvault_obj,domain=session['domain'])



@app.route('/virustotalHash/<link>')
def virustotalHash(link):
     urls_obj = []
     results_url = virus_total.search_hash(link)
     keys = results_url['scans'].keys()
     keys.sort()
     
     for each in keys:
        key = str(each)
        value = results_url['scans'].get(each)['result']
        in_update = results_url['scans'].get(each)['update']
        urls_obj.append({"key":key,"value":value,"in_update":in_update})
     
     
     return render_template('virustotalHash.html',urls_obj = urls_obj,results_url=results_url,domain=session['domain']) 

@app.route('/virustotalUrl/<link>')
def virustotalUrl(link):
     return link
     
     
     
investigate_obj = Investigate('**********************')

@app.route('/investigate')
def investigate():
#print ----------------- Domain Tagging -------------------------------------
    domain = session['domain']
    response_domain = investigate_obj.domain_tags(domain)
    
    
#print ----------------- Features -------------------------------------
    response_rr_history = investigate_obj.rr_history(domain)
    ttls_min = response_rr_history['features']['ttls_min']
    ttls_max = response_rr_history['features']['ttls_max']
    ttls_mean = response_rr_history['features']['ttls_mean']
    ttls_median = response_rr_history['features']['ttls_median']
    ttls_stddev = response_rr_history['features']['ttls_stddev']
    country_codes = response_rr_history['features']['country_codes'][0]
    country_count = response_rr_history['features']['country_count']
    asns = response_rr_history['features']['asns']
    asns_count = response_rr_history['features']['asns_count']
    prefixes = response_rr_history['features']['prefixes'][0]
    prefixes_count = response_rr_history['features']['prefixes_count']
    rips = response_rr_history['features']['rips']
    div_rips = response_rr_history['features']['div_rips']
    locations_count = response_rr_history['features']['locations_count']
    geo_distance_sum = response_rr_history['features']['geo_distance_sum']
    geo_distance_mean = response_rr_history['features']['geo_distance_mean']
    non_routable =  response_rr_history['features']['non_routable']
    mail_exchanger = response_rr_history['features']['mail_exchanger']
    ff_candidate = response_rr_history['features']['ff_candidate']
    
    features_obj = {"ttls_min" : ttls_min , "ttls_max" : ttls_max , "ttls_mean" : ttls_mean , "ttls_median" : ttls_median ,
                     "ttls_stddev" : ttls_stddev ,"country_codes" :country_codes ,"country_count" : country_count , 
                     "asns" : asns ,"asns_count" :asns_count, "prefixes" : prefixes , "prefixes_count" : prefixes_count , "rips" : rips ,
                     "div_rips" : div_rips , "locations_count" : locations_count , "geo_distance_sum" : geo_distance_sum,
                     "geo_distance_mean" : geo_distance_mean , "non_routable" : non_routable ,"mail_exchanger" :mail_exchanger,
                     "ff_candidate" : ff_candidate }  
                     
#print ----------------- Security Features -------------------------------------
   
    response_security_features = investigate_obj.security(domain)
    securerank2 = response_security_features['securerank2']
    pagerank = response_security_features['pagerank']
    prefix_score = response_security_features['prefix_score']
    rip_score = response_security_features['rip_score']
    popularity = response_security_features['popularity']
    geodiversity = response_security_features['geodiversity']
    geodiversity_normalized = response_security_features['geodiversity_normalized']
   
    securityFeatures_obj = {"securerank2" : securerank2 , "pagerank" : pagerank ,
                           "prefix_score" : prefix_score, "rip_score" : rip_score ,
                           "popularity" : popularity , "geodiversity" : geodiversity ,
                           "geodiversity_normalized" : geodiversity_normalized}


    #print ----------------- SECURITY-DGA DETECTION -------------------------------------
    response_security_dga = investigate_obj.security(domain)
    dga_score = response_security_dga['dga_score']
    perplexity = response_security_dga['perplexity']
    entropy = round(response_security_dga['entropy'],2) 
    
    dga_obj = {"dga-score" : dga_score , "perplexity" : perplexity , "entropy" : entropy}
   
     #print ----------------- RELATED DOMAINS -------------------------------------
    related_obj = investigate_obj.related(domain)
    
     #print ----------------- CO-OCCURRENCES -------------------------------------
    response_cooccurrences = investigate_obj.cooccurrences(domain)
    cooccurrences_obj = []
    for index in range(len(response_cooccurrences['pfs2'])):
         id = response_cooccurrences['pfs2'][index][0]
         round_sum = response_cooccurrences['pfs2'][index][1] * 100
         final_sum = round(round_sum,2)
         number = '(' + str(final_sum) + ')'
         cooccurrences_obj.append({"id":id , "number":number})
    
     
     #print -----------------QUERY HANDLING-------------------------------------
    round_sum = response_security_features['handlings']['normal']*100 
    final_sum = round(round_sum,2)
    normal  = str(final_sum) + '%'
     #print 'nxdomain : ' + str(response_security_features['pagerank'])
     #print 'Smart Cache : ' + str(response_security_features['asn_score'])
    round_sum = response_security_features['handlings']['blocked']* 100
    final_sum = round(round_sum,2)
    blocked = str(final_sum) + '%'
     #print 'nodata : ' + str(response_security_features['rip_score'])        
     #print 'servfail : ' + str(response_security_features['blocked'])
    query_obj = {"normal" : normal , "blocked" : blocked}
    
    ip_obj = []
    #print -----------------IP ADDRESSES-------------------------------------
    for index in range(len(response_rr_history['rrs_tf'])):
	    first_seen = response_rr_history['rrs_tf'][index]['first_seen']
	    datetimeobject = datetime.strptime(first_seen,'%Y-%m-%d')
	    first_seen = datetimeobject.strftime('%m/%d/%Y')
	    
	    last_seen = response_rr_history['rrs_tf'][index]['last_seen']
	    datetimeobject = datetime.strptime(last_seen,'%Y-%m-%d')
	    last_seen = datetimeobject.strftime('%m/%d/%Y')
	    ip_addresses = response_rr_history['rrs_tf'][index]['rrs'][0]['rr'] + ' (' + 'TTL:' + str(response_rr_history['rrs_tf'][index]['rrs'][0]['ttl']) + ')'
	    ip_obj.append({"first_seen" : first_seen , "last_seen" : last_seen , "ip_addresses" : ip_addresses})
	
    
    return render_template('investigate.html',
                                        features_obj= features_obj,
                                        securityFeatures_obj = securityFeatures_obj,
                                        dga_obj = dga_obj,
                                        related_obj = related_obj,
                                        cooccurrences_obj = cooccurrences_obj,
                                        query_obj = query_obj,
                                        ip_obj = ip_obj,domain=session['domain'])

    
if __name__ == '__main__':
    app.run()

  
  
