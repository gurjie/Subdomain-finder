import requests
import sys
import os
import censys.certificates
import censys.data
import censys.ipv4
import censys.base
import socket
import json
import subprocess
import pydig
from json import JSONEncoder
from IPy import IP

CENSYS_API_KEY=""
CENSYS_SECRET=""
toggle_censys_ipv4 = True

# Used to hold objects referring to IP addresses, as well as their attributes from the IPv4 lookup. When initialising the object, we fetch Censys IPv4 lookup data,
class IPObject(object):

    def __init__(self,ip):
        self.ip = ip # give this IP address object an IP, as it deserves!
        if toggle_censys_ipv4:
            c = censys.ipv4.CensysIPv4(api_id=CENSYS_API_KEY, api_secret=CENSYS_SECRET)
            # fields we want to pull back from censys ipv4 search - totally configurable
            IPV4_FIELDS = [ 'tags',
                            'ports',
                            'protocols',
                            '80.http.get.headers.server',
                            '80.http.get.metadata.product',
                             '80.http.get.title',
                             '443.https.get.title',
                             '25.smtp.starttls.banner',
                             '80.http.get.server',
                             '21.ftp.banner.banner',
                             '22.ssh.v2.banner.raw'
                             ]
            # set the censys data pulled back for this IP to this object
            try:
                self.data = list(c.search(ip, IPV4_FIELDS, max_records=15))
            except Exception as e:
                print(e)
                exit(1)
        else:
            self.data = ""
    
    def reprJSON(self):
        return dict(ip=self.ip, data=self.data)


class Domain(object):

    def __init__(self, domain, ips=[]):
        self.domain = domain
        """ my ISP kept DNS hijacking whenever an NXDOMAIN was fetched, and replaced it with the below IP
         (barefruit), to suggest 'relevant alternatives' for non-existant domains - knocked this IP from the list """
        if "92.242.132.24" in ips: ips.remove("92.242.132.24")
        self.ips = [] # array used to temporarily hold IPs associated with this domain, before instantiating an IPObject 
        for ip in ips:
            self.add_ip(ip)
    # let's return any associated IP addresses with this domain. Used for debugging
    def get_associated_addresses(self):
        ips = []
        for ip_object in self.ips:
            ips.append(ip_object.ip)
        return ips

    # let's retrieve the IPv4 lookup data associated with this domain
    def get_data_for_all_IPs(self):
        data = []
        for ip_object in self.ips:
            data.append(ip_object.data)
        return data

    def add_ip(self, ip):
        # cast to an IP using IPy, then check whether its an internal or external IP, also using IPy
        if ((IP(ip).iptype()=='PRIVATE') or ip==""):
            pass
        else:
            # if the IP isn't private or blank, let's add it to the list of IPs associated with this domain
            IP_object = IPObject(ip)
            self.ips.append(IP_object)


    # code reused much appreciatedly, from https://stackoverflow.com/questions/5160077/encoding-nested-python-object-in-json; massively helped understanding encoding
    # (reprJSON functions are from this link)
    def reprJSON(self):
        return dict(domain=self.domain, ips=self.ips)

# code reused much appreciatedly, from https://stackoverflow.com/questions/5160077/encoding-nested-python-object-in-json; massively helped understanding encoding
class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj,'reprJSON'):
            return obj.reprJSON()
        else:
            return json.JSONEncoder.default(self, obj)

def dig_using_wordlist(domain, already_found_domains, objectified_domains):
    try:
        wordlist = open("/data/default_domains.txt","r")
    except Exception as e:
        print(e)
        exit(1)
    for word in wordlist:
        full_domain = word.rstrip()+"."+domain
        returned = pydig.query(full_domain,'A')
        if(len(returned)==0):
            pass
        elif(len(returned)==1):
            if(returned[0]=="92.242.132.24" or returned[0]=="NXDOMAIN" or returned==""):
                pass
        else:
            if(full_domain not in already_found_domains):
                already_found_domains.append(full_domain)
            to_remove_from_ip_list = []
            for suspected_ip in returned:
                # if what should be an ip contains any alpha letters
                if(suspected_ip.lower().islower()==True):
                    to_remove_from_ip_list.append(suspected_ip)    
            for item in to_remove_from_ip_list:
                returned.remove(item)
            domain_object = Domain(full_domain,returned)
            objectified_domains.append(domain_object)            

def grab_domains(domain):
    # We're using the certificates python API instead of making REST API calls to the certificates endpoint
    certificates = censys.certificates.CensysCertificates(CENSYS_API_KEY, CENSYS_SECRET)
    # Iterate over certs that match a specific search; we're going to match on the Names field 
    # Could look at Subject Alternate Name (SAN) on cert, which allows multiple hostnames to be protected by a single cert
    fields = ["parsed.names"]
    # Declare empty set to hold subdomains
    subdomains = set()
    # initiate a search for any certs associated with the domain
    try:
        for certificate in certificates.search("parsed.names: "+domain, fields=fields):
            # Add contents of parsed names list to our set of domains
            subdomains.update(certificate["parsed.names"])
        return subdomains
    # we're not permissive of exceptions here; if there's an API issue we'll quit right away
    except censys.base.CensysRateLimitExceededException as e:
        print(e)
        exit(1)
    except censys.base.CensysNotFoundException as e:
        print(e)
        exit(1)
    except censys.base.CensysUnauthorizedException as e:
        print(e)
        exit(1)
    except censys.base.CensysJSONDecodeException as e:
        print(e)
        exit(1)
    # we've caught the most critical faults, but the one below is if you've hit maximum free results in one search
    except Exception as e:
        print(e)
        return subdomains

def resolve_and_objectify(domain, subdomains, toggle_google, toggle_dig):
    objectified_domains = [] # Array holding all of our domains, as objects, discovered
    unique_domains = [] # Store all unique and relevant domains pulled back, to negate from our google query
    # for every subdomain, let's resolve an IP we can further use for investigation
    for value in subdomains:
        # let's check that the fetched domain contains the one we're looking for, so we can striclty filter not-subdomains
        if((domain in value)==True and value!="*."+domain):
            # we also want to strictly get rid of cases such as 'heavythoughtmachine.net' or 'asp-thoughtmachine.net'
            # as they're not technically subdomains: we check the character one  to the left of wherever thoughtmachine is in 
            # the domain string fetched to see if it's a '.' character e.g. we accept 'asp.thoughtmachine.net*'.
            # Both checks mean we miss out alot of potential phishing links or other interesting domains
            if((value[value.find(domain)-1])=='.' or value==domain):                
                lookup_domain_and_store((value.replace('*.','')), objectified_domains, unique_domains)
            else:
                pass #placeholder 
        else:
           pass #placeholder
    
    if (toggle_dig):
        dig_using_wordlist(domain,unique_domains, objectified_domains)
    # The idea of this length check is only to make sure we don't trigger some sort of bot detection with google...
    # Haven't been detected yet. Plus, changing the search limit and intervals has a way bigger effect. This is just preemptive
    if ((len(unique_domains)<20) and (toggle_google == True)):
        search_google(domain, unique_domains, objectified_domains)
    return objectified_domains

def lookup_domain_and_store(domain_to_lookup, domain_object_array, unique_domains=[]):
    try:
        # Using gethostbyname_ex will retrieve zero or more associated IPs as opposed to gethostbyname which will
        # retrieve 0 or 1. Because getaddrinfo wasn't used, only ipv4 addresses will be resovled
        resolved = socket.gethostbyname_ex(domain_to_lookup)
        # Awesome work, we resolved the domain and now we'll store itself and associated IPs in an objects
        domain_object = Domain(domain_to_lookup,resolved[2])
        unique_domains.append(domain_to_lookup)
    except Exception as e:
        # We likely couldn't fetch back a valid response to our query, so attribute the domain with no associated IPs
        domain_object = Domain(domain_to_lookup) # don't give the domain_object any associated IPs
        unique_domains.append(domain_to_lookup)
        pass
    finally:
        domain_object_array.append(domain_object)
        #print(domain_object.domain,domain_object.get_associated_addresses(),domain_object.get_data_for_all_IPs())

"""
    The purpose of this function is to scrape google. We search google using its searching syntax, excluding domains
    we've already discovered, so that we might be able to discover new ones. Its not guaranteed to pull back
    all subdomains listed on google, as the search is limited to 100 results... 
"""
def search_google(domain, knownsites, domain_objects):
    ###### begin imports ##
    try:
        from googlesearch import search
        from urllib.parse import urlparse
    except ImportError as e:
        print("module not found, msg:",e)
        exit(1)
    ######### end #########
    querified_sites = "" # We define an empty string to query google with
    # for every domain that we've already discovered, let's exclude it from our string that we'll query google with!
    for site in knownsites:
        if (site!=domain):
            querified_sites += "-site:"+site+" "
    ## end for ##
    querified_sites = querified_sites[0:len(querified_sites)-1] ##Trim the trailing white space
    # tutorial followed here https://www.geeksforgeeks.org/performing-google-search-using-python-code/
    query = "site:"+domain+" -www "+querified_sites
    discovered = set()
    # for all google search results pulled back by our query, let's parse out the hostname and add it to discovered domains
    for google_search_result in search(query, tld="com", num=100, stop=100, pause=3):
        result = urlparse(google_search_result).hostname
        # if we haven't already discovered this site, let's go ahead and add it to our (local) list of discovered domains!
        if result not in knownsites:
            discovered.add(result)

    # for all domains that's we've discovered via google that we didn't discover via censys, let's resolve IP and create an object!
    for discovered_domain in discovered:
        lookup_domain_and_store(discovered_domain, domain_objects)

def print_help(arg):
    if arg != "genuine":
        print("ERROR:",arg,"is invalid input to this script...exiting")
    print("--- SCRIPT ARGUMENT FORMAT (in any order): domain [optional]-ng [optional]-nc [optional]-nip ---")
    print("Where domain must contain a period ('.') character, and the other flages are optional.")            
    print("ng: don't search google to reolve domains;")
    print("nc: don't search censys certificates for subdomains\nnip: don't make an ipv4 lookup and find info about the domains")

"""
    The main entry point. Here, we execute the subdomains() routin to fetch any domains from the censys IPv4 API.
    We then process to resolving IP addresses for each domain, and then instantiatigng objects for each Domain, as well as objects to store each IP address. 
    The Domain objects hold IP address objects, which in turn hold an IP address and list of attributes discovered from the Censys IPv4 lookup.
    We then get a JSON dump for each domain and print it to the prompt, which is our final output.
"""
def main(domain, toggle_google, toggle_censys_certs, toggle_dig):
    if (toggle_censys_certs == True):
        subdomains = grab_domains(domain)
    else:
        subdomains = set()
    all_discovered_subdomains = resolve_and_objectify(domain, subdomains, toggle_google, toggle_dig)
    for every_domain in all_discovered_subdomains:
        print(json.dumps(every_domain.reprJSON(), cls=ComplexEncoder))
    
    print(json.dumps(every_domain.reprJSON(), cls=ComplexEncoder))
"""
    Here, we set a flag as to whether we want to search google to discover subdomains. We also validate the command line input.
    TODO: Find a way to validate that the user's actually provided a hostname, as difficult as that seems...
    We validate number of args provided.
    The second argument after the script must be -ng or blank. 

    Then, we fetch the API keys from the operating system's environment variables and proceed to execute the main function.
"""
if __name__ == "__main__":
    scrape_google = True  #flag specifying whether we should scrape google for subdomains
    search_censys_certs = True
    toggle_dig = True
    domain = ""
    # validate arg length and contents
    count = 0
    for arg in sys.argv:
        if count == 0:
            count += 1
        elif  count == 1:
            count+=1
            if "." in arg:
                domain = arg
            elif arg == "-help" or arg == "help" or arg == "-h":
                print_help("genuine")
                exit(1)
            else:
                print("You must enter a valid domain...exiting")
                exit(1)
        elif arg == "-ng":
            scrape_google = False
        elif arg == "-nc":
            search_censys_certs = False
        elif arg == "-nip":
            toggle_censys_ipv4 = False
        elif arg == "-ndg":
            toggle_dig = False
        else:
            print_help(arg)
            exit(1)

    if (scrape_google == False and search_censys_certs == False and toggle_dig == False):
        print("You've got to either scrape google or search censys certs. Invalid arguments")
        exit(1)
            
    try:
        CENSYS_API_KEY = os.environ.get('CENSYS_API_KEY')
    except KeyError:
        print("The API key was not set as a docker environment variable")
        sys.exit(1)

    try:
        CENSYS_SECRET = os.environ.get('CENSYS_SECRET')
    except KeyError:
        print("The API secret was not set as a docker environment variable")
        sys.exit(1)
    
    main(domain, scrape_google, search_censys_certs, toggle_dig)
