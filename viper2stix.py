#!/usr/bin/env python
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

"""
Description: Build a STIX Document with Viper API Information
"""

description = 'Create Stix files based on Viper Malware repository API'
authors = ['deralexxx']
version = '0.6'
# stdlib
from pprint import pprint
try:
    # python-cybox
    from cybox.common import ToolInformationList, ToolInformation
    from cybox.objects.file_object import File
    from cybox.common import Time
    from cybox.common import Hash
    # python-stix
    from stix.core import STIXPackage, STIXHeader
    from stix.common import InformationSource
    from stix.common import Identity 
    from stix.indicator import Indicator
    from stix.extensions.marking.tlp import TLPMarkingStructure
    from stix.data_marking import Marking, MarkingSpecification

    HAVE_STIX = True
except ImportError:
    HAVE_STIX = False    
    
try:
    import simplejson as json    
    HAVE_JSON = True
except ImportError:
    HAVE_JSON = False
       
import requests
import argparse
import logging
from datetime import datetime
# Config parser
import ConfigParser

import urllib2
import pprint
from requests.auth import HTTPBasicAuth
import base64,urllib
    


# Logger
logger = logging.getLogger('viper2stix')
logging.basicConfig(level=logging.DEBUG,
datefmt='%Y-%m-%d %H:%M:%S',
format="%(asctime)s - %(name)s -  %(funcName)s():%(lineno)s - %(levelname)s - %(message)s")
logger.setLevel(logging.DEBUG)

# Config Parser
# TODO
"""
Config parser stuff
"""

Config = ConfigParser.ConfigParser()
Config.read('config.cfg')
user=Config.get('viper','user')
password=Config.get('viper','password')
usehtaccess=Config.getboolean('viper','usehtaccess')

from stix.utils import set_id_namespace
NAMESPACE = {Config.get('stix','namespace_url') : Config.get('stix','namespace_name')}
set_id_namespace(NAMESPACE) 

from cybox.utils import set_id_namespace, Namespace
NAMESPACE = Namespace(Config.get('stix','namespace_url'), Config.get('stix','namespace_name'))
set_id_namespace(NAMESPACE) 


def stix(json):
    """
    Created a stix file based on a json file that is being handed over
    """
    # Create a new STIXPackage
    stix_package = STIXPackage()

    # Create a new STIXHeader
    stix_header = STIXHeader()

    # Add Information Source. This is where we will add the tool information.
    stix_header.information_source = InformationSource()

    # Create a ToolInformation object. Use the initialization parameters
    # to set the tool and vendor names.
    #
    # Note: This is an instance of cybox.common.ToolInformation and NOT
    # stix.common.ToolInformation.
    tool = ToolInformation(
        tool_name="viper2stix",
        tool_vendor="The Viper group http://viper.li - developed by Alexander Jaeger https://github.com/deralexxx/viper2stix"
    )
        
    #Adding your identity to the header
    identity = Identity()
    identity.name = Config.get('stix', 'producer_name')
    stix_header.information_source.identity=identity
    

    # Set the Information Source "tools" section to a
    # cybox.common.ToolInformationList which contains our tool that we
    # created above.
    stix_header.information_source.tools = ToolInformationList(tool)

    stix_header.title = Config.get('stix', 'title')
    # Set the produced time to now
    stix_header.information_source.time = Time()
    stix_header.information_source.time.produced_time = datetime.now()
    
    
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../descendant-or-self::node()"
    tlp = TLPMarkingStructure()
    tlp.color = Config.get('stix', 'TLP')
    marking_specification.marking_structures.append(tlp)

    handling = Marking()
    handling.add_marking(marking_specification)
    

  

    # Set the header description
    stix_header.description =  Config.get('stix', 'description')

    # Set the STIXPackage header
    stix_package.stix_header = stix_header
    
    stix_package.stix_header.handling = handling
    try:
        pp = pprint.PrettyPrinter(indent=5)
        pp.pprint(json['default'])
        #for key, value in json['default'].iteritems():
        #    print key, value
        for item in json['default']:
            #logger.debug("item %s", item)
            indicator = Indicator()
            indicator.title = "File Hash"
            indicator.description = (
            "An indicator containing a File observable with an associated hash"
            )    
            # Create a CyboX File Object
            f = File()
            
            sha_value = item['sha256']
            if sha_value is not None:    
                sha256 = Hash()
                sha256.simple_hash_value = sha_value   
                h = Hash(sha256, Hash.TYPE_SHA256)
                f.add_hash(h)
            sha1_value = item['sha1']
            if sha_value is not None:    
                sha1 = Hash()
                sha1.simple_hash_value = sha1_value   
                h = Hash(sha1, Hash.TYPE_SHA1)
                f.add_hash(h)
            sha512_value = item['sha512']
            if sha_value is not None:    
                sha512 = Hash()
                sha512.simple_hash_value = sha512_value   
                h = Hash(sha512, Hash.TYPE_SHA512)
                f.add_hash(h)

            f.add_hash(item['md5'])
            
            #adding the md5 hash to the title as well
            stix_header.title+=' '+item['md5']
            #print(item['type'])
            f.size_in_bytes=item['size']
            f.file_format=item['type']
            f.file_name = item['name']
            indicator.description = "File hash served by a Viper instance"
            indicator.add_object(f)
            stix_package.add_indicator(indicator)
    except Exception, e:
        logger.error('Error: %s',format(e))
        return False

    # Print the XML!
    #print(stix_package.to_xml())
    return stix_package
    # Print the dictionary!
    #pprint(stix_package.to_dict())


def build_url(route):
    """
    Generates the Viper url based on config file and parameters
    """
    url = "%s%s" % (Config.get('viper', 'url'), route)
    logging.debug("Will use the url %s",url)
    return url

def get_data(url,data):
    """
    Retrieve the data from the API
    """

    #print data
    try:
        proxy_url = ""
        proxy_support = urllib2.ProxyHandler({'http': proxy_url})
        opener = urllib2.build_opener(proxy_support)
        urllib2.install_opener(opener)
        
                #encode the data and the url
        if data != None:
            data = urllib.urlencode(data)
        request = urllib2.Request(url,data=data)
        if usehtaccess:
            base64string = base64.encodestring('%s:%s' % (user,password)).replace('\n', '')
            request.add_header("Authorization", "Basic %s" % base64string)   
        logger.debug(request)
        response = opener.open(request)
        logger.debug(response)

        return response
    except Exception, e:
            logger.error('Error: %s',format(e))

def check_errors(code):
    """
    Checks for the return code if it was successful or not
    
    return true == error
    return false == okay
    
    """
    if code == 500:
        return True
    elif code == 400:
         return True
    else:
        return False

def find_malware(term, value):
    """
    method to find malware on given searchterm and value
    can consume: ["md5", "sha256", "ssdeep", "tag", "name", "all"]

    """
    term = term.lower()
    terms = ["md5", "sha256", "ssdeep", "tag", "name", "latest", "all"]

    if not term in terms:
        logger.error("ERROR: Invalid search term [%s]" % (", ".join(terms)))
        return
    data = {term : value}
    '''
    try:        
        url=build_url("/file/find")
        data = {term : value}
        logger.debug("search params: %s",data)
        result = get_data(url,data)
        logger.debug(result)
        data = json.load(result)
        logger.debug('response: %s',data)
    except Exception, e:
        logger.error('Error: %s',format(e))
    '''
    
    req = requests.post(build_url("/file/find"),
                        data=data,verify=False,proxies={},auth=HTTPBasicAuth(user, password))
    try:
        res = req.json()
        logger.info(res)
        logger.info(req.status_code)
    except:
        logger.error("ERROR: Unable to parse results: {0}".format(e))
        return
    if check_errors(req.status_code):
        logger.info(req.status_code)
        
    else:
        logger.info("result okay")
        return res
'''
		TODO: error handling if file is not there
'''

def test_api():
    """
    method to test the API
    """
    try:        
        url=build_url("/test")
        logger.debug(url)
        data = json.load(get_data(url,None))
        logger.debug('response: %s',data)
    except Exception, e:
        logger.error('Error: %s',format(e))
        
            
def writeFile(path,content):
    """
    method to write the results to a file
    """
    logger.debug('Starting write file')
    outFile = open(path,"w")
    outFile.write(content)
    outFile.close()
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Viper API Actions: find / test")
    parser.add_argument("-H", "--host", help="Host of Viper API server", default=None, action="store", required=False)
    parser.add_argument("-p", "--port", help="Port of Viper API server", default=8080, action="store", required=False)
    parser.add_argument("-a", "--action", help="Action to be performed", default=None, action="store", dest="action",required=True,nargs='?',choices=['test', 'find'])
    parser.add_argument("-m", "--md5", help="list of md5 hashes", default=None, action="store", dest="md5", required=False, nargs='?')
    parser.add_argument("-t", "--tags", help="list of tags to search for", default=None, action="store", dest="tags", required=False,nargs='*')
    parser.add_argument("-e", "--export", help="filename of stix file to be exported", default=None, action="store", dest="export_filename", required=False)
    parser.add_argument("-l", "--latest", help="list of latest files", default=None, action="store", dest="latest", required=False)
    parser.add_argument("-sa", "--all", help="search all (be careful!)", default=None, action="store_true", dest="search_all", required=False)
    parser.add_argument("-n", "--name", help="search by name", default=None, action="store", dest="search_name", required=False)
   
    if not HAVE_STIX:
        logger.error("Missing dependency, install stix (`pip install stix`)")
        quit()        
    
    if not HAVE_JSON:
        logger.error("Missing dependency, install json (`pip install simplejson`)")
        quit()

    args = parser.parse_args()
    if args.action == "test":
            test_api()
    elif args.action == "find":
            if args.tags:
                viper_sample_info = find_malware("tag",args.tags)
            elif args.md5:
                 viper_sample_info = find_malware("md5",args.md5)   
            elif args.latest:
                 viper_sample_info = find_malware("latest",args.latest)
            elif args.search_name:
                 viper_sample_info = find_malware("name",args.search_name)
            elif args.search_all:
                 viper_sample_info = find_malware("all","")
            try:
                if viper_sample_info == None:
                    raise Exception("No data to process")
                # Parse the result info
                logger.info(viper_sample_info)
                stix_result = stix(viper_sample_info)
                if args.export_filename:
                    logger.debug("print to file %s",args.export_filename)
                    writeFile(args.export_filename, stix_result.to_xml())
           
                    # TODO. Check if stix result was correct this means there is a stix result
                    print(stix_result.to_xml())
    
            except Exception, e:
                logger.error('Error: %s',format(e))
