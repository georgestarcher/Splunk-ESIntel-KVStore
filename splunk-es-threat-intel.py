import requests
import json
import csv
from ConfigParser import SafeConfigParser
import sys, os, datetime, time, getopt
import base64

__author__ = "george@georgestarcher.com (George Starcher)"

# GLOBAL FIELDS
confidence_weight = {'low':'1', 'medium':'3', 'high':'5'}
_DEBUGMODE = False 

def log(msg):
    f = open(os.path.join("intel_to_splunk.log"), "a")
    print >> f, str(datetime.datetime.now().isoformat()), msg
    f.close()

def loadConfig(filename):

    global splunk_url_ipintel
    global splunk_url_groupintel
    global splunk_server_verify
    global splunk_user
    global splunk_password

    parser = SafeConfigParser()
    parser.read(filename)

    splunk_url_ipintel = parser.get('splunk', 'splunk_url_ipintel')
    splunk_url_groupintel = parser.get('splunk', 'splunk_url_groupintel')
    splunk_server_verify = parser.getboolean('splunk', 'splunk_server_verify')
    splunk_user = parser.get('splunk', 'splunk_user')
    splunk_password = base64.b64decode(parser.get('splunk', 'splunk_password'))

def cleanData(data):

    outdata = []
    for item in data:
        if len(item.get('ip')) == 0:
            item['_key'] = item.get('threat_key')+"|"+item.get('domain')
            outdata.append(item)
            continue
        elif len(item.get('domain')) == 0:
            item['_key'] = item.get('threat_key')+"|"+item.get('ip')
            outdata.append(item)
            continue
        else:
            newItem = item.copy()
            newItem['ip'] = ''
            newItem['_key'] = newItem.get('threat_key')+"|"+newItem.get('domain')
            outdata.append(newItem)
            newItem = item.copy()
            newItem['domain'] = ''
            newItem['_key'] = newItem.get('threat_key')+"|"+newItem.get('ip')
            outdata.append(newItem)

    return outdata


def loadCSV(filename):

    # CSV should be in format: ip, description

    intelList = []
    with open(filename) as csvfile:
        badReader = csv.DictReader(csvfile)
        for row in badReader:
            intelList.append(row)
    csvfile.close()

    return intelList

def postDataToSplunk(data):

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    isNotError = True
    for item in data:
        if not _DEBUGMODE: r = requests.post(splunk_url_ipintel,auth=(splunk_user,splunk_password),verify=splunk_server_verify,headers=headers,data=json.dumps(item))
        # If the intel item exists, request text will have ERROR keyword. 
        # Post again to item key specific URL to update the intel item instead of create it.
        if not _DEBUGMODE and ('ERROR' in r.text):
            isNotError = False
            updateURL = splunk_url_ipintel+item.get('_key')
            if not _DEBUGMODE: 
                r = requests.post(updateURL,auth=(splunk_user,splunk_password),verify=splunk_server_verify,headers=headers,data=json.dumps(item))
                if 'ERROR' in r.text:
                    log(r.text)
                else:
                    isNotError = True

    if isNotError:
        ip_records = [item for item in data if item.get('ip')!=""]
        domain_records = [item for item in data if item.get('domain')!=""]
        log("script_action=added type=ip record_count=%s" % str(len(ip_records)))
        log("script_action=added type=domain record_count=%s" % str(len(domain_records)))
    else:
        log("script_action=failed category=intel message=record_addition_failure")

def removeDataFromSplunk(data):

    isNotError = True
    for item in data:
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        buildURI = [splunk_url_ipintel]
        buildURI.append(item.get('_key'))
        delete_url = "".join(buildURI)
        if not _DEBUGMODE: 
            r = requests.delete(delete_url,auth=(splunk_user,splunk_password),verify=splunk_server_verify,headers=headers,data=json.dumps(data))
            if 'ERROR' in r.text:
                isNotError = False
                log(r.text)

    if isNotError:
        log("script_action=deleted record_count=%s" % str(len(data)))
    else:
        log("script_action=failed category=intel message=record_deletion_failure")

def postIntelGroupDataToSplunk(data,intel_file):

    intel_group = {}
    for item in data:
        group_data = {}
        source_path = []
        group_data['source_id'] = item.get('threat_key')
        source_path.append('rest:api:%s' % intel_file)
        group_data['source_path'] =  "".join(source_path)
        group_data['source_type'] =  'rest:api'
        group_data['threat_group'] =  item.get('threat_key')
        # use default description if no description present in data
        group_data['description'] = item.get('description','API Manual ThreatIntel')
        group_data['time'] = time.time()
        group_data['source_processed_time'] = time.time()
        if item.get('ip'): group_data['threat_category'] = 'threatlist'
        if item.get('domain'): group_data['threat_category'] = 'threatlist_domain'
        group_data['weight'] = confidence_weight.get(item['weight'],'1')
        intel_group[item['threat_key']] = group_data

    intel_groups = []
    for key in intel_group.keys():
        intel_group_data = {}
        intel_group_data['_key'] = key
        for subkey in intel_group[key].keys():
            intel_group_data[subkey] = intel_group[key][subkey]
        intel_groups.append(intel_group_data)

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    isNotError = True
    for group in intel_groups:
        if not _DEBUGMODE: r = requests.post(splunk_url_groupintel,auth=(splunk_user,splunk_password),verify=splunk_server_verify,headers=headers,data=json.dumps(group))
        if not _DEBUGMODE and ('ERROR' in r.text):
            updateURL = splunk_url_groupintel+group.get('_key')
            isNotError = False
            if not _DEBUGMODE:
                r = requests.post(updateURL,auth=(splunk_user,splunk_password),verify=splunk_server_verify,headers=headers,data=json.dumps(group))
                if 'ERROR' in r.text:
                    isNotError = False
                    log(r.text)
                else:
                    isNotError = True

    if isNotError:
        log("script_action=added group_record_count=%s" % str(len(intel_groups)))
    else:
        log("script_action=failed category=intel_group message=record_addition_failure")

if __name__ == "__main__":

    # defaults
    intel_file = 'badguys-ip.csv'
    config_file = 'kvstore.conf'

    argv = sys.argv[1:]

    add_intel = True 

    try:
        opts, args = getopt.getopt(argv,'i:c:r',['ifile=','cfile=','remove'])
    except getopt.GetoptError:
        print 'splunk-es-threat-intel.py -i <inputfile> -c <confile> --remove '
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'splunk-es-threat-intel -i <inputfile> -c <configfile>'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            intel_file = arg
        elif opt in ("-c", "--cfile"):
            config_file = arg
        elif opt in ("-r", "--remove"):
            add_intel = False
    
    try:
        loadConfig(config_file)
    except Exception, e:
        log("script_action=error type=config_file error_message=:%s" % e)
        sys.exit(2)

    try:
        data = loadCSV(intel_file)
    except Exception, e:
        log("script_action=error type=intel_file error_message=%s" % e)
        sys.exit(2)

    log("script_action=processing intel_file=%s config_file=%s" % (intel_file,config_file))

    cleanedData = cleanData(data)

    if add_intel:
        try:
            postDataToSplunk(cleanedData)
            postIntelGroupDataToSplunk(cleanedData,intel_file)
        except Exception, e:
            log("script_action=error type=data_post error_message=%s" % e)
            sys.exit(2)
    else:
        try:
            removeDataFromSplunk(cleanedData)
        except Exception, e:
            log("script_action=error type=data_delete error_message=%s" % e)
            sys.exit(2)

