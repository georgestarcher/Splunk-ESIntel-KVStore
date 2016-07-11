#splunk-es-threat-intel.py

Author: George Starcher (starcher)
Email: george@georgestarcher.com

Python Script to push threatintel csv into Splunk ES KVStore.

**All materials in this project are provided under the MIT software license. See license.txt for details.**

##Requirements:

* Python Requests library
* Configuring the proper settings in conf file
* Preparing the intel csv properly

###kvstore.conf:

The default conf file is kvstore.conf. You may create a copy and reference that file using the '-c' option.

* You will need to update the fields splunk_server, splunk_user, and splunk_password.
* The splunk_server field may be a DNS name to a search head cluster.
* The splunk_user field must be a user with API permissions and permissions to write to DA-ESS-ThreatIntelligence where the collections are stored.
* The splunk_password field must be base64 encoded password for the splunk_user.

You can generate your base64 encoded password by launching Python interactively. 

    import base64
    print base64..b64encode(('MYPASSWORD')

Then copy and paste the output string for splunk_password.

####Example kvstore.conf:
    [splunk]
    splunk_server = localhost
    splunk_server_port = 8089
    splunk_app_with_collection = DA-ESS-ThreatIntelligence
    splunk_kvstore_collections_ipintel = ip_intel
    splunk_kvstore_collections_groupintel = threat_group_intel
    splunk_server_verify = False
    splunk_user = svc_es_intel
    splunk_password = base64PASSWORD
    splunk_url_ipintel = https://%(splunk_server)s:%(splunk_server_port)s/servicesNS/nobody/%(splunk_app_with_collection)s/storage/collections/data/%(splunk_kvstore_collections_ipintel)s/
    splunk_url_groupintel = https://%(splunk_server)s:%(splunk_server_port)s/servicesNS/nobody/%(splunk_app_with_collection)s/storage/collections/data/%(splunk_kvstore_collections_groupintel)s/

###Intel CSV:

The required fields are: threat_key, ip and/or domain, weight.
The field description is highly recommended.

 1. threat_key: a consistent name for this source like renisac.
 2. ip: a single IP address
 3. domain: a single fully qualified domain name
 4. weight: a confidence weight from the following lowercase terms: low, medium or high
 5. description: a short text description of the intel item and threat_key group
 
You can place an IP and a domain in the same line. The script will post them to Splunk as individual intel objects.

####Example: badguys-ip.csv

    threat_key,ip,domain,weight,description,address,city,country,postal_code,state_prov,organization_name,organization_id,registration_time
    manual_intel,10.63.51.1,,low,TEST:IgnoreThreatIncidents,,,,,,,,


##Usage:

To add the csv data to the ES Threat Intel KVStore you need only perform all the configuration listed above. I recommend keeping each csv and adopt a naming convenstion. The default behavior is to ADD the data. To remove the data call the script again for the same conf and csv but add the --remove option. 

    python splunk-es-threat-intel.py --help
    splunk-es-threat-intel.py -i <inputfile> -c <confile> --remove 
    
You can specify different csv input files and config files to point to different Splunk instances.
If the script is run without arguments, the default input is badguys.csv and config file kvstore.conf in the same folder with the python script.

The optional '--remove' argument will delete the IP/domain names found in the intel file from the ip_intel kvstore collection if they exist for the specified threat_key.
This is intended to allow you to back out saved intel files after they have served their usefullness.
A file naming format is recommended with a source and timestamp in the name.

The script will generate a log file called intel_to_splunk.log in the folder with the script.
This can aid in debugging if you enter bad server name, credentials etc.

###Confirmation:

Once you post the data examine the lookup KVStore tables in Splunk ES.

    | inputlookup ip_intel
 
and 

    | inputlookup threat_group_intel
 
 
