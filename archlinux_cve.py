#!/usr/bin/env python
from lxml import etree
import pyalpm
from pycman import config

repos = ['core','community','extra','testing','multilib','multilib-testing','community-testing']
configpath  = '/etc/pacman.conf'
handle = False
handle = config.init_with_config(configpath)

def search(package):
    results = []
    for db in handle.get_syncdbs():
            results += db.search(package)
    return results


#url = 'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml'
url = 'nvdcve-2.0-modified.xml'
parser = etree.XMLParser(ns_clean=True, recover=True)
try:
    xml = etree.parse(url,parser)
except ValueError:
    print ("Couldn't parse source {0} ".format(url))

ns = {'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4',
      'cvss': 'http://scap.nist.gov/schema/cvss-v2/0.2'}
      #xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" xmlns="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:patch="http://scap.nist.gov/schema/patch/0.1" xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" nvd_xml_version="2.0" pub_date="2013-09-22T01:03:08" xsi:schemaLocation="http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd">

root = xml.getroot()
found = False
for entry in root:
    summary = entry.find('vuln:summary',ns)
    products = entry.find('vuln:vulnerable-software-list',ns)
    #print ("Parsing CVE id: {}".format(entry.attrib['id']))
    #print(summary.text)
    if products is not None:
        for product in products.iterchildren():

            # Parse "cpe:/a:wireshark:wireshark:1.8.4"
            result = product.text.split(':')
            program = result[-2]
            version = result[-1]

            # search syncdb for a match
            results = search(program)

            # search syncdb results and try to match version 
            for pkg in results:
                ver = pkg.version.split('-')[0]
                if ver == version:
                    print(summary.text)
                    print("%s/%s %s CVE: program %s CVE version: %s" % (pkg.db.name, pkg.name, pkg.version,program,version))
                    found = True

                    

    if found:
        references = entry.findall('vuln:references',ns)
        for reference in references:
            ref = reference.find('vuln:reference',ns)
            print("reference {}".format(ref.text))
        found = False
        print ("#####################################################################################################")
