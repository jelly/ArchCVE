#!/usr/bin/env python
from lxml import etree
import pycman

# Setup pyalpm stuff
repos = ['core','community','extra','testing','multilib','multilib-testing','community-testing']
configpath  = '/etc/pacman.conf'
handle = False
handle = pycman.config.init_with_config(configpath)
syncdbs = handle.get_syncdbs()

# search helper 
def search(package):
    results = []
    for db in syncdbs:
            results += db.search(package)
    return results


#url = 'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml'
url = 'nvdcve-2.0-modified.xml'

# setup parser for XML file
parser = etree.XMLParser(ns_clean=True, recover=True)
try:
    xml = etree.parse(url,parser)
except ValueError:
    print ("Couldn't parse source {0} ".format(url))

# Setup XML namespaces
ns = {'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4',
      'cvss': 'http://scap.nist.gov/schema/cvss-v2/0.2'}


root = xml.getroot()
found = False

# Loop over CVE's
for entry in root:
    summary = entry.find('vuln:summary',ns)
    products = entry.find('vuln:vulnerable-software-list',ns)
    #print ("Parsing CVE id: {}".format(entry.attrib['id']))
    #print(summary.text)
    affectedpkgs = ""
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
                    affectedpkgs += "{}/{} {} - CVE program: {} version: {}\n".format(pkg.db.name, pkg.name, pkg.version, program, version)
                    found = True
            
                    

    if found:
        print ("\033[1;31mCVE id: http://cve.mitre.org/cgi-bin/cvename.cgi?name={}\033[1;m".format(entry.attrib['id']))
        print ("Possible affected programs")
        print (affectedpkgs) 
        print("\033[1;31mSUMMARY:\033[1;m")
        print(summary.text)

        print ("\033[1;31mREFERENCES:\033[1;m")
        # Print related references
        references = entry.findall('vuln:references',ns)
        for reference in references:
            ref = reference.find('vuln:reference',ns)
            print(ref.attrib['href'])
        found = False
        print ("\n")
