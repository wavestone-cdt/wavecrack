#!/usr/bin/env python
#coding: utf-8

import urllib2
import pprint
import textwrap

from lxml.html.soupparser import fromstring

from optparse import OptionParser
parser = OptionParser()
parser.add_option('-o', '--output-file', help = "<OUTPUT_FILE>: output file (default 'hashcat_hashes.py')", default = 'hashcat_hashes.py', nargs = 1)

def grab_examples():
    """
        Grab examples from the official hashcat wiki page
    """
    result = []
    response = urllib2.urlopen('https://hashcat.net/wiki/doku.php?id=example_hashes')
    html = response.read()

    root = fromstring(html)
    trs = root.findall('.//tr[@class]')
    for tr in trs:
        mode = tr.xpath("./td[@class='col0']")
        mode_text = mode[0].text.strip() if mode else None
            
        hash_name = tr.xpath("./td[contains(@class,'col1')]")
        hash_name_text = hash_name[0].text.strip() if hash_name else None
        
        hash_example = tr.xpath("./td[@class='col2']")
        hash_example_text = hash_example[0].text.strip() if hash_example else None
        
        if mode_text and hash_name_text and hash_example_text:
            result.append([int(mode_text), hash_name_text, hash_example_text])
    
    print '[+] %d hashes examples grabbed' % len(result)
    return result

def generate_file(list_grabbed_hashes, options):
    """
        Generate a proper python file with the huge list of hashes
    """
    # First let's sort the hashes by their name for a nice visualisation on the drop-down menu in the form
    list_grabbed_hashes_sorted = sorted(list_grabbed_hashes, key=lambda hash:hash[1].lower())
    
    template = '''\
#!/usr/bin/env python
#coding: utf-8

# List containing hashtype number, hashtype and an example
# based on https://hashcat.net/wiki/doku.php?id=example_hashes
# Update this file using the script extract_hashcat_examples.py in the folder setup_resources

HASHS_LIST = %s''' % pprint.saferepr(list_grabbed_hashes_sorted)
    
    with open(options.output_file, 'wb') as fd:
        fd.write(textwrap.dedent(template))
        print "[+] file '%s' successfully written, you can now move it to your wavecrack installation !" % options.output_file
    
    fd.close()
    return None
    
def main(options, arguments):
    """
        Dat main
    """
    list_grabbed_hashes = grab_examples()
    generate_file(list_grabbed_hashes, options)
    
    return None
    
if __name__ == "__main__" :
    options, arguments = parser.parse_args()
    main(options, arguments)
