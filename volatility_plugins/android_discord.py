"""
Plugin to recover discord conversations.

@author:   (@BoBNewz)
"""

import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import volatility.scan as scan
import volatility.debug as debug
import re, ast

class DiscordScanner(scan.BaseScanner):
    def __init__(self, needles=None):
        self.needles = needles
        self.checks = [("MultiStringFinderCheck", {'needles': needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset=0, maxlen=None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class android_discord(linux_common.AbstractLinuxCommand):
    """Recover discord server conversations"""
    
    def __init__(self,config,*args,**kwargs):
        linux_common.AbstractLinuxCommand.__init__(self,config,*args,**kwargs)
        config.add_option("PID", short_option='p', default=None, help="Process ID to filter", action="store", type="int")

    def extract_data(self, address_space, scanner):
        chunk_size = 1024
        known_authors = []
        known_messages = []
        pattern_authors = r'"author":\s*\{"id":\s*"[^"]+",\s*"username":\s*"([^"]+)"'
        pattern_messages = r'"content":\s*"([^"]*)"'
        print("\n{:<10} {:<20}".format("Author", "Message"))
        print("="*30 + "\n")

        for offset in scanner.scan(address_space):
            buff = address_space.read(offset - (512/2), chunk_size)

            try:
                message = re.findall(pattern_messages, buff)
                author = re.findall(pattern_authors, buff)
            except:
                pass

            known_messages.extend(message)
            known_authors.extend(author)
                
            if message:
                try:
                    print("{}\t{}".format(author[0], message[0]))
                except:
                    pass
                #print(len(author))
                #print(author, type(author))

    def calculate(self):
        address_space = utils.load_as(self._config)
        start_tag = "b"

        scanner = DiscordScanner(needles=[start_tag])

        self.extract_data(address_space, scanner)
        
        return None

    def render_text(self, outfd, data):
        pass
