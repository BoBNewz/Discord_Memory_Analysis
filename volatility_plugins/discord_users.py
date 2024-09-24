"""
Plugin to recover discord users.
Tested on Microsoft Windows [Version 10.0.17763.253] & Discord 1.0.9159 x64

@author:   (@BoBNewz)
"""

import re, string
import volatility.plugins.common as common
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.scan as scan

class DiscordScanner(scan.BaseScanner):
    checks = []

    def __init__(self, needles=None):
        self.needles = needles
        self.checks = [("MultiStringFinderCheck", {'needles': needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset=0, maxlen=None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class DiscordDataExtractor():
    def __init__(self):
        self.pattern_id = re.compile(
            r'\d{18,19}".*',
            re.MULTILINE
        )

    def check_text(self, string_to_check):
        alp = string.ascii_letters + string.punctuation
        for c in string_to_check:
            if c in alp:
                return False
        return True
            

    def extract_data(self, outfd, address_space, proc):
        chunk_size = 0x100000
        outfd.write("\nDiscord ID\t\tUsername\n")
        outfd.write("="*40 + "\n")
        list_id_user = []
        found = []

        for addr_tuple in address_space.get_available_addresses():
            addr, size = addr_tuple
            try:
                memory_chunk = address_space.zread(addr, chunk_size)
                if not memory_chunk:
                    continue

                found.extend(self.pattern_id.findall(memory_chunk))

                if found:
                    pattern = re.compile(r'(\d{18,19}.*?)(?=\d{18,19}|$)', re.DOTALL)
                    for line in found:
                        tempo = False
                        matches = pattern.findall(line.replace(b'"', b''))
                        for match in matches:
                            if '{' in match:
                                pass
                            else:
                                try:
                                    out = match.split("username")
                                    if self.check_text(out[0]):
                                        if out[1] != '':
                                            for existing_user in list_id_user:
                                                if existing_user[1] == out[1]:
                                                    tempo = True
                                            if not tempo:                 
                                                list_id_user.append([out[0], out[1]])
                                                outfd.write("{}\t{}\n".format(out[0][:-1], out[1][1:]))
                                except:
                                    pass

            except Exception as e:
                debug.warning("Error reading memory at address: 0x{:x}, error: {}".format(addr, e))
                continue


class discord_users(common.AbstractWindowsCommand):
    """Recover discord users."""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PID", short_option='p', default=None, help="Process ID to filter", action="store", type="int")

    def calculate(self):
        addr_space = utils.load_as(self._config)
        return tasks.pslist(addr_space)

    def render_text(self, outfd, data):
        outfd.write("{:<10} {:<20}\n".format("PID", "Process Name"))
        outfd.write("="*30 + "\n")
        
        if self._config.PID is not None:
            for proc in data:
                if self._config.PID == proc.UniqueProcessId:
                    outfd.write("{:<10} {:<20}\n".format(proc.UniqueProcessId, proc.ImageFileName))
                    debug.info("Looking for users... This may take up to 15 minutes. Coffee break ?")
                    self.extract_discord_data(outfd, proc)
        else:
            for proc in data:
                outfd.write("{:<10} {:<20}\n".format(proc.UniqueProcessId, proc.ImageFileName))
                debug.error("Specify a PID with --pid or -p")

    def extract_discord_data(self, outfd, proc):
        extractor = DiscordDataExtractor()
        process_as = proc.get_process_address_space()

        if not process_as:
            debug.error("Cannot obtain address space for process PID: {0}".format(proc.UniqueProcessId))
            return

        extractor.extract_data(outfd, process_as, proc)
