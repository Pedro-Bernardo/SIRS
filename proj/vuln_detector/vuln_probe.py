from difflib import SequenceMatcher
from pwn import *
import angr, r2pipe, time, os, sys

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class VulnProbe:

    _FMT_FUNCS = [
        {"func" : "printf", "reg": "rdi"},
        {"func" : "fprintf", "reg": "rsi"},
        {"func" : "dprintf", "reg": "rsi"},
        {"func" : "sprintf", "reg": "rsi"},
        {"func" : "snprintf", "reg": "rdx"},
        {"func" : "vprintf", "reg": "rdi"},
        {"func" : "vfprintf", "reg": "rsi"},
        {"func" : "vdprintf", "reg": "rsi"},
        {"func" : "vsprintf", "reg": "rsi"},
        {"func" : "vsnprintf", "reg": "rdx"}
    ]

    _DANGER_FUNCS = [
         { "func" : "strcpy", "severity" : "potential" },
         { "func" : "strcat", "severity" : "potential" },
         { "func" : "sprintf", "severity" : "potential" },
         { "func" : "gets", "severity" :  "danger" },
         { "func" : "vsprintf", "severity" : "potential" },
         { "func" : "__isoc99_scanf" , "severity" : "potential" }
    ]

    _TMP_DIR = "/tmp/probe"
    _TMP_INPUT_FILE = _TMP_DIR + "/inp"
    _TMP_CONFIG_FILE = _TMP_DIR + "/config.rr2"

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.r2 = r2pipe.open(binary_path)


    def go_danger(self):
        vulns = []
        v_append = vulns.append

        for f in self._DANGER_FUNCS:
            xrefs = self._plt_xrefs(f['func'])  

            if f['func'] == 'gets':
                for ref in xrefs:
                    v_append({"func" : f['func'], "addr" : ref})
                    self._log_error("{} vulnerable to overflow @ {}".format(f['func'], hex(ref)))
                continue
                
            elif f['func'] == "__isoc99_scanf":
                potential_vulns = []
                p_append = potential_vulns.append
                for ref in xrefs:
                    inp = ""
                    try:
                        inp = self.reach_address(ref)
                        p_append({'addr': ref, 'input': inp})
                    except Exception, e:
                        pass
                        
                for p in potential_vulns:
                    self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
                    # configure r2 input
                    self.r2_set_config(p['input'])

                    self.r2.cmd('e dbg.profile={}'.format(self._TMP_CONFIG_FILE))
                    self.r2.cmd("doo")
                    self.r2.cmd("db {}".format(hex(p['addr'])))
                    self.r2.cmd("dc")

                    reg = self.r2.cmd("dr~rdi")

                    # get bytes until string terminator '\x00'
                    reg_bytes = self.r2.cmd("p8 @ {}".format(reg)).split("00")[0].decode("hex")
                    if "%s" in reg_bytes:
                        v_append({'func': f['func'], 'addr': p['addr']})
                        self._log_error("{} vulnerable to overflow @ {}".format(f['func'], hex(p['addr'])))
                
            else:
                for ref in xrefs:
                    v_append({"func" : f['func'], "addr": ref}) 
                    self._log_info("{} potentially vulnerable to overflow @ {}".format(f['func'], hex(ref)))

        return vulns

    def go_fs(self):
        vulns = []
        v_append = vulns.append

        for f in self._FMT_FUNCS:
            # get refs to function
            potential_vulns = []
            p_append = potential_vulns.append

            xrefs = self._plt_xrefs(f['func'])  
                    
            if len(xrefs) == 0:
                continue 

            for ref in xrefs:
                # get input to reach address
                inp = ""
                try:
                    inp = self.reach_address(ref)
                    p_append({'addr': ref, 'input': inp})
                except Exception, e:
                    pass
            
            for p in potential_vulns:
                self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
                # configure r2 input
                self.r2_set_config(p['input'])

                self.r2.cmd('e dbg.profile={}'.format(self._TMP_CONFIG_FILE))
                self.r2.cmd("doo")
                self.r2.cmd("db {}".format(hex(p['addr'])))
                self.r2.cmd("dc")

                reg = self.r2.cmd("dr~{}".format(f['reg']))

                # get bytes until string terminator '\x00'
                reg_bytes = self.r2.cmd("p8 @ {}".format(reg)).split("00")[0].decode("hex")

                match = SequenceMatcher(None, reg_bytes, p['input']).find_longest_match(0, len(reg_bytes), 0, len(p['input']))

                # enough for %x
                if match.size > 2:
                    self._log_error("{} vulnerable to format string @ {}".format(f['func'], hex(p['addr'])))
                    v_append({'func': f['func'], 'addr': p['addr']})


        return vulns


    def r2_set_config(self, inpt):
        os.system("mkdir -p {}".format(self._TMP_DIR))
        with open(self._TMP_INPUT_FILE, "w") as f:
            f.write(inpt)
            f.close()
        
        with open(self._TMP_CONFIG_FILE, "w") as f:
            config = "#!/usr/bin/rarun2\nprogram={}\nstdin={}\n".format(self.binary_path, self._TMP_INPUT_FILE)
            f.write(config)
            f.close()


    def reach_address(self, addr):
        proj = angr.Project(self.binary_path)
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.DFS())

        try:
            simgr.explore(find=addr)
            return simgr.found[0].posix.dumps(0)
        except Exception, e:
            raise Exception("Angr can't reach address {}".format(addr))


    def _plt_xrefs(self, func_name):
        self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
        # search for call xrefs (got)
        calls = self.r2.cmd("/r reloc.{}".format(func_name))
        # parse the xrefs (get plt addr)
        xrefs = self.r2.cmdj("axj")

        if xrefs:
            xrefs = [ ref['from'] for ref in xrefs if ref['refname'] == 'reloc.{}'.format(func_name) and ref['type'] == 'CODE' ]

        plt_addr = ""

        try:
            plt_addr = xrefs[0]
        except:
            return []
        
        # search for call xrefs to plt addr
        self.r2.cmd("/r {}".format(hex(plt_addr)))

        xrefs = self.r2.cmdj("axj")
        plt_xrefs = [ref['from'] for ref in xrefs if ref['addr'] == plt_addr and ref['type'] == 'CALL']

        if plt_xrefs:
            return plt_xrefs
        else:
            return []


    def _log_error(self, msg):
        print "{}{}{}".format(bcolors.FAIL, msg, bcolors.ENDC)

    def _log_info(self, msg):
        print "{}{}{}".format(bcolors.OKBLUE, msg, bcolors.ENDC)

    def _log_succ(self, msg):
        print "{}{}{}".format(bcolors.OKGREEN, msg, bcolors.ENDC)
