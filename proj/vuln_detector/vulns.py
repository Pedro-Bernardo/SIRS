import argparse
from vuln_probe import *

parser = argparse.ArgumentParser(description='Automatic Vulnerability Detector')
parser.add_argument('binary', help='Path to binary')

args = parser.parse_args()

if __name__ == "__main__":
    probe = VulnProbe(args.binary)
    formats = probe.go_fs()
    danger = probe.go_danger()
    print "==================================="
    print "Format String scan -> ", formats
    print "Potential overflow scan -> ", danger