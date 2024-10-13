import argparse
import os
import binascii
import re
from objects import *

if __name__ == "__main__":
    object_nt_ace_df = None
    # Read value from a file
    parser = argparse.ArgumentParser(description="Script to load ntSecurityDescriptor from file")
    parser.add_argument('-v', '--value', help="Path to the file", required=True)
    args = parser.parse_args()

    if args.value is not None:
        if os.path.isfile(args.value):
            print("[+] Loading ntSecurityDescriptor from file '%s'" % args.value)
            filename = args.value
            raw_ntsd_value = open(filename, 'r').read().strip()
        if re.compile(r'^[0-9a-fA-F]+$').match(raw_ntsd_value):
            raw_ntsd_value = binascii.unhexlify(raw_ntsd_value)
        
        if raw_ntsd_value is not None:
            ntsd = NTSecurityDescriptor(
                value=raw_ntsd_value, 
                verbose=False,
                ldap_searcher=None
            )
            objecct_nt_ace_df = ntsd.describe()
            print(objecct_nt_ace_df)
