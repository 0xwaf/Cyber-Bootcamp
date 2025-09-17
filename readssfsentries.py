import logging
from pysap.SAPSSFS import SAPSSFSData, SAPSSFSKey, SAPSSFSDecryptedPayload
from pysap.utils.crypto import rsec_decrypt
import argparse
import os
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('pysap.ssfs')

def read_file_or_value(path_or_value):
    if os.path.isfile(path_or_value):
        with open(path_or_value, 'rb') as f:
            return f.read()
    else:
        return path_or_value

def safe_print_key(ssfs_key):
    try:
        key_info = {
            "Key User": ssfs_key.user,
            "Key Length": len(ssfs_key.key) if ssfs_key.key else None
        }
        return key_info
    except Exception as e:
        logger.error("Error printing key: %s", e)
        return {"Error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Reading SSFS data and listing its entries")
    parser.add_argument('-d', '--data', required=True, help="Path of SSFS data file")
    parser.add_argument('-k', '--key', required=True, help="Path of SSFS key file")
    args = parser.parse_args()

    data = read_file_or_value(args.data)
    key = read_file_or_value(args.key)

    output = {}

    try:
        ssfs_data = SAPSSFSData(data)
        ssfs_key = SAPSSFSKey(key)
        output["Entries"] = repr(ssfs_data.show())

    except Exception as e:
        logger.error("Error processing SSFS data: %s", e)
        output["Processing Error"] = str(e)

    key_info = safe_print_key(ssfs_key)
    output.update(key_info)

    for key, value in output.items():
        print("{}: {}".format(key, value))

if __name__ == '__main__':
    main()
