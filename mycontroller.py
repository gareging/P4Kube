#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep
import json
import bmpy_utils as utils
import grpc
from  runtime_CLI import RuntimeAPI, load_json_config
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
#sys.path.append(
#    os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

slice_info = [
	{"ip_address": "10.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:01", "port": 1},
	{"ip_address": "11.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:02", "port": 2},
	{"ip_address": "12.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:03", "port": 3},
	{"ip_address": "13.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:04", "port": 4},
	{"ip_address": "14.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:05", "port": 5},
	{"ip_address": "15.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:06", "port": 6},
	{"ip_address": "16.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:07", "port": 7},
	{"ip_address": "17.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:08", "port": 8},
	{"ip_address": "18.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:09", "port": 9},
	{"ip_address": "19.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:10", "port": 10},
	{"ip_address": "20.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:11", "port": 11},
	{"ip_address": "21.0.0.0", "mask": 24, "mac_address": "5E:00:00:00:00:12", "port": 12}
	]


def writeForwardingRule(p4info_helper, sw, ip_address, mask, mac_address, port):
    table_entry = p4info_helper.buildTableEntry(
      table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (ip_address, mask)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": mac_address,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed ingress forwarding rule on %s" % sw.name)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
      #s = p4runtime_lib.bmv2.Bmv2SwitchConnection(name='s1',address='127.0.0.1:9090',device_id=0,proto_dump_file='logs/s1-p4runtime-requests.txt')
      s = p4runtime_lib.bmv2.Bmv2SwitchConnection(name='s1',address='127.0.0.1:9559',device_id=0,proto_dump_file='logs/s1-p4runtime-requests.txt')
    except KeyboardInterrupt:
      print(" Shutting down.")
    except grpc.RpcError as e:
      printGrpcError(e)
      sys.exit()

    try:
      s.MasterArbitrationUpdate()
      print("Master controller installed")
    except grpc.RpcError as e:
      print("Error for s.MasterArbitrationUpdate")
      printGrpcError(e)
      ShutdownAllSwitchConnections()
      sys.exit()


    s.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
    for dst in slice_info:
       writeForwardingRule(p4info_helper, sw=s, ip_address=dst["ip_address"], mask=dst["mask"], mac_address=dst["mac_address"], port=dst["port"])
    print("All rules installed!!!")
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
