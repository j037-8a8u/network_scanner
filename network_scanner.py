#!/usr/bin/env python

import scapy.all as scapy
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="IP address or range to scan.")
    options = parser.parse_args()
    if options.ip:
        return options
    else:
        parser.error("No arguments specified. Use -h for help.")

def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_frame = broadcast/arp_request
    ans_list = scapy.srp(arp_request_frame, timeout=1, verbose=False)[0]
    client_list = []

    for element in ans_list:
        client = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        client_list.append(client)

    return client_list

def print_results(client_list):
    print("IPv4 address\t\t\tMAC address\n-------------------------------------------------")
    for client in client_list:
        print(client["ip"] + "\t\t\t" + client["mac"])

options_list = parse_arguments()
ip = options_list.ip
client_list = arp_scan(ip)
print_results(client_list)
