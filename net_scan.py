#!/usr/bin/python3

import scapy.all as scapy
import argparse
import pyfiglet

banner = pyfiglet.figlet_format("Net Scan", font = "slant")
print(banner)

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter Target IP Address or IP Address range")
    options = parser.parse_args()
    return options

def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout=3, verbose=False)[0]

    clientList = []
    for element in answeredList:
        clientDict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clientList.append(clientDict)
    return clientList

def result(resultList):
    print("IP Address\t\tMAC Address\n<=================================================>")
    for client in resultList:
        print(client["ip"] + "\t\t" + client["mac"])

options = getArguments()
scanResult  = scan(options.target)
result(scanResult)