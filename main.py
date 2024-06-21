#! /usr/bin/env python3

import string
from os import geteuid
from scapy.all import *
from datetime import date
from random import choice
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

allowed_characters = string.ascii_letters + "1234567890"
mac_elements = "0123456789abcdef"
broadcast_mac = "ff:ff:ff:ff:ff:ff"
send_interval_delay = 0.5

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

def check_root():
    return geteuid() == 0

def generateRandomMAC():
    return ':'.join([f"{choice(mac_elements)}{choice(mac_elements)}" for _ in range(6)])
def generateRandomString(length):
    return ''.join([choice(allowed_characters) for _ in range(length)])

def sendBeaconFrame(ssid, mac, iface, count, interval):
    dot11 = Dot11(type=0, subtype=8, addr1=broadcast_mac, addr2=mac, addr3=mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    packet = RadioTap() / dot11 / beacon / essid
    sendp(packet, iface=iface, count=count, inter=interval, verbose=False)

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--interface", "interface", "Network Interface to Start Sniffing on"),
                              ('-e', "--essid", "essid", "ESSID for the Beacon Frame (Seperated by '~' and mac seperated by ',' (essid_0,mac_0~essid_1,mac_1) or File containing List of ESSIDs and MAC Addresses (essid,mac) (MAC Address is Optional))"),
                              ('-m', "--mac", "mac", "MAC Addresses for ESSIDs (Seperated by ',' or File Containing List of MAC Addresses, Default=Random)"),
                              ('-d', "--delay", "delay", f"Delay Between Channel Hopping (Default={send_interval_delay} seconds)"),
                              ('-w', "--write", "write", "Dump Packets to a File"))
    if not check_root():
        display('-', f"This Program requires {Back.YELLOW}root{Back.RESET} Privileges")
        exit(0)
    if not arguments.interface or arguments.interface not in get_if_list():
        display('-', "Please specify a Valid Interface")
        display('*', f"Available Interfaces : {Back.MAGENTA}{','.join(get_if_list())}{Back.RESET}")
        exit(0)
    if not arguments.delay:
        arguments.delay = send_interval_delay
    else:
        arguments.delay = float(arguments.delay)
    if arguments.essid:
        try:
            with open(arguments.essid, 'r') as file:
                arguments.essid = {line.split(',')[0]: '' if len(line.split(',')) == 1 else line.split(',')[1] for line in file.read().split('\n')}
        except FileNotFoundError:
            arguments.essid = {essid_mac.split(',')[0]: '' if len(essid_mac.split(',')) == 1 else essid_mac.split(',')[1] for essid_mac in arguments.essid.split('~')}
        except:
            display('-', f"Error while Reading File {Back.YELLOW}{arguments.essid}{Back.RESET}")
            exit(0)
    if arguments.mac:
        arguments.mac = arguments.mac.split(',')
        total_macs = len(arguments.mac)
        current_mac_index = 0
        for essid, mac in arguments.essid.items():
            if mac == '':
                arguments.essid[essid] = arguments.mac[current_mac_index%total_macs]
                current_mac_index += 1
    for essid, mac in arguments.essid.items():
        if mac == '':
            arguments.essid[essid] = generateRandomMAC()