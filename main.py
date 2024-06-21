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
mac_elements = "0123456789ABCDEF"

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

if __name__ == "__main__":
    pass