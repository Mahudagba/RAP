#!/usr/bin/env python3
try:
    from os import system
    from sys import exit
    from dprappkg.AccessPoint import *
    from dprappkg.Deauth import *
    from dprappkg.RAPInterne import *
    from dprappkg.Scanner import *
    from dprappkg.ThreadRap import *
    import argparse
except Exception as e:
    system("clear")
    print(e)

parser = argparse.ArgumentParser(description="Detect Rogue Access Point, and can, in some case protect again")
parser.add_argument("--iface", "-i", help="The monitor intreface to watch on", required=False)
parser.add_argument("--essid", "-e", help="The SSID of the legitimate access point to protect.", required=False)
parser.add_argument("--bssid", "-a", help="The BSSID of the legitimate access point to protect.", required=False)
parser.add_argument("--file", "-f", help="The file contains lines of SSID,BSSID (example of line: \n\t\t\thome,""00"
                                         ":00:00:00:00:00:00:00")
parser.add_argument("--intern", "-I", action="store_true", help="Search the Rogue point in the local network")
parser.add_argument("--extern", "-E", action="store_true", help="Search the Evil twin")
parser.usage = "\n   dprap -I\n   dprap -E --essid wifi_essid --bssid " \
               "00:00:00:00:00:00:00:00 --iface mon0 :Search the Evil Twin of wifi_essid" \
               "\n   dprap -E --file ap_list --iface mon0 : Get essids and bssids in ap_list"

args = parser.parse_args()
thread_list = list()


def show_help(advice):
    print('\033[31m', advice, '\033[0m', sep='')
    print(parser.format_help())


def show_banner():
    system("clear")
    dprap_version = "version 1.0"
    print("#" * 52)
    print(" ______   _____ ______    ____   _____   ")
    print("(_  __ \\ (  __ (   __ \\  (    ) (  __ \\  ")
    print("  ) ) \\ \\ ) )_) ) (__) ) / /\\ \\  ) )_) ) ")
    print(" ( (   ) (  ___(    __/ ( (__) )(  ___/  ")
    print("  ) )  ) )) )   ) \\ \\  _ )    (  ) )     ")
    print(" / /__/ /( (   ( ( \\ \\_)/  /\\  \\( (      ")
    print("(______/ /__\\   )_) \\__/__(  )__/__\\     ")
    print("                                         " '\033[90m', dprap_version, '\033[0m', sep='')
    print("#" * 52)
    print("")
    print("")


def wlan():
    if args.file and not (args.essid and args.bssid):
        print('\033[34m', "Notice: Press ENTER to see the number of packets.", '\033[0m', sep='')
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    content = line.split(',')
                    bssid = content[1]
                    essid = content[0]
                    thread = ThreadRap(bssid=bssid, essid=essid, iface=args.iface)
                    thread.start()
                    thread_list.append(thread)
        except FileNotFoundError as fe:
            system("clear")
            print("File", '\033[31m', args.file, '\033[0m', "not found", sep='')
            exit(0)
        except KeyboardInterrupt as ke:
            exit(0)

    else:
        if args.essid and args.bssid:
            print('\033[34m', "Notice: Press ENTER to see the number of packets.", '\033[0m', sep='')
            try:
                thread = ThreadRap(bssid=args.bssid, essid=args.essid, iface=args.iface)
                thread.start()
                thread_list.append(thread)
            except KeyboardInterrupt as ke:
                exit(0)
        else:
            show_help("missing SSID or BSSID, look for manuel")
            exit(0)


if __name__ == '__main__':
    try:
        show_banner()
        if not args.intern and args.extern:
            if args.iface:
                wlan()
            else:
                show_help("missing interface")
                exit(0)
        elif args.intern and not args.extern:
            rap_ether()
        else:
            show_help("Please read the manuel. Need options -w or -t")
            exit(0)
    except KeyboardInterrupt as ke:
        exit(0)

