#!/usr/bin/python

import os

def banner():
	print "oooooooooo              oooo     oooo      o      oooooooooo  "
	print " 888    888 oooo   oooo  8888o   888      888      888    888 "
	print " 888oooo88   888   888   88 888o8 88     8  88     888oooo88  "
	print " 888          888 888    88  888  88    8oooo88    888        "
	print "o888o           8888    o88o  8  o88o o88o  o888o o888o       "
	print "             o8o888                                           "
	print ""
	
	print "=============================================================="
	print ""
	print "\tScript by\t: Shulkhan Efendi ( Resxar )"
	print "\tVersion\t\t: 1.0"
	print "\tGithub\t\t: @resxar"
	print ""
        print "=============================================================="

	selection = raw_input("\t[1] Target Specification\n\t[2] Scan Techniques\n\t[3] Host Discovery\n\t[4] Service and Version Detection\n\t[5] Firewall/IDS Evasion and Spoofing\n\t[-] Exit\n\n\t[+] Enter The Number : ")
	if selection ==  "1":
		os.system("clear")
		TargetSpec()
	if selection == "2":
		os.system("clear")
		ScanT()
	if selection == "3":
		os.system("clear")
		HostDiscover()
	if selection == "4":
		os.system("clear")
		ScDomain()
	if selection == "5":
		os.system("clear")
		ScCIDR()

def TargetSpec():
	print "  #####                                                     #######                                        "
	print " #     #  #####   ######   ####   #  ######  #   ####          #       ##    #####    ####   ######  ##### "
	print " #        #    #  #       #       #  #       #  #    #         #      #  #   #    #  #    #  #         #   "
	print "  #####   #    #  #####    ####   #  #####   #  #              #     #    #  #    #  #       #####     #   "
	print "       #  #####   #            #  #  #       #  #              #     ######  #####   #  ###  #         #   "
	print " #     #  #       #       #    #  #  #       #  #    #         #     #    #  #   #   #    #  #         #   "
	print "  #####   #       ######   ####   #  #       #   ####          #     #    #  #    #   ####   ######    #   "
	print "                                                                                                           "
	print ""
	
	selection = raw_input("\t[1] Scan a single IP\n\t[2] Scan specific IPs\n\t[3] Scan a range\n\t[4] Scan a domain\n\t[5] Scan using CIDR notation\n\t[6] Back\n\n\t[+] Enter The Number :  ")
	if selection == "1":
		print ""
		print "\t[x] For Example: 192.168.1.1"
		print ""
		ip = raw_input("\t[+] Input a single IP target : ")
		a = os.system("nmap {}".format(ip))
	if selection == "2":
		print ""
		print "\t[x] For example 192.168.1.1 192.168.1.2"
		print ""
		ip = raw_input("\t[+] Input multiple IPs : ")
		a = os.system("nmap {}".format(ip))
	if selection == "3":
		print ""
		print "\t[x] For example 192.186.1.1-254"
		print ""
		ip = raw_input("\t[+] Input specific range : ")
		a = os.system("nmap {}".format(ip))
	if selection == "4":
                print ""
                print "\t[x] For example yourwebsite.com"
                print ""
                domain = raw_input("\t[+] Input specific domain : ")
                a = os.system("nmap {}".format(domain))
	if selection == "5":
                print ""
                print "\t[x] For example 192.186.1.0/24"
                print ""
                ip = raw_input("\t[+] Input specific CIDR : ")
                a = os.system("nmap {}".format(ip))
	if selection == "6":
		os.system("clear")
		banner()

def ScanT():
	print "============================================================="
	print "=        =============  ====================================="
	print "====  ================  ====================================="
	print "====  ================  ====================================="
	print "====  =====   ===   ==  ====  = ==  ==    =  =  ==   ===   =="
	print "====  ====  =  =  =  =    ==     ====  =  =  =  =  =  =  =  ="
	print "====  ====     =  ====  =  =  =  =  =  =  =  =  =     ==  ==="
	print "====  ====  ====  ====  =  =  =  =  ==    =  =  =  ======  =="
	print "====  ====  =  =  =  =  =  =  =  =  ====  =  =  =  =  =  =  ="
	print "====  =====   ===   ==  =  =  =  =  ====  ==    ==   ===   =="
	print "============================================================="
	print ""

	selection = raw_input("\t[1] TCP SYN Port Scan\n\t[2] TCP Connect Port Scan\n\t[3] UDP Port Scan\n\t[4] TCP ACK Port Scan\n\t[5] Back\n\n\t[+] Enter The Number : ")
	if selection == "1":
		print ""
		tgt = raw_input("\t[+] Input Domain/IP Target : ")
		a = os.system("nmap -sS {}".format(tgt))
        if selection == "2":
                print ""
                tgt = raw_input("\t[+] Input Domain/IP Target : ")
                a = os.system("nmap -sT {}".format(tgt))
        if selection == "3":
                print ""
                tgt = raw_input("\t[+] Input Domain/IP Target : ")
                a = os.system("nmap -sU {}".format(tgt))
        if selection == "4":
                print ""
                tgt = raw_input("\t[+] Input Domain/IP Target : ")
                a = os.system("nmap -sA {}".format(tgt))
	if selection == "5":
		os.system("clear")
		banner()

def HostDiscover():
	print "    __  __           __     ____  _                                     "
	print "   / / / /___  _____/ /_   / __ \(_)_____________ _   _____  _______  __"
	print "  / /_/ / __ \/ ___/ __/  / / / / / ___/ ___/ __ \ | / / _ \/ ___/ / / /"
	print " / __  / /_/ (__  ) /_   / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ / "
	print "/_/ /_/\____/____/\__/  /_____/_/____/\___/\____/|___/\___/_/   \__, /  "
	print "                                                               /____/   "

	selection = raw_input("\t[1] List Target Only\n\t[2] Disable Port Scanning\n\t[3] Disable Host Discovery, Port Scan Only\n\t[4] TCP SYN Discovery on port x\n\t[5] TCP ACK Discovery On Port x\n\t[6] UDP Discovery On Port x\n\t[7] ARP Discovery On Local Network\n\t[8] Never Do DNS Resolution\n\t[9] Back\n\n\t[+] Enter The Number : ")
	if selection == "1":
		print ""
		print "\t[x] For Example : 192.168.1.1-3"
		print ""
		tgt = raw_input("\t[+] Input Target : ")
		a = os.system("nmap -sL {}".format(tgt))
	if selection == "2":
		print ""
		print "\t[x] For Example : 192.168.1.1/24"
		print ""
		tgt = raw_input("\t[+] Input Target : ")
		a = os.system("nmap -sn {}".format(tgt))
	if selection == "3":
		print ""
		print "\t[x] For Example : 192.168.1.1-5"
		print ""
		tgt = raw_input("\t[+] Input Target : ")
		a = os.system("nmap -Pn {}".format(tgt))
	if selection == "4":
                print ""
                print "\t[x] For Example : Target = 192.168.1.1-5"
		print "\t[x] For Example : Port = 22-25,80"
                print ""
                tgt = raw_input("\t[+] Input Target : ")
		port = raw_input("\t[+] Input Port : ")
                a = os.system("nmap {} -PS{}".format(tgt,port))
	if selection == "5":
                print ""
                print "\t[x] For Example : 192.168.1.1-5"
                print "\t[x] For Example : Port = 22-25,80"
                print ""
                tgt = raw_input("\t[+] Input Target : ")
		port = raw_input("\t[+] Input Port : ")
                a = os.system("nmap {} -PA{}".format(tgt,port))
	if selection == "6":
                print ""
                print "\t[x] For Example : 192.168.1.1-5"
                print "\t[x] For Example : Port = 53"
                print ""
                tgt = raw_input("\t[+] Input Target : ")
		port = raw_input("\t[+] Input Port : ")
                a = os.system("nmap {} -PU{}".format(tgt,port))
	if selection == "7":
                print ""
                print "\t[x] For Example : 192.168.1.1-1/24"
                print ""
                tgt = raw_input("\t[+] Input Target : ")
                a = os.system("nmap {} -PR".format(tgt))
	if selection == "8":
                print ""
                print "\t[x] For Example : 192.168.1.1"
                print ""
                tgt = raw_input("\t[+] Input Target : ")
                a = os.system("nmap {} -n".format(tgt))
	if selection == "9":
		os.system("clear")
		banner()

def ScDomain():
	print " __             ___     _            _   _             "
	print "/ _\/\   /\    /   \___| |_ ___  ___| |_(_) ___  _ __  "
	print "\ \ \ \ / /   / /\ / _ \ __/ _ \/ __| __| |/ _ \| '_ \ "
	print "_\ \ \ V /   / /_//  __/ ||  __/ (__| |_| | (_) | | | |"
	print "\__/  \_/   /___,' \___|\__\___|\___|\__|_|\___/|_| |_|"
	print "                                                       "

	selection = raw_input("\t[1] Attempts to determine the version of the service running on port\n\t[2] Intensity level 0 to 9. Higher number increases possibility of correctness\n\t[3] Enable light mode. Lower possibility of correctness. Faster\n\t[4] Enable intensity level 9. Higher possibility of correctness. Slower\n\t[5] Enables OS detection, version detection, script scanning, and traceroute\n\t[6] Back\n\n\t[+] Enter The Number : ")
	if selection == "1":
		print ""
		tgt = raw_input("\tInput Domain/IP Target : ")
		a = os.system("nmap {} -sV ")
	if selection == "2":
                print ""
                tgt = raw_input("\tInput Domain/IP Target : ")
                a = os.system("nmap {} -sV --version-intensity 8 ")
	if selection == "3":
                print ""
                tgt = raw_input("\tInput Domain/IP Target : ")
                a = os.system("nmap {} -sV --version-light")
	if selection == "4":
                print ""
                tgt = raw_input("\tInput Domain/IP Target : ")
                a = os.system("nmap {} -sV --version-all")
	if selection == "5":
                print ""
                tgt = raw_input("\tInput Domain/IP Target : ")
                a = os.system("nmap {} -A ")
	if selection == "6":
		os.system("clear")
		banner()
def ScCIDR():
	print " ___  _                        _  _     __  _  ___  ___ "
	print "| __><_> _ _  ___  _ _ _  ___ | || |   / / | || . \/ __>"
	print "| _> | || '_>/ ._>| | | |<_> || || |  / /  | || | |\__ \'"
	print "|_|  |_||_|  \___.|__/_/ <___||_||_| /_/   |_||___/<___/"
	print "                                                        "

	selection = raw_input("\t[1] Requested scan use tiny fragmented IP packets. Harder for packet filters\n\t[2] Set your own offset size\n\t[3] Send scans from spoofed IPs\n\t[4] Use given source port number\n\t[5] Appends random data to sent packets\n\t[6] Back\n\n\t[+] Enter The Number : ")
	if selection == "1":
		print ""
		tgt = raw_input("\tInput Domain/IP Target : ")
		a = os.system("nmap {} -f".format(tgt))
	if selection == "2":
		print ""
		tgt = raw_input("\tInput Domain/IP Target : ")
		ownoffset = raw_input("\tInput your own offset size : ")
		a = os.system("nmap {} --mtu {}".format(tgt,ownoffset))
	if selection == "3":
		print ""
		print "[x] For example : 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1"
		print "[x] Explained : decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip"
		tgt = raw_input("\tInput Domain/IP Target : ")
		d1 = raw_input("\tInput Decoy-IP 1 : ")
		d2 = raw_input("\tInput Decoy-IP 2 : ")
		yo = raw_input("\tInput Your Own IP : ")
		d3 = raw_input("\tInput Decoy-IP 3 : ")
		d4 = raw_input("\tInput Decoy-IP 4 : ")
		a = os.system("nmap -D {},{},{},{},{} {}".format(d1,d2,yo,d3,d4,tgt))
	if selection == "4":
		print ""
		tgt = raw_input("\tInput Domain/IP Target : ")
		port = raw_input("\tInput Port Target : ")
		a = os.system("nmap -g {} {}".format(port,tgt))
	if selection == "5":
		print ""
		tgt = raw_input("\tInput Domain/IP Target : ")
		dt = raw_input("\tInput random data : ")
		a = os.system("nmap --data-length {} {}".format(dt,tgt))
	if selection == "6":
		os.system("clear")
		banner()

if __name__ == "__main__":
	banner()
