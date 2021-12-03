from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import concurrent.futures
import argparse
import sys
import ipaddress
import socket

# Environment Setup:
# sudo apt-get install -y unzip openjdk-8-jre-headless xvfb libxi6 libgconf-2-4
# sudo curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add
# sudo echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list
# sudo apt-get -y update
# sudo apt-get -y install google-chrome-stable
# wget -N https://chromedriver.storage.googleapis.com/@@CURRENT_VERSION_OF_CHROME@@/chromedriver_linux64.zip -P ~/
# unzip ~/chromedriver_linux64.zip -d ~/
# rm ~/chromedriver_linux64.zip
# sudo mv -f ~/chromedriver /usr/local/bin/chromedriver
# sudo chown root:root /usr/local/bin/chromedriver
# sudo chmod 0755 /usr/local/bin/chromedriver
# pip install selenium
DRIVER = '/usr/local/bin/chromedriver'

class ScreenGrabber:
    srv = None
    sze = ''
    site = ''
    vrb = False
    port = ''
    out = ''
    wait = 0
    def __init__(self, site, port, vrb, out, sze, wait, driver):
        site = site.strip() # remove trailing \n
        self.site = site
        self.vrb = vrb
        self.out = out
        self.port = port
        self.sze = sze
        self.wait = wait
        self.srv = Service(driver)
        if self.port_open():
            self.grabss()

    def port_open(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.wait)
            result = sock.connect_ex((self.site,int(self.port)))
        except Exception as ex:
            print(f"[!] {self.site}:{self.port}: {ex}")
            sock.close()
            return False
        if result == 0:
            sock.close()
            if self.vrb:
                print(f"[+] Port Open: {self.site}:{self.port}")
            return True
        else:
            sock.close()
            if self.vrb:
                print(f"[!] Port Closed: {self.site}:{self.port}")
            return False

    def grabss(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=%s" % self.sze)
        chrome_options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(service=self.srv, options=chrome_options)
        try:
            if self.port == "80":
                driver.get(f'http://{self.site}')
            else:
                driver.get(f'https://{self.site}:{self.port}')
            print(f"[+] Screengrab: {self.site}-{self.port}.png")
            driver.save_screenshot(f'{self.out}{self.site}-{self.port}.png')
            driver.close()
        except Exception as ex:
            print(f'{ex}')
        driver.close()

parser = argparse.ArgumentParser(description='ScreenGrabber: Sweep an IP space or list of hosts:ports for web applications and take a screenshot. This tool is most useful when you need to scan a large number of hosts for web applications.')
parser.add_argument("-f", "--fileip", action="store", help="file of hostname on each line", type=str)
parser.add_argument("-i", "--iplist", action="store", help="list of ip addresses: 192.168.1.0/24,192.168.5.36", type=str)
parser.add_argument("-p", "--ports", action="store", help="ports to check: 443,8443", default="80,443", type=str)
parser.add_argument("-t", "--threads", action="store", help="number of threads", default=5, type=int)
parser.add_argument("-w", "--wait", action="store", help="timeout", default=4, type=int)
parser.add_argument("-o", "--output", action="store", help="output directory", default=".", type=str)
parser.add_argument("-s", "--size", action="store", help="size of page to grab: 1920,1080", default="1920,1080", type=str)
parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
args = parser.parse_args()

def example():
    print("\nExamples: ")
    print("screengrabber.py -f sites.txt -t 10 -p 443,8080,8443 -v")
    print("screengrabber.py -i 192.168.1.0/24")

if len(sys.argv[1:])==0:
    parser.print_help()
    example()
    parser.exit()

if args.fileip == None and args.iplist == None:
    parser.print_help()        
    example()
    parser.exit()

if args.output[-1:] != '/': args.output += '/'

def get_ips_from_subnet(ip_subnet):
    ips = ipaddress.ip_network(ip_subnet)
    ip_list = [str(ip) for ip in ips]
    return ip_list

sites = []
if args.iplist: # get subnet ips from comma delimited
    try:
        for ips in args.iplist.split(","):
            sites += get_ips_from_subnet(ips)
    except Exception as ex:
        print(f"[!] Error processing ip list: {ex}")
        sys.exit()

if args.fileip: # get sites from file
    try:
        fle = open(args.fileip, "r")
        sites += fle.readlines()
        fle.close()
    except Exception as ex:
        print(f"[!] Error opening file: {ex}")
        sys.exit()

# clean site list
tmps = []
for site in sites:
    try:
        site = site.replace('http://','')
        site = site.replace('https://','')
        # add ports
        for port in args.ports:
            if ":" in site: # already has port
                tmps.append(site)
                s = site.split(':') # remove port
                site = s[0] # and prepare to add new ports
            tmps.append(f"{site}:{port}")
    except Exception as ex:
        print(f"[+] Error processing hosts/ip [{site}]: {ex}")
        continue
sites = tmps

if args.size: # get check the screenshot size
    try:
        s = args.size.split(',')
        if s[0].isnumeric() != True or s[1].isnumeric() != True:
            print("[!] Error with screenshot size: value must be numeric 800,600")
            sys.exit() 
    except Exception as ex:
        print(f"[!] Error with screenshot size: {ex}")
        sys.exit()

if args.ports: # check ports
    try:
        s = args.ports.split(',')
        for p in s:
            if p.isnumeric() != True:
                print("[!] Error with ports: value must be positive numeric")
                sys.exit() 
    except Exception as ex:
        print(f"[!] Error with screenshot size: {ex}")
        sys.exit()

try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        print(f"[+] Starting with {args.threads} threads")
        #TODO: make changes to launch, no longer need ports arg, all ports are added manually
        for site in sites:
            for port in args.ports.split(","):
                if args.verbose:
                    print(f"[+] Launching {site.strip()}:{port}")
                futures.append(executor.submit(ScreenGrabber, site, args.port, args.verbose, args.output, args.size, args.wait, DRIVER))
except Exception as ex:
        print(f"[!] Error launching threads: {ex}")
        sys.exit()
print(f"[+] Complete")
