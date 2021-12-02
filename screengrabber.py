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


class ScreenGrabber:
    DRIVER = '/usr/local/bin/chromedriver'
    srv = Service(DRIVER)
    WINDOW_SIZE = "1920,2160"
    site = ''
    vrb = False
    port = ''
    out = ''
    def __init__(self, site, port, vrb, out):
        site = site.strip() # remove trailing \n
        self.site = site
        self.vrb = vrb
        self.out = out
        self.port = port
        if self.port_open():
            self.grabss()

    def port_open(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.site,int(self.port)))
        except Exception as ex:
            print(str(ex))
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
        chrome_options.add_argument("--window-size=%s" % self.WINDOW_SIZE)
        chrome_options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(service=self.srv, options=chrome_options)
        try:
            if self.port == "80":
                driver.get(f'http://{self.site}')
            else:
                driver.get(f'https://{self.site}')
            print(f"[+] Screengrab: ss-{self.site}-{self.port}.png")
            driver.save_screenshot(f'{self.out}ss-{self.site}-{self.port}.png')
            driver.close()
        except Exception as ex:
            print(f'{ex}')
        driver.close()

def get_ips_from_subnet(ip_subnet):
    ips = ipaddress.ip_network(ip_subnet)
    ip_list = [str(ip) for ip in ips]
    return ip_list

parser = argparse.ArgumentParser(description='ScreenGrabber: Sweep an IP space or list of hosts:ports for web applications and take a screenshot. This tool is most useful when you need to scan a large number of hosts for web applications.')
parser.add_argument("-f", "--fileip", action="store", help="file of hostname on each line", type=str)
parser.add_argument("-i", "--iplist", action="store", help="list of ip addresses: 192.168.1.0/24,192.168.5.36", type=str)
parser.add_argument("-p", "--ports", action="store", help="ports to check: 443,8443", default="80,443", type=str)
parser.add_argument("-t", "--threads", action="store", help="number of threads", default=5, type=int)
parser.add_argument("-o", "--output", action="store", help="output directory", default=".", type=str)
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

sites = []
threads = int(args.threads)
output = args.output
if output[-1:] != '/': output += '/'

if args.iplist: # get subnet ips from comma delimited
    for ips in args.iplist.split(","):
        sites += get_ips_from_subnet(ips)

if args.fileip: # get sites from file
    fle = open(args.fileip, "r")
    sites += fle.readlines()
    fle.close()

with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
    futures = []
    print(f"[+] Starting with {threads} threads")
    for site in sites:
        for port in args.ports.split(","):
            if args.verbose:
                print(f"[+] Launching {site.strip()}:{port}")
            futures.append(executor.submit(ScreenGrabber, site, port, args.verbose, output))
print(f"[+] Complete")
