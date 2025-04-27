# Description
This tool is most helpful when you are performing an assessment on a large number of hosts and want to quickly view what web services are being hosted. No more loading sites one by one to see what is being hosted. Just load a text file with each host/ip on each line or specify a network range, and scan away. Screenshots will be saved into the current directory or a directory of your choosing.

# Purpose
Quickly view a large number of hosted web applications.

# Usage
-f, --fileip    file of hostname on each line

-i, --iplist    list of ip addresses: 192.168.1.0/24,192.168.5.36

-p, --ports     ports to check: 443,8443

-t, --threads   number of threads

-o, --output    screenshot output directory

-v, --verbose   verbose output

`screengrabber.py -f sites.txt -t 10 -p 443,8080,8443 -v`

`screengrabber.py -i 192.168.1.0/24`

``` nmap 10.10.14.14 -p- -sC -sV -A --min-rate=1000 -T4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-19 19:52 EDT
Nmap scan report for 192.168.147.138
Host is up (0.00039s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c8:6b:ba:9b:dd:eb:00:8b:9c:44:93:ed:f8:b2:0c:90 (ECDSA)
|_  256 c0:07:4a:0e:97:22:bf:1e:1d:dd:c2:b8:d1:af:e1:00 (ED25519)
80/tcp    open  http       nginx 1.24.0 (Ubuntu)
|_http-title: Welcome to notes.htb!
|_http-server-header: nginx/1.24.0 (Ubuntu)
36385/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds```
We can see that ports 22 and 80 are both open. Let’s take a look at port 80 and see what it’s hosting.
 
The message on the page says `Welcome to notes.htb` taking notice of the domain, so let’s add this to /etc/hosts file.
``` echo "10.10.14.14 notes.htb" | sudo tee -a /etc/hosts```
Other than the domain name, there is nothing more useful here. Let’s see if we can locate any directories and uncover a site or application.
``` ffuf -u http://notes.htb/FUZZ -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt```
