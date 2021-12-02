# Description
This tool is most helpful when you are performing an assessment on a large number of hosts and want to quickly view what web services are being hosted. No more loading sites one by one to see what is being hosted. Just load a text file with each host/ip on each line or specify a network range, and scan away. Screenshots will be saved into the current directory or a directory of your choosing.

# Purpose
Quickly view a large number of hosted web applications.

# Usage
-f, --fileip:   file of hostname on each line

-i, --iplist:   list of ip addresses: 192.168.1.0/24,192.168.5.36

-p, --ports:    ports to check: 443,8443

-t, --threads:  number of threads

-o, --output:   screenshot output directory

-v, --verbose:  verbose output
`screengrabber.py -f sites.txt -t 10 -p 443,8080,8443 -v`
`screengrabber.py -i 192.168.1.0/24`