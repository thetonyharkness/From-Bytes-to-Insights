![Analytics.png](Analytics.png)

# Information Gathering

Scanned all TCP ports:

```bash
#nmap scan
nmap -sV -sC -v -p- -oN nmap/initial $IP --open

#nmap results
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

# Enumeration

## TCP Port 80 - HTTP

I first added `analytical.htb` to my hosts file. Then, I opened up my browser and navigated to the target

![Untitled](Untitled.png)

Nothing interesting on the main page, but I do see a login button

When pressing the login button, I get that the site couldn’t be reached, let’s add `data.analytical.htb` to the hosts file and try again.

![Untitled](Untitled%201.png)

Boom, appears to be a Metabase login portal. Given that this is a seasonal machine that was recently released, I looked for CVE’s for Metabase and found [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)

---

# Exploitation

## CVE-2023-38646

This CVE allows us RCE without authentication. There is a Metasploit module for this exploit. I quickly read the information on the exploit and configured it

![Untitled](Untitled%202.png)

![Untitled](Untitled%203.png)

![Untitled](Untitled%204.png)

We’re in!

---

# Privilege Escalation

## Lateral Escalation(Container Escape)

I did my initial checks that I usually perform `whoami;id;env;cat /etc/passwd`

![Untitled](Untitled%205.png)

`metalytics:An4lytics_ds20223#`

We found user credentials in the environment variables, let’s try to login via SSH.

![Untitled](Untitled%206.png)

Initial access as metalytics established

## PrivEsc Vector - CVE-2023-2640

I grabbed the `user.txt` file and began enumeration. 

I first searched for exploits associated with the Distribution and Kernel version and found a Privilege Escalation exploit [here](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629). 

I transferred the exploit to the target and ran it, root access obtained.

![Untitled](Untitled%207.png)

# Trophy

**User.txt**

![Untitled](Untitled%208.png)

**Root.txt**

![Untitled](Untitled%209.png)