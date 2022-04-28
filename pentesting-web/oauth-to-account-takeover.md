# OAuth to Account takeover

## Basic Information <a href="#d4a8" id="d4a8"></a>

There are a couple different versions of OAuth, you can read [https://oauth.net/2/](https://oauth.net/2/) to get a baseline understanding.

In this article, we will be focusing on the most common flow that you will come across today, which is the [OAuth 2.0 authorization code grant type](https://oauth.net/2/grant-types/authorization-code/). In essence, OAuth provides developers an **authorization mechanism to allow an application to access data or perform certain actions against your account, from another application** (the authorization server).

For example, let’s say website _**https://yourtweetreader.com**_ has functionality to **display all tweets you’ve ever sent**, including private tweets. In order to do this, OAuth 2.0 is introduced. _https://yourtweetreader.com_ will ask you to **authorize their Twitter application to access all your Tweets**. A consent page will pop up on _https://twitter.com_ displaying what **permissions are being requested**, and who the developer requesting it is. Once you authorize the request, _https://yourtweetreader.com_ will be **able to access to your Tweets on behalf of you**.

Elements which are important to understand in an OAuth 2.0 context:

* **resource owner**: The `resource owner` is the **user/entity** granting access to their protected resource, such as their Twitter account Tweets. In this example, this would be **you**.
* **resource server**: The `resource server` is the **server handling authenticated requests** after the application has obtained an `access token` on behalf of the `resource owner` . In this example, this would be **https://twitter.com**
* **client application**: The `client application` is the **application requesting authorization** from the `resource owner`. In this example, this would be **https://yourtweetreader.com**.
* **authorization server**: The `authorization server` is the **server issuing `access tokens`** to the `client application` **after successfully authenticating** the `resource owner` and obtaining authorization. In the above example, this would be **https://twitter.com**
* **client\_id**: The `client_id` is the **identifier for the application**. This is a public, **non-secret** unique identifier.
* **client\_secret:** The `client_secret` is a **secret known only to the application and the authorization server**. This is used to generate `access_tokens`
* **response\_type**: The `response_type` is a value to detail **which type of token** is being requested, such as `code`
* **scope**: The `scope` is the **requested level of access** the `client application` is requesting from the `resource owner`
* **redirect\_uri**: The `redirect_uri` is the **URL the user is redirected to after the authorization is complete**. This usually must match the redirect URL that you have previously registered with the service
* **state**: The `state` parameter can **persist data between the user being directed to the authorization server and back again**. It’s important that this is a unique value as it serves as a **CSRF protection mechanism** if it contains a unique or random value per request
* **grant\_type**: The `grant_type` parameter explains **what the grant type is**, and which token is going to be returned
* **code**: This `code` is the authorization code received from the `authorization server` which will be in the query string parameter “code” in this request. This code is used in conjunction with the `client_id` and `client_secret` by the client application to fetch an `access_token`
* **access\_token**: The `access_token` is the **token that the client application uses to make API requests** on behalf of a `resource owner`
* **refresh\_token**: The `refresh_token` allows an application to **obtain a new `access_token` without prompting the user**

### Real Example

Putting this all together, here is what a **real OAuth flow looks like**:

1. You visit [https://yourtweetreader.com](https://yourtweetreader.com) and click the “Integrate with Twitter” button.
2. [https://yourtweetreader.com](https://yourtweetreader.com) sends a request to [https://twitter.com](https://twitter.com) asking you, the resource owner, to authorize https://yourtweetreader.com’s Twitter application to access your Tweets. The request will look like:

```
https://twitter.com/auth
 ?response_type=code
 &client_id=yourtweetreader_clientId
 &redirect_uri=https%3A%2F%2Fyourtweetreader.com%2Fcallback
 &scope=readTweets
 &state=kasodk9d1jd992k9klaskdh123
```

3\. You will be prompted with a consent page:

![](https://miro.medium.com/max/1215/1\*y66EY3Fn2qn-NPI9nhZC7A.png)

4\. Once accepted, Twitter will send a request back to the `redirect_uri` with the `code` and `state` parameters:

```
https://yourtweetreader.com?code=asd91j3jd91j92j1j9d1&state=kasodk9d1jd992k9klaskdh123
```

5\. [https://yourtweetreader.com](https://yourtweetreader.com) will then take that `code` , and using their application’s `client_id` and `client_secret` , will make a request from the server to retrieve an `access_token` on behalf of you, which will allow them to access the permissions you consented to:

```
POST /oauth/access_token
Host: twitter.com
...{"client_id": "yourtweetreader_clientId", "client_secret": "yourtweetreader_clientSecret", "code": "asd91j3jd91j92j1j9d1", "grant_type": "authorization_code"}
```

6\. Finally, the flow is complete and [https://yourtweetreader.com](https://yourtweetreader.com) will make an API call to Twitter with your `access_token` to access your Tweets.

## Bug Bounty Findings <a href="#323a" id="323a"></a>

Now, the interesting part! There are many things that can go wrong in an OAuth implementation, here are the different categories of bugs I frequently see:

### Weak redirect\_uri configuration <a href="#cc36" id="cc36"></a>

. The `redirect_uri` is very important because **sensitive data, such as the `code` is appended to this URL** after authorization. If the `redirect_uri` can be redirected to an **attacker controlled server**, this means the attacker can potentially **takeover a victim’s account** by using the `code` themselves, and gaining access to the victim’s data.

The way this is going to be exploited is going to vary by authorization server. **Some** will **only accept** the exact same ** `redirect_uri` path as specified in the client application**, but some will **accept anything** in the same domain or subdirectory of the `redirect_uri` .

Depending on the logic handled by the server, there are a number of techniques to bypass a `redirect_uri` . In a situation where a `redirect_uri` is [https://yourtweetreader.com](https://yourtweetreader.com)/callback, these include:

* Open redirects: [`https://yourtweetreader.com`](https://yourtweetreader.com)`/callback?redirectUrl=https://evil.com`
* Path traversal: `https://yourtweetreader.com/callback/../redirect?url=https://evil.com`
* Weak `redirect_uri` regexes: `https://yourtweetreader.com.evil.com`
* HTML Injection and stealing tokens via referer header: `https://yourtweetreader.com/callback/home/attackerimg.jpg`

**Other parameters** that can be vulnerable to Open Redirects are:

* **client\_uri** - URL of the home page of the client application
* **policy\_uri** - URL that the Relying Party client application provides so that the end user can read about how their profile data will be used.
* **tos\_uri** - URL that the Relying Party client provides so that the end user can read about the Relying Party's terms of service.
* **initiate\_login\_uri** - URI using the https scheme that a third party can use to initiate a login by the RP. Also should be used for client-side redirection.

All these parameters are **optional according to the OAuth and OpenID** specifications and not always supported on a particular server, so it's always worth identifying which parameters are supported on your server.

If you target an OpenID server, the discovery endpoint at **`.well-known/openid-configuration`**sometimes contains parameters such as "_registration\_endpoint_", "_request\_uri\_parameter\_supported_", and "_require\_request\_uri\_registration_". These can help you to find the registration endpoint and other server configuration values.

### XSS in redirect implementation <a href="#bda5" id="bda5"></a>

As mentioned in this bug bounty report [https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html](https://blog.dixitaditya.com/2021/11/19/account-takeover-chain.html) it might be possible that the redirect **URL is being reflected in the response** of the server after the user authenticates, being **vulnerable to XSS**. Possible payload to test:

```
https://app.victim.com/login?redirectUrl=https://app.victim.com/dashboard</script><h1>test</h1>
```

### CSRF - Improper handling of state parameter <a href="#bda5" id="bda5"></a>

Very often, the **`state` parameter is completely omitted or used in the wrong way**. If a state parameter is **nonexistent**, **or a static value** that never changes, the OAuth flow will very likely be **vulnerable to CSRF**. Sometimes, even if there is a `state` parameter, the **application might not do any validation of the parameter** and an attack will work. The way to exploit this would be to go through the authorization process on your own account, and pause right after authorising. You will then come across a request such as:

```
https://yourtweetreader.com?code=asd91j3jd91j92j1j9d1
```

After you receive this request, you can then **drop the request because these codes are typically one-time use**. You can then send this URL to a **logged-in user, and it will add your account to their account**. At first, this might not sound very sensitive since you are simply adding your account to a victim’s account. However, many OAuth implementations are for sign-in purposes, so if you can add your Google account which is used for logging in, you could potentially perform an **Account Takeover** with a single click as logging in with your Google account would give you access to the victim’s account.

You can find an **example** about this in this [**CTF writeup**](https://github.com/gr455/ctf-writeups/blob/master/hacktivity20/notes\_surfer.md) and in the **HTB box called Oouch**.

I’ve also seen the state parameter used as an additional redirect value several times. The application will use `redirect_uri` for the initial redirect, but then the `state` parameter as a second redirect which could contain the `code` within the query parameters, or referer header.

One important thing to note is this doesn’t just apply to logging in and account takeover type situations. I’ve seen misconfigurations in:

* Slack integrations allowing an attacker to add their Slack account as the recipient of all notifications/messages
* Stripe integrations allowing an attacker to overwrite payment info and accept payments from the victim’s customers
* PayPal integrations allowing an attacker to add their PayPal account to the victim’s account, which would deposit money to the attacker’s PayPal

### Pre Account Takeover <a href="#ebe4" id="ebe4"></a>

One of the other more common issues I see is when applications allow “Sign in with X” but also username/password. There are 2 different ways to attack this:

1. If the application does **not require email verification on account creation**, try **creating an account with a victim’s email address and attacker password** before the victim has registered. If the **victim** then tries to register or sign in **with a third party**, such as Google, it’s possible the application will do a lookup, see that email is already registered, then l**ink their Google account to the attacker created account**. This is a “**pre account takeover**” where an attacker will have access to the victim’s account if they created it prior to the victim registering.
2. If an **OAuth app does not require email verification**, try signing up with that OAuth app with a **victim’s email address**. The same issue as above could exist, but you’d be attacking it from the other direction and getting access to the victim’s account for an account takeover.

### Disclosure of Secrets <a href="#e177" id="e177"></a>

It’s very important to recognize **which of the many OAuth parameters are secret**, and to protect those. For example, leaking the `client_id` is perfectly fine and necessary, but leaking the **`client_secret` is dangerous**. If this is leaked, the **attacker** can potentially **abuse the trust and identity of the trusted client application to steal user `access_tokens` and private information/access for their integrated accounts**. Going back to our earlier example, one issue I’ve seen is performing this step from the client, instead of the server:

_5._ [_https://yourtweetreader.com_](https://yourtweetreader.com) _will then take that `code` , and using their application’s `client_id` and `client_secret` , will make a request from the server to retrieve an `access_token` on behalf of you, which will allow them to access the permissions you consented to._

**If this is done from the client, the `client_secret` will be leaked and users will be able to generate `access_tokens` on behalf of the application**. With some social engineering, they can also **add more scopes to the OAuth authorization** and it will all appear legitimate as the request will come from the trusted client application.

### Client Secret Bruteforce

You can try to **bruteforce the client\_secret** of a service provider with the identity provider in order to be try to steal accounts.\
The request to BF may look similar to:

```
POST /token HTTP/1.1
content-type: application/x-www-form-urlencoded
host: 10.10.10.10:3000
content-length: 135
Connection: close

code=77515&redirect_uri=http%3A%2F%2F10.10.10.10%3A3000%2Fcallback&grant_type=authorization_code&client_id=public_client_id&client_secret=[bruteforce]
```

### Referer Header leaking Code + State

Once the client has the **code and state**, if it's **reflected inside the Referer header** when he browses to a different page, then it's vulnerable.

### Access Token Stored in Browser History

Go to the **browser history and check if the access token is saved in there**.

### Everlasting Authorization Code

The **authorization code should live just for some time to limit the time window where an attacker can steal  and use it**.

### Authorization/Refresh Token not bound to client

If you can get the **authorization code and use it with a different client then you can takeover other accounts**.

### AWS Cognito <a href="#bda5" id="bda5"></a>

In this bug bounty report: [**https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/**](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/) you can see that the **token** that **AWS Cognito** gives back to the user might have **enough permissions to overwrite the user data**. Therefore, if you can **change the user email for a different user email**, you might be able to **take over** others accounts.

```
# Read info of the user
aws cognito-idp get-user --region us-east-1 --access-token eyJraWQiOiJPVj[...]

# Change email address
aws cognito-idp update-user-attributes --region us-east-1 --access-token eyJraWQ[...] --user-attributes Name=email,Value=imaginary@flickr.com
{
    "CodeDeliveryDetailsList": [
        {
            "Destination": "i***@f***.com",
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    ]
}
```

### SSRFs parameters <a href="#bda5" id="bda5"></a>

One of the hidden URLs that you may miss is the **Dynamic Client Registration endpoint**. In order to successfully authenticate users, OAuth servers need to know details about the client application, such as the "client\_name", "client\_secret", "redirect\_uris", and so on. These details can be provided via local configuration, but OAuth authorization servers may also have a **special registration endpoint**. This endpoint is normally mapped to "/register" and accepts POST requests with the following format:

```json
POST /connect/register HTTP/1.1
Content-Type: application/json
Host: server.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...

{
 "application_type": "web",
 "redirect_uris": ["https://client.example.org/callback"],
 "client_name": "My Example",
 "logo_uri": "https://client.example.org/logo.png",
 "subject_type": "pairwise",
 "sector_identifier_uri": "https://example.org/rdrct_uris.json",
 "token_endpoint_auth_method": "client_secret_basic",
 "jwks_uri": "https://client.example.org/public_keys.jwks",
 "contacts": ["ve7jtb@example.org"],
 "request_uris": ["https://client.example.org/rf.txt"]
}
```



There are two specifications that define parameters in this request: [RFC7591](https://tools.ietf.org/html/rfc7591) for OAuth and [Openid Connect Registration 1.0](https://openid.net/specs/openid-connect-registration-1\_0.html#rfc.section.3.1).

As you can see here, a number of these values are passed in via URL references and look like potential targets for [Server Side Request Forgery](https://portswigger.net/web-security/ssrf). At the same time, most servers we've tested do not resolve these URLs immediately when they receive a registration request. Instead, they just **save these parameters and use them later during the OAuth authorization flow**. In other words, this is more like a second-order SSRF, which makes black-box detection harder.

The following parameters are particularly interesting for SSRF attacks:

* **logo\_uri** - URL that references a **logo for the client application**. **After you register a client**, you can try to call the OAuth authorization endpoint ("/authorize") using your new "client\_id". After the login, the server will ask you to approve the request and **may display the image from the "logo\_uri"**. If the **server fetches the image by itself**, the SSRF should be triggered by this step. Alternatively, the server may just include the logo via a **client-side "\<img>" tag**. Although this doesn't lead to SSRF, it may lead to **XSS if the URL is not escaped**.
*   **jwks\_uri** - URL for the client's JSON Web Key Set \[JWK] document. This key set is needed on the server for validating signed requests made to the token endpoint when using JWTs for client authentication \[RFC7523]. In order to test for SSRF in this parameter, **register a new client application with a malicious "jwks\_uri"**, perform the authorization process to **obtain an authorization code for any user, and then fetch the "/token" endpoint** with the following body:

    `POST /oauth/token HTTP/1.1`\
    `...`\
    ``\
    `grant_type=authorization_code&code=n0esc3NRze7LTCu7iYzS6a5acc3f0ogp4&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=eyJhbGci...`

    If vulnerable, the **server should perform a server-to-server HTTP request to the supplied "jwks\_uri"** because it needs this key to check the validity of the "client\_assertion" parameter in your request. This will probably only be a **blind SSRF vulnerability though**, as the server expects a proper JSON response.
* **sector\_identifier\_uri** - This URL references a file with a single **JSON array of redirect\_uri values**. If supported, the server may **fetch this value as soon as you submit the dynamic registration request**. If this is not fetched immediately, try to perform authorization for this client on the server. As it needs to know the redirect\_uris in order to complete the authorization flow, this will force the server to make a request to your malicious sector\_identifier\_uri.
*   **request\_uris** - An array of the **allowed request\_uris for this client**. The "request\_uri" parameter may be supported on the authorization endpoint to provide a URL that contains a JWT with the request information (see [https://openid.net/specs/openid-connect-core-1\_0.html#rfc.section.6.2](https://openid.net/specs/openid-connect-core-1\_0.html#rfc.section.6.2)).

    Even if dynamic client registration is not enabled, or it requires authentication, we can try to perform SSRF on the authorization endpoint simply by using "request\_uri":\


    `GET /authorize?response_type=code%20id_token&client_id=sclient1&request_uri=https://ybd1rc7ylpbqzygoahtjh6v0frlh96.burpcollaborator.net/request.jwt`

    Note: do not confuse this parameter with "redirect\_uri". The "redirect\_uri" is used for redirection after authorization, whereas **"request\_uri" is fetched by the server at the start of the authorization process**.

    At the same time, many servers we've seen do not allow arbitrary "request\_uri" values: they only allow whitelisted URLs that were pre-registered during the client registration process. That's why we need to supply "request\_uris": "https://ybd1rc7ylpbqzygoahtjh6v0frlh96.burpcollaborator.net/request.jwt" beforehand.

## OAuth providers Race Conditions

If the platform you are testing is an OAuth provider [**read this to test for possible Race Conditions**](race-condition.md).

## References

* [**https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1**](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
* [**https://portswigger.net/research/hidden-oauth-attack-vectors**](https://portswigger.net/research/hidden-oauth-attack-vectors)
