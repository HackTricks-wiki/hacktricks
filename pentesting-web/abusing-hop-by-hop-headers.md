# hop-by-hop headers

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## What is a hop-by-hop header?

A hop-by-hop header is a header which is designed to be processed and consumed by the proxy currently handling the request, as opposed to an end-to-end header.

According to [RFC 2616](https://tools.ietf.org/html/rfc2616#section-13.5.1), the HTTP/1.1 spec treats the following headers as hop-by-hop by default: `Keep-Alive`, `Transfer-Encoding`, `TE`, `Connection`, `Trailer`, `Upgrade`, `Proxy-Authorization` and `Proxy-Authenticate`. When encountering these headers in a request, a compliant proxy should process or action whatever it is these headers are indicating, and not forward them on to the next hop.

Further to these defaults, a request [may also define a custom set of headers to be treated as hop-by-hop](https://tools.ietf.org/html/rfc2616#section-14.10) by adding them to the `Connection` header, like so:

```
Connection: close, X-Foo, X-Bar
```

## The theory on abusing hop-by-hop headers

In theory, proxies should remove hop-by-hop headers received before sending them to the next address. But you can find in the wild that this is done by some proxies and others just send all the headers adding its own `Connection`header.

![](<../.gitbook/assets/image (138).png>)

## Testing hop-by-hop deletions

If you find a header that makes the response of the server changes if it is set of if it is not, then you can search for hop-by-hop deletions. For example, the cookie header will make the response of the server to be dramatically different if it is set (with a valid content) and if it is not.

So, send a request with a valid header and with this value of the Connection header `Connection: close, Cookie` if the response is the same as if the cookie wasn't sent, then there is a proxy removing headers.

You can find if the response of the server is any different if a header is deleted using this technique using[ this script](https://gist.github.com/ndavison/298d11b3a77b97c908d63a345d3c624d). Then, if you pass in a list of known headers, such as [this one](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers), you can observe which headers are causing effects despite not being in your original request:

```
for HEADER in $(cat headers.txt); do python poison-test.py -u "https://target" -x "$HEADER"; sleep 1; done
```

This will cycle through the entire header list and print out if its presence in the hop-by-hop list created a different status code or response body size.

## Abusing X-Forwarded-For

In general, proxies will add the IPs of the clients inside the `X-Forwarded-For` header so the next hop will know where does the petition comes from. However, if an attacker sends a Connection value like `Connection: close, X-Forwarded-For` and the first proxy sends the hop-by-hop headers with their values (it sends the special Connection value), then the second value may delete the X-Forward-For header.\
At the end, the final App won't know who sent the request and may think that it was the last proxy, and is this scenario an attacker may be able to access resources protected by IP whitelisting (maybe some `/admin` ?).

Depending on the system being targeted, you may also have `Forwarded`, `X-Real-IP`, and a bunch of others that are less common.

## Detecting Proxies and fingerprinting services

This technique may be useful to detect proxies (using the cookie technique) or even to detect services. For example, if you abuse this technique to delete the header `X-BLUECOAT-VIA` and an error is thrown, then you have find that Bluecoat was being used.

## Other Attacks

* For a possible DoS Cache poisoning abusing this technique read the original link
* This could be useful in attacks that may allow you to insert new headers (low probability)
* Also,it could be useful to bypass defensive functionalities. For example, if the lack of a header means that a request shouldn't be processed by a WAF, you could bypass a WAF with this technique.

## References

{% embed url="https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers" %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.\


{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
