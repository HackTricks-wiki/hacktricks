# Timing Attacks

{{#include ../banners/hacktricks-training.md}}

> [!WARNING]
> For obtaining a deep understanding of this technique check the original report from [https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)

## Basic Information

The basic goal of a timing attack is basically to be able to answer complicated questions or detect hidden functionalities by just **checking the time differences in the responses from similar requests**.

Traditionally this has been very complicated because the latency an jitter introduced by both the network and the server. However, since the discovery and improvement of the [**Race Condition Single Packet attack**](race-condition.md#http-2-single-packet-attack-vs.-http-1.1-last-byte-synchronization), it's possible to use this technique to remove all network delays noised from the equation.\
Leaving only the **server delays** make timing attack easier to discover and abuse.

## Discoveries

### Hidden Attack Surface

In the blog post is commented how using this technique it was possible to find hidden parameters and even headers just checking that whenever the param or header was present in the request there was a **time difference of about 5ms**. Actually, this discovery technique has been adde to **Param Miner** in Burp Suite.

These time differences might because a **DNS request** was performed, some **log was written** because an invalid input or because some **checks are performed** when a parameter is present int he request.

Something you need to remember when performing this kind of attacks is that because of the hidden nature of the surface, you might not know what is the actual real cause of the time differences.

### Reverse Proxy Misconfigurations

In the same research, it was shared that the timing technique was great to discover "scoped SSRFs" (which are SSRFs that can only access to allowed IP/domains). Just **checking the time difference when an allowed domain is set** versus when a not allowed domain is set helps to discover open proxies even if the response is the same.

Once an scoped open proxy is discovered, it was possible to find valid targets by parsing known subdomains of the target and this allowed to:

- **Bypass firewalls** by accessing restricted subdomains via the **open proxy** instead of through internet
  - Moreover, abusing an **open proxy** it's also possible to **discover new subdomains only accessible internally.**
- **Front-End impersonation attacks**: Front-end servers normally add headers for the backend like `X-Forwarded-For` or `X-Real-IP`. Open proxies that receives these headers will add them to the requested endpoint, therefore, an attacker could be able to access even more internal domains by adding these headers will whitelisted values.

## References

- [https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)

{{#include ../banners/hacktricks-training.md}}



