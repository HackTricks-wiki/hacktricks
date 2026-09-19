# Domain/Subdomain takeover

{{#include ../banners/hacktricks-training.md}}


## Domain takeover

If an in-scope service still depends on a domain whose registration has expired, an authorized tester may be able to register it and demonstrate a **domain takeover**. The impact increases when applications send the domain sensitive data in URL parameters, redirects, or the `Referer` header.<sup>[[1]](#references)</sup>

### Subdomain takeover

A subdomain of the company is pointing to a **third-party service with a name not registered**. If you can **create** an **account** in this **third party service** and **register** the **name** being in use, you can perform the subdomain takeover.<sup>[[2]](#references)</sup>

There are several tools with dictionaries to check for possible takeovers:

- [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)
- [https://github.com/punk-security/dnsReaper](https://github.com/punk-security/dnsReaper)
- [https://github.com/haccer/subjack](https://github.com/haccer/subjack)
- [https://github.com/anshumanbh/tko-sub](https://github.com/anshumanbh/tko-subs)
- [https://github.com/ArifulProtik/sub-domain-takeover](https://github.com/ArifulProtik/sub-domain-takeover)
- [https://github.com/SaadAhmedx/Subdomain-Takeover](https://github.com/SaadAhmedx/Subdomain-Takeover)
- [https://github.com/Ice3man543/SubOver](https://github.com/Ice3man543/SubOver)
- [https://github.com/antichown/subdomain-takeover](https://github.com/antichown/subdomain-takeover)
- [https://github.com/musana/mx-takeover](https://github.com/musana/mx-takeover)
- [https://github.com/PentestPad/subzy](https://github.com/PentestPad/subzy)
- [https://github.com/Stratus-Security/Subdominator](https://github.com/Stratus-Security/Subdominator)
- [https://github.com/NImaism/takeit](https://github.com/NImaism/takeit)
- [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) (use `-tags takeover` with nuclei-templates)
- [https://github.com/edoardottt/cariddi](https://github.com/edoardottt/cariddi) (takeover checks in crawling output)

### Subdomain Takeover Generation via DNS Wildcard

When wildcard DNS is used, a queried name without a more specific matching record can resolve through the wildcard. The wildcard may provide an A/AAAA record or a CNAME.<sup>[[2]](#references)</sup>

For example, if `*.testing.com` is wildcarded to `1.1.1.1`. Then, `not-existent.testing.com` will be pointing to `1.1.1.1`.

However, if instead of pointing to an IP address, the sysadmin points it to a **third party service via CNAME**, like a **GitHub subdomain** for example (`sohomdatta1.github.io`). An attacker could **create his own third party page** (in GitHub in this case) and say that `something.testing.com` is pointing there. Because the **CNAME wildcard** will agree, the attacker will be able to **generate arbitrary subdomains for the domain of the victim pointing to his pages**.

You can find an example of this vulnerability in the CTF write-up: [https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api)<sup>[[4]](#references)</sup>

### Lame NS delegation / DNS-provider claim ("Sitting Ducks")

A domain does not need to expire for its DNS to be taken over. In a **Sitting Ducks** scenario, the parent continues to delegate a registered domain or subzone to a third-party authoritative DNS provider, that provider no longer has an active zone for it, and the provider lets another account create the same zone on nameservers matching the parent delegation without strong ownership validation. An attacker can then publish arbitrary records without access to either the registrar or the victim's former DNS-provider account. This is different from registering an expired nameserver domain: the contested resource is the **hosted zone at the provider**.<sup>[[5]](#references)[[6]](#references)</sup>

Read the referral from the **parent zone**, because a recursive `NS` query can return cached or child-side data. Then query every delegated server directly and look for an authoritative (`aa`) `SOA` response. `REFUSED`, `SERVFAIL`, timeouts, or an answer without `aa`/`SOA` indicate a broken delegation, but do **not** prove that the provider will allow the zone to be claimed.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
zone=delegated.example.com
parent=example.com                 # use the TLD for a registrable-domain apex
pns=$(dig +short "$parent" NS | head -1)

# Obtain the actual parent-side delegation
dig @"${pns%.}" "$zone" NS +norecurse +noall +answer +authority
nslist=$(dig @"${pns%.}" "$zone" NS +norecurse +noall +authority | \
  awk '$4 == "NS" {print $5}')

# A correctly configured server should answer authoritatively for the zone apex
for ns in $nslist; do
  echo "== $ns =="
  dig @"${ns%.}" "$zone" SOA +norecurse +noall +comments +answer +authority
done
```

If only some servers are lame or claimable, resolution and attacker control can be intermittent. Validate provider ownership requirements separately; a provider error page or one non-authoritative DNS response is only a lead. Creating the zone can disrupt production DNS, so a proof such as an authorized random TXT record should only be attempted with explicit permission. For general delegation-integrity checks, also see [Pentesting DNS](../network-services-pentesting/pentesting-dns.md#ns-delegation-integrity--lame-delegation).<sup>[[5]](#references)[[6]](#references)</sup>

## Exploiting a subdomain takeover

Subdomain takeover is essentially DNS spoofing for a specific domain across the internet, allowing attackers to set A records for a domain, leading browsers to display content from the attacker's server. This **transparency** in browsers makes domains prone to phishing. Attackers may employ [_typosquatting_](https://en.wikipedia.org/wiki/Typosquatting) or [_Doppelganger domains_](https://en.wikipedia.org/wiki/Doppelg%C3%A4nger) for this purpose. Especially vulnerable are domains where the URL in a phishing email appears legitimate, deceiving users and evading spam filters due to the domain's inherent trust.<sup>[[1]](#references)</sup>

Check this [post for further details](https://0xpatrik.com/subdomain-takeover/)<sup>[[1]](#references)</sup>

### **SSL Certificates**

SSL certificates, if generated by attackers via services like [_Let's Encrypt_](https://letsencrypt.org/), add to the legitimacy of these fake domains, making phishing attacks more convincing.<sup>[[1]](#references)</sup>

### **Cookie Security and Browser Transparency**

Cookie impact depends on cookie scope. A host-only cookie for `example.com` is not sent to `taken.example.com`, while a cookie set with `Domain=example.com` is sent to matching subdomains. `HttpOnly` prevents JavaScript from reading a cookie but does not prevent the browser from attaching a domain-scoped cookie to a request to the compromised host. `Secure` only restricts the transport to HTTPS.<sup>[[1]](#references)</sup>

### CORS Bypass

It might be possible that every subdomain is allowed to access CORS resources from the main domain or other subdomains. This could be exploited by an attacker to **access sensitive information** abusing CORS requests.<sup>[[3]](#references)</sup>

### CSRF - Same-Site Cookies bypass

A compromised subdomain is normally **same-site** with sibling hosts under the same registrable domain, although it is not same-origin. Therefore, `SameSite` alone may not block cross-origin requests initiated from that subdomain; correctly validated anti-CSRF tokens and Origin/Referer checks are still important.<sup>[[1]](#references)[[3]](#references)</sup>

### OAuth tokens redirect

If an OAuth client accepts the compromised subdomain in a `redirect_uri`, an attacker may be able to receive authorization codes or tokens sent to that URI.<sup>[[1]](#references)</sup>

### CSP Bypass

If a CSP directive such as `script-src` trusts the compromised subdomain or an overly broad wildcard, the attacker-controlled host may become a permitted script source and strengthen an injection flaw.<sup>[[1]](#references)</sup>

### **Emails and Subdomain Takeover**

Another aspect of subdomain takeover involves email services. Attackers can manipulate **MX records** to receive or send emails from a legitimate subdomain, enhancing the efficacy of phishing attacks.<sup>[[1]](#references)</sup>

### **Higher Order Risks**

Further risks include **NS delegation takeover**. If a parent zone delegates a domain or subdomain to an attacker-controlled or re-registerable nameserver, the attacker may answer authoritatively for that delegated namespace. Cached records and TTLs affect how quickly changes propagate.<sup>[[1]](#references)</sup>

### CNAME Record Vulnerability

Attackers may exploit dangling CNAME records that point to an external resource which has been deleted but can be claimed again. Provider-specific ownership validation can prevent the claim, so a dangling record is not automatically exploitable.<sup>[[2]](#references)</sup>

### **Mitigation Strategies**

Mitigation strategies include:

1. **Removing vulnerable DNS records** - This is effective if the subdomain is no longer required.
2. **Claiming the domain name** - Registering the resource with the respective cloud provider or repurchasing an expired domain.
3. **Regular monitoring for vulnerabilities** - Tools like [aquatone](https://github.com/michenriksen/aquatone) can help identify susceptible domains. Organizations should also revise their infrastructure management processes, ensuring that DNS record creation is the final step in resource creation and the first step in resource destruction.
4. **Coupling delegations to hosted-zone lifecycle** - Change or remove parent-side `NS` records first, wait out their TTL, and only then delete the old provider zone/account. Periodically compare parent delegations with active provider inventory and prefer providers that validate control before accepting a zone.<sup>[[5]](#references)[[6]](#references)</sup>

For cloud providers, verifying domain ownership is crucial to prevent subdomain takeovers. Some, like [GitLab](https://about.gitlab.com/2018/02/05/gitlab-pages-custom-domain-validation/), have recognized this issue and implemented domain verification mechanisms.<sup>[[1]](#references)</sup>

## Detection techniques

- **Find dangling DNS records**: look for CNAME/A/AAAA/ALIAS/ANAME records pointing to non-existent resources (deleted buckets, apps, pages, load balancers), and inspect `NS` referrals with the [parent-side lame-delegation procedure](#lame-ns-delegation--dns-provider-claim-sitting-ducks).
- **Check provider error signatures**: match HTTP responses, TLS certs, or DNS errors to known takeover patterns (see can-i-take-over-xyz).
- **Look for orphaned cloud assets**: verify S3/CloudFront, Azure Websites, GCP App Engine/Storage, GitHub Pages, Heroku, Fastly, Netlify, Vercel, Zendesk, Shopify, Atlassian, and similar services.
- **Passive DNS and historical records**: old CNAMEs often reveal previously used third-party services that may still be vulnerable.
- **Wildcard pitfalls**: confirm wildcard DNS vs. explicit records to avoid false positives and understand takeover amplification.

## APIs and data sources

- [https://securitytrails.com/](https://securitytrails.com/) (historical DNS, passive DNS API)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://search.censys.io/](https://search.censys.io/) (certs and host data)
- [https://www.shodan.io/](https://www.shodan.io/) (host data)
- [https://www.virustotal.com/](https://www.virustotal.com/) (historical DNS, URLs)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) (subdomains dataset)



## References

- [1] [Subdomain Takeover: Thoughts on Risks - 0xpatrik](https://0xpatrik.com/subdomain-takeover/)
- [2] [Subdomain Takeover Guide - Stratus Security](https://www.stratussecurity.com/post/subdomain-takeover-guide)
- [3] [A Guide To Subdomain Takeovers - HackerOne](https://www.hackerone.com/blog/guide-subdomain-takeovers-20)
- [4] [Undocumented JS API - niteCTF 2022 write-up](https://ctf.zeyu2001.com/2022/nitectf-2022/undocumented-js-api)
- [5] [Who Knew? Domain Hijacking is So Easy - Infoblox](https://www.infoblox.com/blog/threat-intelligence/who-knew-domain-hijacking-is-so-easy/)
- [6] [Ducks Now Sitting (DNS): Internet Infrastructure Insecurity - Eclypsium](https://eclypsium.com/blog/ducks-now-sitting-dns-internet-infrastructure-insecurity/)
{{#include ../banners/hacktricks-training.md}}
