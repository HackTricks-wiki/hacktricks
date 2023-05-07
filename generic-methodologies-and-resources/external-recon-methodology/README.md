# External Recon Methodology

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Assets discoveries

> So you were said that everything belonging to some company is inside the scope, and you want to figure out what this company actually owns.

The goal of this phase is to obtain all the **companies owned by the main company** and then all the **assets** of these companies. To do so, we are going to:

1. Find the acquisitions of the main company, this will give us the companies inside the scope.
2. Find the ASN (if any) of each company, this will give us the IP ranges owned by each company
3. Use reverse whois lookups to search for other entries (organisation names, domains...) related to the first one (this can be done recursively)
4. Use other techniques like shodan `org`and `ssl`filters to search for other assets (the `ssl` trick can be done recursively).

### **Acquisitions**

First of all, we need to know which **other companies are owned by the main company**.\
One option is to visit [https://www.crunchbase.com/](https://www.crunchbase.com), **search** for the **main company**, and **click** on "**acquisitions**". There you will see other companies acquired by the main one.\
Other option is to visit the **Wikipedia** page of the main company and search for **acquisitions**.

> Ok, at this point you should know all the companies inside the scope. Lets figure out how to find their assets.

### **ASNs**

An autonomous system number (**ASN**) is a **unique number** assigned to an **autonomous system** (AS) by the **Internet Assigned Numbers Authority (IANA)**.\
An **AS** consists of **blocks** of **IP addresses** which have a distinctly defined policy for accessing external networks and are administered by a single organisation but may be made up of several operators.

It's interesting to find if the **company have assigned any ASN** to find its **IP ranges.** It will be interested to perform a **vulnerability test** against all the **hosts** inside the **scope** and **look for domains** inside these IPs.\
You can **search** by company **name**, by **IP** or by **domain** in [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Depending on the region of the company this links could be useful to gather more data:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** appears already in the first link.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Also, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** subdomain enumeration automatically aggregates and summarizes ASNs at the end of the scan.

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can fins the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

At this point we known **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/#discovering-hosts-from-the-outside) **or use services like** shodan **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

For this to work, the administrator has to enable manually the PTR.\
You can also use a online tool for this info: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
* [https://www.domainiq.com/](https://www.domainiq.com) - Not Free

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

There are some pages and tools that let you search by these trackers and more:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Did you know that we can find related domains and sub domains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simply said, favihash will allow us to discover domains that have the same favicon icon hash as our target.

Moreover, you can also search technologies using the favicon hash as explained in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). That means that if you know the **hash of the favicon of a vulnerable version of a web tech** you can search if in shodan and **find more vulnerable places**:

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```

This is how you can **calculate the favicon hash** of a web:

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url)
    favicon = codecs.encode(response.content,"base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

### **Copyright / Uniq string**

Search inside the web pages **strings that could be shared across different webs in the same organisation**. The **copyright string** could be a good example. Then search for that string in **google**, in other **browsers** or even in **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

It's common to have a cron job such as

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"`

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that look for **domains related** with a main domain and **subdomains** of them, pretty amazing.

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

The fastest way to obtain a lot of subdomains is search in external sources. The most used **tools** are the following ones (for better results configure the API keys):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

* [**Amass**](https://github.com/OWASP/Amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

* [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

* [**findomain**](https://github.com/Edu4rdSHL/findomain/)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

* [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

* [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

* [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

There are **other interesting tools/APIs** that even if not directly specialised in finding subdomains could be useful to find subdomains, like:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Uses the API [https://sonar.omnisint.io](https://sonar.omnisint.io) to obtain subdomains

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

* [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```

* [**RapidDNS**](https://rapiddns.io) free API

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

* [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

* [**gau**](https://github.com/lc/gau)**:** fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl for any given domain.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): They scrap the web looking for JS files and extract subdomains from there.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

* [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)

```
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

* [**securitytrails.com**](https://securitytrails.com/) has a free API to search for subdomains and IP history
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

You can find a **comparison** of many of these tools here: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Let's try to find new **subdomains** brute-forcing DNS servers using possible subdomain names.

For this action you will need some **common subdomains wordlists like**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

And also IPs of good DNS resolvers. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them. Or you could use: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

* [**massdns**](https://github.com/blechschmidt/massdns): This was the first tool that performed an effective DNS brute-force. It's very fast however it's prone to false positives.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

* [**gobuster**](https://github.com/OJ/gobuster): This one I think just uses 1 resolver

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) is a wrapper around `massdns`, written in go, that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

* [**puredns**](https://github.com/d3mondev/puredns): It also uses `massdns`.

```
puredns bruteforce all.txt domain.com
```

* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) uses asyncio to brute force domain names asynchronously.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Second DNS Brute-Force Round

After having found subdomains using open sources and brute-forcing, you could generate alterations of the subdomains found to try to find even more. Several tools are useful for this purpose:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Given the domains and subdomains generate permutations.

```bash
cat subdomains.txt | dnsgen -
```

* [**goaltdns**](https://github.com/subfinder/goaltdns): Given the domains and subdomains generate permutations.
  * You can get goaltdns permutations **wordlist** in [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

* [**gotator**](https://github.com/Josue87/gotator)**:** Given the domains and subdomains generate permutations. If not permutations file is indicated gotator will use its own one.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

* [**altdns**](https://github.com/infosec-au/altdns): Apart from generating subdomains permutations, it can also try to resolve them (but it's better to use the previous commented tools).
  * You can get altdns permutations **wordlist** in [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

* [**dmut**](https://github.com/bp0lr/dmut): Another tool to perform permutations, mutations and alteration of subdomains. This tool will brute force the result (it doesn't support dns wild card).
  * You can get dmut permutations wordlist in [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Based on a domain it **generates new potential subdomains names** based on indicated patterns to try to discover more subdomains.

#### Smart permutations generation

* [**regulator**](https://github.com/cramppet/regulator): For more info read this [**post**](https://cramppet.github.io/regulator/index.html) but it will basically get the **main parts** from the **discovered subdomains** and will mix them to find more subdomains.

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ is a subdomain brute-force fuzzer coupled with an immensly simple but effective DNS reponse-guided algorithm. It utilizes a provided set of input data, like a tailored wordlist or historical DNS/TLS records, to accurately synthesize more corresponding domain names and expand them even further in a loop based on information gathered during DNS scan.

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Check this blog post I wrote about how to **automate the subdomain discovery** from a domain using **Trickest workflows** so I don't need to launch manually a bunch of tools in my computer:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

If you found an IP address containing **one or several web pages** belonging to subdomains, you could try to **find other subdomains with webs in that IP** by looking in **OSINT sources** for domains in an IP or by **brute-forcing VHost domain names in that IP**.

#### OSINT

You can find some **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

If you suspect that some subdomain can be hidden in a web server you could try to brute force it:

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

{% hint style="info" %}
With this technique you may even be able to access internal/hidden endpoints.
{% endhint %}

### **CORS Brute Force**

Sometimes you will find pages that only return the header _**Access-Control-Allow-Origin**_ when a valid domain/subdomain is set in the _**Origin**_ header. In these scenarios, you can abuse this behaviour to **discover** new **subdomains**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

While looking for **subdomains** keep an eye to see if it is **pointing** to any type of **bucket**, and in that case [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Also, as at this point you will know all the domains inside the scope, try to [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorization**

You can **monitor** if **new subdomains** of a domain are created by monitoring the **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)does.

### **Looking for vulnerabilities**

Check for possible [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
If the **subdomain** is pointing to some **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/).

If you find any **subdomain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

In the initial steps you might have **found some IP ranges, domains and subdomains**.\
It’s time to **recollect all the IPs from those ranges** and for the **domains/subdomains (DNS queries).**

Using services from the following **free apis** you can also find **previous IPs used by domains and subdomains**. These IPs might still be owned by the client (and might allow you to find [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (as you highly probably won’t find anything interested in there). In the running services discovered you might be **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

In the previous steps you have probably already performed some **recon of the IPs and domains discovered**, so you may have **already found all the possible web servers**. However, if you haven't we are now going to see some **fast tricks to search for web servers** inside the scope.

Please, note that this will be **oriented for web apps discovery**, so you should **perform the vulnerability** and **port scanning** also (**if allowed** by the scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/#http-port-discovery).\
Another friendly tool to look for web servers is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) and [**httpx**](https://github.com/projectdiscovery/httpx). You just pass a list of domains and it will try to connect to port 80 (http) and 443 (https). Additionally, you can indicate to try other ports:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Now that you have discovered **all the web servers** present in the scope (among the **IPs** of the company and all the **domains** and **subdomains**) you probably **don't know where to start**. So, let's make it simple and start just taking screenshots of all of them. Just by **taking a look** at the **main page** you can find **weird** endpoints that are more **prone** to be **vulnerable**.

To perform the proposed idea you can use [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) or [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Moreover, you could then use [**eyeballer**](https://github.com/BishopFox/eyeballer) to run over all the **screenshots** to tell you **what's likely to contain vulnerabilities**, and what isn't.

## Public Cloud Assets

In order to find potential cloud assets belonging to a company you should **start with a list of keywords that identify that company**. For example, a crypto for a crypto company you might use words such as: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

You will also need wordlists of **common words used in buckets**:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Then, with those words you should generate **permutations** (check the [**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round) for more info).

With the resulting wordlists you could use tools such as [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **or** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Remember that when looking for Cloud Assets you should l**ook for more than just buckets in AWS**.

### **Looking for vulnerabilities**

If you find things such as **open buckets or cloud functions exposed** you should **access them** and try to see what they offer you and if you can abuse them.

## Emails

With the **domains** and **subdomains** inside the scope you basically have all what you **need to start searching for emails**. These are the **APIs** and **tools** that have worked the best for me to find emails of a company:

* [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
* API of [**https://hunter.io/**](https://hunter.io/) (free version)
* API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
* API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails will come handy later to **brute-force web logins and auth services** (such as SSH). Also, they are needed for **phishings**. Moreover, these APIs will give you even more **info about the person** behind the email, which is useful for the phishing campaign.

## Credential Leaks

With the **domains,** **subdomains**, and **emails** you can start looking for credentials leaked in the past belonging to those emails:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

If you find **valid leaked** credentials, this is a very easy win.

## Secrets Leaks

Credential leaks are related to hacks of companies where **sensitive information was leaked and sold**. However, companies might be affected for **other leaks** whose info isn't in those databases:

### Github Leaks

Credentials and APIs might be leaked in the **public repositories** of the **company** or of the **users** working by that github company.\
You can use the **tool** [**Leakos**](https://github.com/carlospolop/Leakos) to **download** all the **public repos** of an **organization** and of its **developers** and run [**gitleaks**](https://github.com/zricethezav/gitleaks) over them automatically.

**Leakos** can also be used to run **gitleaks** agains all the **text** provided **URLs passed** to it as sometimes **web pages also contains secrets**.

#### Github Dorks

Check also this **page** for potential **github dorks** you could also search for in the organization you are attacking:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes Leaks

Sometimes attackers or just workers will **publish company content in a paste site**. This might or might not contain **sensitive information**, but it's very interesting to search for it.\
You can use the tool [**Pastos**](https://github.com/carlospolop/Pastos) to search in more that 80 paste sites at the same time.

### Google Dorks

Old but gold google dorks are always useful to find **exposed information that shouldn't be there**. The only problem is that the [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contains several **thousands** of possible queries that you cannot run manually. So, you can get your favourite 10 ones or you could use a **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

If you find **valid leaked** credentials or API tokens, this is a very easy win.

## Public Code Vulnerabilities

If you found that the company has **open-source code** you can **analyse** it and search for **vulnerabilities** on it.

**Depending on the language** there are different **tools** you can use:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

There are also free services that allow you to **scan public repositories**, such as:

* [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

The **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/).

I also want to do a special mention to the section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/#automatic-scanners), as, if you shouldn't expect them to find you very sensitive vulnerabilities, they come handy to implement them on **workflows to have some initial web information.**

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

So you have already:

1. Found all the **companies** inside the scope
2. Found all the **assets** belonging to the companies (and perform some vuln scan if in scope)
3. Found all the **domains** belonging to the companies
4. Found all the **subdomains** of the domains (any subdomain takeover?)
5. Found all the **IPs** (from and **not from CDNs**) inside the scope.
6. Found all the **web servers** and took a **screenshot** of them (anything weird worth a deeper look?)
7. Found all the **potential public cloud assets** belonging to the company.
8. **Emails**, **credentials leaks**, and **secret leaks** that could give you a **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

There are several tools out there that will perform part of the proposed actions against a given scope.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

* **All free courses of** [**@Jhaddix**](https://twitter.com/Jhaddix) **(like** [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)**)**

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
