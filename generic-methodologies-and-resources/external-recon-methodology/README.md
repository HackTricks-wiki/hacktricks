# External Recon Methodology

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

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

There are some pages that let you search by these trackers and more:

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

The fastest way to obtain a lot of subdomains is search in external sources. I'm not going to discuss which sources are the bests and how to use them, but you can find here several utilities: [https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html](https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html)

The most used **tools** are the following ones (for better results configure the API keys):

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
python3 oneforall.py --target tesla.com [--dns False] [--req False] run
```

* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

* [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires taht you create a sudomy.api file with API keys
sudomy -d tesla.com
```

There are **other interesting tools/APIs** that even if not directly specialised in finding subdomains could be useful to find subdomains, like:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Uses the API [https://sonar.omnisint.io](https://sonar.omnisint.io) to obtain subdomains

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
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

* ****[**https://crt.sh/**](https://crt.sh)****

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
gau tesla.com | cut -d "/" -f 3 | sort | uniq
```

* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): They scrap the web looking for JS files and extract subdomains from there.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

* [**Shodan**](https://www.shodan.io/)****

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

#### For bug hunters: [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

This project offers for **free all the subdomains related to bug-bounty programs**. You can access this data also using [chaospy](https://github.com/dr-0x0x/chaospy) or even access the scope used by this project [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

### **DNS Brute force**

Let's try to find new **subdomains** brute-forcing DNS servers using possible subdomain names.\
The most recommended tools for this are [**massdns**](https://github.com/blechschmidt/massdns)**,** [**gobuster**](https://github.com/OJ/gobuster)**,** [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) **and** [**shuffledns**](https://github.com/projectdiscovery/shuffledns). The first one is faster but more prone to errors (you should always check for **false positives**) and the second one **is more reliable**. There are other tools like [**gotator**](https://github.com/Josue87/gotator) that helps to generate generate DNS wordlists through permutations.

For this action you will need some common subdomains lists like:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)

{% code title="Gobuster bruteforcing dns" %}
```bash
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
{% endcode %}

For **massdns** you will need to pass as argument the file will all the **possible well formed subdomains** you want to bruteforce and list of DNS resolvers to use. Some projects that use massdns as base and provides better results by checking massdns results are [**shuffledns**](https://github.com/projectdiscovery/shuffledns) **and** [**puredns**](https://github.com/d3mondev/puredns)**.**

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt

shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
puredns bruteforce all.txt domain.com
```

Note how these tools require a **list of IPs of public DNSs**. If these public DNSs are malfunctioning (DNS poisoning for example) you will get bad results. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them.

### **VHosts / Virtual Hosts**

You can find some VHosts in IPs using [HostHunter](https://github.com/SpiderLabs/HostHunter)

**Brute Force**

If you suspect that some subdomain can be hidden in a web server you could try to brute force it:

```bash
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

### **DNS Brute Force v2**

Once you have finished looking for subdomains you can use [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**,** [**altdns**](https://github.com/infosec-au/altdns) and [**gotator**](https://github.com/Josue87/gotator) to generate possible permutations of the discovered subdomains and use again **massdns** and **gobuster** to search new domains.

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

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

In the previous steps you have probably already performed some **recon of the IPs and domains discovered**, so you may have **already found all the possible web servers**. However, if you haven't we are now going to see some **fast tricks to search for web servers** inside the scope.

Please, note that this will be **oriented for web apps discovery**, so you should **perform the vulnerability** and **port scanning** also (**if allowed** by the scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/#http-port-discovery).\
Another friendly tool to look for web servers is [**httprobe**](https://github.com/tomnomnom/httprobe) **and** [**fprobe**](https://github.com/theblackturtle/fprobe). You just pass a list of domains and it will try to connect to port 80 (http) and 443 (https). Additionaly, you can indicate to try other ports:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

Now that you have discovered **all the web servers** present in the scope (among the **IPs** of the company and all the **domains** and **subdomains**) you probably **don't know where to start**. So, let's make it simple and start just taking screenshots of all of them. Just by **taking a look** at the **main page** you can find **weird** endpoints that are more **prone** to be **vulnerable**.

To perform the proposed idea you can use [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), \[shutter]\([**https://shutter-project.org/downloads/**](https://shutter-project.org/downloads/)) or [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

### Cloud Assets

Just with some **specific keywords** identifying the company it's possible to enumerate possible cloud assets belonging to them with tools like [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper) **or** [**cloudlist**](https://github.com/projectdiscovery/cloudlist)**.**

## Recapitulation 1

> Congratulations! At this point you have already perform all the basic enumeration. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).\
> Do you know that the BBs experts recommends to spend only 10-15mins in this phase? But don't worry, one you have practice you will do this even faster than that.

So you have already:

1. Found all the **companies** inside the scope
2. Found all the **assets** belonging to the companies (and perform some vuln scan if in scope)
3. Found all the **domains** belonging to the companies
4. Found all the **subdomains** of the domains (any subdomain takeover?)
5. Found all the **web servers** and took a **screenshot** of them (anything weird worth a deeper look?)

Then, it's time for the real Bug Bounty hunt! In this methodology I'm **not going to talk about how to scan hosts** (you can see a [guide for that here](../pentesting-network/)), how to use tools like Nessus or OpenVas to perform a **vuln scan** or how to **look for vulnerabilities** in the services open (this book already contains tons of information about possible vulnerabilities on a lot of common services). **But, don't forget that if the scope allows it, you should give it a try.**

### Github leaked secrets

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

You can also search for leaked secrets in all open repository platforms using: [https://searchcode.com/?q=auth\_key](https://searchcode.com/?q=auth\_key)

### [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/)

Anyway, the **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/).

## Recapitulation 2

> Congratulations! The testing has finished! I hope you have find some vulnerabilities.

At this point you should have already read the Pentesting Web Methodology and applied it to the scope.\
As you can see there is a lot of different vulnerabilities to search for.

**If you have find any vulnerability thanks to this book, please reference the book in your write-up.**

### **Automatic Tools**

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

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>
