# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете зрозуміти, чим ця компанія насправді володіє.

Мета цієї фази — отримати всі **компанії, що належать основній компанії**, а потім усі **assets** цих компаній. Для цього ми:

1. Знайдемо acquisitions основної компанії; це дасть нам companies у scope.
2. Знайдемо ASN (якщо є) кожної компанії; це дасть нам IP ranges, що належать кожній компанії
3. Використаємо reverse whois lookups, щоб шукати інші записи (organisation names, domains...) пов’язані з першим (це можна робити рекурсивно)
4. Використаємо інші техніки, як-от shodan `org`and `ssl`filters, щоб шукати інші assets (trick з `ssl` можна робити рекурсивно).

### **Acquisitions**

Насамперед нам потрібно знати, які **інші companies належать основній company**.\
Один варіант — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **search** основну **company** і натиснути на "**acquisitions**". Там ви побачите інші companies, acquired основною.\
Інший варіант — відвідати сторінку **Wikipedia** основної company і шукати **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або локальні corporate registries (наприклад, **Companies House** у Великій Британії).\
Для глобальних corporate trees і subsidiaries спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) та базу **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Добре, на цьому етапі ви маєте знати всі companies у scope. Давайте з’ясуємо, як знайти їхні assets.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP addresses**, які мають чітко визначену політику доступу до external networks і адмініструються однією organisation, але можуть складатися з кількох операторів.

Цікаво з’ясувати, чи **company призначила будь-який ASN**, щоб знайти її **IP ranges.**\
Буде корисно провести **vulnerability test** проти всіх **hosts** у **scope** і **look for domains** усередині цих IPs.\
Ви можете **search** за **company name**, за **IP** або за **domain** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону company ці links could be useful to gather more data:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** already appears in the first link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
перерахування автоматично агрегує та підсумовує ASNs наприкінці сканування.
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
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Шукання вразливостей**

At this point we know **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
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
Для цього адміністратору потрібно вручну увімкнути PTR.\
Також можна використати онлайн-інструмент для цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисні інструменти на кшталт [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx) для автоматизації reverse lookups та enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **організаційна назва**, **адреса**, **emails**, номери телефонів... Але ще цікавіше те, що можна знайти **більше assets, пов’язаних із компанією**, якщо виконати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші whois записи, де фігурує та сама email).\
Можна використовувати онлайн-інструменти, як-от:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Можна автоматизувати це завдання за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен whoxy API key).\
Також можна виконувати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зауважте, що можна використовувати цю техніку, щоб знаходити більше доменних імен щоразу, коли ви знаходите новий домен.**

### **Trackers**

Якщо знайти **той самий ID того самого tracker** на 2 різних сторінках, можна припустити, що **обидві сторінки** **керуються тією самою командою**.\
Наприклад, якщо ви бачите той самий **Google Analytics ID** або той самий **Adsense ID** на кількох сторінках.

Є кілька сторінок і інструментів, які дозволяють шукати за цими trackers та іншим:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними analytics/trackers)

### **Favicon**

Чи знаєте ви, що можна знаходити пов’язані домени та subdomains нашої цілі, шукаючи той самий хеш favicon-іконки? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простими словами, favihash дозволить нам виявити домени, які мають той самий hash favicon, що й наша ціль.

Крім того, ви також можете шукати technologies, використовуючи hash favicon, як пояснено в [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **hash favicon вразливої версії web tech** ви можете шукати, чи є це в shodan, і **знайти більше вразливих місць**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ось як можна **обчислити hash favicon** вебсайту:
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
Можна також отримувати favicon hashes у масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) і потім pivot у Shodan/Censys.

### **Copyright / Uniq string**

Шукайте всередині веб-сторінок **strings, які можуть бути спільними для різних web у тій самій організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **google**, в інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Часто є cron job, наприклад
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато subdomains — шукати в external sources. Найчастіше використовувані **tools** такі (для кращих результатів налаштуйте API keys):

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
- [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
- [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
- [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
- [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
- [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
- [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
- [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Є **інші цікаві tools/APIs**, які, навіть якщо не спеціалізуються безпосередньо на пошуку subdomains, можуть бути корисними для знаходження subdomains, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання субдоменів
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) безкоштовне API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
- [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL з AlienVault's Open Threat Exchange, the Wayback Machine, та Common Crawl для будь-якого заданого domain.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках JS-файлів і витягують звідти subdomains.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
- [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) має безплатний API для пошуку subdomains та історії IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт безплатно надає всі subdomains, пов’язані з bug-bounty програмами. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати доступ до scope, який використовує цей проєкт [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **comparison** багатьох із цих tools тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **subdomains**, brute-forcing DNS servers за допомогою можливих назв subdomain.

Для цієї дії вам знадобляться деякі **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP хороших DNS resolvers. Щоб згенерувати список trusted DNS resolvers, ви можете завантажити resolvers з [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати їх. Або ж ви можете використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані tools для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший tool, який виконував ефективний DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, здається, використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка над `massdns`, написана на go, яка дозволяє перераховувати валідні субдомени за допомогою active bruteforce, а також резолвити субдомени з обробкою wildcard і зручною підтримкою input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Він також використовує `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) використовує asyncio для асинхронного brute force доменних імен.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Другий раунд DNS Brute-Force

Після того, як було знайдено піддомени за допомогою open sources і brute-forcing, можна згенерувати варіації знайдених піддоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** На основі доменів і піддоменів генерує перестановки.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Маючи домени та субдомени, генерує пермутації.
- Ви можете отримати **wordlist** пермутацій goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Given the domains and subdomains generate permutations. If not permutations file is indicated gotator will use its own one.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок subdomains, він також може намагатися їх resolve (але краще використовувати попередні інструменти, про які було згадано).
- Ви можете отримати **wordlist** для перестановок altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один tool для виконання permutations, mutations та alteration of subdomains. Цей tool буде brute force результат (він не підтримує dns wild card).
- Ви можете отримати dmut permutations wordlist [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену він **генерує нові потенційні імена піддоменів** за вказаними шаблонами, щоб спробувати виявити більше піддоменів.

#### Розумна генерація пермутацій

- [**regulator**](https://github.com/cramppet/regulator): Для детальнішої інформації прочитайте цей [**post**](https://cramppet.github.io/regulator/index.html), але по суті він бере **основні частини** з **виявлених піддоменів** і комбінує їх, щоб знайти більше піддоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це brute-force fuzzer для субдоменів, поєднаний з надзвичайно простим, але ефективним алгоритмом, керованим DNS-відповіддю. Він використовує наданий набір вхідних даних, як-от налаштований wordlist або історичні DNS/TLS records, щоб точно синтезувати більше відповідних domain names і ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Пошук піддоменів у робочому процесі**

Переглянь цей блог-пост, який я написав про те, як **автоматизувати пошук піддоменів** для домену за допомогою **Trickest workflows**, щоб мені не доводилося вручну запускати купу інструментів на своєму комп'ютері:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ти знайшов IP-адресу, що містить **одну або кілька веб-сторінок**, які належать піддоменам, ти можеш спробувати **знайти інші піддомени з вебом на цій IP** шляхом пошуку в **OSINT-джерелах** доменів в IP або **brute-forcing назв VHost на цій IP**.

#### OSINT

Ти можеш знайти деякі **VHosts в IP за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших APIs**.

**Brute Force**

Якщо ти підозрюєш, що якийсь піддомен може бути схований на вебсервері, ти можеш спробувати brute force:

Коли **IP редиректить на hostname** (name-based vhosts), fuzz безпосередньо `Host` header і дай ffuf **auto-calibrate**, щоб підсвітити відповіді, які відрізняються від default vhost:
```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
-w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!TIP]
> За допомогою цієї техніки ви навіть можете отримати доступ до internal/hidden endpoints.

### **CORS Brute Force**

Іноді ви знайдете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано валідний domain/subdomain. У таких сценаріях ви можете зловживати цією поведінкою, щоб **discover** нові **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** слідкуйте, чи вони **вказують** на будь-який тип **bucket**, і в такому разі [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цей момент ви вже знатимете всі domains у scope, спробуйте [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Ви можете **monitor**, чи створюються **new subdomains** домену, відстежуючи **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) робить це.

### **Looking for vulnerabilities**

Перевірте наявність можливих [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** вказує на якийсь **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете будь-який **subdomain з IP, відмінним** від тих, які ви вже знайшли під час assets discovery, слід виконати **basic vulnerability scan** (using Nessus or OpenVAS) і також [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від того, які сервіси працюють, ви можете знайти в **цій книзі деякі tricks, щоб "attack" їх**.\
_Примітка: інколи subdomain розміщений на IP, який не контролюється клієнтом, тож він не входить у scope — будьте обережні._

## IPs

На початкових етапах ви могли **знайти деякі IP ranges, domains і subdomains**.\
Час **зібрати всі IPs із цих ranges** і для **domains/subdomains (DNS queries).**

Використовуючи сервіси з наведених нижче **free apis**, ви також можете знайти **previous IPs used by domains and subdomains**. Ці IPs можуть досі належати клієнту (і можуть допомогти вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна перевірити domains, що вказують на конкретну IP address, за допомогою tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan усі IPs, які не належать до CDNs** (бо, ймовірно, ви не знайдете там нічого цікавого). У виявлених running services ви можете **знайти vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Ми знайшли всі companies та їхні assets і знаємо IP ranges, domains і subdomains у scope. Час шукати web servers.

На попередніх етапах ви, ймовірно, вже виконали деякий **recon of the IPs and domains discovered**, тож, можливо, ви вже **знайшли всі possible web servers**. Однак, якщо ні, зараз ми розглянемо **швидкі tricks to search for web servers** у scope.

Будь ласка, зверніть увагу, що це буде **oriented for web apps discovery**, тож ви також повинні **perform the vulnerability** і **port scanning** (**if allowed** by the scope).

**Швидкий method** для **discover** відкритих **ports**, пов'язаних із **web** servers, за допомогою [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний tool для пошуку web servers — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список domains, і він спробує підключитися до port 80 (http) і 443 (https). Додатково можна вказати спробу на інших ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Тепер, коли ви виявили **всі web servers**, присутні в scope (серед **IP** компанії та всіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тож зробімо все просто й почнемо просто робити screenshots усіх із них. Лише **поглянувши** на **main page**, ви можете знайти **weird** endpoints, які більш **prone** до **vulnerable**.

Щоб реалізувати запропоновану ідею, ви можете використати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, ви можете потім використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб прогнати всі **screenshots** і визначити, **що ймовірно містить vulnerabilities**, а що ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, вам слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії ви можете використовувати слова на кшталт: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також вам знадобляться wordlists із **common words, used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім, використовуючи ці слова, ви повинні згенерувати **permutations** (див. [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) для більшої інформації).

З отриманими wordlists ви можете використовувати такі tools, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що коли ви шукаєте Cloud Assets, слід ш**укати не лише buckets в AWS**.

### **Looking for vulnerabilities**

Якщо ви знаходите щось на кшталт **open buckets або exposed cloud functions**, вам слід **отримати до них доступ** і спробувати зрозуміти, що вони пропонують, та чи можна їх abuse.

## Emails

Маючи **domains** і **subdomains** у scope, ви фактично маєте все, що **потрібно, щоб почати шукати emails**. Ось **APIs** і **tools**, які найкраще працювали для мене, щоб знаходити emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails згодяться пізніше для **brute-force web logins and auth services** (таких як SSH). Також вони потрібні для **phishings**. Крім того, ці APIs дадуть вам ще більше **info about the person** за email, що корисно для phishing campaign.

## Credential Leaks

Маючи **domains,** **subdomains**, і **emails**, ви можете почати шукати credentials, які були leaked у минулому й належать цим emails:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані з hacks компаній, де **sensitive information was leaked and sold**. Однак компанії можуть постраждати й від **інших leaks**, інформація з яких не потрапила до цих databases:

### Github Leaks

Credentials і APIs можуть бути leaked у **public repositories** **company** або **users** who work by that github company.\
Ви можете використати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **download** усі **public repos** **organization** і її **developers** та автоматично прогнати через них [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** також можна використовувати, щоб запускати **gitleaks** agains усі **text**-передані **URLs**, бо інколи **web pages також містять secrets**.

#### Github Dorks

Також перегляньте цю **page** на предмет потенційних **github dorks**, які ви теж можете шукати в organization, яку атакуєте:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді attackers або просто workers можуть **publish company content in a paste site**. Це може містити або не містити **sensitive information**, але шукати це дуже цікаво.\
Ви можете використати tool [**Pastos**](https://github.com/carlospolop/Pastos), щоб шукати більш ніж у 80 paste sites одночасно.

### Google Dorks

Старі, але gold google dorks завжди корисні, щоб знаходити **exposed information that shouldn't be there**. Єдина проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо запускати вручну. Тож ви можете взяти свої улюблені 10 або використати **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Зверніть увагу, що tools, які очікують запускати всю database через звичайний браузер Google, ніколи не завершаться, оскільки google дуже швидко заблокує вас._

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, ви можете **analyse** його та шукати в ньому **vulnerabilities**.

**Залежно від мови** існують різні **tools**, які можна використовувати:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Також є безкоштовні сервіси, які дозволяють **scan public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість vulnerabilities**, які знаходять bug hunters, містяться всередині **web applications**, тож на цьому етапі я хотів би поговорити про **web application testing methodology**, і ви можете **знайти цю інформацію тут**(../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже sensitive vulnerabilities, вони корисні для інтеграції в **workflows**, щоб отримати початкову web information.

## Recapitulation

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, саме базову, бо можна зробити ще набагато більше enumeration (ще побачимо більше tricks пізніше).

Отже, ви вже:

1. Знайшли всі **companies** у scope
2. Знайшли всі **assets**, що належать компаніям (і виконали vuln scan, якщо це в scope)
3. Знайшли всі **domains**, що належать компаніям
4. Знайшли всі **subdomains** доменів (будь-який subdomain takeover?)
5. Знайшли всі **IPs** (з **CDNs** і **не з CDNs**) у scope.
6. Знайшли всі **web servers** і зробили їх **screenshot** (чи є щось weird, що варте глибшого погляду?)
7. Знайшли всі **potential public cloud assets**, що належать компанії.
8. **Emails**, **credentials leaks**, і **secret leaks**, які можуть дати вам **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Існує кілька tools, які виконають частину запропонованих дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи застарілий і не оновлюється

## **References**

- Усі безкоштовні курси від [**@Jhaddix**](https://twitter.com/Jhaddix), як-от [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
