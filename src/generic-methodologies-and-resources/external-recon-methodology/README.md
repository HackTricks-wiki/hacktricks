# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з’ясувати, чим саме ця компанія володіє.

Мета цієї фази — отримати всі **companies, що належать main company** , а потім усі **assets** цих companies. Для цього ми збираємося:

1. Знайти acquisitions main company, це дасть нам companies у scope.
2. Знайти ASN (якщо є) кожної company, це дасть нам IP ranges, що належать кожній company
3. Використати reverse whois lookups для пошуку інших записів (organisation names, domains...) пов’язаних із першим (це можна робити рекурсивно)
4. Використати інші техніки, як-от shodan `org`and `ssl`filters, щоб шукати інші assets (трюк `ssl` можна робити рекурсивно).

### **Acquisitions**

Перш за все, нам потрібно знати, які **other companies are owned by the main company**.\
Один варіант — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **search** for the **main company**, і **click** on "**acquisitions**". Там ви побачите інші companies, acquired by the main one.\
Інший варіант — відвідати сторінку **Wikipedia** main company і знайти **acquisitions**.\
Для public companies перевіряйте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві corporate registries (наприклад, **Companies House** у Великій Британії).\
Для global corporate trees і subsidiaries спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) та базу **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Добре, на цьому етапі ви вже повинні знати всі companies у scope. Давайте з’ясуємо, як знайти їхні assets.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **autonomous system** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **blocks** **IP addresses**, для яких визначено окрему політику доступу до external networks, і якими керує одна organisation, але які можуть складатися з кількох операторів.

Цікаво з’ясувати, чи **company assigned any ASN** щоб знайти її **IP ranges.** Буде корисно провести **vulnerability test** проти всіх **hosts** у **scope** і **look for domains** всередині цих IPs.\
Ви можете **search** за company **name**, за **IP** або за **domain** у [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Depending on the region of the company this links could be useful to gather more data:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** already appears in the first link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration автоматично агрегує та підсумовує ASNs наприкінці сканування.
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

### **Looking for vulnerabilities**

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
Для цього адміністратор має вручну увімкнути PTR.\
Також можна використати онлайн-інструмент для цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів інструменти на кшталт [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx) корисні для автоматизації reverse lookups і enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назву організації**, **адресу**, **emails**, номери телефонів... Але ще цікавіше те, що можна знайти **більше assets, пов'язаних із компанією**, якщо виконати **reverse whois lookups** за будь-яким із цих полів (наприклад, інші whois-реєстри, де зустрічається той самий email).\
Можна використовувати онлайн-інструменти на кшталт:

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
Також можна виконати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зауважте, що цю техніку можна використовувати, щоб знаходити більше domain names щоразу, коли ви знаходите новий domain.**

### **Trackers**

Якщо знайти **той самий ID того самого tracker** на 2 різних сторінках, можна припустити, що **обидві сторінки** керуються **тією самою командою**.\
Наприклад, якщо на кількох сторінках бачите однаковий **Google Analytics ID** або однаковий **Adsense ID**.

Є кілька сторінок і інструментів, які дозволяють шукати за цими trackers та іншим:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов'язані sites за спільними analytics/trackers)

### **Favicon**

Чи знали ви, що можна знаходити пов'язані domain names і subdomains нашої цілі, дивлячись на hash favicon-іконки? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як його використовувати:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дозволить нам виявити домени, які мають той самий хеш іконки favicon, що й наша ціль.

Крім того, ви також можете шукати technologies за допомогою хешу favicon, як пояснено в [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **хеш favicon вразливої версії web tech** ви можете шукати, чи є він у shodan, і **знаходити більше вразливих місць**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Так ви можете **обчислити hash favicon** вебсайту:
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
Також можна отримувати favicon hashes у масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) і потім pivot у Shodan/Censys.

### **Copyright / Uniq string**

Шукайте всередині web pages **strings that could be shared across different webs in the same organisation**. **copyright string** може бути хорошим прикладом. Потім шукайте цю string у **google**, в інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Зазвичай є cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **знайти домени, що належать тій самій компанії, у logs certificate transparency**.\
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

Найшвидший спосіб отримати багато subdomains — шукати в external sources. Найбільш використовувані **tools** такі (для кращих результатів налаштуйте API keys):

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
Є **інші цікаві інструменти/API**, які, навіть якщо вони не спеціалізуються безпосередньо на пошуку subdomains, можуть бути корисними для пошуку subdomains, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання піддоменів
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) безкоштовний API
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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URLs з AlienVault's Open Threat Exchange, the Wayback Machine та Common Crawl для будь-якого заданого domain.
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
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку subdomains та IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт безкоштовно надає всі subdomains, пов’язані з bug-bounty programs. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати доступ до scope, який використовує цей проєкт [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **comparison** багатьох із цих tools тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **subdomains**, brute-forcing DNS servers за допомогою можливих назв subdomain.

Для цієї дії вам знадобляться деякі **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP хороших DNS resolvers. Щоб згенерувати список trusted DNS resolvers, ви можете завантажити resolvers з [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб їх відфільтрувати. Або можна використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані tools для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший tool, який виконував ефективний DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, я думаю, використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це wrapper навколо `massdns`, написаний на go, який дозволяє перераховувати valid subdomains за допомогою active bruteforce, а також resolve subdomains із handling wildcard і зручним input-output support.
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
### Другий раунд DNS brute-force

Після того як ви знайшли субдомени за допомогою open sources і brute-forcing, можна згенерувати варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** На основі доменів і субдоменів генерує перестановки.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і піддоменів генерує пермутації.
- Ви можете отримати **wordlist** для пермутацій goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** За заданими доменами та піддоменами генерує permutations. Якщо файл permutations не вказано, gotator використовуватиме власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації пермутацій піддоменів, він також може намагатися їх резолвити (але краще використовувати попередні інструменти, згадані в коментарях).
- Ви можете отримати **wordlist** для пермутацій altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations та alteration субдоменів. Цей інструмент виконає brute force результату (він не підтримує dns wild card).
- Ви можете отримати dmut permutations wordlist [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену він **генерує нові потенційні імена піддоменів** за вказаними шаблонами, щоб спробувати виявити більше піддоменів.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Для детальнішої інформації прочитайте цей [**post**](https://cramppet.github.io/regulator/index.html), але по суті він бере **основні частини** з **виявлених піддоменів** і комбінує їх, щоб знайти більше піддоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force підбору піддоменів, поєднаний із надзвичайно простим, але ефективним алгоритмом, керованим DNS-відповіддю. Він використовує наданий набір вхідних даних, як-от адаптований wordlist або історичні записи DNS/TLS, щоб точно синтезувати ще більше відповідних доменних імен і розширювати їх далі в циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow виявлення субдоменів**

Перевірте цей блог-пост, який я написав про те, як **автоматизувати виявлення субдоменів** для домену за допомогою **Trickest workflows**, щоб мені не доводилося вручну запускати купу інструментів на своєму комп’ютері:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька веб-сторінок**, які належать субдоменам, ви можете спробувати **знайти інші субдомени з веб-сайтами на цій IP**, шукаючи в **OSINT sources** домени в IP або **brute-forcing VHost domain names in that IP**.

#### OSINT

Ви можете знайти деякі **VHosts в IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інші APIs**.

**Brute Force**

Якщо ви підозрюєте, що деякий субдомен може бути схований на вебсервері, ви можете спробувати brute force:

Коли **IP redirects to a hostname** (name-based vhosts), fuzz-те заголовок `Host` напряму і дозвольте ffuf **auto-calibrate**, щоб виділити відповіді, що відрізняються від default vhost:
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
> За допомогою цієї техніки ви навіть можете отримати доступ до внутрішніх/прихованих endpoints.

### **CORS Brute Force**

Іноді ви знайдете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли у заголовку _**Origin**_ вказано дійсний domain/subdomain. У таких сценаріях ви можете зловживати цією поведінкою, щоб **виявляти** нові **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** стежте, чи не **pointing** на якийсь тип **bucket**, і в такому разі [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цей момент ви вже знатимете всі domains у межах scope, спробуйте [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Ви можете **monitor** появу **new subdomains** домену, відстежуючи логи **Certificate Transparency**; це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Перевірте можливі [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** вказує на якийсь **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете будь-який **subdomain з IP, відмінним** від тих, які ви вже знайшли під час assets discovery, вам слід виконати **basic vulnerability scan** (using Nessus or OpenVAS) і [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від того, які сервіси запущені, ви можете знайти в **this book some tricks to "attack" them**.\
_Примітка: іноді subdomain розміщений на IP, який не контролюється client, тож він не входить у scope, будьте обережні._

## IPs

На початкових етапах ви могли **знайти деякі IP ranges, domains and subdomains**.\
Настав час **зібрати всі IPs із цих ranges** і для **domains/subdomains (DNS queries).**

Використовуючи сервіси з наведених нижче **free apis**, ви також можете знайти **previous IPs used by domains and subdomains**. Ці IPs все ще можуть належати client (і можуть допомогти вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити domains, що вказують на певну IP address, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (оскільки, ймовірно, ви не знайдете там нічого цікавого). У виявлених запущених сервісах ви можете **знайти vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Ми знайшли всі companies та їхні assets і знаємо IP ranges, domains and subdomains у межах scope. Час шукати web servers.

На попередніх етапах ви, ймовірно, вже виконали деякий **recon of the IPs and domains discovered**, тож, можливо, ви вже **знайшли всі можливі web servers**. Однак, якщо ні, зараз ми розглянемо кілька **fast tricks to search for web servers** у межах scope.

Будь ласка, зверніть увагу, що це буде **oriented for web apps discovery**, тож вам також слід **perform the vulnerability** і **port scanning** (**if allowed** за scope).

**Швидкий метод** виявлення **ports open**, пов’язаних із **web** servers, за допомогою [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний інструмент для пошуку web servers — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список domains, і він спробує підключитися до port 80 (http) та 443 (https). Додатково ви можете вказати спробу інших ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Тепер, коли ви виявили **всі web servers**, присутні в scope (серед **IP-адрес** компанії та всіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тож зробімо все простіше й почнемо просто знімати screenshots усіх із них. Лише **подивившись** на **головну сторінку**, ви можете знайти **дивні** endpoints, які **ймовірніше** є **вразливими**.

Щоб реалізувати цю ідею, ви можете використати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, ви можете використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб прогнати всі **screenshots** і дізнатися, **що, ймовірно, містить vulnerabilities**, а що ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, вам слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії ви можете використати слова на кшталт: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також вам знадобляться wordlists із **common words, які використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів ви повинні згенерувати **permutations** (див. [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) для детальнішої інформації).

З отриманими wordlists ви можете використовувати такі tools, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що коли ви шукаєте Cloud Assets, вам слід шукати **не лише buckets в AWS**.

### **Looking for vulnerabilities**

Якщо ви знайдете щось на кшталт **open buckets або exposed cloud functions**, ви повинні **доступитися до них** і спробувати зрозуміти, що вони вам надають і чи можна їх abused.

## Emails

Маючи **domains** і **subdomains** у межах scope, ви фактично вже маєте все, що **потрібно, щоб почати пошук email-ів**. Ось **APIs** і **tools**, які найкраще спрацьовували для мене під час пошуку email-ів компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Email-и стануть у пригоді пізніше для **brute-force web logins і auth services** (таких як SSH). Також вони потрібні для **phishings**. Крім того, ці APIs дадуть вам ще більше **info про людину** за email-ом, що корисно для phishing campaign.

## Credential Leaks

Маючи **domains,** **subdomains** і **emails**, ви можете почати шукати credentials, що були leaked у минулому та належать цим email-ам:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані з hacks компаній, де **sensitive information була leaked і sold**. Однак на компанію можуть вплинути й **інші leaks**, інформації з яких немає в цих базах даних:

### Github Leaks

Credentials і APIs можуть бути leaked у **public repositories** **компанії** або користувачів, які працюють у цій github-компанії.\
Ви можете використати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **download** усі **public repos** **organization** і її **developers** та автоматично прогнати по них [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** також можна використати, щоб запускати **gitleaks** agains усі **text**-based **URLs passed** йому, оскільки інколи **web pages also contains secrets**.

#### Github Dorks

Також перегляньте цю **page** на предмет potential **github dorks**, які ви також можете шукати в organization, яку атакуєте:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді attackers або просто workers публікуватимуть company content на paste site. Це може містити або не містити **sensitive information**, але це дуже цікаво перевірити.\
Ви можете використати tool [**Pastos**](https://github.com/carlospolop/Pastos), щоб шукати більш ніж у 80 paste sites одночасно.

### Google Dorks

Старі, але золоті google dorks завжди корисні, щоб знаходити **exposed information, якої там не повинно бути**. Єдина проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо запускати вручну. Тож ви можете взяти свої улюблені 10 або використати **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб запустити їх усі**.

_Зверніть увагу, що tools, які очікують запуск усієї database через звичайний Google browser, ніколи не завершаться, оскільки google дуже швидко вас заблокує._

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, ви можете **аналізувати** його та шукати в ньому **vulnerabilities**.

**Залежно від language** є різні **tools**, які ви можете використати:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Також є безкоштовні сервіси, які дозволяють вам **scan public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість vulnerabilities**, які знаходять bug hunters, знаходяться всередині **web applications**, тож зараз я хотів би поговорити про **web application testing methodology**, і ви можете [**знайти цю інформацію тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), адже, хоча не слід очікувати, що вони знайдуть для вас дуже sensitive vulnerabilities, вони дуже корисні для впровадження в **workflows**, щоб отримати початкову web information.

## Recapitulation

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, тому що ще багато чого можна зробити (пізніше побачимо більше trickів).

Отже, ви вже:

1. Знайшли всі **companies** у межах scope
2. Знайшли всі **assets**, що належать компаніям (і виконали певний vuln scan, якщо це в scope)
3. Знайшли всі **domains**, що належать компаніям
4. Знайшли всі **subdomains** доменів (будь-який subdomain takeover?)
5. Знайшли всі **IPs** (як **from**, так і **not from CDNs**) у межах scope.
6. Знайшли всі **web servers** і зробили їх **screenshot** (чи є щось дивне, що варте глибшого погляду?)
7. Знайшли всі **potential public cloud assets**, що належать компанії.
8. **Emails**, **credentials leaks** і **secret leaks**, які можуть дуже легко дати вам **великий виграш**.
9. **Pentesting усіх webs, які ви знайшли**

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
