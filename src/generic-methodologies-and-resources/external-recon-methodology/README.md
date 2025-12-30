# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Вам сказали, що все, що належить певній компанії, входить у scope, і ви хочете з'ясувати, чим саме володіє ця компанія.

Метою цього етапу є отримати всі **компанії, якими володіє головна компанія**, а потім усі **активи** цих компаній. Для цього ми будемо:

1. Знайти придбання головної компанії — це дасть нам компанії всередині scope.
2. Знайти ASN (якщо такий є) кожної компанії — це дасть нам IP ranges, якими володіє кожна компанія.
3. Використати reverse whois lookups для пошуку інших записів (назви організацій, домени...) пов'язаних з початковим записом (це можна робити рекурсивно).
4. Використати інші техніки, наприклад shodan `org` і `ssl` фільтри для пошуку інших активів (трюк з `ssl` можна виконувати рекурсивно).

### **Acquisitions**

По-перше, нам потрібно знати, які **інші компанії належать головній компанії**.\
Один варіант — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **search** для **main company**, і **click** на "**acquisitions**". Там ви побачите інші компанії, придбані головною.\
Інший варіант — відвідати сторінку **Wikipedia** головної компанії і шукати **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations**, або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних дерев і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) та базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Добре, на цьому етапі ви повинні знати всі компанії в межах scope. Давайте з'ясуємо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, присвоєний **автономній системі** (AS) органом **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP addresses**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть включати кількох операторів.

Цікавим є з'ясувати, чи **компанії призначено який-небудь ASN**, щоб знайти її **IP ranges.** Варто виконати **vulnerability test** проти всіх **hosts** у межах **scope** та **look for domains** на цих IP.\
Ви можете **search** за назвою компанії, за **IP** або за **domain** на [**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) або [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону компанії ці links можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** У будь-якому випадку, ймовірно, вся корисна інформація **(IP ranges and Whois)** вже з'являється на першому сайті.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration автоматично агрегує та підсумовує ASNs наприкінці сканування.
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

### **Пошук вразливостей**

At this point we know **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи — час знайти домени в межах scope.

_Будь ласка, зверніть увагу, що в наведених нижче запропонованих техніках ви також можете знайти субдомени, і цю інформацію не слід недооцінювати._

По-перше, слід шукати **main domain**(s) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Для цього адміністратору потрібно вручну увімкнути PTR.\
Можна також використовувати онлайн-інструмент для цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисні інструменти, такі як [**massdns**](https://github.com/blechschmidt/massdns) та [**dnsx**](https://github.com/projectdiscovery/dnsx), щоб автоматизувати reverse lookups і збагачення.

### **Reverse Whois (loop)**

У записі **whois** можна знайти багато цікавої **інформації**, наприклад **назву організації**, **адресу**, **електронні адреси**, телефонні номери... Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконувати **reverse whois lookups за будь-яким із цих полів** (наприклад інші whois-записи, де з’являється той самий email).\
Можна використовувати онлайн-інструменти, такі як:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Безкоштовний** веб, API — платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен whoxy API key).\
Також можна виконати автоматичне виявлення reverse whois за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення більшої кількості доменних імен щоразу, коли ви знаходитe новий домен.**

### **Трекери**

Якщо ви знаходите **той самий ID одного й того ж трекера** на 2 різних сторінках, можна припустити, що **обидві сторінки** **керуються однією й тією ж командою**.\
Наприклад, якщо ви бачите один і той самий **Google Analytics ID** або один і той самий **Adsense ID** на кількох сторінках.

Існують сайти й інструменти, які дозволяють шукати за цими трекерами та іншим:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Чи знали ви, що можна знайти пов’язані домени й субдомени з нашою ціллю, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - знайти домени з тим самим favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Просто кажучи, favihash дозволяє нам знаходити домени, які мають той самий favicon icon hash, що й наша ціль.

Крім того, ви також можете шукати технології за допомогою favicon hash, як пояснено в [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **hash of the favicon of a vulnerable version of a web tech** ви можете шукати його в shodan і **find more vulnerable places**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ось як ви можете **calculate the favicon hash** для веб-сайту:
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

### **Авторське право / Унікальний рядок**

Шукайте всередині веб-сторінок **рядки, які можуть повторюватися на різних сайтах однієї організації**. **copyright string** може бути хорошим прикладом. Потім шукайте цей рядок у **google**, в інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Зазвичай є cron job, наприклад
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб поновити всі сертифікати доменів на сервері. Це означає, що навіть якщо CA, яка використовується для цього, не вказує час генерації в полі Validity, все ще можливо **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Також використовуйте **certificate transparency** logs безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Ви можете скористатися веб-сайтом на кшталт [https://dmarc.live/info/google.com] або інструментом на зразок [https://github.com/Tedixx/dmarc-subdomains], щоб знайти **domains and subdomain sharing the same dmarc information**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) та [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Схоже, часто люди призначають субдомени IP-адресам, що належать cloud providers, і з часом **lose that IP address but forget about removing the DNS record**. Тому просто **spawning a VM** у хмарі (наприклад Digital Ocean) ви фактично **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) пояснює історію про це і пропонує скрипт, який **spawns a VM in DigitalOcean**, **gets** the **IPv4** нової машини, і **searches in Virustotal for subdomain records** що вказують на неї.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

Оскільки ви вже знаєте назву організації, яка володіє IP-простором, ви можете шукати за цією інформацією в shodan використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових несподіваних доменів у TLS certificate.

Ви можете отримати доступ до **TLS certificate** головної веб-сторінки, витягнути **Organisation name** і потім шукати це ім'я всередині **TLS certificates** всіх веб-сторінок, відомих **shodan**, з фільтром: `ssl:"Tesla Motors"` або використати інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is інструмент, який шукає **domains related** з основним доменом і їх **subdomains**, досить вражає.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для знаходження **old and forgotten records**, які досі резольвляться або які можна зайняти. Дивіться:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Перевірте на наявність [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **using some a domain**, але вони **lost the ownership**. Просто зареєструйте його (якщо це досить дешево) і повідомте компанію.

Якщо ви знайдете будь-який **domain with an IP different** від тих, які ви вже виявили під час discovery активів, ви повинні виконати **basic vulnerability scan** (використовуючи Nessus або OpenVAS) та деякий [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від сервісів, що працюють, ви можете знайти в **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

Пора знайти всі можливі субдомени для кожного знайденого домену.

> [!TIP]
> Зауважте, що деякі інструменти та техніки для пошуку доменів також можуть допомогти знайти субдомени

### **DNS**

Спробуємо отримати **subdomains** з **DNS** записів. Також варто спробувати **Zone Transfer** (якщо вразливо, слід повідомити про це).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато subdomains — шукати їх у зовнішніх джерелах. Найпоширеніші **tools** наведені нижче (для кращих результатів налаштуйте API keys):

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
Є й інші цікаві інструменти/API, які, навіть якщо не спеціалізуються безпосередньо на пошуку subdomains, можуть бути корисними для їх виявлення, наприклад:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання subdomains
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
- [**gau**](https://github.com/lc/gau)**:** витягує відомі URL-адреси з AlienVault's Open Threat Exchange, the Wayback Machine та Common Crawl для будь-якого домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках JS-файлів та витягують з них піддомени.
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

Цей проєкт пропонує безкоштовно всі subdomains, пов'язані з bug-bounty programs. До цих даних також можна отримати доступ за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть переглянути scope, який використовує цей проєкт [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **порівняння** багатьох із цих інструментів тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуємо знайти нові **subdomains**, brute-forcing DNS servers, використовуючи можливі subdomain names.

Для цієї дії вам знадобляться деякі **common subdomains wordlists, як-от**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IPs хороших DNS resolvers. Щоб згенерувати список trusted DNS resolvers, ви можете завантажити resolvers з [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для їх фільтрації. Або ви можете використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який виконав ефективний DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Я думаю, він використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — оболонка над `massdns`, написана на go, яка дозволяє перераховувати дійсні піддомени за допомогою активного bruteforce, а також резолвити піддомени із обробкою wildcard та простою підтримкою input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Також використовує `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) використовує asyncio для асинхронного brute force доменних імен.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Другий раунд DNS Brute-Force

Після того як ви знайшли субдомени за допомогою відкритих джерел та brute-forcing, можна згенерувати варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Для заданих доменів і субдоменів генерує перестановки.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Отримати **wordlist** перестановок для goaltdns можна [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** За заданими доменами та субдоменами генерує перестановки. Якщо файл перестановок не вказано, gotator використає власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації subdomains permutations, він також може спробувати resolve їх (але краще використовувати раніше згадані інструменти).
- Ви можете отримати altdns permutations **wordlist** в [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations і зміни subdomains. Цей інструмент виконуватиме brute force над результатами (він не підтримує dns wild card).
- Ви можете отримати dmut permutations wordlist за посиланням: [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену воно **генерує нові потенційні імена піддоменів** за вказаними шаблонами, щоб спробувати виявити більше піддоменів.

#### Розумна генерація перестановок

- [**regulator**](https://github.com/cramppet/regulator): Для більш детальної інформації читайте цей [**post**](https://cramppet.github.io/regulator/index.html), але по суті він витягає **основні частини** з **знайдених піддоменів** і перемішує їх, щоб знайти більше піддоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це subdomain brute-force fuzzer, поєднаний з надзвичайно простим, але ефективним DNS response-guided алгоритмом. Він використовує наданий набір вхідних даних, наприклад адаптований wordlist або історичні DNS/TLS записи, щоб точно синтезувати більше відповідних domain names і ще далі розширювати їх у циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Перегляньте цей пост у блозі, який я написав про те, як **automate the subdomain discovery** з домену за допомогою **Trickest workflows**, щоб мені не доводилося вручну запускати купу інструментів на своєму комп'ютері:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **one or several web pages** які належать subdomains, ви можете спробувати **find other subdomains with webs in that IP** шукаючи в **OSINT sources** домени в цій IP або шляхом **brute-forcing VHost domain names in that IP**.

#### OSINT

Ви можете знайти деякі **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**.

**Brute Force**

Якщо ви підозрюєте, що певний subdomain може бути прихований на веб-сервері, ви можете спробувати brute force його:
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

Іноді ви знайдете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише коли в заголовку _**Origin**_ вказано дійсний domain/subdomain. У таких випадках ви можете зловживати цією поведінкою, щоб **виявити** нові **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи вони **pointing** на якийсь тип **bucket**, і в такому випадку [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знаєте всі домени всередині scope, спробуйте [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Ви можете **monitor** появу **new subdomains** домену, відстежуючи журнали **Certificate Transparency**, як це робить [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Перевірте можливі [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** **pointing** на якийсь **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **subdomain with an IP different** від тих, що ви вже виявили під час assets discovery, варто виконати **basic vulnerability scan** (з використанням Nessus або OpenVAS) та зробити деякі [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів у **this book** ви можете знайти трюки, щоб "attack" їх.\
_Зверніть увагу, що іноді subdomain розміщений на IP, який не контролюється клієнтом, тому він може бути поза scope — будьте обережні._

## IPs

На початкових кроках ви могли **found some IP ranges, domains and subdomains**.\
Пора **recollect all the IPs from those ranges** та для **domains/subdomains (DNS queries).**

Використовуючи сервіси з перелічених **free apis**, ви також можете знайти **previous IPs used by domains and subdomains**. Ці IP можуть досі належати клієнту (і можуть дозволити вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна перевірити, які домени pointing на конкретну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (оскільки в них, швидше за все, ви нічого цікавого не знайдете). У виявлених запущених сервісах ви можете **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

На попередніх кроках ви, ймовірно, вже виконали певний **recon of the IPs and domains discovered**, тому можливо **already found all the possible web servers**. Проте, якщо цього не сталося, зараз ми розглянемо кілька **fast tricks to search for web servers** всередині scope.

Зверніть увагу, що це буде **oriented for web apps discovery**, тому ви також повинні **perform the vulnerability** та **port scanning** (**if allowed** за scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Інші дружні інструменти для пошуку веб-серверів: [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Ви передаєте список доменів, і вони спробують підключитися до порту 80 (http) та 443 (https). Додатково можна вказати спробу інших портів:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скріншоти**

Тепер, коли ви виявили **всі веб-сервери** в межах обсягу (серед **IPs** компанії та всіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тому зробімо все просто — почніть зі знімків екрана всіх цих сервісів. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** endpoints, які більш **схильні** до наявності **вразливостей**.

Для реалізації цієї ідеї ви можете використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, ви можете використати [**eyeballer**](https://github.com/BishopFox/eyeballer) щоб пройтись по всіх **скріншотах** і визначити, **що ймовірно містить вразливості**, а що — ні.

## Публічні хмарні активи

Щоб знайти потенційні хмарні активи, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії можна використовувати слова на кшталт: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Також вам знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім з цими словами слід згенерувати **пермутації** (перегляньте [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) для детальнішої інформації).

Отриманими wordlists можна користуватися за допомогою інструментів типу [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам'ятайте, що під час пошуку Cloud Assets потрібно **шукати більше, ніж просто buckets в AWS** — **шукати не тільки buckets в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете, наприклад, **open buckets або cloud functions exposed**, слід **отримати до них доступ** і перевірити, що вони вам дають і чи можна їх зловживати.

## Електронні адреси

Маючи **domains** і **subdomains** в межах обсягу, ви фактично маєте все необхідне, щоб почати пошук електронних адрес. Ось **APIs** та інструменти, які найкраще працювали для мене при знаходженні електронних адрес компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з API
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Пошук вразливостей**

Електронні адреси потім стануть в пригоді для **brute-force** веб-логінів та auth-сервісів (наприклад, **SSH**). Також вони необхідні для **phishings**. Крім того, ці **APIs** нададуть більше **інформації про особу**, пов'язану з email, що корисно для фішингової кампанії.

## Credential Leaks

Маючи **domains**, **subdomains** і **emails**, ви можете почати шукати облікові дані, які were **leaked** раніше і належать цим email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **валідні leaked** облікові дані, це дуже легкий виграш.

## Secrets Leaks

Credential leaks пов'язані з компрометаціями компаній, коли була витікнута та продана **чутлива інформація**. Однак компанії можуть страждати від інших типів **leaks**, інформація про які не завжди присутня в цих базах даних:

### Github Leaks

Облікові дані та API-токени можуть бути **leaked** у публічних репозиторіях компанії або користувачів, що працюють у цій GitHub-організації.\
Ви можете використати інструмент [**Leakos**](https://github.com/carlospolop/Leakos) щоб **скачати** всі **public repos** організації та її розробників і автоматично запустити над ними [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** також можна використати, щоб запустити **gitleaks** проти всього **тексту** з наданих URL-адрес, оскільки іноді **веб-сторінки також містять secrets**.

#### Github Dorks

Перевірте також цю **сторінку** на предмет потенційних **github dorks**, які ви можете шукати в організації, яку атакуєте:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді атакуючі або просто працівники публікують контент компанії на paste-сайтах. Це може містити або не містити **чутливу інформацію**, але це дуже корисно для пошуку.\
Ви можете використати інструмент [**Pastos**](https://github.com/carlospolop/Pastos) для пошуку одночасно по більш ніж 80 paste-сайтам.

### Google Dorks

Старі, але дієві google dorks завжди корисні для знаходження **відкритої інформації, яка не повинна там бути**. Проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** потенційних запитів, які неможливо прогнати вручну. Отже, ви можете взяти свої улюблені 10 запитів або використати інструмент на кшталт [**Gorks**](https://github.com/carlospolop/Gorks) **щоб прогнати їх усі**.

_Зверніть увагу, що інструменти, які намагаються прогнати всю базу через звичайний браузер Google, швидко закінчаться — Google заблокує вас дуже-дуже скоро._

### **Пошук вразливостей**

Якщо ви знайдете **валідні leaked** облікові дані або API-токени, це дуже простий виграш.

## Вразливості в публічному коді

Якщо ви виявили, що компанія має **open-source code**, ви можете **проаналізувати** його та шукати **вразливості**.

**В залежності від мови** існують різні **інструменти**, які можна використати:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Існують також безкоштовні сервіси, які дозволяють **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Більшість вразливостей, які знаходять bug hunters, містяться у **веб-додатках**, тому на цьому етапі варто ознайомитися з **методологією тестування веб-додатків** — ви можете [**знайти цю інформацію тут**](../../network-services-pentesting/pentesting-web/index.html).

Також окремо хочу відзначити розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), адже, хоча не варто очікувати від них виявлення дуже серйозних вразливостей, вони корисні для інтеграції в workflows, щоб отримати початкову веб-інформацію.

## Підсумок

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, це базово, бо можна виконати набагато більше перерахувань (побачимо ще трюки пізніше).

Отже, ви вже:

1. Знайшли всі **компанії** в межах обсягу  
2. Знайшли всі **assets**, що належать компаніям (і виконали деяке сканування вразливостей, якщо це в межах обсягу)  
3. Знайшли всі **domains**, що належать компаніям  
4. Знайшли всі **subdomains** доменів (чи можливий subdomain takeover?)  
5. Знайшли всі **IPs** (як від CDN, так і не від CDN) в межах обсягу  
6. Знайшли всі **веб-сервери** і зробили **скріншоти** їх (є щось дивне, що варто дослідити глибше?)  
7. Знайшли всі **потенційні public cloud assets**, що належать компанії  
8. **Emails**, **credentials leaks**, і **secret leaks**, які можуть принести вам **великий виграш дуже просто**  
9. **Pentesting** усіх знайдених вебів

## **Full Recon Automatic Tools**

Існує декілька інструментів, які виконають частину описаних дій для заданого обсягу:

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи застарілий і нещодавно не оновлювався

## **Посилання**

- Всі безкоштовні курси [**@Jhaddix**](https://twitter.com/Jhaddix), наприклад [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
