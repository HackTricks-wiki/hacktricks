# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Тобто вам сказали, що все, що належить деякій компанії, входить до зони дослідження, і ви хочете з’ясувати, чим ця компанія фактично володіє.

Мета цього етапу — отримати всі **компанії, що належать головній компанії**, а потім всі **активи** цих компаній. Для цього ми збираємося:

1. Знайти придбання (acquisitions) головної компанії — це дасть нам компанії в межах scope.
2. Знайти ASN (якщо є) кожної компанії — це дасть нам IP-діапазони, якими володіє кожна компанія.
3. Використати reverse whois lookup-и для пошуку інших записів (назви організацій, домени...) пов’язаних з першим — це можна робити рекурсивно.
4. Використати інші техніки, як shodan `org`and `ssl`filters, для пошуку інших активів (фокус `ssl` можна застосовувати рекурсивно).

### **Придбання**

Насамперед потрібно дізнатися, які **інші компанії належать головній компанії**.\
Один варіант — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** головну компанію і **натиснути** на "**acquisitions**". Там ви побачите інші компанії, придбані головною.\
Інший варіант — відвідати сторінку головної компанії в **Wikipedia** і шукати розділ **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві реєстри компаній (наприклад, **Companies House** у Великобританії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Добре, на цьому етапі ви повинні знати всі компанії в межах scope. Тепер з’ясуємо, як знайти їхні активи.

### **ASNs**

An autonomous system number (**ASN**) — це **унікальний номер**, призначений автономній системі (AS) органом **Internet Assigned Numbers Authority (IANA)**.\
Автономна система (AS) складається з **блоків** IP-адрес, які мають чітко визначену політику доступу до зовнішніх мереж і керуються однією організацією, але можуть включати кількох операторів.

Цікавить визначити, чи **компанії призначено якийсь ASN**, щоб знайти її **IP-діапазони**. Варто виконати **перевірку на вразливості** проти всіх **hosts** в межах **scope** і **шукати домени** в цих IP-адресах.\
Ви можете **шукати** за назвою компанії, за IP або за доменом на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону** компанії, корисними для збору додаткових даних можуть бути: [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Втім, ймовірно, вся** корисна інформація **(IP-діапазони та Whois)** вже з’явиться на першому посиланню.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration автоматично агрегує та підсумовує ASNs наприкінці scan.
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
Ви також можете знайти діапазони IP організації, використовуючи [http://asnlookup.com/](http://asnlookup.com) (він має безкоштовний API).\
Ви можете знайти IP та ASN домену, використовуючи [http://ipv4info.com/](http://ipv4info.com/).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах охоплення**, тому, якщо вам дозволено, ви можете запустити якийсь **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) над усіма хостами.\
Також ви можете виконати деякі [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися сервісами на зразок** Shodan, Censys або ZoomEye **щоб знайти** відкриті порти, **і залежно від того, що ви знайдете, вам слід** звернутися до цієї книги, щоб дізнатися, як pentest кілька можливих сервісів, що працюють.\
**Також варто зазначити, що можна підготувати деякі** стандартні списки імен користувачів **та** паролів **і спробувати** bruteforce сервіси за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домені

> Ми знаємо всі компанії в межах охоплення та їхні активи — час знайти домени в межах охоплення.

_Зверніть увагу, що наведеними нижче методами ви також можете знайти піддомени, і цю інформацію не слід недооцінювати._

Перш за все вам слід шукати **основний(і) домен(и)** кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP доменів, ви можете спробувати виконати **reverse dns lookups** на тих **IPs, щоб знайти більше доменів в межах охоплення**. Спробуйте використовувати якийсь dns-сервер жертви або якийсь відомий dns-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Щоб це працювало, адміністратору потрібно вручну увімкнути PTR.\
Також можете скористатися онлайн-інструментом для цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисні інструменти, такі як [**massdns**](https://github.com/blechschmidt/massdns) та [**dnsx**](https://github.com/projectdiscovery/dnsx), щоб автоматизувати зворотні DNS-запити та збагачення.

### **Reverse Whois (loop)**

У середині **whois** можна знайти багато цікавих **даних**, як-от **назву організації**, **адресу**, **електронні адреси**, телефонні номери... Але ще цікавіше те, що можна знайти **додаткові активи, пов'язані з компанією**, якщо виконати **reverse whois lookups за будь-яким із цих полів** (наприклад інші whois-записи, де з'являється та сама електронна пошта).\
Можна використовувати онлайн-інструменти, такі як:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com/) - веб — **безкоштовно**, API — платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **Платно**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **Платно** (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - **Платно**
- [https://securitytrails.com/](https://securitytrails.com/) - **Платно** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **Платно** (API)

Це завдання можна автоматизувати за допомогою [**DomLink**](https://github.com/vysecurity/DomLink) (потребує whoxy API key).\
Можна також виконати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення більшої кількості доменних імен щоразу, коли ви знаходите новий домен.**

### **Trackers**

Якщо виявити **той самий ID одного й того ж трекера** на двох різних сторінках, можна припустити, що **обидві сторінки** **керуються тією самою командою**.\
Наприклад, якщо ви бачите той самий **Google Analytics ID** або той самий **Adsense ID** на декількох сторінках.

Є кілька сайтів та інструментів, що дозволяють шукати за цими трекерами та іншим:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов'язані сайти за спільними analytics/trackers)

### **Favicon**

Чи знали ви, що можна знайти пов'язані домени та піддомени нашої цілі, шукаючи однаковий хеш іконки favicon? Саме це і робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - виявлення доменів з тим самим favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Просто кажучи, favihash дозволить нам виявляти домени, які мають той самий favicon icon hash, що й наш target.

Moreover, you can also search technologies using the favicon hash as explained in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **hash of the favicon of a vulnerable version of a web tech** ви можете шукати його в shodan і **знайти більше вразливих місць**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Ось як ви можете **розрахувати favicon hash** веб-сайту:
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
Ви також можете отримувати хеші favicon у великих масштабах за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) і потім pivot у Shodan/Censys.

### **Авторське право / Унікальний рядок**

Шукайте на веб-сторінках **рядки, які можуть повторюватися на різних сайтах однієї організації**. **Рядок авторського права** може бути хорошим прикладом. Потім шукайте цей рядок у **google**, в інших **браузерах** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Зазвичай у системі є cron job, такий як
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб поновити всі сертифікати доменів на сервері. Це означає, що навіть якщо CA, який використано для цього, не вказує час створення у полі Validity, все одно можливо **знайти домени тієї самої компанії у certificate transparency logs**.\
Перегляньте це [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Ви можете використовувати веб-сайт, такий як [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструмент, такий як [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та субдомени з однаковою DMARC-інформацією**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) та [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Схоже, часто люди призначають субдомени IP-адресам, які належать cloud providers, і згодом **втрачають ту IP-адресу, але забувають видалити DNS-запис**. Тому просто **спаунінг VM** у хмарі (наприклад Digital Ocean) фактично може призвести до **takeover деяких subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) розповідає історію про це та пропонує скрипт, який **спаунить VM в DigitalOcean**, **отримує** **IPv4** нової машини та **шукає в Virustotal записи субдоменів**, що вказують на неї.

### **Other ways**

**Зауважте, що ви можете використовувати цю техніку для виявлення додаткових доменів щоразу, коли знаходите новий домен.**

**Shodan**

Оскільки ви вже знаєте назву організації, що володіє IP-простором, ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."`. Перевірте знайдені хости на наявність нових несподіваних доменів у TLS certificate.

Ви можете отримати **TLS certificate** головної веб-сторінки, визначити **Organisation name**, а потім шукати це ім'я в **TLS certificates** усіх відомих shodan веб-сторінок з фільтром: `ssl:"Tesla Motors"` або використати інструмент, такий як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — інструмент, який шукає **domains related** з основним доменом та їх **subdomains**, доволі вражаюче.

**Passive DNS / Historical DNS**

Passive DNS дані чудово підходять для пошуку **старих і забутих записів**, які досі резолвляться або які можна захопити. Дивіться:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Перевірте на наявність [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує якийсь домен**, але **втратила право власності**. Просто зареєструйте його (якщо дешево) і повідомте компанію.

Якщо ви знайдете будь-який **домен з IP, відмінним** від тих, що ви вже знайшли під час виявлення активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) та деякі [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) інструментами **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі** ви знайдете кілька трюків, щоб «атакувати» їх.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> Ми знаємо всі компанії в межах scope, всі активи кожної компанії та всі домени, пов'язані з цими компаніями.

Настав час знайти всі можливі субдомени кожного знайденого домену.

> [!TIP]
> Зауважте, що деякі інструменти та техніки для пошуку доменів також можуть допомогти у пошуку субдоменів

### **DNS**

Спробуємо отримати **subdomains** з записів **DNS**. Також слід спробувати **Zone Transfer** (якщо вразливий — необхідно про це повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато subdomains — це пошук у зовнішніх джерелах. Найчастіше використовувані **інструменти** (для кращих результатів налаштуйте ключі API):

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
Існують **інші цікаві інструменти/APIs**, які, хоча й не спеціалізуються на пошуку subdomains, можуть бути корисними для їх виявлення, наприклад:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC безкоштовний API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** витягує відомі URLs з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого заданого домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках JS files і витягують звідти subdomains.
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

Цей проект пропонує **безкоштовно всі subdomains, що стосуються bug-bounty programs**. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть переглянути scope, який використовує цей проект [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **порівняння** багатьох із цих інструментів тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуємо знайти нові **subdomains**, brute-forcing DNS servers, використовуючи можливі subdomain names.

Для цієї дії вам знадобляться деякі **common subdomains wordlists, такі як**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IPs хороших DNS resolvers. Щоб згенерувати список trusted DNS resolvers, ви можете завантажити resolvers з [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для фільтрації. Або ви можете використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який ефективно виконував DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Здається, цей просто використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це оболонка для `massdns`, написана на go, яка дозволяє перераховувати valid subdomains за допомогою active bruteforce, а також resolve subdomains з підтримкою wildcard та простим input-output support.
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

Після того як ви знайшли субдомени за допомогою відкритих джерел та brute-forcing, ви можете згенерувати варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Беручи домени та субдомени, генерує їхні перестановки.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Генерує перестановки на основі доменів та піддоменів.
- Ви можете отримати goaltdns permutations **wordlist** за адресою [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Генерує перестановки на основі доменів та субдоменів. Якщо файл permutations не вказано, gotator використовуватиме власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерування subdomains permutations, він також може спробувати їх resolve (але краще використовувати попередньо згадані інструменти).
- Ви можете отримати altdns permutations **wordlist** в [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations та alteration субдоменів. Цей інструмент буде brute force результат (він не підтримує dns wild card).
- Ви можете отримати dmut permutations wordlist за посиланням [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі domain воно **генерує нові потенційні імена subdomains** на основі вказаних шаблонів, щоб спробувати виявити більше subdomains.

#### Розумна генерація перестановок

- [**regulator**](https://github.com/cramppet/regulator): За детальнішою інформацією прочитайте цей [**post**](https://cramppet.github.io/regulator/index.html), але по суті він отримає **основні частини** з **виявлених subdomains** та перемішає їх, щоб знайти більше subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це subdomain brute-force fuzzer, поєднаний з надзвичайно простим, але ефективним DNS reponse-guided алгоритмом. Він використовує наданий набір вхідних даних, таких як tailored wordlist або історичні DNS/TLS records, щоб точно синтезувати більше відповідних доменних імен та ще більше їх розширювати в циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Робочий процес виявлення субдоменів**

Перегляньте цей блог-пост, який я написав про те, як **автоматизувати виявлення субдоменів** для домену за допомогою **Trickest workflows**, щоб мені не доводилося вручну запускати багато інструментів на моєму комп'ютері:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька веб-сторінок**, які належать субдоменам, ви можете спробувати **знайти інші субдомени з веб-сайтами на цьому IP**, переглядаючи **джерела OSINT** на предмет доменів в IP або шляхом **brute-forcing VHost domain names in that IP**.

#### OSINT

Ви можете знайти деякі **VHosts на IP за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що якийсь субдомен може бути прихований на веб-сервері, ви можете спробувати brute force його:

Коли **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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

Інколи ви знайдете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли у заголовку _**Origin**_ встановлено допустимий домен/піддомен. У таких сценаріях ви можете зловживати цією поведінкою, щоб **виявляти** нові **піддомени**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи **pointing** він на будь-який тип **bucket**, і в такому разі [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже будете знати всі домени в межах області, спробуйте [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **new subdomains** для домену, відстежуючи **Certificate Transparency** Logs, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте на можливі [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** **pointing** на якийсь **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете будь-який **subdomain with an IP different** від тих, що ви вже виявили під час assets discovery, слід виконати **basic vulnerability scan** (з використанням Nessus або OpenVAS) та деякі [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) з **nmap/masscan/shodan**. Залежно від запущених сервісів, у **this book some tricks to "attack" them**.\
_Зверніть увагу, що інколи subdomain розміщено на IP, який не контролюється клієнтом, тому він може не входити в scope — будьте обережні._

## IPs

На початкових кроках ви могли **found some IP ranges, domains and subdomains**.\
Пора **recollect all the IPs from those ranges** і для **domains/subdomains (DNS queries).**

Використовуючи сервіси з наступних **free apis**, ви також можете знайти **previous IPs used by domains and subdomains**. Ці IP можуть іще належати клієнту (і можуть дозволити вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна перевірити, які домени вказують на конкретну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Port scan all the IPs that doesn’t belong to CDNs** (бо, ймовірно, ви там нічого цікавого не знайдете). У запущених сервісах можна **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Пошук web-серверів

> Ми знайшли всі компанії та їх активи і знаємо IP ranges, domains and subdomains в межах scope. Час шукати web servers.

На попередніх кроках ви, ймовірно, вже провели деякий **recon of the IPs and domains discovered**, тож можете **already found all the possible web servers**. Однак якщо ні — далі розглянемо кілька **fast tricks to search for web servers** в межах scope.

Зверніть увагу, що це буде **орієнтовано на web apps discovery**, тому ви також повинні виконати **вразливісний** та **port scanning** (якщо це дозволено в scope).

Швидкий метод для виявлення **ports open**, пов'язаних з **web** серверами з використанням [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний інструмент для пошуку web-серверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і вони спробують підключитися до порту 80 (http) та 443 (https). Додатково можна вказати спробу інших портів:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Тепер, коли ви виявили **all the web servers**, що знаходяться в межах scope (серед **IPs** компанії та усіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тож давайте спростимо: почнемо зі зроблення скріншотів усіх них. Просто **поглянувши** на **main page**, ви можете знайти **дивні** endpoints, які більш **схильні** до бути **vulnerable**.

Для реалізації цієї ідеї ви можете використати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, ви можете потім використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб прогнати всі **screenshots** і визначити, **що ймовірно містить vulnerabilities**, а що — ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto компанії можна використовувати слова типу: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Також вам знадобляться wordlists з **common words used in buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім, використовуючи ці слова, слід згенерувати **permutations** (див. [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) для отримання додаткової інформації).

З отриманих wordlists ви можете скористатися такими інструментами, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що при пошуку Cloud Assets слід шукати **не лише buckets в AWS**.

### **Looking for vulnerabilities**

Якщо ви знайдете, наприклад, **open buckets or cloud functions exposed**, ви повинні **отримати доступ до них** і подивитися, що вони вам можуть запропонувати і чи можна їх зловживати.

## Emails

Маючи **domains** і **subdomains** всередині scope, ви фактично маєте все, що потрібно для початку пошуку emails. Ось API та інструменти, які найкраще допомагали мені знаходити emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails стануть у пригоді пізніше для **brute-force web logins and auth services** (наприклад, SSH). Також вони потрібні для **phishings**. Крім того, ці APIs дадуть вам більше **info about the person** за email, що корисно для phishing-кампанії.

## Credential Leaks

Маючи **domains,** **subdomains**, і **emails**, ви можете почати шукати credentials, які були leak в минулому й належать цим email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials, це дуже легкий win.

## Secrets Leaks

Credential leaks пов'язані з compromise компаній, де **sensitive information was leaked and sold**. Проте компанії можуть постраждати від **інших leaks**, інформація про які відсутня в тих базах:

### Github Leaks

Credentials і API можуть бути leaked у **публічних репозиторіях** компанії або користувачів, що працюють у тій github company.\
Ви можете використати інструмент **Leakos** ([**Leakos**](https://github.com/carlospolop/Leakos)) для **завантаження** всіх **public repos** організації та її **developers** і автоматичного запуску [**gitleaks**](https://github.com/zricethezav/gitleaks) по ним.

**Leakos** також можна використати для запуску **gitleaks** проти всього **text** з переданих URL, оскільки інколи **web pages also contains secrets**.

#### Github Dorks

Перевірте також цю **сторінку** для потенційних **github dorks**, які ви також можете шукати в організації, яку атакуєте:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді attackers або просто працівники публікують company content на paste-сайтах. Це може містити, а може й не містувати **sensitive information**, проте варте пошуку.\
Ви можете використати інструмент [**Pastos**](https://github.com/carlospolop/Pastos) для пошуку одночасно по більш ніж 80 paste-сайтам.

### Google Dorks

Старі, але ефективні google dorks завжди корисні для знаходження **exposed information that shouldn't be there**. Проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **thousands** можливих запитів, які важко виконувати вручну. Тож ви можете взяти свої улюблені 10 або використати інструмент, такий як [**Gorks**](https://github.com/carlospolop/Gorks), **щоб прогнати їх усі**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials або API tokens, це дуже легкий win.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, ви можете **проаналізувати** його і шукати **vulnerabilities** в ньому.

**Залежно від мови** існують різні **tools**, які ви можете використовувати:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Є також безкоштовні сервіси, які дозволяють **scan public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Більшість вразливостей, які знаходять bug hunters, знаходяться всередині **web applications**, тому зараз я хотів би згадати про **web application testing methodology**, і ви можете [**знайти цю інформацію тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу особливо відзначити розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча ви не повинні очікувати від них відкриття дуже чутливих vulnerabilities, вони зручні для вбудовування у **workflows** щоб отримати початкову web information.

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

Отже, ви вже:

1. Знайшли усіх **companies** в межах scope
2. Знайшли усі **assets** компаній (і провели часткове vuln scan, якщо це в межах scope)
3. Знайшли усі **domains** компаній
4. Знайшли усі **subdomains** від доменів (будь-який subdomain takeover?)
5. Знайшли усі **IPs** (з CDN і поза CDN) в межах scope.
6. Знайшли усі **web servers** і зробили їх **screenshot** (є щось дивне, що варто глибшого дослідження?)
7. Знайшли усі **potential public cloud assets** компанії.
8. **Emails**, **credentials leaks**, і **secret leaks**, які можуть дати вам дуже легкий big win.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Існує кілька інструментів, які виконуватимуть частину перелічених дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи старий і не оновлюється

## **References**

- Усі безкоштовні курси від [**@Jhaddix**](https://twitter.com/Jhaddix), наприклад [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
