# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим насправді володіє ця компанія.

Мета цього етапу — отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми:

1. Знаходимо придбання головної компанії — це дасть нам компанії, що входять до scope.
2. Знаходимо ASN (якщо є) кожної компанії — це дасть нам IP-діапазони, якими володіє кожна компанія.
3. Використовуємо reverse whois lookups для пошуку інших записів (назви організацій, домени...) пов'язаних із першим записом (це можна робити рекурсивно).
4. Використовуємо інші техніки, як-от фільтри `org` і `ssl` у shodan, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку головної компанії у **Wikipedia** та пошукати **acquisitions**.\
Для публічних компаній перевірте **документи SEC/EDGAR**, сторінки **зв'язків з інвесторами** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви маєте знати всі компанії, що входять до scope. З'ясуймо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво з'ясувати, чи **компанії призначено будь-який ASN**, щоб знайти її **IP-діапазони.** Варто виконати **тестування на вразливості** всіх **хостів** усередині **scope** і **пошукати домени** серед цих IP-адрес.\
Ви можете **шукати** за **назвою** компанії, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). У будь-якому разі, імовірно, вся** корисна інформація **(IP-діапазони та Whois)** уже є в першому посиланні.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також enumeration [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** автоматично агрегує та підсумовує ASN наприкінці сканування.
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
Ви також можете знайти IP-діапазони організації за допомогою [http://asnlookup.com/](http://asnlookup.com) (сервіс має безкоштовний API).\
Ви можете знайти IP та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тому, якщо вам це дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також ви можете виконати [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **а залежно від того, що ви знайдете, варто** переглянути в цій книзі, як виконувати pentest різних можливих запущених сервісів.\
**Також варто згадати, що ви можете підготувати** списки стандартних username **і** passwords **та спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою наведених нижче запропонованих технік можна також знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все, потрібно знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі IP-діапазони доменів, можна спробувати виконати **reverse DNS lookups** для цих **IP, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або відомий DNS-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Щоб це працювало, адміністратор має вручну увімкнути PTR.\
Ви також можете скористатися онлайн-інструментом для отримання цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними будуть такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які дають змогу автоматизувати reverse lookups та enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші реєстраційні записи whois, де зустрічається та сама електронна адреса).\
Ви можете використовувати такі онлайн-інструменти:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (Web та API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** Web, API платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Ви можете автоматизувати це завдання за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен API key whoxy).\
Ви також можете виконувати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що за допомогою цієї техніки можна знаходити більше доменних імен щоразу, коли ви виявляєте новий домен.**

### **Trackers**

Якщо ви знаходите **той самий ID того самого tracker** на 2 різних сторінках, можна припустити, що **обома сторінками** керує **одна команда**.\
Наприклад, якщо ви бачите той самий **Google Analytics ID** або той самий **Adsense ID** на кількох сторінках.

Існують сторінки та інструменти, які дають змогу виконувати пошук за цими trackers та іншими даними:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними analytics/trackers)

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та subdomains нашої цілі, шукаючи той самий hash іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Простіше кажучи, favihash дозволить нам виявити домени, які мають такий самий хеш іконки favicon, як і наша ціль.

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ось як можна **обчислити хеш favicon** вебсайту (MMH3 над **закодованими в base64** байтами favicon):
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url, timeout=10)
favicon = codecs.encode(response.content, "base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Можна також отримувати favicon hashes у масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім виконувати pivoting у Shodan/Censys.

Розглядайте fingerprint favicon як підказки та перевіряйте їх за допомогою додаткових сигналів.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте hash як індикатор, а не доказ**: MMH3 є компактним; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: аналізуйте шляхи framework/build, manifest-файли, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URLs і HTML-теги `<link rel="icon">`.
- **Static assets можуть залишатися доступними за контролями WAF/SSO/IdP**: запитуйте іконку напряму та перевіряйте `ETag`, `Last-Modified`, redirects і cache headers.
- **Перевіряйте збіги за додатковими сигналами**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS-сертифікатів, product components і exposed ports.
- **Групуйте за HTML/body hash**: узгоджений template посилює fingerprint; різні templates вказують на generic або shared icon.
- **Розглядайте hash, який трапляється в різних signatures, ports і products, як потенційний honeypot або placeholder.**
- **Для неоднозначних targets порівнюйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові hosting або parking responses можуть пояснювати спільну іконку.
- **Починайте triage з detection rules Nuclei або public datasets**, які зіставляють favicon hashes із products і CPEs.
- **Пам’ятайте про IP-centric coverage gap**: поверхні, що працюють через CDN, маршрутизацію SNI, anycast і доступні лише через domain, можуть бути відсутні в наборах даних на кшталт Shodan.

### **Copyright / Uniq string**

Шукайте всередині вебсторінок **strings, які можуть бути спільними для різних вебсайтів тієї самої організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **Google**, інших **browsers** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Поширеною є наявність cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб одночасно оновити всі сертифікати на сервері. Зіставлення часових міток сертифікатів або позицій у журналах certificate-transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також безпосередньо використовуйте журнали **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Ви можете скористатися вебсайтом на кшталт [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструментом на кшталт [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та піддомени, які використовують однакову інформацію dmarc**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Покинутий A-запис може стати доступним, коли cloud-провайдер повторно призначає IP-адресу. У згаданому дослідженні демонструється opportunistic workflow, який розгортає instance і зіставляє його адресу з даними passive DNS; перевіряйте сценарії takeover лише в межах дозволеного периметра.<sup>[[7]](#references)</sup>

### **Інші способи**

**Shodan**

Як ви вже знаєте назву організації, якій належить діапазон IP-адрес. Ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете отримати доступ до **TLS-сертифіката** головної вебсторінки, отримати **назву організації**, а потім шукати цю назву всередині **TLS-сертифікатів** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)— це інструмент, який шукає **домени, пов’язані** з основним доменом, і їхні **піддомени**; просто чудовий інструмент.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово допомагають знаходити **старі та забуті записи**, які досі резолвляться або можуть бути захоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте на наявність [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від тих, які вже виявили під час пошуку активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і виконати [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб, у **цій книзі можна знайти деякі прийоми для їхньої «атаки»**.\
_Зверніть увагу, що іноді домен розміщено всередині IP-адреси, яка не контролюється клієнтом, тому він не входить до периметра; будьте обережні._

## Піддомени

> Ми знаємо всі компанії в межах периметра, усі активи кожної компанії та всі домени, пов’язані з цими компаніями.

Час знайти всі можливі піддомени кожного виявленого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти й методи пошуку доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо він можливий через вразливість, це слід повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — це пошук у зовнішніх джерелах. Найчастіше використовувані **інструменти** наведено нижче (для кращих результатів налаштуйте API-ключі):

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
Є **інші цікаві tools/API**, які, навіть якщо безпосередньо не спеціалізуються на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) безкоштовний API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання піддоменів
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**Безкоштовний API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого заданого домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб-простір у пошуках JS-файлів і витягують із них субдомени.
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
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку subdomains та історії IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт **безкоштовно надає всі subdomains, пов'язані з bug-bounty programs**. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовує цей проєкт: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Порівняння багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **subdomains**, виконуючи brute-force DNS-серверів із використанням можливих назв subdomains.

Для цієї дії вам знадобляться **wordlists із поширеними назвами subdomains, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси надійних DNS-resolvers. Щоб створити список trusted DNS-resolvers, ви можете завантажити resolvers із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати їх. Або можна використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який забезпечив ефективний DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, наскільки я розумію, використовує лише 1 резолвер
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка над `massdns`, написана на go, яка дає змогу перераховувати дійсні субдомени за допомогою active bruteforce, а також розв’язувати субдомени з обробкою wildcard і зручною підтримкою введення та виведення.
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

Після знаходження субдоменів за допомогою відкритих джерел і brute-forcing можна створити варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисними є кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Створює перестановки на основі доменів і субдоменів.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** На основі доменів і субдоменів генерує перестановки. Якщо файл перестановок не вказано, gotator використає власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації permutations субдоменів, він також може спробувати їх розв’язати (але краще використовувати попередні інструменти, позначені як коментарі).
- Ви можете отримати **wordlist** permutations altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Інший інструмент для виконання перестановок, мутацій і змін піддоменів. Цей інструмент здійснює brute force результату (не підтримує dns wild card).
- Ви можете отримати wordlist перестановок dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена субдоменів** за вказаними шаблонами, щоб спробувати виявити більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Навчається regex-подібних шаблонів на основі виявлених субдоменів і генерує імена-кандидати для DNS-розв’язання.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force піддоменів, поєднаний із надзвичайно простим, але ефективним алгоритмом, керованим DNS-відповідями. Він використовує наданий набір вхідних даних, як-от спеціально підготовлений wordlist або історичні DNS/TLS-записи, щоб точно генерувати більше відповідних доменних імен і ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS-сканування.
```
echo www | subzuf facebook.com
```
### **Workflow виявлення піддоменів**

Приклади workflow у Trickest поєднують OSINT, DNS brute force та етапи permutation для повторюваного перерахування піддоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать піддоменам, можна спробувати **знайти інші піддомени з вебсайтами на цій IP-адресі**, шукаючи в **OSINT-джерелах** домени за IP-адресою або виконуючи **brute force доменних імен VHost на цій IP-адресі**.

#### OSINT

Ви можете знайти деякі **VHosts в IP-адресах за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що вебсервер може приховувати певний піддомен, можна спробувати виконати brute force:

Для vhosts на основі імені виконуйте fuzzing заголовка `Host` і використовуйте auto-calibration ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>
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
> За допомогою цієї technique ви навіть можете отримати доступ до внутрішніх/прихованих endpoints.

### **CORS Brute Force**

Іноді ви знаходитимете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли у заголовку _**Origin**_ вказано дійсний domain/subdomain. У таких сценаріях ви можете зловживати цією поведінкою, щоб **виявити** нові **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи **вказує** він на будь-який тип **bucket**, і в такому разі [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**brute force можливих назв bucket і перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові subdomains** домену, моніторячи логи **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі випадки [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** вказує на певний **S3 bucket**, [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **subdomain з IP, відмінною** від уже знайдених під час asset discovery, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених services, у **цій книзі можна знайти певні tricks для їхньої "атаки"**.\
_Зверніть увагу, що іноді subdomain розміщений на IP, яка не контролюється клієнтом, тому вона не входить до scope; будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти певні діапазони IP, домени та subdomains**.\
Настав час **зібрати всі IP-адреси з цих діапазонів**, а також **домени/subdomains (DNS-запити).**

За допомогою services із наведених нижче **безкоштовних API** ви також можете знайти **попередні IP-адреси, які використовувалися доменами та subdomains**. Ці IP-адреси все ще можуть належати клієнту (і можуть допомогти знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити домени, що вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Проскануйте порти всіх IP-адрес, які не належать CDN** (оскільки, найімовірніше, ви не знайдете там нічого цікавого). У виявлених запущених services ви можете **знайти вразливості**.

**Знайдіть** [**guide**](../pentesting-network/index.html) **щодо сканування hosts.**

## Пошук web servers

> Ми знайшли всі компанії та їхні assets і знаємо діапазони IP, домени та subdomains у межах scope. Настав час шукати web servers.

На попередніх етапах ви, ймовірно, вже виконали певну **recon IP-адрес і знайдених доменів**, тож, можливо, **вже знайшли всі можливі web servers**. Однак якщо ні, зараз ми розглянемо кілька **швидких tricks для пошуку web servers** у межах scope.

Зверніть увагу, що це буде **орієнтовано на виявлення web apps**, тому також слід виконати **сканування вразливостей** і **сканування портів** (**якщо це дозволено** scope).

[**Швидкий метод** виявлення **відкритих портів**, пов’язаних із **web** servers, за допомогою **masscan** можна знайти тут](../pentesting-network/index.html#http-port-discovery).\
Ще одним зручним інструментом для пошуку web servers є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і інструмент спробує підключитися до портів 80 (http) і 443 (https). Додатково можна вказати інші порти:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Знімки екрана**

Тепер, коли ви виявили **всі вебсервери**, присутні в межах scope (серед **IP-адрес** компанії, а також усіх **доменів** і **піддоменів**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі створення знімків екрана для всіх них. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **знімків екрана**, щоб визначити, **що, ймовірно, містить вразливості**, а що — ні.

## Публічні хмарні активи

Щоб знайти потенційні cloud-активи, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії можна використовувати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід згенерувати **перестановки** (докладнішу інформацію див. у розділі [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

З отриманими wordlists можна використовувати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud Assets слід шукати **не лише buckets в AWS**.

### **Пошук вразливостей**

Якщо ви виявили **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ**, перевірити, що вони можуть вам запропонувати, і чи можна ними зловживати.

## Електронні адреси

Маючи **домени** та **піддомени** в межах scope, ви фактично маєте все, що **потрібно для початку пошуку електронних адрес**. Ось **API** та **інструменти**, які найкраще працювали для мене під час пошуку електронних адрес компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси стануть у пригоді пізніше для **brute-force веблогінів і auth-сервісів** (наприклад, SSH). Вони також потрібні для **phishings**. Крім того, ці API нададуть ще більше **інформації про людину**, яка стоїть за електронною адресою, що корисно для phishing-кампанії.

## Credential Leaks

Маючи **домени,** **піддомени** та **електронні адреси**, можна почати шукати credentials, leaked у минулому, які належать цим електронним адресам:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **valid leaked** credentials, це буде дуже легкою перемогою.

## Secrets Leaks

Credential leaks пов’язані зі зламами компаній, під час яких **конфіденційна інформація була leaked і продана**. Однак компанії можуть постраждати через **інші leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials та API можуть бути leaked у **публічних репозиторіях** **компанії** або **користувачів**, які працюють у цій github-компанії.\
Можна використовувати **інструмент** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **організації** та її **розробників**, а також автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** щодо всього **тексту**, наданого через **URL-адреси**, передані йому, оскільки іноді **вебсторінки також містять secrets**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks page](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Pastes Leaks

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайті**. Він може містити або не містити **конфіденційну інформацію**, але пошук таких даних є дуже цікавим.\
Можна використовувати інструмент [**Pastos**](https://github.com/carlospolop/Pastos) для одночасного пошуку на понад 80 paste-сайтах.

### Google Dorks

Старі, але ефективні Google dorks завжди корисні для пошуку **відкритої інформації, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо запускати вручну. Тому можна вибрати свої улюблені 10 або скористатися **інструментом, наприклад** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб запустити їх усі**.

_Зверніть увагу, що інструменти, які намагаються використати всю базу даних через звичайний браузер Google, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **valid leaked** credentials або API-токени, це буде дуже легкою перемогою.

## Вразливості публічного коду

Якщо ви виявили, що компанія має **open-source код**, його можна **проаналізувати** та пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **інструменти**; див. список [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також існують безкоштовні сервіси, які дають змогу **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься всередині **вебзастосунків**, тому на цьому етапі я хочу розповісти про **методологію тестування вебзастосунків**. Цю [**інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже чутливі вразливості, вони корисні для додавання до **workflows, щоб отримати початкову інформацію про вебзастосунки.**

## Підсумок

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше ми розглянемо додаткові прийоми).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **активи**, що належать компаніям (і виконали vuln scan, якщо це входить до scope)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **піддомени** доменів (чи немає subdomain takeover?)
5. Знайшли всі **IP-адреси** (з **CDN** і **без CDN**) у межах scope.
6. Знайшли всі **вебсервери** та зробили їхні **знімки екрана** (чи є щось дивне, що варте детальнішого аналізу?)
7. Знайшли всі **потенційні public cloud assets**, що належать компанії.
8. **Електронні адреси**, **credential leaks** і **secret leaks**, які можуть дуже легко принести вам **велику перемогу**.
9. **Провели Pentesting усіх знайдених вебзастосунків**

## **Повністю автоматизовані інструменти Recon**

Існує чимало інструментів, які виконують частину запропонованих дій щодо заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — Трохи застарілий і не оновлюється

## References

- [1] [Jason Haddix – Методологія Bug Hunter's v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про Favicons: від іконок браузера до розвідки поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою атаки на часову кореляцію Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: виявлення (та імітація) дорогої кампанії з subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Унікальний метод enumeration піддоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний workflow виявлення піддоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Повне brute-force виявлення піддоменів за допомогою автоматизованого Trickest workflow, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
{{#include ../../banners/hacktricks-training.md}}
