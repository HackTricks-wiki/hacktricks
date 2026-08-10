# Методологія зовнішньої розвідки

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим саме ця компанія володіє.

Мета цього етапу — отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми будемо:

1. Знайти придбання головної компанії — це дасть нам компанії, що входять до scope.
2. Знайти ASN (якщо є) кожної компанії — це дасть нам діапазони IP, якими володіє кожна компанія.
3. Використати reverse whois lookups для пошуку інших записів (назв організацій, доменів...) пов'язаних із першою компанією (це можна робити рекурсивно).
4. Використати інші техніки, як-от фільтри shodan `org` і `ssl`, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** на "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку головної компанії у **Wikipedia** та пошукати **придбання**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) та базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви маєте знати всі компанії, що входять до scope. З'ясуймо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво з'ясувати, чи **компанії призначено ASN**, щоб знайти її **діапазони IP**. Буде корисно виконати **тест на вразливості** всіх **хостів** у межах **scope** і **пошукати домени** серед цих IP.\
Можна **шукати** за **назвою** компанії, **IP** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону компанії, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). У будь-якому разі, ймовірно, вся** корисна інформація **(діапазони IP і Whois)** уже міститься в першому посиланні.
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
Ви також можете знайти діапазони IP організації за допомогою [http://asnlookup.com/](http://asnlookup.com) (сервіс має безкоштовний API).\
Ви можете знайти IP та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тому, якщо вам це дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також ви можете запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або використовувати такі сервіси, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **і залежно від того, що ви знайдете, варто** переглянути цю книгу, щоб дізнатися, як проводити pentest різних можливих запущених сервісів.\
**Також варто згадати, що ви можете підготувати деякі** списки стандартних імен користувачів **та** паролів **і спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи, тож настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою наведених нижче запропонованих технік ви також можете знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все, вам слід знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP доменів, ви можете спробувати виконати **reverse dns lookups** для цих **IP, щоб знайти більше доменів у межах scope**. Спробуйте використовувати dns-сервер жертви або відомий dns-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Щоб це працювало, адміністратор має вручну увімкнути PTR.\
Ви також можете скористатися online-інструментом для отримання цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними є такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), щоб автоматизувати reverse lookups та enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше asset'ів, пов’язаних із компанією**, якщо виконувати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші реєстри whois, де зустрічається та сама електронна адреса).\
Ви можете скористатися такими online-інструментами:

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

Ви можете автоматизувати це завдання за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен API-ключ whoxy).\
Також можна виконувати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

### **Trackers**

Якщо ви знаходите **той самий ID того самого tracker'а** на 2 різних сторінках, можна припустити, що **обома сторінками** **керує одна й та сама команда**.\
Наприклад, якщо ви бачите однаковий **Google Analytics ID** або однаковий **Adsense ID** на кількох сторінках.

Існують сторінки та інструменти, які дають змогу виконувати пошук за цими tracker'ами та іншими даними:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними analytics/trackers)

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та субдомени нашої цілі, шукаючи той самий hash іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Простіше кажучи, favihash дасть змогу виявити домени, які мають такий самий hash favicon, як і наша ціль.

Використовуйте відомий hash favicon як pivot у Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої technology.<sup>[[5]](#references)</sup>
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
Ви також можете отримувати favicon hashes у масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім виконувати pivoting у Shodan/Censys.

Розглядайте favicon fingerprints як підказки та перевіряйте їх за допомогою додаткових сигналів.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте hash як індикатор, а не доказ**: MMH3 є компактним; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: досліджуйте шляхи framework/build, manifest-файли, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URLs і HTML-теги `<link rel="icon">`.
- **Статичні assets можуть залишатися доступними за WAF/SSO/IdP controls**: запитуйте іконку безпосередньо та перевіряйте `ETag`, `Last-Modified`, redirects і cache headers.
- **Перевіряйте збіги за додатковими сигналами**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS certificate, product components і exposed ports.
- **Групуйте за HTML/body hash**: узгоджений template посилює fingerprint; різні templates вказують на generic або shared icon.
- **Розглядайте hash, що з’являється в різних signatures, ports і products, як потенційний honeypot або placeholder.**
- **Для неоднозначних targets порівнюйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові hosting або parking responses можуть пояснити спільну іконку.
- **Починайте triage з Nuclei detection rules або public datasets**, які зіставляють favicon hashes із products і CPEs.
- **Пам’ятайте про IP-centric coverage gap**: поверхні за CDN, SNI-routed, anycast і domain-only можуть бути відсутні в datasets на кшталт Shodan.

### **Copyright / Унікальний рядок**

Шукайте всередині web pages **strings, які можуть бути спільними для різних webs в одній організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **google**, інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Поширеною є наявність cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
для одночасного поновлення всіх сертифікатів на сервері. Кореляція часових міток сертифікатів або позицій у журналах Certificate Transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також безпосередньо використовуйте журнали **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Ви можете скористатися вебсайтом на кшталт [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструментом на кшталт [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та піддомени, які спільно використовують однакову інформацію dmarc**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Покинутий A record може стати доступним, коли cloud provider повторно призначає IP-адресу. У наведеному дослідженні продемонстровано opportunistic workflow, який розгортає instance і зіставляє його адресу з даними passive DNS; сценарії takeover слід тестувати лише в межах авторизованого scope.<sup>[[7]](#references)</sup>

### **Інші способи**

**Shodan**

Оскільки вам уже відома назва організації, якій належить IP space, ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені hosts на наявність нових неочікуваних доменів у TLS certificate.

Ви можете отримати доступ до **TLS certificate** головної вебсторінки, визначити **Organisation name**, а потім шукати це ім’я всередині **TLS certificates** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)— це інструмент, який шукає **домени, пов’язані** з основним доменом, і його **піддомени**, що є надзвичайно корисним.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово допомагають знаходити **старі та забуті записи**, які досі резолвляться або можуть бути захоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте можливість [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує певний домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від уже виявлених під час asset discovery, слід виконати **basic vulnerability scan** (за допомогою Nessus або OpenVAS) і [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти деякі прийоми для їх «атаки»**.\
_Зверніть увагу, що іноді домен розміщений на IP-адресі, яка не контролюється клієнтом, тому він не входить до scope; будьте обережні._

## Піддомени

> Ми знаємо всі компанії в scope, усі assets кожної компанії та всі домени, пов’язані з компаніями.

Настав час знайти всі можливі піддомени кожного виявленого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти й техніки пошуку доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також слід перевірити **Zone Transfer** (якщо він вразливий, це потрібно повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовувані **інструменти** наведено нижче (для кращих результатів налаштуйте API keys):

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
Є **інші цікаві tools/APIs**, які, навіть якщо вони безпосередньо не спеціалізуються на пошуку subdomains, можуть бути корисними для пошуку subdomains, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) безкоштовний API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io) для отримання субдоменів
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**Безкоштовний API JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого вказаного домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **та** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках JS-файлів і витягують звідти субдомени.
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
- [**Censys пошук субдоменів**](https://github.com/christophetd/censys-subdomain-finder)
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

Цей проєкт безкоштовно надає **всі subdomains, пов'язані з bug-bounty programs**. Ви також можете отримати ці дані за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовується цим проєктом: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **порівняння** багатьох із цих tools тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуємо знайти нові **subdomains**, виконуючи brute-force DNS-серверів за допомогою можливих назв subdomains.

Для цієї дії вам знадобляться деякі **wordlists поширених subdomains, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси якісних DNS resolvers. Щоб створити список надійних DNS resolvers, ви можете завантажити resolvers із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для їх фільтрації. Або ви можете використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані tools для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший tool, який ефективно виконував DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, здається, використовує лише 1 резолвер
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це wrapper над `massdns`, написаний на go, який дає змогу перераховувати дійсні субдомени за допомогою active bruteforce, а також розв’язувати субдомени з обробкою wildcard і зручною підтримкою введення-виведення.
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

Після знаходження субдоменів за допомогою відкритих джерел і brute-forcing можна генерувати варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Створює перестановки на основі доменів і субдоменів.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): За наявності доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** На основі доменів і субдоменів генерує permutations. Якщо файл permutations не вказано, gotator використає власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок subdomains, він також може спробувати розв’язати їх (але краще використовувати попередні інструменти, позначені як commented).
- Ви можете отримати **wordlist** перестановок altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один tool для виконання permutations, mutations та alteration субдоменів. Цей tool здійснює brute force результату (він не підтримує DNS wildcard).
- Ви можете отримати wordlist для permutations dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена subdomains** за вказаними шаблонами, щоб спробувати виявити більше subdomains.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Навчається regex-подібних шаблонів на основі виявлених subdomains і генерує кандидатні імена для резолвингу.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це brute-force fuzzer субдоменів у поєднанні з надзвичайно простим, але ефективним алгоритмом, керованим DNS-відповідями. Він використовує наданий набір вхідних даних, як-от спеціально підібраний wordlist або історичні DNS/TLS записи, щоб точно синтезувати більше відповідних доменних імен і ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS-сканування.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Приклади workflow у Trickest поєднують OSINT, DNS brute force і етапи permutation для повторюваного перерахування піддоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать піддоменам, можна спробувати **знайти інші піддомени з вебсайтами на цій IP-адресі**, шукаючи в **OSINT-джерелах** домени за IP-адресою або виконуючи **brute force доменних імен VHost на цій IP-адресі**.

#### OSINT

Деякі **VHosts на IP-адресах можна знайти за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері може бути прихований піддомен, можна спробувати виконати його brute force:

Для VHost на основі імені виконуйте fuzzing заголовка `Host` і використовуйте auto-calibration у ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>
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

Іноді ви можете знайти сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний domain/subdomain. У таких сценаріях ви можете зловживати цією поведінкою, щоб **виявити** нові **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи **pointing** він на будь-який тип **bucket**, і в такому разі [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**brute force можливих назв bucket і перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **monitor**, чи створюються **new subdomains** домену, відстежуючи журнали **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук vulnerabilities**

Перевірте можливі випадки [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** pointing на певний **S3 bucket**, [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **subdomain з IP, відмінним** від уже виявлених під час assets discovery, слід виконати **basic vulnerability scan** (за допомогою Nessus або OpenVAS) і виконати [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених services, у **цій книзі можна знайти деякі tricks для їх "атаки"**.\
_Зверніть увагу, що іноді subdomain розміщений на IP, який не контролюється клієнтом, тому він не входить до scope; будьте обережні._

## IPs

На початкових етапах ви могли **знайти певні IP ranges, domains і subdomains**.\
Настав час **зібрати всі IP з цих ranges**, а також IP для **domains/subdomains (DNS queries).**

Використовуючи services із наведених нижче **free apis**, ви також можете знайти **попередні IP, які використовувалися domains і subdomains**. Ці IP усе ще можуть належати клієнту (і можуть дозволити вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити domains, які вказують на певну IP-адресу, за допомогою tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук vulnerabilities**

**Виконайте port scan усіх IP, які не належать CDNs** (оскільки, найімовірніше, ви не знайдете там нічого цікавого). У виявлених запущених services ви можете **знайти vulnerabilities**.

**Знайдіть** [**guide**](../pentesting-network/index.html) **про те, як сканувати hosts.**

## Пошук web servers

> Ми знайшли всі компанії та їхні assets і знаємо IP ranges, domains і subdomains у межах scope. Настав час шукати web servers.

На попередніх етапах ви, ймовірно, вже виконали певну **recon для виявлених IP і domains**, тому, можливо, **вже знайшли всі можливі web servers**. Однак якщо цього не сталося, зараз ми розглянемо кілька **швидких tricks для пошуку web servers** у межах scope.

Зверніть увагу, що цей процес буде **орієнтований на web apps discovery**, тому також слід **виконати vulnerability** та **port scanning** (**якщо це дозволено** scope).

**Швидкий метод** виявлення **ports open**, пов’язаних із **web** servers, за допомогою [**masscan** можна знайти тут](../pentesting-network/index.html#http-port-discovery).\
Іншими зручними tools для пошуку web servers є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список domains, і tool спробує підключитися до port 80 (http) і 443 (https). Додатково можна вказати інші ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скриншоти**

Тепер, коли ви виявили **всі вебсервери**, наявні в межах scope (серед **IP-адрес** компанії, а також усіх **доменів** і **субдоменів**), ви, імовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо просто зі створення скриншотів усіх них. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **скриншотів**, щоб визначити, **що, ймовірно, містить вразливості**, а що — ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії можна використовувати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід створити **перестановки** (докладніше див. у розділі [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Для отриманих wordlists можна використовувати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud Assets слід шукати **не лише buckets в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете такі речі, як **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ** і спробувати перевірити, що вони можуть вам запропонувати та чи можна ними зловживати.

## Emails

Маючи **домени** та **субдомени** в межах scope, ви фактично маєте все, що **потрібно для початку пошуку emails**. Ось **APIs** та **інструменти**, які найкраще працювали для мене під час пошуку emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з APIs
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Emails стануть у пригоді пізніше для **brute-force веблогінів і auth-сервісів** (наприклад, SSH). Також вони потрібні для **phishings**. Крім того, ці APIs нададуть ще більше **інформації про особу**, яка стоїть за email, що корисно для phishing-кампанії.

## Credential Leaks

Маючи **домени,** **субдомени** та **emails**, можна почати пошук credentials, які раніше були leaked і належали цим emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані зі зломами компаній, під час яких **чутлива інформація була leaked і продана**. Однак компанії можуть постраждати через **інші leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials та APIs можуть бути leaked у **публічних репозиторіях** **компанії** або **користувачів**, які працюють у цій github-компанії.\
Можна використовувати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **organization** та її **developers**, а також автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** проти всього **тексту**, наданого йому через **передані URLs**, оскільки іноді **вебсторінки також містять secrets**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks page](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в organization.

### Pastes Leaks

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайті**. Він може містити або не містити **чутливу інформацію**, але пошук таких даних є дуже цікавим.\
Можна використовувати tool [**Pastos**](https://github.com/carlospolop/Pastos), щоб одночасно шукати більш ніж на 80 paste-сайтах.

### Google Dorks

Старі, але ефективні Google dorks завжди корисні для пошуку **відкритої інформації, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тому можна вибрати свої улюблені 10 або використати **tool, наприклад** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зверніть увагу, що tools, які намагаються використовувати всю базу даних через звичайний Google browser, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, його можна **проаналізувати** та пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **tools**; дивіться список [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також існують безкоштовні сервіси, які дають змогу **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься всередині **вебзастосунків**, тому на цьому етапі я хотів би розповісти про **методологію тестування вебзастосунків**; [**цю інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже чутливі вразливості, вони корисні для додавання до **workflows, щоб отримати певну початкову інформацію про web.**

## Recapitulation

> Вітаємо! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше ми розглянемо додаткові tricks).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **assets**, що належать компаніям (і виконали певне vuln scan, якщо це входить до scope)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **субдомени** доменів (чи можливий subdomain takeover?)
5. Знайшли всі **IP-адреси** (з **CDNs** і **без CDNs**) у межах scope.
6. Знайшли всі **вебсервери** та зробили їхні **скриншоти** (чи є щось дивне, що варте глибшого аналізу?)
7. Знайшли всі **потенційні public cloud assets**, що належать компанії.
8. **Emails**, **credential leaks** і **secret leaks**, які можуть дуже легко принести вам **велику перемогу**.
9. **Виконали Pentesting усіх знайдених web**

## **Full Recon Automatic Tools**

Існує кілька tools, які виконують частину запропонованих дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Дещо застарілий і не оновлюється

## References

- [1] [Jason Haddix – Методологія Bug Hunter's v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про Favicons: від іконок браузера до аналізу attack surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico для BugBounties, OSINT та іншого](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою атаки часової кореляції на Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: виявлення (та емуляція) дорогої кампанії з subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: унікальний метод enumeration субдоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний workflow виявлення субдоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Повне brute-force-виявлення субдоменів за допомогою автоматизованого Trickest workflow, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
{{#include ../../banners/hacktricks-training.md}}
