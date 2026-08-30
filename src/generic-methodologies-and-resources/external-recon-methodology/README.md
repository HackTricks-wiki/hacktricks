# Методологія External Recon

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим саме володіє ця компанія.

Мета цього етапу полягає в тому, щоб отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми будемо:<sup>[[1]](#references)</sup>

1. Знайти придбання головної компанії, що дасть нам компанії, які входять до scope.
2. Знайти ASN (якщо є) кожної компанії, що дасть нам IP-діапазони, якими володіє кожна компанія.
3. Використати reverse whois lookups для пошуку інших записів (назв організацій, доменів тощо), пов'язаних із першим записом (це можна виконувати рекурсивно).
4. Використати інші техніки, як-от фільтри `org` і `ssl` у shodan, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку **Wikipedia** головної компанії та пошукати **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви повинні знати всі компанії, які входять до scope. Давайте з'ясуємо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво перевірити, чи **компанії призначено ASN**, щоб знайти її **IP-діапазони.** Буде корисно виконати **тест на вразливості** проти всіх **хостів** у межах **scope** і **пошукати домени** серед цих IP-адрес.\
Ви можете **шукати** за **назвою** компанії, **IP** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(IP-діапазони та Whois)** уже міститься в першому посиланні.
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
Ви також можете знайти діапазони IP-адрес організації за допомогою [http://asnlookup.com/](http://asnlookup.com) (сервіс має безкоштовний API).\
Ви можете знайти IP-адресу та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам це дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також ви можете запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або використовувати такі сервіси, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **і залежно від того, що ви виявите, варто** переглянути цю книгу, щоб дізнатися, як проводити pentest різних можливих запущених сервісів.\
**Також варто згадати, що ви можете підготувати** списки стандартних імен користувачів **та** паролів **і спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи, тож настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою наведених нижче методів ви також можете знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все, слід знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, можна спробувати виконати **reverse dns lookups** для цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати dns-сервер жертви або загальновідомий dns-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Щоб це працювало, адміністратор має вручну увімкнути PTR.\
Для отримання цієї інформації також можна скористатися онлайн-інструментом: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними будуть такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які автоматизують reverse lookups і enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів тощо. Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші реєстраційні записи whois, де зустрічається та сама електронна адреса).\
Можна скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовний** (Web і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовний**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовний**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовний**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** Web, API — платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платний
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платний (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платний
- [https://securitytrails.com/](https://securitytrails.com/) - Платний (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платний (API)

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен API key whoxy).\
Також можна виконувати автоматичне виявлення reverse whois за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

### **Трекери**

Якщо ви знаходите **той самий ID того самого трекера** на 2 різних сторінках, можна припустити, що **обома сторінками** **керує та сама команда**.\
Наприклад, якщо ви бачите однаковий **Google Analytics ID** або однаковий **Adsense ID** на кількох сторінках.

Існують сторінки та інструменти, які дають змогу виконувати пошук за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними analytics/trackers)
- [**StackScan**](https://www.stackscan.com) - **Безкоштовний тариф** (Web і API). Дає змогу виконувати pivot за будь-яким asset, що обслуговується, а не лише за ID трекерів: шляхом до script, назвою self-hosted bundle або хостом, з якого завантажується asset, повертаючи кожен сайт, що його містить

API повертає stack для одного домену, що корисно для підтвердження того, що candidate asset належить до тієї самої estate:
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
Повертає кожну виявлену технологію разом із її категорією. Asset pivoting наразі працює лише для web, а API охоплює пошук за окремим доменом.

### **Favicon**

Чи знали ви, що можемо знаходити пов’язані домени та субдомени нашої цілі, шукаючи той самий hash іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Результати Favihash, використані для виявлення доменів із спільним хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу виявляти домени, які мають такий самий хеш іконки favicon, що й наша ціль.

![Вивід favihash, використаний для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знаходити інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>
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

Розглядайте favicon fingerprints як підказки та перевіряйте їх за допомогою навколишніх сигналів.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте hash як індикатор, а не доказ**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: аналізуйте шляхи framework/build, manifest-файли, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URLs і HTML-теги `<link rel="icon">`.
- **Static assets можуть залишатися доступними за WAF/SSO/IdP controls**: запитуйте іконку безпосередньо та аналізуйте `ETag`, `Last-Modified`, redirects і cache headers.
- **Перевіряйте збіги за допомогою навколишніх сигналів**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS certificate, product components і exposed ports.
- **Групуйте за HTML/body hash**: узгоджений template посилює fingerprint; різні templates можуть вказувати на generic або shared icon.
- **Розглядайте hash, який з’являється в unrelated signatures, ports і products, як потенційний honeypot або placeholder.**
- **Для неоднозначних targets порівнюйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові hosting або parking responses можуть пояснювати shared icon.
- **Починайте triage з Nuclei detection rules або public datasets**, які зіставляють favicon hashes із products і CPEs.
- **Пам’ятайте про IP-centric coverage gap**: CDN-fronted, SNI-routed, anycast і domain-only surfaces можуть бути відсутні в Shodan-like datasets.

### **Copyright / Uniq string**

Шукайте всередині web pages **strings, які можуть бути спільними для різних web-сайтів тієї самої організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **google**, інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Часто використовується cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб одночасно оновити всі сертифікати на сервері. Кореляція часових міток сертифікатів або позицій у журналах certificate transparency може виявити пов'язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Ви можете використати вебсайт на кшталт [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструмент на кшталт [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та піддомени, які спільно використовують однакову інформацію dmarc**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Залишений A-запис може стати доступним, коли cloud-провайдер повторно призначає IP-адресу. У згаданому дослідженні продемонстровано opportunistic workflow, який створює instance і зіставляє його адресу з даними passive DNS; тестуйте сценарії takeover лише в межах авторизованого scope.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні discovery pivots щоразу, коли знаходите новий домен: кожен результат може виявити додаткові імена сертифікатів, зв'язки passive-DNS, збіги favicon та ідентифікатори організації, які не були видимі з початкового seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, яка володіє IP-простором, ви можете виконати пошук у shodan за цими даними, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете отримати доступ до **TLS-сертифіката** головної вебсторінки, дізнатися **назву Organisation**, а потім шукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — це інструмент, який шукає **домени, пов'язані** з основним доменом, і **піддомени** цих доменів; досить вражає.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які все ще резолвляться або можуть бути захоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте можливість [захоплення домену](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від уже виявлених під час discovery assets, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, ви можете знайти в **цій книзі деякі прийоми для їхньої "атаки"**.\
_Зверніть увагу, що іноді домен розміщено всередині IP-адреси, яка не контролюється клієнтом, тому вона не входить до scope; будьте обережні._

## Піддомени

> Ми знаємо всі компанії в scope, усі assets кожної компанії та всі домени, пов'язані з цими компаніями.

Час знайти всі можливі піддомени кожного знайденого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти й техніки пошуку доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо він вразливий, про це слід повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — виконати пошук у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте API-ключі):

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
Є **інші цікаві інструменти/API**, які, навіть якщо безпосередньо не спеціалізуються на пошуку субдоменів, можуть бути корисними для пошуку субдоменів, наприклад:

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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого вказаного домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб-простір у пошуках JS-файлів і видобувають із них субдомени.
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
- [**Пошук субдоменів Censys**](https://github.com/christophetd/censys-subdomain-finder)
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

Цей проєкт **безкоштовно** надає всі subdomains, пов’язані з bug-bounty programs. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовується цим проєктом: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Ви можете знайти **порівняння** багатьох із цих tools тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **subdomains**, виконуючи brute-force DNS-серверів із використанням можливих імен subdomains.

Для цієї дії вам знадобляться деякі **wordlists поширених subdomains, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси надійних DNS resolvers. Щоб створити список перевірених DNS resolvers, ви можете завантажити resolvers із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати їх. Або скористатися: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші tools для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший tool, який ефективно виконував DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, наскільки я розумію, використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це wrapper над `massdns`, написаний на Go, який дає змогу перелічувати дійсні субдомени за допомогою активного bruteforce, а також визначати субдомени з обробкою wildcard і зручною підтримкою введення-виведення.
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

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Генерує перестановки на основі доменів і субдоменів.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** На основі доменів і субдоменів генерує перестановки. Якщо файл перестановок не вказано, gotator використовуватиме власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації permutations піддоменів, він також може спробувати їх розв’язати (але краще використовувати попередні закоментовані інструменти).
- Ви можете отримати **wordlist** permutations altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations та alteration піддоменів. Цей інструмент виконає brute force результату (він не підтримує DNS wildcard).
- Ви можете отримати wordlist permutations для dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні назви субдоменів** за вказаними шаблонами, щоб спробувати виявити більше субдоменів.

#### Розумне генерування перестановок

- [**regulator**](https://github.com/cramppet/regulator): Вивчає шаблони, подібні до regex, із виявлених субдоменів і генерує кандидатні назви для резолюції.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzing-інструмент для brute-force пошуку субдоменів, доповнений надзвичайно простим, але ефективним алгоритмом, керованим DNS-відповідями. Він використовує наданий набір вхідних даних, наприклад спеціально підібраний wordlist або історичні DNS/TLS-записи, щоб точно генерувати більше відповідних доменних імен і розширювати їх у циклі на основі інформації, зібраної під час DNS-сканування.
```
echo www | subzuf facebook.com
```
### **Процес виявлення субдоменів**

Приклади workflow у Trickest поєднують OSINT, DNS brute force та етапи пермутацій для повторюваного переліку субдоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать субдоменам, можна спробувати **знайти інші субдомени з вебсайтами на цій IP-адресі**, шукаючи в **джерелах OSINT** домени за IP-адресою або виконуючи **brute force доменних імен VHost на цій IP-адресі**.

#### OSINT

Деякі **VHosts в IP-адресах можна знайти за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що вебсервер може приховувати певний субдомен, можна спробувати виконати його brute force:

Для vhost на основі імені виконуйте fuzz заголовка `Host` і використовуйте auto-calibration у ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>
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

Іноді ви виявлятимете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ указано дійсний домен/піддомен. У таких сценаріях можна скористатися цією поведінкою, щоб **виявити** нові **піддомени**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **субдоменів** звертайте увагу, чи **вказує** субдомен на будь-який тип **bucket**, і в такому разі [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**brute force можливих назв bucket і перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** домену, контролюючи логи **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі [**захоплення субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на певний **S3 bucket**, [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **субдомен з IP, який відрізняється** від уже знайдених під час discovery assets, вам слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і здійснити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти деякі прийоми для їхньої "атаки"**.\
_Зверніть увагу, що іноді субдомен розміщений на IP, який не контролюється клієнтом, тому він не входить до scope; будьте обережні._

## IPs

На початкових етапах ви могли **знайти деякі діапазони IP, домени та субдомени**.\
Час **зібрати всі IP з цих діапазонів**, а також IP для **доменів/субдоменів (DNS-запити).**

За допомогою сервісів із наведених нижче **безкоштовних API** ви також можете знайти **попередні IP, які використовувалися доменами та субдоменами**. Ці IP усе ще можуть належати клієнту (і можуть допомогти знайти [**обходи CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити домени, які вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Проскануйте порти всіх IP, які не належать CDN** (оскільки ви, найімовірніше, не знайдете там нічого цікавого). У виявлених запущених сервісах ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **про те, як сканувати хости.**

## Пошук web-серверів

> Ми знайшли всі компанії та їхні assets і знаємо діапазони IP, домени та субдомени в межах scope. Час шукати web-сервери.

На попередніх етапах ви, імовірно, вже виконали певний **recon IP і виявлених доменів**, тому, можливо, **вже знайшли всі можливі web-сервери**. Однак якщо ні, зараз ми розглянемо деякі **швидкі прийоми пошуку web-серверів** у межах scope.

Зверніть увагу, що це буде **орієнтовано на discovery web apps**, тому вам також слід виконати **сканування вразливостей** і **сканування портів** (**якщо це дозволено** scope).

**Швидкий метод** виявлення **відкритих портів**, пов’язаних із **web-серверами**, за допомогою [**masscan можна знайти тут**](../pentesting-network/index.html#http-port-discovery).\
Іншим зручним інструментом для пошуку web-серверів є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і інструмент спробує підключитися до портів 80 (http) і 443 (https). Додатково можна вказати інші порти для перевірки:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скріншоти**

Тепер, коли ви виявили **всі вебсервери**, присутні в межах scope (серед **IP-адрес** компанії, а також усіх **доменів** і **субдоменів**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі створення скріншотів усіх них. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб опрацювати всі **скріншоти** й визначити, **що, ймовірно, містить вразливості**, а що — ні.

## Публічні Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії можна використовувати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід створити **перестановки** (докладніше див. [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Отримані wordlists можна використовувати з такими tools, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте: під час пошуку Cloud Assets слід шукати **не лише buckets в AWS**.

### **Пошук вразливостей**

Якщо ви знайшли **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ** і спробувати з’ясувати, що вони можуть вам запропонувати та чи можна ними зловживати.

## Emails

Маючи **домени** та **субдомени** в межах scope, ви фактично маєте все, що **потрібно для початку пошуку emails**. Ось **APIs** і **tools**, які найкраще працювали для мене під час пошуку emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з APIs
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Emails стануть у пригоді пізніше для **brute-force web logins і auth services** (наприклад, SSH). Вони також потрібні для **phishings**. Крім того, ці APIs нададуть ще більше **інформації про людину**, яка стоїть за email, що корисно для phishing-кампанії.

## Credential Leaks

Маючи **домени,** **субдомени** та **emails**, можна почати шукати credentials, що раніше були leaked і належали цим emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайшли **дійсні leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані зі зламами компаній, під час яких **чутлива інформація була leaked і продана**. Однак компанії можуть постраждати від **інших leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials і APIs можуть бути leaked у **публічних repositories** **компанії** або **користувачів**, які працюють у цій github-компанії.\
Можна використати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **public repos** **organization** та її **developers**, а також автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** проти всього **тексту**, що міститься в **URLs, переданих** йому, оскільки іноді **вебсторінки також містять secrets**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в organization.

### Pastes Leaks

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайті**. Він може містити або не містити **чутливу інформацію**, але шукати її безумовно варто.\
Можна використовувати tool [**Pastos**](https://github.com/carlospolop/Pastos) для одночасного пошуку більш ніж на 80 paste-сайтах.

### Google Dorks

Старі, але ефективні google dorks завжди корисні для пошуку **exposed інформації, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить **кілька тисяч** можливих запитів, які неможливо виконати вручну. Тому можна вибрати свої улюблені 10 або використати **tool, наприклад** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зверніть увагу: tools, які намагаються опрацювати всю базу даних через звичайний Google browser, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайшли **дійсні leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, його можна **проаналізувати** та пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **tools**; див. список [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також існують безкоштовні services, які дозволяють **сканувати public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься всередині **вебзастосунків**, тому на цьому етапі я хотів би розповісти про **методологію тестування вебзастосунків**; цю [**інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже чутливі вразливості, вони зручні для додавання у **workflows, щоб отримати початкову інформацію про web.**

## Підсумок

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше ми розглянемо додаткові tricks).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **assets**, що належать компаніям (і виконали vuln scan, якщо це входить у scope)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **субдомени** доменів (чи можливий subdomain takeover?)
5. Знайшли всі **IP-адреси** (з **CDNs** і **без них**) у межах scope.
6. Знайшли всі **вебсервери** та зробили їхні **скріншоти** (чи є щось дивне, що варто перевірити глибше?)
7. Знайшли всі **потенційні public cloud assets**, що належать компанії.
8. **Emails**, **credential leaks** і **secret leaks**, які можуть дуже легко забезпечити вам **велику перемогу**.
9. Виконали **Pentesting усіх знайдених web**

## **Full Recon Automatic Tools**

Існує кілька tools, які виконують частину запропонованих дій щодо заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — Трохи застарілий і не оновлюється

## References

- [1] [Jason Haddix – Методологія Bug Hunter's v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про Favicons: від іконок браузера до розвідки attack surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою Time-Correlation Attack на Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: виявлення (та емуляція) дорогої кампанії Subdomain Takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: унікальний метод Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний workflow Subdomain Discovery, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Повне Subdomain Brute Force Discovery за допомогою Automated Trickest Workflow, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – скріншот виводу favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
