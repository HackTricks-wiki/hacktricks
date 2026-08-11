# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим саме ця компанія володіє.

Мета цього етапу — отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми будемо:<sup>[[1]](#references)</sup>

1. Знайти придбання головної компанії — це дасть нам компанії, що входять до scope.
2. Знайти ASN (якщо є) кожної компанії — це дасть нам діапазони IP, якими володіє кожна компанія.
3. Використати reverse whois lookups для пошуку інших записів (назв організацій, доменів тощо), пов'язаних із першим записом (це можна робити рекурсивно).
4. Використати інші techniques, як-от фільтри `org` і `ssl` у shodan, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку головної компанії у **Wikipedia** та пошукати **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви вже маєте знати всі компанії, що входять до scope. Тепер з'ясуймо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво з'ясувати, чи **компанії призначено ASN**, щоб знайти її **діапазони IP**. Варто виконати **vulnerability test** усіх **хостів** у межах **scope** і **пошукати домени** всередині цих IP.\
Ви можете **шукати** за **назвою компанії**, **IP** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). У будь-якому разі, ймовірно, вся** корисна інформація **(діапазони IP і Whois)** уже міститься в першому посиланні.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Крім того, enumeration [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** автоматично агрегує та підсумовує ASN наприкінці сканування.
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
Також ви можете запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **і залежно від того, що ви виявите, вам слід** переглянути відповідні розділи цієї книги, щоб дізнатися, як проводити pentest різних можливих запущених сервісів.\
**Також варто зазначити, що ви можете підготувати списки** стандартних імен користувачів **і** паролів **та спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних нижче методів можна також знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все слід знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, ви можете спробувати виконати **reverse DNS lookups** для цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використовувати DNS-сервер жертви або один із загальновідомих DNS-серверів (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Ви також можете скористатися онлайн-інструментом для отримання цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними будуть такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які дають змогу автоматизувати reverse lookup та enrichment.

### **Reverse Whois (цикл)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів тощо. Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконувати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші реєстри whois, де зустрічається та сама електронна адреса).\
Ви можете скористатися такими онлайн-інструментами:

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
Також можна виконувати автоматичний reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

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

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та субдомени нашої цілі, шукаючи такий самий hash іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Простіше кажучи, favihash дозволить нам знаходити домени, які мають такий самий хеш іконки favicon, як і наша ціль.

![Вивід favihash, використаний для пошуку доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ось як можна **обчислити хеш favicon** вебсайту (MMH3 над **байтами favicon, закодованими в base64**):
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
Ви також можете отримувати хеші favicon у великому масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім виконувати pivoting у Shodan/Censys.

Розглядайте fingerprinting favicon як підказки та перевіряйте їх за допомогою супутніх сигналів.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте хеш як індикатор, а не доказ**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: досліджуйте шляхи framework/build, manifest-файли, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URLs і HTML-теги `<link rel="icon">`.
- **Static assets можуть залишатися доступними за WAF/SSO/IdP-контролями**: запитуйте іконку безпосередньо та перевіряйте `ETag`, `Last-Modified`, redirects і cache headers.
- **Перевіряйте збіги за допомогою супутніх сигналів**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS-сертифіката, product components і exposed ports.
- **Групуйте за HTML/body hash**: узгоджений template посилює fingerprint; різні templates вказують на generic або shared icon.
- **Розглядайте хеш, що з’являється в різних unrelated signatures, ports і products, як потенційний honeypot або placeholder.**
- **Для неоднозначних targets порівнюйте реальну сторінку з неіснуючим path**, наприклад `/_favicon_probe_<8-hex>`; однакові hosting або parking responses можуть пояснювати спільну іконку.
- **Розпочинайте triage з Nuclei detection rules або public datasets**, які пов’язують favicon hashes із products і CPEs.
- **Пам’ятайте про IP-centric coverage gap**: surfaces за CDN, SNI-routed, anycast і domain-only можуть бути відсутні в Shodan-подібних datasets.

### **Copyright / Uniq string**

Шукайте всередині web pages **strings, які можуть бути спільними для різних web-сайтів однієї організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **google**, в інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Часто використовують cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
щоб одночасно оновити всі сертифікати на сервері. Кореляція часових міток сертифікатів або позицій у журналах certificate transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також безпосередньо використовуйте журнали **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Ви можете використовувати вебсайт на кшталт [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструмент на кшталт [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знаходити **домени та піддомени, які використовують однакову інформацію dmarc**.\
Інші корисні інструменти — [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Залишений A-запис може стати доступним, коли cloud provider повторно призначає IP-адресу. У відповідному дослідженні описано opportunistic workflow, який створює instance і зіставляє його адресу з даними passive DNS; перевіряйте сценарії takeover лише в межах дозволеної області тестування.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні discovery pivots щоразу, коли знаходите новий домен: кожен результат може виявити додаткові імена сертифікатів, зв’язки passive DNS, збіги favicon і ідентифікатори організації, які не були видимі з початкового seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, якій належить діапазон IP-адрес, ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені hosts на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете отримати доступ до **TLS certificate** головної вебсторінки, визначити **Organisation name**, а потім шукати цю назву всередині **TLS certificates** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — це інструмент, який шукає **домени, пов’язані** з основним доменом, і **піддомени** цих доменів; він справді чудовий.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які досі резолвляться або можуть бути захоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте можливість [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує певний домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) та повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від тих, які вже виявили під час discovery активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і певне [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти деякі прийоми для їхньої «атаки»**.\
_Зауважте, що іноді домен розміщений в IP-адресі, яка не контролюється клієнтом, тому він не входить до області тестування; будьте уважні._

## Піддомени

> Ми знаємо всі компанії в межах області тестування, усі активи кожної компанії та всі домени, пов’язані з цими компаніями.

Настав час знайти всі можливі піддомени кожного знайденого домену.

> [!TIP]
> Зауважте, що деякі інструменти й техніки пошуку доменів також можуть допомогти знаходити піддомени

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо він вразливий, про це слід повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовуються такі **інструменти** (для кращих результатів налаштуйте API-ключі):

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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують вебресурси в пошуках JS-файлів і видобувають із них піддомени.
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
- [**Пошук піддоменів Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку субдоменів та історії IP-адрес
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт безкоштовно надає **всі субдомени, пов’язані з bug-bounty програмами**. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовує цей проєкт: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

[Тут](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off) наведено **порівняння** багатьох із цих інструментів: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **субдомени**, виконуючи brute force DNS-серверів за допомогою можливих назв субдоменів.

Для цієї дії вам знадобляться деякі **wordlists поширених субдоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси надійних DNS-resolverів. Щоб створити список перевірених DNS-resolverів, ви можете завантажити resolverи з [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати їх. Або можна скористатися: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який ефективно виконував DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Як на мене, він використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка над `massdns`, написана мовою go, яка дає змогу перераховувати дійсні субдомени за допомогою активного bruteforce, а також розв’язувати субдомени з обробкою wildcard і зручною підтримкою введення-виведення.
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

Після знаходження субдоменів за допомогою відкритих джерел і brute-forcing можна згенерувати варіанти знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Генерує перестановки на основі доменів і субдоменів.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** На основі доменів і піддоменів генерує permutations. Якщо файл permutations не вказано, gotator використає власний файл.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати розв’язати їх (але краще використовувати попередні згадані інструменти).
- Ви можете отримати **wordlist** перестановок altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання перестановок, мутацій і змін субдоменів. Цей інструмент перебирає результати методом brute force (не підтримує dns wild card).
- Ви можете отримати wordlist перестановок dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні назви субдоменів** за вказаними шаблонами, щоб спробувати виявити більше субдоменів.

#### Розумна генерація перестановок

- [**regulator**](https://github.com/cramppet/regulator): Навчається regex-подібних шаблонів на основі виявлених субдоменів і генерує імена-кандидати для резолвінгу.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це subdomain brute-force fuzzer, поєднаний із надзвичайно простим, але ефективним DNS response-guided алгоритмом. Він використовує наданий набір вхідних даних, як-от адаптований wordlist або історичні DNS/TLS records, щоб точно синтезувати додаткові відповідні доменні імена та ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Workflow виявлення субдоменів**

Приклади workflow у Trickest поєднують OSINT, DNS brute force та етапи permutation для повторюваного переліку субдоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать субдоменам, можна спробувати **знайти інші субдомени з вебсайтами на цій IP-адресі**, шукаючи **в OSINT-джерелах** домени на IP-адресі або виконуючи **brute force назв доменів VHost на цій IP-адресі**.

#### OSINT

Ви можете знайти деякі **VHosts на IP-адресах за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що вебсервер може приховувати певний субдомен, можна спробувати виконати brute force:

Для VHost на основі імені змінюйте заголовок `Host` і використовуйте auto-calibration ffuf, щоб відфільтрувати стандартну відповідь.<sup>[[2]](#references)</sup>
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
> За допомогою цієї техніки ви навіть можете отримати доступ до внутрішніх/прихованих ендпойнтів.

### **CORS Brute Force**

Іноді ви можете знайти сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/піддомен. У таких сценаріях ви можете використати цю поведінку для **виявлення** нових **піддоменів**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force Buckets**

Під час пошуку **субдоменів** звертайте увагу, чи **вказує** якийсь із них на будь-який тип **bucket**, і в такому разі [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**перебрати можливі назви bucket і перевірити дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** домену, моніторячи журнали **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі випадки [**перехоплення субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на якийсь **S3 bucket**, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **субдомен з IP-адресою, що відрізняється** від уже знайдених під час виявлення активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти деякі прийоми для їхньої «атаки»**.\
_Зверніть увагу, що іноді субдомен розміщений всередині IP-адреси, яка не контролюється клієнтом, тому вона не входить до scope; будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти деякі діапазони IP-адрес, домени та субдомени**.\
Настав час **зібрати всі IP-адреси з цих діапазонів**, а також IP-адреси для **доменів/субдоменів (DNS-запити).**

За допомогою сервісів із наведених нижче **безкоштовних API** ви також можете знайти **попередні IP-адреси, які використовувалися доменами та субдоменами**. Ці IP-адреси все ще можуть належати клієнту (і можуть допомогти знайти [**обходи CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити домени, які вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Проскануйте всі IP-адреси, які не належать CDN** (оскільки, найімовірніше, ви не знайдете там нічого цікавого). У виявлених запущених сервісах вам, можливо, **вдасться знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **про сканування хостів.**

## Пошук web-серверів

> Ми знайшли всі компанії та їхні активи й знаємо діапазони IP-адрес, домени та субдомени в межах scope. Настав час шукати web-сервери.

На попередніх етапах ви, ймовірно, уже виконали певну **розвідку знайдених IP-адрес і доменів**, тому, можливо, **вже виявили всі доступні web-сервери**. Однак якщо цього не сталося, тепер ми розглянемо деякі **швидкі прийоми для пошуку web-серверів** у межах scope.

Зверніть увагу, що цей процес буде **орієнтований на виявлення web-застосунків**, тому також слід виконати **сканування вразливостей** і **сканування портів** (**якщо це дозволено** умовами scope).

[**Тут наведено швидкий метод**](../pentesting-network/index.html#http-port-discovery) виявлення **відкритих портів**, пов’язаних із **web-серверами**, за допомогою [**masscan**].\
Ще одним зручним інструментом для пошуку web-серверів є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і інструмент спробує підключитися до портів 80 (http) і 443 (https). Додатково можна вказати інші порти для перевірки:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скріншоти**

Тепер, коли ви виявили **всі вебсервери**, присутні в межах scope (серед **IP-адрес** компанії, а також усіх **доменів** і **піддоменів**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі створення скріншотів усіх них. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб обробити всі **скріншоти** й визначити, **що, ймовірно, містить вразливості**, а що — ні.

## Публічні Cloud-активи

Щоб знайти потенційні cloud-активи, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto-компанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід згенерувати **перестановки** (докладніше див. [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

З отриманими wordlists можна використовувати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud-активів слід шукати **не лише buckets в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете такі речі, як **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ** і спробувати з’ясувати, що вони вам пропонують і чи можна ними зловживати.

## Emails

Маючи **домени** та **піддомени** в межах scope, ви фактично маєте все, що **потрібно для початку пошуку emails**. Ось **APIs** та **інструменти**, які найкраще працювали для мене під час пошуку emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з APIs
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Emails стануть у пригоді пізніше для **brute-force веблогінів і auth-сервісів** (наприклад, SSH). Вони також потрібні для **phishings**. Крім того, ці APIs нададуть ще більше **інформації про людину**, яка стоїть за email, що корисно для phishing-кампанії.

## Credential Leaks

Маючи **домени,** **піддомени** та **emails**, можна почати пошук credentials, які раніше були leaked і належали цим emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials, це буде дуже легкою перемогою.

## Secrets Leaks

Credential leaks пов’язані зі зломами компаній, під час яких **чутлива інформація була leaked і продана**. Однак компанії можуть постраждати й від **інших leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials та APIs можуть бути leaked у **публічних репозиторіях** **компанії** або **користувачів**, які працюють у цій github-компанії.\
Можна використати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **організації** та її **розробників**, а також автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** проти всього **тексту**, що міститься в **URL, переданих** йому, оскільки іноді **вебсторінки також містять secrets**.

#### Github Dorks

Перегляньте [сторінку GitHub dorks і leaks](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Pastes Leaks

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайті**. Він може містити або не містити **чутливу інформацію**, але шукати її дуже цікаво.\
Можна використати tool [**Pastos**](https://github.com/carlospolop/Pastos) для одночасного пошуку на понад 80 paste-сайтах.

### Google Dorks

Старі, але ефективні google dorks завжди корисні для пошуку **відкритої інформації, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тому можна вибрати свої улюблені 10 або використати **tool, наприклад** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зверніть увагу, що tools, які намагаються виконати всю базу даних через звичайний браузер Google, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials або API-токени, це буде дуже легкою перемогою.

## Вразливості публічного коду

Якщо ви виявили, що компанія має **open-source код**, його можна **проаналізувати** та пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **tools**; див. список [інструментів для source-code review](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також існують безкоштовні сервіси, які дозволяють **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься всередині **вебзастосунків**, тому на цьому етапі я хочу розповісти про **методологію тестування вебзастосунків**; [**цю інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не слід очікувати, що вони знайдуть дуже чутливі вразливості, вони зручні для інтеграції у **workflows, щоб отримати початкову інформацію про web.**

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше розглянемо додаткові tricks).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **активи**, що належать компаніям (і виконали vuln scan, якщо це входить у scope)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **піддомени** доменів (чи можливий subdomain takeover?)
5. Знайшли всі **IP-адреси** (як **з CDN**, так і **без CDN**) у межах scope.
6. Знайшли всі **вебсервери** та зробили їхні **скріншоти** (чи є щось дивне, що варте глибшого аналізу?)
7. Знайшли всі **потенційні публічні cloud-активи**, що належать компанії.
8. **Emails**, **credential leaks** і **secret leaks**, які могли б дуже легко забезпечити вам **велику перемогу**.
9. **Виконали Pentesting усіх знайдених web**

## **Повністю автоматизовані Recon Tools**

Існує багато tools, які виконують частину запропонованих дій щодо заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи застарілий і не оновлюється

## References

- [1] [Jason Haddix – Методологія bug hunter'а v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про Favicons: від іконок браузера до розвідки attack surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою time-correlation attack на Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: виявлення (та імітація) дорогої кампанії subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: унікальний метод enumeration піддоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний workflow виявлення піддоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Повне brute-force виявлення піддоменів за допомогою автоматизованого Trickest workflow, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – скріншот виводу favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
