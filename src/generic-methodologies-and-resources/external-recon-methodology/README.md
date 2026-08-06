# Методологія External Recon

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим саме володіє ця компанія.

Мета цього етапу полягає в тому, щоб отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми:

1. Знайдемо придбання головної компанії — це дасть нам компанії, що входять до scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам IP-діапазони, якими володіє кожна компанія.
3. Використаємо reverse whois lookups для пошуку інших записів (назви організацій, домени...) пов'язаних із першою компанією (це можна робити рекурсивно).
4. Використаємо інші техніки, наприклад фільтри `org` і `ssl` у shodan, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку **Wikipedia** головної компанії та пошукати **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви вже повинні знати всі компанії, що входять до scope. Давайте з'ясуємо, як знайти їхні активи.

### **ASNs**

Номер автономної системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво перевірити, чи **компанії призначено ASN**, щоб знайти її **IP-діапазони.** Також варто виконати **тест на вразливості** проти всіх **хостів** у **scope** і **пошукати домени** серед цих IP-адрес.\
Ви можете **шукати** за **назвою** компанії, **IP** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону компанії, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). У будь-якому разі, ймовірно, вся** корисна інформація **(IP-діапазони та Whois)** уже міститься в першому посиланні.
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
Також ви можете виконати [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або використати такі сервіси, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **і залежно від того, що ви знайдете, вам слід** переглянути цю книгу, щоб дізнатися, як проводити pentest різних можливих запущених сервісів.\
**Також варто зазначити, що ви можете підготувати** списки **стандартних імен користувачів** та **паролів** і спробувати **брутфорсити** сервіси за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних нижче методів ви також можете знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все, вам слід знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP доменів, ви можете спробувати виконати **reverse DNS lookups** для цих **IP, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або загальновідомий DNS-сервер (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Для того щоб це працювало, адміністратор має вручну увімкнути PTR.\
Ви також можете скористатися online-інструментом для отримання цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними будуть такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), щоб автоматизувати reverse lookups і збагачення даних.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші whois-реєстри, де зустрічається та сама електронна адреса).\
Ви можете скористатися такими online-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (Web і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовна** Web-версія, API платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Ви можете автоматизувати це завдання за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен API key від whoxy).\
Також можна виконати автоматичне reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

### **Трекери**

Якщо ви знаходите **однаковий ID одного й того самого трекера** на 2 різних сторінках, можна припустити, що **обома сторінками** **керує одна й та сама команда**.\
Наприклад, якщо ви бачите однаковий **Google Analytics ID** або однаковий **Adsense ID** на кількох сторінках.

Існують сторінки та інструменти, які дають змогу виконувати пошук за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними analytics/trackers)

### **Favicon**

Чи знали ви, що можна знайти пов’язані домени та субдомени нашої цілі, шукаючи однаковий hash іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дозволяє нам знаходити домени, які мають такий самий favicon icon hash, як і наша ціль.

Крім того, ви також можете шукати технології за допомогою favicon hash, як пояснюється в [**цьому дописі в блозі**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо ви знаєте **hash favicon уразливої версії web-технології**, ви можете перевірити це в shodan і **знайти більше уразливих місць**:
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
Також можна отримувати favicon hashes у масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім виконувати pivot у Shodan/Censys.

Корисні речі, про які варто пам’ятати під час використання favicon fingerprints:<sup>[[3]](#references)[[4]](#references)</sup>

- **Сприймайте hash як індикатор, а не доказ**: MMH3 є компактним, і можливі колізії; оператори також можуть замінити favicons або навмисно повторно використовувати оманливу іконку.
- **Перевіряйте не лише** `/favicon.ico`: багато продуктів надають іконки у framework/build paths або через `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, вбудовані `data:` URLs чи HTML-теги `<link rel="icon">`. Сам path може fingerprint продуктову family.
- **Static files часто доступні, навіть коли app недоступний**: засоби контролю WAF/SSO/IdP можуть захищати dynamic routes, але водночас залишати static icons доступними. Завжди запитуйте favicon безпосередньо та перевіряйте `ETag`, `Last-Modified`, redirects і cache headers на наявність слабких підказок щодо version/build.
- **Валідуйте matches за допомогою супутніх сигналів**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS certificate, компоненти Shodan/Censys і exposed ports, перш ніж робити висновок, що favicon ідентифікує продукт.
- **Під час pivot у масштабі групуйте за HTML/body hash**: якщо більшість hosts, що мають спільний favicon, зводяться до одного page template, fingerprint є сильнішим; якщо той самий hash розподіляється між багатьма не пов’язаними templates, віддавайте перевагу "generic/shared/honeypot", а не назві продукту.
- **Honeypot heuristic**: якщо той самий favicon hash зустрічається в багатьох не пов’язаних HTML signatures, random ports і конфліктних продуктах, вважайте його ймовірним honeypot або generic placeholder, а не справжнім product fingerprint.
- **Використовуйте 404 probe для неоднозначних targets**: у browser отримайте реальну сторінку та неіснуючий path, наприклад `/_favicon_probe_<8-hex>`. Однакові hosting-provider/parking responses часто краще пояснюють спільні favicons, ніж справжній product overlap.
- **Створюйте початкові mappings із detection rules**: Nuclei templates і public favicon datasets можуть надати відомі mappings `favicon` ↔ `product` ↔ `CPE`, корисні для швидкого triage після розкриття CVE.
- **Застереження щодо coverage**: datasets у стилі Shodan є IP-centric. CDN-fronted, SNI-routed, anycast і domain-only surfaces можуть бути недооцінені, тому мала кількість hits **не** означає низьке поширення у реальному світі.

### **Copyright / Uniq string**

Шукайте всередині web pages **strings, які можуть бути спільними для різних web sites тієї самої організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **Google**, в інших **browsers** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Часто використовують cron job, наприклад
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
оновити всі сертифікати доменів на сервері. Це означає, що навіть якщо CA, який використовується для цього, не вказує час генерації у Validity time, можна **знайти домени, що належать тій самій компанії, у журналах certificate transparency**.\
Перегляньте цей [**writeup для отримання додаткової інформації**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація про Mail DMARC

Ви можете використати вебсайт, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструмент, такий як [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та піддомени, які використовують однакову інформацію dmarc**.\
Інші корисні інструменти — [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Вочевидь, поширеною є ситуація, коли люди призначають піддомени для IP-адрес, що належать cloud-провайдерам, а потім **втрачають цю IP-адресу, але забувають видалити DNS-запис**. Тому, просто **створивши VM** у cloud (наприклад, Digital Ocean), ви фактично **захопите деякі піддомени**.

[**Цей допис**](https://kmsec.uk/blog/passive-takeover/) описує випадок із цього приводу та пропонує скрипт, який **створює VM у DigitalOcean**, **отримує** **IPv4** нової машини та **шукає у Virustotal записи піддоменів**, що вказують на неї.

### **Інші способи**

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

**Shodan**

Оскільки вам уже відома назва організації, яка володіє діапазоном IP-адрес, ви можете шукати за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете отримати доступ до **TLS-сертифіката** головної вебсторінки, отримати **назву організації**, а потім шукати цю назву всередині **TLS-сертифікатів** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — це інструмент, який шукає **домени, пов’язані** з основним доменом, і **їхні піддомени**. Він надзвичайно корисний.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які все ще розпізнаються або можуть бути захоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте на наявність деяких випадків [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) та повідомте компанію.

Якщо ви знайдете **домен з IP-адресою, відмінною** від тих, які вже виявили під час пошуку активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти деякі способи їхньої «атаки»**.\
_Зверніть увагу, що іноді домен розміщений усередині IP-адреси, яка не контролюється клієнтом, тому він не входить до scope. Будьте обережні._

## Піддомени

> Ми знаємо всі компанії в scope, усі активи кожної компанії та всі домени, пов’язані з компаніями.

Настав час знайти всі можливі піддомени кожного знайденого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти й техніки пошуку доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо він можливий через вразливість, про це слід повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Нижче наведено найпоширеніші **інструменти** (для кращих результатів налаштуйте API-ключі):

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
Є **інші цікаві інструменти/API**, які, навіть якщо вони безпосередньо не спеціалізуються на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

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
- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого вказаного домену.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб, шукаючи JS-файли, і витягують із них субдомени.
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
- [**Censys пошук піддоменів**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку піддоменів та історії IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт безкоштовно надає всі піддомени, пов’язані з **bug-bounty programs**. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовується цим проєктом: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Порівняння багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **піддомени**, виконуючи brute-force DNS-серверів за допомогою можливих назв піддоменів.

Для цієї дії вам знадобляться деякі **wordlists поширених піддоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси надійних DNS-resolvers. Щоб створити список trusted DNS-resolvers, ви можете завантажити resolvers із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) та використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для їх фільтрації. Або ви можете використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найбільш рекомендовані інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент, який ефективно виконував DNS brute-force. Він дуже швидкий, однак схильний до false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Цей, наскільки я розумію, використовує лише 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це оболонка навколо `massdns`, написана на go, яка дає змогу перераховувати дійсні піддомени за допомогою активного bruteforce, а також розв’язувати піддомени з обробкою wildcard і зручною підтримкою введення-виведення.
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

Після знаходження субдоменів за допомогою відкритих джерел і brute-forcing можна створити варіації знайдених субдоменів, щоб спробувати знайти ще більше. Для цього корисні кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Створює перестановки на основі доменів і субдоменів.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** За вказаними доменами та піддоменами генерує перестановки. Якщо файл із перестановками не вказано, gotator використає власний файл.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати їх розв’язати (але краще використовувати попередні інструменти, зазначені в коментарях).
- Ви можете отримати **wordlist** перестановок altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations та alteration піддоменів. Цей інструмент виконає brute force результату (він не підтримує DNS wildcard).
- Wordlist для permutations dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена піддоменів** на основі вказаних шаблонів, щоб спробувати виявити більше піддоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Докладніше читайте в цьому [**дописі**](https://cramppet.github.io/regulator/index.html), але загалом він отримує **основні частини** з **виявлених піддоменів** і комбінує їх, щоб знайти більше піддоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzер для brute-force пошуку субдоменів, поєднаний із надзвичайно простим, але ефективним алгоритмом, керованим відповідями DNS. Він використовує наданий набір вхідних даних, як-от спеціально підготовлений wordlist або історичні записи DNS/TLS, щоб точно синтезувати більше відповідних доменних імен і ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS-сканування.
```
echo www | subzuf facebook.com
```
### **Процес виявлення субдоменів**

Перегляньте цей допис у блозі про те, як **автоматизувати виявлення субдоменів** домену за допомогою **Trickest workflows**, щоб не запускати вручну безліч інструментів на своєму комп'ютері:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать субдоменам, можна спробувати **знайти інші субдомени з вебсторінками на цій IP-адресі**, шукаючи в **OSINT-джерелах** домени на IP-адресі або виконуючи **brute force доменних імен VHost на цій IP-адресі**.

#### OSINT

Ви можете знайти деякі **VHosts на IP-адресах за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що вебсервер може приховувати певний субдомен, можна спробувати виконати brute force:

Коли **IP-адреса перенаправляє на hostname** (name-based vhosts), виконуйте fuzzing заголовка `Host` безпосередньо та дозвольте ffuf **auto-calibrate**, щоб виділити відповіді, які відрізняються від стандартного vhost:<sup>[[2]](#references)</sup>
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
> За допомогою цієї техніки ви навіть можете отримати доступ до внутрішніх/прихованих ендпоїнтів.

### **CORS Brute Force**

Іноді ви знаходитимете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/субдомен. У таких сценаріях ви можете скористатися цією поведінкою, щоб **виявити** нові **субдомени**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи **pointing** він на будь-який тип **bucket**, і в такому разі [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі ви вже знатимете всі домени в scope, спробуйте [**brute force можливих назв bucket і перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **моніторити**, чи створюються **нові subdomains** домену, відстежуючи логи **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук vulnerabilities**

Перевірте можливі [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** вказує на певний **S3 bucket**, [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайшли **subdomain з IP, відмінною** від уже знайдених під час assets discovery, слід виконати **базове vulnerability сканування** (за допомогою Nessus або OpenVAS) і певне [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених services, у **цій книзі можна знайти певні прийоми для їхньої "атаки"**.\
_Зверніть увагу, що іноді subdomain розміщений на IP, який не контролюється клієнтом, тому він не входить до scope — будьте обережні._

## IPs

На початкових етапах ви могли **знайти певні діапазони IP, домени та subdomains**.\
Час **зібрати всі IP з цих діапазонів**, а також **домени/subdomains (DNS queries).**

Використовуючи services із наведених нижче **free apis**, ви також можете знайти **попередні IP, які використовувалися доменами та subdomains**. Ці IP досі можуть належати клієнту (і можуть дозволити вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ви також можете перевірити домени, що вказують на певну IP-адресу, за допомогою tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук vulnerabilities**

**Проскануйте порти на всіх IP, які не належать CDN** (оскільки ви, найімовірніше, не знайдете там нічого цікавого). У виявлених запущених services ви можете **знайти vulnerabilities**.

**Знайдіть** [**guide**](../pentesting-network/index.html) **про сканування hosts.**

## Пошук web servers

> Ми знайшли всі компанії та їхні assets і знаємо діапазони IP, домени та subdomains у scope. Час шукати web servers.

На попередніх етапах ви, ймовірно, вже виконали певний **recon IP і виявлених доменів**, тому, можливо, **вже знайшли всі можливі web servers**. Однак якщо ні, зараз ми розглянемо кілька **швидких прийомів пошуку web servers** у scope.

Зверніть увагу, що це буде **орієнтовано на web apps discovery**, тому слід також **виконати vulnerability** і **сканування портів** (**якщо це дозволено** scope).

**Швидкий метод** виявлення **відкритих портів**, пов’язаних із **web** servers, за допомогою [**masscan** можна знайти тут](../pentesting-network/index.html#http-port-discovery).\
Ще одним зручним tool для пошуку web servers є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Ви просто передаєте список доменів, і tool спробує підключитися до портів 80 (http) і 443 (https). Додатково можна вказати інші порти для перевірки:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Скріншоти**

Тепер, коли ви виявили **всі web servers**, наявні в scope (серед **IPs** компанії, а також усіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо просто зі створення скріншотів усіх них. Лише **поглянувши** на **main page**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використовувати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб обробити всі **скріншоти** й визначити, **що, найімовірніше, містить вразливості**, а що — ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto company можна використовувати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід згенерувати **permutations** (додаткову інформацію див. у розділі [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Отримані wordlists можна використовувати з такими інструментами, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud Assets слід шукати **не лише buckets в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ**, перевірити, що вони пропонують і чи можна ними зловживати.

## Emails

Маючи **domains** і **subdomains** у scope, ви фактично маєте все, що **потрібно для початку пошуку emails**. Ось **APIs** та **інструменти**, які найкраще працювали для мене під час пошуку emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з APIs
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Emails знадобляться пізніше для **brute-force web logins і auth services** (наприклад, SSH). Також вони потрібні для **phishings**. Крім того, ці APIs нададуть ще більше **інформації про людину**, яка стоїть за email, що корисно для phishing campaign.

## Credential Leaks

Маючи **domains,** **subdomains** і **emails**, можна почати шукати credentials, що були leaked раніше та належать цим emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані зі зломами компаній, під час яких **чутлива інформація була leaked і продана**. Однак компанії можуть постраждати через **інші leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials і APIs можуть бути leaked у **public repositories** **компанії** або **користувачів**, які працюють у цій github company.\
Можна використовувати **інструмент** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **public repos** **organization** та її **developers**, а також автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** проти всього **тексту**, наданого через **URLs, передані** йому, оскільки іноді **web pages також містять secrets**.

#### Github Dorks

Також перевірте цю **сторінку** на наявність потенційних **github dorks**, які можна пошукати в organization, яку ви атакуєте:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді attackers або просто працівники **публікують вміст компанії на paste site**. Він може містити або не містити **чутливу інформацію**, але пошук таких даних є дуже цікавим.\
Можна використовувати інструмент [**Pastos**](https://github.com/carlospolop/Pastos), щоб одночасно шукати більш ніж на 80 paste sites.

### Google Dorks

Старі, але перевірені google dorks завжди корисні для пошуку **відкритої інформації, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо запускати вручну. Тому можна вибрати свої улюблені 10 або скористатися **інструментом, таким як** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб запустити їх усі**.

_Зверніть увагу, що інструменти, які намагаються виконати всю базу даних через звичайний Google browser, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **дійсні leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, його можна **проаналізувати** й пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **інструменти**:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Також існують безкоштовні сервіси, які дозволяють **сканувати public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься у **web applications**, тому на цьому етапі я хотів би розповісти про **методологію тестування web applications**, а [**цю інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже чутливі вразливості, вони зручні для додавання у **workflows, щоб отримати початкову інформацію про web.**

## Recapitulation

> Вітаємо! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше ми розглянемо додаткові tricks).

Отже, ви вже:

1. Знайшли всі **companies** у scope
2. Знайшли всі **assets**, що належать компаніям (і виконали vuln scan, якщо це входить у scope)
3. Знайшли всі **domains**, що належать компаніям
4. Знайшли всі **subdomains** цих domains (чи можливий subdomain takeover?)
5. Знайшли всі **IPs** (з **CDNs** і **не з CDNs**) у scope.
6. Знайшли всі **web servers** і зробили їхні **скріншоти** (чи є щось дивне, що варте глибшого аналізу?)
7. Знайшли всі **потенційні public cloud assets**, що належать компанії.
8. Знайшли **emails**, **credential leaks** і **secret leaks**, які можуть дуже легко забезпечити **значний результат**.
9. Виконали **pentesting усіх знайдених web sites**

## **Full Recon Automatic Tools**

Існує кілька інструментів, які виконують частину запропонованих дій проти заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи застарілий і не оновлюється

## References

- [1] Усі безкоштовні курси [**@Jhaddix**](https://twitter.com/Jhaddix), наприклад [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
