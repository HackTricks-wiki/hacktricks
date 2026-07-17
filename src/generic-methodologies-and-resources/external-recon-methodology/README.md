# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з'ясувати, чим насправді володіє ця компанія.

Мета цього етапу — отримати всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми будемо:

1. Знайдемо придбання головної компанії — це дасть нам компанії, що входять до scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам діапазони IP, якими володіє кожна компанія.
3. Використаємо reverse whois lookups для пошуку інших записів (назви організацій, домени...) пов'язаних із першою компанією (це можна робити рекурсивно).
4. Використаємо інші техніки, як-от фільтри shodan `org` і `ssl`, для пошуку інших активів (трюк із `ssl` можна виконувати рекурсивно).

### **Придбання**

Перш за все, нам потрібно дізнатися, **які інші компанії належать головній компанії**.\
Один із варіантів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** на "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший варіант — відвідати сторінку **Wikipedia** головної компанії та виконати пошук за словом **acquisitions**.\
Для публічних компаній перевірте **SEC/EDGAR filings**, сторінки **investor relations** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для глобальних корпоративних структур і дочірніх компаній спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) та базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Отже, на цьому етапі ви вже повинні знати всі компанії, що входять до scope. Давайте з'ясуємо, як знайти їхні активи.

### **ASN**

Автономний номер системи (**ASN**) — це **унікальний номер**, призначений **автономній системі** (AS) **Internet Assigned Numbers Authority (IANA)**.\
**AS** складається з **блоків** **IP-адрес**, які мають чітко визначену політику доступу до зовнішніх мереж і адмініструються однією організацією, але можуть складатися з кількох операторів.

Цікаво з'ясувати, чи **компанії призначено ASN**, щоб знайти її **діапазони IP.** Варто виконати **тестування вразливостей** усіх **хостів** усередині **scope** та **пошукати домени** серед цих IP.\
Ви можете виконувати **пошук** за **назвою** компанії, **IP** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). У будь-якому разі, ймовірно, вся** корисна інформація **(діапазони IP і Whois)** вже є в першому посиланні.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Також enumeration у [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** автоматично агрегує та підсумовує ASN наприкінці сканування.
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
Ви можете знайти IP-адресу та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам це дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також ви можете виконати [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або використовувати такі сервіси, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти **і, залежно від того, що ви знайдете, вам слід** переглянути цю книгу, щоб дізнатися, як проводити pentesting різних можливих запущених сервісів.\
**Також варто зазначити, що ви можете підготувати деякі** списки стандартних імен користувачів **і** паролів **та спробувати виконати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; настав час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних нижче методів ви також можете знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все слід знайти **основний домен**(и) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі IP-діапазони доменів, ви можете спробувати виконати **reverse DNS lookups** для цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або добре відомий DNS-сервер (1.1.1.1, 8.8.8.8).
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, адміністратор має вручну увімкнути PTR.\
Ви також можете скористатися онлайн-інструментом для отримання цієї інформації: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисними є такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які дають змогу автоматизувати reverse lookups і enrichment.

### **Reverse Whois (loop)**

У **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше assets, пов’язаних із компанією**, якщо виконувати **reverse whois lookups за будь-яким із цих полів** (наприклад, інші реєстри whois, де зустрічається та сама електронна адреса).\
Ви можете скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (Web та API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** web, API платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Ви можете автоматизувати це завдання за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен API key whoxy).\
Ви також можете виконати автоматичний reverse whois discovery за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

### **Trackers**

Якщо ви знаходите **той самий ID того самого tracker** на 2 різних сторінках, можна припустити, що **обидві сторінки** **керуються однією командою**.\
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
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу знаходити домени, які мають такий самий hash favicon, як і наша ціль.

Крім того, можна також шукати технології за допомогою hash favicon, як пояснюється в [**цьому дописі в блозі**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Це означає, що якщо вам відомий **hash favicon вразливої версії web-технології**, ви можете перевірити це в shodan і **знайти більше вразливих місць**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Ось як можна **обчислити хеш favicon** вебсайту (MMH3 для **кодованих у base64** байтів favicon):
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

Корисно пам’ятати під час використання fingerprinting favicon:

- **Сприймайте хеш як індикатор, а не доказ**: MMH3 компактний, і можливі колізії; оператори також можуть замінити favicon або навмисно повторно використовувати оманливу іконку.
- **Перевіряйте не лише** `/favicon.ico`: багато продуктів відкривають іконки у framework/build paths або через `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, вбудовані `data:` URLs чи HTML-теги `<link rel="icon">`. Сам шлях також може ідентифікувати сімейство продуктів.
- **Static files часто доступні, навіть коли app недоступний**: WAF/SSO/IdP controls можуть захищати dynamic routes, але водночас відкривати static icons. Завжди запитуйте favicon напряму та перевіряйте `ETag`, `Last-Modified`, redirects і cache headers на наявність слабких підказок щодо версії/build.
- **Валідуйте збіги за допомогою супутніх сигналів**: порівнюйте title, HTML/body hash, headers, subjects/SANs TLS-сертифікатів, компоненти Shodan/Censys і exposed ports, перш ніж робити висновок, що favicon ідентифікує продукт.
- **Під час pivoting у великому масштабі кластеризуйте за HTML/body hash**: якщо більшість hosts із таким favicon зводяться до одного page template, fingerprint є надійнішим; якщо той самий hash розподіляється між багатьма непов’язаними templates, надавайте перевагу позначці "generic/shared/honeypot", а не назві продукту.
- **Honeypot heuristic**: якщо той самий favicon hash з’являється в багатьох непов’язаних HTML signatures, random ports і conflicting products, вважайте його ймовірним honeypot або generic placeholder, а не справжнім product fingerprint.
- **Використовуйте 404 probe для неоднозначних targets**: у browser отримайте реальну сторінку та неіснуючий path, наприклад `/_favicon_probe_<8-hex>`. Однакові hosting-provider/parking responses часто краще пояснюють спільні favicons, ніж справжній збіг продуктів.
- **Створюйте початкові mappings із detection rules**: Nuclei templates і public favicon datasets можуть містити відомі mappings `favicon` ↔ `product` ↔ `CPE`, корисні для швидкого triage після розкриття CVE.
- **Coverage caveat**: datasets у стилі Shodan орієнтовані на IP. CDN-fronted, SNI-routed, anycast і domain-only surfaces можуть бути недооцінені, тому мала кількість hits **не означає** малого реального deployment.

### **Copyright / Uniq string**

Шукайте на web pages **strings, які можуть бути спільними для різних web-сайтів в одній організації**. **Copyright string** може бути хорошим прикладом. Потім шукайте цей string у **google**, в інших **browsers** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Часто використовують cron job на кшталт
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
оновити всі сертифікати доменів на сервері. Це означає, що навіть якщо CA, використаний для цього, не вказує час генерації у Validity time, можна **знайти домени, що належать тій самій компанії, у certificate transparency logs**.\
Перегляньте [**цей writeup для отримання додаткової інформації**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Також використовуйте **certificate transparency** logs безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація про Mail DMARC

Ви можете використати вебсайт, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або такий інструмент, як [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени та субдомени, які використовують однакову інформацію dmarc**.\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) та [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Очевидно, люди часто призначають субдомени IP-адресам, що належать cloud-провайдерам, а згодом **втрачають цю IP-адресу, але забувають видалити DNS-запис**. Тому, просто **створивши VM** у cloud (наприклад, Digital Ocean), ви фактично **перехопите деякі субдомени**.

[**У цьому дописі**](https://kmsec.uk/blog/passive-takeover/) описано історію про це та запропоновано скрипт, який **створює VM у DigitalOcean**, **отримує** **IPv4** нової машини та **шукає у Virustotal записи субдоменів**, що вказують на неї.

### **Інші способи**

**Зверніть увагу, що цю техніку можна використовувати для виявлення нових доменних імен щоразу, коли ви знаходите новий домен.**

**Shodan**

Як ви вже знаєте назву організації, якій належить IP-простір, можна виконати пошук за цими даними в shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете отримати **TLS-сертифікат** головної вебсторінки, визначити **назву організації**, а потім шукати цю назву всередині **TLS-сертифікатів** усіх вебсторінок, відомих **shodan**, за допомогою фільтра: `ssl:"Tesla Motors"`, або використати такий інструмент, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — це інструмент, який шукає **домени, пов'язані** з основним доменом, і його **субдомени**; він надзвичайно корисний.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які все ще розв'язуються або можуть бути перехоплені. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте можливість [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує певний домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від уже знайдених під час виявлення активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів у **цій книзі можна знайти деякі прийоми для їх "атаки"**.\
_Зверніть увагу, що іноді домен розміщений на IP-адресі, яка не контролюється клієнтом, тому він не входить до scope; будьте обережні._

## Субдомени

> Ми знаємо всі компанії, що входять до scope, усі активи кожної компанії та всі домени, пов'язані з цими компаніями.

Настав час знайти всі можливі субдомени кожного знайденого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти та техніки пошуку доменів також можуть допомогти знайти субдомени

### **DNS**

Спробуймо отримати **субдомени** із записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо він доступний через вразливість, це слід повідомити).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте API-ключі):

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
Є **інші цікаві tools/APIs**, які, навіть якщо безпосередньо не спеціалізуються на пошуку subdomains, можуть бути корисними для пошуку subdomains, зокрема:

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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують вебпростір у пошуках JS-файлів і видобувають із них субдомени.
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
- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку піддоменів та історії IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Цей проєкт безкоштовно надає всі піддомени, пов’язані з **bug-bounty програмами**. Ви також можете отримати доступ до цих даних за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або навіть отримати scope, який використовується цим проєктом: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off) містить **порівняння** багатьох із цих інструментів.

### **DNS Brute force**

Спробуймо знайти нові **піддомени**, виконуючи brute-force DNS-серверів із використанням можливих назв піддоменів.

Для цієї дії вам знадобляться деякі **wordlists поширених піддоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

А також IP-адреси надійних DNS-resolver’ів. Щоб створити список надійних DNS-resolver’ів, ви можете завантажити resolver’и з [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і використати [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) для їх фільтрації. Або можна використати: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

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
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це wrapper навколо `massdns`, написаний на Go, який дає змогу перелічувати дійсні субдомени за допомогою активного bruteforce, а також resolve субдомени з обробкою wildcard і зручною підтримкою input-output.
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

Після знаходження subdomains за допомогою відкритих джерел і brute-forcing можна генерувати варіації знайдених subdomains, щоб спробувати знайти ще більше. Для цього корисні кілька tools:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Генерує permutations на основі domains і subdomains.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): На основі доменів і субдоменів генерує перестановки.
- Ви можете отримати **wordlist** перестановок goaltdns [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Отримуючи домени та субдомени, генерує перестановки. Якщо файл із перестановками не вказано, gotator використає власний.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати їх резолвити (але краще використовувати згадані раніше інструменти).
- Ви можете отримати **wordlist** перестановок altdns [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Інший інструмент для виконання permutations, mutations та alteration субдоменів. Цей інструмент здійснює brute force результату (не підтримує DNS wildcard).
- Ви можете отримати wordlist для permutations dmut [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена субдоменів** за вказаними шаблонами, щоб спробувати виявити більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Докладніше читайте в цьому [**дописі**](https://cramppet.github.io/regulator/index.html), але загалом він отримує **основні частини** з **виявлених субдоменів** і комбінує їх, щоб знайти більше субдоменів.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це brute-force fuzzer субдоменів, поєднаний із надзвичайно простим, але ефективним DNS response-guided algorithm. Він використовує наданий набір вхідних даних, наприклад спеціально підібраний wordlist або історичні DNS/TLS-записи, щоб точно синтезувати більше відповідних domain names і ще більше розширювати їх у циклі на основі інформації, зібраної під час DNS scan.
```
echo www | subzuf facebook.com
```
### **Процес виявлення субдоменів**

Перегляньте цей допис у блозі, який я написав про те, як **автоматизувати виявлення субдоменів** домену за допомогою **Trickest workflows**, щоб мені не доводилося вручну запускати безліч інструментів на своєму комп’ютері:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, що містить **одну або кілька вебсторінок**, які належать субдоменам, можна спробувати **знайти інші субдомени з вебсайтами на цій IP-адресі**, шукаючи в **OSINT-джерелах** домени на IP-адресі або виконуючи **brute-force доменних імен VHost на цій IP-адресі**.

#### OSINT

Ви можете знайти деякі **VHosts на IP-адресах за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері може бути прихований субдомен, можна спробувати виконати brute force:

Коли **IP-адреса перенаправляє на hostname** (name-based vhosts), безпосередньо fuzz-те заголовок `Host` і дозвольте ffuf **автоматично калібруватися**, щоб виділити відповіді, які відрізняються від стандартного vhost:
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

Іноді трапляються сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ указано дійсний домен/субдомен. У таких випадках можна зловживати цією поведінкою, щоб **виявляти** нові **субдомени**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Під час пошуку **subdomains** звертайте увагу, чи не **pointing** вони на будь-який тип **bucket**, і в такому разі [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі вам будуть відомі всі домени в межах scope, спробуйте [**brute force можливих назв bucket і перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **monitor** створення **new subdomains** домену, відстежуючи журнали **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі випадки [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **subdomain** вказує на певний **S3 bucket**, [**перевірте permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **subdomain з IP, відмінною** від тих, які вже були знайдені під час discovery assets, слід виконати **basic vulnerability scan** (за допомогою Nessus або OpenVAS) і [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених services, у **цій книзі можна знайти деякі tricks для їх "атаки"**.\
_Зверніть увагу, що іноді subdomain розміщений на IP, який не контролюється клієнтом, тому він не входить до scope. Будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти деякі діапазони IP, домени та subdomains**.\
Час **зібрати всі IP-адреси з цих діапазонів**, а також для **доменів/subdomains (DNS queries).**

Використовуючи services із наведених нижче **free apis**, ви також можете знайти **попередні IP-адреси, які використовувалися доменами та subdomains**. Ці IP-адреси все ще можуть належати клієнту (і можуть дозволити вам знайти [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна перевірити домени, що вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Виконайте port scan усіх IP-адрес, які не належать CDN** (оскільки, найімовірніше, ви не знайдете там нічого цікавого). У виявлених запущених services вам, можливо, **вдасться знайти вразливості**.

**Знайдіть** [**guide**](../pentesting-network/index.html) **щодо сканування hosts.**

## Пошук web-серверів

> Ми знайшли всі компанії та їхні assets і знаємо діапазони IP, домени та subdomains у межах scope. Час шукати web-сервери.

На попередніх етапах ви, ймовірно, вже виконали певний **recon IP-адрес і виявлених доменів**, тому, можливо, **вже знайшли всі можливі web-сервери**. Однак якщо цього не сталося, зараз ми розглянемо кілька **швидких tricks для пошуку web-серверів** у межах scope.

Зверніть увагу, що це буде **орієнтовано на discovery web apps**, тому слід також **виконати vulnerability** та **port scanning** (**якщо це дозволено** scope).

[**Швидкий метод** виявлення **відкритих портів**, пов’язаних із **web-серверами**, за допомогою **masscan** можна знайти тут](../pentesting-network/index.html#http-port-discovery).\
Ще одним зручним інструментом для пошуку web-серверів є [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Ви лише передаєте список доменів, і він спробує підключитися до портів 80 (http) та 443 (https). Додатково можна вказати інші порти для перевірки:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Тепер, коли ви виявили **all the web servers** у межах scope (серед **IPs** компанії, а також усіх **domains** і **subdomains**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо просто зі створення screenshots для всіх них. Лише **поглянувши** на **main page**, можна знайти **дивні** endpoints, які більш **схильні** бути **вразливими**.

Для реалізації запропонованої ідеї можна використати [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна використати [**eyeballer**](https://github.com/BishopFox/eyeballer), щоб обробити всі **screenshots** і визначити, **що, ймовірно, містить vulnerabilities**, а що — ні.

## Public Cloud Assets

Щоб знайти потенційні cloud assets, що належать компанії, слід **почати зі списку ключових слів, які ідентифікують цю компанію**. Наприклад, для crypto company можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться wordlists із **поширеними словами, що використовуються в buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід згенерувати **permutations** (додаткову інформацію див. у розділі [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Отримані wordlists можна використати з такими tools, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud Assets слід **шукати не лише buckets в AWS**.

### **Looking for vulnerabilities**

Якщо ви знайдете **відкриті buckets або exposed cloud functions**, слід **отримати до них доступ** і спробувати з’ясувати, що вони можуть вам запропонувати та чи можна їх abuse.

## Emails

Маючи **domains** і **subdomains** у межах scope, ви фактично маєте все, що **потрібно для початку пошуку emails**. Ось **APIs** і **tools**, які найкраще допомагали мені знаходити emails компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) - з APIs
- API of [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API of [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API of [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Looking for vulnerabilities**

Emails стануть у пригоді пізніше для **brute-force web logins and auth services** (таких як SSH). Також вони потрібні для **phishings**. Крім того, ці APIs нададуть ще більше **інформації про людину**, яка стоїть за email, що корисно для phishing campaign.

## Credential Leaks

Маючи **domains,** **subdomains** і **emails**, можна почати шукати credentials, які раніше були leaked і належали цим emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials, це дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані зі зламами компаній, під час яких **sensitive information була leaked і продана**. Однак компанії можуть постраждати від **інших leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Credentials і APIs можуть бути leaked у **public repositories** **компанії** або **users**, які працюють у цій github company.\
Ви можете використати **tool** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **public repos** **organization** та її **developers** і автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використати для запуску **gitleaks** проти всього **text**, наданого у **URLs, переданих** йому, оскільки іноді **web pages також містять secrets**.

#### Github Dorks

Також перегляньте цю **page** щодо потенційних **github dorks**, які можна шукати в organization, яку ви атакуєте:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Іноді attackers або просто workers **публікують вміст компанії на paste site**. Це може містити або не містити **sensitive information**, але пошук таких даних є дуже цікавим.\
Ви можете використати tool [**Pastos**](https://github.com/carlospolop/Pastos), щоб одночасно шукати більш ніж на 80 paste sites.

### Google Dorks

Старі, але перевірені google dorks завжди корисні для пошуку **exposed information, якої там не повинно бути**. Єдина проблема полягає в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих queries, які неможливо запускати вручну. Тож можна вибрати свої улюблені 10 або використати **tool, такий як** [**Gorks**](https://github.com/carlospolop/Gorks) **для запуску їх усіх**.

_Зверніть увагу, що tools, які намагаються використати всю database через звичайний Google browser, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Looking for vulnerabilities**

Якщо ви знайдете **valid leaked** credentials або API tokens, це дуже легка перемога.

## Public Code Vulnerabilities

Якщо ви виявили, що компанія має **open-source code**, його можна **проаналізувати** та пошукати в ньому **vulnerabilities**.

**Залежно від мови** можна використовувати різні **tools**:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Також існують безкоштовні services, які дозволяють **сканувати public repositories**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість vulnerabilities**, які знаходять bug hunters, міститься всередині **web applications**, тому на цьому етапі я хотів би розповісти про **web application testing methodology**, а [**цю інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), оскільки, хоча не варто очікувати, що вони знайдуть дуже важливі vulnerabilities, вони стануть у пригоді для їх додавання до **workflows, щоб отримати певну початкову web information.**

## Recapitulation

> Вітаю! На цьому етапі ви вже виконали **всю базову enumeration**. Так, вона базова, оскільки можна виконати набагато більше enumeration (пізніше ми розглянемо додаткові tricks).

Отже, ви вже:

1. Знайшли всі **companies** у межах scope
2. Знайшли всі **assets**, що належать companies (і виконали vuln scan, якщо це входить до scope)
3. Знайшли всі **domains**, що належать companies
4. Знайшли всі **subdomains** цих domains (чи можливий subdomain takeover?)
5. Знайшли всі **IPs** (з **CDNs** і **не з CDNs**) у межах scope.
6. Знайшли всі **web servers** і створили їхні **screenshots** (чи є щось дивне, що варте глибшого аналізу?)
7. Знайшли всі **potential public cloud assets**, що належать компанії.
8. Знайшли **Emails**, **credentials leaks** і **secret leaks**, які можуть дуже легко забезпечити вам **big win**.
9. Виконали **Pentesting усіх знайдених вами webs**

## **Full Recon Automatic Tools**

Існує кілька tools, які виконують частину запропонованих дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Трохи застарілий і не оновлюється

## **References**

- Усі безкоштовні courses від [**@Jhaddix**](https://twitter.com/Jhaddix), наприклад [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
