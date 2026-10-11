# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Вам сказали, що все, що належить певній компанії, входить у scope, і ви хочете з'ясувати, чим насправді володіє ця компанія.

Мета цього етапу — визначити всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми:<sup>[[1]](#references)</sup>

1. Знайдемо придбання головної компанії — це дасть нам перелік компаній, що входять у scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам діапазони IP-адрес, що належать кожній компанії.
3. Використаємо пошук reverse whois, щоб знайти інші записи (назви організацій, домени...), пов'язані з першим записом (це можна робити рекурсивно).
4. Використаємо інші методи, як-от фільтри `org` і `ssl` у shodan, щоб знайти інші активи (трюк із `ssl` можна застосовувати рекурсивно).

### **Придбання**

Перш за все, потрібно з'ясувати, **якими іншими компаніями володіє головна компанія**.\
Один зі способів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший спосіб — відвідати сторінку **Wikipedia** головної компанії та знайти інформацію про **придбання**.\
Для публічних компаній перевірте документи **SEC/EDGAR**, сторінки **Investor Relations** або місцеві реєстри компаній (наприклад, **Companies House** у Великій Британії).\
Щоб переглянути глобальні структури корпорацій і дочірні компанії, скористайтеся **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базою даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Гаразд, тепер ви маєте знати всі компанії, що входять у scope. З'ясуймо, як знайти їхні активи.

### **ASN**

Номер автономної системи (**ASN**) — це **унікальний номер**, який **Internet Assigned Numbers Authority (IANA)** присвоює **автономній системі** (AS).\
**AS** складається з **блоків** **IP-адрес**, для яких визначено окрему політику доступу до зовнішніх мереж. Такими системами керує одна організація, хоча вони можуть складатися з кількох операторів.

Варто з'ясувати, чи **присвоєно компанії ASN**, щоб знайти її **діапазони IP-адрес**. Було б корисно провести **тест на вразливості** всіх **хостів** у **scope** та **пошукати домени** за цими IP-адресами.\
Можна шукати за **назвою** компанії, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону компанії, ці посилання можуть допомогти зібрати більше даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(діапазони IP-адрес і Whois)** уже є в першому посиланні.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Також enumeration від [**BBOT**](https://github.com/blacklanternsecurity/bbot) автоматично агрегує та підсумовує ASN наприкінці сканування.

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

Ви також можете знайти діапазони IP-адрес організації за допомогою [http://asnlookup.com/](http://asnlookup.com) (є безкоштовний API).\
Ви можете знайти IP-адресу та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі нам відомі **всі активи в межах scope**, тож, якщо вам дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також можна запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти **і, залежно від результатів, переглянути в цій книзі, як проводити pentest кількох можливих запущених сервісів.**\
**Також варто зазначити, що можна підготувати списки** типових імен користувачів **і** паролів **та спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Нам відомі всі компанії в межах scope та їхні активи; час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних нижче методів можна також знайти субдомени, і цю інформацію не варто недооцінювати._

Перш за все, слід знайти **основний домен** кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, можна спробувати виконати **зворотні DNS-запити** до цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або загальновідомий DNS-сервер (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Для отримання цієї інформації також можна скористатися онлайн-інструментом: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисно автоматизувати зворотні запити та збагачення даних за допомогою таких інструментів, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx).

### **Зворотний Whois (цикл)**

У записі **whois** можна знайти багато цікавої **інформації**, як-от **назва організації**, **адреса**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, якщо виконати **зворотний пошук whois за будь-яким із цих полів** (наприклад, знайти інші реєстраційні записи whois, де вказано ту саму електронну адресу).\
Можна скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (вебсайт і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - вебсайт **безкоштовний**, API платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен ключ API whoxy).\
Також можна автоматично шукати пов’язані записи whois за допомогою [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Зверніть увагу: цю техніку можна використовувати, щоб знаходити більше доменних імен щоразу, коли ви знаходите новий домен.**

### **Трекери**

Якщо на двох різних сторінках знайти **однаковий ID одного й того самого трекера**, можна припустити, що **обома сторінками** **керує та сама команда**.\
Наприклад, якщо на кількох сторінках ви бачите однаковий **ID Google Analytics** або однаковий **ID Adsense**.

Є сторінки та інструменти, за допомогою яких можна шукати за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними аналітичними даними/трекерами)
- [**StackScan**](https://www.stackscan.com) - **Безкоштовний тариф** (вебсайт і API). Шукайте за будь-яким активом, який віддає сервер, а не лише за ID трекерів: шляхом до скрипту, назвою локально розміщеного пакета або хостом, з якого завантажується актив. Інструмент повертає всі сайти, на яких він є.

API повертає технологічний стек для одного домену, що корисно для підтвердження того, що знайдений актив належить до тієї самої інфраструктури:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Повертає кожну виявлену технологію з її категорією. Asset pivoting наразі доступний лише для вебу, API підтримує пошук за доменом.

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та субдомени нашої цілі, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Результати Favihash, використані для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу виявляти домени з таким самим хешем іконки favicon, як у нашої цілі.

![Вивід favihash, використаний для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як точку опори для пошуку в Shodan або FOFA інших доступних ззовні екземплярів тієї самої технології.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ось як можна **обчислити хеш favicon** вебсайту (MMH3 для **байтів favicon, закодованих у base64**):

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

Також можна масово отримувати хеші favicon за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім шукати пов’язані дані в Shodan/Censys.

Вважайте відбитки favicon зачіпками й перевіряйте їх за супутніми сигналами.<sup>[[3]](#references)[[4]](#references)</sup>

- **Вважайте хеш індикатором, а не доказом**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підробка.
- **Перевіряйте не лише** `/favicon.ico`: досліджуйте шляхи фреймворків і збірок, файли маніфестів, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані URL-адреси даних і теги HTML `<link rel="icon">`.
- **Статичні ресурси можуть залишатися доступними за екранами WAF/SSO/IdP**: запитуйте іконку безпосередньо й перевіряйте `ETag`, `Last-Modified`, перенаправлення та заголовки кешу.
- **Перевіряйте збіги за супутніми сигналами**: порівнюйте заголовок сторінки, хеш HTML/тіла, заголовки, суб’єкти/SAN TLS-сертифікатів, компоненти продукту та відкриті порти.
- **Групуйте за хешем HTML/тіла**: узгоджений шаблон посилює достовірність відбитка; різні шаблони вказують на загальну або спільну іконку.
- **Якщо хеш трапляється в непов’язаних сигнатурах, портах і продуктах, вважайте його потенційною ознакою honeypot або заповнювача.**
- **Для неоднозначних цілей порівнюйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові відповіді хостингу або паркування домену можуть пояснити спільну іконку.
- **Починайте тріаж із правил виявлення Nuclei або публічних наборів даних**, які зіставляють хеші favicon із продуктами та CPE.
- **Пам’ятайте про обмеження охоплення, орієнтованого на IP**: поверхні за CDN, з маршрутизацією SNI, anycast і доступні лише через домен можуть бути відсутні в наборах даних на кшталт Shodan.

### **Авторське право / Унікальний рядок**

Шукайте на вебсторінках **рядки, які можуть повторюватися на різних сайтах однієї організації**. Гарним прикладом може бути **рядок авторського права**. Потім шукайте цей рядок у **Google**, інших **браузерах** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Зазвичай використовують cron job на кшталт

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

для одночасного поновлення всіх сертифікатів на сервері. Кореляція часових позначок сертифікатів або їхніх позицій у журналах прозорості сертифікатів може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Для пошуку **доменів і субдоменів із тією самою інформацією DMARC** можна скористатися вебсайтом на кшталт [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) або інструментом на кшталт [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains).\
Інші корисні інструменти — [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Занедбаний A-запис може знову стати доступним, коли хмарний провайдер перепризначить IP-адресу. У дослідженні описано opportunistic workflow, який створює екземпляр і зіставляє його адресу з даними passive DNS; перевіряйте сценарії захоплення лише в межах дозволеного обсягу робіт.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні кроки пошуку щоразу, коли виявляєте новий домен: кожен результат може виявити додаткові імена в сертифікатах, зв’язки passive DNS, збіги favicon і ідентифікатори організацій, які не були видимі за початковими даними.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, якій належить діапазон IP-адрес, можна шукати ці дані в Shodan за допомогою: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Ви можете переглянути **TLS-сертифікат** головної вебсторінки, отримати **назву організації**, а потім шукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **Shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або скористатися інструментом на кшталт [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)— це інструмент для пошуку **доменів, пов’язаних** з основним доменом, і їхніх **субдоменів**. Просто неймовірний інструмент.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово допомагають знаходити **старі й забуті записи**, які досі резолвляться або які можна захопити. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук уразливостей**

Перевірте, чи можливе [захоплення домену](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайдете **домен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування на вразливості** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб у **цій книжці можна знайти кілька способів їх «атакувати»**.\
_Зауважте, що іноді домен розміщений на IP-адресі, яка не контролюється клієнтом, тож він поза межами дозволеного обсягу робіт. Будьте обережні._

## Субдомени

> Ми знаємо всі компанії в межах дозволеного обсягу робіт, усі активи кожної компанії та всі домени, пов’язані з цими компаніями.

Час знайти всі можливі субдомени кожного виявленого домену.

> [!TIP]
> Зауважте, що деякі інструменти й методи пошуку доменів також можуть допомогти знайти субдомени

### **DNS**

Спробуймо отримати **субдомени** з записів **DNS**. Також слід перевірити можливість **Zone Transfer** (якщо вона є, повідомте про це).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте API keys):


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

Є **інші цікаві інструменти/API**, які, хоча й не спеціалізуються безпосередньо на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) безкоштовний API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io), щоб отримати субдомени

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

- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси для будь-якого домену з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках JS-файлів і витягують звідти субдомени.

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

- [**securitytrails.com**](https://securitytrails.com/) має безкоштовний API для пошуку піддоменів та історії IP-адрес
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Цей проєкт безкоштовно надає **всі піддомени, пов’язані з bug-bounty програмами**. Ви також можете отримати ці дані за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або переглянути scope, який використовує цей проєкт: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Порівняння** багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **піддомени**, перебираючи можливі назви піддоменів на DNS-серверах.

Для цього вам знадобляться **поширені wordlist-и піддоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Також знадобляться IP-адреси надійних DNS-resolver-ів. Щоб створити список перевірених DNS-resolver-ів, завантажте їх із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і відфільтруйте за допомогою [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Також можна скористатися цим списком: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): Це був перший інструмент для ефективного DNS brute-force. Він дуже швидкий, але схильний видавати хибнопозитивні результати.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Цей, здається, використовує лише 1 резолвер.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка над `massdns`, написана на Go, що дає змогу перераховувати валідні субдомени за допомогою активного bruteforce, а також резолвити субдомени з обробкою wildcard і зручною підтримкою введення-виведення.

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

Після пошуку субдоменів у відкритих джерелах і за допомогою brute-force можна згенерувати варіанти знайдених субдоменів, щоб спробувати знайти ще більше. Для цього стануть у пригоді кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Генерує перестановки на основі доменів і субдоменів.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Створює перестановки на основі доменів і субдоменів.
  - [**Тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt) можна отримати **wordlist** для перестановок goaltdns.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** За наявними доменами та субдоменами генерує перестановки. Якщо файл із перестановками не вказано, gotator використовуватиме власний.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати їх розв’язати (але краще скористатися згаданими вище інструментами).
  - **wordlist** із перестановками altdns можна знайти [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для виконання permutations, mutations та зміни субдоменів. Цей інструмент перебирає результати методом brute force (не підтримує DNS wildcard).
  - Список слів для permutations у dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена субдоменів** за заданими шаблонами, щоб спробувати виявити більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Вивчає шаблони, подібні до регулярних виразів, на основі знайдених субдоменів і генерує кандидатні імена для DNS-резолву.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force перебору субдоменів, що використовує надзвичайно простий, але ефективний алгоритм, керований DNS-відповідями. Він використовує надані вхідні дані, як-от спеціально підібраний wordlist або історичні DNS/TLS-записи, щоб точно генерувати більше відповідних доменних імен і циклічно розширювати їх на основі інформації, зібраної під час DNS-сканування.

```
echo www | subzuf facebook.com
```

### **Воркфлоу виявлення піддоменів**

Приклади workflow від Trickest поєднують OSINT, DNS brute force і етапи перестановок для повторюваного переліку піддоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Віртуальні хости**

Якщо ви знайшли IP-адресу з **однією або кількома вебсторінками**, що належать піддоменам, можна спробувати **знайти інші піддомени з вебсайтами на цій IP-адресі**: пошукати домени, пов’язані з IP-адресою, в **OSINT-джерелах** або виконати **brute force доменних імен VHost на цій IP-адресі**.

#### OSINT

Деякі **VHosts на IP-адресах можна знайти за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері може бути прихований піддомен, спробуйте виконати brute force:

Для vhosts на основі імен перебирайте значення заголовка `Host` і використовуйте автокалібрування ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>

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
> За допомогою цієї техніки ви навіть можете отримати доступ до внутрішніх/прихованих endpoint-ів.

### **CORS Brute Force**

Іноді ви знаходитимете сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/субдомен. У таких випадках можна скористатися цією поведінкою, щоб **виявити** нові **субдомени**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute Force для Buckets**

Під час пошуку **субдоменів** перевіряйте, чи **спрямований** якийсь із них на **bucket**. Якщо так, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**підібрати можливі назви buckets методом brute force і перевірити дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** для домену, стежачи за журналами **Certificate Transparency**. Саме це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте, чи можливий [**захват субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** спрямований на **S3 bucket**, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **субдомен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування на вразливості** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб у **цій книзі ви знайдете кілька способів їх «атакувати»**.\
_Зауважте, що іноді субдомен розміщений на IP-адресі, яка не контролюється клієнтом, а отже, не входить у scope. Будьте обережні._

## IPs

На початкових етапах ви могли **знайти діапазони IP-адрес, домени та субдомени**.\
Настав час **зібрати всі IP-адреси з цих діапазонів**, а також IP-адреси **доменів/субдоменів (через DNS-запити).**

За допомогою сервісів із наведених нижче **безкоштовних API** можна також знайти **IP-адреси, які раніше використовували домени й субдомени**. Можливо, клієнт і досі володіє цими IP-адресами, що може допомогти знайти [**способи обходу CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна знайти домени, спрямовані на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Проскануйте порти всіх IP-адрес, що не належать CDN** (оскільки там, найімовірніше, не знайдеться нічого цікавого). У виявлених запущених службах ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **зі сканування хостів.**

## Пошук вебсерверів

> Ми знайшли всі компанії та їхні активи, а також відомі діапазони IP-адрес, домени й субдомени в межах scope. Час шукати вебсервери.

На попередніх етапах ви, імовірно, вже виконали **розвідку виявлених IP-адрес і доменів**, тож, можливо, **вже знайшли всі потенційні вебсервери**. Якщо ні, зараз розглянемо кілька **швидких способів знайти вебсервери** в межах scope.

Зверніть увагу, що цей етап **орієнтований на виявлення вебзастосунків**, тож також слід виконати **сканування на вразливості** та **сканування портів** (**якщо це дозволено** умовами scope).

[**Швидкий спосіб виявити відкриті порти вебсерверів за допомогою masscan описано тут**](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний інструмент для пошуку вебсерверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Достатньо передати список доменів — інструмент спробує під’єднатися до портів 80 (http) і 443 (https). Також можна вказати інші порти для перевірки:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Скріншоти**

Тепер, коли ви виявили **всі вебсервери** в межах scope (серед **IP-адрес** компанії, а також усіх її **доменів** і **субдоменів**), ви, мабуть, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі скриншотів усіх серверів. Просто **переглянувши** **головну сторінку**, можна знайти **дивні** кінцеві точки, які більш **схильні** до **вразливостей**.

Щоб реалізувати цю ідею, можна скористатися [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, потім можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **скриншотів** — він підкаже, що **ймовірно містить вразливості**, а що ні.

## Публічні хмарні активи

Щоб знайти потенційні хмарні активи компанії, варто **почати зі списку ключових слів, за якими можна її ідентифікувати**. Наприклад, для криптокомпанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться списки слів із **поширеними назвами bucket-ів**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Далі на основі цих слів потрібно згенерувати **перестановки** (докладніше див. [**Другий раунд DNS brute-force**](#second-dns-bruteforce-round)).

Для отриманих списків слів можна використовувати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку Cloud Assets варто шукати не лише **bucket-и в AWS**.

### **Пошук вразливостей**

Якщо знайдете такі речі, як **відкриті bucket-и або доступні хмарні функції**, перейдіть до них і спробуйте з’ясувати, що вони пропонують і чи можна ними зловживати.

## Електронні адреси

Маючи **домени** та **субдомени** в межах scope, ви вже маєте все **необхідне, щоб почати шукати електронні адреси**. Ось **API** та **інструменти**, які найкраще допомагали мені знаходити адреси електронної пошти співробітників компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси стануть у пригоді пізніше для **brute-force веблогінів і сервісів автентифікації** (наприклад, SSH). Вони також потрібні для **фішингу**. Крім того, ці API нададуть вам більше **інформації про людину**, якій належить адреса, що стане в пригоді для фішингової кампанії.

## Credential Leaks

Маючи **домени**, **субдомени** та **електронні адреси**, можна почати шукати облікові дані, які раніше потрапили в leak і належать до цих адрес:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо знайдете **дійсні облікові дані з leak**, це буде дуже легка перемога.

## Secrets Leaks

Credential leaks пов’язані зі зламами компаній, під час яких **конфіденційна інформація потрапила в leak і була продана**. Однак компанії можуть постраждати й від **інших leaks**, інформація про які відсутня в цих базах даних:

### Github Leaks

Облікові дані та API можуть потрапити в leak у **публічних репозиторіях** **компанії** або **користувачів**, які працюють у цій компанії.\
Можна скористатися **інструментом** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **організації** та її **розробників**, а потім автоматично запустити [**gitleaks**](https://github.com/zricethezav/gitleaks) для їх перевірки.

**Leakos** також можна використовувати для запуску **gitleaks** на всіх **текстових URL-адресах**, переданих йому, оскільки іноді **вебсторінки теж містять секрети**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Pastes Leaks

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайтах**. Там може бути або не бути **конфіденційна інформація**, але пошукати її все одно варто.\
Можна скористатися інструментом [**Pastos**](https://github.com/carlospolop/Pastos), щоб одночасно шукати на понад 80 paste-сайтах.

### Google Dorks

Старі, але безвідмовні google dorks завжди допомагають знаходити **відкриту інформацію, якої там не мало б бути**. Єдина проблема в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо запускати вручну. Тож можна вибрати 10 улюблених запитів або скористатися **інструментом на кшталт** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб запустити їх усі**.

_Зауважте: інструменти, які намагаються перевірити всю базу даних через звичайний браузер Google, працюватимуть безкінечно, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо знайдете **дійсні облікові дані або API-токени з leak**, це буде дуже легка перемога.

## Вразливості у відкритому коді

Якщо ви з’ясували, що компанія має **код із відкритим вихідним кодом**, його можна **проаналізувати** й пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **інструменти**; див. список [інструментів для аналізу вихідного коду](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також існують безкоштовні сервіси для **сканування публічних репозиторіїв**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, містяться у **вебзастосунках**, тому на цьому етапі я хотів би розповісти про **методологію тестування вебзастосунків**. [**Докладніше читайте тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): хоча від них не варто очікувати виявлення дуже серйозних вразливостей, вони стануть у пригоді, якщо додати їх до **workflow для отримання початкової інформації про вебзастосунки.**

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову розвідку**. Так, вона базова, адже можна провести ще багато розвідки (пізніше розглянемо більше прийомів).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **активи**, що належать компаніям (і виконали vuln scan, якщо це дозволено scope)
3. Знайшли всі **домени** компаній
4. Знайшли всі **субдомени** доменів (чи є серед них subdomain takeover?)
5. Знайшли всі **IP-адреси** в межах scope (як **від CDN, так і не від CDN**).
6. Знайшли всі **вебсервери** й зробили їхні **скриншоти** (чи є щось дивне, що варто ретельніше дослідити?)
7. Знайшли всі **потенційні публічні хмарні активи**, що належать компанії.
8. **Електронні адреси**, **credential leaks** і **secret leaks**, які можуть дуже легко принести вам **великий успіх**.
9. **Провели Pentesting усіх знайдених вебсайтів**

## **Інструменти для повністю автоматизованої розвідки**

Є різні інструменти, які виконують частину запропонованих дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — дещо застарілий і більше не оновлюється

## References

- [1] [Jason Haddix — Методологія bug hunter’а v4.0: розвідка](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf — HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) — Про favicon: від іконок браузера до розвідки поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) — Перетворення favicon.ico на зброю для BugBounties, OSINT і не тільки](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov — Виявлення доменів за допомогою атаки на часову кореляцію в Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) — Пасивний takeover: виявлення (та емуляція) дорогої кампанії з subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet — Regulator: унікальний метод переліку субдоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop — Повний workflow виявлення субдоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop — Повний brute-force пошук субдоменів за допомогою автоматизованого workflow Trickest, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter — скриншот результату favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
