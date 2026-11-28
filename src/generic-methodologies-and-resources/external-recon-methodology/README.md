# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

Список інших проєктів для OSINT і пошуку в інтернеті за категоріями дивіться в розділі [Інструменти та ресурси сторонніх розробників](../third-party-tools-and-resources.md#osint).

> Отже, вам сказали, що все, що належить певній компанії, входить у scope, і ви хочете з’ясувати, чим саме володіє ця компанія.

Мета цього етапу — отримати список усіх **компаній, що належать головній компанії**, а потім — усіх **активів** цих компаній. Для цього ми:<sup>[[1]](#references)</sup>

1. Знайдемо придбані головною компанією компанії — це дасть нам перелік компаній у scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам IP-діапазони, що належать кожній компанії.
3. Скористаємося пошуком reverse whois, щоб знайти інші записи (назви організацій, домени тощо), пов’язані з початковим записом (це можна робити рекурсивно).
4. Скористаємося іншими методами, наприклад фільтрами `org` і `ssl` у shodan, щоб шукати інші активи (трюк із `ssl` можна застосовувати рекурсивно).

Про поетапну передачу знайдених піддоменів для HTTP-сканування та виявлення портів дивіться в розділі [Методологія пентестингу](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Придбання компаній**

Перш за все, потрібно з’ясувати, **які інші компанії належать головній компанії**.\
Один зі способів — відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** й **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Інший спосіб — відвідати сторінку головної компанії у **Wikipedia** й пошукати **придбання**.\
Для публічних компаній перевірте документи **SEC/EDGAR**, сторінки **відносин з інвесторами** або місцеві реєстри компаній (наприклад, **Companies House** у Великій Британії).\
Щоб знайти глобальні корпоративні структури та дочірні компанії, спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Гаразд, на цьому етапі ви маєте знати всі компанії, що входять у scope. З’ясуймо, як знайти їхні активи.

### **ASN**

Номер автономної системи (**ASN**) — це **унікальний номер**, який **Internet Assigned Numbers Authority (IANA)** призначає **автономній системі** (AS).\
**AS** складається з **блоків** **IP-адрес** із чітко визначеною політикою доступу до зовнішніх мереж. Такою системою керує одна організація, але вона може складатися з кількох операторів.

Варто з’ясувати, чи **призначено компанії ASN**, щоб знайти її **IP-діапазони**. Буде корисно провести **перевірку на вразливості** всіх **хостів** у **scope** і **пошукати домени** на цих IP-адресах.\
Шукати можна за **назвою компанії**, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть допомогти зібрати більше даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(IP-діапазони та Whois)** уже є за першим посиланням.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Також під час enumeration [**BBOT**](https://github.com/blacklanternsecurity/bbot) автоматично збирає та підсумовує ASN наприкінці сканування.

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

Також можна знайти діапазони IP-адрес організації за допомогою [ASNLookup](https://asnlookup.com/), який має обмежений безкоштовний рівень API.

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам дозволено, ви можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також можна виконати [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти, **а залежно від результатів варто** подивитися в цій книзі, як pentest-ити різні можливі запущені сервіси.\
**Також варто згадати, що можна підготувати списки** стандартних імен користувачів **і** паролів **та спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи — час знайти домени в межах scope.

_Зверніть увагу, що за допомогою наведених нижче запропонованих методів можна також знайти субдомени, і цю інформацію не варто недооцінювати._

Перш за все слід знайти **основний домен** (або домени) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, можна спробувати виконати **reverse DNS lookups** для цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або відомий DNS-сервер (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Для отримання цієї інформації можна також скористатися [SecurityTrails](https://securitytrails.com/), хоча для доступу до історичних DNS-даних потрібен платний план.\
Для великих діапазонів корисні такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які автоматизують зворотні запити та збагачення даних.

### **Reverse Whois (цикл)**

У записі **whois** можна знайти багато цікавої **інформації**, як-от **назву організації**, **адресу**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **інші активи, пов’язані з компанією**, виконавши **запити Reverse Whois за будь-яким із цих полів** (наприклад, знайти інші реєстраційні записи whois, у яких фігурує та сама електронна адреса).\
Можна скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (вебінтерфейс та API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** вебінтерфейс; API платний.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Не безкоштовно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Не безкоштовно
- [https://securitytrails.com/](https://securitytrails.com/) - Обмежений безкоштовний доступ до API для поточних DNS-записів і субдоменів; для історичних даних і зворотного пошуку потрібен платний план.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 безкоштовних кредитів API після реєстрації; надалі послуга платна.

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен ключ API whoxy).\
Також можна автоматично шукати записи Reverse Whois за допомогою [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Зауважте, що за допомогою цієї техніки можна знаходити нові доменні імена щоразу, коли ви знаходите новий домен.**

### **Трекери**

Якщо на двох різних сторінках знайти **однаковий ID того самого трекера**, можна припустити, що **обома сторінками** **керує та сама команда**.\
Наприклад, якщо на кількох сторінках ви бачите однаковий **ID Google Analytics** або **ID Adsense**.

Є кілька сайтів та інструментів, які дають змогу шукати за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Платний** вебсервіс та API ([ціни](https://www.stackscan.com/pricing)); наразі безкоштовний план не пропонується. Шукайте пов’язані активи, а не лише ID трекерів: шлях до скрипту, назву власного пакета або хост, з якого завантажується актив, щоб знайти всі сайти, де він використовується.

API повертає стек для одного домену, що корисно для підтвердження того, що знайдений актив належить тій самій інфраструктурі:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Повертає кожну виявлену технологію разом із її категорією. Asset pivoting наразі доступний лише для вебу, а API підтримує пошук за доменом.

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та субдомени нашої цілі, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Результати Favihash, використані для виявлення доменів зі спільним хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простими словами, favihash дає змогу виявити домени, хеш іконки favicon яких збігається з хешем цільового домену.

![Вивід favihash, використаний для виявлення доменів з однаковим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знайти інші доступні ззовні екземпляри тієї самої технології.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ось як можна **обчислити хеш favicon** вебсайту (MMH3 від **байтів favicon, закодованих у base64**):

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

Також можна отримувати хеші favicon у великому масштабі за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім шукати пов’язані дані в Shodan/Censys.

Розглядайте відбитки favicon як зачіпки та перевіряйте їх за супутніми ознаками.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте хеш як індикатор, а не доказ**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: досліджуйте шляхи фреймворків/збірок, файли маніфестів, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URL і HTML-теги `<link rel="icon">`.
- **Статичні ресурси можуть залишатися доступними за WAF/SSO/IdP-контролями**: запитуйте іконку безпосередньо та перевіряйте `ETag`, `Last-Modified`, перенаправлення й заголовки кешу.
- **Перевіряйте збіги за супутніми ознаками**: порівнюйте заголовок сторінки, хеш HTML/тіла відповіді, заголовки, суб’єкти/SAN TLS-сертифікатів, компоненти продукту та відкриті порти.
- **Групуйте за хешем HTML/тіла відповіді**: узгоджений шаблон посилює достовірність відбитка; різні шаблони можуть свідчити про загальну або спільну іконку.
- **Хеш, що трапляється в не пов’язаних між собою підписах, портах і продуктах, може вказувати на honeypot або заглушку.**
- **Для неоднозначних цілей порівняйте реальну сторінку зі сторінкою за неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; збіг відповідей хостингу або паркування домену може пояснити спільну іконку.
- **Починайте первинне сортування з правил виявлення Nuclei або публічних наборів даних**, які пов’язують хеші favicon із продуктами та CPE.
- **Пам’ятайте про обмеження охоплення, зумовлене орієнтацією на IP-адреси**: поверхні за CDN, з маршрутизацією SNI, anycast і лише доменним доступом можуть бути відсутні в наборах даних на кшталт Shodan.

### **Авторське право / Унікальний рядок**

Шукайте на вебсторінках **рядки, які можуть повторюватися на різних сайтах однієї організації**. Хорошим прикладом може бути **рядок авторського права**. Потім шукайте цей рядок у **Google**, інших **браузерах** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Часто використовують cron job, наприклад:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

щоб одночасно поновити всі сертифікати на сервері. Зіставлення часових позначок сертифікатів або позицій у журналах certificate transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація DMARC для пошти

Можна скористатися вебсайтом, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструментом, наприклад [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени й субдомени зі спільною інформацією DMARC**.\
Ще один корисний сервіс — [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Занедбаний A-запис може стати доступним, коли хмарний провайдер повторно призначить IP-адресу. У дослідженні описано opportunistic workflow, який створює інстанс і зіставляє його адресу з даними passive DNS; перевіряйте сценарії takeover лише в межах дозволеного scope.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні кроки пошуку щоразу, коли знаходите новий домен: кожен результат може виявити додаткові імена сертифікатів, зв’язки passive DNS, збіги favicon та ідентифікатори організацій, які не були помітні з початкового seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, якій належить діапазон IP-адрес, у Shodan можна шукати за цими даними: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікатах.

Можна отримати **TLS-сертифікат** головної вебсторінки, дізнатися **назву організації**, а потім шукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **Shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або скористатися таким інструментом, як [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — це неймовірний інструмент, який шукає **домени, пов’язані** з основним доменом, і їхні **субдомени**.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які досі розв’язуються або які можна перехопити. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Пошук вразливостей**

Перевірте на наявність [перехоплення домену](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо знайдете **домен з IP-адресою, відмінною** від тих, які вже виявили під час пошуку активів, виконайте **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів у **цій книзі можна знайти кілька хитрощів для їх «атаки»**.\
_Зверніть увагу: іноді домен розміщено на IP-адресі, яка не контролюється клієнтом, а отже, не входить до scope. Будьте обережні._

## Субдомени

> Нам відомі всі компанії в scope, усі активи кожної компанії та всі домени, пов’язані з цими компаніями.

Настав час знайти всі можливі субдомени кожного виявленого домену.

> [!TIP]
> Зауважте, що деякі інструменти й методи пошуку доменів також можуть допомогти знайти субдомени.

### **DNS**

Спробуймо отримати **субдомени** з записів **DNS**. Також варто спробувати виконати **Zone Transfer** (якщо він вразливий — повідомте про це).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Щоб дізнатися про API та платформи, що охоплюють інфраструктуру, репутацію, записи про витоки даних і збагачення інформацією за межами пошуку субдоменів, див. [каталог API для розвідки та аналізу загроз](reconnaissance-and-threat-intelligence-apis.md).

Найшвидший спосіб знайти багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте ключі API):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Є **інші цікаві інструменти/API**, які, навіть якщо вони не спеціалізуються безпосередньо на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) безкоштовний API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Безкоштовний API AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси для будь-якого домену з AlienVault's Open Threat Exchange, Wayback Machine та Common Crawl.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують веб у пошуках файлів JS і витягують звідти субдомени.

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

- [**SecurityTrails**](https://securitytrails.com/) надає обмежений безкоштовний доступ до API з актуальними даними DNS і субдоменів; для доступу до історичних даних DNS/IP потрібен платний план.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Цей проєкт безкоштовно надає всі субдомени, пов’язані з програмами bug bounty. Також отримати ці дані можна за допомогою [chaospy](https://github.com/Moaaz-0x/chaospy) або скористатися scope, який використовує цей проєкт: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Порівняння багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові субдомени, виконуючи brute-force DNS-серверів із можливими іменами субдоменів.

Для цього вам знадобляться поширені wordlist-и субдоменів, наприклад:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Також вам знадобляться IP-адреси надійних DNS-резолверів. Щоб створити список надійних DNS-резолверів, завантажте їх із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і відфільтруйте за допомогою [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Або скористайтеся цим списком: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): це був перший інструмент для ефективного DNS brute-force. Він дуже швидкий, але схильний до хибнопозитивних результатів.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Цей, здається, використовує лише 1 резолвер.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка для `massdns`, написана мовою Go, яка дає змогу перераховувати дійсні субдомени за допомогою активного bruteforce, а також розв’язувати субдомени з обробкою wildcard і зручним введенням-виведенням.

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

Після того як ви знайшли піддомени за допомогою відкритих джерел і brute-forcing, можна згенерувати варіанти знайдених піддоменів, щоб спробувати знайти ще більше. Для цього стануть у пригоді кілька інструментів:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Отримавши домени та піддомени, генерує їхні варіанти.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Генерує перестановки на основі доменів і субдоменів.
  - Список слів для перестановок goaltdns можна знайти [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** За заданими доменами та субдоменами генерує перестановки. Якщо файл із перестановками не вказано, gotator використовує власний.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Крім генерації перестановок субдоменів, він також може спробувати їх розв’язати (але краще скористатися попередніми згаданими інструментами).
  - **Список слів** для генерації перестановок altdns можна знайти [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для створення перестановок, мутацій і змін субдоменів. Цей інструмент перебирає всі можливі результати (не підтримує DNS wildcard).
  - Список слів для створення перестановок за допомогою dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні імена субдоменів** за вказаними шаблонами, щоб спробувати знайти більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Вивчає regex-подібні шаблони з виявлених субдоменів і генерує кандидатні імена для перевірки.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це subdomain brute-force fuzzer із надзвичайно простим, але ефективним алгоритмом, керованим відповідями DNS. Він використовує наданий набір вхідних даних, як-от спеціально підібраний wordlist або історичні записи DNS/TLS, щоб точно генерувати більше відповідних доменних імен і циклічно розширювати їх на основі інформації, отриманої під час DNS-сканування.

```
echo www | subzuf facebook.com
```

### **Робочий процес виявлення піддоменів**

Приклади workflow від Trickest поєднують OSINT, DNS brute force та етапи генерації перестановок для повторюваного перерахування піддоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, на якій розміщено **одну або кілька вебсторінок**, що належать піддоменам, можна спробувати **знайти інші піддомени з вебсайтами на цій IP-адресі**: пошукати домени, що вказують на цю IP-адресу, в **джерелах OSINT** або **перебрати назви доменів VHost на цій IP-адресі**.

#### OSINT

Знайти деякі **VHosts на IP-адресах можна за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері приховано якийсь піддомен, можна спробувати перебрати можливі варіанти:

Для віртуальних хостів на основі імені перебирайте значення заголовка `Host` і використовуйте автоматичне калібрування ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>

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

Іноді трапляються сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/піддомен. У таких випадках можна скористатися цією поведінкою, щоб **виявити** нові **піддомени**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute Force bucket-ів**

Шукаючи **субдомени**, стежте, чи **вказують** вони на якийсь тип **bucket**, і в такому разі [**перевірте дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Також, оскільки на цьому етапі ви знатимете всі домени в межах scope, спробуйте [**перебрати можливі назви bucket і перевірити дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** домену, моніторячи журнали **Certificate Transparency** — це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте наявність можливих [**перехоплень субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на якийсь **S3 bucket**, [**перевірте дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Якщо ви знайдете **субдомени з IP-адресою, відмінною** від уже виявлених під час пошуку активів, виконайте **базове сканування на вразливості** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб у **цій книзі можна знайти кілька хитрощів, щоб їх «атакувати»**.\
_Зверніть увагу, що іноді субдомен розміщений на IP-адресі, яка не контролюється клієнтом, а отже, не входить у scope. Будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти діапазони IP-адрес, домени й субдомени**.\
Тепер час **зібрати всі IP-адреси з цих діапазонів**, а також IP-адреси **доменів/субдоменів (DNS-запити).**

За допомогою таких сервісів можна також знайти **IP-адреси, які раніше використовувалися доменами й субдоменами**. Ці IP-адреси можуть і досі належати клієнту (і допомогти знайти [**способи обходу CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (для історичних даних DNS/IP потрібен платний план)

Також можна перевірити, які домени вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host) або онлайн-сервісу зворотного пошуку IP, наприклад [**NetAPI**](https://netapi.com/lookup-ip/).

### **Пошук вразливостей**

**Проскануйте порти на всіх IP-адресах, що не належать CDN** (оскільки там, найімовірніше, не знайдеться нічого цікавого). У виявлених запущених службах ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **зі сканування хостів.**

## Пошук вебсерверів

> Ми знайшли всі компанії та їхні активи, а також знаємо діапазони IP-адрес, домени й субдомени в межах scope. Час шукати вебсервери.

На попередніх етапах ви, ймовірно, уже провели **розвідку виявлених IP-адрес і доменів**, тож, можливо, **знайшли всі можливі вебсервери**. Якщо ні, зараз розглянемо кілька **швидких способів пошуку вебсерверів** у межах scope.

Зверніть увагу: цей етап **орієнтований на пошук вебзастосунків**, тому також слід виконати **сканування на вразливості** та **сканування портів** (**якщо це дозволено** умовами scope).

[**Тут наведено швидкий спосіб** знайти **відкриті порти**, пов’язані з вебсерверами, за допомогою **masscan**](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний інструмент для пошуку вебсерверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Передайте їм список доменів, і вони спробують під’єднатися до портів 80 (http) і 443 (https). Також можна вказати інші порти:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Знімки екрана**

Тепер, коли ви виявили **всі вебсервери** в межах області тестування (серед **IP-адрес** компанії та всіх її **доменів** і **піддоменів**), ви, мабуть, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі знімків екрана всіх серверів. Просто **переглянувши** **головну сторінку**, можна знайти **дивні** кінцеві точки, які з більшою **ймовірністю** можуть бути **вразливими**.

Щоб реалізувати цю ідею, можна скористатися [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **знімків екрана** й визначення, **де ймовірно є вразливості**, а де їх немає.

## Публічні хмарні ресурси

Щоб знайти потенційні хмарні ресурси, що належать компанії, слід **почати зі списку ключових слів, які її ідентифікують**. Наприклад, для криптовалютної компанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться списки слів із **поширеними назвами bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за цими словами слід згенерувати **перестановки** (докладніше див. [**Другий раунд DNS brute-force**](#second-dns-bruteforce-round)).

Для отриманих списків слів можна використати такі інструменти, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте: шукаючи хмарні ресурси, потрібно **шукати не лише bucket в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете **відкриті bucket або доступні зовні cloud functions**, **перейдіть до них** і спробуйте з’ясувати, що вони пропонують і чи можна ними зловживати.

## Електронні адреси

Маючи **домени** й **піддомени** в межах області тестування, ви маєте все необхідне, щоб **почати шукати адреси електронної пошти**. Ось **API** та **інструменти**, які найкраще допомогли мені знайти електронні адреси працівників компаній:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси стануть у пригоді пізніше для **brute-force веблогінів і сервісів автентифікації** (наприклад, SSH). Вони також потрібні для **фішингових атак**. Крім того, ці API нададуть ще більше **інформації про людину**, яка стоїть за адресою електронної пошти, а це корисно для фішингової кампанії.

## Витоки облікових даних

Маючи **домени,** **піддомени** й **електронні адреси**, можна почати шукати облікові дані, які раніше потрапили у витоки й пов’язані з цими адресами:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **дійсні облікові дані з витоків**, це буде дуже легка перемога.

## Витоки секретів

Витоки облікових даних пов’язані зі зламами компаній, під час яких **конфіденційну інформацію викрали й продали**. Однак компанії можуть постраждати й від **інших витоків**, інформації про які немає в цих базах даних:

### Витоки з Github

Облікові дані й API можуть потрапити у витоки з **публічних репозиторіїв** **компанії** або **користувачів**, які працюють у цій компанії на github.\
Можна скористатися **інструментом** [**Leakos**](https://github.com/carlospolop/Leakos), щоб **завантажити** всі **публічні репозиторії** **організації** та її **розробників** і автоматично запустити на них [**gitleaks**](https://github.com/gitleaks/gitleaks).

**Leakos** також можна використовувати для запуску **gitleaks** на всьому **тексті**, доступному за переданими йому **URL-адресами**, адже іноді **вебсторінки також містять секрети**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Витоки з paste-сайтів

Іноді зловмисники або просто працівники **публікують вміст компанії на paste-сайтах**. Він може містити або не містити **конфіденційну інформацію**, але шукати її все одно варто.\
Можна скористатися інструментом [**Pastos**](https://github.com/carlospolop/Pastos), щоб одночасно шукати на понад 80 paste-сайтах.

### Google Dorks

Старі, але дієві Google dorks завжди допомагають знаходити **оприлюднену інформацію, якій там не місце**. Проблема лише в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тож можна вибрати 10 улюблених або скористатися **інструментом на кшталт** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зверніть увагу: інструменти, які намагаються пройти всю базу даних через звичайний браузер Google, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **дійсні облікові дані або API-токени з витоків**, це буде дуже легка перемога.

## Вразливості у публічному коді

Якщо ви виявили, що компанія має **код із відкритим вихідним кодом**, його можна **проаналізувати** й пошукати в ньому **вразливості**.

**Залежно від мови програмування** можна скористатися різними **інструментами**; див. список [інструментів для аналізу вихідного коду](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також є безкоштовні сервіси, які дають змогу **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія вебпентестингу**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunter-и, міститься у **вебзастосунках**, тож тепер я хочу розповісти про **методологію тестування вебзастосунків**. [**Цю інформацію можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Інструменти з відкритим вихідним кодом для автоматизованого сканування вебзастосунків**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): не варто очікувати, що вони знайдуть дуже серйозні вразливості, але вони стануть у пригоді, якщо додати їх до **робочих процесів для початкового збору інформації про вебзастосунки**.

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову розвідку**. Так, вона базова, адже можна провести ще чимало розвідки (пізніше розглянемо інші хитрощі).

Отже, ви вже:

1. Знайшли всі **компанії** в межах області тестування
2. Знайшли всі **ресурси**, що належать компаніям (і провели сканування вразливостей, якщо це входить в область тестування)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **піддомени** цих доменів (чи є серед них піддомен, який можна перехопити?)
5. Знайшли всі **IP-адреси** в межах області тестування (як CDN, так і не CDN).
6. Знайшли всі **вебсервери** й зробили їхні **знімки екрана** (чи є щось дивне, що варто дослідити детальніше?)
7. Знайшли всі **потенційні публічні хмарні ресурси**, що належать компанії.
8. Знайшли **електронні адреси**, **витоки облікових даних** і **витоки секретів**, які можуть допомогти **дуже легко досягти значного успіху**.
9. Провели **пентестинг усіх знайдених вебсайтів**

## **Інструменти для повністю автоматизованої розвідки**

Існує чимало інструментів, які виконують частину запропонованих дій для заданої області тестування.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — дещо застарілий і не оновлюється



## References

- [1] [Jason Haddix – Методологія bug hunter-а, версія 4.0: розвідка](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про favicon: від іконок браузера до аналізу поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Використання favicon.ico для BugBounties, OSINT та іншого](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою атаки на Certificate Transparency, що використовує часову кореляцію](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Пасивне перехоплення: викриття (та відтворення) дорогої кампанії з перехоплення піддоменів](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: унікальний метод переліку піддоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний процес виявлення піддоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Повне виявлення піддоменів методом brute-force за допомогою автоматизованого робочого процесу Trickest, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Знімок екрана з результатами favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
