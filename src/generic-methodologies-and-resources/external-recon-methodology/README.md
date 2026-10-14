# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить у scope, і ви хочете з’ясувати, чим саме володіє ця компанія.

Мета цього етапу — отримати список усіх **компаній, що належать головній компанії**, а потім знайти всі **активи** цих компаній. Для цього ми:<sup>[[1]](#references)</sup>

1. Знайдемо компанії, придбані головною компанією: це дасть нам список компаній у scope.
2. Знайдемо ASN (якщо є) кожної компанії: це дасть нам діапазони IP-адрес, що належать кожній компанії.
3. Скористаємося пошуком reverse whois, щоб знайти інші записи (назви організацій, домени...), пов’язані з першою компанією (це можна робити рекурсивно).
4. Скористаємося іншими методами, наприклад фільтрами `org` і `ssl` у shodan, щоб знайти інші активи (трюк із `ssl` можна застосовувати рекурсивно).

### **Придбання**

Перш за все, потрібно з’ясувати, **якими іншими компаніями володіє головна компанія**.\
Можна відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані головною компанією.\
Також можна відвідати сторінку головної компанії у **Wikipedia** та пошукати **acquisitions**.\
Для публічних компаній перевірте звітність **SEC/EDGAR**, сторінки **для інвесторів** або місцеві реєстри компаній (наприклад, **Companies House** у Великій Британії).\
Щоб знайти глобальні структури корпорацій і дочірні компанії, спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Гаразд, тепер ви маєте знати всі компанії у scope. З’ясуймо, як знайти їхні активи.

### **ASN**

Номер автономної системи (**ASN**) — це **унікальний номер**, який **Internet Assigned Numbers Authority (IANA)** призначає **автономній системі** (AS).\
**AS** складається з **блоків** **IP-адрес**, для яких визначено окрему політику доступу до зовнішніх мереж. Нею керує одна організація, але вона може об’єднувати кількох операторів.

Варто з’ясувати, чи **призначено компанії ASN**, щоб знайти її **діапазони IP-адрес**. Цікаво провести **тест на вразливості** всіх **хостів** у **scope** та **пошукати домени** на цих IP-адресах.\
Можна шукати за **назвою компанії**, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону компанії, ці посилання можуть допомогти зібрати більше даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(діапазони IP-адрес і Whois)** вже є за першим посиланням.

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

Ви також можете знайти діапазони IP-адрес організації за допомогою [http://asnlookup.com/](http://asnlookup.com) (сервіс має безкоштовний API).\
Ви можете знайти IP-адресу та ASN домену за допомогою [http://ipv4info.com/](http://ipv4info.com).

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам це дозволено, можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також можете запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти. **Залежно від результатів варто** переглянути цю книгу, щоб дізнатися, як проводити pentest різних сервісів, які можуть працювати на знайдених хостах.\
**Також варто згадати, що можна підготувати списки** стандартних імен користувачів **і** паролів **та спробувати виконати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Ми знаємо всі компанії в межах scope та їхні активи; тепер час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних нижче методів можна також знайти субдомени, і цю інформацію не варто недооцінювати._

Насамперед слід знайти **основний домен** кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, можете спробувати виконати **зворотні DNS lookup** для цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте скористатися DNS-сервером цілі або одним із загальновідомих DNS-серверів (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Для отримання цієї інформації можна також скористатися онлайн-інструментом: [http://ptrarchive.com/](http://ptrarchive.com).\
Для великих діапазонів корисні такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які автоматизують зворотні DNS-запити та збагачення даних.

### **Reverse Whois (loop)**

У записі **whois** можна знайти багато цікавої **інформації**, як-от **назву організації**, **адресу**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **інші активи, пов’язані з компанією**, виконавши **reverse whois lookups за будь-яким із цих полів** (наприклад, знайти інші записи whois, де вказано ту саму електронну адресу).\
Можна скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (вебсайт і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовно** у вебверсії, API платний.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Платно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Платно
- [https://securitytrails.com/](https://securitytrails.com/) - Платно (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Платно (API)

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink) (потрібен ключ API whoxy).\
За допомогою [amass](https://github.com/OWASP/Amass) також можна автоматично шукати записи reverse whois: `amass intel -d tesla.com -whois`

**Зверніть увагу: за допомогою цієї техніки можна знаходити нові доменні імена щоразу, коли ви виявляєте новий домен.**

### **Трекери**

Якщо на двох різних сторінках ви знайдете **той самий ID того самого трекера**, можна припустити, що **обома сторінками** керує **та сама команда**.\
Наприклад, якщо на кількох сторінках ви бачите той самий **ID Google Analytics** або **ID Adsense**.

Є кілька сторінок та інструментів, які дають змогу шукати за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (знаходить пов’язані сайти за спільними аналітичними даними/трекерами)
- [**StackScan**](https://www.stackscan.com) - **Безкоштовний тариф** (вебсайт і API). Дає змогу шукати за будь-яким ресурсом, який обслуговує сайт, а не лише за ID трекерів: шляхом до скрипта, назвою власного пакета або хостом, із якого завантажується ресурс, і показує всі сайти, де він є.

API повертає технологічний стек одного домену, що корисно для підтвердження, чи належить знайдений ресурс тій самій інфраструктурі:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Повертає кожну виявлену технологію разом із її категорією. Пошук пов’язаних активів наразі доступний лише для вебресурсів, а API дає змогу шукати за доменом.

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени та піддомени цілі, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Результати Favihash, використані для виявлення доменів зі спільним хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу виявляти домени, що мають такий самий хеш іконки favicon, як і наша ціль.

![Вивід favihash, використаний для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ось як можна **обчислити хеш favicon** вебсайту (MMH3 від **base64-кодованих** байтів favicon):

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

Також можна масштабно отримувати хеші favicon за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім шукати збіги в Shodan/Censys.

Розглядайте відбитки favicon як зачіпки та перевіряйте їх за додатковими сигналами.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте хеш як індикатор, а не доказ**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисне підроблення.
- **Перевіряйте не лише** `/favicon.ico`: досліджуйте шляхи фреймворків/збірок, файли маніфестів, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані URL-адреси даних і теги HTML `<link rel="icon">`.
- **Статичні ресурси можуть залишатися доступними за елементами керування WAF/SSO/IdP**: запитуйте іконку напряму й перевіряйте `ETag`, `Last-Modified`, перенаправлення та заголовки кешування.
- **Перевіряйте збіги за додатковими сигналами**: порівнюйте заголовок сторінки, хеш HTML/тіла, заголовки, теми/SAN сертифіката TLS, компоненти продукту й відкриті порти.
- **Групуйте за хешем HTML/тіла**: узгоджений шаблон посилює достовірність відбитка; різні шаблони можуть свідчити про типову або спільну іконку.
- **Якщо хеш зустрічається в непов’язаних сигнатурах, портах і продуктах, вважайте це потенційною honeypot-системою або заповнювачем.**
- **Для неоднозначних цілей порівняйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові відповіді хостингу або паркування домену можуть пояснити спільну іконку.
- **Починайте тріаж із правил виявлення Nuclei або публічних наборів даних**, які пов’язують хеші favicon із продуктами та CPE.
- **Пам’ятайте про прогалину в охопленні, орієнтованому на IP**: поверхні за CDN, маршрутизацією SNI, anycast і доступом лише через домен можуть бути відсутні в наборах даних на кшталт Shodan.

### **Авторське право / унікальний рядок**

Шукайте на вебсторінках **рядки, спільні для різних сайтів однієї організації**. **Рядок про авторські права** може бути вдалим прикладом. Потім шукайте цей рядок у **Google**, в інших **браузерах** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Зазвичай налаштовують cron-завдання, наприклад, так:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

щоб поновити всі сертифікати на сервері одночасно. Зіставлення часових міток сертифікатів або позицій у журналах прозорості сертифікатів може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Щоб знайти **домени та субдомени зі спільною інформацією DMARC**, скористайтеся вебсайтом, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструментом, наприклад [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains).\
Інші корисні інструменти: [**spoofcheck**](https://github.com/BishopFox/spoofcheck) і [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Покинутий A-запис може стати доступним, якщо хмарний провайдер повторно призначить IP-адресу. У дослідженні, на яке тут посилаються, описано опортуністичний сценарій: розгорнути інстанс і зіставити його адресу з даними passive DNS; перевіряйте сценарії takeover лише в межах дозволеного обсягу робіт.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні кроки пошуку щоразу, коли знаходите новий домен: кожен результат може виявити додаткові імена сертифікатів, зв’язки passive DNS, збіги favicon і ідентифікатори організацій, які не були помітні для початкового домену.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, якій належить діапазон IP-адрес, можете шукати в Shodan за цими даними: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Можна переглянути **TLS-сертифікат** головної вебсторінки, отримати **назву організації**, а потім шукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **Shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або скористатися інструментом на кшталт [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) — інструмент для пошуку **доменів, пов’язаних** з основним доменом, а також його **субдоменів**. Дуже крутий.

**Passive DNS / Історичні DNS-дані**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які досі резолвляться або які можна захопити. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Пошук вразливостей**

Перевірте, чи можливий [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо ви знайшли **домен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування на вразливості** (за допомогою Nessus або OpenVAS) і [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб, у **цій книзі можна знайти кілька способів їх «атакувати»**.\
_Зверніть увагу, що іноді домен розміщено на IP-адресі, яка не контролюється клієнтом і тому не входить в обсяг робіт. Будьте обережні._

## Субдомени

> Ми знаємо всі компанії в межах обсягу робіт, усі активи кожної компанії та всі домени, пов’язані з компаніями.

Час знайти всі можливі субдомени кожного знайденого домену.

> [!TIP]
> Зверніть увагу, що деякі інструменти й методи пошуку доменів також можуть допомогти знайти субдомени

### **DNS**

Спробуймо знайти **субдомени** в **DNS**-записах. Також варто перевірити можливість **Zone Transfer** (якщо він можливий через вразливість, про це слід повідомити).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Для API та платформ, що охоплюють інфраструктуру, репутацію, записи про витоки й збагачення даних за межами пошуку субдоменів, див. [каталог API для розвідки та аналізу загроз](reconnaissance-and-threat-intelligence-apis.md).

Найшвидший спосіб отримати багато субдоменів — шукати у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте ключі API):


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

Є **інші цікаві інструменти/API**, які, навіть якщо вони не спеціалізуються безпосередньо на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

- [**IP.THC.ORG**](https://ip.thc.org) безкоштовний API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Використовує API [https://sonar.omnisint.io](https://sonar.omnisint.io), щоб отримати субдомени.

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

- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого домену.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Вони сканують вебсайти в пошуках JS-файлів і витягують звідти субдомени.

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

- [**Пошуковик субдоменів Censys**](https://github.com/christophetd/censys-subdomain-finder)

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
- [**activedns.net**](https://activedns.net/)

Цей проєкт безкоштовно надає **всі субдомени, пов’язані з bug-bounty-програмами**. Ви також можете отримати ці дані за допомогою [chaospy](https://github.com/dr-0x0x/chaospy) або переглянути scope, який використовує цей проєкт: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Порівняння** багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **субдомени**, перебираючи DNS-сервери за допомогою можливих назв субдоменів.

Для цього знадобляться **поширені wordlists субдоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Також знадобляться IP-адреси надійних DNS-резолверів. Щоб створити список надійних DNS-резолверів, завантажте їх із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і скористайтеся [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати список. Або скористайтеся цим списком: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): це був перший інструмент для ефективного DNS brute-force. Він дуже швидкий, але схильний давати хибнопозитивні результати.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Цей, здається, використовує лише 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка для `massdns`, написана мовою Go, яка дає змогу перераховувати дійсні субдомени за допомогою активного bruteforce, а також резолвити субдомени з обробкою wildcard-записів і зручним введенням-виведенням.

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

### Другий раунд перебору DNS

Знайшовши піддомени за допомогою відкритих джерел і перебору, можна згенерувати варіанти знайдених піддоменів, щоб спробувати знайти ще більше. Для цього стануть у пригоді кілька інструментів:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Генерує перестановки на основі доменів і піддоменів.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Генерує permutations на основі доменів і піддоменів.
  - **wordlist** із permutations для goaltdns можна знайти [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Для заданих доменів і піддоменів генерує перестановки. Якщо файл із перестановками не вказано, gotator використає власний.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації варіантів subdomains, він також може спробувати їх розв’язати (але краще використовувати інструменти, згадані вище).
  - **wordlist** із варіантами altdns можна отримати [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для створення перестановок, мутацій і змін піддоменів. Цей інструмент підбиратиме результати методом brute force (не підтримує DNS wildcard).
  - Список слів для перестановок dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові ймовірні назви субдоменів** за заданими шаблонами, щоб спробувати виявити більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Вивчає шаблони, схожі на regex, на основі виявлених субдоменів і генерує кандидатні назви для перевірки їхнього розв’язання.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force пошуку субдоменів із надзвичайно простим, але ефективним алгоритмом, що керується відповідями DNS. Він використовує надані вхідні дані, як-от спеціально підібраний wordlist або історичні записи DNS/TLS, щоб точно генерувати більше відповідних доменних імен і циклічно розширювати їх на основі інформації, отриманої під час сканування DNS.

```
echo www | subzuf facebook.com
```

### **Робочий процес виявлення субдоменів**

Приклади workflow від Trickest поєднують OSINT, DNS brute force і етапи перестановок для повторюваного переліку субдоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / віртуальні хости**

Якщо ви знайшли IP-адресу, на якій розміщено **одну або кілька вебсторінок**, що належать субдоменам, можна спробувати **знайти інші субдомени з вебсайтами на цій IP-адресі**: пошукати домени, пов’язані з IP-адресою, в **джерелах OSINT** або **перебором назв доменів VHost на цій IP-адресі**.

#### OSINT

Деякі **VHosts на IP-адресах можна знайти за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері може бути прихований субдомен, спробуйте перебрати можливі назви:

Для VHosts на основі імені перевіряйте заголовок `Host` і використовуйте автокалібрування ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>

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

Іноді трапляються сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/субдомен. У таких випадках можна скористатися цією поведінкою, щоб **виявити** нові **субдомени**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Під час пошуку **субдоменів** стежте, чи не **вказують** вони на якийсь тип **bucket**, і в такому разі [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**підібрати можливі назви bucket і перевірити дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** домену, перевіряючи журнали **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі випадки [**перехоплення субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на **S3 bucket**, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайшли **субдомен з IP-адресою, відмінною** від уже виявлених під час пошуку активів, виконайте **базове сканування на вразливості** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб, у **цій книзі можна знайти деякі способи їх «атакувати»**.\
_Зверніть увагу: іноді субдомен розміщено на IP-адресі, якою клієнт не керує, тож вона не входить до scope. Будьте обережні._

## IP-адреси

На початкових етапах ви могли **виявити діапазони IP-адрес, домени та субдомени**.\
Час **зібрати всі IP-адреси з цих діапазонів**, а також ті, що відповідають **доменам/субдоменам (DNS-запити).**

За допомогою сервісів із наведених нижче **безкоштовних API** можна також знайти **IP-адреси, які раніше використовувалися доменами й субдоменами**. Ці IP-адреси все ще можуть належати клієнту (і допомогти знайти [**обходи CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Також можна перевірити, які домени вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

Виконайте **сканування портів на всіх IP-адресах, що не належать CDN** (оскільки там ви, найімовірніше, не знайдете нічого цікавого). У виявлених запущених службах **можна знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **про сканування хостів.**

## Пошук вебсерверів

> Ми знайшли всі компанії та їхні активи, а також знаємо діапазони IP-адрес, домени й субдомени в межах scope. Час шукати вебсервери.

На попередніх етапах ви, імовірно, уже виконали **recon виявлених IP-адрес і доменів**, тож, можливо, **знайшли всі можливі вебсервери**. Якщо ні, зараз розглянемо кілька **швидких способів пошуку вебсерверів** у межах scope.

Зверніть увагу, що цей етап **орієнтований на пошук вебзастосунків**, тому також слід виконати **сканування на вразливості** та **сканування портів** (**якщо це дозволено** умовами scope).

[**Тут наведено швидкий спосіб**](../pentesting-network/index.html#http-port-discovery) виявити **відкриті порти**, пов’язані з **вебсерверами**, за допомогою **masscan**.\
Ще один зручний інструмент для пошуку вебсерверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Передайте їм список доменів, і вони спробують підключитися до портів 80 (http) і 443 (https). Також можна вказати інші порти для перевірки:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Знімки екрана**

Тепер, коли ви виявили **всі вебсервери** в межах обсягу (серед **IP-адрес** компанії та всіх її **доменів** і **субдоменів**), ви, мабуть, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо просто зі знімків екрана для всіх них. Просто **переглянувши** **головну сторінку**, можна знайти **дивні** кінцеві точки, які з більшою **ймовірністю** можуть бути **вразливими**.

Для цього можна скористатися [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **знімків екрана** — інструмент підкаже, **де ймовірно є вразливості**, а де їх немає.

## Публічні ресурси хмарних платформ

Щоб знайти потенційні хмарні ресурси компанії, **почніть зі списку ключових слів, що ідентифікують цю компанію**. Наприклад, для криптокомпанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться списки слів із **поширеними назвами бакетів**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім на основі цих слів згенеруйте **перестановки** (докладніше див. [**Другий раунд DNS-брутфорсу**](#second-dns-bruteforce-round)).

Для отриманих списків слів можна скористатися такими інструментами, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте: шукаючи хмарні ресурси, потрібно **шукати не лише бакети в AWS**.

### **Пошук вразливостей**

Якщо ви знайдете щось на кшталт **відкритих бакетів або доступних ззовні хмарних функцій**, відкрийте їх і перевірте, що вони пропонують і чи можна ними зловживати.

## Електронні адреси

Маючи **домени** та **субдомени**, що входять до обсягу, ви вже маєте все **необхідне, щоб почати шукати електронні адреси**. Ось **API** та **інструменти**, які найкраще допомагали мені знаходити адреси співробітників компанії:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси стануть у пригоді згодом для **брутфорсу вебвходів і служб автентифікації** (наприклад, SSH). Вони також потрібні для **фішингу**. Крім того, ці API нададуть вам більше **інформації про людину**, якій належить адреса, що корисно для фішингової кампанії.

## Витоки облікових даних

Маючи **домени,** **субдомени** та **електронні адреси**, можна шукати облікові дані, що належать до цих адрес і витекли раніше:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **чинні облікові дані, що витекли**, це буде дуже легкою перемогою.

## Витоки секретів

Витоки облікових даних пов’язані зі зламами компаній, під час яких **конфіденційну інформацію викрадали й продавали**. Однак компанії можуть постраждати й від **інших витоків**, інформація про які відсутня в цих базах даних:

### Витоки на Github

Облікові дані та API можуть потрапити у **публічні репозиторії** **компанії** або **користувачів**, які працюють у цій компанії на Github.\
За допомогою інструмента [**Leakos**](https://github.com/carlospolop/Leakos) можна **завантажити** всі **публічні репозиторії** **організації** та її **розробників**, а потім автоматично запустити на них [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** також можна використовувати для запуску **gitleaks** на всіх **текстових URL-адресах**, переданих йому, оскільки **вебсторінки теж можуть містити секрети**.

#### Github Dorks

На сторінці [GitHub dorks and leaks](github-leaked-secrets.md) наведено потенційні **GitHub dorks** для пошуку в організації.

### Витоки на пастах

Іноді зловмисники або просто працівники **публікують вміст компанії на сайтах для публікації текстів**. Він може містити або не містити **конфіденційну інформацію**, але шукати її там усе одно дуже корисно.\
Інструмент [**Pastos**](https://github.com/carlospolop/Pastos) дає змогу одночасно шукати на понад 80 сайтах для публікації текстів.

### Google Dorks

Старі, але надійні google dorks завжди допомагають знаходити **відкриту інформацію, якій не місце у відкритому доступі**. Проблема лише в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тож можна вибрати 10 улюблених запитів або скористатися **інструментом на кшталт** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зауважте, що інструменти, які мають запускати всю базу даних через звичайний браузер Google, працюватимуть нескінченно, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **чинні облікові дані або API-токени, що витекли**, це буде дуже легкою перемогою.

## Уразливості у відкритому коді

Якщо компанія має **відкритий код**, його можна **проаналізувати** та пошукати в ньому **вразливості**.

**Залежно від мови** можна скористатися різними **інструментами**; див. список [інструментів для аналізу вихідного коду](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також є безкоштовні сервіси, які дають змогу **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія Pentesting вебзастосунків**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься у **вебзастосунках**, тому зараз я розповім про **методологію тестування вебзастосунків**. [**Докладніше про неї можна прочитати тут**](../../network-services-pentesting/pentesting-web/index.html).

Окремо хочу згадати розділ [**Відкриті інструменти автоматизованого сканування вебзастосунків**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): хоча від них не варто очікувати виявлення дуже серйозних вразливостей, вони стануть у пригоді у **робочих процесах, щоб отримати початкову інформацію про вебзастосунки.**

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову розвідку**. Так, вона базова, адже можна провести набагато більше розвідки (пізніше розглянемо ще кілька прийомів).

Отже, ви вже:

1. Знайшли всі **компанії** в межах обсягу
2. Знайшли всі **ресурси** компаній (і виконали сканування на вразливості, якщо це входить до обсягу)
3. Знайшли всі **домени** компаній
4. Знайшли всі **субдомени** доменів (чи є серед них субдомени, які можна перехопити?)
5. Знайшли всі **IP-адреси** (як із **CDN**, так і без них) у межах обсягу.
6. Знайшли всі **вебсервери** та зробили їхні **знімки екрана** (чи є щось дивне, варте ретельнішої уваги?)
7. Знайшли всі **потенційні публічні хмарні ресурси** компанії.
8. **Електронні адреси**, **витоки облікових даних** і **витоки секретів**, які можуть забезпечити вам **легку перемогу**.
9. **Провели Pentesting усіх знайдених вебсайтів**

## **Інструменти для повністю автоматизованої розвідки**

Є кілька інструментів, які виконують частину описаних дій для заданого обсягу.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — трохи застарілий і не оновлюється

## References

- [1] [Jason Haddix – Методологія мисливця за багами v4.0: етап розвідки](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Про фавікони: від іконок браузера до розвідки поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Використання favicon.ico для BugBounties, OSINT та не тільки](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Виявлення доменів за допомогою атаки на часову кореляцію даних Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Пасивне перехоплення: виявлення (та імітація) дорогої кампанії з перехоплення субдоменів](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: унікальний метод переліку субдоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Повний робочий процес виявлення субдоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Автоматизований брутфорс субдоменів за допомогою робочого процесу Trickest, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Знімок екрана з результатом favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
