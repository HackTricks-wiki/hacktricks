# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

> Отже, вам сказали, що все, що належить певній компанії, входить у scope, і ви хочете з’ясувати, чим насправді володіє ця компанія.

Мета цього етапу — знайти всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми:<sup>[[1]](#references)</sup>

1. Знайдемо придбання головної компанії — це дасть нам компанії, що входять у scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам діапазони IP-адрес, якими володіє кожна компанія.
3. Використаємо зворотний пошук Whois, щоб знайти інші записи (назви організацій, домени...), пов’язані з першим записом (це можна робити рекурсивно).
4. Використаємо інші методи, наприклад фільтри shodan `org` і `ssl`, щоб знайти інші активи (прийом із `ssl` можна застосовувати рекурсивно).

### **Придбання**

Перш за все потрібно з’ясувати, **якими іншими компаніями володіє головна компанія**.\
Один із варіантів — перейти на [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** й **натиснути** "**acquisitions**". Там ви побачите інші компанії, які придбала головна компанія.\
Інший варіант — перейти на сторінку **Wikipedia** головної компанії та пошукати **acquisitions**.\
Для публічних компаній перевірте документи **SEC/EDGAR**, сторінки **для інвесторів** або місцеві реєстри компаній (наприклад, **Companies House** у Великій Британії).\
Щоб дізнатися про глобальні корпоративні структури та дочірні компанії, спробуйте **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базу даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Гаразд, на цьому етапі ви маєте знати всі компанії, що входять у scope. З’ясуймо, як знайти їхні активи.

### **ASN**

Номер автономної системи (**ASN**) — це **унікальний номер**, який **Internet Assigned Numbers Authority (IANA)** призначає **автономній системі** (AS).\
**AS** складається з **блоків** **IP-адрес**, для яких визначено окрему політику доступу до зовнішніх мереж. Такою системою керує одна організація, але вона може складатися з кількох операторів.

Варто з’ясувати, чи **призначено компанії ASN**, щоб знайти її **діапазони IP-адрес**. Було б корисно провести **перевірку на вразливості** всіх **хостів** у **scope** і **пошукати домени** серед цих IP-адрес.\
Можна **шукати** за **назвою** компанії, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть бути корисними для збору додаткових даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(діапазони IP-адрес і Whois)** вже є в першому посиланні.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Також enumeration у [**BBOT**](https://github.com/blacklanternsecurity/bbot) автоматично агрегує та підсумовує ASN наприкінці сканування.

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

Ви також можете знайти діапазони IP-адрес організації за допомогою [ASNLookup](https://asnlookup.com/), який має обмежений безкоштовний тариф API.

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам це дозволено, можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) для всіх хостів.\
Також можна запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти **і, залежно від результатів,** переглянути цю книгу, щоб дізнатися, як проводити pentest різних можливих сервісів.\
**Також варто згадати, що можна підготувати списки** типових імен користувачів **і** паролів **та спробувати** брутфорсити сервіси за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; час знайти домени в межах scope.

_Зверніть увагу, що за допомогою описаних далі методів можна також знаходити субдомени, і цю інформацію не слід недооцінювати._

Перш за все, потрібно знайти **основний домен** (або домени) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Reverse DNS**

Оскільки ви знайшли всі діапазони IP-адрес доменів, можна спробувати виконати **зворотні DNS-запити** до цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або відомий DNS-сервер (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Для отримання цієї інформації можна також скористатися [SecurityTrails](https://securitytrails.com/), хоча для доступу до історичних даних DNS потрібен платний план.\
Для великих діапазонів корисні такі інструменти, як [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які автоматизують зворотні запити та доповнення даних.

### **Reverse Whois (loop)**

У записі **whois** можна знайти багато цікавої **інформації**, як-от **назву організації**, **адресу**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **більше активів, пов’язаних із компанією**, виконавши **зворотний пошук whois за будь-яким із цих полів** (наприклад, знайти інші реєстраційні записи whois, де вказано ту саму електронну адресу).\
Можна скористатися такими онлайн-інструментами:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (вебсайт і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** вебінтерфейс; API платний.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Платний
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Не безкоштовно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Не безкоштовно
- [https://securitytrails.com/](https://securitytrails.com/) - Обмежений безкоштовний доступ до API для поточних даних DNS/субдоменів; для доступу до історичних даних і зворотного пошуку потрібен платний план.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 безкоштовних кредитів API після реєстрації; подальше використання платне.

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен ключ API whoxy).\
За допомогою [amass](https://github.com/owasp-amass/amass) можна також автоматично виконувати пошук зворотних записів whois: `amass intel -d tesla.com -whois`

**Зауважте, що цю техніку можна використовувати для пошуку нових доменних імен щоразу, коли ви знаходите новий домен.**

### **Trackers**

Якщо на двох різних сторінках знайти **той самий ID того самого трекера**, можна припустити, що **обома сторінками** керує **та сама команда**.\
Наприклад, якщо на кількох сторінках виявлено той самий **ID Google Analytics** або той самий **ID Adsense**.

Є кілька сайтів та інструментів, які дають змогу шукати за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Платний** вебсервіс та API ([ціни](https://www.stackscan.com/pricing)); безкоштовний план наразі не пропонується. Шукайте за будь-яким ресурсом, що обслуговується, а не лише за ID трекерів: шляхом до скрипту, назвою пакета, розміщеного на власному сервері, або хостом, з якого завантажується ресурс. У результатах будуть усі сайти, де він використовується.

API повертає стек для одного домену, що корисно для перевірки, чи належить знайдений ресурс до тієї самої інфраструктури:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Повертає кожну виявлену технологію з її категорією. Пошук пов’язаних активів наразі доступний лише для вебресурсів, а API підтримує пошук за доменом.

### **Favicon**

Чи знали ви, що можна знайти пов’язані домени й субдомени цілі, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Результати Favihash, використані для виявлення доменів зі спільним хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу знаходити домени, які мають такий самий хеш іконки favicon, як і наша ціль.

![Вивід favihash, використаний для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як pivot у Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Так можна **обчислити хеш favicon** вебсайту (MMH3 над **base64-кодованими** байтами favicon):

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

Також можна масово отримувати хеші favicon за допомогою [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), а потім шукати збіги в Shodan/Censys.

Використовуйте відбитки favicon як зачіпки й перевіряйте їх за супутніми сигналами.<sup>[[3]](#references)[[4]](#references)</sup>

- **Вважайте хеш індикатором, а не доказом**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: оглядайте шляхи framework/build, файли manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URL і теги HTML `<link rel="icon">`.
- **Статичні ресурси можуть залишатися доступними за WAF/SSO/IdP-контролями**: запитуйте іконку напряму й перевіряйте `ETag`, `Last-Modified`, перенаправлення та заголовки кешування.
- **Перевіряйте збіги за супутніми сигналами**: порівнюйте заголовок сторінки, хеш HTML/тіла, заголовки, теми/SAN сертифіката TLS, компоненти продукту й відкриті порти.
- **Групуйте за хешем HTML/тіла**: узгоджений шаблон посилює достовірність відбитка; різні шаблони можуть указувати на загальну або спільну іконку.
- **Вважайте хеш, що трапляється в непов’язаних сигнатурах, портах і продуктах, потенційною honeypot-іконкою або заглушкою.**
- **Для неоднозначних цілей порівняйте реальну сторінку з неіснуючим шляхом**, наприклад `/_favicon_probe_<8-hex>`; однакові відповіді хостингу чи паркування домену можуть пояснити спільну іконку.
- **Для початкового аналізу використовуйте правила виявлення Nuclei або публічні набори даних**, які пов’язують хеші favicon із продуктами та CPE.
- **Пам’ятайте про прогалину в охопленні, орієнтованому на IP**: поверхні за CDN, із маршрутизацією SNI, anycast і доступом лише за доменом можуть бути відсутні в наборах даних на кшталт Shodan.

### **Авторське право / Унікальний рядок**

Шукайте на вебсторінках **рядки, які можуть повторюватися на різних сайтах однієї організації**. Гарним прикладом може бути **рядок авторського права**. Потім шукайте цей рядок у **Google**, в інших **браузерах** або навіть у **Shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Часто налаштовують cron job на кшталт 天天彩票中奖

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

щоб одночасно оновити всі сертифікати на сервері. Зіставлення часових позначок сертифікатів або їхніх позицій у журналах certificate transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація DMARC пошти

Можна скористатися вебсайтом, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструментом, наприклад [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), щоб знайти **домени й піддомени зі спільною інформацією DMARC**.\
Ще один корисний сервіс — [**dmarcian**](https://dmarcian.com/).

### **Пасивне захоплення**

Забутий запис A може стати доступним, якщо хмарний провайдер повторно призначить IP-адресу. У згаданому дослідженні описано опортуністичний робочий процес: створення екземпляра та зіставлення його адреси з даними passive DNS; перевіряйте сценарії захоплення лише в межах дозволеної області тестування.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні кроки пошуку щоразу, коли знаходите новий домен: кожен результат може виявити додаткові імена сертифікатів, зв’язки passive DNS, збіги favicon і ідентифікатори організації, яких не було видно за початковим доменом.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Ви вже знаєте назву організації, якій належить діапазон IP-адрес. У Shodan можна шукати за цими даними, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Можна переглянути **TLS-сертифікат** головної вебсторінки, отримати **назву організації**, а потім пошукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **Shodan**, за допомогою фільтра: `ssl:"Tesla Motors"` або скористатися інструментом на кшталт [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)— це неймовірний інструмент для пошуку **доменів, пов’язаних** з основним доменом, і їхніх **піддоменів**.

**Passive DNS / історичний DNS**

Дані passive DNS чудово підходять для пошуку **старих і забутих записів**, які досі резолвляться або які можна захопити. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Пошук вразливостей**

Перевірте можливість [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це досить дешево) і повідомте компанію.

Якщо знайдете **домен з IP-адресою, відмінною** від уже виявлених під час пошуку активів, слід виконати **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб у **цій книзі можна знайти кілька способів їх «атакувати»**.\
_Зверніть увагу: іноді домен розміщено на IP-адресі, якою клієнт не керує, тож він не входить до області тестування. Будьте обережні._

## Піддомени

> Нам відомі всі компанії в області тестування, усі активи кожної компанії та всі пов’язані з ними домени.

Час знайти всі можливі піддомени кожного виявленого домену.

> [!TIP]
> Зверніть увагу: деякі інструменти й методи пошуку доменів також можуть допомогти знайти піддомени

### **DNS**

Спробуймо знайти **піддомени** в записах **DNS**. Також варто перевірити можливість **Zone Transfer** (якщо вона доступна через уразливість, про це слід повідомити).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Щоб отримати доступ до API та платформ, що охоплюють інфраструктуру, репутацію, записи про витоки даних і збагачення інформації поза пошуком субдоменів, див. [каталог API для розвідки та аналізу загроз](reconnaissance-and-threat-intelligence-apis.md).

Найшвидший спосіб отримати багато субдоменів — шукати їх у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте ключі API):

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

Є **інші цікаві інструменти/API**, які, хоч і не спеціалізуються безпосередньо на пошуку субдоменів, можуть стати в пригоді для їх пошуку, наприклад:

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

- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl для будь-якого домену.

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

- [**Засіб пошуку субдоменів Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) надає обмежений безкоштовний доступ до API для отримання поточних даних DNS і субдоменів; для доступу до історичних даних DNS/IP потрібен платний тариф.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Цей проєкт безкоштовно надає **всі субдомени, пов’язані з bug-bounty програмами**. Отримати ці дані можна також за допомогою [chaospy](https://github.com/Moaaz-0x/chaospy) або переглянути scope, який використовує цей проєкт: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Порівняння** багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **субдомени**, виконуючи brute-force DNS-серверів із можливими назвами субдоменів.

Для цього вам знадобляться **списки слів із поширеними назвами субдоменів**, наприклад:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Також знадобляться IP-адреси надійних DNS-резолверів. Щоб створити список надійних DNS-резолверів, завантажте їх зі сторінки [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і скористайтеся [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), щоб відфільтрувати їх. Або скористайтеся списком: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): це був перший інструмент для ефективного DNS brute-force. Він дуже швидкий, але схильний давати хибнопозитивні результати.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Як на мене, цей інструмент використовує лише 1 резолвер.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка для `massdns`, написана на go, яка дає змогу виявляти дійсні субдомени за допомогою активного brute force, а також розв’язувати субдомени з обробкою wildcard і зручною підтримкою введення-виведення.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Він також використовує `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) використовує asyncio для асинхронного перебору доменних імен.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Другий раунд DNS Brute-Force

Знайшовши субдомени за допомогою відкритих джерел і brute-force, можна згенерувати варіанти знайдених субдоменів, щоб спробувати знайти ще більше. Для цього стануть у пригоді кілька інструментів:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Генерує перестановки на основі доменів і субдоменів.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Створює перестановки на основі доменів і субдоменів.
  - **wordlist** для перестановок goaltdns можна отримати [**тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Отримує домени та субдомени й генерує перестановки. Якщо файл із перестановками не вказано, gotator використовуватиме власний.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати їх розв’язати (але краще скористатися інструментами, згаданими вище).
  - **wordlist** із перестановками altdns можна знайти [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для створення перестановок, мутацій і змін субдоменів. Цей інструмент виконує brute force результату (не підтримує DNS wildcard).
  - Список слів для перестановок dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні назви субдоменів** за заданими шаблонами, щоб спробувати виявити більше субдоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Вивчає шаблони на кшталт regex на основі виявлених субдоменів і генерує кандидатні назви для перевірки.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force пошуку субдоменів, поєднаний із надзвичайно простим, але ефективним алгоритмом, що керується відповідями DNS. Він використовує наданий набір вхідних даних, як-от спеціально підібраний wordlist або історичні записи DNS/TLS, щоб точно генерувати більше відповідних доменних імен і циклічно розширювати цей набір на основі інформації, отриманої під час DNS-сканування.

```
echo www | subzuf facebook.com
```

### **Робочий процес виявлення субдоменів**

Приклади workflow від Trickest поєднують OSINT, DNS brute force і етапи permutation для повторюваного переліку субдоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Якщо ви знайшли IP-адресу, на якій розміщено **одну чи кілька вебсторінок**, що належать субдоменам, можна спробувати **знайти інші субдомени з вебсайтами на цій IP-адресі**: пошукати домени, пов’язані з цією IP-адресою, у **джерелах OSINT** або **виконати brute force назв доменів VHost на цій IP-адресі**.

#### OSINT

Знайти деякі **VHosts на IP-адресах можна за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що вебсервер може приховувати субдомен, спробуйте виконати brute force:

Для vhost на основі імені перебирайте значення заголовка `Host` і використовуйте автокалібрування ffuf, щоб відфільтрувати відповідь за замовчуванням.<sup>[[2]](#references)</sup>

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

Іноді трапляються сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ вказано дійсний домен/субдомен. У таких випадках цією поведінкою можна скористатися, щоб **виявити** нові **субдомени**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute Force бакетів**

Під час пошуку **субдоменів** стежте, чи **вказують** вони на якийсь тип **бакета**; якщо так, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Також, оскільки на цьому етапі вам будуть відомі всі домени в межах scope, спробуйте [**підібрати можливі назви бакетів методом brute force і перевірити дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Моніторинг**

Ви можете **відстежувати** створення **нових субдоменів** для домену, моніторячи логи **Certificate Transparency**, як це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте можливі випадки [**перехоплення субдоменів**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на якийсь **S3 bucket**, [**перевірте дозволи**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Якщо ви знайдете **субдомен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів у **цій книзі можна знайти деякі прийоми для їхньої «атаки»**.\
_Зверніть увагу, що іноді субдомен розміщений на IP-адресі, яка не контролюється клієнтом і тому не входить до scope. Будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти деякі діапазони IP-адрес, домени та субдомени**.\
Настав час **зібрати всі IP-адреси з цих діапазонів**, а також IP-адреси для **доменів/субдоменів (DNS-запити).**

За допомогою таких сервісів можна також знайти **IP-адреси, які раніше використовувалися доменами та субдоменами**. Ці IP-адреси все ще можуть належати клієнту (і допомогти вам знайти [**способи обходу CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (для доступу до історичних даних DNS/IP потрібен платний план)

Також можна перевірити, які домени вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Скануйте порти всіх IP-адрес, які не належать CDN** (оскільки, найімовірніше, там не знайдеться нічого цікавого). У виявлених запущених сервісах ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **про сканування хостів.**

## Пошук вебсерверів

> Ми знайшли всі компанії та їхні активи, а також знаємо діапазони IP-адрес, домени й субдомени в межах scope. Настав час шукати вебсервери.

На попередніх етапах ви, імовірно, вже виконали **recon виявлених IP-адрес і доменів**, тож, можливо, **вже знайшли всі потенційні вебсервери**. Однак, якщо цього не сталося, зараз розглянемо кілька **швидких прийомів пошуку вебсерверів** у межах scope.

Зверніть увагу, що цей процес **орієнтований на пошук вебзастосунків**, тому також слід виконати **сканування вразливостей** і **портів** (**якщо це дозволено** умовами scope).

[**Тут наведено швидкий спосіб**](../pentesting-network/index.html#http-port-discovery) виявити **відкриті порти**, пов’язані з **вебсерверами**, за допомогою [**masscan**.**](../pentesting-network/index.html#http-port-discovery)\
Ще один зручний інструмент для пошуку вебсерверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) та [**httpx**](https://github.com/projectdiscovery/httpx). Передайте їм список доменів, і вони спробують під’єднатися до портів 80 (http) і 443 (https). Крім того, можна вказати інші порти для перевірки:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Знімки екрана**

Тепер, коли ви виявили **всі вебсервери** в межах scope (серед **IP-адрес** компанії та всіх її **доменів** і **субдоменів**), ви, мабуть, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі знімків екрана всіх серверів. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** кінцеві точки, які більш **схильні** до **вразливостей**.

Для цього можна скористатися [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **знімків екрана** й визначення, **де ймовірно є вразливості**, а де їх немає.

## Публічні хмарні ресурси

Щоб знайти потенційні хмарні ресурси, що належать компанії, варто **почати зі списку ключових слів, які її ідентифікують**. Наприклад, для криптокомпанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться списки слів із **поширеними словами, що використовуються в назвах buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім за допомогою цих слів слід згенерувати **перестановки** (докладніше див. [**Другий раунд DNS brute-force**](#second-dns-bruteforce-round)).

Для отриманих списків слів можна скористатися такими інструментами, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте: шукаючи Cloud Assets, слід ш**укай**ти не лише buckets в AWS.

### **Пошук вразливостей**

Якщо ви знайдете щось на кшталт **відкритих buckets або доступних ззовні cloud functions**, слід **звернутися до них** і спробувати з’ясувати, що вони пропонують і чи можна ними зловживати.

## Електронні адреси

Маючи **домени** та **субдомени** в межах scope, ви вже маєте все необхідне, щоб **почати пошук електронних адрес**. Ось **API** та **інструменти**, які найкраще допомагали мені знаходити адреси електронної пошти компаній:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси стануть у пригоді згодом для **brute-force веблогінів і сервісів автентифікації** (наприклад, SSH). Вони також потрібні для **phishing**. Крім того, ці API нададуть ще більше **інформації про людину**, якій належить адреса, що стане у пригоді для phishing-кампанії.

## Витоки облікових даних

Маючи **домени,** **субдомени** та **електронні адреси**, можна почати шукати облікові дані, які раніше витекли для цих адрес:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо знайдете **дійсні облікові дані, що витекли**, це буде легкою перемогою.

## Витоки секретів

Витоки облікових даних пов’язані зі зламами компаній, під час яких **конфіденційну інформацію зливали й продавали**. Однак компанії можуть постраждати й від **інших витоків**, інформація про які відсутня в цих базах даних:

### Витоки на Github

Облікові дані та API можуть витекти в **публічні репозиторії** **компанії** або **користувачів**, які працюють у цій компанії на Github.\
За допомогою інструмента [**Leakos**](https://github.com/carlospolop/Leakos) можна **завантажити** всі **публічні репозиторії** **організації** та її **розробників** і автоматично запустити по них [**gitleaks**](https://github.com/gitleaks/gitleaks).

**Leakos** також можна використовувати для запуску **gitleaks** на всіх переданих йому **текстових URL-адресах**, оскільки **вебсторінки теж можуть містити секрети**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks and leaks](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Витоки на Paste-сайтах

Іноді зловмисники або працівники просто **публікують матеріали компанії на paste-сайтах**. Там може бути або не бути **конфіденційна інформація**, але її варто пошукати.\
За допомогою інструмента [**Pastos**](https://github.com/carlospolop/Pastos) можна одночасно шукати на понад 80 paste-сайтах.

### Google Dorks

Старі, але перевірені Google dorks завжди корисні для пошуку **відкритої інформації, якої там не мало б бути**. Проблема лише в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тож можна вибрати свої улюблені 10 або скористатися **інструментом на кшталт** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зауважте: інструменти, що намагаються перевірити всю базу даних через звичайний браузер Google, ніколи не завершать роботу, оскільки Google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо знайдете **дійсні облікові дані або API-токени, що витекли**, це буде легкою перемогою.

## Вразливості у публічному коді

Якщо ви виявили, що компанія має **open-source код**, його можна **проаналізувати** й пошукати в ньому **вразливості**.

**Залежно від мови** можна скористатися різними **інструментами**; див. список [інструментів для аналізу вихідного коду](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також є безкоштовні сервіси для **сканування публічних репозиторіїв**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять bug hunters, міститься у **вебзастосунках**, тож на цьому етапі я хочу розповісти про **методологію тестування вебзастосунків**. [**Докладніше про неї можна прочитати тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners): хоча не варто очікувати, що ці інструменти знайдуть дуже критичні вразливості, вони стануть у пригоді у **workflow для отримання початкової інформації про вебресурси**.

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову розвідку**. Так, вона базова, адже можна провести ще багато розвідки (пізніше розглянемо додаткові прийоми).

Отже, ви вже:

1. Знайшли всі **компанії** в межах scope
2. Знайшли всі **ресурси**, що належать компаніям (і виконали сканування на вразливості, якщо це дозволено scope)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **субдомени** доменів (чи можливий subdomain takeover?)
5. Знайшли всі **IP-адреси** в межах scope (як із **CDN**, так і без них).
6. Знайшли всі **вебсервери** й зробили їхні **знімки екрана** (чи є щось дивне, що варте детальнішого вивчення?)
7. Знайшли всі **потенційні публічні хмарні ресурси**, що належать компанії.
8. Знайшли **електронні адреси**, **витоки облікових даних** і **витоки секретів**, які можуть забезпечити **легку перемогу**.
9. Провели **Pentesting усіх знайдених вебресурсів**

## **Інструменти для автоматичної повної розвідки**

Існує кілька інструментів, які виконують частину запропонованих дій для заданого scope.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — дещо застарілий і не оновлюється

## References

- [1] [Jason Haddix — Методологія bug hunter’а v4.0: розвідка](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf — HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) — Про favicons: від значків браузера до розвідки поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) — Використання favicon.ico для BugBounties, OSINT та іншого](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov — Виявлення доменів за допомогою атаки на часову кореляцію даних Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) — Пасивний takeover: виявлення (та імітація) дорогої кампанії з subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet — Regulator: унікальний метод переліку субдоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop — Повний workflow виявлення субдоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop — Повний brute-force пошук субдоменів за допомогою автоматизованого workflow Trickest, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter — Знімок екрана з результатом favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
