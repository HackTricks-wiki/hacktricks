# Методологія зовнішньої розвідки

{{#include ../../banners/hacktricks-training.md}}

## Виявлення активів

Категоризований список додаткових проєктів з OSINT і пошуку в Інтернеті дивіться в розділі [Сторонні інструменти та ресурси](../third-party-tools-and-resources.md#osint).

> Вам сказали, що все, що належить певній компанії, входить до scope, і ви хочете з’ясувати, чим ця компанія насправді володіє.

Мета цього етапу — визначити всі **компанії, що належать головній компанії**, а потім усі **активи** цих компаній. Для цього ми:<sup>[[1]](#references)</sup>

1. Знайдемо придбання головної компанії — це дасть нам перелік компаній у scope.
2. Знайдемо ASN (якщо є) кожної компанії — це дасть нам IP-діапазони, що належать кожній компанії.
3. Скористаємося пошуком reverse whois, щоб знайти інші записи (назви організацій, домени...), пов’язані з першим записом (це можна робити рекурсивно).
4. Скористаємося іншими методами, як-от фільтрами shodan `org` і `ssl`, щоб шукати інші активи (прийом із `ssl` можна застосовувати рекурсивно).

Щоб дізнатися про поетапну передачу знайдених субдоменів для HTTP-краулінгу та виявлення портів, дивіться [Методологію pentesting](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Придбання**

Перш за все, потрібно з’ясувати, **якими іншими компаніями володіє головна компанія**.\
Можна відвідати [https://www.crunchbase.com/](https://www.crunchbase.com), **знайти** **головну компанію** та **натиснути** "**acquisitions**". Там ви побачите інші компанії, придбані нею.\
Також можна відвідати сторінку головної компанії у **Wikipedia** та пошукати **acquisitions**.\
Для публічних компаній перевірте документи **SEC/EDGAR**, сторінки **відносин з інвесторами** або місцеві корпоративні реєстри (наприклад, **Companies House** у Великій Британії).\
Для отримання відомостей про глобальні корпоративні структури та дочірні компанії скористайтеся **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) і базою даних **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Гаразд, на цьому етапі ви маєте знати всі компанії у scope. З’ясуймо, як знайти їхні активи.

### **ASN**

Номер автономної системи (**ASN**) — це **унікальний номер**, який **Internet Assigned Numbers Authority (IANA)** призначає **автономній системі** (AS).\
**AS** складається з **блоків** **IP-адрес**, для яких визначено окрему політику доступу до зовнішніх мереж. Ними керує одна організація, але вони можуть охоплювати кількох операторів.

Варто з’ясувати, чи має **компанія призначений ASN**, щоб знайти її **IP-діапазони**. Також варто провести **перевірку вразливостей** усіх **хостів** у **scope** і **пошукати домени** в межах цих IP-адрес.\
Можна шукати за **назвою** компанії, **IP-адресою** або **доменом** на [**https://bgp.he.net/**](https://bgp.he.net) **або** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Залежно від регіону, у якому розташована компанія, ці посилання можуть допомогти зібрати більше даних:** [**AFRINIC**](https://www.afrinic.net) **(Африка),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Північна Америка),** [**APNIC**](https://www.apnic.net) **(Азія),** [**LACNIC**](https://www.lacnic.net) **(Латинська Америка),** [**RIPE NCC**](https://www.ripe.net) **(Європа). Утім, імовірно, вся** корисна інформація **(IP-діапазони та Whois)** уже є за першим посиланням.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Також [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** перерахування автоматично агрегує та підсумовує ASN наприкінці сканування.

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

Ви також можете знайти діапазони IP організації за допомогою [ASNLookup](https://asnlookup.com/), який має обмежений безкоштовний рівень API.

### **Пошук вразливостей**

На цьому етапі ми знаємо **всі активи в межах scope**, тож, якщо вам це дозволено, можете запустити **сканер вразливостей** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) на всіх хостах.\
Також можете запустити [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **або скористатися такими сервісами, як** Shodan, Censys чи ZoomEye, **щоб знайти** відкриті порти **і, залежно від результатів, переглянути цю книгу, щоб дізнатися, як провести pentest різних можливих запущених сервісів.**\
**Також варто згадати, що можна підготувати списки стандартних імен користувачів і паролів та спробувати** bruteforce сервісів за допомогою [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Домени

> Ми знаємо всі компанії в межах scope та їхні активи; час знайти домени в межах scope.

_Зверніть увагу, що за допомогою наведених далі запропонованих методів можна також знайти субдомени, і цю інформацію не слід недооцінювати._

Перш за все, потрібно знайти **основний домен** (домени) кожної компанії. Наприклад, для _Tesla Inc._ це буде _tesla.com_.

### **Зворотний DNS**

Оскільки ви знайшли всі діапазони IP доменів, можна спробувати виконати **зворотні DNS-запити** до цих **IP-адрес, щоб знайти більше доменів у межах scope**. Спробуйте використати DNS-сервер жертви або загальновідомий DNS-сервер (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Щоб це працювало, адміністратор має вручну ввімкнути PTR.\
Також для отримання цієї інформації можна скористатися [SecurityTrails](https://securitytrails.com/), хоча для доступу до історичних даних DNS потрібен платний план.\
Для великих діапазонів корисні інструменти на кшталт [**massdns**](https://github.com/blechschmidt/massdns) і [**dnsx**](https://github.com/projectdiscovery/dnsx), які автоматизують зворотні DNS-запити та доповнення даних.

### **Зворотний Whois (цикл)**

У **whois** можна знайти багато цікавої **інформації**, наприклад **назву організації**, **адресу**, **електронні адреси**, номери телефонів... Але ще цікавіше те, що можна знайти **інші активи, пов’язані з компанією**, виконавши **зворотний пошук Whois за будь-яким із цих полів** (наприклад, знайти інші реєстраційні записи Whois, у яких вказана та сама електронна адреса).\
Можна скористатися онлайн-інструментами, наприклад:

- [https://ip.thc.org/](https://ip.thc.org/) - **Безкоштовно** (вебсайт і API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Безкоштовно**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Безкоштовно**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Безкоштовний** вебінтерфейс; API платний.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Платно
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Не безкоштовно (лише **100 безкоштовних** пошуків)
- [https://www.domainiq.com/](https://www.domainiq.com) - Не безкоштовно
- [https://securitytrails.com/](https://securitytrails.com/) - Обмежений безкоштовний доступ до API для поточних даних DNS і субдоменів; для історичних даних і зворотного пошуку потрібен платний план.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 безкоштовних кредитів API після реєстрації; надалі послуга платна.

Це завдання можна автоматизувати за допомогою [**DomLink** ](https://github.com/vysecurity/DomLink)(потрібен ключ API whoxy).\
Також можна автоматично шукати записи Whois у зворотному напрямку за допомогою [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Зауважте, що цю техніку можна використовувати, щоб знаходити нові доменні імена щоразу, коли ви виявляєте новий домен.**

### **Трекери**

Якщо на двох різних сторінках знайти **однаковий ID того самого трекера**, можна припустити, що **обома сторінками** **керує та сама команда**.\
Наприклад, якщо на кількох сторінках ви бачите однаковий **ID Google Analytics** або **ID Adsense**.

Існують сторінки та інструменти, що дають змогу шукати за цими та іншими трекерами:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Платна** вебслужба та API ([ціни](https://www.stackscan.com/pricing)); безкоштовний план наразі не пропонується. Шукайте збіги за будь-яким ресурсом, що завантажується, а не лише за ID трекерів: шляхом до скрипту, назвою розміщеного на власному сервері пакета або доменом, із якого завантажується ресурс. У результатах буде кожен сайт, що його використовує.

API повертає технологічний стек для одного домену — це допомагає перевірити, чи належить потенційно пов’язаний ресурс до тієї самої інфраструктури:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Повертає кожну виявлену технологію разом із її категорією. Asset pivoting наразі працює лише з вебресурсами, API дає змогу виконувати пошук за доменом.

### **Favicon**

Чи знали ви, що можна знаходити пов’язані домени й субдомени нашої цілі, шукаючи однаковий хеш іконки favicon? Саме це робить інструмент [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py), створений [@m4ll0k2](https://twitter.com/m4ll0k2). Ось як ним користуватися:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Результати Favihash, використані для виявлення доменів зі спільним хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Простіше кажучи, favihash дає змогу виявити домени, що мають такий самий хеш іконки favicon, як і наша ціль.

![Вивід favihash, використаний для виявлення доменів із таким самим хешем favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Використовуйте відомий хеш favicon як точку відліку для Shodan або FOFA, щоб знайти інші відкриті екземпляри тієї самої технології.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Ось як можна **обчислити хеш favicon** вебсайту (MMH3 над **base64-кодованими** байтами favicon):

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

Розглядайте відбитки favicon як зачіпки та перевіряйте їх за допомогою супутніх сигналів.<sup>[[3]](#references)[[4]](#references)</sup>

- **Розглядайте хеш як індикатор, а не доказ**: MMH3 компактний; можливі колізії, повторне використання іконок і навмисна підміна.
- **Перевіряйте не лише** `/favicon.ico`: вивчайте шляхи framework/build, файли manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, вбудовані data URL і HTML-теги `<link rel="icon">`.
- **Статичні assets можуть залишатися доступними за WAF/SSO/IdP-контролями**: запитуйте іконку безпосередньо та перевіряйте `ETag`, `Last-Modified`, перенаправлення й cache-заголовки.
- **Перевіряйте збіги за супутніми сигналами**: порівнюйте title, HTML/body-хеш, заголовки, теми/SAN TLS-сертифікатів, компоненти продукту й відкриті порти.
- **Групуйте за HTML/body-хешем**: однаковий шаблон посилює відбиток; різні шаблони можуть свідчити про загальну або спільну іконку.
- **Якщо хеш зустрічається в різних, не пов’язаних між собою сигнатурах, портах і продуктах, розглядайте це як можливий honeypot або заповнювач.**
- **Для неоднозначних цілей порівняйте реальну сторінку зі шляхом, якого не існує**, наприклад `/_favicon_probe_<8-hex>`; однакові відповіді хостингу або паркування домену можуть пояснити спільну іконку.
- **Для початкового сортування використовуйте правила виявлення Nuclei або публічні набори даних**, що зіставляють хеші favicon із продуктами та CPE.
- **Пам’ятайте про прогалини в охопленні, зумовлені орієнтацією на IP**: поверхні за CDN, із маршрутизацією SNI, anycast і лише доменним доступом можуть бути відсутні в наборах даних на кшталт Shodan.

### **Авторське право / Унікальний рядок**

Шукайте на вебсторінках **рядки, які можуть траплятися на різних сайтах однієї організації**. Хорошим прикладом може бути **рядок про авторське право**. Потім шукайте цей рядок у **google**, в інших **браузерах** або навіть у **shodan**: `shodan search http.html:"Copyright string"`

### **Час CRT**

Часто налаштовують завдання cron, наприклад:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

для одночасного поновлення всіх сертифікатів на сервері. Зіставлення часових позначок сертифікатів або позицій у журналах certificate transparency може виявити пов’язані домени.<sup>[[6]](#references)</sup>

Також використовуйте журнали **certificate transparency** безпосередньо:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Інформація Mail DMARC

Щоб знайти **домени й піддомени, які використовують однакову інформацію DMARC**, можна скористатися вебсайтом, наприклад [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), або інструментом на зразок [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains).\
Ще один корисний сервіс — [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Забутий запис A може стати доступним, якщо cloud-провайдер повторно призначить IP-адресу. У наведеному дослідженні показано opportunistic workflow: створити інстанс і зіставити його адресу з даними passive DNS; перевіряйте сценарії takeover лише в межах дозволеної сфери тестування.<sup>[[7]](#references)</sup>

### **Інші способи**

Повторюйте відповідні кроки пошуку щоразу, коли знаходите новий домен: кожен результат може виявити додаткові назви в сертифікатах, зв’язки passive DNS, збіги favicon і ідентифікатори організацій, яких не було видно в початковому seed.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Оскільки вам уже відома назва організації, якій належить діапазон IP-адрес, можна шукати за цими даними в Shodan, використовуючи: `org:"Tesla, Inc."` Перевірте знайдені хости на наявність нових неочікуваних доменів у TLS-сертифікаті.

Можна отримати **TLS-сертифікат** головної вебсторінки, дізнатися **назву організації**, а потім шукати цю назву в **TLS-сертифікатах** усіх вебсторінок, відомих **Shodan**, за допомогою фільтра : `ssl:"Tesla Motors"` або скористатися інструментом на зразок [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is — це інструмент для пошуку **доменів, пов’язаних** з основним доменом, і їхніх **піддоменів**; просто неймовірно.

**Passive DNS / Historical DNS**

Дані Passive DNS чудово підходять для пошуку **старих і забутих записів**, які досі резолвляться або які можна перехопити. Перегляньте:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Пошук вразливостей**

Перевірте на наявність [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Можливо, якась компанія **використовує домен**, але **втратила право власності на нього**. Просто зареєструйте його (якщо це достатньо дешево) і повідомте компанію.

Якщо знайдете **домен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених сервісів, у **цій книзі можна знайти кілька прийомів, щоб їх «атакувати»**.\
_Зверніть увагу, що іноді домен розміщено на IP-адресі, яка не контролюється клієнтом, тож вона не входить до сфери тестування. Будьте обережні._

## Піддомени

> Ми знаємо всі компанії в межах сфери тестування, усі активи кожної компанії та всі домени, пов’язані з цими компаніями.

Тепер час знайти всі можливі піддомени кожного знайденого домену.

> [!TIP]
> Зауважте, що деякі інструменти й методи пошуку доменів також можуть допомогти знайти піддомени.

### **DNS**

Спробуймо отримати **піддомени** із записів **DNS**. Також варто спробувати виконати **Zone Transfer** (якщо він вразливий, про це слід повідомити).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Щоб отримати доступ до API та платформ для роботи з інфраструктурою, репутацією, записами про витоки й збагаченням даних поза пошуком піддоменів, див. [каталог API для розвідки та аналізу загроз](reconnaissance-and-threat-intelligence-apis.md).

Найшвидший спосіб отримати багато піддоменів — шукати їх у зовнішніх джерелах. Найчастіше використовують такі **інструменти** (для кращих результатів налаштуйте API-ключі):


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

Є **інші цікаві інструменти/API**, які, навіть якщо не спеціалізуються безпосередньо на пошуку субдоменів, можуть бути корисними для їх пошуку, наприклад:

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

- [**gau**](https://github.com/lc/gau)**:** отримує відомі URL-адреси для будь-якого домену з AlienVault's Open Threat Exchange, Wayback Machine і Common Crawl.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): сканують веб у пошуках JS-файлів і витягують із них субдомени.

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

- [**SecurityTrails**](https://securitytrails.com/) надає обмежений безкоштовний доступ до API для отримання поточних DNS-даних і даних про субдомени; для доступу до історичних DNS/IP-даних потрібен платний план.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Цей проєкт безкоштовно надає **всі субдомени, пов’язані з bug-bounty програмами**. Отримати ці дані можна також за допомогою [chaospy](https://github.com/Moaaz-0x/chaospy) або навіть переглянути scope, який використовує цей проєкт: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Порівняння** багатьох із цих інструментів можна знайти тут: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Спробуймо знайти нові **субдомени**, перебираючи можливі імена субдоменів на DNS-серверах.

Для цього вам знадобляться **поширені wordlist-и субдоменів, наприклад**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Також потрібні IP-адреси надійних DNS-резолверів. Щоб створити список перевірених DNS-резолверів, завантажте список резолверів із [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) і відфільтруйте їх за допомогою [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Також можна скористатися цим списком: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Найрекомендованіші інструменти для DNS brute-force:

- [**massdns**](https://github.com/blechschmidt/massdns): це перший інструмент, який ефективно виконував DNS brute-force. Він дуже швидкий, але схильний давати хибнопозитивні результати.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Як на мене, цей інструмент використовує лише 1 резолвер.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) — це обгортка для `massdns`, написана мовою Go, яка дає змогу знаходити дійсні субдомени за допомогою активного bruteforce, а також розв’язувати субдомени з обробкою wildcard і зручним введенням-виведенням.

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

### Другий раунд DNS-брутфорсу

Після того як за допомогою відкритих джерел і брутфорсу ви знайшли субдомени, можна згенерувати їхні варіанти, щоб спробувати знайти ще більше. Для цього стануть у пригоді кілька інструментів:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** генерує перестановки на основі доменів і субдоменів.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Генерує перестановки на основі заданих доменів і субдоменів.
  - [**Тут**](https://github.com/subfinder/goaltdns/blob/master/words.txt) можна отримати **wordlist** перестановок goaltdns.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** На основі доменів і субдоменів генерує перестановки. Якщо файл із перестановками не вказано, gotator використовуватиме власний.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Окрім генерації перестановок субдоменів, він також може спробувати їх зарезолвити (але краще скористатися згаданими вище інструментами).
  - **wordlist** для перестановок altdns можна отримати [**тут**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Ще один інструмент для створення перестановок, мутацій і змін субдоменів. Цей інструмент перебирає результати методом brute force (не підтримує DNS wildcard).
  - Список слів для перестановок dmut можна отримати [**тут**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** На основі домену **генерує нові потенційні назви піддоменів** за заданими шаблонами, щоб спробувати виявити більше піддоменів.

#### Генерація розумних перестановок

- [**regulator**](https://github.com/cramppet/regulator): Навчається на regex-подібних шаблонах із виявлених піддоменів і генерує кандидатні назви для резолву.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ — це fuzzer для brute-force пошуку субдоменів із надзвичайно простим, але ефективним алгоритмом, керованим відповідями DNS. Він використовує наданий набір вхідних даних, як-от спеціально підібраний wordlist або історичні записи DNS/TLS, щоб точно генерувати більше відповідних доменних імен і розширювати їх далі в циклі на основі інформації, зібраної під час сканування DNS.

```
echo www | subzuf facebook.com
```

### **Workflow виявлення піддоменів**

Приклади workflow від Trickest поєднують OSINT, DNS brute force та етапи генерації перестановок для повторюваного перерахування піддоменів.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / віртуальні хости**

Якщо ви знайшли IP-адресу, на якій розміщено **одну або кілька вебсторінок**, що належать піддоменам, можна спробувати **знайти інші піддомени з вебсторінками на цій IP-адресі**: пошукати в **джерелах OSINT** домени, пов’язані з цією IP-адресою, або **перебором визначити назви доменів VHost на цій IP-адресі**.

#### OSINT

Знайти **VHosts на IP-адресах можна за допомогою** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **або інших API**.

**Brute Force**

Якщо ви підозрюєте, що на вебсервері може бути прихований піддомен, можна спробувати підібрати його перебором:

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
> За допомогою цієї техніки ви навіть можете отримати доступ до внутрішніх/прихованих кінцевих точок.

### **CORS Brute Force**

Іноді трапляються сторінки, які повертають заголовок _**Access-Control-Allow-Origin**_ лише тоді, коли в заголовку _**Origin**_ указано дійсний домен/субдомен. У таких випадках можна скористатися цією поведінкою, щоб **виявити** нові **субдомени**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force бакетів**

Під час пошуку **субдоменів** перевіряйте, чи вони **вказують** на якийсь тип **бакета**. Якщо так, [**перевірте дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Оскільки на цьому етапі ви вже знатимете всі домени в межах scope, спробуйте [**перебрати можливі назви бакетів і перевірити дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Моніторинг**

Ви можете **відстежувати**, чи створюються **нові субдомени** домену, моніторячи журнали **Certificate Transparency** — це робить [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Пошук вразливостей**

Перевірте, чи можливе [**перехоплення субдомену**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Якщо **субдомен** вказує на якийсь **S3 bucket**, [**перевірте дозволи**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Якщо ви знайдете **субдомен з IP-адресою, відмінною** від тих, що вже виявили під час пошуку активів, виконайте **базове сканування вразливостей** (за допомогою Nessus або OpenVAS) і [**сканування портів**](../pentesting-network/index.html#discovering-hosts-from-the-outside) за допомогою **nmap/masscan/shodan**. Залежно від запущених служб, у **цій книзі ви можете знайти кілька хитрощів, щоб їх «атакувати»**.\
_Зверніть увагу, що іноді субдомен розміщено на IP-адресі, якою клієнт не керує, тому вона не входить у scope. Будьте обережні._

## IP-адреси

На початкових етапах ви могли **знайти діапазони IP-адрес, домени та субдомени**.\
Час **зібрати всі IP-адреси з цих діапазонів**, а також IP-адреси доменів і субдоменів (за допомогою DNS-запитів).

За допомогою таких сервісів можна також знайти **IP-адреси, які раніше використовували домени й субдомени**. Можливо, клієнт досі володіє цими IP-адресами, і вони допоможуть вам знайти [**способи обходу CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md).

- [**SecurityTrails**](https://securitytrails.com/) (для доступу до історичних даних DNS/IP потрібен платний план)

Також можна перевірити, які домени вказують на певну IP-адресу, за допомогою інструмента [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Пошук вразливостей**

**Проскануйте порти на всіх IP-адресах, які не належать CDN** (оскільки там ви, найімовірніше, нічого цікавого не знайдете). Серед виявлених запущених служб ви можете **знайти вразливості**.

**Знайдіть** [**посібник**](../pentesting-network/index.html) **зі сканування хостів.**

## Пошук вебсерверів

> Ми знайшли всі компанії та їхні активи й знаємо діапазони IP-адрес, домени та субдомени в межах scope. Час шукати вебсервери.

На попередніх етапах ви, імовірно, вже виконали **розвідку виявлених IP-адрес і доменів**, тож могли **знайти всі можливі вебсервери**. Якщо ні, далі розглянемо кілька **швидких способів пошуку вебсерверів** у межах scope.

Зверніть увагу: це призначено для **виявлення вебзастосунків**, тому вам також слід виконати **сканування вразливостей** і **портів** (**якщо це дозволено** умовами scope).

[**Тут наведено швидкий спосіб виявлення відкритих портів** вебсерверів за допомогою [**masscan**](../pentesting-network/index.html#http-port-discovery).\
Ще один зручний інструмент для пошуку вебсерверів — [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) і [**httpx**](https://github.com/projectdiscovery/httpx). Передайте їм список доменів — і вони спробують підключитися до портів 80 (http) і 443 (https). Крім того, можна вказати й інші порти:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Знімки екрана**

Тепер, коли ви виявили **усі вебсервери** в межах області тестування (серед **IP-адрес** компанії та всіх її **доменів** і **субдоменів**), ви, ймовірно, **не знаєте, з чого почати**. Тож спростімо завдання й почнімо зі знімків екрана всіх серверів. Просто **поглянувши** на **головну сторінку**, можна знайти **дивні** кінцеві точки, які з більшою **ймовірністю** можуть бути **вразливими**.

Для цього можна скористатися [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) або [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Крім того, можна запустити [**eyeballer**](https://github.com/BishopFox/eyeballer) для аналізу всіх **знімків екрана** й визначення, **що, ймовірно, містить вразливості**, а що ні.

## Публічні хмарні ресурси

Щоб знайти потенційні хмарні ресурси, що належать компанії, слід **почати зі списку ключових слів, за якими можна ідентифікувати цю компанію**. Наприклад, для криптокомпанії можна використати такі слова: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Також знадобляться списки **поширених слів, які використовують у назвах бакетів**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Потім на основі цих слів слід згенерувати **перестановки** (докладніше див. [**Другий раунд перебору DNS**](#second-dns-bruteforce-round)).

Для роботи зі створеними списками слів можна скористатися такими інструментами, як [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **або** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Пам’ятайте, що під час пошуку хмарних ресурсів потрібно шукати **не лише бакети в AWS**.

### **Пошук вразливостей**

Якщо ви знайшли такі речі, як **відкриті бакети або доступні хмарні функції**, слід **перевірити їх** і з’ясувати, що вони пропонують та чи можна ними зловживати.

## Електронні адреси

Маючи **домени** й **субдомени** в межах області тестування, ви вже маєте все, що **потрібно для пошуку електронних адрес**. Ось **API** та **інструменти**, які найкраще допомагали мені знаходити електронні адреси співробітників компаній:

- [**theHarvester**](https://github.com/laramies/theHarvester) — з API
- API [**https://hunter.io/**](https://hunter.io/) (безкоштовна версія)
- API [**https://app.snov.io/**](https://app.snov.io/) (безкоштовна версія)
- API [**https://minelead.io/**](https://minelead.io/) (безкоштовна версія)

### **Пошук вразливостей**

Електронні адреси згодом стануть у пригоді для **перебору облікових даних вебсервісів і служб автентифікації** (наприклад, SSH). Вони також потрібні для **фішингових атак**. Крім того, ці API нададуть більше **інформації про людину**, якій належить адреса, що корисно для фішингової кампанії.

## Витоки облікових даних

Маючи **домени,** **субдомени** й **електронні адреси**, можна почати шукати облікові дані, що раніше потрапили у витоки й належать власникам цих адрес:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Пошук вразливостей**

Якщо ви знайдете **дійсні облікові дані з витоків**, це буде дуже легка перемога.

## Витоки секретів

Витоки облікових даних пов’язані зі зламами компаній, унаслідок яких **конфіденційну інформацію було викрадено й продано**. Однак компанії можуть постраждати й від **інших витоків**, інформації про які немає в цих базах даних:

### Витоки на Github

Облікові дані й API можуть потрапити у витоки через **публічні репозиторії** **компанії** або **користувачів**, які працюють у цій компанії та використовують github.\
За допомогою **інструмента** [**Leakos**](https://github.com/carlospolop/Leakos) можна **завантажити** всі **публічні репозиторії** **організації** та її **розробників** і автоматично запустити на них [**gitleaks**](https://github.com/gitleaks/gitleaks).

**Leakos** також можна використовувати для запуску **gitleaks** на всіх переданих йому **текстових URL-адресах**, адже іноді **вебсторінки також містять секрети**.

#### Github Dorks

Перегляньте сторінку [GitHub dorks і витоки](github-leaked-secrets.md), щоб знайти потенційні **GitHub dorks** для пошуку в організації.

### Витоки на пастах

Іноді зловмисники або просто працівники **публікують вміст компанії на сайтах для публікації тексту**. Там може бути або не бути **конфіденційної інформації**, але пошукати її варто.\
За допомогою інструмента [**Pastos**](https://github.com/carlospolop/Pastos) можна одночасно шукати на понад 80 сайтах для публікації тексту.

### Google Dorks

Старі, але перевірені google dorks завжди допомагають знаходити **відкриту інформацію, якій не місце у відкритому доступі**. Проблема лише в тому, що [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) містить кілька **тисяч** можливих запитів, які неможливо виконати вручну. Тож можна вибрати 10 улюблених запитів або скористатися **інструментом на кшталт** [**Gorks**](https://github.com/carlospolop/Gorks), **щоб виконати їх усі**.

_Зверніть увагу: інструменти, які намагаються переглянути всю базу даних через звичайний браузер Google, не завершать роботу, оскільки google дуже швидко вас заблокує._

### **Пошук вразливостей**

Якщо ви знайдете **дійсні облікові дані або API-токени з витоків**, це буде дуже легка перемога.

## Вразливості у відкритому коді

Якщо ви виявили, що компанія має **код із відкритим вихідним кодом**, його можна **проаналізувати** й пошукати в ньому **вразливості**.

**Залежно від мови** можна використовувати різні **інструменти**; див. список [інструментів для аналізу вихідного коду](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Також є безкоштовні сервіси, які дають змогу **сканувати публічні репозиторії**, наприклад:

- [**Snyk**](https://app.snyk.io/)

## [**Методологія тестування на проникнення вебзастосунків**](../../network-services-pentesting/pentesting-web/index.html)

**Більшість вразливостей**, які знаходять мисливці за багами, міститься у **вебзастосунках**, тому на цьому етапі я хотів би розповісти про **методологію тестування вебзастосунків**. [**Інформацію про неї можна знайти тут**](../../network-services-pentesting/pentesting-web/index.html).

Також хочу окремо згадати розділ [**Інструменти з відкритим вихідним кодом для автоматизованого сканування вебзастосунків**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), адже, хоча не варто очікувати, що вони знайдуть дуже чутливі вразливості, їх зручно додавати до **робочих процесів, щоб отримати початкову інформацію про вебзастосунки.**

## Підсумок

> Вітаємо! На цьому етапі ви вже виконали **всю базову розвідку**. Так, вона базова, адже можна провести ще багато розвідки (пізніше розглянемо додаткові хитрощі).

Отже, ви вже:

1. Знайшли всі **компанії** в межах області тестування
2. Знайшли всі **ресурси**, що належать компаніям (і виконали сканування на вразливості, якщо це дозволено)
3. Знайшли всі **домени**, що належать компаніям
4. Знайшли всі **субдомени** доменів (чи є захоплення субдоменів?)
5. Знайшли всі **IP-адреси** в межах області тестування (як пов’язані з **CDN**, так і не пов’язані).
6. Знайшли всі **вебсервери** та зробили їхні **знімки екрана** (чи є щось дивне, що варто дослідити?)
7. Знайшли всі **потенційні публічні хмарні ресурси**, що належать компанії.
8. Знайшли **електронні адреси**, **витоки облікових даних** і **витоки секретів**, які можуть **дуже легко принести значний результат**.
9. **Провели тестування на проникнення всіх знайдених вебсайтів**

## **Інструменти для повністю автоматизованої розвідки**

Існує кілька інструментів, які виконують частину запропонованих дій для заданої області тестування.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) — трохи застарілий і не оновлюється



## References

- [1] [Jason Haddix — Методологія мисливця за багами, версія 4.0: розвідка](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf — HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) — Про favicons: від іконок браузера до розвідки поверхні атаки](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) — Як перетворити favicon.ico на зброю для BugBounties, OSINT та інших цілей](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov — Виявлення доменів за допомогою атаки на часову кореляцію даних Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) — Пасивне захоплення: виявлення (і відтворення) дорогої кампанії із захоплення субдоменів](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet — Regulator: унікальний метод переліку субдоменів](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop — Повний робочий процес виявлення субдоменів, частина 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop — Повний автоматизований робочий процес перебору для виявлення субдоменів за допомогою Trickest, частина 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter — Знімок екрана з результатами favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
