# Виявлення Phishing

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Щоб виявити phishing-спробу, важливо **розуміти phishing-техніки, які використовуються сьогодні**. На батьківській сторінці цього допису ви знайдете цю інформацію, тож якщо ви не ознайомлені з техніками, що застосовуються зараз, рекомендую перейти на батьківську сторінку і прочитати принаймні цю секцію.

Цей допис базується на ідеї, що **атакуючі спробують якимось чином імітувати або використати домен жертви**. Якщо ваш домен називається `example.com` і вас phished використовуючи зовсім інший домен, наприклад `youwonthelottery.com`, ці техніки цього не виявлять.

## Варіації імен доменів

Досить **просто** виявити ті **phishing**-спроби, що використовують у листі **схожий домен**.  
Достатньо **згенерувати список найімовірніших phishing-імен**, які може використати атакуючий, і **перевірити**, чи вони **зареєстровані**, або просто перевірити, чи є на них якийсь **IP**.

### Пошук підозрілих доменів

Для цього можна використати будь-який з наведених інструментів. Зверніть увагу, що ці інструменти автоматично виконують DNS-запити, щоб перевірити, чи має домен призначений **IP**:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Порада: Якщо ви згенеруєте список кандидатів, підсуньте його також у логи вашого DNS-resolver'а, щоб виявити **NXDOMAIN запити зсередини організації** (користувачі, що намагаються дістатися до опечатки до того, як атакуючий її зареєструє). Sinkhole або попередньо заблокуйте ці домени, якщо політика дозволяє.

### Bitflipping

**Коротке пояснення цієї техніки можна знайти на батьківській сторінці. Або прочитайте оригінальне дослідження в** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Наприклад, одне бітове змінення в домені microsoft.com може перетворити його на _windnws.com_.\
**Атакуючі можуть зареєструвати якомога більше bit-flipping доменів, пов'язаних із жертвою, щоб перенаправити легітимних користувачів на свою інфраструктуру**.

**Усі можливі bit-flipping доменні імена також повинні моніторитись.**

Якщо вам також треба врахувати homoglyph/IDN підробки (наприклад, змішування латиниці/кирилиці), дивіться:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Базові перевірки

Коли у вас є список потенційно підозрілих доменів, ви повинні їх **перевірити** (насамперед порти HTTP та HTTPS), щоб **переконатися, чи використовують вони якийсь login form, схожий на форму домену жертви**.\
Також можна перевірити порт 3333, щоб побачити, чи відкритий він і чи запущений там екземпляр `gophish`.\
Цікаво також знати, **якого віку кожен виявлений підозрілий домен** — чим молодший, тим ризик вищий.\
Ви також можете отримати **скриншоти** підозрілої HTTP/HTTPS сторінки, щоб перевірити її, і в разі підозри **перейти на неї для детальнішого огляду**.

### Розширені перевірки

Якщо хочете піти далі, рекомендую **моніторити ці підозрілі домени і періодично шукати нові** (щодня? це займає лише кілька секунд/хвилин). Також потрібно **перевіряти відкриті порти пов'язаних IP-адрес** та **шукати інстанси `gophish` або подібних інструментів** (так, атакуючі теж помиляються), а також **моніторити HTTP та HTTPS сторінки підозрілих доменів і субдоменів**, щоб побачити, чи скопіювали вони будь-яку login form зі сторінок жертви.\
Для автоматизації рекомендую мати список login form доменів жертви, сканувати підозрілі сторінки і порівнювати кожну знайдену login form на підозрілих доменах з кожною login form домену жертви, використовуючи щось на кшталт `ssdeep`.\
Якщо ви локалізували login form-и підозрілих доменів, можна спробувати **надіслати junk credentials** і **перевірити, чи перенаправляє вас на домен жертви**.

---

### Полювання за favicon та веб-фінгерпринтами (Shodan/ZoomEye/Censys)

Багато phishing kit-ів повторно використовують favicons бренду, який вони імітують. Інтернет-сканери обчислюють MurmurHash3 від base64-encoded favicon. Ви можете згенерувати хеш і pivot-нути за ним:

Приклад Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Запит у Shodan: `http.favicon.hash:309020573`
- За допомогою інструментів: використовуйте інструменти спільноти, такі як favfreak, щоб генерувати hashes і dorks для Shodan/ZoomEye/Censys.

Примітки
- Favicons часто повторно використовуються; розглядайте збіги як leads і перевіряйте вміст та certs перед діями.
- Комбінуйте з domain-age та keyword heuristics для підвищення точності.

### Пошук URL-телеметрії (urlscan.io)

`urlscan.io` зберігає історичні скриншоти, DOM, requests та TLS metadata поданих URL. Ви можете шукати зловживання брендом та клони:

Приклади запитів (UI або API):
- Знайти lookalikes, виключаючи ваші легітимні домени: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Знайти сайти, що роблять hotlinking ваших assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Обмежити до нещодавніх результатів: додайте `AND date:>now-7d`

Приклад API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
У JSON орієнтуйтеся на:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` щоб виявляти дуже нові certs для lookalikes
- значення `task.source`, як-от `certstream-suspicious`, щоб пов'язувати знахідки з моніторингом CT

### Вік домену через RDAP (скриптовано)

RDAP повертає машинозчитувані події створення. Корисно для позначення **ново зареєстрованих доменів (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Збагачуйте свій pipeline, позначаючи domains за віком реєстрації (наприклад, <7 днів, <30 днів) і відповідно пріоритезуйте triage.

### TLS/JAx fingerprints для виявлення AiTM-інфраструктури

Сучасний credential-phishing все частіше використовує **Adversary-in-the-Middle (AiTM)** reverse proxies (наприклад, Evilginx) для викрадення session tokens. Ви можете додати мережеві детекції:

- Логуйте TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) на egress. Деякі збірки Evilginx спостерігалися зі стабільними JA4 client/server значеннями. Викликайте оповіщення по відомо-шкідливих fingerprints лише як слабкий сигнал і завжди підтверджуйте контентом та domain intel.
- Проактивно зберігайте метадані TLS certificate (issuer, SAN count, wildcard use, validity) для lookalike hosts, виявлених через CT або urlscan, і корелюйте з DNS age та геолокацією.

> Note: Treat fingerprints as enrichment, not as sole blockers; frameworks evolve and may randomise or obfuscate.

### Domain names using keywords

Батьківська сторінка також згадує техніку варіації domain name, яка полягає в розміщенні **домену жертви всередині більшого домену** (наприклад, paypal-financial.com для paypal.com).

#### Certificate Transparency

Не завжди можливо застосувати попередній підхід "Brute-Force", але насправді **можна виявити такі phishing-спроби** також завдяки Certificate Transparency. Кожного разу, коли сертифікат випускається CA, деталі стають публічними. Це означає, що читаючи Certificate Transparency або навіть моніторячи його, **можна знайти домени, які використовують ключове слово у своєму імені**. Наприклад, якщо атакувальник згенерує сертифікат для [https://paypal-financial.com](https://paypal-financial.com), переглянувши сертифікат, можна знайти ключове слово "paypal" і з'ясувати, що використовується підозрілий email.

The post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggests that you can use Censys to search for certificates affecting a specific keyword and filter by date (only "new" certificates) and by the CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Однак те ж саме можна зробити через безкоштовний веб [**crt.sh**](https://crt.sh). Ви можете **шукати ключове слово** та **фільтрувати** результати **за датою та CA**, якщо бажаєте.

![](<../../images/image (519).png>)

Використовуючи останній варіант, ви навіть можете скористатися полем Matching Identities, щоб перевірити, чи співпадає якась identity реального домену з будь-яким із підозрілих доменів (зауважте, що підозрілий домен може бути false positive).

**Another alternative** — чудовий проект [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream надає потокову передачу в реальному часі новостворених сертифікатів, яку можна використовувати для виявлення заданих ключових слів у (майже) реальному часі. Насправді є проект [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), який робить саме це.

Практична порада: при triage CT hits пріоритезуйте NRDs, untrusted/unknown registrars, privacy-proxy WHOIS та сертифікати з дуже недавніми `NotBefore` часами. Підтримуйте allowlist ваших власних доменів/брендів, щоб зменшити шум.

#### **New domains**

**One last alternative** — зібрати список **newly registered domains** для деяких TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) надає таку послугу) і **перевіряти ключові слова в цих доменах**. Проте довгі домени зазвичай використовують один або більше субдоменів, тому ключове слово не з'явиться всередині FLD і ви не зможете знайти phishing subdomain.

Додаткова евристика: ставтеся з підвищеною підозрою до певних **file-extension TLDs** (наприклад, `.zip`, `.mov`) при формуванні оповіщень. Їх часто плутають з іменами файлів у приманках; поєднуйте сигнал TLD з бренд-ключовими словами та NRD age для кращої точності.

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
