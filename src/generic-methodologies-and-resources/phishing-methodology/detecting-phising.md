# Виявлення Phishing

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Щоб виявити спробу phishing, важливо **розуміти техніки phishing, які використовуються сьогодні**. На батьківській сторінці цього допису ви можете знайти цю інформацію, тому, якщо ви не знаєте, які техніки використовуються сьогодні, рекомендую перейти на батьківську сторінку та прочитати хоча б цей розділ.

Цей допис ґрунтується на припущенні, що **зловмисники спробують певним чином імітувати або використати доменне ім'я жертви**. Якщо ваш домен називається `example.com`, а вас phish-ять, використовуючи з якоїсь причини зовсім інше доменне ім'я, наприклад `youwonthelottery.com`, ці техніки не допоможуть це виявити.

## Варіації доменних імен

Досить **легко** **виявити** ті спроби **phishing**, у яких у листі використовується **схоже доменне** ім'я.\
Достатньо **згенерувати список найімовірніших phishing-імен**, які може використати зловмисник, і **перевірити**, чи **зареєстровані** вони, або просто перевірити, чи використовує їх якась **IP**-адреса.

### Пошук підозрілих доменів

Для цього можна скористатися будь-яким із наведених нижче інструментів. Зверніть увагу, що ці інструменти також автоматично виконуватимуть DNS-запити, щоб перевірити, чи має домен призначену IP-адресу:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Порада: Якщо ви генеруєте список кандидатів, також передайте його до логів вашого DNS-резолвера, щоб виявляти **NXDOMAIN-запити зсередини вашої організації** (користувачі намагаються перейти до typo-домену ще до того, як зловмисник фактично його зареєструє). Якщо це дозволяє політика, перенаправляйте ці домени до sinkhole або блокуйте їх заздалегідь.

### Bitflipping

**Коротке пояснення цієї техніки наведено на батьківській сторінці. Або прочитайте оригінальне дослідження за посиланням** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Наприклад, зміна 1 біта в домені microsoft.com може перетворити його на _windnws.com._\
**Зловмисники можуть зареєструвати якомога більше доменів із bit-flipping, пов'язаних із жертвою, щоб перенаправляти легітимних користувачів до своєї інфраструктури**.<sup>[[1]](#references)</sup>

**Також слід відстежувати всі можливі доменні імена, отримані за допомогою bit-flipping.**

Якщо вам також потрібно враховувати homoglyph/IDN-подібні домени (наприклад, змішування символів Latin/Cyrillic), перегляньте:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Базові перевірки

Після того як ви матимете список потенційно підозрілих доменних імен, слід **перевірити** їх (передусім порти HTTP і HTTPS), щоб **з'ясувати, чи використовують вони якусь форму входу, схожу** на форму входу в доменах жертви.\
Також можна перевірити порт 3333, щоб з'ясувати, чи відкритий він і чи працює на ньому інстанс `gophish`.\
Також важливо знати, **скільки років кожному виявленому підозрілому домену**: що він молодший, то вищий ризик.\
Ви також можете отримати **скриншоти** підозрілої вебсторінки HTTP та/або HTTPS, щоб перевірити, чи є вона підозрілою, і в такому разі **перейти до неї для детальнішого аналізу**.

### Розширені перевірки

Якщо ви хочете піти на крок далі, рекомендую **відстежувати ці підозрілі домени та час від часу шукати нові** (щодня? це займає лише кілька секунд/хвилин). Також слід **перевіряти** відкриті **порти** пов'язаних IP-адрес і **шукати інстанси `gophish` або подібних інструментів** (так, зловмисники також припускаються помилок), а також **відстежувати вебсторінки HTTP і HTTPS підозрілих доменів та субдоменів**, щоб перевірити, чи не скопіювали вони форми входу з вебсторінок жертви.\
Щоб **автоматизувати це**, рекомендую мати список форм входу з доменів жертви, виконувати spidering підозрілих вебсторінок і порівнювати кожну форму входу, знайдену в підозрілих доменах, із кожною формою входу в домені жертви за допомогою чогось на кшталт `ssdeep`.\
Якщо ви виявили форми входу в підозрілих доменах, можна спробувати **надіслати фіктивні облікові дані** та **перевірити, чи перенаправляють вони вас до домену жертви**.

---

### Пошук за favicon і вебвідбитками (Shodan/ZoomEye/Censys)

Багато phishing-kit повторно використовують favicon бренду, який вони імітують. Сканери всього Інтернету обчислюють MurmurHash3 від favicon, закодованого в base64. Ви можете згенерувати хеш і виконати pivot за ним:

Приклад на Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Запит у Shodan: `http.favicon.hash:309020573`
- За допомогою інструментів: зверніть увагу на community tools, як-от favfreak, для генерування хешів і dorks для Shodan/ZoomEye/Censys.

Примітки
- Favicon повторно використовуються; розглядайте збіги як зачіпки та перевіряйте вміст і сертифікати перед виконанням будь-яких дій.
- Поєднуйте це з евристиками віку домену та ключових слів для підвищення точності.

### Полювання за телеметрією URL (urlscan.io)

`urlscan.io` зберігає історичні знімки екрана, DOM, запити та метадані TLS надісланих URL. Ви можете шукати зловживання брендом і клони:<sup>[[2]](#references)</sup>

Приклади запитів (у UI або через API):
- Пошук схожих доменів із виключенням ваших легітимних доменів: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Пошук сайтів, що hotlink-ять ваші assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Обмеження результатів за останнім часом: додайте `AND date:>now-7d`

Приклад API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Із JSON здійснюйте pivot за такими полями:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, щоб виявляти дуже нові сертифікати для lookalike-доменів
- значення `task.source`, як-от `certstream-suspicious`, щоб пов’язувати результати з моніторингом CT

### Вік домену через RDAP (придатний для використання у скриптах)

RDAP повертає машиночитні події створення. Це корисно для виявлення **нещодавно зареєстрованих доменів (NRD)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Збагачуйте свій pipeline, додаючи до доменів категорії віку реєстрації (наприклад, <7 днів, <30 днів), і відповідно визначайте пріоритет під час triage.

### TLS/JAx fingerprints для виявлення AiTM infrastructure

Сучасний credential-phishing дедалі частіше використовує reverse proxies **Adversary-in-the-Middle (AiTM)** (наприклад, Evilginx) для викрадення session tokens. Ви можете додати detections на мережевому рівні:

- Логуйте TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) на egress. Деякі збірки Evilginx, за спостереженнями, мають стабільні значення JA4 client/server. Створюйте alert лише для відомих небезпечних fingerprints як слабкого сигналу й завжди підтверджуйте їх за допомогою content та domain intel.<sup>[[3]](#references)</sup>
- Проактивно записуйте metadata TLS certificate (issuer, кількість SAN, використання wildcard, validity) для lookalike hosts, виявлених через CT або urlscan, і зіставляйте їх із віком DNS та geolocation.

> Примітка: Розглядайте fingerprints як enrichment, а не як єдиний blocker; frameworks розвиваються й можуть рандомізувати або обфускувати їх.

### Domain names using keywords

На батьківській сторінці також згадується техніка variation доменного імені, яка полягає в розміщенні **доменного імені жертви всередині більшого домену** (наприклад, paypal-financial.com для paypal.com).

#### Certificate Transparency

Неможливо застосувати попередній підхід "Brute-Force", але насправді **можна також виявляти такі phishing-спроби** завдяки Certificate Transparency. Щоразу, коли CA видає certificate, його details стають загальнодоступними. Це означає, що, читаючи Certificate Transparency або навіть здійснюючи його monitoring, **можна знаходити домени, які використовують keyword у своєму імені**. Наприклад, якщо attacker генерує certificate для [https://paypal-financial.com](https://paypal-financial.com), переглянувши certificate, можна знайти keyword "paypal" і зрозуміти, що використовується suspicious email.

У дописі [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) пропонується використовувати Censys для пошуку certificates, пов'язаних із певним keyword, і фільтрувати їх за датою (лише "new" certificates) та за CA issuer "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Однак ви можете зробити "те саме", використовуючи безкоштовний web-сервіс [**crt.sh**](https://crt.sh). Ви можете **виконати пошук за keyword** і за бажанням **відфільтрувати** результати **за датою та CA**.

![Domain names using keywords - Certificate Transparency: Однак ви можете зробити "те саме", використовуючи безкоштовний web-сервіс crt.sh. Ви можете виконати пошук за keyword і відфільтрувати результати за датою та...](<../../images/image (519).png>)

За допомогою цього останнього варіанту можна навіть використати поле Matching Identities, щоб перевірити, чи відповідає якась identity із реального домену одному із suspicious domains (зверніть увагу, що suspicious domain може бути false positive).

**Ще одна альтернатива** — чудовий project під назвою [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream надає real-time stream нових certificates, який можна використовувати для виявлення вказаних keywords майже в real-time. Насправді існує project під назвою [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), який робить саме це.

Практична порада: під час triage CT hits надавайте пріоритет NRDs, untrusted/unknown registrars, privacy-proxy WHOIS і certificates із дуже недавніми значеннями `NotBefore`. Підтримуйте allowlist власних domains/brands, щоб зменшити шум.

#### **New domains**

**Остання альтернатива** — зібрати список **newly registered domains** для деяких TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) надає такий сервіс) і **перевірити keywords у цих доменах**. Однак довгі домени зазвичай використовують один або кілька subdomains, тому keyword не з'явиться всередині FLD, і ви не зможете знайти phishing subdomain.

Додаткова heuristic: під час alerting із підвищеною підозрою ставтеся до певних **file-extension TLD** (наприклад, `.zip`, `.mov`). У lure їх часто плутають із filenames; для кращої точності поєднуйте сигнал TLD із brand keywords та віком NRD.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
