# Виявлення фішингу

## Вступ

Щоб виявити фішингову атаку, важливо **розуміти фішингові техніки, які використовуються сьогодні**. На батьківській сторінці цього допису ви можете знайти цю інформацію, тому, якщо ви не знаєте, які техніки використовуються сьогодні, рекомендую перейти на батьківську сторінку та прочитати принаймні цей розділ.

Цей допис ґрунтується на ідеї, що **зловмисники намагатимуться певним чином імітувати доменне ім'я жертви або використовувати його**. Якщо ваш домен називається `example.com`, а вас фішать, використовуючи з абсолютно іншої причини доменне ім'я на кшталт `youwonthelottery.com`, ці техніки не допоможуть це виявити.

## Варіації доменних імен

Досить **легко** **виявити** ті **фішингові** спроби, у яких в електронному листі використовується **схоже доменне** ім'я.\
Достатньо **згенерувати список найімовірніших фішингових імен**, які може використати зловмисник, і **перевірити**, чи вони **зареєстровані**, або просто перевірити, чи використовується для них якась **IP**-адреса.

### Пошук підозрілих доменів

Для цього можна використовувати будь-який із наведених нижче інструментів. Обидва перетворюють кандидатні домени на IP-адреси, щоб перевірити, чи використовуються вони.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Порада: якщо ви згенерували список кандидатів, також передайте його до журналів вашого DNS resolver, щоб виявляти **запити NXDOMAIN зсередини вашої організації** (користувачі намагаються перейти на домен з помилкою до того, як зловмисник фактично його зареєструє). Якщо це дозволено політикою, перенаправляйте ці домени до sinkhole або попередньо блокуйте їх.

### Bitflipping

**Коротке пояснення дивіться на батьківській сторінці; первинне дослідження bitsquatting для Windows.com дивіться у [матеріалі Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) та [звіті BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Наприклад, зміна 1 біта в домені microsoft.com може перетворити його на _windnws.com._\
**Зловмисники можуть зареєструвати якомога більше доменів із bit-flipping, пов'язаних із жертвою, щоб перенаправляти легітимних користувачів на свою інфраструктуру**.<sup>[[1]](#references)[[2]](#references)</sup>

**Також слід відстежувати всі можливі доменні імена з bit-flipping.**

Якщо вам також потрібно враховувати homoglyph/IDN lookalikes (наприклад, змішування латинських і кириличних символів), перегляньте:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Базові перевірки

Після того як у вас буде список потенційно підозрілих доменних імен, слід **перевірити** їх (переважно порти HTTP та HTTPS), щоб **з'ясувати, чи використовують вони певну форму входу, схожу** на форму входу в домені жертви.\
Також можна перевірити порт 3333, щоб з'ясувати, чи відкритий він і чи запущено на ньому екземпляр `gophish`.\
Також важливо знати, **як давно існує кожен виявлений підозрілий домен**: що він молодший, то вищий ризик.\
Ви також можете отримати **скриншоти** підозрілої вебсторінки HTTP та/або HTTPS, щоб з'ясувати, чи є вона підозрілою, і в такому разі **відкрити її для детальнішого аналізу**.

### Розширені перевірки

Якщо ви хочете піти на крок далі, рекомендую **відстежувати ці підозрілі домени та час від часу шукати нові** (щодня? це займає лише кілька секунд або хвилин). Також слід **перевіряти** відкриті **порти** пов'язаних IP-адрес і **шукати екземпляри `gophish` або подібних інструментів** (так, зловмисники також припускаються помилок), а також **відстежувати вебсторінки HTTP та HTTPS підозрілих доменів і субдоменів**, щоб з'ясувати, чи скопіювали вони якусь форму входу з вебсторінок жертви.\
Щоб **автоматизувати це**, рекомендую мати список форм входу доменів жертви, виконувати spidering підозрілих вебсторінок і порівнювати кожну форму входу, знайдену в підозрілих доменах, з кожною формою входу домену жертви за допомогою чогось на кшталт `ssdeep`.\
Якщо ви знайшли форми входу підозрілих доменів, можна спробувати **надіслати некоректні облікові дані** та **перевірити, чи перенаправляють вони вас на домен жертви**.

---

### Пошук за favicon і вебвідбитками (Shodan/Censys)

Багато фішингових наборів повторно використовують favicon бренду, який вони імітують. Shodan хешує свої дані favicon, закодовані в base64, за допомогою MurmurHash3, тоді як Censys надає власні поля хешів favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Ви можете згенерувати сумісний із Shodan хеш і виконати пошук за ним:

Приклад Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Запит до Shodan: `http.favicon.hash:309020573`
- За допомогою tooling: перегляньте community tools, як-от favfreak, щоб обчислювати хеші та генерувати Shodan dorks.<sup>[[16]](#references)</sup>

Примітки
- Favicons повторно використовуються; розглядайте збіги як потенційні зачіпки та перевіряйте вміст і сертифікати перед подальшими діями.
- Поєднуйте це з евристиками віку домену та ключових слів для кращої точності.

### Полювання за телеметрією URL (urlscan.io)

`urlscan.io` зберігає історичні знімки екрана, DOM, запити та метадані TLS для надісланих URL. Ви можете шукати зловживання брендом і клони:<sup>[[8]](#references)</sup>

Приклади запитів (UI або API):
- Знаходження схожих сайтів без ваших легітимних доменів: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Знаходження сайтів, які hotlinking ваші assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Обмеження результатів за останнім часом: додайте `AND date:>now-7d`

Приклад API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
З JSON використовуйте такі поля:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, щоб виявляти дуже нові сертифікати для lookalike-доменів
- значення `task.source`, як-от `certstream-suspicious`, щоб пов’язувати результати з CT-моніторингом

### Вік домену через RDAP (придатний для використання у скриптах)

RDAP повертає події реєстрації у форматі, придатному для машинної обробки. Це корисно для виявлення **нещодавно зареєстрованих доменів (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Збагачуйте свій pipeline, додаючи до доменів категорії віку реєстрації (наприклад, <7 днів, <30 днів), і відповідно визначайте пріоритет triage.

### TLS/JAx fingerprints для виявлення AiTM-інфраструктури

Credential-phishing може використовувати reverse proxy Adversary-in-the-Middle (AiTM) (наприклад, Evilginx) для викрадення session tokens.<sup>[[11]](#references)</sup> Ви можете додати detections на мережевому рівні:

- Логуйте TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) на egress. У деяких збірках Evilginx спостерігалися стабільні значення JA4 client/server. Створюйте alert для відомих шкідливих fingerprints лише як слабкий сигнал і завжди підтверджуйте його за допомогою content та domain intel.<sup>[[12]](#references)</sup>
- Проактивно записуйте metadata TLS-сертифікатів (issuer, кількість SAN, використання wildcard, validity) для lookalike-хостів, виявлених через CT або urlscan, і корелюйте їх із віком DNS та геолокацією.

> Примітка: розглядайте fingerprints як enrichment, а не як єдиний блокувальний механізм; фреймворки розвиваються та можуть рандомізувати або обфускувати їх.

### Домени, що використовують ключові слова

На батьківській сторінці також згадується техніка варіації доменного імені, яка полягає в розміщенні **доменного імені жертви всередині більшого домену** (наприклад, paypal-financial.com для paypal.com).

#### Certificate Transparency

Журнали Certificate Transparency (CT) розкривають ідентифікатори сертифікатів, тому пошук ключових слів брендів у Subject або SAN може виявити lookalike-домени (наприклад, сертифікат для `paypal-financial.com` розкриває ключове слово `paypal`). За потреби фільтруйте результати за датою видачі та CA і перевіряйте кандидатів, оскільки збіги ключових слів можуть бути false positives.<sup>[[13]](#references)</sup>

Оригінальний [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) Patrik Hudak демонструє цей workflow у Censys, включно з фільтрами за датою сертифіката та issuer, таким як Let's Encrypt.<sup>[[13]](#references)</sup>

Ви також можете використовувати безкоштовний сервіс [**crt.sh**](https://crt.sh) для пошуку ключового слова та фільтрації результатів за датою і CA.<sup>[[13]](#references)</sup>

Його поле Matching Identities може допомогти порівняти ідентифікатори реального домену з підозрілими доменами, але розглядайте збіги як leads, а не як доказ.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) передає оновлення CT майже в реальному часі, а [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) використовує цей stream для оцінювання підозрілих назв сертифікатів.<sup>[[14]](#references)[[15]](#references)</sup>

Практична порада: під час triage результатів CT надавайте пріоритет NRD, недовіреним/невідомим registrar, WHOIS із privacy proxy та сертифікатам із дуже свіжими значеннями `NotBefore`. Підтримуйте allowlist власних доменів/брендів, щоб зменшити кількість шуму.

#### **Нові домени**

Другий варіант — збирати нещодавно зареєстровані домени за TLD (наприклад, через [Whoxy](https://www.whoxy.com/newly-registered-domains/)) і фільтрувати їх за ключовими словами брендів. Це не виявляє phishing, розміщений на subdomains, якщо ключове слово відсутнє в зареєстрованому домені.<sup>[[13]](#references)</sup>

Додаткова heuristic: під час alerting із підвищеною підозрою ставтеся до певних **TLD із розширеннями файлів** (наприклад, `.zip`, `.mov`). У lure їх часто плутають з іменами файлів; для кращої точності поєднуйте сигнал TLD із ключовими словами бренду та віком NRD.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Перехоплення трафіку до windows.com Microsoft за допомогою bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Глибокий огляд: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Документація mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Набір даних вебвластивостей платформ](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – довідник Search API](https://urlscan.io/docs/search/)
- [9] [Довідка Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-відповіді для Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Тактики роботи з токенами: як запобігати викраденню cloud-токенів, виявляти його та реагувати на нього](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – пошук phishing: інструменти й методи](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – представлення CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
