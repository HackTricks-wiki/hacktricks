# Виявлення phishing

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Щоб виявити спробу phishing, важливо **розуміти техніки phishing, які використовуються сьогодні**. На батьківській сторінці цього допису можна знайти цю інформацію, тож якщо ви не знаєте, які техніки використовуються сьогодні, рекомендую перейти на батьківську сторінку й прочитати принаймні цей розділ.

Цей допис ґрунтується на ідеї, що **зловмисники спробують певним чином імітувати або використати доменне ім'я жертви**. Якщо ваш домен називається `example.com`, а вас атакують за допомогою зовсім іншого доменного імені, наприклад `youwonthelottery.com`, ці техніки не допоможуть його виявити.

## Варіації доменних імен

Досить **легко** **виявити** спроби **phishing**, у яких в електронному листі використовується **схоже доменне** ім'я.\
Достатньо **згенерувати список найімовірніших phishing-імен**, які може використати зловмисник, і **перевірити**, чи воно **зареєстроване**, або просто перевірити, чи використовує його якась **IP-адреса**.

### Пошук підозрілих доменів

Для цього можна використовувати будь-який із наведених нижче інструментів. Обидва вони розв'язують кандидатні домени, щоб перевірити, чи використовуються вони.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Порада: якщо ви генеруєте список кандидатів, також передайте його у журнали вашого DNS-resolver, щоб виявляти **NXDOMAIN-запити зсередини вашої організації** (користувачі намагаються перейти за доменом із помилкою до того, як зловмисник фактично зареєструє його). Якщо це дозволяє політика, перенаправляйте ці домени в sinkhole або попередньо блокуйте їх.

### Bitflipping

**Для короткого пояснення дивіться батьківську сторінку; основні дослідження bitsquatting для Windows.com дивіться у [матеріалі Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) та [звіті BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Наприклад, зміна 1 біта в домені microsoft.com може перетворити його на _windnws.com._\
**Зловмисники можуть зареєструвати якомога більше доменів із bit-flipping, пов'язаних із жертвою, щоб перенаправляти легітимних користувачів на свою інфраструктуру**.<sup>[[1]](#references)[[2]](#references)</sup>

**Також слід відстежувати всі можливі доменні імена з bit-flipping.**

Якщо вам також потрібно враховувати homoglyph/IDN-двійники (наприклад, змішування латинських і кириличних символів), перегляньте:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Базові перевірки

Після того як ви склали список потенційно підозрілих доменних імен, слід **перевірити** їх (передусім порти HTTP і HTTPS), щоб **з'ясувати, чи використовують вони форму входу, схожу** на форму входу в одному з доменів жертви.\
Також можна перевірити порт 3333, щоб з'ясувати, чи відкритий він і чи працює на ньому екземпляр `gophish`.\
Також важливо знати, **скільки років кожному виявленому підозрілому домену**: що він молодший, то вищий ризик.\
Можна також отримати **скриншоти** підозрілої вебсторінки HTTP та/або HTTPS, щоб перевірити, чи є вона підозрілою, і в такому разі **відкрити її для детальнішого аналізу**.

### Розширені перевірки

Якщо ви хочете піти далі, рекомендую **відстежувати ці підозрілі домени та час від часу шукати нові** (щодня? це займає лише кілька секунд/хвилин). Також слід **перевіряти** відкриті **порти** пов'язаних IP-адрес і **шукати екземпляри `gophish` або подібних інструментів** (так, зловмисники теж припускаються помилок), а також **відстежувати вебсторінки HTTP і HTTPS підозрілих доменів і субдоменів**, щоб перевірити, чи не скопіювали вони форму входу з вебсторінок жертви.\
Щоб **автоматизувати це**, рекомендую мати список форм входу з доменів жертви, виконувати spidering підозрілих вебсторінок і порівнювати кожну знайдену в підозрілих доменах форму входу з кожною формою входу в домені жертви за допомогою чогось на кшталт `ssdeep`.\
Якщо ви виявили форми входу підозрілих доменів, можна спробувати **надіслати тестові облікові дані** та **перевірити, чи перенаправляє система вас на домен жертви**.

---

### Пошук за favicon і вебвідбитками (Shodan/Censys)

Багато phishing-kit повторно використовують favicon бренду, який вони імітують. Shodan хешує свої дані favicon, закодовані в base64, за допомогою MurmurHash3, тоді як Censys надає власні поля хешів favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Ви можете згенерувати сумісний із Shodan хеш і виконати пошук за ним:

Приклад Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Запитайте Shodan: `http.favicon.hash:309020573`
- За допомогою tooling: ознайомтеся зі спільнотними інструментами, такими як favfreak, для обчислення хешів і генерування Shodan dorks.<sup>[[16]](#references)</sup>

Примітки
- Favicons повторно використовуються; розглядайте збіги як зачіпки та перевіряйте вміст і сертифікати перед діями.
- Поєднуйте це з евристиками віку домену та ключових слів для кращої точності.

### Полювання за URL-телеметрією (urlscan.io)

`urlscan.io` зберігає історичні знімки екрана, DOM, запити та метадані TLS надісланих URL. Ви можете шукати зловживання брендом і клони:<sup>[[8]](#references)</sup>

Приклади запитів (UI або API):
- Знайти схожі сайти, виключивши ваші легітимні домени: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Знайти сайти, що підключають ваші assets через hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Обмежити результати за останнім часом: додайте `AND date:>now-7d`

Приклад API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
З JSON використовуйте такі поля:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, щоб виявляти дуже нові сертифікати для lookalike-доменів
- значення `task.source`, наприклад `certstream-suspicious`, щоб пов’язувати результати з моніторингом CT

### Вік домену через RDAP (придатний для використання у скриптах)

RDAP повертає машиночитабельні події реєстрації. Це корисно для виявлення **новозареєстрованих доменів (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Збагачуйте свій pipeline, позначаючи домени за категоріями віку реєстрації (наприклад, <7 днів, <30 днів), і відповідно визначайте пріоритет під час triage.

### TLS/JAx fingerprints для виявлення AiTM-інфраструктури

Credential-phishing може використовувати reverse proxy **Adversary-in-the-Middle (AiTM)** (наприклад, Evilginx) для викрадення session tokens.<sup>[[11]](#references)</sup> Ви можете додати detections на мережевому рівні:

- Записуйте TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) на egress. У деяких збірках Evilginx спостерігалися стабільні клієнтські/серверні значення JA4. Використовуйте відомі шкідливі fingerprints для alerting лише як слабкий сигнал і завжди підтверджуйте їх за допомогою аналізу вмісту та domain intel.<sup>[[12]](#references)</sup>
- Проактивно записуйте метадані TLS-сертифікатів (issuer, кількість SAN, використання wildcard, строк дії) для схожих на справжні хостів, виявлених через CT або urlscan, і зіставляйте їх із віком DNS та геолокацією.

> Примітка: розглядайте fingerprints як enrichment, а не як єдиний механізм блокування; frameworks розвиваються та можуть рандомізувати або приховувати їх.

### Доменные імена з використанням keywords

На батьківській сторінці також згадується техніка варіації доменного імені, яка полягає в розміщенні **доменного імені жертви всередині більшого домену** (наприклад, paypal-financial.com для paypal.com).

#### Certificate Transparency

Логи Certificate Transparency (CT) розкривають ідентичності сертифікатів, тому пошук brand keywords у назвах Subject або SAN може виявити схожі на справжні домени (наприклад, сертифікат для `paypal-financial.com` розкриває keyword `paypal`). За потреби фільтруйте результати за датою випуску та CA і перевіряйте кандидатів, оскільки збіги keywords можуть бути false positives.<sup>[[13]](#references)</sup>

Оригінальний [матеріал Patrik Hudak про пошук phishing-доменів](https://0xpatrik.com/phishing-domains/) демонструє цей workflow у Censys, включно з фільтрами за датою сертифіката та issuer, наприклад Let's Encrypt.<sup>[[13]](#references)</sup>

Також можна скористатися безкоштовним сервісом [**crt.sh**](https://crt.sh), щоб виконати пошук за keyword і відфільтрувати результати за датою та CA.<sup>[[13]](#references)</sup>

Його поле Matching Identities може допомогти порівняти ідентичності реального домену з підозрілими доменами, але розглядайте збіги як підстави для подальшої перевірки, а не як доказ.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) передає оновлення CT майже в реальному часі, а [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) використовує цей stream для оцінювання підозрілих назв сертифікатів.<sup>[[14]](#references)[[15]](#references)</sup>

Практична порада: під час triage результатів CT надавайте пріоритет NRD, ненадійним/невідомим registrar, WHOIS із privacy-proxy та сертифікатам із дуже недавніми значеннями `NotBefore`. Підтримуйте allowlist власних доменів/брендів, щоб зменшити кількість шуму.

#### **New domains**

Другий варіант — збирати нещодавно зареєстровані домени за TLD (наприклад, через [Whoxy](https://www.whoxy.com/newly-registered-domains/)) і фільтрувати їх за brand keywords. Цей підхід не виявляє phishing, розміщений на subdomains, якщо keyword відсутній у зареєстрованому домені.<sup>[[13]](#references)</sup>

Додаткова heuristic: під час alerting із підвищеною підозрою ставтеся до певних **TLD із розширеннями файлів** (наприклад, `.zip`, `.mov`). У lure їх часто помилково сприймають як імена файлів; для кращої точності поєднуйте сигнал TLD із brand keywords і віком NRD.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Перехоплення трафіку до windows.com компанії Microsoft за допомогою bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Поглиблений огляд: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Документація mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Набір даних Platform Web Property](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Довідник Search API](https://urlscan.io/docs/search/)
- [9] [Довідка Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-відповіді для Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Тактики роботи з токенами: як запобігати викраденню cloud-токенів, виявляти його та реагувати на нього](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Блог APNIC – мережева fingerprinting-технологія JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Виявлення phishing: інструменти та техніки](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Представлення CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
