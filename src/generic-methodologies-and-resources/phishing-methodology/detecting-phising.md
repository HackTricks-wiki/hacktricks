# Виявлення Phishing

{{#include ../../banners/hacktricks-training.md}}

## Вступ

Щоб виявити спробу phishing, важливо **розуміти техніки phishing, які використовуються сьогодні**. На батьківській сторінці цього допису можна знайти цю інформацію, тому, якщо ви не знаєте, які техніки використовуються сьогодні, рекомендую перейти на батьківську сторінку та прочитати принаймні цей розділ.

Цей допис ґрунтується на ідеї, що **атакувальники намагатимуться певним чином імітувати доменне ім'я жертви або використовувати його**. Якщо ваш домен називається `example.com`, а вас піддали phishing, використовуючи з якоїсь причини зовсім інше доменне ім'я, наприклад `youwonthelottery.com`, ці техніки не допоможуть це виявити.

## Варіації доменних імен

Досить **легко** **виявити** ті спроби **phishing**, у яких в email використовується **схоже доменне** ім'я.\
Достатньо **згенерувати список найімовірніших phishing-імен**, які може використати атакувальник, і **перевірити**, чи вони **зареєстровані**, або просто перевірити, чи використовується якась **IP-адреса**.

### Пошук підозрілих доменів

Для цього можна використати будь-який із наведених нижче інструментів. Обидва виконують resolve кандидатних доменів, щоб перевірити, чи використовуються вони.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Порада: якщо ви генеруєте список кандидатів, також передайте його до логів вашого DNS resolver, щоб виявляти **NXDOMAIN-запити зсередини вашої організації** (користувачі намагаються перейти за помилково написаним доменом до того, як атакувальник фактично його зареєструє). Якщо політика це дозволяє, перенаправте ці домени до sinkhole або заздалегідь заблокуйте їх.

### Bitflipping

**Для короткого пояснення дивіться батьківську сторінку; основне дослідження bitsquatting для Windows.com дивіться у [матеріалі Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) та [звіті BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Наприклад, зміна 1 біта в домені microsoft.com може перетворити його на _windnws.com._\
**Атакувальники можуть зареєструвати якомога більше доменів із bit-flipping, пов'язаних із жертвою, щоб перенаправляти легітимних користувачів до своєї інфраструктури**.<sup>[[1]](#references)[[2]](#references)</sup>

**Також слід відстежувати всі можливі доменні імена з bit-flipping.**

Якщо вам також потрібно враховувати lookalike-домени homoglyph/IDN (наприклад, зі змішуванням латинських і кириличних символів), дивіться:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Базові перевірки

Після того як ви отримали список потенційно підозрілих доменних імен, слід **перевірити** їх (переважно порти HTTP та HTTPS), щоб **з'ясувати, чи використовують вони якусь login form, схожу** на login form домену жертви.\
Також можна перевірити порт 3333, щоб з'ясувати, чи відкритий він і чи працює на ньому екземпляр `gophish`.\
Також важливо знати, **скільки років кожному виявленому підозрілому домену**: чим він молодший, тим вищий ризик.\
Можна також отримати **скриншоти** підозрілої HTTP- та/або HTTPS-вебсторінки, щоб з'ясувати, чи є вона підозрілою, і в такому разі **перейти до неї для детальнішого аналізу**.

### Розширені перевірки

Якщо ви хочете піти далі, рекомендую **відстежувати ці підозрілі домени та час від часу шукати нові** (щодня? це займає лише кілька секунд/хвилин). Також слід **перевіряти** відкриті **порти** пов'язаних IP-адрес і **шукати екземпляри `gophish` або схожих інструментів** (так, атакувальники також помиляються), а також **відстежувати HTTP- та HTTPS-вебсторінки підозрілих доменів і піддоменів**, щоб з'ясувати, чи скопіювали вони login form із вебсторінок жертви.\
Щоб **автоматизувати це**, рекомендую мати список login form доменів жертви, виконувати spidering підозрілих вебсторінок і порівнювати кожну login form, знайдену в підозрілих доменах, з кожною login form домену жертви за допомогою чогось на кшталт `ssdeep`.\
Якщо ви виявили login form підозрілих доменів, можна спробувати **надіслати фіктивні облікові дані** та **перевірити, чи перенаправляє вона вас на домен жертви**.

---

### Пошук за favicon і web fingerprints (Shodan/Censys)

Багато phishing kits повторно використовують favicon бренду, який вони імітують. Shodan хешує свої base64-кодовані дані favicon за допомогою MurmurHash3, а Censys надає власні поля хешів favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Можна згенерувати сумісний із Shodan хеш і виконати pivot за ним:

Приклад Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Запит до Shodan: `http.favicon.hash:309020573`
- За допомогою tooling: ознайомтеся зі community tools, як-от favfreak, щоб обчислювати хеші та генерувати Shodan dorks.<sup>[[16]](#references)</sup>

Примітки
- Favicons перевикористовуються; розглядайте збіги як потенційні напрямки для перевірки та перевіряйте вміст і сертифікати перед виконанням будь-яких дій.
- Поєднуйте це з heuristics щодо віку домену та ключових слів для підвищення точності.

### Полювання за URL-телеметрією (urlscan.io)

`urlscan.io` зберігає історичні знімки екрана, DOM, запити та метадані TLS для надісланих URL. Ви можете шукати зловживання брендом і клони:<sup>[[8]](#references)</sup>

Приклади запитів (UI або API):
- Пошук lookalikes, за винятком ваших легітимних доменів: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Пошук сайтів, що hotlink-ять ваші assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Обмеження результатів за останнім часом: додайте `AND date:>now-7d`

Приклад API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Із JSON виконайте pivot за такими полями:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, щоб виявити дуже нові сертифікати для lookalike-доменів
- значеннями `task.source`, як-от `certstream-suspicious`, щоб пов’язати результати з CT monitoring

### Вік домену через RDAP (придатний для автоматизації)

RDAP повертає машиночитані події реєстрації. Це корисно для виявлення **щойно зареєстрованих доменів (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Збагачуйте свій pipeline, додаючи до доменів категорії віку реєстрації (наприклад, <7 днів, <30 днів), і відповідно визначайте пріоритет triage.

### TLS/JAx fingerprints для виявлення AiTM-інфраструктури

Credential-phishing може використовувати reverse proxy типу **Adversary-in-the-Middle (AiTM)** (наприклад, Evilginx), щоб викрадати session tokens.<sup>[[11]](#references)</sup> Ви можете додати detections на мережевому рівні:

- Логуйте TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) на egress. У деяких збірках Evilginx спостерігалися стабільні клієнтські/серверні значення JA4. Використовуйте alert лише для відомих шкідливих fingerprints як слабкий сигнал і завжди підтверджуйте його за допомогою content та domain intel.<sup>[[12]](#references)</sup>
- Проактивно записуйте метадані TLS-сертифікатів (issuer, кількість SAN, використання wildcard, validity) для lookalike-хостів, виявлених через CT або urlscan, і корелюйте їх із віком DNS та геолокацією.

> Примітка: розглядайте fingerprints як enrichment, а не як єдині blockers; frameworks розвиваються та можуть рандомізувати або обфускувати їх.

### Домени, що використовують keywords

На батьківській сторінці також згадується техніка варіації доменного імені, яка полягає в розміщенні **доменного імені жертви всередині більшого домену** (наприклад, paypal-financial.com для paypal.com).

#### Certificate Transparency

Журнали Certificate Transparency (CT) розкривають ідентичності сертифікатів, тому пошук brand keywords у Subject або SAN може виявити lookalike-домени (наприклад, сертифікат для `paypal-financial.com` розкриває keyword `paypal`). За потреби фільтруйте результати за датою видачі та CA і перевіряйте кандидатів, оскільки збіги keywords можуть бути false positives.<sup>[[13]](#references)</sup>

Оригінальний [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) Patrik Hudak демонструє цей workflow у Censys, включно з filters для дати сертифіката та issuer, наприклад Let's Encrypt.<sup>[[13]](#references)</sup>

![Результати пошуку сертифікатів у Censys, використані для виявлення lookalike-доменів](<../../images/image (1115).png>)

Також можна скористатися безкоштовним сервісом [**crt.sh**](https://crt.sh), щоб шукати keyword і фільтрувати результати за датою та CA.<sup>[[13]](#references)</sup>

![Пошук підозрілих ідентичностей сертифікатів за keyword у crt.sh](<../../images/image (519).png>)

Поле Matching Identities може допомогти порівняти ідентичності реального домену з підозрілими доменами, але розглядайте збіги як leads, а не як доказ.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) передає оновлення CT майже в реальному часі, а [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) споживає цей stream для оцінювання підозрілих назв сертифікатів.<sup>[[14]](#references)[[15]](#references)</sup>

Практична порада: під час triage результатів CT надавайте пріоритет NRDs, ненадійним/невідомим реєстраторам, WHOIS із privacy-proxy та сертифікатам із дуже недавніми значеннями `NotBefore`. Підтримуйте allowlist власних доменів/брендів, щоб зменшити шум.

#### **Нові домени**

Другий варіант — збирати нещодавно зареєстровані домени за TLD (наприклад, через [Whoxy](https://www.whoxy.com/newly-registered-domains/)) і фільтрувати їх за brand keywords. Цей підхід не виявляє phishing, розміщений на subdomains, якщо keyword відсутній у зареєстрованому домені.<sup>[[13]](#references)</sup>

Додаткова heuristic: під час alerting із підвищеною підозрою розглядайте певні **file-extension TLDs** (наприклад, `.zip`, `.mov`). У lure їх часто плутають із назвами файлів; для кращої точності поєднуйте сигнал TLD із brand keywords та віком NRD.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Перехоплення трафіку до windows.com від Microsoft за допомогою bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Поглиблений огляд: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Документація mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Набір даних вебвластивостей платформ](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Довідник Search API](https://urlscan.io/docs/search/)
- [9] [Довідка Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON-відповіді для Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Тактики роботи з токенами: як запобігати викраденню cloud-токенів, виявляти його та реагувати на нього](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Мережева fingerprinting-технологія JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Виявлення phishing: інструменти та техніки](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Представлення CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
