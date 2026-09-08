# Атрибуція, виявлення та контрзаходи

{{#include ../banners/hacktricks-training.md}}

Інфраструктура для ухилення від атрибуції створена так, щоб окремі індикатори можна було замінювати. Захисники повинні зберігати необроблені докази, моделювати зв’язки та шукати поведінку, яка зберігається після зміни IP, домену або персони.

## Ієрархія доказів

| Доказ | Корисний для | Основне застереження |
|---|---|---|
| Source IP/ASN/geolocation | визначення видимого виходу та провайдера | вихід може бути relay, NAT або жертвою; геолокація приблизна |
| Passive DNS/registration | історії інфраструктури та спільного хостингу | privacy/redaction і shared hosting створюють прогалини |
| Certificate/TLS/HTTP fingerprint | кластеризації повторних розгортань | common software і mimicry створюють false positives |
| Flow timing and byte shape | пов’язування етапів relay і повторюваних beacon | CDN/NAT та обмежена видимість знижують достовірність |
| Endpoint process/identity | пояснення причини встановлення з’єднання | відсутні на edge/IoT; attacker може використовувати native tools |
| Cloud/CDN/API audit | визначення tenant та контролю інфраструктури | термін зберігання і провайдерський/юридичний доступ різняться |
| Payment/account/device | пов’язування закупівлі з особою/організацією | необхідно враховувати nominee, compromise та спільні пристрої |
| Seized implant/configuration | виявлення ключів, peers, контролерів і зв’язків збірки | важливі цілісність збору та час вилучення |
| Human/physical evidence | пов’язування цифрової події з місцем/оператором | інвазивні, залежать від юрисдикції та потребують суворого поводження |

Жоден окремий рядок не повинен бути підставою для атрибуції держави з високою впевненістю. Використовуйте конкуруючі гіпотези та вказуйте, яке спостереження спростувало б кожну з них.

## Мінімальна телеметрія

1. **DNS:** клієнт, запит, тип, відповіді, TTL, код відповіді, resolver і часова мітка.
2. **Network flow:** source/destination/port, початок/завершення, пакети/байти, TCP flags і розташування сенсора.
3. **TLS/HTTP:** SNI, коли видимий, сертифікат, узгоджений протокол, client/server fingerprint, метод, категорія authority/path, статус і кількість байтів. Захищайте конфіденційні повні URL.
4. **Identity:** результат автентифікації, factor/certificate/device, source, application, ID сесії та рішення щодо ризику.
5. **Endpoint:** процес-ініціатор, батьківський процес, користувач, підпис/хеш binary та destination.
6. **Edge/network device:** diff конфігурації, admin login, цілісність процесів/файлів/firmware, журнали інтерфейсів і flow.
7. **Cloud/SaaS/CDN:** actor, tenant/project, дія API, source, object/resource, token і результат.
8. **Wireless/NAC:** station, прапорець randomized-MAC, AP, сигнал, EAP identity/certificate, призначені VLAN/IP і posture.

Синхронізуйте годинники, зберігайте оригінальні часові пояси, документуйте межі NAT/proxy та зберігайте достатню історію, щоб пережити 31-денний вузол ORB.

## Побудова графа атрибуції

Представляйте спостереження як типізовані вузли та ребра:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Корисні вузли включають IP, prefix, ASN, domain, DNS account, certificate/key, fingerprint на кшталт JA3/JA4, HTTP grammar, hash файлу/конфігурації, cloud tenant, API token, email, persona, платіжний інструмент і фізичний пристрій. Кожне ребро має містити `first_seen`, `last_seen`, sensor/source, confidence і зазначення, чи є воно спостережуваним або виведеним.

Сама лише щільність графа вводить в оману: CDN або certificate authority з'єднує багато не пов'язаних між собою акторів. Надавайте більшу вагу рідкісним зв'язкам, контрольованим оператором, — тому самому API account, SSH key, origin allowlist, унікальному тілу відповіді або control protocol — ніж поширеному hosting.

## ORB і пошук скомпрометованих маршрутизаторів

### Від спостережуваного exit

1. Визначте, чи є адреса hosting, residential, mobile, education або business; не відкидайте residential sources.
2. Отримайте історичні DNS, services/certificates, відкриті порти та спостережувану scan/exploitation behavior за обмежений період.
3. Шукайте вузли-аналоги, що мають спільні рідкісні service fingerprints, controller destinations, certificate material або час ротації.
4. Класифікуйте ймовірні ролі: access, traversal, exit/staging або administration.
5. Перевірте, чи використовували кілька не пов'язаних між собою intrusion clusters той самий pool; multi-tenancy послаблює пряму атрибуцію актора, але посилює ORB hypothesis.
6. Відстежуйте нові вузли, що відповідають профілю ролі, після зникнення старих IP.

### У network owner

- Створіть alert для нових Internet-exposed management і default/legacy authentication.
- Передавайте зміни router/firewall/VPN configuration та admin authentication за межі пристрою.
- Створіть baseline для outbound connections від інфраструктури, яка зазвичай ініціює мало сесій.
- Виявляйте нові proxy/listener processes, tunnels, scheduled tasks, firmware changes і неочікувані DNS.
- Замініть end-of-life devices; reboot, який видаляє volatile malware, не усуває exposure.
- Обмежте management автентифікованим administration plane і відомими sources.

Mandiant рекомендує відстежувати ORB infrastructure як сутність, що розвивається, оскільки короткочасне блокування IP не відображає topology та lifecycle.<sup>[[1]](#references)</sup>

## Аналітика Fast-flux і dynamic-DNS

Агрегуйте за зареєстрованим domain і sliding window. Практичний score може поєднувати:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Досліджуйте домени за кількома незалежними ознаками, а не за одним пороговим значенням. Порівнюйте їх із allow-моделлю CDN/anti-DDoS і перевіряйте ротацію авторитетних name-серверів, щоб відрізнити single flux від double flux. Для DGA додавайте сплески NXDOMAIN для кожного клієнта, розподіл довжини/символів, синхронізовані запити між хостами та процес, який їх генерує. Поточні рекомендації MITRE також наголошують на частих змінах, низькому TTL і кореляції процесів та мережі.<sup>[[2]](#references)</sup>

## Виявлення Domain-fronting

Якщо корпоративна кінцева точка або авторизована точка перевірки має обидві ідентичності, порівнюйте:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Підвищуйте рівень впевненості, коли SNI та authority належать непов’язаним tenant'ам, процес не є схваленим клієнтом, сесія є періодичною/довготривалою, а внутрішній origin трапляється рідко. Порожній SNI — це ознака, яку слід зафіксувати, а не автоматично вважати шкідливою. ECH може приховувати SNI у мережі, тому журнали endpoint, DNS і provider/CDN стають важливішими. MITRE документує як варіанти з невідповідністю, так і варіанти з порожнім SNI.<sup>[[3]](#references)</sup>

## Виявлення послідовностей dead-drop resolver

Поведінка з високою сигнальністю — це послідовність, а не заблокований домен:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Полюйте по всьому флоту на ідентичні шляхи об'єктів, хеші відповідей, API-ідентифікатори та наступні destinations. Зберігайте отриманий контент, оскільки actor може його відредагувати або видалити. Обмежуйте непотрібні service APIs і вимагайте, щоб схвалені застосунки використовували enterprise proxies, але враховуйте developer tools та автоматизацію. MITRE наводить GitHub, форуми, документи та social/web services у реальних процедурах.<sup>[[4]](#references)</sup>

## Кластеризація Redirector і повторно використовуваних розгортань

Навіть коли домени й адреси змінюються, operators часто повторно розгортають ту саму автоматизацію. Кластеризуйте за комбінаціями:

- полів сертифікатів/повторного використання ключів і часу видачі;
- версії TLS/порядку cipher/extension і поведінки сервера;
- ідентичних HTTP status, порядку заголовків, поведінки кешу, icon/body та error page;
- незвичних пар портів і ланцюжків перенаправлень;
- шаблону DNS provider/name-server і розкладу TTL;
- часу розгортання, доступності та вікна обслуговування;
- розкриття back-end origin або ідентичних allowlists.

Одна стандартна сторінка Nginx є слабким доказом. Кілька рідкісних незалежних збігів разом із часовою безперервністю можуть обґрунтувати гіпотезу про кластер інфраструктури.

## Виявлення Residential proxy та неможливих сесій

Підтримуйте ідентичність сесії на рівні вище за IP. Позначайте такі комбінації:

- один session/device fingerprint змінює країни/ASN швидше, ніж це дозволяє подорож;
- consumer IP змінюється з кожним запитом, тоді як cookies та TLS/browser identity залишаються незмінними;
- заявлений локальний пристрій має latency/time-zone/language, несумісні з exit;
- адреса почергово використовується непов'язаними популяціями акаунтів або демонструє поведінку backconnect proxy;
- privileged session з'являється через residential access без device certificate організації.

Carrier NAT, accessibility tools, corporate VPNs і подорожі спричиняють benign anomalies. Вимагайте step-up authentication або розслідування замість незворотного блокування, що ґрунтується лише на labels “residential proxy”.

## Виявлення Wireless і covert devices

Об'єднуйте RADIUS/NAC із контекстом AP та фізичного розташування:

1. знаходьте вперше помічені комбінації account–device–AP;
2. визначайте credentials, використані без managed EAP certificate/posture;
3. порівнюйте одночасні сесії та присутність у будівлі за badge;
4. перевіряйте незвично слабкий/граничний signal і переміщення між AP;
5. шукайте на nearby managed endpoints wireless scanning, щойно увімкнений interface bridge/NAT, virtual adapters або tunnels;
6. проводьте інвентаризацію нової активності switchport, DHCP, USB network і PoE;
7. виконуйте authorized RF/physical sweep, якщо докази це підтверджують.

Це виявляє як path у стилі APT28 до найближчого сусіда, так і exercise drop. MAC randomization не можна трактувати як ідентичність або доказ вини.

## Виявлення Financial-attribution

- Зберігайте точний chain, token, address, transaction та block identifiers.
- Відстежуйте value через change, peel chains, fan-out/in, mixers, bridges і service deposits, позначаючи heuristics.
- Співвідносьте час, amount мінус fees, contract event, liquidity та withdrawal у destination-chain.
- Отримуйте або зберігайте lawful exchange, bridge, merchant, account, device та delivery records.
- Перевіряйте поточні sanctioned entities/addresses і похідні об'єкти за відповідною програмою; не покладайтеся на старий static list.
- Розглядайте використання privacy-protocol як вхідні дані risk-context, а не як доказ правопорушення.

Red flags FATF прямо залежать від контексту: незвичний pattern, amount/frequency, geography, source of funds і anonymity-enhancing services набувають значення разом.<sup>[[5]](#references)</sup>

## Deception і canaries

Defenders можуть створювати high-confidence signals, не намагаючись deanonymize звичайних користувачів:

- унікальні credentials або документи, які ніколи не повинні залишати одну систему;
- fake administrative endpoints і decoy shares;
- instrumented DNS names, вбудовані лише у контрольовані artifacts;
- canary cloud keys без legitimate use;
- decoy Wi-Fi identity, якою не володіє жоден managed device.

Ретельно визначайте scope і керуйте deception. Canary має виявляти неправомірне використання власного asset захисника, а не збирати непов'язаний traffic третіх сторін.

## Пріоритети Countermeasure

1. Видаліть routers, VPNs та appliances, доступні з Internet, які не мають підтримки.
2. Вимагайте phishing-resistant MFA і device-bound certificates, включно з internal/wireless access.
3. Централізуйте достатньо immutable identity, endpoint, DNS, flow, proxy, cloud та network-device logs.
4. Обмежте management і egress; проведіть інвентаризацію кожного externally reachable service.
5. Відстежуйте DNS, certificate transparency і cloud configuration на предмет unauthorized assets.
6. Збережіть process-to-network та object-level SaaS visibility.
7. Проводьте cross-layer investigations і координацію з neighboring providers.
8. Відстежуйте infrastructure clusters і behaviors, а не лише IP blocklists.

## Аналітична дисципліна

Використовуйте формулювання рівня впевненості:

- **Observed:** запис sensor/provider безпосередньо показує зв'язок.
- **Strongly supported:** кілька незалежних спостережень підтримують його більше, ніж альтернативи.
- **Assessed:** inference, що ґрунтується на заявлених припущеннях і доказах.
- **Unknown:** недостатня visibility не дозволяє зробити висновок.

Завжди підтримуйте щонайменше дві гіпотези: infrastructure, якою керує actor, проти compromised/shared intermediary; один actor проти multi-tenant service; deliberate evasion проти legitimate privacy/CDN behavior. Здатність пояснити невизначеність є частиною коректного detection.

## References

- [1] [Google Cloud/Mandiant — Актори шпигунства, пов'язані з Китаєм, використовують ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Індикатори red flags для Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Актори КНР компрометують і підтримують persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Рекомендації щодо enhanced visibility і hardening для communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
