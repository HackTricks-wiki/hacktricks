# Атрибуція, виявлення та контрзаходи

Інфраструктура для ухилення від атрибуції призначена для того, щоб окремі індикатори можна було замінювати. Захисники повинні зберігати необроблені докази, моделювати взаємозв’язки та шукати поведінку, яка зберігається після зміни IP, домену або персони.

## Ієрархія доказів

| Доказ | Корисний для | Основне застереження |
|---|---|---|
| Source IP/ASN/geolocation | визначення видимого виходу та провайдера | вихід може бути relay, NAT або скомпрометованою системою; геолокація приблизна |
| Passive DNS/registration | історії інфраструктури та спільного хостингу | privacy/redaction і shared hosting створюють прогалини |
| Certificate/TLS/HTTP fingerprint | кластеризації повторних розгортань | поширене ПЗ та mimicry створюють false positives |
| Flow timing and byte shape | зв’язування етапів relay і повторюваних beacon | CDN/NAT та обмежена видимість знижують певність |
| Endpoint process/identity | пояснення причини встановлення з’єднання | відсутні на edge/IoT; attacker може використовувати native tools |
| Cloud/CDN/API audit | ідентифікації tenant та контролю над інфраструктурою | терміни зберігання та provider/legal access відрізняються |
| Payment/account/device | пов’язування закупівлі з особою/організацією | необхідно враховувати nominee, compromise та спільні пристрої |
| Seized implant/configuration | виявлення keys, peers, controllers і build links | важливі цілісність збору та час вилучення |
| Human/physical evidence | пов’язування цифрової події з місцем/operator | intrusive, залежить від юрисдикції та потребує суворого поводження |

Жоден окремий рядок не повинен забезпечувати атрибуцію state з високою впевненістю. Використовуйте конкуруючі гіпотези та вказуйте, яке спостереження могло б спростувати кожну з них.

## Мінімальна телеметрія

1. **DNS:** client, question, type, answers, TTL, response code, resolver і timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags і sensor location.
3. **TLS/HTTP:** SNI, коли доступний, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status і byte count. Захищайте чутливі повні URL.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID і risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash і destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface і flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token і result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP і posture.

Синхронізуйте clocks, зберігайте оригінальні часові пояси, документуйте межі NAT/proxy та зберігайте достатню історію, щоб пережити 31-денний ORB node.

## Побудова графа атрибуції

Представляйте спостереження як типізовані nodes і edges:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Корисні вузли включають IP, prefix, ASN, domain, DNS account, certificate/key, відбиток на кшталт JA3/JA4, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, платіжний інструмент і фізичний пристрій. Кожне ребро має містити `first_seen`, `last_seen`, sensor/source, рівень упевненості та ознаку того, чи є воно observed або inferred.

Сама лише щільність графа вводить в оману: CDN або certificate authority з'єднує багато не пов'язаних між собою акторів. Надавайте більшу вагу рідкісним зв'язкам, контрольованим оператором, — тому самому API account, SSH key, origin allowlist, унікальному тілу відповіді або control protocol — ніж поширеному hosting.

## ORB та пошук скомпрометованих маршрутизаторів

### Із observed exit

1. Визначте, чи є адреса hosting, residential, mobile, education або business; не відкидайте residential sources.
2. За обмежений період отримайте historical DNS, services/certificates, open ports і спостережувану scan/exploitation behavior.
3. Шукайте вузли, що мають спільні рідкісні service fingerprints, controller destinations, certificate material або timing ротації.
4. Класифікуйте ймовірні ролі: access, traversal, exit/staging або administration.
5. Перевірте, чи використовували той самий pool кілька не пов'язаних між собою intrusion clusters; multi-tenancy послаблює пряму attribution актора, але посилює ORB hypothesis.
6. Відстежуйте нові вузли, що відповідають профілю ролі, після зникнення старих IP.

### На боці network owner

- Створюйте alert на нові Internet-exposed management і default/legacy authentication.
- Передавайте зміни router/firewall/VPN configuration та admin authentication off-device.
- Створюйте baseline outbound connections для infrastructure, яка зазвичай ініціює мало сесій.
- Виявляйте нові proxy/listener processes, tunnels, scheduled tasks, firmware changes і неочікуваний DNS.
- Замінюйте end-of-life devices; reboot, який видаляє volatile malware, не усуває exposure.
- Обмежуйте management до authenticated administration plane та відомих sources.

Mandiant рекомендує відстежувати ORB infrastructure як entity, що розвивається, оскільки короткочасне IP blocking не відображає topology та lifecycle.<sup>[[1]](#references)</sup>

## Fast-flux та dynamic-DNS analytics

Агрегуйте за registered domain і sliding window. Практичний score може поєднувати:
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
Досліджуйте домени за кількома незалежними ознаками, а не за одним пороговим значенням. Порівнюйте їх із allow-моделлю CDN/anti-DDoS і перевіряйте ротацію authoritative name-серверів, щоб відрізнити single flux від double flux. Для DGA додайте сплески NXDOMAIN для кожного клієнта, розподіл довжини та символів, синхронізовані запити між хостами й процес, який їх генерує. Поточні рекомендації MITRE також наголошують на частих змінах, низькому TTL і кореляції процесів та мережевої активності.<sup>[[2]](#references)</sup>

## Виявлення Domain-fronting

Якщо корпоративна кінцева точка або авторизована точка перевірки має обидві ідентичності, порівняйте:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Підвищуйте рівень впевненості, коли SNI та authority належать непов’язаним tenant, процес не є схваленим client, сесія є періодичною/довготривалою, а внутрішній origin є рідкісним. Порожній SNI — це ознака, яку слід записувати, а не автоматично вважати шкідливою. ECH може приховувати SNI у мережі, тому журнали endpoint, DNS і provider/CDN стають важливішими. MITRE документує як варіанти з невідповідністю, так і варіанти з порожнім SNI.<sup>[[3]](#references)</sup>

## Виявлення послідовності dead-drop resolver

Поведінка з високою сигнальністю — це послідовність, а не заблокований домен:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Полюйте по всьому флоту на ідентичні шляхи об'єктів, хеші відповідей, ідентифікатори API та подальші destinations. Зберігайте отриманий вміст, оскільки actor може його редагувати або видалити. Обмежте непотрібні service APIs і вимагайте, щоб схвалені застосунки використовували enterprise proxies, але враховуйте developer tools та automation. MITRE наводить GitHub, форуми, документи й social/web services у реальних процедурах.<sup>[[4]](#references)</sup>

## Кластеризація redirector і повторно використовуваних deployment

Навіть коли домени й адреси змінюються, operators часто повторно розгортають ту саму automation. Кластеризуйте за комбінаціями:

- полів сертифіката/повторного використання ключа та часу видачі;
- версії TLS/порядку cipher/extension і поведінки сервера;
- ідентичних HTTP status, порядку заголовків, поведінки cache, icon/body та сторінки помилки;
- незвичних пар портів і redirect chains;
- шаблону DNS provider/name-server та розкладу TTL;
- часу deployment, uptime та вікна maintenance;
- розкриття back-end origin або ідентичних allowlists.

Одна типова сторінка Nginx є слабким доказом. Кілька рідкісних незалежних збігів разом із часовою безперервністю можуть обґрунтувати гіпотезу про кластер інфраструктури.

## Виявлення residential proxy та неможливих сесій

Підтримуйте ідентичність сесії на рівні вище за IP. Позначайте такі комбінації:

- один session/device fingerprint змінює країни/ASNs швидше, ніж це дозволяє переміщення;
- consumer IP змінюється з кожним запитом, тоді як cookies і TLS/browser identity залишаються незмінними;
- заявлений локальний пристрій має latency/time-zone/language, несумісні з exit;
- адреса чергує unrelated account populations або демонструє поведінку backconnect proxy;
- privileged session з'являється з residential access без device certificate організації.

Carrier NAT, accessibility tools, corporate VPNs і подорожі створюють нешкідливі аномалії. Вимагайте step-up authentication або розслідування замість незворотного блокування, яке ґрунтується лише на позначках “residential proxy”.

## Виявлення wireless і covert devices

Об'єднуйте RADIUS/NAC із контекстом AP та фізичним контекстом:

1. знайдіть уперше виявлені комбінації account–device–AP;
2. ідентифікуйте credentials, використані без керованого EAP certificate/posture;
3. порівняйте одночасні сесії та присутність за badge/building;
4. перевірте незвично слабкий/граничний сигнал і переміщення між AP;
5. шукайте на nearby managed endpoints wireless scanning, щойно увімкнений interface bridge/NAT, virtual adapters або tunnels;
6. інвентаризуйте нову активність switchport, DHCP, USB network і PoE;
7. проведіть authorized RF/physical sweep, коли докази це підтримують.

Це виявляє як path у стилі APT28 до найближчого сусіда, так і exercise drop. MAC randomization не слід трактувати як ідентичність або доказ вини.

## Виявлення financial attribution

- Зберігайте точний chain, token, address, transaction і block identifiers.
- Відстежуйте value через change, peel chains, fan-out/in, mixers, bridges і service deposits, позначаючи heuristics.
- Корелюйте time, amount minus fees, contract event, liquidity і withdrawal у destination-chain.
- Отримуйте або зберігайте lawful exchange, bridge, merchant, account, device і delivery records.
- Перевіряйте поточні sanctioned entities/addresses і derivatives за відповідною програмою; не покладайтеся на старий static list.
- Розглядайте використання privacy-protocol як input для risk-context, а не як доказ wrongdoing.

Red flags FATF прямо залежать від контексту: незвичний pattern, amount/frequency, geography, source of funds і anonymity-enhancing services набувають значення разом.<sup>[[5]](#references)</sup>

## Deception і canaries

Defenders можуть створювати high-confidence signals, не намагаючись deanonymize звичайних користувачів:

- унікальні credentials або документи, які ніколи не повинні залишати одну систему;
- fake administrative endpoints і decoy shares;
- instrumented DNS names, вбудовані лише у контрольовані artifacts;
- canary cloud keys без легітимного використання;
- decoy Wi-Fi identity, якою не володіє жоден managed device.

Ретельно визначайте scope і керуйте deception. Canary має виявляти misuse власного asset defender, а не збирати unrelated third-party traffic.

## Пріоритети countermeasures

1. Видаліть непідтримувані Internet-facing routers, VPNs і appliances.
2. Вимагайте phishing-resistant MFA і device-bound certificates, зокрема для internal/wireless access.
3. Централізуйте достатньо immutable identity, endpoint, DNS, flow, proxy, cloud і network-device logs.
4. Обмежте management та egress; інвентаризуйте кожен externally reachable service.
5. Моніторте DNS, certificate transparency і cloud configuration на unauthorized assets.
6. Забезпечте process-to-network та object-level SaaS visibility.
7. Проводьте cross-layer investigations і координацію із сусідніми providers.
8. Відстежуйте infrastructure clusters і behaviors, а не лише IP blocklists.

## Аналітична дисципліна

Використовуйте формулювання рівня впевненості:

- **Observed:** запис sensor/provider безпосередньо показує взаємозв'язок.
- **Strongly supported:** кілька незалежних спостережень підтверджують його більше, ніж альтернативи.
- **Assessed:** inference на основі зазначених assumptions і evidence.
- **Unknown:** відсутня visibility, тому висновок неможливий.

Завжди зберігайте щонайменше дві гіпотези: infrastructure, керована actor, проти compromised/shared intermediary; один actor проти multi-tenant service; deliberate evasion проти legitimate privacy/CDN behavior. Здатність пояснити невизначеність є частиною коректного detection.

## References

- [1] [Google Cloud/Mandiant — актори шпигунства China-nexus використовують ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — індикатори Red Flags для Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — актори PRC здійснюють компрометацію та підтримують persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — рекомендації щодо Enhanced visibility і hardening для communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
