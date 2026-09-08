# Прихований фізичний і wireless-доступ

Детальний, схвалений власником план реалізації, що охоплює outbound rendezvous, відновлення живлення/uplink, мінімальний обсяг секретів, що зберігаються на пристрої, capture-тестування та моніторинг можливого виявлення, див. [Field Nodes із захистом від вилучення](capture-resilient-authorized-field-nodes.md).

Зміна мережевого маршруту також може змінити видиме фізичне походження. Складний зловмисник може використати розташовану поблизу скомпрометовану систему, прихований пристрій, публічний доступ, cellular backhaul або супутниковий приймач, щоб журнали цілі вказували не на оператора. Жоден із цих методів не усуває фізичні, радіо- чи провайдерські докази; він переносить атрибуцію до інших наборів даних.

## Матриця технік

| Техніка | Видиме походження | Необхідна умова | Найцінніші докази |
|---|---|---|---|
| Nearby wireless pivot | бізнес або житло поруч із ціллю | скомпрометований dual-homed host і доступ до Wi-Fi цілі | endpoint-журнали сусіднього хоста, RF-асоціація та RADIUS/DHCP цілі |
| Публічна/гостьова мережа | NAT закладу або tunnel exit | законний доступ або обхід контролю доступу | captive portal, DHCP, асоціація з AP, CCTV та записи платежів/місцезнаходження |
| Прихований drop-пристрій | дротова, Wi-Fi або cellular-адреса цілі/оточення | фізичне розміщення або доставка | switchport/USB, RF, інвентаризація, живлення та телеметрія outbound tunnel |
| Cellular router/eSIM | carrier NAT або виділений APN | modem/SIM/subscription | IMEI/IMSI/eSIM, сектор стільникової мережі, обліковий запис оператора та часові параметри трафіку |
| Зловживання satellite-link | адреса абонента в зоні покриття beam | специфічна для протоколу та сервісу вразливість | RF-локація, uplink flow, неможливі RTT/routing і записи провайдера |

## Nearest Neighbor Attack

Volexity задокументувала операцію APT28/GRU 2022 року, під час якої зловмисник перебував віддалено від кінцевої цілі. Він здійснив password spraying публічного сервісу цілі, щоб отримати дійсні облікові дані, але MFA запобіг прямому входу через Internet. Корпоративна Wi-Fi-мережа цілі приймала ці облікові дані без MFA. Зловмисник скомпрометував організації, розташовані фізично близько до цілі, знайшов dual-homed system із wireless reach і використав цю систему для автентифікації у Wi-Fi цілі. Volexity назвала це **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Новизна полягає в композиції. Жоден оператор не вирушає до цілі, а MFA сервісу, доступного з Internet, продовжує працювати. Скомпрометований сусід забезпечує фізичну близькість; викрадений credential цілі забезпечує логічний доступ; Wi-Fi цілі стає шляхом перетину межі.

### Передумови та видимість

- Сусідня система має бути доступною для remote control і мати сумісний radio або доступ до іншого сусіднього pivot.
- SSID цілі має досягати цієї системи, а Wi-Fi admission має приймати багаторазово використовуваний credential/certificate/device state.
- Pivot часто потребує двох одночасних шляхів: одного назад до оператора, іншого — у цільову WLAN.
- Ціль може побачити нову station MAC і легітимне username, але не побачити відповідного managed-device certificate, posture, history або очікуваного входу до будівлі.
- Логи endpoint сусіда можуть показувати wireless scans, нові profiles, зміни interfaces, tunneling і remote-control activity.

### Виявлення та запобігання

1. Вимагайте certificate-backed EAP-TLS і managed-device posture для корпоративного Wi-Fi; не вважайте пароль, який не пройшов MFA в Internet, достатнім лише тому, що він надходить через radio.
2. Співвідносіть RADIUS authentication з MDM/NAC identity, історичним station/device binding, AP location, подіями physical-access і одночасними sessions.
3. Створюйте alert, коли account вперше associates, походить із незвичного AP edge, не має managed certificate або коли та сама identity активна в іншому місці.
4. Моніторте endpoints, здатні bridge interfaces. У Windows, Linux і network appliances перевіряйте неочікувані WLAN profiles, forwarding/NAT configuration, virtual adapters і persistent tunnels.
5. Зменшуйте непотрібне поширення signal за допомогою розумного розміщення AP і планування потужності. Це допоміжний control, а не authentication.
6. Координуйте incident response із сусідніми орендарями: остаточним джерелом radio може бути сама жертва.

[owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) відтворює ці observables без атаки на сусіда.

## Public venues and third-party Wi-Fi

Використання Wi-Fi у кафе, готелі, аеропорту або муніципальній мережі змінює IP, який бачить destination. Це не створює anonymity. Venue або його provider може зберігати AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation і flow logs. Фізичний вхід, CCTV, покупка, дані про mobile-location і записи про подорожі можуть пов’язати digital event із людиною.

Actor може спробувати зменшити кількість одного handle, використовуючи randomized MAC addresses, окремий device, готівку або tunnel. Cross-layer correlation усе одно можлива за часом прибуття, повторюваним pattern відвідувань venue, radio fingerprints, поведінкою portal, timing трафіку, відеозаписами камер і tunnel provider. VPN також переносить destination із логів venue до логів VPN; він не усуває знання venue про те, що device перебував на місці.

Захисники public access мають ізолювати clients, блокувати lateral traffic, використовувати WPA2/3-Enterprise або per-device keys, де це можливо, зберігати пропорційні DHCP/RADIUS/security logs, захищати captive portals і публікувати abuse process. Red teams мають використовувати такий venue лише тоді, коли його умови й engagement це дозволяють; обходити portal, красти доступ або атакувати інших гостей — не означає отримати shortcut для authorized testing.

## Covert drop devices and warshipping

Drop — це невелика система, розміщена на території або доставлена туди, якою потім керують через outbound Ethernet, Wi-Fi або cellular. “Warshipping” упаковує device так, щоб звичайна доставка переносила його всередину radio perimeter. Можливе hardware варіюється від single-board computer до модифікованого charger, USB peripheral, network appliance або battery-powered modem.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Пристрій може забезпечити remote foothold, виконувати wireless measurements, емулювати авторизований exercise peripheral або relay traffic. Його видиме джерело є локальним, але він створює фізичні артефакти: серійні номери, пакування, відбитки пальців, камери, записи контролю доступу, енергоспоживання, USB-дескриптори, узгодження switchport, DHCP fingerprints, поведінку MAC OUI/randomization, RF emissions і регулярні rendezvous connections.

### Захисні засоби

- Підтримуйте процедури receiving-room та asset-inventory; перевіряйте неочікувану електроніку й пакунки, адресовані неіснуючим співробітникам.
- Використовуйте 802.1X/NAC для дротового та бездротового доступу, вимикайте невикористовувані порти й переміщуйте невідомі пристрої до обмеженої remediation VLAN.
- Створюйте сповіщення про нові DHCP fingerprints, локально адміністровані MAC-адреси, які зберігаються, нові USB network/HID devices, несанкціоновані Wi-Fi Direct/Bluetooth і довготривалі outbound tunnels.
- Створіть базову модель switchport, power-over-Ethernet, DNS і TLS behavior. Невеликий хост без запису в inventory, який періодично встановлює encrypted connections, є більш показовим сигналом, ніж лише “Raspberry Pi OUI”.
- Під час exercise складіть inventory, промаркуйте пристрої, визначте scope, зашифруйте їх, надайте remote kill, встановіть deadline для повернення та переконайтеся, що втрата пристрою не може розкрити повторно використовувані credentials.

## Cellular та eSIM backhaul

Cellular modem оминає Internet gateway цілі й може зберігати доступність drop за carrier NAT через outbound rendezvous. Mobile addresses можуть змінюватися або бути спільними; cellular operator усе одно має вагомі дані про subscriber і network: ідентифікатор SIM/eSIM, IMSI, IMEI пристрою, призначені addresses/ports, дані про час проходження сигналу до cell/sector, а також записи про account/payment і roaming.

З погляду enterprise, виявляйте неочікувані modems і personal hotspots за допомогою wireless/RF surveys, inventory USB/PCI на endpoints, MDM restrictions, моніторингу rogue-SSID та фізичної перевірки. Drop, який використовує cellular для control, усе одно можна виявити за його локальною Ethernet/Wi-Fi behavior і radio emissions.

Для авторизованих exercises організація повинна володіти subscription і modem, зареєструвати identifiers у controller та перевірити, що умови carrier/provider дозволяють такий traffic. Prepaid label або купівля за cryptocurrency не стирає tower, device чи retail records.

## MAC randomization та device fingerprinting

Сучасні системи можуть використовувати locally administered random MAC для кожної мережі. Це зменшує пасивне довготривале відстеження за стабільною factory MAC; однак це не приховує:

- час probe/association і набір запитаних network capabilities;
- 802.11 information elements, supported rates і vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers і captive-portal/browser fingerprint;
- автентифіковану 802.1X identity або certificate;
- higher-layer account, tunnel і traffic pattern; або
- фізичне спостереження.

Захисники не повинні використовувати MAC allowlists як authentication. Пов’язуйте radio identity із certificate/device posture і вважайте зміну MAC нормальною поведінкою, якщо інший context не є аномальним.

## Satellite-link hijacking

Kaspersky задокументувала використання Turla слабких місць у старішому односторонньому DVB-S satellite Internet. У описаній моделі легітимний remote subscriber надсилав outbound requests через terrestrial link, але отримував downstream data через незашифровану wide-area satellite broadcast. Actor у межах satellite footprint міг спостерігати downlink, вибрати IP активного subscriber і організувати надсилання C2 replies на цю IP-адресу. І легітимний subscriber, і actor отримували broadcast; actor вилучав traffic для вибраного port, тоді як легітимний subscriber відкидав unsolicited packets. Після цього C2 operator, здавалося, використовував адресу satellite-provider в іншій географії.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Це було специфічним для протоколу/сервісу, обмеженим пропускною здатністю й не еквівалентним компрометації сучасного двонапрямленого зашифрованого супутникового термінала. Це також не приховувало вихідний шлях запиту актора від достатньо спроможного спостерігача. Можливості виявлення включають асиметричну/неможливу маршрутизацію, трафік до абонента, який не ініціював потік, незвичні порти призначення, телеметрію провайдера, дослідження місцезнаходження приймача/RF і конфігурацію malware. Використовуйте цей випадок, щоб поставити під сумнів припущення, що геолокація IP-адреси C2 визначає місцезнаходження його оператора, а не як рецепт побудови.

## Робочий аркуш фізично-цифрової кореляції

Коли підозрілим є джерело, яке, імовірно, знаходиться локально, складіть одну часову шкалу:

1. нормалізуйте час на AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, комутаторах і системах фізичного доступу;
2. визначте першу радіоасоціацію або встановлення з'єднання, а не лише перше сповіщення;
3. зіставте станцію із сертифікатом, станом пристрою, DHCP-відбитком і місцезнаходженням комутатора/AP;
4. перевірте наявність одночасної активності remote-control/tunnel у сусідніх системах;
5. перегляньте доставки, відвідувачів, винятки в інвентаризації, записи камер і результати RF-досліджень відповідно до чинної політики/законодавства;
6. збережіть підозрілий пристрій і мінливий стан мережі; не виконуйте бездумне вимкнення живлення;
7. визначте, чи є джерело, яке здається таким, підконтрольною актору інфраструктурою або іншим victim.

## References

- [1] [Volexity — Атака найближчого сусіда: як російська APT використала сусідні Wi-Fi-мережі для прихованого доступу](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: командування й керування APT у небі](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Настанови із захисту бездротових локальних мереж](https://csrc.nist.gov/pubs/sp/800/153/final)
