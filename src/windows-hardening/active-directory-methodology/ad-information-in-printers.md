# Інформація в принтерах

{{#include ../../banners/hacktricks-training.md}}

В Інтернеті є кілька блогів, які **підкреслюють небезпеку залишення принтерів, налаштованих на LDAP із типовими/слабкими** обліковими даними для входу.  \
Це пояснюється тим, що зловмисник може **обманом змусити принтер пройти автентифікацію на rogue LDAP server** (зазвичай достатньо `nc -vv -l -p 389` або `slapd -d 2`) і перехопити **облікові дані принтера у відкритому вигляді**.

Крім того, деякі принтери містять **логи з іменами користувачів** або навіть можуть **завантажувати всі імена користувачів** із Domain Controller.

Уся ця **чутлива інформація** та поширений **низький рівень безпеки** роблять принтери дуже цікавими для зловмисників.

Кілька вступних блогів на цю тему:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Конфігурація принтера

- **Розташування**: Список LDAP server зазвичай знаходиться у вебінтерфейсі (наприклад, *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Поведінка**: Багато вбудованих вебсерверів дозволяють змінювати LDAP server **без повторного введення облікових даних** (функція зручності → ризик для безпеки).
- **Експлуатація**: Перенаправте адресу LDAP server на host під контролем зловмисника та натисніть кнопку *Test Connection* / *Address Book Sync*, щоб змусити принтер виконати bind до вашого server.

---

## Перехоплення облікових даних

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Малі/старі МФП можуть надсилати простий *simple-bind* у відкритому тексті, який netcat може перехопити. Сучасні пристрої зазвичай спочатку виконують anonymous query, а потім намагаються виконати bind, тому результати можуть відрізнятися.<sup>[[1]](#references)</sup>

### Метод 2 – Повноцінний Rogue LDAP server (рекомендовано)

Оскільки багато пристроїв виконують anonymous search *перед* автентифікацією, розгортання справжнього LDAP daemon забезпечує набагато надійніші результати:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Коли printer виконує свій lookup, ви побачите облікові дані у clear-text у debug output.

> 💡  Ви також можете використовувати `impacket/examples/ldapd.py` (Python rogue LDAP) або `Responder -w -r -f`, щоб отримати NTLMv2 hashes через LDAP/SMB.

---

## Нещодавні вразливості Pass-Back (2024-2025)

Pass-back — це *не теоретична проблема*: у 2024/2025 vendors продовжують публікувати advisories, які точно описують цей клас атак.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 для Xerox VersaLink C70xx MFPs дозволяла автентифікованому адміністратору (або будь-кому, якщо залишалися default creds):

* **CVE-2024-12510 – LDAP pass-back**: змінити адресу LDAP server і запустити lookup, унаслідок чого пристрій leak-ав налаштовані Windows credentials на host, контрольований attacker.
* **CVE-2024-12511 – SMB/FTP pass-back**: ідентична проблема через destinations *scan-to-folder*, що призводила до витоку NetNTLMv2 або FTP clear-text creds.<sup>[[2]](#references)</sup>

Простий listener, наприклад:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
або rogue SMB server (`impacket-smbserver`) достатньо, щоб harvest credentials.

### Canon imageRUNNER / imageCLASS – Advisory 20 May 2025

Canon підтвердила weakness типу **SMTP/LDAP pass-back** у десятках ліній Laser & MFP. Attacker з admin access може змінити конфігурацію сервера та отримати збережені credentials для LDAP **або** SMTP (багато організацій використовують privileged account, щоб дозволити scan-to-mail).<sup>[[3]](#references)</sup>

У рекомендаціях vendor прямо радить:

1. Якомога швидше оновити firmware до patched version.
2. Використовувати strong, unique admin passwords.
3. Не використовувати privileged AD accounts для printer integration.

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Abuse PostScript/PJL/PCL, доступ до file-system, перевірка default-creds, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Harvest configuration (включно з address books і LDAP creds) через HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Capture і relay NetNTLM hashes через SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lightweight rogue LDAP service для отримання clear-text binds | `python ldapd.py -debug` |

---

## Hardening & Detection

1. **Patch / firmware-update** MFPs без зволікань (перевіряйте vendor PSIRT bulletins).
2. **Least-Privilege Service Accounts** – ніколи не використовуйте Domain Admin для LDAP/SMB/SMTP; обмежуйте їх read-only OU scopes.
3. **Restrict Management Access** – розміщуйте printer web/IPP/SNMP interfaces у management VLAN або за ACL/VPN.
4. **Disable Unused Protocols** – FTP, Telnet, raw-9100, older SSL ciphers.
5. **Enable Audit Logging** – деякі devices можуть надсилати LDAP/SMTP failures у syslog; корелюйте unexpected binds.
6. **Monitor for Clear-Text LDAP binds** з unusual sources (printers зазвичай мають взаємодіяти лише з DCs).
7. **SNMPv3 or disable SNMP** – community `public` часто leak-ить device & LDAP config.

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
