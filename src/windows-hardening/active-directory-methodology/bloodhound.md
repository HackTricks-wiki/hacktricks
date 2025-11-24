# BloodHound & Інші Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ПРИМІТКА: Ця сторінка згруповує деякі з найкорисніших утиліт для **enumerate** та візуалізації відносин Active Directory. Для збору через прихований канал **Active Directory Web Services (ADWS)** перегляньте посилання вище.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) — це розширений **AD viewer & editor**, який дозволяє:

* Перегляд дерева директорій через GUI
* Редагування атрибутів об'єктів та дескрипторів безпеки
* Створення знімків і їх порівняння для офлайн-аналізу

### Швидке використання

1. Запустіть інструмент і підключіться до `dc01.corp.local` з будь-якими доменними обліковими даними.
2. Створіть офлайн-знімок через `File ➜ Create Snapshot`.
3. Порівняйте два знімки за допомогою `File ➜ Compare`, щоб виявити зміни в дозволах.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) витягує великий набір артефактів з домену (ACLs, GPOs, trusts, CA templates …) і генерує **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (візуалізація графів)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) використовує теорію графів + Neo4j для виявлення прихованих відносин привілеїв всередині on-prem AD & Azure AD.

### Розгортання (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Колектори

* `SharpHound.exe` / `Invoke-BloodHound` – нативна або версія для PowerShell
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – збір через ADWS (див. посилання вище)

#### Поширені режими SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Колектори генерують JSON, який завантажується через BloodHound GUI.

---

## Пріоритизація Kerberoasting за допомогою BloodHound

Контекст графа має вирішальне значення, щоб уникнути шумного, безрозбірливого roasting. Легкий робочий процес:

1. **Зібрати все один раз** за допомогою ADWS-сумісного колектора (наприклад, RustHound-CE), щоб ви могли працювати офлайн і відрепетирувати шляхи без повторного доступу до DC:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Імпортуйте ZIP, позначте скомпрометований principal як owned**, потім виконайте вбудовані запити, такі як *Kerberoastable Users* та *Shortest Paths to Domain Admins*. Це миттєво виділяє акаунти з SPN з корисними членствами в групах (Exchange, IT, tier0 service accounts, etc.).
3. **Пріоритезуйте за blast radius** – зосередьтеся на SPNs, які контролюють спільну інфраструктуру або мають права адміністратора, і перевірте `pwdLastSet`, `lastLogon` та дозволені типи шифрування перед тим, як витрачати cracking cycles.
4. **Запитуйте лише ті tickets, які вас цікавлять**. Інструменти, як NetExec, можуть націлюватися на вибрані `sAMAccountName`s, щоб кожен LDAP ROAST запит мав чітке обґрунтування:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, а потім одразу зробіть повторний запит до BloodHound, щоб спланувати post-exploitation із новими привілеями.

Такий підхід підтримує високе співвідношення сигнал/шум, зменшує обсяг помітної активності (no mass SPN requests) і гарантує, що кожен cracked ticket перетворюється на осмислені кроки privilege escalation.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) перелічує **Group Policy Objects** і виявляє неправильні налаштування.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) виконує **перевірку стану** Active Directory і генерує HTML-звіт з оцінкою ризиків.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Посилання

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
