# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ця сторінка об'єднує деякі з найкорисніших утиліт для **перерахунку** та **візуалізації** відносин Active Directory. Для збору через непомітний **Active Directory Web Services (ADWS)** канал перегляньте посилання вище.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) є розширеним **переглядачем та редактором AD**, який дозволяє:

* Графічний перегляд дерева каталогу
* Редагування атрибутів об'єктів та дескрипторів безпеки
* Створення / порівняння знімків для офлайн-аналізу

### Швидке використання

1. Запустіть інструмент і підключіться до `dc01.corp.local` з будь-якими обліковими даними домену.
2. Створіть офлайн-знімок через `File ➜ Create Snapshot`.
3. Порівняйте два знімки за допомогою `File ➜ Compare`, щоб виявити зміни в дозволах.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) витягує великий набір артефактів з домену (ACL, GPO, довіри, шаблони CA …) і створює **Excel звіт**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (графічна візуалізація)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) використовує теорію графів + Neo4j для виявлення прихованих відносин привілеїв у локальному AD та Azure AD.

### Розгортання (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Збирачі

* `SharpHound.exe` / `Invoke-BloodHound` – нативний або PowerShell варіант
* `AzureHound` – Azure AD перерахування
* **SoaPy + BOFHound** – ADWS збір (див. посилання вгорі)

#### Загальні режими SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Збирачі генерують JSON, який споживається через BloodHound GUI.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) перераховує **Group Policy Objects** та підкреслює неправильні налаштування.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) виконує **перевірку стану** Active Directory та генерує HTML звіт з оцінкою ризиків.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
