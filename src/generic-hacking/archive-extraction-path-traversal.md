# Обхід шляхів під час розпакування архівів ("Zip-Slip" / WinRAR CVE-2025-8088)

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Якщо утиліта розпакування без перевірки використовує цей шлях, створене ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записано за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **обхід шляхів під час розпакування архівів**.<sup>[[6]](#references)</sup>

Наслідки варіюються від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у місці **автоматичного запуску**, наприклад у папці Windows *Startup*.

## Першопричина

1. Attacker створює архів, у якому один або кілька заголовків файлів містять:
* Відносні послідовності обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його або примусово виконувати розпакування всередині вибраного каталогу.
3. Файл записується в контрольоване Attacker місце та виконується/завантажується наступного разу, коли система або користувач активує цей шлях.

### .NET `Path.Combine` + `ZipArchive` traversal

Поширеним anti-pattern у .NET є об'єднання призначеного місця призначення з **контрольованим користувачем** `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Якщо `entry.FullName` починається з `..\\`, відбувається traversal; якщо це **абсолютний шлях**, компонент ліворуч повністю відкидається, що призводить до **довільного запису файлу** як ідентифікатора extraction.
- Proof-of-concept archive для запису в сусідній каталог `app`, за яким стежить запланований scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Поміщення цього ZIP до контрольованої папки вхідних файлів призводить до появи `C:\samples\app\0xdf.txt`, що підтверджує traversal за межі `C:\samples\queue\` і дає змогу використовувати подальші примітиви (наприклад, DLL hijacks).

## Приклад із реального світу – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows і його компоненти Windows RAR/UnRAR не перевіряли імена файлів під час розпакування. Уразливість використовувала alternate data streams (ADS) NTFS, щоб обійти вибраний шлях розпакування та записати файли в ненавмисні місця.<sup>[[5]](#references)</sup>
Шкідливий RAR-архів, що містить такий запис:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
опинився б **за межами** вибраного вихідного каталогу та всередині папки *Startup* користувача. ESET спостерігала, як там розпаковувалися шкідливі LNK-файли та виконувалися під час входу користувача в систему, забезпечуючи persistence і шлях до RCE.<sup>[[5]](#references)</sup>

### Створення PoC Archive (Linux/Mac)

Оскільки CVE-2025-8088 використовує traversal path в імені ADS, для створення RAR слід використовувати спеціально призначений генератор, а тестування extraction виконувати лише в ізольованій lab із вразливою збіркою WinRAR.<sup>[[5]](#references)</sup>

### Спостереження за Exploitation in the Wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у межах яких додавалися RAR-архіви, що використовували CVE-2025-8088 для розгортання кастомізованих backdoors і сприяння ransomware-операціям.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries, які були **symbolic links**, розіменовувалися під час extraction, що дозволяло attackers вийти за межі destination directory і перезаписати довільні paths. Взаємодія користувача полягає лише у *відкритті/розпакуванні* archive.<sup>[[1]](#references)</sup>
* **Affected**: збірки 7-Zip до **25.00**. Flaw обробки symbolic-link було виправлено у версії **25.00** (липень 2025) і новіших.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Перезаписати `Start Menu/Programs/Startup` або service-run locations → код запускається під час наступного входу в систему або перезапуску service.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Цей archive містить symlink entry, що вказує за межі extraction directory; використовуйте disposable target і перевірте, що extractor не переходить за ним. Для write-through test також потрібен regular-file entry під symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` переходить за `../` і symlinked ZIP entries, записуючи дані за межі `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт тепер deprecated).
* **Fix**: Перейдіть на `mholt/archives` ≥ 0.1.0 або реалізуйте canonical-path checks перед записом.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради щодо Detection

* **Static inspection** – Перелічіть archive entries і позначте будь-яке ім’я, що містить `../`, `..\\`, *absolute paths* (`/`, `C:`), або entries типу *symlink*, target яких знаходиться за межами extraction dir.
* **Canonicalisation** – Переконайтеся, що `realpath(join(dest, name))` залишається всередині `realpath(dest)` (порівнюйте path components, а не лише raw string prefix). В іншому разі відхиліть entry.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Розпаковуйте в disposable directory за допомогою extractor із path/symlink checks (наприклад, стандартних secure checks у bsdtar або 7-Zip ≥ 25.00), а потім перевіряйте, що resulting paths залишаються всередині directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Створюйте alert, якщо незабаром після відкриття archive через WinRAR/7-Zip тощо до `Startup`/`Run`/`cron` locations записуються нові executables.

## Mitigation & Hardening

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ містять fixes для згаданих path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. За можливості розпаковуйте archives з параметром “**Do not extract paths**” / “**Ignore paths**”.
3. У Unix знижуйте privileges і монтуйте **chroot/namespace** перед extraction; у Windows використовуйте **AppContainer** або sandbox.
4. Якщо пишете custom code, виконуйте normalise за допомогою `realpath()`/`PathCanonicalize()` **перед** create/write і відхиляйте будь-який entry, що виходить за межі destination.

## Додаткові вразливі / історичні випадки

* 2018 – Масштабне advisory щодо *Zip-Slip* від Snyk, яке стосувалося багатьох Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal під час TAR extraction у slugs (виправлено у v0.16.3).<sup>[[7]](#references)</sup>
* Будь-яка custom extraction logic, яка не викликає `PathCanonicalize` / `realpath` перед write.

## References

- [1] [Trend Micro ZDI-25-949 – ZIP traversal через symlink у 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip у mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Запобігання Zip Slip у .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno: ZipSlip → ланцюжок DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Негайно оновіть WinRAR: RomCom та інші використовують zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Публічне розкриття критичної вразливості довільного перезапису файлів: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug вразливий до Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Метод Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – secure extraction flags у bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Для CVE-2025-11001 у 7-Zip повідомлено Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
