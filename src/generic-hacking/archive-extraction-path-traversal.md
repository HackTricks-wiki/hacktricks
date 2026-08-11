# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Якщо утиліта для розпакування без перевірки використовує цей шлях, спеціально створене ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записано за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Наслідки варіюються від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у місці **auto-run**, наприклад у папці Windows *Startup*.

## Першопричина

1. Attacker створює архів, де один або кілька заголовків файлів містять:
* Послідовності відносної навігації (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його або примусово виконувати розпакування всередині вибраного каталогу.
3. Файл записується в контрольоване attacker місце та виконується/завантажується наступного разу, коли система або користувач звертається до цього шляху.

### .NET `Path.Combine` + `ZipArchive` traversal

Поширеним anti-pattern у .NET є об'єднання призначеного каталогу з **керованим користувачем** `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Якщо `entry.FullName` починається з `..\\`, відбувається traversal; якщо це **абсолютний шлях**, компонент зліва повністю відкидається, що як ідентифікатор розпакування призводить до **запису довільного файлу**.
- Архів proof-of-concept для запису в сусідній каталог `app`, за яким стежить запланований сканер:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Переміщення цього ZIP до контрольованої вхідної папки призводить до створення `C:\samples\app\0xdf.txt`, що підтверджує traversal за межі `C:\samples\queue\` і дає змогу використовувати подальші примітиви (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows і його компоненти Windows RAR/UnRAR не перевіряли імена файлів під час розпакування. Уразливість використовувала альтернативні потоки даних NTFS (ADS), щоб обійти вибраний шлях розпакування та записувати файли в ненавмисні місця.<sup>[[5]](#references)</sup>
Шкідливий RAR-архів, що містить такий запис:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
опинився б **за межами** вибраного вихідного каталогу та всередині папки *Startup* користувача. ESET спостерігала, як там розпаковувалися шкідливі LNK-файли та виконувалися під час входу користувача в систему, забезпечуючи persistence і шлях до RCE.<sup>[[5]](#references)</sup>

### Створення PoC Archive (Linux/Mac)

Оскільки CVE-2025-8088 використовує traversal path в імені ADS, скористайтеся спеціально створеним генератором для створення RAR, а потім тестуйте extraction лише в ізольованій lab з vulnerable build WinRAR.<sup>[[5]](#references)</sup>

### Спостереження за Exploitation у Wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у яких як вкладення надсилалися RAR-архіви, що використовували CVE-2025-8088 для розгортання customized backdoors і сприяння ransomware operations.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries, які були **symbolic links**, розіменовувалися під час extraction, що дозволяло attackers вийти за межі destination directory і перезаписати довільні paths. Взаємодія користувача обмежується *відкриттям/extracting* archive.<sup>[[1]](#references)</sup>
* **Affected**: builds 7-Zip до **25.00**. Flaw в обробці symbolic link було виправлено у **25.00** (липень 2025) і пізніших версіях.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Перезаписати `Start Menu/Programs/Startup` або service-run locations → code запускається під час наступного входу в систему або restart service.
* **Швидка fixture для обробки symlink (Linux)**:
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
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Перейдіть на `mholt/archives` ≥ 0.1.0 або реалізуйте canonical-path checks перед записом.
* **Мінімальне відтворення**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради щодо Detection

* **Static inspection** – Перелічіть archive entries і позначте будь-яке name, що містить `../`, `..\\`, *absolute paths* (`/`, `C:`), або entries типу *symlink*, target яких розташований за межами extraction dir.
* **Canonicalisation** – Переконайтеся, що `realpath(join(dest, name))` залишається всередині `realpath(dest)` (порівнюйте path components, а не лише raw string prefix). В іншому разі відхиляйте entry.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Розпаковуйте в disposable directory за допомогою extractor із path/symlink checks (наприклад, стандартних secure checks bsdtar або 7-Zip ≥ 25.00), а потім перевіряйте, що resulting paths залишаються всередині directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Створіть alert на нові executables, записані в locations `Startup`/`Run`/`cron` невдовзі після відкриття archive через WinRAR/7-Zip тощо.

## Mitigation & Hardening

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ містять fixes для проблем із d path/symlink.<sup>[[1]](#references)[[5]](#references)</sup>
2. За можливості розпаковуйте archives з параметром “**Do not extract paths**” / “**Ignore paths**”.
3. У Unix знизьте privileges і змонтуйте **chroot/namespace** перед extraction; у Windows використовуйте **AppContainer** або sandbox.
4. Якщо ви пишете custom code, виконуйте normalise за допомогою `realpath()`/`PathCanonicalize()` **до** create/write і відхиляйте будь-який entry, що виходить за межі destination.

## Додаткові Affected / Historical Cases

* 2018 – Масштабний advisory про *Zip-Slip* від Snyk, що стосувався багатьох Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – `go-slug` HashiCorp (CVE-2025-0377): traversal під час TAR extraction у slugs (виправлено у v0.16.3).<sup>[[7]](#references)</sup>
* Будь-яка custom extraction logic, яка не викликає `PathCanonicalize` / `realpath` перед записом.

## References

- [1] [Trend Micro ZDI-25-949 – symlink traversal у ZIP 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip у mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Запобігання Zip Slip у .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno: ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Негайно оновіть WinRAR tools: RomCom та інші використовують zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Публічне розкриття critical arbitrary file overwrite vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug vulnerable до Zip Slip attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Метод Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – secure extraction flags bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Повідомлено про Proof-of-Concept Exploit для CVE-2025-11001 у 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
