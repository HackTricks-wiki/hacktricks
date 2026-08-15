# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Якщо утиліта для розпакування без перевірки враховує цей шлях, створене ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записано за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **обхід шляху під час розпакування архіву**.<sup>[[6]](#references)</sup>

Наслідки можуть варіюватися від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у розташуванні **автозапуску**, наприклад у папці Windows *Startup*.

## Першопричина

1. Attacker створює архів, у якому один або кілька заголовків файлів містять:
* Відносні послідовності обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його або примусово виконувати розпакування всередині вибраного каталогу.
3. Файл записується в контрольоване attacker розташування та виконується/завантажується наступного разу, коли система або користувач звертається до цього шляху.

### Обхід через `.NET` `Path.Combine` + `ZipArchive`

Поширеною анти-моделлю в .NET є об'єднання призначеного для цього каталогу з **контрольованим користувачем** `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Якщо `entry.FullName` починається з `..\\`, він здійснює обхід; якщо це **absolute path**, компонент зліва повністю відкидається, що призводить до **довільного запису файлу** як ідентичності розпакування.
- Proof-of-concept archive для запису в сусідній каталог `app`, за яким стежить планувальник сканування:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Переміщення цього ZIP до inbox, який відстежується, призводить до появи `C:\samples\app\0xdf.txt`, що доводить traversal за межі `C:\samples\queue\` і дає змогу використовувати follow-on primitives (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows і його компоненти Windows RAR/UnRAR не виконували перевірку filenames під час розпакування. Уразливість використовувала alternate data streams (ADS) NTFS, щоб обійти вибраний шлях розпакування та записати файли в ненавмисні місця.<sup>[[5]](#references)</sup>
Шкідливий RAR-архів, що містить такий entry:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** вибраного вихідного каталогу та всередині папки *Startup* користувача. ESET спостерігала, як шкідливі LNK-файли розпаковувалися туди та виконувалися під час входу користувача в систему, забезпечуючи persistence і шлях до RCE.<sup>[[5]](#references)</sup>

### Створення PoC-архіву (Linux/Mac)

Оскільки CVE-2025-8088 використовує traversal-шлях в імені ADS, скористайтеся спеціально створеним генератором для створення RAR, а потім тестуйте розпакування лише в ізольованій lab-середовищі з вразливою збіркою WinRAR.<sup>[[5]](#references)</sup>

### Спостереження за експлуатацією in the Wild

ESET повідомила про spear-phishing-кампанії RomCom (Storm-0978/UNC2596), у межах яких надсилалися RAR-архіви, що використовували CVE-2025-8088 для розгортання кастомізованих backdoor-ів і сприяння ransomware-операціям.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Вразливість**: ZIP-записи, які були **symbolic links**, розіменовувалися під час розпакування, що дозволяло attackers вийти за межі каталогу призначення та перезаписати довільні шляхи. Взаємодія користувача полягає лише у *відкритті/розпакуванні* архіву.<sup>[[1]](#references)</sup>
* **Вразливі версії**: збірки 7-Zip до **25.00**. Вразливість обробки symbolic links була виправлена у версії **25.00** (липень 2025) та пізніших версіях.<sup>[[1]](#references)[[10]](#references)</sup>
* **Шлях впливу**: Перезаписати `Start Menu/Programs/Startup` або розташування запуску служб → код виконається під час наступного входу в систему або перезапуску служби.
* **Швидка fixture для обробки symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Цей архів містить запис symlink, що вказує за межі каталогу розпакування; використовуйте disposable target і перевірте, що extractor не переходить за ним. Для тесту запису крізь symlink також потрібен запис звичайного файлу під symlink.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Вразливість**: `archiver.Unarchive()` переходить за `../` і symlinked ZIP-записами, записуючи дані за межі `outputDir`.<sup>[[2]](#references)</sup>
* **Вразливі версії**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт наразі deprecated).
* **Виправлення**: Перейдіть на `mholt/archives` ≥ 0.1.0 або реалізуйте перевірки canonical path перед записом.
* **Мінімальне відтворення**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради щодо виявлення

* **Статична перевірка** – Перелічіть записи архіву та позначте будь-яке ім’я, що містить `../`, `..\\`, *absolute paths* (`/`, `C:`), або записи типу *symlink*, ціль яких розташована за межами каталогу розпакування.
* **Канонікалізація** – Переконайтеся, що `realpath(join(dest, name))` залишається всередині `realpath(dest)` (порівнюйте компоненти шляху, а не лише необроблений префікс рядка). В іншому разі відхиляйте запис.<sup>[[3]](#references)</sup>
* **Розпакування в sandbox** – Розпаковуйте в disposable directory за допомогою extractor із перевірками шляхів/symlink (наприклад, стандартними secure checks у bsdtar або 7-Zip ≥ 25.00), а потім перевіряйте, що результуючі шляхи залишаються всередині каталогу.<sup>[[1]](#references)[[9]](#references)</sup>
* **Моніторинг endpoint-ів** – Створіть alert на появу нових виконуваних файлів у розташуваннях `Startup`/`Run`/`cron` невдовзі після відкриття архіву через WinRAR/7-Zip тощо.

## Пом’якшення та посилення захисту

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ містять виправлення для згаданих проблем із path/symlink.<sup>[[1]](#references)[[5]](#references)</sup>
2. За можливості розпаковуйте архіви з параметрами “**Do not extract paths**” / “**Ignore paths**”.
3. В Unix знизьте privileges і змонтуйте **chroot/namespace** перед розпакуванням; у Windows використовуйте **AppContainer** або sandbox.
4. Якщо ви пишете власний код, нормалізуйте шлях за допомогою `realpath()`/`PathCanonicalize()` **перед** створенням/записом і відхиляйте будь-який запис, що виходить за межі каталогу призначення.

## Додаткові вразливі / історичні випадки

* 2018 – масштабне повідомлення про *Zip-Slip* від Snyk, що стосувалося багатьох Java/Go/JS-бібліотек.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal під час TAR-розпакування slug-ів (виправлено у v0.16.3).<sup>[[7]](#references)</sup>
* Будь-яка власна логіка розпакування, яка не викликає `PathCanonicalize` / `realpath` перед записом.

## References

- [1] [Trend Micro ZDI-25-949 – traversal symlink у ZIP 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip у mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Запобігання Zip Slip у .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – ланцюжок HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Негайно оновіть інструменти WinRAR: RomCom та інші експлуатують zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Публічне розкриття критичної вразливості довільного перезапису файлів: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug вразливий до Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Метод Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – secure extraction flags bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Для CVE-2025-11001 у 7-Zip повідомлено Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
