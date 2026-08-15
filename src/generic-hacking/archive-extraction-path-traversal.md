# Обхід шляхів під час розпакування архівів ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Коли утиліта розпакування без перевірки використовує цей шлях, спеціально створене ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записано за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **обхід шляхів під час розпакування архівів**.<sup>[[6]](#references)</sup>

Наслідки можуть варіюватися від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у місці **auto-run**, наприклад у папці Windows *Startup*.

## Першопричина

1. Attacker створює архів, у якому один або кілька заголовків файлів містять:
* Відносні послідовності обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або спеціально створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його або примусово розпаковувати в межах вибраного каталогу.
3. Файл записується в місце, контрольоване attacker, і виконується/завантажується наступного разу, коли система або користувач звертається до цього шляху.

### Обхід шляхів через `.NET` `Path.Combine` + `ZipArchive`

Поширеним anti-pattern у .NET є об'єднання передбаченого каталогу призначення з **контрольованим користувачем** `ZipArchiveEntry.FullName` і розпакування без нормалізації шляху:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Якщо `entry.FullName` починається з `..\\`, він виконує traversal; якщо це **абсолютний шлях**, лівий компонент повністю відкидається, що призводить до **довільного запису файлів** як ідентифікатора extraction.
- Proof-of-concept archive для запису до сусіднього каталогу `app`, який відстежує запланований scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Додавання цього ZIP до monitored inbox призводить до появи `C:\samples\app\0xdf.txt`, що доводить traversal за межі `C:\samples\queue\` і дає змогу застосовувати follow-on primitives (наприклад, DLL hijacks).

## Advanced Archive-Breakout Primitives

Розглядайте extraction як послідовність filesystem mutations, а не як незалежні перевірки імен файлів. Entry, безпечний під час parsing, може стати небезпечним після того, як попередній member створить або замінить link; та сама проблема виникає, коли extractor кешує directory як безпечну, а пізніше змінює її тип.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: створіть `pivot -> /tmp`, а потім extract regular member як `pivot/PWNED.txt`. Якщо extractor follows перший member під час materialising другого, запис виходить за межі цільового шляху без `..` у другому імені.
* **Directory-cache/TOCTOU collision**: створіть directory `d/sub/`, замініть `d/sub` на symlink до `/tmp`, а потім створіть `d/sub/PWNED.txt`. Це атакує extractors, які перевіряють або кешують directory один раз і не виконують повторну перевірку перед final write.
* **Hardlink read/overwrite**: TAR і RAR можуть представляти hardlinks. Hardlink до наявного host file може розкрити його вміст, якщо пізніший component обслуговує extracted name; colliding regular entry натомість може перезаписати пов’язаний inode. Це обмежується правилами same-filesystem і OS hardlink-permission.
* **Pre-existing or cross-archive pivot**: повторіть спробу з non-empty destination. Один archive може встановити link, а наступне extraction — записати через нього, навіть якщо кожен archive проходить stateless header-name check.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Порівнюйте імена, використовуючи semantics filesystem, який прийматиме їх. Корисні differential cases включають `LINK` проти `link` у case-insensitive filesystems, Unicode-запис NFC проти NFD, compatibility-equivalent names на кшталт `ﬁle` проти `file`, duplicate members, які змінюють path з directory на symlink, а також backslashes, що трактуються як separators лише у Windows. Також тестуйте ADS-bearing names у NTFS. Через ці випадки validator може бачити два paths, тоді як filesystem resolve-ить один.<sup>[[5]](#references)[[11]](#references)</sup>

Отже, compact corpus має тестувати впорядковані комбінації **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, змішані `/` і `\`, absolute/rooted names, а також compressed wrappers на кшталт `.tar.gz`. Запускайте це лише у disposable VM/container і стежте як за destination, так і за intended outside canary path.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows і його Windows RAR/UnRAR components не виконували належну валідацію filenames під час extraction. Flaw використовував NTFS alternate data streams (ADS), щоб обійти selected extraction path і записувати files у unintended locations.<sup>[[5]](#references)</sup>
Malicious RAR archive, що містить entry на кшталт:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
опинився б **за межами** вибраного вихідного каталогу та всередині папки *Startup* користувача. ESET спостерігала, як шкідливі LNK-файли розпаковувалися туди й виконувалися під час входу користувача в систему, забезпечуючи persistence і шлях до RCE.<sup>[[5]](#references)</sup>

### Створення PoC Archive (Linux/Mac)

Оскільки CVE-2025-8088 використовує traversal path в імені ADS, скористайтеся спеціально створеним генератором для створення RAR, а потім тестуйте extraction лише в ізольованій lab із вразливою збіркою WinRAR.<sup>[[5]](#references)</sup>

### Спостереження за Exploitation у Wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у межах яких прикріплювалися RAR-архіви, що використовували CVE-2025-8088 для розгортання кастомізованих backdoor і сприяння ransomware-операціям.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP-записи, які були **symbolic links**, розіменовувалися під час extraction, що дозволяло attackers вийти за межі destination directory та перезаписати довільні paths. Взаємодія користувача полягає лише у *відкритті/розпаковуванні* архіву.<sup>[[1]](#references)</sup>
* **Affected**: збірки 7-Zip до **25.00**. Flaw в обробці symbolic-link було виправлено у **25.00** (липень 2025) та пізніших версіях.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Перезаписати `Start Menu/Programs/Startup` або locations, які запускаються службами → code виконується під час наступного входу в систему або перезапуску служби.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Цей архів містить symlink entry, що вказує за межі extraction directory; використовуйте disposable target і перевірте, що extractor не переходить за ним. Для write-through test також потрібен regular-file entry під symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` може розпакувати ZIP symlink, а потім розіменувати його, коли пізніший regular member має таке саме ім’я, перетворюючи начебто запис у root на запис за межами root.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт наразі deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Перейдіть на `mholt/archives` ≥ 0.1.0 або відхиляйте links і повторно визначайте кожен destination безпосередньо перед його відкриттям.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (потім викличте `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

Навіть `tarfile.extractall(filter="data")` і `filter="tar"` мали bypass через порядок links. У цьому випадку hardlink посилався на symlink, заархівований за глибшим path; fallback extraction перевіряв relative symlink у цьому глибокому location, але відтворював його в більш поверхневому location hardlink, де той самий relative target виходив за межі. Це корисний загальний test: зробіть так, щоб validation і materialisation використовували різні base directory або final member type.<sup>[[12]](#references)</sup>

## Поради щодо Detection

* **Static inspection** – Перелічіть імена всіх members та link targets. Позначайте `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes і collisions, еквівалентні з погляду case/Unicode. Під час review зберігайте порядок entries, оскільки exploit може залежати від попередніх members.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Переконайтеся, що resolved parent разом із final basename залишається всередині resolved destination (порівнюйте path components, а не raw string prefix). Повторно перевіряйте це після кожного попереднього member; одноразова перевірка `realpath(join(dest, name))` вразлива до заміни link і може не спрацювати для leaf, який ще не створено.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Розпаковуйте у свіжий disposable directory за допомогою extractor із path/symlink checks (наприклад, стандартних secure checks у bsdtar або 7-Zip ≥ 25.00), а потім перевірте, що отримане дерево не містить links назовні. Isolation має запобігати тому, щоб уже виконаний escape досягав paths хоста.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Symlink або hardlink, що зберігся, може стати primitive для arbitrary-file-read, коли previewer, CDN, file browser або package pipeline згодом відкриває чи віддає extracted name, навіть якщо сам extraction не створив жодного зовнішнього file.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Створюйте alert на нові executables, записані в locations `Startup`/`Run`/`cron` невдовзі після відкриття archive через WinRAR/7-Zip тощо.

## Mitigation & Hardening

1. **Оновіть extractor** – WinRAR 7.13+ і 7-Zip 25.00+ містять fixes для згаданих path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Розпаковуйте archives з параметрами “**Do not extract paths**” / “**Ignore paths**”, коли це можливо. Для untrusted input відхиляйте symbolic links, hardlinks, devices і FIFOs, якщо application явно їх не потребує.<sup>[[9]](#references)[[11]](#references)</sup>
3. Розпаковуйте у **новий порожній directory**. Не об’єднуйте untrusted members із деревом, що містить paths, які attacker може замінити, і не використовуйте повторно directory, створений попереднім archive.<sup>[[11]](#references)</sup>
4. У Unix знижуйте privileges та ізолюйте destination у **chroot/mount namespace**; у Windows використовуйте **AppContainer** або sandbox. Одного post-extraction scan недостатньо, оскільки escaped write відбувається до scan.<sup>[[11]](#references)</sup>
5. У custom code застосовуйте правила separator/case/Unicode цільової OS і перевіряйте як member, так і link target. Resolve і відкривайте destination без переходу за links; не відокремлюйте containment check від подальшої create/replace operation. Validator має використовувати точно такі самі base та link-emulation semantics, як і write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Додаткові / історичні affected cases

* 2018 – Великий advisory Snyk щодо *Zip-Slip*, який стосувався багатьох Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR extraction traversal у slugs (виправлено у v0.16.3).<sup>[[7]](#references)</sup>
* Будь-яка custom extraction logic, яка перевіряє header strings, але не link targets і final filesystem path, що використовується для кожного write.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Запобігання Zip Slip у .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Оновіть WinRAR tools зараз: RomCom та інші використовують zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Метод Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – secure extraction flags у bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Для CVE-2025-11001 у 7-Zip повідомлено про Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Розваги з zip-slips, tar-slips, symlinks, hardlinks, collisions та іншим](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – bypass extraction filter tarfile для CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
