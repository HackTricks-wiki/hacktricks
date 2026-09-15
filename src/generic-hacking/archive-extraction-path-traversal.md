# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Огляд

Багато форматів архівів (ZIP, RAR, TAR, 7-ZIP тощо) дозволяють кожному запису містити власний **внутрішній шлях**. Коли утиліта розпакування без перевірки використовує цей шлях, створене ім'я файлу, що містить `..` або **абсолютний шлях** (наприклад, `C:\Windows\System32\`), буде записано за межами вибраного користувачем каталогу.
Цей клас вразливостей широко відомий як *Zip-Slip* або **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Наслідки варіюються від перезапису довільних файлів до безпосереднього досягнення **remote code execution (RCE)** шляхом розміщення payload у місці **auto-run**, наприклад у папці Windows *Startup*.

## Root Cause

1. Attacker створює архів, у якому один або кілька заголовків файлів містять:
* Відносні послідовності обходу (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Абсолютні шляхи (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Або створені **symlinks**, які вказують за межі цільового каталогу (поширено в ZIP/TAR на *nix*).
2. Victim розпаковує архів за допомогою вразливого інструмента, який довіряє вбудованому шляху (або переходить за symlinks), замість того щоб санітизувати його або примусово виконувати розпакування всередині вибраного каталогу.
3. Файл записується в контрольоване Attacker місце та виконується/завантажується наступного разу, коли система або користувач активує цей шлях.

### .NET `Path.Combine` + `ZipArchive` traversal

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
- Якщо `entry.FullName` починається з `..\\`, він виконує traversal; якщо це **абсолютний шлях**, компонент зліва повністю відкидається, що дає змогу виконати **запис у довільний файл** як ідентичність розпакування.
- Архів proof-of-concept для запису в сусідній каталог `app`, за яким стежить планувальник сканера:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Переміщення цього ZIP до monitored inbox призводить до появи `C:\samples\app\0xdf.txt`, що доводить traversal за межі `C:\samples\queue\` і дає змогу застосувати подальші primitives (наприклад, DLL hijacks).

## Advanced Archive-Breakout Primitives

Розглядайте extraction як послідовність мутацій файлової системи, а не як незалежні перевірки імен файлів. Entry, безпечний під час парсингу, може стати небезпечним після того, як попередній member створить або замінить link; така сама проблема виникає, коли extractor кешує directory як безпечний, а згодом змінює його тип.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: створіть `pivot -> /tmp`, а потім витягніть regular member як `pivot/PWNED.txt`. Якщо extractor переходить за першим member під час materialising другого, запис виходить за межі цільового шляху без `..` у другому імені.
* **Directory-cache/TOCTOU collision**: створіть directory `d/sub/`, замініть `d/sub` на symlink до `/tmp`, а потім додайте `d/sub/PWNED.txt`. Це націлено на extractors, які перевіряють або кешують directory один раз і не перевіряють його повторно перед фінальним записом.
* **Hardlink read/overwrite**: TAR і RAR можуть представляти hardlinks. Hardlink на наявний host file може розкрити його вміст, якщо пізніший component обслуговує витягнуте ім’я; colliding regular entry натомість може перезаписати пов’язаний inode. Це обмежується правилами щодо same-filesystem і дозволів ОС на hardlinks.
* **Pre-existing or cross-archive pivot**: повторіть спробу з непорожнім destination. Один archive може встановити link, а подальше extraction може записати через нього, навіть якщо кожен archive проходить stateless header-name check.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Порівнюйте імена, використовуючи семантику файлової системи, яка прийматиме їх. Корисні differential cases включають `LINK` проти `link` у case-insensitive файлових системах, Unicode-написання NFC проти NFD, compatibility-equivalent імена на кшталт `ﬁle` проти `file`, duplicate members, які змінюють path із directory на symlink, а також backslashes, що інтерпретуються як separators лише у Windows. Також тестуйте імена з ADS на NTFS. Ці випадки можуть призвести до того, що validator бачить два paths, тоді як файлова система визначає один.<sup>[[5]](#references)[[11]](#references)</sup>

Отже, компактний corpus має тестувати впорядковані комбінації **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, змішані `/` і `\`, absolute/rooted names та compressed wrappers на кшталт `.tar.gz`. Запускайте це лише у disposable VM/container і відстежуйте як destination, так і призначений зовнішній canary path.<sup>[[11]](#references)</sup>

ZIP-specific structural ambiguity може призвести до того, що pre-scan і реальний extractor побачать різні entry names або trees. Дивіться [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), а не покладайтеся на результат лише однієї ZIP library.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR для Windows і його Windows RAR/UnRAR components не виконували належну валідацію filenames під час extraction. Уразливість використовувала NTFS alternate data streams (ADS), щоб обійти вибраний extraction path і записати files у непередбачені locations.<sup>[[5]](#references)</sup>  
Шкідливий RAR archive, що містить entry на кшталт:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
опинився б **за межами** вибраного каталогу в папці *Startup* користувача. ESET спостерігала, як шкідливі LNK-файли розпаковувалися туди й виконувалися під час входу користувача в систему, забезпечуючи persistence і шлях до RCE.<sup>[[5]](#references)</sup>

### Створення PoC Archive (Linux/Mac)

Оскільки CVE-2025-8088 використовує traversal path в імені ADS, скористайтеся спеціально створеним генератором для створення RAR, а потім тестуйте розпакування лише в ізольованій lab із вразливою збіркою WinRAR.<sup>[[5]](#references)</sup>

### Спостереження за Exploitation у Wild

ESET повідомила про spear-phishing кампанії RomCom (Storm-0978/UNC2596), у яких додавалися RAR-архіви, що використовували CVE-2025-8088 для розгортання кастомізованих backdoors і сприяння ransomware-операціям.<sup>[[5]](#references)</sup>

## Новіші випадки (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Вразливість**: ZIP entries, які були **symbolic links**, розіменовувалися під час розпакування, що дозволяло attackers вийти за межі destination directory і перезаписати довільні paths. Взаємодія з боку користувача полягає лише у *відкритті/розпакуванні* archive.<sup>[[1]](#references)</sup>
* **Вразливі версії**: збірки 7-Zip до **25.00**. Flaw в обробці symbolic links було виправлено у версії **25.00** (липень 2025) і пізніших версіях.<sup>[[1]](#references)[[10]](#references)</sup>
* **Шлях до impact**: Перезаписати `Start Menu/Programs/Startup` або service-run locations → code виконується під час наступного входу в систему або перезапуску service.
* **Швидкий fixture для обробки symlink (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Цей archive містить symlink entry, що вказує за межі extraction directory; використовуйте disposable target і перевірте, що extractor не переходить за ним. Для тесту запису також потрібен regular-file entry всередині symlink.

### Колізія symlink у Go mholt/archiver `Unarchive()` (CVE-2025-3445)
* **Вразливість**: `archiver.Unarchive()` може розпакувати ZIP symlink, а потім розіменувати його, коли пізніший regular member має таке саме ім’я, перетворюючи запис, який начебто відбувається всередині root, на запис за межами root.<sup>[[2]](#references)</sup>
* **Вразливі версії**: `github.com/mholt/archiver` ≤ 3.5.1 (проєкт тепер deprecated).<sup>[[2]](#references)</sup>
* **Виправлення**: Перейдіть на `mholt/archives` ≥ 0.1.0 або відхиляйте links і повторно визначайте кожен destination безпосередньо перед його відкриттям.<sup>[[2]](#references)</sup>
* **Мінімальний генератор collision** (потім викличте `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### Обхід фільтрованого TAR extraction у CPython (CVE-2026-11940)

Навіть `tarfile.extractall(filter="data")` і `filter="tar"` мали bypass через порядок links. У цьому випадку hardlink посилався на symlink, заархівований за глибшим path; fallback extraction перевіряв relative symlink у цій глибокій location, але відтворював його в мілкішій location hardlink, де той самий relative target виходив за межі. Це корисний загальний тест: зробіть так, щоб validation і materialisation розходилися щодо base directory або final member type.<sup>[[12]](#references)</sup>

### Escape hardlink target у Node `tar` через symlink chain (GHSA-83g3-92jg-28cx)

Пакет Node.js `tar` з `tar.extract()` приймав hardlink, target якого лексично здавався таким, що міститься всередині, але через дві попередні symlinks розв’язувався за межами extraction root. Атака працює з default extraction options: перевірки destination-parent охоплювали in-root name hardlink, тоді як hardlink target передавався до filesystem без розв’язання повного chain для перевірки containment. Вразливі версії `tar` ≤ 7.5.7; версія 7.5.8 виправляє цю проблему.<sup>[[13]](#references)</sup>

Важливим test fixture є **впорядкований зв’язок** між members, а не ці literal names:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Якщо extraction успішне, `exfil` залишається помітним усередині output tree, але спільно використовує inode з вибраним зовнішнім файлом; його читання leak-ає цей файл, а запис змінює оригінал. Цей bypass показує, чому недостатньо перевіряти лише кінцевий pathname, видаляти absolute prefixes або блокувати `..` у hardlink header: link targets потрібно перевіряти після застосування всього раніше extracted filesystem state.<sup>[[13]](#references)</sup>

## Поради щодо виявлення

* **Static inspection** – Перелічіть як імена member-ів, так і link targets. Позначайте `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes і collisions, еквівалентні з погляду регістру/Unicode. Під час перевірки зберігайте порядок entry, оскільки exploit може залежати від попередніх member-ів.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – Переконайтеся, що resolved parent разом із final basename залишається всередині resolved destination (порівнюйте path components, а не raw string prefix). Виконуйте повторну перевірку після кожного попереднього member-а; одноразова перевірка `realpath(join(dest, name))` вразлива до заміни link і може не спрацювати для ще не створеного leaf.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress-те у свіжу disposable directory за допомогою extractor-а з path/symlink checks (наприклад, стандартних secure checks у bsdtar або 7-Zip ≥ 25.00), а потім перевірте, що resulting tree не містить outward links. Isolation має запобігати тому, щоб уже triggered escape досягав host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Symlink або hardlink, що залишився, може стати primitive для arbitrary-file-read, коли previewer, CDN, file browser або package pipeline згодом відкриває чи обслуговує extracted name, навіть якщо сама extraction не створила жодного зовнішнього файлу.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Створюйте alert на нові executables, записані до розташувань `Startup`/`Run`/`cron` невдовзі після відкриття archive через WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+, 7-Zip 25.00+ і Node `tar` 7.5.8+ містять fixes для наведених issues із path/symlink/link-target.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. За можливості extract-те archives з параметрами “**Do not extract paths**” / “**Ignore paths**”. Для untrusted input відхиляйте symbolic links, hardlinks, devices і FIFOs, якщо application явно їх не потребує.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract-те у **new empty directory**. Не об’єднуйте untrusted members із tree, що містить paths, які може замінити attacker, і не використовуйте повторно directory, підготовлену попереднім archive.<sup>[[11]](#references)</sup>
4. В Unix drop-ніть privileges та ізолюйте destination у **chroot/mount namespace**; у Windows використовуйте **AppContainer** або sandbox. Одного post-extraction scan недостатньо, оскільки escaped write відбувається до scan.<sup>[[11]](#references)</sup>
5. У custom code застосовуйте separator/case/Unicode rules цільової OS і перевіряйте як member, так і link target. Resolve-те й відкривайте destination без переходу за links; не відокремлюйте containment check від подальшої create/replace operation. Validator має використовувати точно такі самі base та link-emulation semantics, як і write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Додаткові / історичні випадки

* 2018 – Великий *Zip-Slip* advisory від Snyk, що стосувався багатьох Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): traversal під час TAR extraction у slugs (виправлено у v0.16.3).<sup>[[7]](#references)</sup>
* Будь-яка custom extraction logic, яка перевіряє header strings, але не link targets і final filesystem path, що використовується для кожного write.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Запобігання Zip Slip у .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → ланцюжок DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Негайно оновіть WinRAR tools: RomCom та інші використовують zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Публічне розкриття critical arbitrary file overwrite vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug вразливий до Zip Slip attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Метод Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – secure extraction flags у bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Для CVE-2025-11001 у 7-Zip повідомлено proof-of-concept exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Веселий hacking із zip-slips, tar-slips, symlinks, hardlinks, collisions та іншим](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Обхід extraction filter у tarfile для CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – escape hardlink target у node-tar через symlink chain](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
