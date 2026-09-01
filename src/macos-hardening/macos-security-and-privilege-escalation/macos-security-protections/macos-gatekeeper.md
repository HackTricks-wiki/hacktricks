# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для операційних систем Mac, яка гарантує, що користувачі **запускають у своїх системах лише довірене програмне забезпечення**. Вона працює шляхом **перевірки програмного забезпечення**, яке користувач завантажує та намагається відкрити з **джерел за межами App Store**, наприклад застосунку, plug-in або installer package.

Ключовим механізмом Gatekeeper є процес **верифікації**. Він перевіряє, чи **підписане завантажене програмне забезпечення визнаним розробником**, підтверджуючи його автентичність. Крім того, він перевіряє, чи було програмне забезпечення **notarised Apple**, що підтверджує відсутність відомого шкідливого вмісту та незмінність після notarisation.

Додатково Gatekeeper посилює контроль користувача та безпеку, **запитуючи дозвіл на відкриття** завантаженого програмного забезпечення під час першого запуску. Цей захист допомагає запобігти випадковому запуску потенційно небезпечного виконуваного коду, який користувач міг помилково прийняти за нешкідливий файл даних.

### Application Signatures

Application signatures, також відомі як code signatures, є критично важливим компонентом інфраструктури безпеки Apple. Вони використовуються для **перевірки особи автора програмного забезпечення** (розробника) і гарантують, що код не було змінено після останнього підписання.

Ось як це працює:

1. **Signing the Application:** Коли розробник готовий поширити свій застосунок, він **підписує застосунок за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** під час його реєстрації в Apple Developer Program. Процес підписання передбачає створення криптографічного хешу всіх частин застосунку та шифрування цього хешу приватним ключем розробника.
2. **Distributing the Application:** Підписаний застосунок поширюється користувачам разом із сертифікатом розробника, який містить відповідний публічний ключ.
3. **Verifying the Application:** Коли користувач завантажує застосунок і намагається його запустити, операційна система Mac використовує публічний ключ із сертифіката розробника для розшифрування хешу. Потім вона повторно обчислює хеш на основі поточного стану застосунку та порівнює його з розшифрованим хешем. Якщо вони збігаються, це означає, що **застосунок не було змінено** після його підписання розробником, і система дозволяє застосунку запуститися.

Application signatures є важливою частиною технології Apple Gatekeeper. Коли користувач намагається **відкрити застосунок, завантажений з інтернету**, Gatekeeper перевіряє application signature. Якщо застосунок підписано сертифікатом, виданим Apple відомому розробнику, і код не було змінено, Gatekeeper дозволяє застосунку запуститися. В іншому випадку він блокує застосунок і попереджає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи було застосунок notarized** Apple, додаючи ще один рівень безпеки. Процес notarization перевіряє застосунок на наявність відомих проблем безпеки та шкідливого коду, і якщо ці перевірки успішні, Apple додає до застосунку ticket, який Gatekeeper може перевірити.

#### Check Signatures

Під час перевірки будь-якого **зразка malware** слід завжди **перевіряти signature** бінарного файлу, оскільки **developer**, який його підписав, уже може бути **пов’язаний** із **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Нотаризація

Процес notarization Apple слугує додатковим захистом для користувачів від потенційно шкідливого програмного забезпечення. Він передбачає **надсилання розробником свого застосунку на перевірку** до **Apple's Notary Service**, яку не слід плутати з App Review. Цей сервіс є **автоматизованою системою**, яка перевіряє надіслане програмне забезпечення на наявність **шкідливого вмісту** та потенційних проблем із code-signing.

Якщо програмне забезпечення **проходить** цю перевірку без зауважень, Notary Service створює ticket notarization. Після цього розробник має **додати цей ticket до свого програмного забезпечення** — процес, відомий як 'stapling'. Крім того, ticket notarization також публікується онлайн, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першого встановлення або запуску програмного забезпечення користувачем наявність ticket notarization — незалежно від того, чи він доданий до виконуваного файлу, чи знайдений онлайн, — **повідомляє Gatekeeper, що програмне забезпечення було нотаризоване Apple**. У результаті Gatekeeper відображає описове повідомлення в діалозі першого запуску, зазначаючи, що Apple перевірила програмне забезпечення на наявність шкідливого вмісту. Таким чином цей процес підвищує впевненість користувачів у безпеці програмного забезпечення, яке вони встановлюють або запускають у своїх системах.

### spctl & syspolicyd

> [!CAUTION]
> Зверніть увагу, що починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI-інструмент для переліку об’єктів Gatekeeper і взаємодії з ним (із daemon `syspolicyd` через XPC-повідомлення). Наприклад, переглянути **статус** GateKeeper можна за допомогою:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Зверніть увагу, що перевірки підпису GateKeeper виконуються лише для **файлів з атрибутом Quarantine**, а не для кожного файлу.

GateKeeper перевірить, чи може binary бути виконаний відповідно до **налаштувань і підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — це основний daemon, відповідальний за застосування Gatekeeper. Він підтримує базу даних, розташовану в `/var/db/SystemPolicy`, а код для роботи з [базою даних можна знайти тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), а [SQL-шаблон — тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що на базу даних не поширюється SIP, і root може записувати до неї, а база даних `/var/db/.SystemPolicy-default` використовується як оригінальна резервна копія на випадок пошкодження іншої.

Крім того, бандли **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які вставляються до бази даних. Ви можете перевірити цю базу даних як root за допомогою:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** також надає XPC-сервер із різними операціями, такими як `assess`, `update`, `record` і `cancel`, які також доступні через API **`Security.framework`'s `SecAssessment*`**, а **`spctl`** фактично взаємодіє із **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчувалося на "**App Store**", а друге — на "**Developer ID**", і що на попередньому зображенні було **дозволено виконувати програми з App Store та від ідентифікованих розробників**.\
Якщо ви **зміните** це налаштування на App Store, правила "**Notarized Developer ID" зникнуть**.

Також існують тисячі правил **типу GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Це хеші з:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Або можна переглянути наведену вище інформацію за допомогою:
```bash
sudo spctl --list
```
Параметри **`--master-disable`** і **`--global-disable`** команди **`spctl`** повністю **вимкнуть** ці перевірки підписів:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Після повного ввімкнення з'явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Можна **перевірити, чи буде App дозволено GateKeeper**, за допомогою:
```bash
spctl --assess -v /Applications/App.app
```
У macOS 14 і новіших версіях **`syspolicy_check`** — це корисна перевірка вищого рівня перед розповсюдженням application bundle. Вона надає більш практичні діагностичні дані щодо trusted execution, ніж простий результат `spctl`, хоча Apple все одно рекомендує тестувати реальний шлях завантаження/розпакування/першого запуску, оскільки він також перевіряє поширення quarantine.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
Можна додати нові правила в GateKeeper, щоб дозволити виконання певних застосунків за допомогою:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Щодо **kernel extensions**, папка `/var/db/SystemPolicyConfiguration` містить файли зі списками kexts, яким дозволено завантажуватися. Крім того, `spctl` має entitlement `com.apple.private.iokit.nvram-csr`, оскільки здатний додавати нові попередньо схвалені kernel extensions, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

#### Керування Gatekeeper у macOS 15 (Sequoia) і новіших версіях

- Тривалий обхід через Finder **Ctrl+Open / Right-click → Open** було видалено; після першого діалогу блокування користувачі повинні явно дозволити заблокований застосунок через **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` більше не приймаються як автоматизовані зміни політики. Операції, що змінюють базу даних правил або глобальний стан оцінювання, є застарілими, тому використовуйте `spctl` для оцінювання, а примусове застосування політики налаштовуйте через UI або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть перемикати політику Gatekeeper через `spctl`. Керування виконується через System Settings або шляхом розгортання профілю конфігурації MDM із payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, який дозволяє застосунки з App Store та від ідентифікованих розробників, але не "Anywhere":

<details>
<summary>Профіль MDM для дозволу застосунків з App Store та від ідентифікованих розробників</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Файли Quarantine

Під час **завантаження** застосунку або файлу певні macOS **застосунки**, як-от веббраузери або поштові клієнти, **додають розширений атрибут файлу**, відомий як "**quarantine flag**", до завантаженого файлу. Цей атрибут є заходом безпеки, що **позначає файл** як такий, що походить із ненадійного джерела (інтернету), і потенційно може становити ризик. Однак не всі застосунки додають цей атрибут; наприклад, поширене програмне забезпечення BitTorrent-клієнтів зазвичай обходить цей процес.

**Наявність quarantine flag сигналізує функції безпеки macOS Gatekeeper, коли користувач намагається виконати файл**.

Якщо **quarantine flag відсутній** (як у випадку з файлами, завантаженими через деякі BitTorrent-клієнти), **перевірки Gatekeeper можуть не виконуватися**. Тому користувачам слід бути обережними під час відкриття файлів, завантажених із менш безпечних або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду є **ресурсомістким** процесом, який включає створення криптографічних **хешів** коду та всіх ресурсів, що входять до нього. Крім того, перевірка дійсності сертифіката передбачає виконання **онлайн-перевірки** серверів Apple, щоб з'ясувати, чи не було його відкликано після видачі. З цих причин повну перевірку підпису коду та notarization **непрактично виконувати щоразу під час запуску застосунку**.
>
> Тому ці перевірки **виконуються лише під час запуску застосунків із quarantine attribute**.

> [!WARNING]
> Цей атрибут має бути **встановлений застосунком, який створює або завантажує** файл.
>
> Однак для файлів, що працюють у sandbox, цей атрибут буде встановлено для кожного створеного ними файлу. Застосунки, що не працюють у sandbox, можуть встановити його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**, що змусить систему встановлювати розширений атрибут `com.apple.quarantine` для створених файлів,

Крім того, усі файли, створені процесом, який викликає **`qtn_proc_apply_to_self`**, поміщаються в quarantine. А API **`qtn_file_apply_to_path`** додає атрибут quarantine до вказаного шляху файлу.

Можна **перевірити його статус і ввімкнути/вимкнути** (потрібні права root) за допомогою:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Також можна **перевірити, чи має файл розширений атрибут quarantine**, за допомогою:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Перевірте **значення** **розширених** **атрибутів** і визначте застосунок, який записав атрибут **quarantine**, за допомогою:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Насправді процес «міг би встановлювати quarantine flags для файлів, які він створює» (я вже намагався застосувати прапорець `USER_APPROVED` до створеного файлу, але він не застосовується):

<details>

<summary>Source Code apply quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

І **видаліть** цей атрибут за допомогою:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
І знайдіть усі файли, поміщені в карантин, за допомогою:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Інформація про Quarantine також зберігається в центральній базі даних, якою керує LaunchServices, у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, що дає змогу GUI отримувати дані про походження файлів. Крім того, ці дані можуть бути перезаписані програмами, зацікавленими у приховуванні свого походження. Це також можна зробити через APIS LaunchServices.

#### **libquarantine.dylib**

Ця бібліотека експортує кілька функцій, які дають змогу маніпулювати полями extended attributes.

API `qtn_file_*` працюють із політиками file quarantine, а API `qtn_proc_*` застосовуються до процесів (файлів, створених процесом). Некспортовані функції `__qtn_syscall_quarantine*` застосовують політики, викликаючи `mac_syscall` із `"Quarantine"` як першим аргументом, що надсилає запити до `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension доступний лише через **kernel cache у системі**; однак ви _можете завантажити **Kernel Debug Kit з** [**https://developer.apple.com/**](https://developer.apple.com/), який міститиме symbolicated версію extension.

Цей Kext за допомогою MACF перехоплює кілька викликів, щоб відстежувати всі події життєвого циклу файлів: створення, відкриття, перейменування, створення hard link тощо, навіть `setxattr`, щоб запобігти встановленню extended attribute `com.apple.quarantine`.

Він також використовує кілька MIB:

- `security.mac.qtn.sandbox_enforce`: застосовувати quarantine разом із Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs можуть виконувати лише схвалені файли

#### Provenance xattr (Ventura і пізніші версії)

У macOS 13 Ventura було представлено окремий механізм provenance, який заповнюється під час першого дозволу на запуск quarantined app.<sup>[[2]](#references)</sup> Створюються два артефакти:

- xattr `com.apple.provenance` у директорії bundle `.app` (бінарне значення фіксованого розміру, що містить primary key і flags).
- Рядок у таблиці `provenance_tracking` усередині бази даних ExecPolicy за шляхом `/var/db/SystemPolicyConfiguration/ExecPolicy/`, де зберігаються cdhash і metadata app.

Практичне використання:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect — це вбудована функція **захисту від malware** у macOS. XProtect **перевіряє кожну програму під час її першого запуску або після внесення змін, порівнюючи її з базою даних** відомих malware і небезпечних типів файлів. Коли ви завантажуєте файл через певні програми, як-от Safari, Mail або Messages, XProtect автоматично сканує файл. Якщо він відповідає будь-якому відомому malware у базі даних, XProtect **забороняє запуск файлу** та повідомляє вас про загрозу.

Apple **регулярно оновлює** базу даних XProtect, додаючи нові визначення malware, а ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Це гарантує, що XProtect завжди містить актуальну інформацію про останні відомі загрози.

Однак варто зазначити, що **XProtect не є повнофункціональним антивірусним рішенням**. Він перевіряє лише певний перелік відомих загроз і не виконує сканування під час доступу, як більшість антивірусного програмного забезпечення.

Отримати інформацію про останнє оновлення XProtect можна, виконавши:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect розташований у захищеному SIP місці **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, і всередині bundle можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhash використовувати legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список plugins і extensions, завантаження яких заборонене через BundleID і TeamID, або для яких указано мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 із hashes заблокованих applications і TeamIDs.

Зверніть увагу, що існує ще один App у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов’язаний із XProtect, але він не бере участі в процесі Gatekeeper.

> XProtect Remediator: У сучасних версіях macOS Apple постачає on-demand scanners (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення сімейств malware. Ви можете спостерігати за цими scans в unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу, що Gatekeeper **не запускається щоразу**, коли ви запускаєте application: лише _**AppleMobileFileIntegrity**_ перевіряє **підписи executable code**, коли ви запускаєте app, яка вже була запущена та перевірена Gatekeeper.

Тому раніше можна було запустити app, щоб закешувати її за допомогою Gatekeeper, потім **змінити не-executable файли application** (наприклад, Electron asar або NIB files), і якщо не було інших protections, application **запускалася** з **malicious** additions.

Однак тепер це неможливо, оскільки macOS **перешкоджає зміні файлів** усередині application bundles. Отже, якщо ви спробуєте виконати attack [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви виявите, що тепер ним неможливо зловживати, оскільки після запуску app для її кешування за допомогою Gatekeeper ви не зможете змінити bundle. А якщо ви, наприклад, зміните назву директорії Contents на NotCon, як зазначено в exploit, а потім запустите main binary app, щоб закешувати її за допомогою Gatekeeper, це спричинить помилку, і app не запуститься.

## Обходи Gatekeeper

Будь-який спосіб обійти Gatekeeper (змусити користувача завантажити щось і запустити це, коли Gatekeeper мав би заборонити запуск) вважається вразливістю macOS. Нижче наведено деякі CVE, присвоєні технікам, які в минулому дозволяли обійти Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що якщо для розпакування використовується **Archive Utility**, файли з **шляхами довжиною понад 886 символів** не отримують extended attribute com.apple.quarantine. Ця ситуація ненавмисно дозволяє цим файлам **обійти** security checks **Gatekeeper**.<sup>[[5]](#references)</sup>

Додаткову інформацію дивіться в [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли application створюється за допомогою **Automator**, інформація про те, що їй потрібно виконати, міститься в `application.app/Contents/document.wflow`, а не в executable. Executable є лише generic Automator binary під назвою **Automator Application Stub**.

Тому можна було зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **вказував за допомогою symbolic link на інший Automator Application Stub у системі**, і він виконував те, що міститься в `document.wflow` (ваш script), **не запускаючи Gatekeeper**, оскільки фактичний executable не мав quarantine xattr.<sup>[[6]](#references)</sup>

Приклад очікуваного розташування: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Додаткову інформацію дивіться в [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

У цьому bypass zip file було створено так, щоб стискання починалося з `application.app/Contents`, а не з `application.app`. Тому **quarantine attr** застосовувався до всіх **files з `application.app/Contents`**, але **не до `application.app`**, яку перевіряв Gatekeeper. Отже, Gatekeeper було обійдено, оскільки під час запуску `application.app` **вона не мала quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/), щоб дізнатися більше.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Навіть якщо компоненти відрізняються, exploitation цієї вразливості дуже схожий на попередній. У цьому випадку ми створимо Apple Archive з **`application.app/Contents`**, тому **`application.app` не отримає quarantine attribute** під час розпакування за допомогою **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) для отримання додаткової інформації.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** можна використовувати, щоб заборонити будь-кому записувати атрибут у файл:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Крім того, формат файлів **AppleDouble** копіює файл разом із його ACE.<sup>[[9]](#references)</sup>

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути application у zip-файл у форматі **AppleDouble** з ACL, який забороняє запис інших xattr до нього... quarantine xattr не було встановлено в application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.<sup>[[9]](#references)</sup>

Зверніть увагу, що це також можна було експлуатувати за допомогою AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут карантину** для завантажених файлів через певні внутрішні проблеми macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble зберігає атрибути файлу в окремому файлі, ім’я якого починається з `._`; це допомагає копіювати атрибути файлів **між машинами macOS**. Однак після розпакування файлу AppleDouble файл, що починається з `._`, **не отримував атрибут карантину**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Маючи можливість створити файл, для якого не буде встановлено атрибут quarantine, **можна було обійти Gatekeeper.** Трюк полягав у тому, щоб **створити DMG file application** за допомогою угоди про імена AppleDouble (почати його з `._`) і створити **видимий файл як символьне посилання на цей прихований** файл без атрибута quarantine.\
Коли **dmg file виконується**, оскільки він не має атрибута quarantine, він **обходить Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Apple виправила логічну помилку LaunchServices у macOS Sonoma 14.0 за допомогою вдосконалених перевірок. У публічному advisory лише зазначено, що застосунок міг обійти Gatekeeper, тому не слід робити висновки щодо конкретного формату carrier або ланцюжка експлуатації, спираючись лише на запис CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущеній у березні 2024 року), спричинений обробкою шкідливих ZIP-файлів у `libarchive`, дозволяв застосункам уникати перевірки. Оновіть систему до версії 14.4 або новішої, де Apple усунула цю проблему.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Workflow Automator Quick Action**, вбудований у завантажений застосунок, міг запускатися без перевірки Gatekeeper, оскільки workflow розглядалися як дані та виконувалися helper Automator поза стандартним шляхом запиту notarization. Тому спеціально сформований `.app`, що містив Quick Action для запуску shell script (наприклад, усередині `Contents/PlugIns/*.workflow/Contents/document.wflow`), міг виконуватися одразу під час запуску. Apple додала додаткове діалогове вікно згоди та виправила шлях перевірки у Ventura **13.7**, Sonoma **14.7** і Sequoia **15**.<sup>[[3]](#references)</sup>

### Помилки поширення Quarantine на межах розпакування та копіювання

Дослідження 2024 року виявило прогалини поширення у протестованих версіях iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) і 7z Utility (DMG/ZIP/7Z); також було виявлено втрату атрибута під час копіювання з host до guest за допомогою VMware Tools. Згодом кілька постачальників оголосили про виправлення, тому сприймайте ці назви як орієнтири для **повторного тестування конкретних версій**, а не як постійний список вразливого програмного забезпечення. Та сама проблема межі довіри стосується нативних Unix workflow: `curl`/`scp` не додають quarantine, а командні `tar`/`unzip` автоматично не успадковують його з carrier archive.<sup>[[15]](#references)</sup>

Під час offensive testing порівнюйте carrier і кінцевий застосунок після **кожного** переходу через браузер, поштовий клієнт, архіватор, disk image, cloud-sync, shared folder і копіювання у VM. Явна відмова `spctl` не виправляє відсутній xattr: без quarantine стандартний шлях Gatekeeper під час першого відкриття може взагалі не запитати цю перевірку.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (з цієї [доповіді](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Створіть directory, що містить app.
- Додайте uchg до app.
- Стисніть app у файл tar.gz.
- Надішліть файл tar.gz victim.
- Victim відкриває файл tar.gz і запускає app.
- Gatekeeper не перевіряє app.<sup>[[12]](#references)</sup>

### Запобігання Quarantine xattr

Якщо до ".app" bundle не додано quarantine xattr, під час його виконання **Gatekeeper не буде запущено**.

Див. [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks), де описано primitives на основі файлової системи, flags, ACL і AppleDouble, які можуть запобігати додаванню або видаляти extended attributes.



## References

- [1] [Безпека платформ Apple: відомості про вміст безпеки macOS Sonoma 14.4 (включно з CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Як macOS тепер відстежує походження app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: відомості про вміст безпеки macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia усуває обхід Gatekeeper через «Open» за допомогою Control-click](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Виявлення CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, обхід macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs виявила вразливість Safari, що дає змогу обійти Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs виявила вразливість macOS Archive Utility, що дає змогу обійти Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: виявлення обходу Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Виявлення та повідомлення про exploit для обходу Gatekeeper за допомогою Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: обхід механізмів безпеки та приватності macOS — від Gatekeeper до System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: відомості про вміст безпеки macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: тестування notarised product](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: обхід Gatekeeper — виявлення слабких місць у механізмі безпеки macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
