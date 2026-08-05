# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для операційних систем Mac, яка гарантує, що користувачі **запускають лише довірене програмне забезпечення** у своїх системах. Вона працює шляхом **перевірки програмного забезпечення**, яке користувач завантажує та намагається відкрити з **джерел за межами App Store**, наприклад програми, plug-in або пакета інсталятора.

Ключовим механізмом Gatekeeper є процес **перевірки**. Він перевіряє, чи **підписане завантажене програмне забезпечення визнаним розробником**, підтверджуючи його автентичність. Крім того, він перевіряє, чи **пройшло програмне забезпечення notarisation в Apple**, підтверджуючи відсутність відомого шкідливого вмісту та змін після notarisation.

Також Gatekeeper посилює контроль користувача та безпеку, **запитуючи дозвіл на відкриття** завантаженого програмного забезпечення під час першого запуску. Цей захист допомагає запобігти випадковому запуску користувачами потенційно шкідливого виконуваного коду, який вони могли помилково прийняти за нешкідливий файл даних.

### Application Signatures

Application signatures, також відомі як code signatures, є критично важливим компонентом інфраструктури безпеки Apple. Вони використовуються для **перевірки особи автора програмного забезпечення** (розробника) і гарантують, що код не було змінено з моменту його останнього підписання.

Ось як це працює:

1. **Signing the Application:** Коли розробник готовий поширити свою програму, він **підписує програму за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** під час його реєстрації в Apple Developer Program. Процес підписання передбачає створення криптографічного hash усіх частин програми та шифрування цього hash приватним ключем розробника.
2. **Distributing the Application:** Потім підписана програма поширюється серед користувачів разом із сертифікатом розробника, який містить відповідний public key.
3. **Verifying the Application:** Коли користувач завантажує програму та намагається її запустити, операційна система Mac використовує public key із сертифіката розробника для розшифрування hash. Потім вона повторно обчислює hash на основі поточного стану програми та порівнює його з розшифрованим hash. Якщо вони збігаються, це означає, що **програму не було змінено** після її підписання розробником, і система дозволяє програмі запуститися.

Application signatures є важливою частиною технології Apple Gatekeeper. Коли користувач намагається **відкрити програму, завантажену з інтернету**, Gatekeeper перевіряє application signature. Якщо вона підписана сертифікатом, виданим Apple відомому розробнику, і код не було змінено, Gatekeeper дозволяє програмі запуститися. В іншому випадку він блокує програму та попереджає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи була програма notarized** в Apple, додаючи додатковий рівень безпеки. Процес notarization перевіряє програму на наявність відомих проблем безпеки та шкідливого коду. Якщо ці перевірки успішні, Apple додає до програми ticket, який Gatekeeper може перевірити.

#### Check Signatures

Під час перевірки деякого **malware sample** слід завжди **перевіряти signature** бінарного файлу, оскільки **developer**, який його підписав, уже може бути **пов’язаний** із **malware.**
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

Процес notarization Apple є додатковим захистом, що допомагає убезпечити користувачів від потенційно шкідливого програмного забезпечення. Він передбачає **подання розробником свого застосунку на перевірку** до **Apple's Notary Service**, яку не слід плутати з App Review. Цей сервіс є **автоматизованою системою**, що перевіряє подане програмне забезпечення на наявність **шкідливого вмісту** та потенційних проблем із code-signing.

Якщо програмне забезпечення **проходить** цю перевірку без зауважень, Notary Service генерує ticket notarization. Після цього розробник має **приєднати цей ticket до свого програмного забезпечення** — процес, відомий як 'stapling'. Крім того, ticket notarization публікується онлайн, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першого встановлення або запуску програмного забезпечення користувачем наявність ticket notarization — незалежно від того, чи він прикріплений до executable, чи знайдений онлайн — **повідомляє Gatekeeper, що програмне забезпечення пройшло notarization від Apple**. У результаті Gatekeeper відображає описове повідомлення в діалозі першого запуску, вказуючи, що Apple перевірила програмне забезпечення на наявність шкідливого вмісту. Таким чином цей процес підвищує довіру користувачів до безпеки програмного забезпечення, яке вони встановлюють або запускають у своїх системах.

### spctl & syspolicyd

> [!CAUTION]
> Зверніть увагу, що починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI tool для переліку об'єктів і взаємодії з Gatekeeper (із daemon `syspolicyd` через XPC messages). Наприклад, за допомогою нього можна переглянути **status** GateKeeper:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Зверніть увагу, що перевірки підпису GateKeeper виконуються лише для **файлів з атрибутом Quarantine**, а не для кожного файлу.

GateKeeper перевірить, чи може binary бути виконаний відповідно до **налаштувань і підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — це основний daemon, відповідальний за застосування Gatekeeper. Він підтримує базу даних, розташовану в `/var/db/SystemPolicy`, а [код для роботи з базою даних тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) і [SQL-шаблон тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що база даних не обмежується SIP і доступна для запису користувачу root, а база даних `/var/db/.SystemPolicy-default` використовується як оригінальна резервна копія на випадок пошкодження іншої бази.

Крім того, bundles **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які вставляються в базу даних. Перевірити цю базу даних від імені root можна за допомогою:
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
**`syspolicyd`** також надає XPC-сервер із різними операціями, такими як `assess`, `update`, `record` і `cancel`, які також доступні через API **`Security.framework`'s `SecAssessment*`**, а **`spctl`** фактично взаємодіє з **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчується на "**App Store**", а друге — на "**Developer ID**", і що на попередньому зображенні було **дозволено запускати програми з App Store і від ідентифікованих розробників**.\
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

Або можна вивести попередню інформацію за допомогою:
```bash
sudo spctl --list
```
Опції **`--master-disable`** і **`--global-disable`** утиліти **`spctl`** повністю **вимкнуть** ці перевірки підписів:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Після повного ввімкнення з’явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Можна **перевірити, чи буде App дозволено GateKeeper**, за допомогою:
```bash
spctl --assess -v /Applications/App.app
```
У GateKeeper можна додавати нові правила, щоб дозволити виконання певних застосунків за допомогою:
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

#### Керування Gatekeeper у macOS 15 (Sequoia) та новіших версіях

- Багаторічний обхід через **Ctrl+Open / Right-click → Open** у Finder було видалено; після першого діалогу блокування користувачі повинні явно дозволити заблокований застосунок через **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` більше не приймаються; `spctl` фактично доступний лише для читання під час assessment і керування labels, тоді як enforcement policy налаштовується через UI або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть перемикати політику Gatekeeper через `spctl`. Керування здійснюється через System Settings або шляхом розгортання конфігураційного профілю MDM із payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, що дозволяє App Store та identified developers (але не "Anywhere"):

<details>
<summary>MDM profile to allow App Store and identified developers</summary>
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

Під час **завантаження** застосунку або файлу певні **застосунки** macOS, як-от веббраузери або поштові клієнти, **додають розширений атрибут файлу**, який зазвичай називають "**прапорцем quarantine**", до завантаженого файлу. Цей атрибут виконує роль заходу безпеки, **позначаючи файл** як такий, що походить із ненадійного джерела (інтернету) і потенційно може становити ризик. Однак не всі застосунки додають цей атрибут; наприклад, поширене програмне забезпечення BitTorrent-клієнтів зазвичай обходить цей процес.

**Наявність прапорця quarantine сигналізує функції безпеки Gatekeeper у macOS, коли користувач намагається виконати файл**.

Якщо **прапорець quarantine відсутній** (як у випадку з файлами, завантаженими через деякі BitTorrent-клієнти), **перевірки Gatekeeper можуть не виконуватися**. Тому користувачам слід бути обережними під час відкриття файлів, завантажених із менш надійних або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду є **ресурсомістким** процесом, який включає створення криптографічних **хешів** коду та всіх його вбудованих ресурсів. Крім того, перевірка дійсності сертифіката передбачає **онлайн-перевірку** серверів Apple, щоб визначити, чи не було його відкликано після видачі. З цих причин повна перевірка підпису коду та notarization **є недоцільною під час кожного запуску застосунку**.
>
> Тому ці перевірки **виконуються лише під час запуску застосунків з атрибутом quarantine.**

> [!WARNING]
> Цей атрибут **має бути встановлений застосунком, який створює або завантажує** файл.
>
> Однак для всіх файлів, які створюють sandboxed-застосунки, цей атрибут буде встановлено. А non sandboxed-застосунки можуть встановити його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**, що змусить систему встановити розширений атрибут `com.apple.quarantine` для створених файлів,

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
Перевірте **значення** **розширених** **атрибутів** і визначте застосунок, який записав атрибут quarantine, за допомогою:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Насправді процес «може встановлювати quarantine flags для створених ним файлів» (я вже намагався застосувати прапорець USER_APPROVED до створеного файлу, але це не спрацювало):

<details>

<summary>Вихідний код для застосування quarantine flags</summary>
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
Інформація про Quarantine також зберігається в центральній базі даних, якою керує LaunchServices, у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, що дозволяє GUI отримувати дані про походження файлів. Крім того, її можуть перезаписувати applications, які можуть бути зацікавлені в приховуванні свого походження. Це також можна зробити через APIs LaunchServices.

#### **libquarantine.dylib**

Ця library експортує кілька функцій, які дозволяють маніпулювати полями extended attributes.

APIs `qtn_file_*` працюють із політиками file quarantine, а APIs `qtn_proc_*` застосовуються до processes (файлів, створених process). Неекспортовані функції `__qtn_syscall_quarantine*` застосовують політики та викликають `mac_syscall` із `"Quarantine"` як першим аргументом, надсилаючи запити до `Quarantine.kext`.

#### **Quarantine.kext**

Kernel extension доступне лише через **kernel cache у системі**; однак ви _можете завантажити **Kernel Debug Kit з** [**https://developer.apple.com/**](https://developer.apple.com/), який міститиме symbolicated версію extension.

Цей Kext використовує hooks через MACF для перехоплення кількох викликів, щоб відстежувати всі події життєвого циклу файлів: створення, відкриття, перейменування, створення hard links... навіть `setxattr`, щоб запобігти встановленню extended attribute `com.apple.quarantine`.

Він також використовує кілька MIBs:

- `security.mac.qtn.sandbox_enforce`: застосовувати quarantine разом із Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs можуть виконувати лише approved files

#### Provenance xattr (Ventura і новіші версії)

macOS 13 Ventura представила окремий механізм provenance, який заповнюється під час першого дозволу на запуск quarantined app.<sup>[[2]](#references)</sup> Створюються два артефакти:

- `com.apple.provenance` xattr у директорії `.app` bundle (двійкове значення фіксованого розміру, що містить primary key і flags).
- Рядок у таблиці `provenance_tracking` усередині бази даних ExecPolicy за адресою `/var/db/SystemPolicyConfiguration/ExecPolicy/`, де зберігаються cdhash і metadata app.

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

XProtect — це вбудована функція **захисту від malware** у macOS. XProtect **перевіряє кожну програму під час її першого запуску або після зміни, порівнюючи її з базою даних** відомого malware і небезпечних типів файлів. Коли ви завантажуєте файл через певні програми, як-от Safari, Mail або Messages, XProtect автоматично сканує файл. Якщо він відповідає будь-якому відомому malware у базі даних, XProtect **не дозволить файлу запуститися** та попередить вас про загрозу.

Apple **регулярно оновлює** базу даних XProtect новими визначеннями malware, і ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Це гарантує, що XProtect завжди містить актуальну інформацію про останні відомі загрози.

Однак варто зазначити, що **XProtect не є повнофункціональним антивірусним рішенням**. Він перевіряє лише певний список відомих загроз і не виконує сканування під час доступу, як більшість антивірусного програмного забезпечення.

Ви можете отримати інформацію про останнє оновлення XProtect, виконавши:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect знаходиться в захищеному SIP місці **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, а всередині bundle можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhash використовувати legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список plugins і extensions, завантаження яких заборонено через BundleID і TeamID, або для яких указано мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Правила Yara для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 із хешами заблокованих applications і TeamIDs.

Зверніть увагу, що існує ще один App у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов’язаний із XProtect, але він не бере участі в процесі Gatekeeper.

> XProtect Remediator: У сучасних версіях macOS Apple постачає on-demand scanners (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення сімейств malware. Ви можете спостерігати за цими скануваннями в unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу, що Gatekeeper **не запускається щоразу**, коли ви виконуєте application; лише _**AppleMobileFileIntegrity**_ перевіряє **підписи executable code**, коли ви запускаєте app, який уже було виконано та перевірено Gatekeeper.

Тому раніше можна було виконати app, щоб кешувати його в Gatekeeper, потім **змінити не-executable files application** (наприклад, Electron asar або NIB files), і якщо не було задіяно інших protections, application **виконувався** з **malicious** additions.

Однак тепер це неможливо, оскільки macOS **забороняє змінювати files** усередині applications bundles. Тому, якщо ви спробуєте виконати атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви виявите, що тепер не можна зловживати нею, оскільки після виконання app для його кешування в Gatekeeper ви не зможете змінити bundle. А якщо ви, наприклад, зміните назву директорії Contents на NotCon (як указано в exploit), а потім виконаєте main binary app, щоб кешувати його в Gatekeeper, це спричинить помилку, і він не запуститься.

## Gatekeeper Bypasses

Будь-який спосіб обійти Gatekeeper (домогтися, щоб користувач завантажив і виконав щось, що Gatekeeper мав би заборонити) вважається вразливістю macOS. Ось деякі CVE, призначені технікам, які в минулому дозволяли обійти Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що якщо для розпакування використовується **Archive Utility**, files із **paths, що перевищують 886 символів**, не отримують extended attribute com.apple.quarantine. Ця ситуація ненавмисно дозволяє цим files **обійти** security checks **Gatekeeper**.<sup>[[5]](#references)</sup>

Докладнішу інформацію дивіться у [**оригінальному звіті**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли application створюється за допомогою **Automator**, інформація про те, що йому потрібно виконати, міститься в `application.app/Contents/document.wflow`, а не у executable. Executable є лише generic Automator binary під назвою **Automator Application Stub**.

Тому можна було зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **вказував за допомогою symbolic link на інший Automator Application Stub усередині system**, і він виконував те, що міститься в `document.wflow` (ваш script), **не запускаючи Gatekeeper**, оскільки фактичний executable не має quarantine xattr.<sup>[[6]](#references)</sup>

Приклад очікуваного розташування: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Докладнішу інформацію дивіться у [**оригінальному звіті**](https://ronmasas.com/posts/bypass-macos-gatekeeper).

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

У цьому bypass zip file створювався з application, стискання якого починалося з `application.app/Contents`, а не з `application.app`. Тому **quarantine attr** застосовувався до всіх **files із `application.app/Contents`**, але **не до `application.app`**, який і перевіряв Gatekeeper. Отже, Gatekeeper обходився, оскільки під час запуску `application.app` він **не мав quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) для отримання додаткової інформації.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Навіть якщо компоненти відрізняються, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку ми створимо Apple Archive з **`application.app/Contents`**, тож **`application.app` не отримає атрибут quarantine** під час розпакування за допомогою **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) для отримання додаткової інформації.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** можна використовувати, щоб заборонити будь-кому записувати атрибут у файл:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Крім того, формат файлів **AppleDouble** копіює файл разом із його ACE.<sup>[[9]](#references)</sup>

У [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr із назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути застосунок у zip-файл у форматі **AppleDouble** з ACL, який забороняє записувати до нього інші xattr... xattr quarantine не буде встановлено у застосунку:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.

Зверніть увагу, що це також можна було експлуатувати за допомогою AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут quarantine** для завантажених файлів через певні внутрішні проблеми macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Формати файлів AppleDouble зберігають атрибути файлу в окремому файлі, назва якого починається з `._`; це допомагає копіювати атрибути файлів **між комп'ютерами macOS**. Однак було помічено, що після розпакування файлу AppleDouble файл, назва якого починається з `._`, **не отримував атрибут quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Можливість створити файл, якому не буде встановлено атрибут quarantine, **дозволяла обійти Gatekeeper.** Трюк полягав у тому, щоб **створити application у DMG-файлі** за допомогою угоди щодо іменування AppleDouble (почати ім’я з `._`) і створити **видимий файл як symlink на цей прихований** файл без атрибута quarantine.\
Коли **dmg-файл виконується**, оскільки він не має атрибута quarantine, він **обходить Gatekeeper**.
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

Обхід Gatekeeper, виправлений у macOS Sonoma 14.0, дозволяв спеціально створеним програмам запускатися без запиту. Подробиці були оприлюднені після випуску виправлення, а до цього проблему активно експлуатували in the wild. Переконайтеся, що встановлено Sonoma 14.0 або новішу версію.

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущеній у березні 2024 року), що виникав через обробку шкідливих ZIP-файлів бібліотекою `libarchive`, дозволяв програмам уникати перевірки. Оновіть систему до версії 14.4 або новішої, де Apple усунула цю проблему.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Workflow Automator Quick Action**, вбудований у завантажену програму, міг запускатися без перевірки Gatekeeper, оскільки workflow розглядалися як дані та виконувалися helper Automator поза звичайним шляхом показу запиту notarization. Таким чином, спеціально створений `.app`, що містив Quick Action для запуску shell script (наприклад, усередині `Contents/PlugIns/*.workflow/Contents/document.wflow`), міг виконуватися одразу після запуску. Apple додала додатковий діалог підтвердження та виправила шлях перевірки у Ventura **13.7**, Sonoma **14.7** і Sequoia **15**.<sup>[[3]](#references)</sup>

### Сторонні unarchiver, які неправильно передавали quarantine (2023–2024)

Кілька вразливостей у популярних інструментах розпакування (наприклад, The Unarchiver) спричиняли втрату файлами, витягнутими з архівів, `com.apple.quarantine` xattr, створюючи можливості для обходу Gatekeeper. Під час тестування завжди використовуйте macOS Archive Utility або виправлені інструменти та перевіряйте xattrs після розпакування.

### uchg (з цього [виступу](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Створіть директорію, що містить програму.
- Додайте uchg до програми.
- Стисніть програму у файл tar.gz.
- Надішліть файл tar.gz жертві.
- Жертва відкриває файл tar.gz і запускає програму.
- Gatekeeper не перевіряє програму.<sup>[[12]](#references)</sup>

### Запобігання quarantine xattr

Якщо до пакета ".app" не додано quarantine xattr, під час його виконання **Gatekeeper не буде запущено**.


## Посилання

- [1] [Apple Platform Security: про вміст безпеки macOS Sonoma 14.4 (містить CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: як macOS тепер відстежує походження програм](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: про вміст безпеки macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia усуває обхід Gatekeeper через Control‑click “Open”](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: виявлення CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, обхід macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs виявила вразливість Safari, що дозволяє обійти Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs виявила вразливість macOS Archive Utility, що дозволяє обійти Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: виявлення обходу Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Виявлення та повідомлення про exploit обходу Gatekeeper за допомогою Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: обхід механізмів безпеки та приватності macOS — від Gatekeeper до System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
