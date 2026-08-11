# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для операційних систем Mac, яка забезпечує, щоб користувачі **запускали у своїх системах лише довірене програмне забезпечення**. Вона працює шляхом **перевірки програмного забезпечення**, яке користувач завантажує та намагається відкрити з **джерел за межами App Store**, наприклад застосунку, plug-in або інсталяційного пакета.

Ключовим механізмом Gatekeeper є процес **верифікації**. Він перевіряє, чи **підписане завантажене програмне забезпечення визнаним розробником**, підтверджуючи його автентичність. Крім того, він визначає, чи **пройшло програмне забезпечення notarization від Apple**, підтверджуючи відсутність відомого шкідливого вмісту та змін після notarization.

Додатково Gatekeeper посилює контроль користувача та безпеку, **запитуючи дозвіл на відкриття** завантаженого програмного забезпечення під час першого запуску. Цей захист допомагає запобігти ненавмисному запуску потенційно небезпечного виконуваного коду, який користувач міг помилково прийняти за нешкідливий файл даних.

### Підписи застосунків

Підписи застосунків, також відомі як підписи коду, є важливим компонентом інфраструктури безпеки Apple. Вони використовуються для **перевірки особи автора програмного забезпечення** (розробника) і гарантування того, що код не було змінено після останнього підписання.

Ось як це працює:

1. **Підписання застосунку:** коли розробник готовий поширити свій застосунок, він **підписує застосунок за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** під час його реєстрації в Apple Developer Program. Процес підписання передбачає створення криптографічного хешу всіх частин застосунку та шифрування цього хешу приватним ключем розробника.
2. **Поширення застосунку:** після цього підписаний застосунок поширюється серед користувачів разом із сертифікатом розробника, який містить відповідний публічний ключ.
3. **Перевірка застосунку:** коли користувач завантажує застосунок і намагається його запустити, операційна система Mac використовує публічний ключ із сертифіката розробника для розшифрування хешу. Потім вона повторно обчислює хеш на основі поточного стану застосунку та порівнює його з розшифрованим хешем. Якщо вони збігаються, це означає, що **застосунок не було змінено** після його підписання розробником, і система дозволяє йому запуститися.

Підписи застосунків є важливою частиною технології Apple Gatekeeper. Коли користувач намагається **відкрити застосунок, завантажений з інтернету**, Gatekeeper перевіряє підпис застосунку. Якщо він підписаний сертифікатом, виданим Apple відомому розробнику, а код не було змінено, Gatekeeper дозволяє застосунку запуститися. В іншому випадку він блокує застосунок і попереджає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи пройшов застосунок notarization від Apple**, додаючи додатковий рівень безпеки. Процес notarization перевіряє застосунок на наявність відомих проблем безпеки та шкідливого коду, і якщо ці перевірки пройдено, Apple додає до застосунку ticket, який може перевірити Gatekeeper.

#### Перевірка підписів

Під час перевірки зразка **malware** завжди слід **перевіряти підпис**, оскільки **розробник**, який його підписав, може бути вже **пов’язаний** із **malware.**
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

Процес нотаризації Apple слугує додатковим захистом користувачів від потенційно шкідливого програмного забезпечення. Він передбачає **надсилання розробником свого застосунку на перевірку** до **Notary Service** Apple, яку не слід плутати з App Review. Цей сервіс є **автоматизованою системою**, яка перевіряє надіслане програмне забезпечення на наявність **шкідливого вмісту** та можливих проблем із code-signing.

Якщо програмне забезпечення **проходить** цю перевірку без зауважень, Notary Service генерує ticket нотаризації. Після цього розробник повинен **приєднати цей ticket до свого програмного забезпечення** — цей процес називається «stapling». Крім того, ticket нотаризації публікується онлайн, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першого встановлення або запуску програмного забезпечення користувачем наявність ticket нотаризації — незалежно від того, чи приєднаний він до виконуваного файлу, чи знайдений онлайн — **повідомляє Gatekeeper, що програмне забезпечення було нотаризоване Apple**. У результаті Gatekeeper відображає описове повідомлення в діалоговому вікні першого запуску, вказуючи, що Apple перевірила програмне забезпечення на наявність шкідливого вмісту. Таким чином цей процес підвищує довіру користувачів до безпеки програмного забезпечення, яке вони встановлюють або запускають у своїх системах.

### spctl & syspolicyd

> [!CAUTION]
> Зверніть увагу, що починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI-інструмент для переліку об'єктів і взаємодії з Gatekeeper (через daemon `syspolicyd` за допомогою XPC-повідомлень). Наприклад, статус **GateKeeper** можна переглянути за допомогою:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Зверніть увагу, що перевірки підпису GateKeeper виконуються лише для **файлів з атрибутом Quarantine**, а не для кожного файлу.

GateKeeper перевірить, чи можна виконати binary відповідно до **налаштувань і підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — основний daemon, відповідальний за забезпечення роботи Gatekeeper. Він підтримує database, розташовану в `/var/db/SystemPolicy`, і [тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) можна знайти code для підтримки [database](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), а [тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) — [SQL template](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що database не обмежена SIP і доступна для запису root, а database `/var/db/.SystemPolicy-default` використовується як оригінальна backup-копія на випадок пошкодження іншої database.

Крім того, bundles **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які вставляються в database. Перевірити цю database від імені root можна за допомогою:
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
**`syspolicyd`** також надає XPC-сервер із різними операціями, як-от `assess`, `update`, `record` і `cancel`, які також доступні через API **`Security.framework` `SecAssessment*`**, а **`spctl`** фактично взаємодіє з **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчувалося на "**App Store**", а друге — на "**Developer ID**", і що на попередньому зображенні було **дозволено виконання програм з App Store і від ідентифікованих розробників**.\
Якщо ви **зміните** це налаштування на App Store, правила "**Notarized Developer ID" зникнуть**.

Також існують тисячі правил **типу GKE** :
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
Параметри **`--master-disable`** і **`--global-disable`** утиліти **`spctl`** повністю **вимкнуть** ці перевірки підписів:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Після повного увімкнення з’явиться нова опція:

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
Щодо **kernel extensions**, папка `/var/db/SystemPolicyConfiguration` містить файли зі списками kexts, яким дозволено завантаження. Крім того, `spctl` має entitlement `com.apple.private.iokit.nvram-csr`, оскільки здатний додавати нові попередньо схвалені kernel extensions, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

#### Керування Gatekeeper у macOS 15 (Sequoia) та новіших версіях

- Тривалий час доступний обхід через Finder **Ctrl+Open / Right-click → Open** було видалено; після першого діалогового вікна блокування користувачі повинні явно дозволити заблокований застосунок через **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` більше не приймаються; `spctl` фактично доступний лише для читання під час оцінювання та керування мітками, тоді як застосування політики налаштовується через UI або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть перемикати політику Gatekeeper через `spctl`. Керування виконується через System Settings або шляхом розгортання профілю конфігурації MDM із payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, який дозволяє App Store та ідентифікованих розробників, але не "Anywhere":

<details>
<summary>Профіль MDM для дозволу App Store та ідентифікованих розробників</summary>
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

Під час **завантаження** програми або файлу певні macOS **програми**, наприклад веббраузери або поштові клієнти, **додають розширений атрибут файлу**, відомий як "**прапорець quarantine**", до завантаженого файлу. Цей атрибут виконує роль заходу безпеки, **позначаючи файл** як такий, що походить із ненадійного джерела (інтернету) і потенційно може становити ризик. Однак не всі програми додають цей атрибут; наприклад, поширене програмне забезпечення BitTorrent-клієнтів зазвичай обходить цей процес.

**Наявність прапорця quarantine повідомляє функцію безпеки Gatekeeper у macOS, коли користувач намагається виконати файл**.

Якщо **прапорець quarantine відсутній** (як у випадку з файлами, завантаженими через деякі BitTorrent-клієнти), **перевірки Gatekeeper можуть не виконуватися**. Тому користувачам слід бути обережними під час відкриття файлів, завантажених із менш захищених або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду є **ресурсомістким** процесом, який передбачає створення криптографічних **хешів** коду та всіх його вбудованих ресурсів. Крім того, перевірка дійсності сертифіката передбачає виконання **онлайн-перевірки** серверів Apple, щоб з'ясувати, чи не було його відкликано після видачі. З цих причин повну перевірку підпису коду та нотаризації **непрактично виконувати щоразу під час запуску програми**.
>
> Отже, ці перевірки **виконуються лише під час запуску програм з атрибутом quarantine**.

> [!WARNING]
> Цей атрибут **має бути встановлений програмою, яка створює або завантажує** файл.
>
> Однак для всіх файлів, які створюють sandboxed-програми, цей атрибут буде встановлено. А non sandboxed-програми можуть встановити його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**, що змусить систему встановлювати розширений атрибут `com.apple.quarantine` для створених файлів,

Крім того, усі файли, створені процесом, який викликає **`qtn_proc_apply_to_self`**, поміщаються в quarantine. А API **`qtn_file_apply_to_path`** додає атрибут quarantine до вказаного шляху файлу.

Можна **перевірити його стан і ввімкнути/вимкнути** (потрібні права root) за допомогою:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Також можна **перевірити, чи має файл розширений атрибут quarantine** за допомогою:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Насправді процес «може встановлювати quarantine flags для створених ним файлів» (я вже намагався застосувати прапорець USER_APPROVED до створеного файлу, але його не вдалося застосувати):

<details>

<summary>Вихідний код застосування quarantine flags</summary>
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
Інформація про quarantine також зберігається в центральній базі даних, якою керує LaunchServices, у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, що дає змогу GUI отримувати дані про походження файлів. Крім того, ці дані можуть бути перезаписані застосунками, які можуть бути зацікавлені у приховуванні свого походження. Це також можна зробити через LaunchServices APIS.

#### **libquarantine.dylib**

Ця бібліотека експортує кілька функцій, які дають змогу маніпулювати полями розширених атрибутів.

API `qtn_file_*` працюють із політиками quarantine для файлів, а API `qtn_proc_*` застосовуються до процесів (файлів, створених процесом). Нексспортовані функції `__qtn_syscall_quarantine*` застосовують політики, викликаючи `mac_syscall` із `"Quarantine"` як першим аргументом, що надсилає запити до `Quarantine.kext`.

#### **Quarantine.kext**

Розширення ядра доступне лише через **kernel cache у системі**; однак ви _можете завантажити **Kernel Debug Kit з** [**https://developer.apple.com/**](https://developer.apple.com/), який міститиме версію розширення із символами.

Цей Kext використовує через MACF hooks для перехоплення кількох викликів, щоб відстежувати всі події життєвого циклу файлів: створення, відкриття, перейменування, створення hard link... навіть `setxattr`, щоб запобігти встановленню розширеного атрибута `com.apple.quarantine`.

Він також використовує кілька MIB:

- `security.mac.qtn.sandbox_enforce`: застосовувати quarantine разом із Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs можуть виконувати лише схвалені файли

#### Provenance xattr (Ventura і новіші версії)

У macOS 13 Ventura було запроваджено окремий механізм provenance, який заповнюється під час першого дозволу на запуск застосунку з quarantine.<sup>[[2]](#references)</sup> Створюються два артефакти:

- xattr `com.apple.provenance` у каталозі `.app` bundle (двійкове значення фіксованого розміру, що містить primary key і flags).
- Рядок у таблиці `provenance_tracking` усередині бази даних ExecPolicy за адресою `/var/db/SystemPolicyConfiguration/ExecPolicy/`, де зберігаються cdhash застосунку та metadata.

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

XProtect — це вбудована функція **anti-malware** у macOS. XProtect **перевіряє кожну програму під час її першого запуску або після внесення змін за своєю базою даних** відомого malware і небезпечних типів файлів. Коли ви завантажуєте файл через певні програми, як-от Safari, Mail або Messages, XProtect автоматично сканує файл. Якщо він відповідає будь-якому відомому malware у базі даних, XProtect **не дозволить файлу запуститися** та попередить вас про загрозу.

База даних XProtect **регулярно оновлюється** компанією Apple новими визначеннями malware, а ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Це забезпечує постійну актуальність XProtect щодо останніх відомих загроз.

Однак варто зазначити, що **XProtect не є повнофункціональним антивірусним рішенням**. Він перевіряє лише певний перелік відомих загроз і не виконує сканування під час доступу, як більшість антивірусного програмного забезпечення.

Ви можете отримати інформацію про останнє оновлення XProtect, виконавши:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect розташований у захищеному SIP місці **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, а всередині bundle можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhash використовувати legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список plugins і extensions, яким заборонено завантажуватися за допомогою BundleID і TeamID, або які мають мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 із hashes заблокованих applications і TeamIDs.

Зверніть увагу, що існує ще один App у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов’язаний із XProtect, але він не бере участі в процесі Gatekeeper.

> XProtect Remediator: У сучасних версіях macOS Apple постачає on-demand scanners (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення malware families. Спостерігати за цими скануваннями можна в unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу, що Gatekeeper **не запускається щоразу**, коли ви запускаєте application; лише _**AppleMobileFileIntegrity**_ виконує **перевірку підписів executable code**, коли ви запускаєте app, який уже запускався та був перевірений Gatekeeper.

Тому раніше можна було запустити app, щоб кешувати його в Gatekeeper, потім **змінити файли application, які не є executables** (наприклад, Electron asar або NIB files), і, якщо не було інших protections, application **запускався** з **malicious** additions.

Однак тепер це неможливо, оскільки macOS **забороняє змінювати files** усередині application bundles. Тому, якщо ви спробуєте виконати атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви побачите, що тепер не можна нею зловживати, оскільки після запуску app для його кешування в Gatekeeper ви не зможете змінити bundle. А якщо ви, наприклад, зміните назву директорії Contents на NotCon (як зазначено в exploit), а потім запустите main binary app, щоб кешувати його в Gatekeeper, це спричинить помилку, і він не запуститься.

## Gatekeeper Bypasses

Будь-який спосіб обійти Gatekeeper (домогтися, щоб user завантажив щось і запустив це, коли Gatekeeper мав би заборонити запуск) вважається vulnerability у macOS. Нижче наведено деякі CVEs, призначені технікам, які в минулому дозволяли bypass Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що якщо для розпакування використовується **Archive Utility**, files із **paths довжиною понад 886 символів** не отримують extended attribute com.apple.quarantine. Ця ситуація ненавмисно дозволяє цим files **обійти** security checks Gatekeeper.<sup>[[5]](#references)</sup>

Перегляньте [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810), щоб отримати додаткову інформацію.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли application створюється за допомогою **Automator**, інформація про те, що йому потрібно виконати, міститься в `application.app/Contents/document.wflow`, а не у executable. Executable є лише generic Automator binary під назвою **Automator Application Stub**.

Тому можна було зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **вказував за допомогою symbolic link на інший Automator Application Stub у system**, і він виконав би вміст `document.wflow` (ваш script) **без запуску Gatekeeper**, оскільки фактичний executable не мав quarantine xattr.<sup>[[6]](#references)</sup>

Приклад очікуваного розташування: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Перегляньте [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper), щоб отримати додаткову інформацію.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

У цьому bypass zip file було створено так, щоб стиснення починалося з `application.app/Contents`, а не з `application.app`. Тому **quarantine attr** застосовувався до всіх **files із `application.app/Contents`**, але **не до `application.app`**, який перевіряв Gatekeeper. Отже, Gatekeeper було обійдено, оскільки під час запуску `application.app` **він не мав quarantine attribute.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) для отримання додаткової інформації.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Навіть якщо компоненти відрізняються, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку ми створимо Apple Archive з **`application.app/Contents`**, тому **`application.app` не отримає атрибут quarantine** під час розпакування за допомогою **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) для отримання додаткової інформації.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** можна використати, щоб заборонити будь-кому записувати атрибут у файл:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Крім того, формат файлів **AppleDouble** копіює файл разом із його ACE.<sup>[[9]](#references)</sup>

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути застосунок у zip-файл у форматі **AppleDouble** з ACL, який забороняє запис інших xattr до нього... quarantine xattr не було встановлено в застосунок:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.<sup>[[9]](#references)</sup>

Зверніть увагу, що це також можна було використати за допомогою AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут quarantine** для завантажених файлів через певні внутрішні проблеми macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble зберігає атрибути файлу в окремому файлі, ім’я якого починається з `._`; це допомагає копіювати атрибути файлів **між машинами macOS**. Однак після розпакування файлу AppleDouble файл, що починається з `._`, **не отримував атрибут quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Маючи можливість створити файл, якому не буде встановлено атрибут quarantine, було **можливо обійти Gatekeeper.** Трюк полягав у тому, щоб **створити application-файл DMG**, використовуючи угоду щодо імен AppleDouble (почати його з `._`), і створити **видимий файл як symlink на цей прихований** файл без атрибута quarantine.\
Коли **файл DMG виконується**, оскільки він не має атрибута quarantine, він **обходить Gatekeeper**.
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

Обхід Gatekeeper, виправлений у macOS Sonoma 14.0, дозволяв створеним спеціальним чином програмам запускатися без запиту. Подробиці були оприлюднені після випуску виправлення, а до цього проблему активно експлуатували в дикій природі. Переконайтеся, що встановлено Sonoma 14.0 або новішу версію.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущеній у березні 2024 року), спричинений обробкою шкідливих ZIP-файлів у `libarchive`, дозволяв програмам уникати перевірки. Оновіть систему до версії 14.4 або новішої, де Apple усунула цю проблему.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow**, вбудований у завантажену програму, міг запускатися без перевірки Gatekeeper, оскільки workflow розглядалися як дані, а виконувалися helper Automator поза звичайним шляхом запиту notarization. Тому створений спеціальним чином `.app` із Quick Action, який запускає shell script (наприклад, у `Contents/PlugIns/*.workflow/Contents/document.wflow`), міг виконуватися одразу під час запуску. Apple додала додаткове діалогове вікно згоди та виправила шлях перевірки у Ventura **13.7**, Sonoma **14.7** і Sequoia **15**.<sup>[[3]](#references)</sup>

### Сторонні unarchivers, які неправильно передавали quarantine (2023–2024)

Кілька вразливостей у популярних інструментах розпакування (наприклад, The Unarchiver) призводили до того, що файли, розпаковані з архівів, не отримували xattr `com.apple.quarantine`, створюючи можливості для обходу Gatekeeper. Під час тестування завжди використовуйте macOS Archive Utility або виправлені інструменти та перевіряйте xattr після розпакування.

### uchg (з цього [виступу](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Створіть директорію, що містить програму.
- Додайте uchg до програми.
- Стисніть програму у файл tar.gz.
- Надішліть файл tar.gz жертві.
- Жертва відкриває файл tar.gz і запускає програму.
- Gatekeeper не перевіряє програму.<sup>[[12]](#references)</sup>

### Запобігання xattr Quarantine

Якщо до bundle ".app" не додано xattr quarantine, під час його виконання **Gatekeeper не буде запущено**.

## References

- [1] [Apple Platform Security: Про вміст безпеки macOS Sonoma 14.4 (містить CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Як macOS тепер відстежує походження програм](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Про вміст безпеки macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia усуває обхід Gatekeeper через Control‑click “Open”](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Виявлення CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, обхід macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs виявила вразливість Safari, що дозволяє обійти Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs виявила вразливість macOS Archive Utility, що дозволяє обійти Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Виявлення обходу Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Пошук і повідомлення про exploit обходу Gatekeeper за допомогою Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Обхід механізмів безпеки та приватності macOS — від Gatekeeper до System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Про вміст безпеки macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
