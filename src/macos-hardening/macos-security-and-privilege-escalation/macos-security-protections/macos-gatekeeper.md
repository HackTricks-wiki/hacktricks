# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для Mac operating systems, призначена гарантувати, що користувачі **запускають лише довірене програмне забезпечення** на своїх системах. Вона працює шляхом **перевірки програмного забезпечення**, яке користувач завантажує і намагається відкрити з **джерел поза App Store**, таких як додаток, плагін або інсталяційний пакет.

Ключовий механізм Gatekeeper полягає в його процесі **верифікації**. Він перевіряє, чи завантажене програмне забезпечення **підписане визнаним розробником**, що підтверджує автентичність програмного забезпечення. Додатково, він встановлює, чи програмне забезпечення **нотаризоване Apple**, підтверджуючи, що воно не містить відомого шкідливого вмісту і не було змінене після нотаризації.

Крім того, Gatekeeper посилює контроль та безпеку користувача, **запитуючи дозволу на відкриття** завантаженого програмного забезпечення вперше. Цей захід допомагає запобігти випадковому запуску потенційно шкідливого виконуваного коду, який користувач міг прийняти за нешкідливий файл даних.

### Application Signatures

Підписи застосунків, також відомі як code signatures, є критичною складовою інфраструктури безпеки Apple. Вони використовуються для **підтвердження ідентичності автора програмного забезпечення** (розробника) і для забезпечення того, що код не був змінений з моменту його підписання.

Ось як це працює:

1. **Signing the Application:** Коли розробник готовий поширювати свій застосунок, він **підписує застосунок за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** при реєстрації в Apple Developer Program. Процес підписання включає створення криптографічного хешу всіх частин програми та шифрування цього хешу приватним ключем розробника.
2. **Distributing the Application:** Підписаний застосунок потім поширюється користувачам разом із сертифікатом розробника, який містить відповідний публічний ключ.
3. **Verifying the Application:** Коли користувач завантажує і намагається запустити застосунок, його Mac operating system використовує публічний ключ із сертифіката розробника для дешифрування хешу. Потім система повторно обчислює хеш на основі поточного стану застосунку і порівнює його з дешифрованим хешем. Якщо вони збігаються, це означає, що **застосунок не був змінений** з моменту підписання розробником, і система дозволяє його запуск.

Підписи застосунків — важлива частина технології Gatekeeper. Коли користувач намагається **відкрити застосунок, завантажений з інтернету**, Gatekeeper перевіряє підпис застосунку. Якщо він підписаний сертифікатом, виданим Apple відомому розробнику, і код не був змінений, Gatekeeper дозволяє запуск. Інакше — блокує застосунок і повідомляє користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи застосунок був notarized by Apple**, додаючи додатковий рівень безпеки. Процес нотаризації перевіряє застосунок на відомі проблеми безпеки та шкідливий код, і якщо перевірки пройдені, Apple додає ticket до застосунку, який Gatekeeper може верифікувати.

#### Check Signatures

Під час перевірки деякого **malware sample** ви завжди повинні **перевіряти підпис** файлу binary, оскільки **розробник**, який його підписав, може вже бути пов'язаний з **malware.**
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

Процес нотаризації Apple служить додатковим засобом захисту користувачів від потенційно шкідливого ПЗ. Він передбачає, що **розробник подає свій додаток на перевірку** до **Сервісу нотаризації Apple**, який не слід плутати з App Review. Цей сервіс є **автоматизованою системою**, яка вивчає подане програмне забезпечення на предмет **шкідливого вмісту** та можливих проблем із підписом коду.

Якщо програмне забезпечення **проходить** цю перевірку без зауважень, Сервіс нотаризації генерує нотаризаційний квиток. Тоді розробник повинен **додати цей квиток до свого ПЗ**, процес, відомий як 'stapling'. Крім того, нотаризаційний квиток публікується онлайн, де до нього може звернутися Gatekeeper — технологія безпеки Apple.

Під час першої інсталяції або запуску програмного забезпечення наявність нотаризаційного квитка — чи то прикріпленого до виконуваного файлу, чи доступного онлайн — **повідомляє Gatekeeper, що програмне забезпечення було нотаризоване Apple**. Внаслідок Gatekeeper показує описове повідомлення в діалозі першого запуску, що вказує, що програму перевіряла Apple на наявність шкідливого вмісту. Цей процес підвищує довіру користувачів до безпеки програм, які вони встановлюють або запускають на своїх системах.

### spctl & syspolicyd

> [!CAUTION]
> Зауважте, що починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI-утиліта для переліку та взаємодії з Gatekeeper (через демон `syspolicyd` за допомогою XPC-повідомлень). Наприклад, можна переглянути **стан** GateKeeper за допомогою:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Зверніть увагу, що перевірки підпису GateKeeper виконуються лише для **файлів з атрибутом Quarantine**, а не для всіх файлів.

GateKeeper перевіряє, чи може бінарний файл виконуватися відповідно до **preferences & the signature**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — це головний демон, відповідальний за застосування Gatekeeper. Він підтримує базу даних, розташовану в `/var/db/SystemPolicy`, і код для роботи з цією базою можна знайти [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), а [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зауважте, що база даних не обмежена SIP і доступна для запису користувачем root, а база `/var/db/.SystemPolicy-default` використовується як оригінальна резервна копія на випадок пошкодження основної.

Крім того, бандли **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які вставляються у базу даних. Ви можете перевірити цю базу даних під root за допомогою:
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
**`syspolicyd`** також відкриває XPC-сервер із різними операціями, такими як `assess`, `update`, `record` та `cancel`, до яких також можна звертатися через **`Security.framework`'s `SecAssessment*`** API, а **`spctl`** фактично спілкується з **`syspolicyd`** через XPC.

Зверніть увагу, як перше правило закінчувалося на "**App Store**", а друге — на "**Developer ID**", і що на попередньому зображенні було **було дозволено запускати додатки з App Store та від ідентифікованих розробників**.\
Якщо ви **зміните** цей параметр на App Store, то "**Notarized Developer ID" правила зникнуть**.

Також є тисячі правил **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Наведені hashes з:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Або ви можете перелічити попередню інформацію за допомогою:
```bash
sudo spctl --list
```
Опції **`--master-disable`** та **`--global-disable`** у **`spctl`** повністю **відключають** ці перевірки підписів:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Коли вона повністю увімкнена, з'явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Можна **перевірити, чи GateKeeper дозволить App** за допомогою:
```bash
spctl --assess -v /Applications/App.app
```
Можна додати нові правила в GateKeeper, щоб дозволити виконання певних додатків за допомогою:
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
Щодо **розширень ядра**, папка `/var/db/SystemPolicyConfiguration` містить файли зі списками kexts, які дозволено завантажувати. Крім того, `spctl` має entitlement `com.apple.private.iokit.nvram-csr`, оскільки він здатний додавати нові попередньо затверджені розширення ядра, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

#### Керування Gatekeeper у macOS 15 (Sequoia) та пізніших версіях

- Довготривалий обхід Finder **Ctrl+Open / Right‑click → Open** видалено; користувачі мають явним чином дозволяти заблокований додаток через **System Settings → Privacy & Security → Open Anyway** після першого діалогу про блокування.
- `spctl --master-disable/--global-disable` більше не приймаються; `spctl` фактично доступний лише для читання для оцінки та управління мітками, тоді як застосування політики конфігурується через UI або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть переключати політику Gatekeeper через `spctl`. Управління здійснюється через System Settings або шляхом розгортання MDM configuration profile з payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, щоб дозволити App Store та identified developers (але не "Anywhere"):

<details>
<summary>MDM профіль для дозволу App Store та identified developers</summary>
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

### Карантин файлів

Під час **завантаження** додатка або файлу окремі macOS **додатки**, такі як веб-браузери чи поштові клієнти, **додають розширений атрибут файлу**, відомий як "**quarantine flag**", до завантаженого файлу. Цей атрибут слугує заходом безпеки, щоб **позначити файл** як такий, що походить з ненадійного джерела (інтернет) і потенційно несе ризики. Однак не всі додатки додають цей атрибут — наприклад, поширені клієнти BitTorrent зазвичай обходять цей процес.

**Наявність quarantine flag сповіщає функцію безпеки Gatekeeper macOS під час спроби користувача виконати файл.**

Якщо **quarantine flag відсутній** (як у файлів, завантажених через деякі клієнти BitTorrent), перевірки Gatekeeper можуть **не виконуватися**. Тому користувачам слід бути обережними при відкритті файлів, завантажених із менш безпечних або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду — це **ресурсоємний** процес, який включає генерування криптографічних **хешів** коду та всіх його вкладених ресурсів. Крім того, перевірка дійсності сертифіката передбачає **онлайн-перевірку** на серверах Apple, щоб з’ясувати, чи не було його відкликано після видачі. Через це повна перевірка підпису коду та нотаризації **непрактична для виконання щоразу при запуску додатку**.
>
> Тому ці перевірки **виконуються лише при запуску додатків з карантинним атрибутом.**

> [!WARNING]
> Цей атрибут має бути **встановлений додатком, що створює/завантажує** файл.
>
> Однак файли, що є sandboxed, матимуть цей атрибут встановленим для кожного створеного ними файлу. А non sandboxed apps можуть встановити його самі або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**, що змусить систему встановлювати розширений атрибут `com.apple.quarantine` на створені файли,

Крім того, усі файли, створені процесом, який викликає **`qtn_proc_apply_to_self`**, підлягають карантину. Або API **`qtn_file_apply_to_path`** додає карантинний атрибут до вказаного шляху файлу.

Можна **перевірити його стан та увімкнути/вимкнути** (потрібні права root) за допомогою:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ви також можете **перевірити, чи файл має розширений атрибут quarantine** за допомогою:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Перевірте **значення** **розширених** **атрибутів** і дізнайтеся, який додаток записав quarantine-атрибут за допомогою:
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
Насправді процес "міг встановлювати quarantine flags для файлів, які він створює" (я вже пробував застосувати прапорець USER_APPROVED до створеного файлу, але він не застосовується):

<details>

<summary>Вихідний код: застосування quarantine flags</summary>
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
І знайти всі карантиновані файли за допомогою:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

Ця бібліотека експортує кілька функцій, що дозволяють маніпулювати полями розширених атрибутів.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura introduced a separate provenance mechanism which is populated the first time a quarantined app is allowed to run. Two artefacts are created:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect — вбудована функція **anti-malware** в macOS. XProtect **перевіряє будь-який додаток при його першому запуску або при зміні, порівнюючи з базою даних** відомих malware і небезпечних типів файлів. Коли ви завантажуєте файл через певні додатки, такі як Safari, Mail або Messages, XProtect автоматично сканує файл. Якщо він відповідає будь-якому відомому malware у базі даних, XProtect **запобіжить виконанню файлу** та попередить вас про загрозу.

База даних XProtect **регулярно оновлюється** Apple новими визначеннями malware, і ці оновлення автоматично завантажуються й встановлюються на ваш Mac. Це гарантує, що XProtect завжди має актуальні дані про останні відомі загрози.

Однак варто зазначити, що **XProtect не є повнофункціональним антивірусним рішенням**. Він перевіряє лише конкретний список відомих загроз і не здійснює on-access сканування, як більшість антивірусних програм.

Ви можете отримати інформацію про останнє оновлення XProtect, запустивши:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect знаходиться в SIP-захищеному розташуванні **/Library/Apple/System/Library/CoreServices/XProtect.bundle** і всередині бандлу можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhashes використовувати legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список плагінів та розширень, які заборонено завантажувати за допомогою BundleID і TeamID або з вказанням мінімальної версії.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Правила Yara для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 база даних з хешами заблокованих додатків та TeamIDs.

Зауважте, що існує інший App у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов’язаний з XProtect, який не залучений у процес Gatekeeper.

> XProtect Remediator: На сучасних macOS Apple постачає сканери на вимогу (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення сімейств malware. Ви можете спостерігати ці сканування в unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зауважте, що Gatekeeper **не виконується щоразу**, коли ви запускаєте застосунок — лише _**AppleMobileFileIntegrity**_ (AMFI) буде **перевіряти підписи виконуваного коду** при запуску додатка, який вже був виконаний і перевірений Gatekeeper.

Тому раніше було можливо виконати застосунок, щоб кешувати його через Gatekeeper, а потім **змінити не-виконувані файли застосунку** (наприклад Electron asar або NIB файли) і, якщо не було інших захистів, застосунок буде **запущений** з **шкідливими** доповненнями.

Однак зараз це неможливо, бо macOS **запобігає модифікації файлів** всередині бандлів застосунків. Тому, якщо ви спробуєте атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви виявите, що її більше неможливо використовувати: після виконання застосунку для кешування через Gatekeeper ви не зможете змінити бандл. І якщо, наприклад, ви перейменуєте папку Contents на NotCon (як вказано в експлоїті), а потім виконаєте головний бінар застосунку для кешування через Gatekeeper, це викличе помилку і застосунок не запуститься.

## Обходи Gatekeeper

Будь-який спосіб обійти Gatekeeper (змусити користувача завантажити щось і виконати це в той момент, коли Gatekeeper мав би заборонити запуск) вважається вразливістю в macOS. Нижче наведені деякі CVE, присвоєні технікам, які дозволяли обходити Gatekeeper у минулому:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що якщо для розпакування використовується **Archive Utility**, файли з **шляхами, що перевищують 886 символів**, не отримують розширений атрибут com.apple.quarantine. Це випадково дозволяло цим файлам **обійти перевірки Gatekeeper**.

Детальніше див. [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли застосунок створюється за допомогою **Automator**, інформація про те, що потрібно для його виконання, знаходиться в `application.app/Contents/document.wflow`, а не в виконуваному файлі. Виконуваний файл — це просто універсальний Automator binary під назвою **Automator Application Stub**.

Отже, можна було зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **вказував символічним посиланням на інший Automator Application Stub у системі**, і тоді виконувалось те, що в `document.wflow` (ваш скрипт) **без спрацювання Gatekeeper**, бо фактичний виконуваний файл не мав quarantine xattr.

Очікуване розташування прикладу: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Детальніше див. [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper).

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

У цьому обході zip-файл було створено так, що архівація застосунку починалась з `application.app/Contents` замість `application.app`. Внаслідок цього **атрибут quarantine** було застосовано до всіх **файлів з `application.app/Contents`**, але **не до `application.app`**, який саме перевіряв Gatekeeper, тож Gatekeeper було обійдено, оскільки при запуску `application.app` він **не мав атрибуту quarantine.**
```bash
zip -r test.app/Contents test.zip
```
Перегляньте [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) для додаткової інформації.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Навіть якщо компоненти відрізняються, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку буде створено Apple Archive з **`application.app/Contents`**, тому **`application.app` won't get the quarantine attr** при розпакуванні за допомогою **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Перегляньте [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) для отримання додаткової інформації.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** може використовуватися, щоб заборонити будь-кому записувати атрибут у файл:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Крім того, формат файлу **AppleDouble** копіює файл разом із його ACEs.

У [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) видно, що текстове представлення ACL, збережене в xattr під назвою **`com.apple.acl.text`**, буде встановлене як ACL у розпакованому файлі. Отже, якщо ви запакували додаток у zip-файл у форматі **AppleDouble** з ACL, яка забороняє запис інших xattr... the quarantine xattr не було встановлено в додатку:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Перегляньте [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.

Зверніть увагу, що це також можна експлуатувати за допомогою AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут карантину** для завантажених файлів через деякі внутрішні проблеми macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble зберігає атрибути файлу в окремому файлі, що починається з `._`; це допомагає копіювати атрибути файлів **між машинами macOS**. Однак було помічено, що після розпакування AppleDouble-файлу файл, що починається з `._`, **не отримував атрибут карантину**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Можливість створити файл, у якого не встановлено атрибут карантину, робила **можливим обійти Gatekeeper.** Хитрість полягала у тому, щоб **створити a DMG file application** використовуючи конвенцію імен AppleDouble (почати з `._`) та створити **видимий файл як sym link до цього прихованого** файлу без атрибута карантину.\
Коли **dmg file is executed**, оскільки він не має атрибута карантину, він **bypass Gatekeeper**.
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

Обхід Gatekeeper, виправлений у macOS Sonoma 14.0, дозволяв спеціально створеним додаткам запускатися без запиту підтвердження. Деталі були оприлюднені після виправлення, і проблему активно експлуатували у реальному світі до виправлення. Переконайтесь, що встановлено Sonoma 14.0 або новішу версію.

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущена в березні 2024) через обробку зловмисних ZIP-архів `libarchive` дозволяв додаткам уникати перевірки. Оновіть до 14.4 або новішої версії, де Apple вирішила цю проблему.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Вбудований у завантажений додаток **Automator Quick Action workflow** міг спрацювати без оцінки Gatekeeper, оскільки workflows трактувалися як дані і виконувалися помічником Automator поза звичайним шляхом показу нотаризаційного запиту. Зловмисне `.app`, яке містить Quick Action, що виконує shell-скрипт (наприклад, всередині `Contents/PlugIns/*.workflow/Contents/document.wflow`), могло тому виконатися одразу при запуску. Apple додала додатковий діалог згоди та виправила шлях оцінки у Ventura **13.7**, Sonoma **14.7** і Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Кілька вразливостей у популярних інструментах для розпакування (наприклад, The Unarchiver) призводили до того, що файли, витягнуті з архівів, втрачали атрибут `com.apple.quarantine`, що відкривало можливості для обходу Gatekeeper. Завжди покладайтеся на macOS Archive Utility або виправлені інструменти під час тестування та перевіряйте xattr після розпакування.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Створіть каталог, що містить додаток.
- Додайте uchg до додатка.
- Стисніть додаток у tar.gz файл.
- Надішліть tar.gz файл жертві.
- Жертва відкриває tar.gz файл і запускає додаток.
- Gatekeeper не перевіряє додаток.

### Prevent Quarantine xattr

У бандлі ".app", якщо quarantine xattr не додано до нього, при виконанні **Gatekeeper не буде спрацьовувати**.


## Посилання

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
