# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для операційних систем Mac, яка має забезпечити, щоб користувачі **запускали у своїх системах лише довірене програмне забезпечення**. Вона перевіряє програмне забезпечення, яке користувач завантажує та намагається відкрити з **джерел поза App Store**, зокрема програми, плагіни або пакети інсталятора.

Ключовий механізм Gatekeeper — це процес **перевірки**. Він перевіряє, чи **підписане завантажене програмне забезпечення визнаним розробником**, щоб підтвердити його автентичність. Крім того, він з’ясовує, чи **пройшло програмне забезпечення нотаризацію Apple**, що підтверджує відсутність у ньому відомого шкідливого вмісту та того, що його не було змінено після нотаризації.

Також Gatekeeper посилює контроль користувачів і безпеку, **запитуючи дозвіл на перше відкриття** завантаженого програмного забезпечення. Цей захист допомагає запобігти випадковому запуску потенційно шкідливого виконуваного коду, який користувачі могли помилково сприйняти як нешкідливий файл даних.

### Підписи програм

Підписи програм, також відомі як підписи коду, є критично важливим компонентом інфраструктури безпеки Apple. Їх використовують, щоб **перевірити особу автора програмного забезпечення** (розробника) та переконатися, що код не було змінено після останнього підписання.

Ось як це працює:

1. **Підписання програми:** Коли розробник готовий поширювати програму, він **підписує її за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** після його реєстрації в Apple Developer Program. Під час підписання створюється криптографічний хеш усіх частин програми, а потім цей хеш шифрується приватним ключем розробника.
2. **Поширення програми:** Підписана програма поширюється серед користувачів разом із сертифікатом розробника, який містить відповідний відкритий ключ.
3. **Перевірка програми:** Коли користувач завантажує програму та намагається її запустити, операційна система Mac використовує відкритий ключ із сертифіката розробника, щоб розшифрувати хеш. Потім вона повторно обчислює хеш на основі поточного стану програми та порівнює його з розшифрованим хешем. Якщо вони збігаються, це означає, що **програму не було змінено** після її підписання розробником, і система дозволяє її запуск.

Підписи програм є важливою частиною технології Gatekeeper від Apple. Коли користувач намагається **відкрити програму, завантажену з інтернету**, Gatekeeper перевіряє її підпис. Якщо вона підписана сертифікатом, виданим Apple відомому розробнику, і код не було змінено, Gatekeeper дозволяє запустити програму. В іншому разі він блокує її та сповіщає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи пройшла програма нотаризацію Apple**, додаючи ще один рівень безпеки. Під час нотаризації програма перевіряється на наявність відомих проблем безпеки та шкідливого коду. Якщо ці перевірки пройдено, Apple додає до програми квиток, який може перевірити Gatekeeper.

#### Перевірка підписів

Перевіряючи **зразок malware**, завжди слід **перевіряти підпис** бінарного файла, оскільки **розробник**, який його підписав, може бути вже **пов’язаний** зі **шкідливим ПЗ**.

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

Процес нотаризації Apple — це додатковий захист користувачів від потенційно шкідливого програмного забезпечення. Він передбачає **надсилання розробником своєї програми на перевірку** до **Notary Service компанії Apple**. Цю службу не слід плутати з App Review. Це **автоматизована система**, яка перевіряє надіслане програмне забезпечення на наявність **шкідливого вмісту** та потенційних проблем із підписуванням коду.

Якщо програмне забезпечення **успішно проходить** цю перевірку, Notary Service створює квиток нотаризації. Розробник має **додати цей квиток до свого програмного забезпечення** — цей процес називається «stapling». Крім того, квиток нотаризації публікується в інтернеті, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першого встановлення або запуску програмного забезпечення користувачем наявність квитка нотаризації — доданого до виконуваного файла або знайденого в інтернеті — **повідомляє Gatekeeper, що Apple нотаризувала це програмне забезпечення**. У результаті Gatekeeper показує в діалоговому вікні першого запуску пояснювальне повідомлення про те, що Apple перевірила програмне забезпечення на наявність шкідливого вмісту. Це підвищує довіру користувачів до безпеки програмного забезпечення, яке вони встановлюють або запускають у своїх системах.

### spctl і syspolicyd

> [!CAUTION]
> Зверніть увагу: починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI-інструмент для перегляду Gatekeeper і взаємодії з ним (через XPC-повідомлення з демоном `syspolicyd`). Наприклад, за допомогою нього можна переглянути **стан** Gatekeeper:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Зверніть увагу: GateKeeper перевіряє підписи лише **файлів з атрибутом Quarantine**, а не кожного файлу.

GateKeeper перевірить, чи можна виконати бінарний файл відповідно до **налаштувань і підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — основний daemon, відповідальний за забезпечення роботи Gatekeeper. Він підтримує базу даних у `/var/db/SystemPolicy`. Код для роботи з [базою даних доступний тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), а [шаблон SQL — тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що на базу даних не поширюється SIP; її може змінювати root. База даних `/var/db/.SystemPolicy-default` використовується як резервна копія оригіналу на випадок пошкодження основної.

Крім того, пакети **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які додаються до бази даних. Переглянути цю базу даних від імені root можна за допомогою:

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

**`syspolicyd`** також надає XPC-сервер із різними операціями, як-от `assess`, `update`, `record` і `cancel`, які також доступні через API **`SecAssessment*`** із **`Security.framework`**, а **`spctl`** фактично взаємодіє з **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчувалося на "**App Store**", а друге — на "**Developer ID**", і на попередньому зображенні було **дозволено запускати програми з App Store і від ідентифікованих розробників**.\
Якщо **змінити** цей параметр на App Store, правила "**Notarized Developer ID" зникнуть**.

Існують також тисячі правил **типу GKE**:

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

Параметри **`--master-disable`** і **`--global-disable`** утиліти **`spctl`** повністю **вимикають** ці перевірки підписів:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Коли його повністю ввімкнено, з’явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Перевірити, чи дозволить GateKeeper запуск App, можна за допомогою:

```bash
spctl --assess -v /Applications/App.app
```

У macOS 14 і новіших версіях **`syspolicy_check`** — корисний інструмент для перевірки пакета програми перед розповсюдженням на вищому рівні. Він надає практичнішу діагностику довіреного виконання, ніж звичайний результат `spctl`, хоча Apple все одно рекомендує перевіряти реальний шлях завантаження, розпакування та першого запуску, оскільки це також дає змогу перевірити поширення атрибута quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

Можна додавати нові правила до GateKeeper, щоб дозволити запуск певних програм за допомогою:

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

Щодо **розширень ядра**, у папці `/var/db/SystemPolicyConfiguration` містяться файли зі списками kexts, завантаження яких дозволено. Крім того, `spctl` має entitlement `com.apple.private.iokit.nvram-csr`, оскільки може додавати нові попередньо схвалені розширення ядра, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

#### Керування Gatekeeper у macOS 15 (Sequoia) і новіших версіях

- Давній спосіб обходу через Finder **Ctrl+Open / клацання правою кнопкою миші → Open** видалено; після першого діалогового вікна блокування користувачі мають явно дозволити заблоковану програму в меню **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` більше не приймаються як зміни політики без нагляду. Операції зі зміни бази правил або глобального стану оцінювання вважаються застарілими, тому використовуйте `spctl` для оцінювання, а застосування політики налаштовуйте через інтерфейс або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть перемикати політику Gatekeeper через `spctl`. Керування здійснюється через System Settings або розгортанням профілю конфігурації MDM із payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, який дозволяє App Store і програми від ідентифікованих розробників (але не «Anywhere»):

<details>
<summary>Профіль MDM для дозволу App Store і програм від ідентифікованих розробників</summary>

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

### Файли в карантині

Після **завантаження** програми або файлу деякі **програми** macOS, наприклад веббраузери чи поштові клієнти, **додають до завантаженого файлу розширений атрибут файлу**, який зазвичай називають «**прапорцем карантину**». Цей атрибут є засобом безпеки, що **позначає файл** як отриманий із ненадійного джерела (інтернету) та такий, що може становити ризик. Однак не всі програми додають цей атрибут; наприклад, поширені клієнти BitTorrent зазвичай оминають цей процес.

**Наявність прапорця карантину сповіщає функцію безпеки Gatekeeper у macOS, коли користувач намагається запустити файл**.

Якщо **прапорець карантину відсутній** (як у файлів, завантажених за допомогою деяких клієнтів BitTorrent), перевірки Gatekeeper **можуть не виконуватися**. Тому користувачам слід бути обережними, відкриваючи файли, завантажені з менш безпечних або невідомих джерел.

> [!NOTE] > **Перевірка** **чинності** підписів коду — це ресурсомісткий процес, який передбачає створення криптографічних **хешів** коду та всіх ресурсів у його пакеті. Крім того, перевірка чинності сертифіката передбачає **онлайн-перевірку** на серверах Apple, щоб з’ясувати, чи не було його відкликано після видачі. З цих причин повну перевірку підпису коду та нотаризації **недоцільно виконувати щоразу під час запуску програми**.
>
> Тому ці перевірки виконуються **лише під час запуску програм з атрибутом карантину**.

> [!WARNING]
> Цей атрибут має **встановлювати програма, яка створює/завантажує** файл.
>
> Однак файли, що працюють у sandbox, матимуть цей атрибут для кожного створеного ними файлу. А програми, що не працюють у sandbox, можуть встановити його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**; тоді система встановлюватиме розширений атрибут `com.apple.quarantine` для створених файлів.

Крім того, усі файли, створені процесом, який викликає **`qtn_proc_apply_to_self`**, поміщаються в карантин. А API **`qtn_file_apply_to_path`** додає атрибут карантину до вказаного шляху до файлу.

Перевірити стан і ввімкнути/вимкнути це (потрібен root) можна так:

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

Перевірте **значення** **розширених** **атрибутів** і з’ясуйте, яка програма записала атрибут quarantine за допомогою:

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

Насправді процес «could set quarantine flags to the files it creates» (я вже пробував застосувати прапорець USER_APPROVED до створеного файлу, але його не вдається застосувати):

<details>

<summary>Вихідний код застосування прапорців quarantine</summary>

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

І знайдіть усі файли в карантині за допомогою:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

Інформація про карантин також зберігається в центральній базі даних, якою керує LaunchServices, у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**. Це дає графічному інтерфейсу змогу отримувати дані про походження файлів. Крім того, застосунки, зацікавлені в приховуванні походження файлів, можуть перезаписати ці дані. Це також можна зробити за допомогою API LaunchServices.

#### **libquarantine.dylib**

Ця бібліотека експортує кілька функцій для роботи з полями розширених атрибутів.

API `qtn_file_*` відповідають за політики карантину файлів, а API `qtn_proc_*` застосовуються до процесів (файлів, створених процесом). Неекспортовані функції `__qtn_syscall_quarantine*` застосовують політики: вони викликають `mac_syscall` із першим аргументом "Quarantine", який надсилає запити до `Quarantine.kext`.

#### **Quarantine.kext**

Це kernel extension доступне лише через **kernel cache у системі**; однак ви _можете_ завантажити **Kernel Debug Kit із** [**https://developer.apple.com/**](https://developer.apple.com/), який містить версію extension із символами.

Цей Kext використовує MACF для перехоплення кількох викликів, аби відстежувати всі події життєвого циклу файлів: створення, відкриття, перейменування, створення hard link тощо — навіть `setxattr`, щоб не дозволити встановити розширений атрибут `com.apple.quarantine`.

Також він використовує кілька MIB:

- `security.mac.qtn.sandbox_enforce`: застосовувати карантин разом із Sandbox
- `security.mac.qtn.user_approved_exec`: процеси в карантині можуть виконувати лише схвалені файли

#### Розширений атрибут Provenance (Ventura і новіші версії)

У macOS 13 Ventura було запроваджено окремий механізм provenance, який заповнюється під час першого дозволеного запуску застосунку в карантині.<sup>[[2]](#references)</sup> Створюються два артефакти:

- Розширений атрибут `com.apple.provenance` у каталозі пакета `.app` (бінарне значення фіксованого розміру, що містить primary key і прапорці).
- Рядок у таблиці `provenance_tracking` у базі даних ExecPolicy за адресою `/var/db/SystemPolicyConfiguration/ExecPolicy/`, де зберігаються cdhash застосунку та метадані.

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

XProtect — це вбудована в macOS функція **захисту від шкідливого програмного забезпечення**. XProtect **перевіряє кожну програму під час першого запуску або після зміни, звіряючи її зі своєю базою даних** відомого шкідливого програмного забезпечення та небезпечних типів файлів. Коли ви завантажуєте файл за допомогою певних програм, як-от Safari, Mail або Messages, XProtect автоматично сканує його. Якщо файл збігається з будь-яким відомим шкідливим програмним забезпеченням у базі даних, XProtect **не дозволить запустити файл** і попередить вас про загрозу.

Apple **регулярно оновлює** базу даних XProtect, додаючи нові сигнатури шкідливого програмного забезпечення. Ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Завдяки цьому XProtect завжди має актуальну інформацію про найновіші відомі загрози.

Однак варто зазначити, що **XProtect — це не повноцінне антивірусне рішення**. Він перевіряє лише певний перелік відомих загроз і, на відміну від більшості антивірусних програм, не виконує сканування під час доступу до файлів.

Дізнатися про останнє оновлення XProtect можна, виконавши:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect розташований у захищеному SIP каталозі **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, а всередині пакета можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhash використовувати застарілі entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список плагінів і розширень, завантаження яких заборонено за BundleID і TeamID, або для яких указано мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Правила Yara для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 із хешами заблокованих застосунків і TeamID.

Зверніть увагу, що є ще один застосунок у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов’язаний із XProtect, але він не бере участі в процесі Gatekeeper.

> XProtect Remediator: У сучасних версіях macOS Apple постачає сканери на вимогу (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення сімейств malware. Ці сканування можна спостерігати в уніфікованих журналах:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу, що Gatekeeper **не запускається щоразу**, коли ви запускаєте програму: лише _**AppleMobileFileIntegrity**_ (AMFI) **перевіряє підписи виконуваного коду**, коли ви запускаєте програму, яку Gatekeeper уже запускав і перевіряв.

Тому раніше можна було запустити програму, щоб Gatekeeper кешував її, а потім **змінити файли програми, які не є виконуваними** (наприклад, Electron asar або файли NIB), і, якщо не було інших засобів захисту, програму **запускали** з **шкідливими** доповненнями.

Однак тепер це неможливо, оскільки macOS **не дозволяє змінювати файли** всередині пакетів програм. Тож якщо спробувати атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви побачите, що тепер її не можна використати: після запуску програми, щоб Gatekeeper кешував її, ви не зможете змінити пакет. А якщо, наприклад, змінити назву каталогу Contents на NotCon (як зазначено в експлойті), а потім запустити головний бінарний файл програми, щоб Gatekeeper кешував її, виникне помилка, і програма не запуститься.

## Обходи Gatekeeper

Будь-який спосіб обійти Gatekeeper (змусити користувача завантажити щось і запустити це, коли Gatekeeper має заборонити запуск) вважається вразливістю macOS. Нижче наведено деякі CVE, присвоєні технікам, які в минулому дозволяли обходити Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що якщо для розпакування використовується **Archive Utility**, файли з **шляхами довжиною понад 886 символів** не отримують розширеного атрибута com.apple.quarantine. Через це такі файли ненавмисно можуть **обходити** перевірки безпеки Gatekeeper.<sup>[[5]](#references)</sup>

Докладніше див. [**оригінальний звіт**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли програму створено за допомогою **Automator**, інформація про те, що саме потрібно виконати, міститься у `application.app/Contents/document.wflow`, а не у виконуваному файлі. Виконуваний файл — це лише типовий бінарний файл Automator під назвою **Automator Application Stub**.

Тому можна було зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **посилався символічним посиланням на інший Automator Application Stub у системі**, і він виконував би вміст `document.wflow` (ваш скрипт) **без запуску Gatekeeper**, оскільки фактичний виконуваний файл не мав xattr quarantine.<sup>[[6]](#references)</sup>

Приклад очікуваного розташування: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Докладніше див. [**оригінальний звіт**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Для цього обходу створили zip-файл, у якому стиснення програми починалося з `application.app/Contents`, а не з `application.app`. Тому атрибут **quarantine** застосовувався до всіх **файлів у `application.app/Contents`**, але **не до `application.app`**, який перевіряв Gatekeeper. Отже, Gatekeeper вдавалося обійти, оскільки під час запуску `application.app` **в нього не було атрибута quarantine.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) для отримання додаткової інформації.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Хоча компоненти відрізняються, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку ми створимо Apple Archive з **`application.app/Contents`**, щоб **`application.app`** не отримав атрибут quarantine під час розпакування за допомогою **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/), щоб дізнатися більше.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** можна використати, щоб заборонити будь-кому записувати атрибут у файл:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Для механізму `com.apple.acl.text`/AppleDouble та повного відтворення sidecar див. [відтворення обходу карантину AppleDouble ACL](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). У варіанті ZIP для застосунків Gatekeeper використовується така послідовність:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/), щоб дізнатися більше.<sup>[[9]](#references)</sup>

Зауважте, що цю вразливість також можна було експлуатувати за допомогою AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут карантину** для завантажених файлів через деякі внутрішні проблеми macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble зберігає атрибути файлу в окремому файлі, ім’я якого починається з `._`; це дає змогу копіювати атрибути файлів **між комп’ютерами macOS**. Однак після розпакування файлу AppleDouble файлу, що починається з `._`, **не призначався атрибут карантину**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Маючи змогу створити файл, якому не буде призначено атрибут quarantine, **можна було обійти Gatekeeper.** Для цього потрібно було **створити файл застосунку DMG**, використовуючи домовленість щодо імен AppleDouble (почати назву з `._`), а також створити **видимий файл як символьне посилання на цей прихований** файл без атрибута quarantine.\
Коли **файл DMG запускається**, він не має атрибута quarantine, тож **обходить Gatekeeper**.

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

Apple виправила логічну помилку LaunchServices у macOS Sonoma 14.0 за допомогою покращених перевірок. У публічному повідомленні лише зазначено, що програма могла обійти Gatekeeper, тому не слід робити висновки про конкретний формат носія чи ланцюжок експлуатації лише на підставі запису CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущеній у березні 2024 року), спричинений обробкою зловмисних ZIP-файлів у `libarchive`, давав змогу програмам уникати перевірки. Оновіть систему до версії 14.4 або новішої, у якій Apple усунула цю проблему.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow**, вбудований у завантажену програму, міг запускатися без перевірки Gatekeeper, оскільки workflow вважалися даними, а Automator helper виконував їх поза звичайним шляхом запиту на нотаризацію. Тому спеціально створений `.app`, що містив Quick Action для запуску shell script (наприклад, у `Contents/PlugIns/*.workflow/Contents/document.wflow`), міг виконатися одразу після запуску. Apple додала додаткове діалогове вікно підтвердження та виправила шлях перевірки у Ventura **13.7**, Sonoma **14.7** і Sequoia **15**.<sup>[[3]](#references)</sup>

### Збої передавання карантину під час розпакування та копіювання

Дослідження 2024 року виявило прогалини в передаванні карантину в протестованих версіях iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) і 7z Utility (DMG/ZIP/7Z); також було зафіксовано втрату атрибута під час копіювання з хоста на гостьову систему через VMware Tools. Згодом кілька постачальників оголосили про виправлення, тож сприймайте ці назви як орієнтири для **повторного тестування конкретних версій**, а не як постійний перелік вразливого ПЗ. Та сама проблема меж довіри стосується і звичайних Unix workflow: `curl`/`scp` не додають атрибут карантину, а `tar`/`unzip` із командного рядка не успадковують його автоматично від архіву-носія.<sup>[[15]](#references)</sup>

Під час тестування на проникнення порівнюйте архів-носій і кінцеву програму після **кожного** переходу через браузер, поштовий клієнт, архіватор, образ диска, хмарну синхронізацію, спільну папку та копіювання між VM. Явна відмова `spctl` не виправляє відсутній xattr: без атрибута карантину під час першого відкриття звичайний шлях Gatekeeper може взагалі не запросити таку перевірку.<sup>[[15]](#references)</sup>

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

- Створіть каталог, що містить app.
- Додайте uchg до app.
- Стисніть app у файл tar.gz.
- Надішліть файл tar.gz жертві.
- Жертва відкриває файл tar.gz і запускає app.
- Gatekeeper не перевіряє app.<sup>[[12]](#references)</sup>

### Запобігання Quarantine xattr

Якщо до пакета ".app" не додано quarantine xattr, під час його запуску **Gatekeeper не спрацює**.

Див. [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks), щоб ознайомитися з примітивами на основі файлової системи, прапорців, ACL та AppleDouble, які можуть запобігти додаванню або видалити extended attributes.





## References

- [1] [Apple Platform Security: Про вміст оновлення безпеки macOS Sonoma 14.4 (включно з CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Як macOS тепер відстежує походження app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Про вміст оновлень безпеки macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia усуває обхід Gatekeeper за допомогою Control-click «Open»](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Виявлення CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, обхід macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs виявила вразливість Safari, що дає змогу обійти Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs виявила вразливість macOS Archive Utility, що дає змогу обійти Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Виявлення обходу Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Виявлення та повідомлення про експлойт для обходу Gatekeeper за допомогою Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Обхід механізмів безпеки та конфіденційності macOS — від Gatekeeper до System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Про вміст оновлення безпеки macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Форуми розробників Apple: Тестування нотаризованого продукту](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Обхід Gatekeeper — виявлення слабких місць механізму безпеки macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
