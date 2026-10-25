# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** — це функція безпеки, розроблена для операційних систем Mac, яка гарантує, що користувачі **запускають лише довірене програмне забезпечення**. Вона перевіряє програмне забезпечення, яке користувач завантажує та намагається відкрити з **джерел поза App Store**, наприклад застосунок, плагін або інсталяційний пакет.

Ключовим механізмом Gatekeeper є процес **перевірки**. Він перевіряє, чи **підписане завантажене програмне забезпечення визнаним розробником**, що засвідчує його автентичність. Крім того, він перевіряє, чи **пройшло програмне забезпечення нотаріальне засвідчення Apple**, підтверджуючи, що воно не містить відомого шкідливого вмісту та не було змінене після нотаріального засвідчення.

Також Gatekeeper посилює контроль користувачів і безпеку, **пропонуючи користувачам підтвердити відкриття** завантаженого програмного забезпечення під час першого запуску. Цей захист допомагає запобігти випадковому виконанню потенційно шкідливого виконуваного коду, який користувачі могли сприйняти за нешкідливий файл даних.

### Підписи застосунків

Підписи застосунків, також відомі як підписи коду, є важливою складовою інфраструктури безпеки Apple. Їх використовують, щоб **перевірити особу автора програмного забезпечення** (розробника) та переконатися, що код не змінювали після останнього підписання.

Ось як це працює:

1. **Підписання застосунку:** Коли розробник готовий поширювати свій застосунок, він **підписує застосунок за допомогою приватного ключа**. Цей приватний ключ пов’язаний із **сертифікатом, який Apple видає розробнику** під час реєстрації в Apple Developer Program. Процес підписання передбачає створення криптографічного хешу всіх частин застосунку та шифрування цього хешу приватним ключем розробника.
2. **Поширення застосунку:** Після цього підписаний застосунок поширюється серед користувачів разом із сертифікатом розробника, який містить відповідний публічний ключ.
3. **Перевірка застосунку:** Коли користувач завантажує застосунок і намагається його запустити, операційна система Mac використовує публічний ключ із сертифіката розробника, щоб розшифрувати хеш. Потім вона повторно обчислює хеш на основі поточного стану застосунку та порівнює його з розшифрованим хешем. Якщо вони збігаються, це означає, що **застосунок не змінювали** після підписання розробником, і система дозволяє його запуск.

Підписи застосунків є важливою частиною технології Gatekeeper від Apple. Коли користувач намагається **відкрити застосунок, завантажений з інтернету**, Gatekeeper перевіряє підпис застосунку. Якщо застосунок підписаний сертифікатом, виданим Apple відомому розробнику, а код не змінювали, Gatekeeper дозволяє його запуск. В іншому разі він блокує застосунок і попереджає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи пройшов застосунок нотаріальне засвідчення Apple**, додаючи ще один рівень безпеки. Під час нотаріального засвідчення застосунок перевіряють на наявність відомих проблем безпеки та шкідливого коду. Якщо перевірку пройдено, Apple додає до застосунку квиток, який Gatekeeper може перевірити.

#### Перевірка підписів

Під час перевірки зразка **malware** завжди слід **перевіряти підпис** бінарного файлу, оскільки **розробник**, який його підписав, уже може бути **пов’язаний** із **malware**.

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

Процес нотаризації Apple — це додатковий засіб захисту користувачів від потенційно шкідливого програмного забезпечення. Він передбачає, що **розробник надсилає свою програму на перевірку** до **служби нотаризації Apple**. Її не слід плутати з App Review. Це **автоматизована система**, яка перевіряє надіслане програмне забезпечення на наявність **шкідливого вмісту** й потенційних проблем із підписуванням коду.

Якщо програмне забезпечення **проходить** перевірку без зауважень, служба нотаризації створює квиток нотаризації. Розробник має **додати цей квиток до свого програмного забезпечення** — цей процес називається «скріпленням» (stapling). Крім того, квиток нотаризації публікується онлайн, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першого встановлення або запуску програмного забезпечення користувачем наявність квитка нотаризації — прикріпленого до виконуваного файла або знайденого онлайн — **повідомляє Gatekeeper, що Apple нотаризувала це програмне забезпечення**. У результаті Gatekeeper показує в діалоговому вікні першого запуску описове повідомлення про те, що Apple перевірила програмне забезпечення на наявність шкідливого вмісту. Це підвищує впевненість користувачів у безпеці програмного забезпечення, яке вони встановлюють або запускають на своїх системах.

### spctl і syspolicyd

> [!CAUTION]
> Зверніть увагу: починаючи з версії Sequoia, **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** — це CLI-інструмент для перегляду Gatekeeper і взаємодії з ним (через демон `syspolicyd` за допомогою повідомлень XPC). Наприклад, за його допомогою можна переглянути **стан** Gatekeeper:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Зверніть увагу, що GateKeeper перевіряє підписи лише **файлів з атрибутом Quarantine**, а не всіх файлів.

GateKeeper перевірить, чи можна виконати бінарний файл відповідно до **налаштувань і підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** — основний демон, відповідальний за застосування Gatekeeper. Він підтримує базу даних у `/var/db/SystemPolicy`. Код для роботи з [базою даних можна знайти тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), а [шаблон SQL — тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що SIP не обмежує доступ до бази даних: root може записувати до неї, а база даних `/var/db/.SystemPolicy-default` використовується як резервна копія на випадок пошкодження основної бази.

Крім того, пакети **`/var/db/gke.bundle`** і **`/var/db/gkopaque.bundle`** містять файли з правилами, які додаються до бази даних. Переглянути цю базу даних від імені root можна так:

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

**`syspolicyd`** також надає XPC-сервер із різними операціями, як-от `assess`, `update`, `record` і `cancel`, до яких також можна звертатися через API **`SecAssessment*`** із **`Security.framework`**, а **`spctl`** фактично взаємодіє з **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчувалося на «**App Store**», а друге — на «**Developer ID**», і що на попередньому зображенні було **дозволено запускати програми з App Store та від ідентифікованих розробників**.\
Якщо **змінити** це налаштування на App Store, правила «**Notarized Developer ID**» зникнуть.

Також є тисячі правил **типу GKE**:

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

Або можна переглянути попередню інформацію за допомогою:

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

Після повного ввімкнення з’явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

За допомогою цієї опції можна **перевірити, чи дозволить GateKeeper запуск програми**:

```bash
spctl --assess -v /Applications/App.app
```

У macOS 14 і новіших версіях **`syspolicy_check`** — корисний інструмент для перевірки пакета програми перед розповсюдженням на вищому рівні. Він надає кориснішу діагностику довіреного виконання, ніж простий результат `spctl`, хоча Apple усе ще рекомендує тестувати реальний сценарій завантаження, розпакування та першого запуску, оскільки він також перевіряє поширення атрибута quarantine.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

У GateKeeper можна додавати нові правила, щоб дозволити запуск певних програм за допомогою:

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

Щодо **kernel extensions**, папка `/var/db/SystemPolicyConfiguration` містить файли зі списками kexts, яким дозволено завантажуватися. Крім того, `spctl` має entitlement `com.apple.private.iokit.nvram-csr`, оскільки може додавати нові попередньо дозволені kernel extensions, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

#### Керування Gatekeeper у macOS 15 (Sequoia) і новіших версіях

- Давній обхід через Finder **Ctrl+Open / клацання правою кнопкою → Open** прибрали; після першого діалогового вікна з блокуванням користувачі мають явно дозволити заблоковану програму через **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` більше не приймаються як автоматизовані зміни політики. Операції, що змінюють базу даних правил або глобальний стан оцінювання, застаріли, тому використовуйте `spctl` для оцінювання, а примусове застосування налаштовуйте через інтерфейс або MDM.

Починаючи з macOS 15 Sequoia, кінцеві користувачі більше не можуть перемикати політику Gatekeeper через `spctl`. Керування здійснюється через System Settings або розгортанням конфігураційного профілю MDM із payload `com.apple.systempolicy.control`. Приклад фрагмента профілю, який дозволяє App Store і визначених розробників (але не «Anywhere»):

<details>
<summary>Профіль MDM для дозволу App Store і визначених розробників</summary>

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

### Файли карантину

Під час **завантаження** програми або файлу певні **програми** macOS, як-от веббраузери чи поштові клієнти, **додають розширений атрибут файлу**, відомий як «**прапорець карантину**», до завантаженого файлу. Цей атрибут є засобом безпеки, який **позначає файл** як такий, що походить із ненадійного джерела (інтернету) та потенційно може становити ризик. Однак не всі програми додають цей атрибут. Наприклад, поширені клієнти BitTorrent зазвичай обходять цей процес.

**Наявність прапорця карантину сигналізує функції безпеки Gatekeeper у macOS, коли користувач намагається виконати файл**.

Якщо **прапорець карантину відсутній** (наприклад, у файлів, завантажених за допомогою деяких клієнтів BitTorrent), **перевірки** Gatekeeper можуть **не виконуватися**. Тому користувачам слід бути обережними, відкриваючи файли, завантажені з менш захищених або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду — це ресурсомісткий процес, що передбачає створення криптографічних **хешів** коду та всіх його вбудованих ресурсів. Крім того, перевірка дійсності сертифіката передбачає **онлайн-перевірку** на серверах Apple, щоб з’ясувати, чи його було відкликано після видачі. З цих причин повна перевірка підпису коду та нотаріального засвідчення **непрактична під час кожного запуску програми**.
>
> Тому ці перевірки виконуються **лише під час запуску програм з атрибутом карантину**.

> [!WARNING]
> Цей атрибут має **встановлювати програма, яка створює/завантажує** файл.
>
> Однак для файлів, створених у пісочниці, цей атрибут установлюється для кожного створеного файлу. Програми поза пісочницею можуть установлювати його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist** — тоді система встановлюватиме розширений атрибут `com.apple.quarantine` для створених файлів.

Крім того, усі файли, створені процесом, який викликає **`qtn_proc_apply_to_self`**, поміщаються в карантин. API **`qtn_file_apply_to_path`** додає атрибут карантину до вказаного шляху файлу.

Його **стан можна перевірити, а карантин — увімкнути або вимкнути** (потрібні права root) за допомогою:

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

Перевірте **значення** **розширених** **атрибутів** і з’ясуйте, яка програма записала атрибут карантину за допомогою:

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

Насправді процес «може встановлювати прапорці карантину для створених ним файлів» (я вже намагався встановити прапорець USER_APPROVED для створеного файлу, але не вдалося):

<details>

<summary>Вихідний код: встановлення прапорців карантину</summary>

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

Інформація про карантин також зберігається в центральній базі даних, якою керує LaunchServices, у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**. Це дає графічному інтерфейсу змогу отримувати дані про походження файлу. Крім того, програми, зацікавлені в приховуванні походження файлів, можуть перезаписати ці дані. Це також можна зробити за допомогою API LaunchServices.

#### **libquarantine.dylib**

Ця бібліотека експортує кілька функцій для керування полями розширених атрибутів.

API `qtn_file_*` працюють із політиками карантину файлів, а API `qtn_proc_*` застосовуються до процесів (файлів, створених процесом). Неекспортовані функції `__qtn_syscall_quarantine*` застосовують політики: вони викликають `mac_syscall` із першим аргументом "Quarantine", надсилаючи запити до `Quarantine.kext`.

#### **Quarantine.kext**

Це розширення ядра доступне лише в **кеші ядра системи**; однак можна завантажити **Kernel Debug Kit із сайту** [**https://developer.apple.com/**](https://developer.apple.com/), який містить версію розширення із символами.

Цей Kext використовує перехоплення через MACF для відстеження всіх подій життєвого циклу файлів: створення, відкриття, перейменування, створення жорстких посилань... навіть `setxattr`, щоб заборонити встановлення розширеного атрибута `com.apple.quarantine`.

Він також використовує кілька MIB:

- `security.mac.qtn.sandbox_enforce`: застосовувати карантин разом із Sandbox
- `security.mac.qtn.user_approved_exec`: процеси в карантині можуть виконувати лише схвалені файли

#### Атрибут xattr походження (Ventura і новіші версії)

У macOS 13 Ventura запроваджено окремий механізм походження, який заповнюється під час першого запуску програми в карантині.<sup>[[2]](#references)</sup> Створюються два артефакти:

- Атрибут xattr `com.apple.provenance` у каталозі пакета `.app` (бінарне значення фіксованого розміру, що містить первинний ключ і прапорці).
- Рядок у таблиці `provenance_tracking` бази даних ExecPolicy за адресою `/var/db/SystemPolicyConfiguration/ExecPolicy/`, у якому зберігаються cdhash програми та метадані.

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

XProtect — це вбудована в macOS функція **захисту від шкідливого програмного забезпечення**. XProtect **перевіряє кожну програму під час першого запуску або після змін, звіряючи її зі своєю базою даних** відомого шкідливого програмного забезпечення та небезпечних типів файлів. Коли ви завантажуєте файл через певні програми, як-от Safari, Mail або Messages, XProtect автоматично сканує його. Якщо файл відповідає будь-якому відомому зразку шкідливого програмного забезпечення у своїй базі даних, XProtect **не дозволить запустити файл** і попередить вас про загрозу.

Apple **регулярно оновлює** базу даних XProtect новими визначеннями шкідливого програмного забезпечення, а ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Це гарантує, що XProtect завжди має актуальні дані про найновіші відомі загрози.

Однак варто зазначити, що **XProtect — це не повноцінне антивірусне рішення**. Він перевіряє лише певний перелік відомих загроз і не виконує сканування під час доступу, як більшість антивірусних програм.

Отримати інформацію про останнє оновлення XProtect можна, виконавши:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect розташований у захищеному SIP місці **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, і всередині bundle можна знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhash використовувати legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список плагінів і розширень, завантаження яких заборонено за BundleID і TeamID, або вказано мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Правила Yara для виявлення malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 із хешами заблокованих програм і TeamID.

Зверніть увагу, що існує ще один App, пов’язаний із XProtect, у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, який не бере участі в процесі Gatekeeper.

> XProtect Remediator: У сучасних версіях macOS Apple постачає сканери на вимогу (XProtect Remediator), які періодично запускаються через launchd для виявлення та усунення сімейств malware. Ці сканування можна спостерігати в unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу: Gatekeeper **не запускається щоразу**, коли ви запускаєте програму. Лише _**AppleMobileFileIntegrity**_ (AMFI) **перевіряє підписи виконуваного коду**, коли ви запускаєте програму, яку Gatekeeper уже запускав і перевіряв.

Тому раніше можна було запустити програму, щоб Gatekeeper кешував її, а потім **змінити файли програми, які не є виконуваними** (наприклад, файли Electron asar або NIB). Якщо інших засобів захисту не було, програму **запускали** зі **шкідливими** доповненнями.

Однак тепер це неможливо, оскільки macOS **не дозволяє змінювати файли** всередині пакетів програм. Тож якщо ви спробуєте атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), то побачите, що тепер її неможливо використати: після запуску програми, щоб Gatekeeper кешував її, ви не зможете змінити пакет. А якщо, наприклад, змінити назву каталогу Contents на NotCon (як зазначено в експлойті), а потім запустити головний бінарний файл програми, щоб Gatekeeper кешував її, це призведе до помилки, і програма не запуститься.

## Обходи Gatekeeper

Будь-який спосіб обійти Gatekeeper (домогтися, щоб користувач завантажив і запустив щось, що Gatekeeper мав би заблокувати) вважається вразливістю macOS. Ось кілька CVE, присвоєних методам обходу Gatekeeper, які працювали раніше:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було виявлено, що під час розпакування за допомогою **Archive Utility** файли, шляхи до яких **перевищують 886 символів**, не отримують розширеного атрибута com.apple.quarantine. Через це ці файли ненавмисно можуть **обійти** перевірки безпеки Gatekeeper.<sup>[[5]](#references)</sup>

Докладніше дивіться в [**оригінальному звіті**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли програму створюють за допомогою **Automator**, інформація про те, що їй потрібно виконати, міститься у `application.app/Contents/document.wflow`, а не у виконуваному файлі. Виконуваний файл — це лише універсальний бінарний файл Automator під назвою **Automator Application Stub**.

Тому можна було створити символічне посилання `application.app/Contents/MacOS/Automator\ Application\ Stub` на інший Automator Application Stub у системі, і він виконував би вміст `document.wflow` (ваш скрипт) **без запуску Gatekeeper**, оскільки фактичний виконуваний файл не має атрибута xattr quarantine.<sup>[[6]](#references)</sup>

Приклад очікуваного розташування: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Докладніше дивіться в [**оригінальному звіті**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Для цього обходу було створено zip-файл із програмою, причому архівацію починали з `application.app/Contents`, а не з `application.app`. Тому атрибут **quarantine** застосовувався до всіх **файлів у `application.app/Contents`**, але **не до `application.app`**, який перевіряв Gatekeeper. Отже, Gatekeeper можна було обійти, оскільки під час запуску `application.app` **він не мав атрибута quarantine**.<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Перегляньте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/), щоб дізнатися більше.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Хоча компоненти відрізняються, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку ми створимо Apple Archive з **`application.app/Contents`**, тож **`application.app`** не отримає атрибут quarantine під час розпакування за допомогою **Archive Utility**.<sup>[[8]](#references)</sup>

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

Крім того, формат файлів **AppleDouble** копіює файл разом із його ACE.<sup>[[9]](#references)</sup>

У [**вихідному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене у xattr з назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо стиснути програму в zip-файл у форматі **AppleDouble** з ACL, який не дозволяє записувати до неї інші xattr... quarantine xattr не буде встановлено для програми:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.<sup>[[9]](#references)</sup> Див. [відтворення AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md), щоб ознайомитися з етапами створення та перевірки sidecar-файлу.

Зверніть увагу, що це також можна було б експлуатувати за допомогою AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут карантину** для завантажених файлів через деякі внутрішні проблеми macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble зберігає атрибути файлу в окремому файлі, назва якого починається з `._`; це дає змогу копіювати атрибути файлів **між комп’ютерами macOS**. Однак після розпакування файлу AppleDouble файл із назвою, що починається з `._`, **не отримував атрибут карантину**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Оскільки можна було створити файл без атрибута quarantine, **з’являлася можливість обійти Gatekeeper.** Для цього потрібно було **створити файл застосунку DMG** за домовленістю іменування AppleDouble (почати його з `._`) і створити **видимий файл як символьне посилання на цей прихований** файл без атрибута quarantine.\
Коли **файл DMG запускається**, оскільки він не має атрибута quarantine, він **обходить Gatekeeper**.

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

Apple виправила логічну помилку в LaunchServices у macOS Sonoma 14.0, покращивши перевірки. У публічному повідомленні лише зазначено, що застосунок міг обійти Gatekeeper, тож не слід робити висновки про конкретний формат носія чи ланцюжок експлуатації лише на підставі запису CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Обхід Gatekeeper у macOS 14.4 (випущеній у березні 2024 року) був спричинений тим, як `libarchive` обробляла шкідливі ZIP-архіви, і дозволяв застосункам уникнути перевірки. Оновіться до версії 14.4 або новішої, у якій Apple виправила цю проблему.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Вбудований у завантажений застосунок **Automator Quick Action workflow** міг запуститися без перевірки Gatekeeper, оскільки workflow вважали даними, а допоміжний процес Automator запускав його поза звичайним шляхом запиту на нотаризацію. Тому спеціально створений `.app`, що містить Quick Action для запуску shell-скрипту (наприклад, у `Contents/PlugIns/*.workflow/Contents/document.wflow`), міг виконати його одразу після запуску. Apple додала додаткове діалогове вікно згоди й виправила шлях перевірки у Ventura **13.7**, Sonoma **14.7** та Sequoia **15**.<sup>[[3]](#references)</sup>

### Збої поширення атрибута карантину під час розпакування та копіювання

Дослідження 2024 року виявило прогалини в поширенні атрибута у протестованих версіях iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) та 7z Utility (DMG/ZIP/7Z); також було виявлено втрату атрибута під час копіювання з хоста до гостьової системи через VMware Tools. Згодом кілька постачальників оголосили про виправлення, тож сприймайте ці назви як підказки для **повторного тестування конкретних версій**, а не як постійний перелік вразливого програмного забезпечення. Та сама проблема меж довіри стосується й нативних Unix-процесів: `curl`/`scp` не додають атрибут карантину, а командні `tar`/`unzip` не успадковують його автоматично з архіву-носія.<sup>[[15]](#references)</sup>

Під час тестування на проникнення порівнюйте носій і кінцевий застосунок після **кожного** переходу через браузер, поштовий клієнт, архіватор, образ диска, хмарну синхронізацію, спільну папку та копіювання між віртуальними машинами. Явна відмова `spctl` не виправляє відсутній xattr: без атрибута карантину звичайний сценарій першого відкриття Gatekeeper може взагалі не запитати таку перевірку.<sup>[[15]](#references)</sup>

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
- Додайте до app uchg.
- Стисніть app у файл tar.gz.
- Надішліть файл tar.gz жертві.
- Жертва відкриває файл tar.gz і запускає app.
- Gatekeeper не перевіряє app.<sup>[[12]](#references)</sup>

### Запобігання атрибуту quarantine xattr

Якщо до пакета ".app" не додано quarantine xattr, під час його запуску **Gatekeeper не спрацьовує**.

Див. [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks), щоб дізнатися про примітиви на основі файлової системи, прапорців, ACL та AppleDouble, які можуть запобігти додаванню або видалити розширені атрибути.





## References

- [1] [Apple Platform Security: Про вміст оновлення безпеки macOS Sonoma 14.4 (містить CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Як macOS тепер відстежує походження програм](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Про вміст оновлення безпеки macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia усуває обхід Gatekeeper через «Відкрити» в контекстному меню](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Виявлення CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990: обхід macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs виявила вразливість Safari, що дає змогу обійти Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs виявила вразливість Archive Utility у macOS, що дає змогу обійти Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Ахіллесова п’ята Gatekeeper: виявлення вразливості macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: виявлення обходу Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Виявлення та повідомлення про експлойт для обходу Gatekeeper за допомогою Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: обхід механізмів безпеки та конфіденційності macOS — від Gatekeeper до System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Про вміст оновлення безпеки macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Форуми Apple Developer: тестування нотаризованого продукту](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: обхід Gatekeeper — виявлення слабких місць механізму безпеки macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
