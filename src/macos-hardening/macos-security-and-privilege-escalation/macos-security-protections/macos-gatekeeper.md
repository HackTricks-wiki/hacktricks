# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

**Gatekeeper** - це функція безпеки, розроблена для операційних систем Mac, призначена для забезпечення того, щоб користувачі **використовували лише надійне програмне забезпечення** на своїх системах. Вона функціонує шляхом **перевірки програмного забезпечення**, яке користувач завантажує та намагається відкрити з **джерел поза App Store**, таких як додаток, плагін або пакет установника.

Ключовий механізм Gatekeeper полягає в її **процесі перевірки**. Вона перевіряє, чи підписане завантажене програмне забезпечення **визнаним розробником**, що забезпечує автентичність програмного забезпечення. Додатково, вона підтверджує, чи програмне забезпечення **нотаризоване Apple**, що підтверджує, що воно не містить відомого шкідливого вмісту і не було змінено після нотаризації.

Крім того, Gatekeeper посилює контроль користувача та безпеку, **запитуючи користувачів підтвердити відкриття** завантаженого програмного забезпечення вперше. Ця запобіжна міра допомагає запобігти випадковому запуску потенційно шкідливого виконуваного коду, який користувач міг помилково прийняти за безпечний файл даних.

### Application Signatures

Підписи додатків, також відомі як підписи коду, є критично важливим компонентом інфраструктури безпеки Apple. Вони використовуються для **перевірки особи автора програмного забезпечення** (розробника) та для забезпечення того, що код не був змінений з моменту останнього підписання.

Ось як це працює:

1. **Підписання додатка:** Коли розробник готовий розповсюдити свій додаток, він **підписує додаток за допомогою приватного ключа**. Цей приватний ключ пов'язаний з **сертифікатом, який Apple видає розробнику** під час його реєстрації в програмі Apple Developer Program. Процес підписання включає створення криптографічного хешу всіх частин додатка та шифрування цього хешу за допомогою приватного ключа розробника.
2. **Розповсюдження додатка:** Підписаний додаток потім розповсюджується користувачам разом із сертифікатом розробника, який містить відповідний публічний ключ.
3. **Перевірка додатка:** Коли користувач завантажує та намагається запустити додаток, його операційна система Mac використовує публічний ключ з сертифіката розробника для розшифрування хешу. Потім вона повторно обчислює хеш на основі поточного стану додатка та порівнює його з розшифрованим хешем. Якщо вони збігаються, це означає, що **додаток не був змінений** з моменту його підписання розробником, і система дозволяє запуск додатка.

Підписи додатків є важливою частиною технології Gatekeeper Apple. Коли користувач намагається **відкрити додаток, завантажений з Інтернету**, Gatekeeper перевіряє підпис додатка. Якщо він підписаний сертифікатом, виданим Apple відомому розробнику, і код не був змінений, Gatekeeper дозволяє запуск додатка. В іншому випадку, він блокує додаток і сповіщає користувача.

Починаючи з macOS Catalina, **Gatekeeper також перевіряє, чи був додаток нотаризований** Apple, додаючи додатковий рівень безпеки. Процес нотаризації перевіряє додаток на наявність відомих проблем безпеки та шкідливого коду, і якщо ці перевірки проходять, Apple додає квиток до додатка, який може перевірити Gatekeeper.

#### Check Signatures

При перевірці деякого **зразка шкідливого ПЗ** ви завжди повинні **перевіряти підпис** бінарного файлу, оскільки **розробник**, який його підписав, може вже бути **пов'язаний** зі **шкідливим ПЗ.**
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

Процес нотаризації Apple слугує додатковим захистом для користувачів від потенційно шкідливого програмного забезпечення. Він передбачає, що **розробник подає свою програму на перевірку** до **Служби нотаризації Apple**, яку не слід плутати з перевіркою додатків. Ця служба є **автоматизованою системою**, яка ретельно перевіряє подане програмне забезпечення на наявність **шкідливого контенту** та будь-яких потенційних проблем з підписуванням коду.

Якщо програмне забезпечення **проходить** цю перевірку без жодних зауважень, Служба нотаризації генерує квиток нотаризації. Розробник зобов'язаний **додати цей квиток до свого програмного забезпечення**, процес, відомий як 'стаплінг'. Крім того, квиток нотаризації також публікується в Інтернеті, де Gatekeeper, технологія безпеки Apple, може отримати до нього доступ.

Під час першої установки або виконання програмного забезпечення користувачем, наявність квитка нотаризації - чи то прикріпленого до виконуваного файлу, чи знайденого в Інтернеті - **інформує Gatekeeper, що програмне забезпечення було нотаризовано Apple**. В результаті Gatekeeper відображає описове повідомлення в початковому діалоговому вікні запуску, вказуючи на те, що програмне забезпечення пройшло перевірку на наявність шкідливого контенту від Apple. Цей процес таким чином підвищує довіру користувачів до безпеки програмного забезпечення, яке вони встановлюють або запускають на своїх системах.

### spctl & syspolicyd

> [!CAUTION]
> Зверніть увагу, що з версії Sequoia **`spctl`** більше не дозволяє змінювати конфігурацію Gatekeeper.

**`spctl`** - це інструмент CLI для перерахунку та взаємодії з Gatekeeper (через демон `syspolicyd` за допомогою повідомлень XPC). Наприклад, можна побачити **статус** GateKeeper за допомогою:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Зверніть увагу, що перевірки підпису GateKeeper виконуються лише для **файлів з атрибутом Quarantine**, а не для кожного файлу.

GateKeeper перевірить, чи може бінарний файл бути виконаний відповідно до **налаштувань та підпису**:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** є основним демон, відповідальним за забезпечення роботи Gatekeeper. Він підтримує базу даних, розташовану в `/var/db/SystemPolicy`, і ви можете знайти код для підтримки [бази даних тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) та [SQL шаблон тут](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Зверніть увагу, що база даних не обмежена SIP і доступна для запису root, а база даних `/var/db/.SystemPolicy-default` використовується як оригінальна резервна копія на випадок, якщо інша буде пошкоджена.

Більше того, пакети **`/var/db/gke.bundle`** та **`/var/db/gkopaque.bundle`** містять файли з правилами, які вставляються в базу даних. Ви можете перевірити цю базу даних як root за допомогою:
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
**`syspolicyd`** також надає XPC сервер з різними операціями, такими як `assess`, `update`, `record` та `cancel`, які також доступні через **`Security.framework`'s `SecAssessment*`** API, а **`xpctl`** насправді спілкується з **`syspolicyd`** через XPC.

Зверніть увагу, що перше правило закінчується на "**App Store**", а друге на "**Developer ID**", і що в попередньому зображенні було **дозволено виконувати програми з App Store та від ідентифікованих розробників**.\
Якщо ви **зміните** це налаштування на App Store, то правила "**Notarized Developer ID" зникнуть**.

Існує також тисячі правил **типу GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Це хеші, які з:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Або ви можете перерахувати попередню інформацію за допомогою:
```bash
sudo spctl --list
```
Опції **`--master-disable`** та **`--global-disable`** команди **`spctl`** повністю **відключать** ці перевірки підписів:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Коли повністю увімкнено, з'явиться нова опція:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Можна **перевірити, чи буде додаток дозволено GateKeeper** за допомогою:
```bash
spctl --assess -v /Applications/App.app
```
Можливо додати нові правила в GateKeeper, щоб дозволити виконання певних додатків за допомогою:
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
Щодо **розширень ядра**, папка `/var/db/SystemPolicyConfiguration` містить файли зі списками kext, які дозволено завантажувати. Більше того, `spctl` має право `com.apple.private.iokit.nvram-csr`, оскільки здатний додавати нові попередньо схвалені розширення ядра, які також потрібно зберігати в NVRAM у ключі `kext-allowed-teams`.

### Файли карантину

Після **завантаження** програми або файлу, певні програми macOS, такі як веб-браузери або поштові клієнти, **додають розширений атрибут файлу**, відомий як "**прапор карантину**", до завантаженого файлу. Цей атрибут діє як захисний захід, щоб **позначити файл** як такий, що походить з ненадійного джерела (інтернету), і потенційно несе ризики. Однак не всі програми додають цей атрибут, наприклад, звичайне програмне забезпечення клієнтів BitTorrent зазвичай обходить цей процес.

**Наявність прапора карантину сигналізує про функцію безпеки Gatekeeper macOS, коли користувач намагається виконати файл**.

У випадку, якщо **прапор карантину відсутній** (як у випадку з файлами, завантаженими через деякі клієнти BitTorrent), **перевірки Gatekeeper можуть не виконуватись**. Тому користувачі повинні бути обережними при відкритті файлів, завантажених з менш безпечних або невідомих джерел.

> [!NOTE] > **Перевірка** **дійсності** підписів коду є **ресурсоємним** процесом, який включає в себе генерацію криптографічних **хешів** коду та всіх його упакованих ресурсів. Крім того, перевірка дійсності сертифіката передбачає проведення **онлайн-перевірки** на серверах Apple, щоб дізнатися, чи був він відкликаний після його видачі. З цих причин повна перевірка підпису коду та нотаризації є **недоцільною для виконання щоразу при запуску програми**.
>
> Тому ці перевірки **виконуються лише при виконанні програм з атрибутом карантину.**

> [!WARNING]
> Цей атрибут повинен бути **встановлений програмою, що створює/завантажує** файл.
>
> Однак файли, які знаходяться в пісочниці, матимуть цей атрибут, встановлений для кожного файлу, який вони створюють. А програми без пісочниці можуть встановити його самостійно або вказати ключ [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) у **Info.plist**, що змусить систему встановити розширений атрибут `com.apple.quarantine` на створені файли,

Більше того, всі файли, створені процесом, що викликає **`qtn_proc_apply_to_self`**, підлягають карантину. Або API **`qtn_file_apply_to_path`** додає атрибут карантину до вказаного шляху файлу.

Можна **перевірити його статус і увімкнути/вимкнути** (потрібні права root) за допомогою:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Ви також можете **знайти, чи має файл розширений атрибут карантину** за допомогою:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Перевірте **значення** **розширених** **атрибутів** та знайдіть додаток, який записав атрибут карантину за допомогою:
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
Насправді процес "може встановити прапори карантину для файлів, які він створює" (я вже намагався застосувати прапор USER_APPROVED у створеному файлі, але він не застосовується):

<details>

<summary>Джерельний код для застосування прапорів карантину</summary>
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
Інформація про карантин також зберігається в центральній базі даних, керованій LaunchServices у **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, що дозволяє графічному інтерфейсу отримувати дані про походження файлів. Більше того, це може бути перезаписано додатками, які можуть бути зацікавлені в приховуванні своїх походжень. Це також можна зробити з API LaunchServices.

#### **libquarantine.dylb**

Ця бібліотека експортує кілька функцій, які дозволяють маніпулювати полями розширених атрибутів.

API `qtn_file_*` стосуються політик карантину файлів, API `qtn_proc_*` застосовуються до процесів (файлів, створених процесом). Невиведені функції `__qtn_syscall_quarantine*` є тими, які застосовують політики, які викликають `mac_syscall` з "Quarantine" як першим аргументом, що надсилає запити до `Quarantine.kext`.

#### **Quarantine.kext**

Розширення ядра доступне лише через **кеш ядра на системі**; однак ви _можете_ завантажити **Kernel Debug Kit з** [**https://developer.apple.com/**](https://developer.apple.com/), який міститиме символізовану версію розширення.

Цей Kext буде перехоплювати через MACF кілька викликів, щоб захопити всі події життєвого циклу файлів: створення, відкриття, перейменування, жорстке посилання... навіть `setxattr`, щоб запобігти встановленню розширеного атрибута `com.apple.quarantine`.

Він також використовує кілька MIB:

- `security.mac.qtn.sandbox_enforce`: Застосування карантину разом із Sandbox
- `security.mac.qtn.user_approved_exec`: Карантиновані процеси можуть виконувати лише затверджені файли

### XProtect

XProtect - це вбудована **антивірусна** функція в macOS. XProtect **перевіряє будь-який додаток, коли він вперше запускається або модифікується, проти своєї бази даних** відомих шкідливих програм і небезпечних типів файлів. Коли ви завантажуєте файл через певні додатки, такі як Safari, Mail або Messages, XProtect автоматично сканує файл. Якщо він відповідає будь-якій відомій шкідливій програмі в його базі даних, XProtect **запобіжить виконанню файлу** і сповістить вас про загрозу.

База даних XProtect **регулярно оновлюється** Apple новими визначеннями шкідливих програм, і ці оновлення автоматично завантажуються та встановлюються на ваш Mac. Це забезпечує, що XProtect завжди актуальний з останніми відомими загрозами.

Однак варто зазначити, що **XProtect не є повнофункціональним антивірусним рішенням**. Він лише перевіряє конкретний список відомих загроз і не виконує сканування при доступі, як більшість антивірусного програмного забезпечення.

Ви можете отримати інформацію про останнє оновлення XProtect, запустивши:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect розташований у захищеному місці SIP за адресою **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, і всередині пакету ви можете знайти інформацію, яку використовує XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Дозволяє коду з цими cdhashes використовувати спадкові права.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Список плагінів і розширень, які заборонено завантажувати через BundleID і TeamID або вказуючи мінімальну версію.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Правила Yara для виявлення шкідливого ПЗ.
- **`XProtect.bundle/Contents/Resources/gk.db`**: База даних SQLite3 з хешами заблокованих додатків і TeamIDs.

Зверніть увагу, що є ще один додаток у **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, пов'язаний з XProtect, який не бере участі в процесі Gatekeeper.

### Не Gatekeeper

> [!CAUTION]
> Зверніть увагу, що Gatekeeper **не виконується щоразу**, коли ви запускаєте додаток, лише _**AppleMobileFileIntegrity**_ (AMFI) **перевіряє підписи виконуваного коду** лише тоді, коли ви запускаєте додаток, який вже був виконаний і перевірений Gatekeeper.

Отже, раніше було можливо виконати додаток, щоб кешувати його з Gatekeeper, а потім **модифікувати не виконувані файли додатка** (як-от Electron asar або NIB файли), і якщо не було інших захистів, додаток **виконувався** з **шкідливими** доповненнями.

Однак тепер це неможливо, оскільки macOS **запобігає модифікації файлів** всередині пакетів додатків. Тож, якщо ви спробуєте атаку [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), ви виявите, що більше не можна зловживати цим, оскільки після виконання додатка для кешування з Gatekeeper ви не зможете модифікувати пакет. І якщо ви, наприклад, зміните назву каталогу Contents на NotCon (як вказано в експлойті), а потім виконаєте основний бінарний файл додатка для кешування з Gatekeeper, це викличе помилку і не виконається.

## Обходи Gatekeeper

Будь-який спосіб обійти Gatekeeper (змусити користувача завантажити щось і виконати це, коли Gatekeeper повинен це заборонити) вважається вразливістю в macOS. Ось деякі CVE, призначені технікам, які дозволяли обійти Gatekeeper у минулому:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Було помічено, що якщо для розпакування використовується **Archive Utility**, файли з **шляхами, що перевищують 886 символів**, не отримують розширену атрибуцію com.apple.quarantine. Ця ситуація ненавмисно дозволяє цим файлам **обійти перевірки безпеки Gatekeeper**.

Перевірте [**оригінальний звіт**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) для отримання додаткової інформації.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Коли додаток створюється за допомогою **Automator**, інформація про те, що йому потрібно для виконання, знаходиться всередині `application.app/Contents/document.wflow`, а не в виконуваному файлі. Виконуваний файл - це просто загальний бінарний файл Automator, званий **Automator Application Stub**.

Отже, ви могли б зробити так, щоб `application.app/Contents/MacOS/Automator\ Application\ Stub` **вказував за допомогою символічного посилання на інший Automator Application Stub всередині системи**, і він виконає те, що знаходиться в `document.wflow` (ваш скрипт) **без активації Gatekeeper**, оскільки фактичний виконуваний файл не має атрибута карантину.

Приклад очікуваного місця: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Перевірте [**оригінальний звіт**](https://ronmasas.com/posts/bypass-macos-gatekeeper) для отримання додаткової інформації.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

У цьому обході був створений zip-файл з додатком, який починався з компресії з `application.app/Contents`, а не з `application.app`. Отже, **атрибут карантину** був застосований до всіх **файлів з `application.app/Contents`**, але **не до `application.app`**, що перевіряв Gatekeeper, тому Gatekeeper був обійдений, оскільки коли `application.app` був активований, він **не мав атрибута карантину.**
```bash
zip -r test.app/Contents test.zip
```
Перевірте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) для отримання додаткової інформації.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Навіть якщо компоненти різні, експлуатація цієї вразливості дуже схожа на попередню. У цьому випадку ми згенеруємо Apple Archive з **`application.app/Contents`**, тому **`application.app` не отримає атрибут карантину** при розпакуванні за допомогою **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Перевірте [**оригінальний звіт**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) для отримання додаткової інформації.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** може бути використаний для запобігання запису атрибута у файл:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Крім того, формат файлу **AppleDouble** копіює файл, включаючи його ACE.

У [**джерельному коді**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) можна побачити, що текстове представлення ACL, збережене всередині xattr під назвою **`com.apple.acl.text`**, буде встановлено як ACL у розпакованому файлі. Отже, якщо ви стиснули додаток у zip-файл з форматом файлу **AppleDouble** з ACL, який заважає запису інших xattrs у нього... xattr карантину не було встановлено в додатку:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Перегляньте [**оригінальний звіт**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) для отримання додаткової інформації.

Зверніть увагу, що це також може бути використано з AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Було виявлено, що **Google Chrome не встановлював атрибут карантину** для завантажених файлів через деякі внутрішні проблеми macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Формати файлів AppleDouble зберігають атрибути файлу в окремому файлі, що починається з `._`, це допомагає копіювати атрибути файлів **між машинами macOS**. Однак було помічено, що після розпакування файлу AppleDouble файл, що починається з `._`, **не отримав атрибут карантину**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Можливість створити файл, який не матиме атрибуту карантину, дозволила **обійти Gatekeeper.** Трюк полягав у тому, щоб **створити DMG файл додатку** за допомогою конвенції імен AppleDouble (почати з `._`) і створити **видимий файл як символьне посилання на цей прихований** файл без атрибуту карантину.\
Коли **файл dmg виконується**, оскільки він не має атрибуту карантину, він **обійде Gatekeeper.**
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
### uchg (з цього [докладу](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Створіть каталог, що містить додаток.
- Додайте uchg до додатку.
- Стисніть додаток у файл tar.gz.
- Відправте файл tar.gz жертві.
- Жертва відкриває файл tar.gz і запускає додаток.
- Gatekeeper не перевіряє додаток.

### Запобігання Quarantine xattr

У пакеті ".app", якщо xattr карантину не додано, при виконанні **Gatekeeper не буде активовано**.


{{#include ../../../banners/hacktricks-training.md}}
