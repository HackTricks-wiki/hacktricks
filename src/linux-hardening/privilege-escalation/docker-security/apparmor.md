# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

AppArmor - це **покращення ядра, призначене для обмеження ресурсів, доступних програмам через профілі для кожної програми**, ефективно реалізуючи Обов'язковий Контроль Доступу (MAC), прив'язуючи атрибути контролю доступу безпосередньо до програм, а не до користувачів. Ця система працює шляхом **завантаження профілів у ядро**, зазвичай під час завантаження, і ці профілі визначають, до яких ресурсів програма може отримати доступ, таких як мережеві з'єднання, доступ до сирих сокетів і дозволи на файли.

Існує два робочих режими для профілів AppArmor:

- **Режим виконання**: Цей режим активно забезпечує виконання політик, визначених у профілі, блокуючи дії, які порушують ці політики, і реєструючи будь-які спроби їх порушення через системи, такі як syslog або auditd.
- **Режим скарги**: На відміну від режиму виконання, режим скарги не блокує дії, які суперечать політикам профілю. Натомість він реєструє ці спроби як порушення політики без накладення обмежень.

### Компоненти AppArmor

- **Модуль ядра**: Відповідає за забезпечення політик.
- **Політики**: Визначають правила та обмеження для поведінки програми та доступу до ресурсів.
- **Парсер**: Завантажує політики в ядро для забезпечення виконання або звітування.
- **Утиліти**: Це програми в режимі користувача, які надають інтерфейс для взаємодії та управління AppArmor.

### Шлях до профілів

Профілі AppArmor зазвичай зберігаються в _**/etc/apparmor.d/**_\
За допомогою `sudo aa-status` ви зможете перерахувати двійкові файли, які обмежені якимось профілем. Якщо ви можете змінити символ "/" на крапку в шляху кожного перерахованого двійкового файлу, ви отримаєте назву профілю apparmor у згаданій папці.

Наприклад, профіль **apparmor** для _/usr/bin/man_ буде розташований у _/etc/apparmor.d/usr.bin.man_

### Команди
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Створення профілю

- Щоб вказати на уражений виконуваний файл, **дозволені абсолютні шляхи та шаблони** для вказування файлів.
- Щоб вказати доступ, який бінарний файл матиме до **файлів**, можна використовувати такі **контролі доступу**:
- **r** (читання)
- **w** (запис)
- **m** (відображення пам'яті як виконуваного)
- **k** (блокування файлів)
- **l** (створення жорстких посилань)
- **ix** (виконати іншу програму з новою політикою успадкування)
- **Px** (виконати під іншим профілем, після очищення середовища)
- **Cx** (виконати під дочірнім профілем, після очищення середовища)
- **Ux** (виконати без обмежень, після очищення середовища)
- **Змінні** можуть бути визначені в профілях і можуть бути змінені ззовні профілю. Наприклад: @{PROC} та @{HOME} (додайте #include \<tunables/global> до файлу профілю)
- **Правила заборони підтримуються для переважання правил дозволу**.

### aa-genprof

Щоб легко почати створення профілю, apparmor може вам допомогти. Можливо, **apparmor перевіряє дії, виконувані бінарним файлом, а потім дозволяє вам вирішити, які дії ви хочете дозволити або заборонити**.\
Вам просто потрібно виконати:
```bash
sudo aa-genprof /path/to/binary
```
Потім, у іншій консолі виконайте всі дії, які зазвичай виконує двійковий файл:
```bash
/path/to/binary -a dosomething
```
Тоді в першій консолі натисніть "**s**", а потім у записаних діях вкажіть, чи хочете ви ігнорувати, дозволити або щось інше. Коли ви закінчите, натисніть "**f**", і новий профіль буде створено в _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Використовуючи клавіші зі стрілками, ви можете вибрати, що хочете дозволити/заборонити/щось інше

### aa-easyprof

Ви також можете створити шаблон профілю apparmor для бінарного файлу за допомогою:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> Зверніть увагу, що за замовчуванням у створеному профілі нічого не дозволено, тому все заборонено. Вам потрібно буде додати рядки, такі як `/etc/passwd r,`, щоб дозволити бінарному файлу читати `/etc/passwd`, наприклад.

Ви можете потім **застосувати** новий профіль з
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Модифікація профілю з журналів

Наступний інструмент буде читати журнали та запитувати в користувача, чи хоче він дозволити деякі з виявлених заборонених дій:
```bash
sudo aa-logprof
```
> [!NOTE]
> Використовуючи клавіші зі стрілками, ви можете вибрати, що ви хочете дозволити/заборонити/що завгодно

### Керування профілем
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Приклад **AUDIT** та **DENIED** журналів з _/var/log/audit/audit.log_ виконуваного **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Ви також можете отримати цю інформацію, використовуючи:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor в Docker

Зверніть увагу, як профіль **docker-profile** Docker завантажується за замовчуванням:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
За замовчуванням **профіль docker-default Apparmor** генерується з [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Резюме профілю docker-default**:

- **Доступ** до всіх **мереж**
- **Жодна можливість** не визначена (Однак деякі можливості будуть отримані з включення базових правил, тобто #include \<abstractions/base>)
- **Запис** у будь-який **файл /proc** **не дозволено**
- Інші **підкаталоги**/**файли** /**proc** та /**sys** **не мають** доступу на читання/запис/блокування/посилання/виконання
- **Монтування** **не дозволено**
- **Ptrace** може бути виконано лише на процесі, який обмежений **тим же профілем apparmor**

Якщо ви **запустите контейнер docker**, ви повинні побачити наступний вивід:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Зверніть увагу, що **apparmor навіть заблокує привілеї можливостей**, надані контейнеру за замовчуванням. Наприклад, він зможе **заблокувати дозвіл на запис у /proc, навіть якщо можливість SYS_ADMIN надана**, оскільки за замовчуванням профіль apparmor для docker забороняє цей доступ:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Вам потрібно **вимкнути apparmor**, щоб обійти його обмеження:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Зверніть увагу, що за замовчуванням **AppArmor** також **заборонить контейнеру монтувати** папки зсередини, навіть з можливістю SYS_ADMIN.

Зверніть увагу, що ви можете **додати/видалити** **можливості** до контейнера docker (це все ще буде обмежено методами захисту, такими як **AppArmor** та **Seccomp**):

- `--cap-add=SYS_ADMIN` надає можливість `SYS_ADMIN`
- `--cap-add=ALL` надає всі можливості
- `--cap-drop=ALL --cap-add=SYS_PTRACE` скидає всі можливості і надає лише `SYS_PTRACE`

> [!NOTE]
> Зазвичай, коли ви **виявляєте**, що у вас є **привілейована можливість** доступна **всередині** контейнера **docker**, **але** деяка частина **експлуатації не працює**, це буде тому, що **apparmor docker заважатиме цьому**.

### Приклад

(Приклад з [**тут**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Щоб проілюструвати функціональність AppArmor, я створив новий профіль Docker “mydocker” з наступним рядком:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Щоб активувати профіль, нам потрібно зробити наступне:
```
sudo apparmor_parser -r -W mydocker
```
Щоб перерахувати профілі, ми можемо виконати наступну команду. Команда нижче перераховує мій новий профіль AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Як показано нижче, ми отримуємо помилку, коли намагаємося змінити “/etc/”, оскільки профіль AppArmor заважає запису в “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Ви можете дізнатися, який **профіль apparmor запущений у контейнері**, використовуючи:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Тоді ви можете виконати наступний рядок, щоб **знайти точний профіль, що використовується**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
У дивному випадку ви можете **змінити профіль apparmor docker і перезавантажити його.** Ви могли б видалити обмеження і "обійти" їх.

### AppArmor Docker Bypass2

**AppArmor базується на шляху**, це означає, що навіть якщо він може **захищати** файли всередині каталогу, як **`/proc`**, якщо ви можете **налаштувати, як контейнер буде запущений**, ви могли б **монтувати** каталог proc хоста всередині **`/host/proc`** і він **більше не буде захищений AppArmor**.

### AppArmor Shebang Bypass

У [**цьому багу**](https://bugs.launchpad.net/apparmor/+bug/1911431) ви можете побачити приклад того, як **навіть якщо ви заважаєте perl виконуватися з певними ресурсами**, якщо ви просто створите оболонковий скрипт **вказуючи** в першому рядку **`#!/usr/bin/perl`** і ви **виконаєте файл безпосередньо**, ви зможете виконати що завгодно. Наприклад:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
