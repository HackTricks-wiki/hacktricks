# Linux 포렌식

{{#include ../../banners/hacktricks-training.md}}

## 초기 정보 수집

### 기본 정보

우선, **좋은 알려진 바이너리와 라이브러리**가 있는 **USB**를 준비하는 것이 좋습니다(우분투를 가져와서 _/bin_, _/sbin_, _/lib,_ 및 _/lib64_ 폴더를 복사하면 됩니다). 그런 다음 USB를 마운트하고 환경 변수를 수정하여 해당 바이너리를 사용합니다:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
시스템을 신뢰할 수 있는 알려진 바이너리를 사용하도록 구성한 후, **기본 정보를 추출하기 시작할 수 있습니다**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### 의심스러운 정보

기본 정보를 얻는 동안 다음과 같은 이상한 사항을 확인해야 합니다:

- **루트 프로세스**는 일반적으로 낮은 PID로 실행되므로, 큰 PID를 가진 루트 프로세스를 발견하면 의심할 수 있습니다.
- `/etc/passwd` 내에서 셸이 없는 사용자의 **등록된 로그인**을 확인하십시오.
- 셸이 없는 사용자의 `/etc/shadow` 내에서 **비밀번호 해시**를 확인하십시오.

### 메모리 덤프

실행 중인 시스템의 메모리를 얻으려면 [**LiME**](https://github.com/504ensicsLabs/LiME)를 사용하는 것이 좋습니다.\
**컴파일**하려면 피해자 머신이 사용하는 **동일한 커널**을 사용해야 합니다.

> [!NOTE]
> 피해자 머신에 **LiME 또는 다른 어떤 것**도 설치할 수 없음을 기억하십시오. 이는 여러 가지 변경을 초래할 것입니다.

따라서 동일한 버전의 Ubuntu가 있다면 `apt-get install lime-forensics-dkms`를 사용할 수 있습니다.\
다른 경우에는 [**LiME**](https://github.com/504ensicsLabs/LiME)를 github에서 다운로드하고 올바른 커널 헤더로 컴파일해야 합니다. 피해자 머신의 **정확한 커널 헤더**를 얻으려면 `/lib/modules/<kernel version>` 디렉토리를 귀하의 머신으로 **복사**한 다음, 이를 사용하여 LiME를 **컴파일**하면 됩니다:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME는 3가지 **형식**을 지원합니다:

- Raw (모든 세그먼트가 함께 연결됨)
- Padded (raw와 동일하지만 오른쪽 비트에 제로가 추가됨)
- Lime (메타데이터가 포함된 추천 형식)

LiME는 또한 **시스템에 저장하는 대신 네트워크를 통해 덤프를 전송**하는 데 사용할 수 있습니다. 예: `path=tcp:4444`

### 디스크 이미징

#### 시스템 종료

우선, **시스템을 종료해야** 합니다. 이는 항상 가능한 옵션이 아니며, 경우에 따라 시스템이 회사가 종료할 수 없는 프로덕션 서버일 수 있습니다.\
시스템을 종료하는 방법은 **정상 종료**와 **"플러그를 뽑는" 종료**의 **2가지 방법**이 있습니다. 첫 번째 방법은 **프로세스가 정상적으로 종료**되고 **파일 시스템**이 **동기화**되도록 허용하지만, **악성코드**가 **증거를 파괴**할 가능성도 있습니다. "플러그를 뽑는" 접근 방식은 **일부 정보 손실**을 초래할 수 있습니다(메모리 이미지를 이미 가져왔기 때문에 많은 정보가 손실되지 않음) 그리고 **악성코드가 아무것도 할 기회가 없습니다**. 따라서 **악성코드**가 있을 것으로 **의심**되는 경우, 시스템에서 **`sync`** **명령**을 실행하고 플러그를 뽑으십시오.

#### 디스크 이미지 가져오기

**사건과 관련된 어떤 것에 컴퓨터를 연결하기 전에** 반드시 **읽기 전용으로 마운트**될 것인지 확인해야 정보를 수정하지 않도록 하는 것이 중요합니다.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 디스크 이미지 사전 분석

더 이상 데이터가 없는 디스크 이미지를 이미징합니다.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## 알려진 악성코드 검색

### 수정된 시스템 파일

Linux는 시스템 구성 요소의 무결성을 보장하기 위한 도구를 제공하며, 이는 잠재적으로 문제가 있는 파일을 발견하는 데 중요합니다.

- **RedHat 기반 시스템**: 포괄적인 검사를 위해 `rpm -Va`를 사용합니다.
- **Debian 기반 시스템**: 초기 검증을 위해 `dpkg --verify`를 사용한 후, `debsums | grep -v "OK$"` (먼저 `apt-get install debsums`로 `debsums`를 설치한 후)로 문제를 식별합니다.

### 악성코드/루트킷 탐지기

악성코드를 찾는 데 유용할 수 있는 도구에 대해 알아보려면 다음 페이지를 읽어보세요:

{{#ref}}
malware-analysis.md
{{#endref}}

## 설치된 프로그램 검색

Debian 및 RedHat 시스템에서 설치된 프로그램을 효과적으로 검색하려면 시스템 로그 및 데이터베이스를 활용하고 일반 디렉토리에서 수동 검사를 고려하세요.

- Debian의 경우, 패키지 설치에 대한 세부 정보를 가져오기 위해 _**`/var/lib/dpkg/status`**_ 및 _**`/var/log/dpkg.log`**_를 검사하고, `grep`을 사용하여 특정 정보를 필터링합니다.
- RedHat 사용자는 `rpm -qa --root=/mntpath/var/lib/rpm`로 RPM 데이터베이스를 쿼리하여 설치된 패키지를 나열할 수 있습니다.

패키지 관리자 외부에서 수동으로 설치된 소프트웨어를 발견하려면 _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, 및 _**`/sbin`**_과 같은 디렉토리를 탐색하세요. 디렉토리 목록과 시스템 특정 명령을 결합하여 알려진 패키지와 관련이 없는 실행 파일을 식별하고, 모든 설치된 프로그램을 검색하는 데 도움을 줍니다.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## 삭제된 실행 중인 바이너리 복구

/tmp/exec에서 실행된 후 삭제된 프로세스를 상상해 보십시오. 이를 추출하는 것이 가능합니다.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## 자동 시작 위치 검사

### 예약된 작업
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### 서비스

악성 코드가 서비스로 설치될 수 있는 경로:

- **/etc/inittab**: rc.sysinit과 같은 초기화 스크립트를 호출하여 추가적인 시작 스크립트로 안내합니다.
- **/etc/rc.d/** 및 **/etc/rc.boot/**: 서비스 시작을 위한 스크립트를 포함하며, 후자는 구버전 리눅스에서 발견됩니다.
- **/etc/init.d/**: Debian과 같은 특정 리눅스 버전에서 시작 스크립트를 저장하는 데 사용됩니다.
- 서비스는 리눅스 변형에 따라 **/etc/inetd.conf** 또는 **/etc/xinetd/**를 통해 활성화될 수 있습니다.
- **/etc/systemd/system**: 시스템 및 서비스 관리자 스크립트를 위한 디렉토리입니다.
- **/etc/systemd/system/multi-user.target.wants/**: 다중 사용자 실행 수준에서 시작해야 하는 서비스에 대한 링크를 포함합니다.
- **/usr/local/etc/rc.d/**: 사용자 정의 또는 타사 서비스용입니다.
- **\~/.config/autostart/**: 사용자 특정 자동 시작 애플리케이션을 위한 것으로, 사용자 타겟 악성 코드의 은신처가 될 수 있습니다.
- **/lib/systemd/system/**: 설치된 패키지에서 제공하는 시스템 전체 기본 유닛 파일입니다.

### 커널 모듈

리눅스 커널 모듈은 종종 악성 코드에 의해 루트킷 구성 요소로 사용되며, 시스템 부팅 시 로드됩니다. 이러한 모듈에 중요한 디렉토리 및 파일은 다음과 같습니다:

- **/lib/modules/$(uname -r)**: 실행 중인 커널 버전의 모듈을 보유합니다.
- **/etc/modprobe.d**: 모듈 로드를 제어하는 구성 파일을 포함합니다.
- **/etc/modprobe** 및 **/etc/modprobe.conf**: 전역 모듈 설정을 위한 파일입니다.

### 기타 자동 시작 위치

리눅스는 사용자 로그인 시 프로그램을 자동으로 실행하기 위해 다양한 파일을 사용하며, 이는 악성 코드를 숨길 수 있습니다:

- **/etc/profile.d/**\*, **/etc/profile**, 및 **/etc/bash.bashrc**: 모든 사용자 로그인 시 실행됩니다.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, 및 **\~/.config/autostart**: 사용자 특정 파일로, 로그인 시 실행됩니다.
- **/etc/rc.local**: 모든 시스템 서비스가 시작된 후 실행되며, 다중 사용자 환경으로의 전환이 끝났음을 나타냅니다.

## 로그 검사

리눅스 시스템은 다양한 로그 파일을 통해 사용자 활동 및 시스템 이벤트를 추적합니다. 이러한 로그는 무단 접근, 악성 코드 감염 및 기타 보안 사건을 식별하는 데 중요합니다. 주요 로그 파일은 다음과 같습니다:

- **/var/log/syslog** (Debian) 또는 **/var/log/messages** (RedHat): 시스템 전체 메시지 및 활동을 캡처합니다.
- **/var/log/auth.log** (Debian) 또는 **/var/log/secure** (RedHat): 인증 시도, 성공 및 실패한 로그인 기록.
- 관련 인증 이벤트를 필터링하려면 `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log`를 사용합니다.
- **/var/log/boot.log**: 시스템 시작 메시지를 포함합니다.
- **/var/log/maillog** 또는 **/var/log/mail.log**: 이메일 서버 활동을 기록하며, 이메일 관련 서비스를 추적하는 데 유용합니다.
- **/var/log/kern.log**: 오류 및 경고를 포함한 커널 메시지를 저장합니다.
- **/var/log/dmesg**: 장치 드라이버 메시지를 보유합니다.
- **/var/log/faillog**: 실패한 로그인 시도를 기록하여 보안 침해 조사에 도움을 줍니다.
- **/var/log/cron**: 크론 작업 실행을 기록합니다.
- **/var/log/daemon.log**: 백그라운드 서비스 활동을 추적합니다.
- **/var/log/btmp**: 실패한 로그인 시도를 문서화합니다.
- **/var/log/httpd/**: Apache HTTPD 오류 및 접근 로그를 포함합니다.
- **/var/log/mysqld.log** 또는 **/var/log/mysql.log**: MySQL 데이터베이스 활동을 기록합니다.
- **/var/log/xferlog**: FTP 파일 전송을 기록합니다.
- **/var/log/**: 여기에서 예상치 못한 로그를 항상 확인하십시오.

> [!NOTE]
> 리눅스 시스템 로그 및 감사 하위 시스템은 침입 또는 악성 코드 사건에서 비활성화되거나 삭제될 수 있습니다. 리눅스 시스템의 로그는 악의적인 활동에 대한 가장 유용한 정보를 포함하고 있기 때문에, 침입자는 이를 정기적으로 삭제합니다. 따라서 사용 가능한 로그 파일을 검사할 때는 삭제 또는 변조의 징후가 될 수 있는 간격이나 순서가 어긋난 항목을 찾는 것이 중요합니다.

**리눅스는 각 사용자의 명령 기록을 유지합니다**, 저장 위치는 다음과 같습니다:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

또한, `last -Faiwx` 명령은 사용자 로그인 목록을 제공합니다. 알 수 없거나 예상치 못한 로그인을 확인하십시오.

추가 권한을 부여할 수 있는 파일을 확인하십시오:

- 예상치 못한 사용자 권한이 부여되었는지 확인하려면 `/etc/sudoers`를 검토하십시오.
- 예상치 못한 사용자 권한이 부여되었는지 확인하려면 `/etc/sudoers.d/`를 검토하십시오.
- 비정상적인 그룹 구성원 또는 권한을 식별하기 위해 `/etc/groups`를 검사하십시오.
- 비정상적인 그룹 구성원 또는 권한을 식별하기 위해 `/etc/passwd`를 검사하십시오.

일부 앱은 자체 로그를 생성합니다:

- **SSH**: 무단 원격 연결을 위해 _\~/.ssh/authorized_keys_ 및 _\~/.ssh/known_hosts_를 검사하십시오.
- **Gnome Desktop**: Gnome 애플리케이션을 통해 최근에 접근한 파일을 위해 _\~/.recently-used.xbel_를 확인하십시오.
- **Firefox/Chrome**: 의심스러운 활동을 위해 _\~/.mozilla/firefox_ 또는 _\~/.config/google-chrome_에서 브라우저 기록 및 다운로드를 확인하십시오.
- **VIM**: 접근한 파일 경로 및 검색 기록과 같은 사용 세부정보를 위해 _\~/.viminfo_를 검토하십시오.
- **Open Office**: 손상된 파일을 나타낼 수 있는 최근 문서 접근을 확인하십시오.
- **FTP/SFTP**: 무단 파일 전송이 있을 수 있는 _\~/.ftp_history_ 또는 _\~/.sftp_history_의 로그를 검토하십시오.
- **MySQL**: 무단 데이터베이스 활동을 드러낼 수 있는 실행된 MySQL 쿼리를 위해 _\~/.mysql_history_를 조사하십시오.
- **Less**: 본 파일 및 실행된 명령을 포함한 사용 기록을 위해 _\~/.lesshst_를 분석하십시오.
- **Git**: 리포지토리에 대한 변경 사항을 위해 _\~/.gitconfig_ 및 프로젝트 _.git/logs_를 검사하십시오.

### USB 로그

[**usbrip**](https://github.com/snovvcrash/usbrip)는 리눅스 로그 파일(`/var/log/syslog*` 또는 `/var/log/messages*`, 배포판에 따라 다름)을 파싱하여 USB 이벤트 이력 테이블을 구성하는 순수 Python 3로 작성된 작은 소프트웨어입니다.

모든 USB 사용 내역을 아는 것은 흥미롭고, "위반 사건"(목록에 없는 USB 사용)을 찾기 위해 승인된 USB 목록이 있다면 더욱 유용할 것입니다.

### 설치
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 예시
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
더 많은 예제와 정보는 GitHub에서 확인하세요: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 사용자 계정 및 로그인 활동 검토

_**/etc/passwd**_, _**/etc/shadow**_ 및 **보안 로그**에서 비정상적인 이름이나 계정을 확인하고, 알려진 무단 이벤트와 가까운 시기에 생성되거나 사용된 계정을 검토합니다. 또한 가능한 sudo 무차별 대입 공격을 확인합니다.\
또한, _**/etc/sudoers**_ 및 _**/etc/groups**_와 같은 파일에서 사용자에게 부여된 예상치 못한 권한을 확인합니다.\
마지막으로, **비밀번호가 없는** 계정이나 **쉽게 추측할 수 있는** 비밀번호를 가진 계정을 찾아보세요.

## 파일 시스템 검사

### 악성 코드 조사에서 파일 시스템 구조 분석

악성 코드 사건을 조사할 때, 파일 시스템의 구조는 사건의 순서와 악성 코드의 내용을 드러내는 중요한 정보 출처입니다. 그러나 악성 코드 작성자들은 파일 타임스탬프를 수정하거나 데이터 저장을 위해 파일 시스템을 회피하는 등의 분석을 방해하는 기술을 개발하고 있습니다.

이러한 반포렌식 방법에 대응하기 위해서는 다음이 필수적입니다:

- **Autopsy**와 같은 도구를 사용하여 사건 타임라인을 시각화하거나 **Sleuth Kit의** `mactime`을 사용하여 상세한 타임라인 데이터를 통해 철저한 타임라인 분석을 수행합니다.
- 공격자가 사용할 수 있는 셸 또는 PHP 스크립트를 포함할 수 있는 시스템의 $PATH에서 **예상치 못한 스크립트**를 조사합니다.
- **/dev에서 비정상적인 파일**을 검사합니다. 전통적으로 특별한 파일을 포함하지만, 악성 코드 관련 파일이 있을 수 있습니다.
- **".. " (dot dot space)** 또는 **"..^G" (dot dot control-G)**와 같은 이름을 가진 숨겨진 파일이나 디렉토리를 검색하여 악성 콘텐츠를 숨길 수 있습니다.
- 공격자가 악용할 수 있는 권한이 상승된 파일을 찾기 위해 다음 명령어를 사용하여 **setuid root 파일**을 식별합니다: `find / -user root -perm -04000 -print`
- 루트킷이나 트로이 목마의 존재를 나타낼 수 있는 대량 파일 삭제를 감지하기 위해 inode 테이블에서 **삭제 타임스탬프**를 검토합니다.
- 하나의 악성 파일을 식별한 후, 인접한 악성 파일을 찾기 위해 **연속적인 inode**를 검사합니다. 이들은 함께 배치되었을 수 있습니다.
- 악성 코드에 의해 변경될 수 있는 최근 수정된 파일을 찾기 위해 일반 이진 디렉토리 (_/bin_, _/sbin_)를 확인합니다.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> 공격자가 **시간**을 **수정**하여 **파일이 합법적으로 보이게** 할 수 있지만, **inode**는 **수정할 수 없습니다**. 동일한 폴더의 나머지 파일과 **동일한 시간**에 생성 및 수정된 것으로 표시된 **파일**을 발견했지만 **inode**가 **예상보다 크면**, 해당 **파일의 타임스탬프가 수정된 것입니다**.

## 서로 다른 파일 시스템 버전 비교

### 파일 시스템 버전 비교 요약

파일 시스템 버전을 비교하고 변경 사항을 파악하기 위해 간소화된 `git diff` 명령을 사용합니다:

- **새 파일을 찾으려면**, 두 디렉토리를 비교합니다:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **수정된 내용**: 특정 줄을 무시하고 변경 사항을 나열합니다.
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **삭제된 파일을 감지하기 위해**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **필터 옵션** (`--diff-filter`)은 추가된 (`A`), 삭제된 (`D`), 또는 수정된 (`M`) 파일과 같은 특정 변경 사항으로 좁히는 데 도움을 줍니다.
- `A`: 추가된 파일
- `C`: 복사된 파일
- `D`: 삭제된 파일
- `M`: 수정된 파일
- `R`: 이름이 변경된 파일
- `T`: 유형 변경 (예: 파일에서 심볼릭 링크로)
- `U`: 병합되지 않은 파일
- `X`: 알 수 없는 파일
- `B`: 손상된 파일

## 참고 문헌

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **책: Linux 시스템을 위한 악성코드 포렌식 필드 가이드: 디지털 포렌식 필드 가이드**

{{#include ../../banners/hacktricks-training.md}}
