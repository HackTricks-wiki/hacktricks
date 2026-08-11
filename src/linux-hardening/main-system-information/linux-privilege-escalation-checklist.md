# Linux 권한 상승 체크리스트

{{#include ../../banners/hacktricks-training.md}}

# 체크리스트 - Linux 권한 상승



### **Linux 로컬 권한 상승 벡터를 찾는 최고의 도구:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [시스템 정보](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 정보** 수집
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) 확인, **writable folder**가 있는가?
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) 확인, 민감한 정보가 있는가?
- [ ] **scripts를 사용하여** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) 검색 (DirtyCow?)
- [ ] kernel PoC를 실행하기 전에 `uname -r`뿐만 아니라 실제 **prerequisites**를 확인한다: 아키텍처, 필요한 `CONFIG_*` 옵션/modules, namespace 생성 및 활성화된 완화 기능. 예를 들어 `unshare -Urn true`를 사용하여 user/network namespace 사용 가능 여부를 테스트한다. 최신 netfilter exploits에는 `CONFIG_USER_NS`, 권한 없는 user namespaces 및 `CONFIG_NF_TABLES`가 필요할 수 있다.<sup>[[3]](#references)</sup>
- [ ] [**sudo version**이 취약한지](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **확인**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module 및 module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) 검토: `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement 및 `modules_disabled`.
- [ ] helper path를 수정하거나 trigger할 수 있는 경우 [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) 확인
- [ ] writable `.ko*` 파일 및 `modules.*` metadata를 포함하여 [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) 확인
- [ ] 추가 시스템 enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [추가 defenses 열거](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mounted** drives 나열
- [ ] **unmounted drive가 있는가?**
- [ ] **fstab에 creds가 있는가?**

### [**설치된 Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] [**유용한 software**](../linux-basics/linux-privilege-escalation/index.html#useful-software)가 **설치되어 있는지 확인**
- [ ] [**취약한 software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)가 **설치되어 있는지 확인**
- [ ] Debian/Ubuntu에서 **needrestart interpreter scanning**이 설치 및 활성화되어 있는지 확인한다: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. 취약한 builds는 APT 또는 `unattended-upgrades`가 needrestart를 root로 호출할 때 attacker-controlled `PYTHONPATH`/`RUBYLIB`를 재사용하거나, `/proc/<pid>/exe`에 race condition을 일으키거나, attacker-controlled Perl paths를 scan하여 privilege boundary를 넘었다.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **알 수 없는 software가 실행 중인가?**
- [ ] 어떤 software가 **필요한 것보다 높은 privileges로 실행 중인가?**
- [ ] **실행 중인 processes의 exploits** 검색 (특히 실행 중인 version)
- [ ] 실행 중인 process의 **binary를 수정**할 수 있는가?
- [ ] **processes를 monitor**하고 흥미로운 process가 자주 실행되는지 확인
- [ ] 일부 흥미로운 **process memory를 read**할 수 있는가? (passwords가 저장될 수 있는 곳)

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 일부 cron에 의해 [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)이 수정되고 있으며 해당 PATH에 **write**할 수 있는가?
- [ ] cron job에 [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)가 있는가?
- [ ] 일부 [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)가 **실행 중**이거나 **modifiable folder** 안에 있는가?
- [ ] 어떤 **script**가 [**매우 **자주 **실행**되고 있거나 실행될 수 있음](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)을 발견했는가? (1, 2 또는 5분마다)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **writable .service** 파일이 있는가?
- [ ] **service에 의해 실행되는 writable binary**가 있는가?
- [ ] root unit이 참조하는 writable **helper, config 또는 environment file**이 있는가 (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? `systemctl cat <unit>`을 사용하여 merged unit을 검사하고 [service/socket file abuse](../interesting-files-permissions/write-to-root.md)를 검토한다.
- [ ] **systemd PATH에 writable folder**가 있는가?
- [ ] `/etc/systemd/system/<unit>.d/*.conf`에 `ExecStart`/`User`를 override할 수 있는 **writable systemd unit drop-in**이 있는가?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **writable timer**가 있는가?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **writable .socket** 파일이 있는가?
- [ ] 어떤 **socket과 communicate**할 수 있는가?
- [ ] 흥미로운 정보가 있는 **HTTP sockets**가 있는가?
- [ ] `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` 또는 kubelet endpoint와 같은 [**container-runtime 또는 node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)에 access할 수 있는가? 일반적인 CLI가 없어도 raw HTTP/gRPC API를 테스트한다.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] 어떤 **D-Bus와 communicate**할 수 있는가?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 현재 위치를 파악하기 위해 network 열거
- [ ] 시스템 내부에서 shell을 획득하기 전에는 access할 수 없었던 **open ports**가 있는가?
- [ ] `tcpdump`를 사용하여 traffic을 **sniff**할 수 있는가?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] 일반적인 users/groups **열거**
- [ ] **매우 큰 UID**를 가지고 있는가? **machine**이 **취약한가?**
- [ ] 자신이 속한 [**group 덕분에 privileges를 상승**](../user-information/interesting-groups-linux-pe/index.html)시킬 수 있는가?
- [ ] **Clipboard** data가 있는가?
- [ ] Password Policy?
- [ ] 이전에 발견한 모든 **known password**를 사용하여 가능한 **각각의 user**로 **login**을 시도한다. password 없이도 login을 시도한다.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH의 일부 folder에 write privileges**가 있다면 privileges를 상승시킬 수 있음

### [SUDO 및 SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] `sudo`로 **어떤 command든 실행**할 수 있는가? 이를 사용하여 root로 무엇이든 READ, WRITE 또는 EXECUTE할 수 있는가? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l`이 `sudoedit`를 허용한다면, 취약한 version (`sudo -V` < 1.9.12p2)에서 `SUDO_EDITOR`/`VISUAL`/`EDITOR`를 통한 **sudoedit argument injection** (CVE-2023-22809)을 확인하여 임의의 파일을 edit할 수 있는지 검사한다. 예: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] **exploitable SUID binary**가 있는가? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** commands가 **path**로 **제한**되어 있는가? 제한을 **bypass**할 수 있는가](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**path가 지정되지 않은 Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)가 있는가?
- [ ] [**path를 지정하는 SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)가 있는가? Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] writable folder에 있는 SUID binary의 [**.so library 누락**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)이 있는가?
- [ ] [**SUID RPATH/RUNPATH 또는 writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)가 있는가?
- [ ] [**SUDO tokens를 사용할 수 있는가**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**SUDO token을 생성**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)할 수 있는가?
- [ ] [**sudoers files를 read 또는 modify**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)할 수 있는가?
- [ ] [**/etc/ld.so.conf.d/를 modify**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)할 수 있는가?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 어떤 binary에든 **예상치 못한 capability**가 있는가?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 어떤 file에든 **예상치 못한 ACL**이 있는가?

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 민감한 data를 Read할 수 있는가? privesc를 위해 Write할 수 있는가?
- [ ] **passwd/shadow files** - 민감한 data를 Read할 수 있는가? privesc를 위해 Write할 수 있는가?
- [ ] 민감한 data가 있는 **일반적으로 흥미로운 folders** 확인
- [ ] **이상한 위치/소유 files,** access하거나 executable files를 alter할 수 있음
- [ ] 최근 몇 분 내 **Modified**된 항목
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH의 Script/Binaries**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **passwords를 포함하는 것으로 알려진 files**: **Linpeas** 및 **LaZagne** 사용
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] 임의의 commands를 실행하도록 **python library를 Modify**할 수 있는가?
- [ ] **log files를 modify**할 수 있는가? **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/**를 **modify**할 수 있는가? Centos/Redhat exploit
- [ ] [**ini, int.d, systemd 또는 rc.d files에 write**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)할 수 있는가?

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS를 abuse하여 privileges를 상승**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)시킬 수 있는가?
- [ ] [**restrictive shell에서 escape**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)해야 하는가?



## References

- [1] [Sudo advisory: sudoedit 임의 파일 편집](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart의 LPEs](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
