# Volatility - CheatSheet

{{#include ../../../banners/hacktricks-training.md}}

다양한 scan level로 memory analysis를 자동화하고 여러 Volatility3 plugin을 병렬로 실행하는 tool이 필요하다면 autoVolatility3를 사용할 수 있습니다:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/)
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
**빠르고 강력한** 방식으로 여러 Volatility plugins를 병렬로 실행하려면 다음을 사용할 수 있습니다: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## 설치

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{{#tabs}}
{{#tab name="Method1"}}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{{#endtab}}

{{#tab name="Method 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Volatility 명령어

공식 문서는 [Volatility 명령어 참조](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)에서 확인할 수 있습니다.

### “list” 플러그인과 “scan” 플러그인 비교

Volatility에는 두 가지 주요 플러그인 접근 방식이 있으며, 플러그인 이름에 반영되는 경우가 많습니다. “list” 플러그인은 Windows Kernel 구조를 탐색하여 프로세스(`_EPROCESS` 구조체의 연결 리스트를 메모리에서 찾고 순회), OS 핸들(핸들 테이블을 찾고 나열하며 발견된 포인터를 역참조하는 등)과 같은 정보를 가져옵니다. 이는 예를 들어 프로세스 목록을 요청했을 때 Windows API가 동작하는 방식과 거의 동일합니다.

따라서 “list” 플러그인은 매우 빠르지만, malware에 의한 조작에도 Windows API와 동일하게 취약합니다. 예를 들어 malware가 DKOM을 사용하여 `_EPROCESS` 연결 리스트에서 프로세스의 연결을 해제하면, 해당 프로세스는 Task Manager에도 나타나지 않고 pslist에도 나타나지 않습니다.

반면 “scan” 플러그인은 특정 구조체로 역참조했을 때 의미가 있을 수 있는 항목을 메모리에서 carving하는 것과 유사한 방식으로 접근합니다. 예를 들어 `psscan`은 메모리를 읽고 그 안에서 `_EPROCESS` 객체를 만들려고 시도합니다(pool-tag scanning을 사용하며, 이는 관심 있는 구조체의 존재를 나타내는 4바이트 문자열을 검색하는 방식입니다). 이 방식의 장점은 이미 종료된 프로세스도 찾아낼 수 있다는 것입니다. 또한 malware가 `_EPROCESS` 연결 리스트를 변조하더라도 해당 구조체는 프로세스 실행을 위해 여전히 존재해야 하므로, 플러그인은 메모리에 남아 있는 구조체를 찾아낼 수 있습니다. 단점은 “scan” 플러그인이 “list” 플러그인보다 다소 느리고, 때때로 false positive를 생성할 수 있다는 것입니다(너무 오래전에 종료되어 구조체의 일부가 다른 작업에 의해 덮어쓰인 프로세스 등).

출처: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## OS 프로필

### Volatility3

readme에 설명된 것처럼, 지원하려는 **OS의 symbol table**을 _volatility3/volatility/symbols_ 내부에 넣어야 합니다.\
다양한 운영 체제용 symbol table pack은 다음 위치에서 **download**할 수 있습니다.

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

다음 명령을 실행하여 지원되는 profile 목록을 확인할 수 있습니다.
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
**새로 다운로드한 프로필**(예: linux 프로필)을 사용하려면 다음 폴더 구조를 어딘가에 생성해야 합니다: _plugins/overlays/linux_ 그리고 프로필이 포함된 zip 파일을 이 폴더 안에 넣습니다. 그런 다음 다음을 사용하여 프로필 번호를 확인합니다:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)에서 **Linux 및 Mac 프로필을 다운로드**할 수 있습니다.

이전 부분에서 프로필 이름이 `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`임을 확인할 수 있으며, 이를 사용해 다음과 같은 명령을 실행할 수 있습니다:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### 프로필 확인
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo와 kdbgscan의 차이점**

[**여기에서**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): 단순히 profile 제안만 제공하는 imageinfo와 달리, **kdbgscan**은 올바른 profile과 올바른 KDBG 주소(여러 개가 존재하는 경우)를 확실하게 식별하도록 설계되었습니다. 이 plugin은 Volatility profile에 연결된 KDBGHeader 시그니처를 검색하고 sanity checks를 적용하여 false positive를 줄입니다. 수행할 수 있는 출력의 상세 수준과 sanity checks의 수는 Volatility가 DTB를 찾을 수 있는지에 따라 달라집니다. 따라서 올바른 profile을 이미 알고 있거나 imageinfo에서 profile 제안을 받은 경우에는 해당 profile을 사용해야 합니다.<sup>[[1]](#references)</sup>

항상 **kdbgscan이 찾은 프로세스 수**를 확인하세요. 경우에 따라 imageinfo와 kdbgscan이 적합한 **profile**을 **두 개 이상** 찾을 수 있지만, **유효한 profile에만 프로세스와 관련된 항목이 표시됩니다**(프로세스를 추출하려면 올바른 KDBG 주소가 필요하기 때문입니다).<sup>[[1]](#references)</sup>
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**kernel debugger block**은 Volatility에서 **KDBG**라고 하며, Volatility와 다양한 debugger가 수행하는 forensic 작업에 매우 중요합니다. `KdDebuggerDataBlock`으로 식별되고 `_KDDEBUGGER_DATA64` 타입인 이 구조체에는 `PsActiveProcessHead`와 같은 필수 참조가 포함되어 있습니다. 이 특정 참조는 process list의 head를 가리키므로 모든 process를 나열할 수 있으며, 이는 철저한 memory analysis의 기본입니다.<sup>[[2]](#references)</sup>

## OS Information
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
`banners.Banners` plugin은 dump에서 **linux banners를 찾기 위해 vol3에서** 사용할 수 있습니다.

## Hashes/Passwords

SAM hashes, [domain cached credentials](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) 및 [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets)을 추출합니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{{#endtab}}
{{#endtabs}}

## 메모리 덤프

프로세스의 메모리 덤프는 프로세스의 현재 상태에 대한 **모든 정보를 추출**합니다. **procdump** 모듈은 **코드**만 **추출**합니다.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## 프로세스

### 프로세스 목록

**의심스러운** 프로세스(이름 기준) 또는 **예상하지 못한** 자식 **프로세스**(예: iexplorer.exe의 자식인 cmd.exe)를 찾아보세요.\
숨겨진 프로세스를 식별하기 위해 pslist의 결과를 psscan의 결과와 **비교**해 보는 것도 유용할 수 있습니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{{#endtab}}
{{#endtabs}}

### proc 덤프

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

### 명령줄

의심스러운 명령이 실행되었는가?

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{{#endtab}}
{{#endtabs}}

`cmd.exe`에서 실행된 명령은 **`conhost.exe`**(Windows 7 이전 시스템에서는 **`csrss.exe`**)에서 관리됩니다. 따라서 메모리 덤프를 얻기 전에 공격자가 **`cmd.exe`**를 종료하더라도 **`conhost.exe`**의 메모리에서 세션의 명령 기록을 복구할 수 있습니다. 이를 위해 콘솔의 모듈에서 비정상적인 활동이 감지되면 관련 **`conhost.exe`** 프로세스의 메모리를 덤프해야 합니다. 그런 다음 이 덤프 내에서 **strings**를 검색하면 세션에서 사용된 명령줄을 추출할 수 있습니다.

### 환경

실행 중인 각 프로세스의 환경 변수를 가져옵니다. 흥미로운 값이 있을 수 있습니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{{#endtab}}
{{#endtabs}}

### Token 권한

예상치 못한 서비스에서 권한 토큰을 확인합니다.\
일부 권한 토큰을 사용하는 프로세스를 나열하는 것이 유용할 수 있습니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}
{{#endtabs}}

### SIDs

프로세스가 소유한 각 SSID를 확인합니다.\
privileges SID를 사용하는 프로세스와 일부 service SID를 사용하는 프로세스를 나열하는 것이 유용할 수 있습니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{{#endtab}}
{{#endtabs}}

### 핸들

어떤 다른 파일, 키, 스레드, 프로세스...에 **프로세스가 핸들을 가지고 있는지**(열어 둔 상태인지) 확인할 때 유용합니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{{#endtab}}
{{#endtabs}}

### DLL

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{{#endtab}}
{{#endtabs}}

### 프로세스별 Strings

Volatility를 사용하면 특정 String이 어느 프로세스에 속하는지 확인할 수 있습니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{{#endtab}}
{{#endtabs}}

또한 yarascan 모듈을 사용하여 프로세스 내부의 문자열을 검색할 수 있습니다:

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{{#endtab}}
{{#endtabs}}

### UserAssist

**Windows**는 레지스트리의 **UserAssist keys**라는 기능을 사용하여 실행한 프로그램을 추적합니다. 이러한 키에는 각 프로그램이 실행된 횟수와 마지막으로 실행된 시점이 기록됩니다.<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{{#endtab}}
{{#endtabs}}

## 서비스

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## 네트워크

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{{#endtab}}
{{#endtabs}}

## Registry hive

### 사용 가능한 hive 출력

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{{#endtab}}
{{#endtabs}}

### 값 가져오기

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{{#endtab}}
{{#endtabs}}

### 덤프
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## 파일 시스템

### 마운트

{{#tabs}}
{{#tab name="vol3"}}
```bash
#See vol2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{{#endtab}}
{{#endtabs}}

### 스캔/덤프

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{{#endtab}}
{{#endtabs}}

### Master File Table

{{#tabs}}
{{#tab name="vol3"}}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{{#endtab}}
{{#endtabs}}

**NTFS 파일 시스템**은 _master file table_ (MFT)이라는 중요한 구성 요소를 사용합니다. 이 테이블에는 MFT 자체를 포함하여 볼륨의 모든 파일에 대한 항목이 하나 이상 포함됩니다. **크기, 타임스탬프, 권한, 실제 데이터**와 같은 각 파일의 중요한 세부 정보는 MFT 항목 자체 또는 MFT 외부 영역에 저장되며, 해당 항목에서 이를 참조합니다. 자세한 내용은 [공식 문서](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)에서 확인할 수 있습니다.<sup>[[4]](#references)</sup>

### SSL 키/인증서

{{#tabs}}
{{#tab name="vol3"}}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## Malware

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{{#endtab}}
{{#endtabs}}

### yara를 사용한 Scanning

github에서 모든 yara malware rules를 다운로드하고 병합하려면 다음 script를 사용하세요: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ directory를 생성하고 script를 실행하세요. 그러면 malware에 대한 모든 yara rules가 포함된 _**malware_rules.yar**_ 파일이 생성됩니다.

{{#tabs}}
{{#tab name="vol3"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{{#endtab}}
{{#endtabs}}

## 기타

### 외부 plugins

외부 plugins를 사용하려면 해당 plugins와 관련된 폴더가 사용되는 첫 번째 parameter인지 확인하세요.

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{{#endtab}}
{{#endtabs}}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)에서 다운로드합니다.
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### 뮤텍스

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{{#endtab}}
{{#endtabs}}

### 심볼릭 링크

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{{#endtab}}
{{#endtabs}}

### Bash

**bash history를 메모리에서 읽을 수 있습니다.** _.bash_history_ 파일을 dump할 수도 있지만, 비활성화되어 있었다면 이 Volatility module을 사용할 수 있어 다행일 것입니다.

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp linux.bash.Bash
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{{#endtab}}
{{#endtabs}}

### 타임라인

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{{#endtab}}
{{#endtabs}}

### 드라이버

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{{#endtab}}
{{#endtabs}}

### 클립보드 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE 기록 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### notepad 텍스트 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### 스크린샷
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record(MBR)**는 다양한 [파일 시스템](https://en.wikipedia.org/wiki/File_system)으로 구성된 저장 매체의 논리 파티션을 관리하는 데 중요한 역할을 합니다. MBR에는 파티션 레이아웃 정보뿐만 아니라 부트 로더로 동작하는 실행 가능한 코드도 포함되어 있습니다. 이 부트 로더는 OS의 second-stage 로딩 프로세스를 직접 시작하거나([second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader) 참고), 각 파티션의 [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record)(VBR)와 함께 작동합니다. 자세한 내용은 [MBR Wikipedia 페이지](https://en.wikipedia.org/wiki/Master_boot_record)를 참고하세요.<sup>[[5]](#references)</sup>

## 참고 자료

- [1] [Volatility, my own cheatsheet (Part 1): Image Identification](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Finding the Kernel Debugger Block](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table (Local File Systems) - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI-based PC, protective MBR: what is it? - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial: Volatility plugins for malware analysis](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
