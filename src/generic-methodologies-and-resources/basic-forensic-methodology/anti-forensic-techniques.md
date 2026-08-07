# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

공격자는 탐지를 피하기 위해 **파일의 timestamp를 변경**하려 할 수 있습니다.\
MFT 내부의 `$STANDARD_INFORMATION` __ 및 __ `$FILE_NAME` attributes에서 timestamp를 확인할 수 있습니다.

두 attributes에는 각각 4개의 timestamp가 있습니다: **Modification**, **access**, **creation**, **MFT registry modification** (MACE 또는 MACB).

**Windows explorer** 및 기타 도구는 **`$STANDARD_INFORMATION`**의 정보를 표시합니다.

### TimeStomp - Anti-forensic Tool

이 tool은 **`$STANDARD_INFORMATION`** 내부의 timestamp 정보를 **수정**하지만, **`$FILE_NAME`** 내부의 정보는 **수정하지 않습니다**. 따라서 **의심스러운** **activity**를 **식별**할 수 있습니다.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal)은 volume의 변경 사항을 추적하는 NTFS (Windows NT file system)의 기능입니다. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool을 사용하면 이러한 변경 사항을 검사할 수 있습니다.

![TimeStomp - Anti-forensic Tool - Usnjrnl: **USN Journal** (Update Sequence Number Journal)은 volume의 변경 사항을 추적하는 NTFS (Windows NT file system)의 기능입니다. ...](<../../images/image (801).png>)

이전 이미지는 **tool**에서 표시한 **output**이며, 파일에 일부 **변경이 수행되었음**을 확인할 수 있습니다.

### $LogFile

[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)이라고 알려진 process를 통해 **file system에 대한 모든 metadata 변경 사항이 기록됩니다**. 기록된 metadata는 NTFS file system의 root directory에 있는 `**$LogFile**`이라는 파일에 저장됩니다. [LogFileParser](https://github.com/jschicht/LogFileParser)와 같은 tool을 사용하여 이 파일을 parse하고 변경 사항을 식별할 수 있습니다.

![Usnjrnl - $LogFile: **file system에 대한 모든 metadata 변경 사항이 기록됩니다**. 기록된 metadata는 NTFS file system의 root...](<../../images/image (137).png>)

다시 말해, tool의 output에서 **일부 변경이 수행되었음**을 확인할 수 있습니다.

동일한 tool을 사용하면 timestamp가 **언제 수정되었는지** 식별할 수 있습니다:

![Usnjrnl - $LogFile: 동일한 tool을 사용하면 timestamp가 언제 수정되었는지 식별할 수 있습니다](<../../images/image (1089).png>)

- CTIME: 파일의 creation time
- ATIME: 파일의 modification time
- MTIME: 파일의 MFT registry modification
- RTIME: 파일의 access time

### `$STANDARD_INFORMATION` 및 `$FILE_NAME` 비교

의심스러운 수정 파일을 식별하는 또 다른 방법은 두 attributes의 시간을 비교하여 **mismatch**를 찾는 것입니다.

### Nanoseconds

**NTFS** timestamp의 **precision**은 **100 nanoseconds**입니다. 따라서 2010-10-10 10:10:**00.000:0000과 같은 timestamp를 가진 파일은 매우 의심스럽습니다**.

### SetMace - Anti-forensic Tool

이 tool은 `$STARNDAR_INFORMATION` 및 `$FILE_NAME` 두 attributes를 모두 수정할 수 있습니다. 그러나 Windows Vista부터는 이 정보를 수정하려면 live OS가 필요합니다.

## Data Hiding

NFTS는 cluster와 최소 information size를 사용합니다. 즉, 파일이 cluster 하나와 절반을 사용한다면, **나머지 절반은** 파일이 삭제될 때까지 **절대 사용되지 않습니다**. 따라서 이 slack space에 **data를 숨길 수 있습니다**.

slacker와 같이 이 "hidden" space에 data를 숨길 수 있는 tool이 있습니다. 그러나 `$logfile` 및 `$usnjrnl`을 분석하면 일부 data가 추가되었음을 확인할 수 있습니다:

![SetMace - Anti-forensic Tool - Data Hiding: slacker와 같이 이 "hidden" space에 data를 숨길 수 있는 tool이 있습니다. 그러나 $logfile 및 $usnjrnl을 분석하면...](<../../images/image (1060).png>)

그런 다음 FTK Imager와 같은 tool을 사용하여 slack space를 복구할 수 있습니다. 이러한 종류의 tool은 content를 obfuscated 상태 또는 심지어 encrypted 상태로 저장할 수 있다는 점에 유의해야 합니다.

## UsbKill

USB port에서 변경 사항이 감지되면 **computer를 종료하는** tool입니다.\
이를 발견하는 방법은 실행 중인 process를 검사하고 **실행 중인 각 python script를 검토**하는 것입니다.

## Live Linux Distributions

이러한 distro는 **RAM** memory 내부에서 **실행됩니다**. 이를 탐지하는 유일한 방법은 **NTFS file-system이 write permissions로 mount된 경우**입니다. read permissions만으로 mount되어 있다면 intrusion을 탐지할 수 없습니다.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

여러 Windows logging method를 disable하여 forensic investigation을 훨씬 어렵게 만들 수 있습니다.

### Disable Timestamps - UserAssist

이는 사용자가 각 executable을 실행한 날짜와 시간을 유지하는 registry key입니다.

UserAssist를 disable하려면 두 단계가 필요합니다:

1. 두 registry key `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 및 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`를 모두 zero로 설정하여 UserAssist를 disable하려는 것을 나타냅니다.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`와 같은 형태의 registry subtree를 삭제합니다.

### Disable Timestamps - Prefetch

이는 Windows system의 performance 향상을 위해 실행된 application에 대한 정보를 저장합니다. 그러나 forensic practice에도 유용할 수 있습니다.

- `regedit` 실행
- file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` 선택
- `EnablePrefetcher` 및 `EnableSuperfetch`를 모두 마우스 오른쪽 버튼으로 클릭
- 각각에서 Modify를 선택하여 값을 1 (또는 3)에서 0으로 변경
- Restart

### Disable Timestamps - Last Access Time

Windows NT server에서 NTFS volume의 folder를 열 때마다 system은 각 listed folder의 **timestamp field를 update**하며, 이를 last access time이라고 합니다. 많이 사용되는 NTFS volume에서는 performance에 영향을 줄 수 있습니다.

1. Registry Editor (Regedit.exe)를 엽니다.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`으로 이동합니다.
3. `NtfsDisableLastAccessUpdate`를 찾습니다. 존재하지 않는 경우 이 DWORD를 추가하고 값을 1로 설정하여 process를 disable합니다.
4. Registry Editor를 닫고 server를 reboot합니다.

### Delete USB History

모든 **USB Device Entries**는 Windows Registry의 **USBSTOR** registry key에 저장됩니다. 이 key에는 USB Device를 PC 또는 Laptop에 연결할 때마다 생성되는 sub key가 포함되어 있습니다. 이 key는 H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`에서 찾을 수 있습니다. **이를 삭제하면** USB history가 삭제됩니다.\
또한 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool을 사용하여 해당 항목이 삭제되었는지 확인할 수 있으며 (또한 삭제할 수 있습니다).

USB에 대한 정보를 저장하는 또 다른 파일은 `C:\Windows\INF` 내부의 `setupapi.dev.log`입니다. 이 파일도 삭제해야 합니다.

### Disable Shadow Copies

`vssadmin list shadowstorage`를 사용하여 shadow copy를 **list**합니다.\
`vssadmin delete shadow`를 실행하여 **삭제**합니다.

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)에 제시된 단계를 따라 GUI를 통해 삭제할 수도 있습니다.

shadow copy를 disable하려면 [여기의 steps](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)를 따릅니다:

1. Windows start button을 클릭한 후 text search box에 "services"를 입력하여 Services program을 엽니다.
2. 목록에서 "Volume Shadow Copy"를 찾아 선택한 다음, 마우스 오른쪽 버튼을 클릭하여 Properties에 접근합니다.
3. "Startup type" drop-down menu에서 Disabled를 선택한 후 Apply 및 OK를 클릭하여 변경 사항을 confirm합니다.

registry의 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`에서 shadow copy에 복사할 file을 수정하는 configuration도 가능합니다.

### Overwrite deleted files

- **Windows tool**인 `cipher /w:C`를 사용할 수 있습니다. 이 명령은 C drive 내부의 사용 가능한 unused disk space에서 모든 data를 제거하도록 cipher에 지시합니다.
- [**Eraser**](https://eraser.heidi.ie)와 같은 tool을 사용할 수도 있습니다.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs"를 Expand --> 각 category를 마우스 오른쪽 버튼으로 클릭하고 "Clear Log" 선택
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- services section에서 "Windows Event Log" service를 disable
- `WEvtUtil.exec clear-log` 또는 `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

최근 버전의 Windows 10/11 및 Windows Server는
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106)에 **풍부한 PowerShell forensic artifact**를 저장합니다.
공격자는 이를 on-the-fly로 disable하거나 wipe할 수 있습니다:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
방어자는 해당 레지스트리 키의 변경과 대량의 PowerShell 이벤트 제거를 모니터링해야 합니다.

### ETW (Event Tracing for Windows) Patch

Endpoint security 제품은 ETW에 크게 의존합니다. 2024년에 널리 사용된 evasion 방법은 메모리에서
`ntdll!EtwEventWrite`/`EtwEventWriteFull`을 patch하여 모든 ETW 호출이 이벤트를 생성하지 않고
`STATUS_SUCCESS`를 반환하도록 하는 것입니다:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (예: `EtwTiSwallow`)는 PowerShell 또는 C++에서 동일한 primitive를 구현합니다.  
패치가 **process-local**이므로 다른 프로세스에서 실행 중인 EDR은 이를 놓칠 수 있습니다.  
Detection: 메모리의 `ntdll`과 디스크의 `ntdll`을 비교하거나 user-mode 진입 전에 hook합니다.

### Alternate Data Streams (ADS) Revival

2023년의 Malware campaign(예: **FIN12** loaders)에서는 traditional scanner의 감시를 피하기 위해 ADS 내부에 second-stage binaries를 staging하는 사례가 확인되었습니다:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *`, 또는 Sysinternals의 `streams64.exe`로 stream을 열거합니다.
호스트 파일을 FAT/exFAT 또는 SMB를 통해 복사하면 hidden stream이 제거되므로, 조사관이
payload를 복구하는 데 사용할 수 있습니다.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver는 이제 ransomware 침투에서 **anti-forensics**를 위해
일상적으로 사용됩니다.
오픈 소스 도구 **AuKill**은 서명되었지만 취약한 driver(`procexp152.sys`)를 로드하여
암호화 및 로그 파괴 **전에** EDR과 forensic sensor를 suspend하거나 terminate합니다:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
드라이버는 이후 제거되어 최소한의 artifact만 남습니다.<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist(HVCI/SAC)을 활성화하고,
user-writable paths에서 kernel-service가 생성되는 경우 alert를 발생시킵니다.

---

## Linux Anti-Forensics: Self-Patching 및 Cloud C2 (2023–2025)

### 탐지를 줄이기 위해 침해된 service를 self-patching하기 (Linux)
공격자는 재-exploitation을 방지하고 vulnerability 기반 탐지를 억제하기 위해 service를 exploit한 직후 점점 더 자주 “self-patch”합니다. 이는 취약한 component를 최신 legitimate upstream binaries/JARs로 교체하여 scanner에는 host가 patched된 것으로 보고되도록 하면서 persistence와 C2는 유지하는 방식입니다.<sup>[[3]](#references)</sup>

예시: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation 단계에서 공격자는 Maven Central(repo1.maven.org)에서 legitimate JARs를 가져오고, ActiveMQ install에 있는 취약한 JARs를 삭제한 뒤 broker를 restart했습니다.
- 이를 통해 초기 RCE는 차단하면서도 다른 footholds(cron, SSH config 변경, 별도의 C2 implants)는 유지했습니다.

운영 예시(설명용)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forensic/hunting 팁
- 예약되지 않은 binary/JAR 교체 여부를 확인하기 위해 service directories를 검토:
- Debian/Ubuntu: `dpkg -V activemq`를 실행하고 repo mirrors와 file hashes/paths를 비교.
- 디스크에 존재하지만 package manager가 소유하지 않는 JAR version이나, 별도로 업데이트된 symbolic links를 확인.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`를 사용해 ctime/mtime을 compromise window와 대조.
- Shell history/process telemetry: initial exploitation 직후 `repo1.maven.org` 또는 기타 artifact CDN으로 `curl`/`wget`을 실행한 흔적.
- Change management: patched version이 존재한다는 사실뿐 아니라 누가, 왜 “patch”를 적용했는지 검증.

### Bearer token 및 anti-analysis stager를 사용하는 Cloud-service C2
관찰된 tradecraft는 여러 long-haul C2 경로와 anti-analysis packaging을 결합했음:<sup>[[3]](#references)</sup>
- Sandboxing과 static analysis를 방해하기 위한 password-protected PyInstaller ELF loader (예: encrypted PYZ, `/_MEI*` 하위의 temporary extraction).
- Indicators: `strings`에서 `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` 등의 문자열이 탐지됨.
- Runtime artifacts: `/tmp/_MEI*` 또는 사용자 지정 `--runtime-tmpdir` paths로 extraction.
- Hardcoded OAuth Bearer token을 사용하는 Dropbox 기반 C2
- Network markers: `Authorization: Bearer <token>`과 함께 `api.dropboxapi.com` / `content.dropboxapi.com`.
- 일반적으로 file sync를 수행하지 않는 server workload에서 Dropbox domain으로 나가는 HTTPS를 proxy/NetFlow/Zeek/Suricata에서 hunt.
- Tunneling을 통한 parallel/backup C2 (예: Cloudflare Tunnel `cloudflared`)를 사용해 한 channel이 차단되어도 control을 유지.
- Host IOCs: `cloudflared` processes/units, `~/.cloudflared/*.json`의 config, Cloudflare edge로 나가는 outbound 443.

### Access를 유지하기 위한 Persistence 및 “hardening rollback” (Linux examples)
Attackers는 durable access paths와 self-patching을 자주 결합함:<sup>[[3]](#references)</sup>
- Cron/Anacron: 주기적 execution을 위해 각 `/etc/cron.*/` directory의 `0anacron` stub을 수정.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root login을 활성화하고 low-privileged account의 default shell을 변경.
- Root login enablement hunt:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes"와 같은 값 또는 지나치게 permissive한 설정을 flag
```
- System account (예: `games`)의 suspicious interactive shell hunt:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Cloud C2에도 contact하는, random short-named beacon artifact (8개의 alphabetic characters)가 디스크에 drop됨:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders는 이러한 artifacts를 external exposure 및 service patching events와 대조하여 initial exploitation을 숨기기 위해 사용된 anti-forensic self-remediation을 밝혀내야 함.

## References

- [1] [Sophos X-Ops – AuKill: EDR 비활성화를 위한 weaponized vulnerable driver (2023년 3월)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth를 위한 EtwEventWrite patching: Detection & Hunting (2024년 6월)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence를 위한 patching: DripDropper Linux malware가 cloud를 통해 이동하는 방식](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
