# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper는 실행 파일이나 스크립트를 Windows Installer (`.msi`) 파일로 패키징할 수 있습니다. 무료 버전을 다운로드해 실행한 다음, 패키징할 실행 파일을 선택합니다.<sup>[[3]](#references)</sup> 여러 명령을 순서대로 실행하려면 `cmd.exe`를 패키징하는 대신 입력 파일로 `.bat` 파일을 선택합니다.<sup>[[1]](#references)</sup>

![MSI Wrapper에서 원본 실행 파일 또는 배치 스크립트 선택](<../../images/image (417).png>)

실행 컨텍스트와 기타 설치 프로그램 속성을 신중하게 설정합니다.

![MSI Wrapper에서 애플리케이션 ID 및 보안 컨텍스트 설정](<../../images/image (312).png>)

![MSI Wrapper에서 설치 프로그램 속성 설정](<../../images/image (346).png>)

![MSI Wrapper의 빌드 설정 검토](<../../images/image (1072).png>)

사용자 지정 바이너리를 패키징할 때 이러한 값을 변경할 수 있습니다.

마법사의 나머지 페이지를 진행한 다음 **Build**를 선택해 설치 프로그램을 생성합니다.<sup>[[1]](#references)</sup>

## 래핑된 명령의 실행 컨텍스트 확인

테스트 패키지에서는 MSI의 권한 상승 설정이 자식 프로세스에도 적용된다고 가정하지 말고, token을 기록하는 `.bat` 파일을 래핑합니다.<sup>[[4]](#references)</sup> 마법사에서 **User** 대신 **System** 보안 컨텍스트를 선택하고, 해당 경로를 사용하려는 경우 컴퓨터 단위의 권한 상승 설치를 선택합니다.<sup>[[5]](#references)</sup> **System** 옵션은 권한 부여를 우회하지 않습니다. 비관리자에게는 [두 정책의 `AlwaysInstallElevated` 잘못된 구성](index.html#alwaysinstallelevated) 또는 권한 있는 설치 프로그램 워크플로와 같은 권한 상승 설치 경로가 여전히 필요합니다.<sup>[[2]](#references)</sup> 대신 **User**를 선택하면 래핑된 명령은 설치를 수행하는 사용자의 컨텍스트로 실행되며, 사용자별 리소스나 네트워크 리소스를 사용해야 하는 경우 이 방식이 필요할 수 있습니다.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

이 batch 파일을 입력으로 MSI를 빌드한 다음 테스트 호스트에서 실행하고 기록된 identity와 privileges를 확인합니다.<sup>[[4]](#references)</sup> MSI Wrapper는 0이 아닌 batch 종료 코드를 설치 오류 1603으로 매핑하므로, 테스트가 성공한 뒤 잘못된 실패로 처리되지 않도록 명시적으로 0을 반환합니다.<sup>[[4]](#references)</sup> 출력 파일은 테스트 결과물입니다. `msiexec`가 성공적으로 종료되었거나 조용히 설치되었다는 사실만으로 SYSTEM 권한으로 실행되었다고 판단하지 마세요.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn`은 MSI UI를 표시하지 않지만, 래핑된 실행 파일 자체의 UI까지 반드시 숨기는 것은 아닙니다.<sup>[[6]](#references)[[7]](#references)</sup> 래핑된 설치 프로그램의 경우, 마법사에서 지원되는 silent arguments를 설정하세요. MSI Wrapper의 동적 `WRAPPED_ARGUMENTS` 속성은 PRO 기능입니다.<sup>[[1]](#references)[[7]](#references)</sup> custom-action 시퀀싱과 impersonation을 직접 제어해야 하는 경우 [WiX custom-action 방식](create-msi-with-wix.md)을 참조하세요.

> [!WARNING]
> MSI를 생성하는 것만으로 elevated privileges가 부여되지는 않습니다. 설치 시 elevated privileges가 적용되는지는 Windows Installer 정책, 패키지 컨텍스트, 사용자 권한 부여 여부에 따라 달라집니다. Microsoft는 사용자와 컴퓨터 모두에 `AlwaysInstallElevated`를 활성화하면 관리자가 아닌 사용자도 system privileges로 패키지를 설치할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper 문서 - 시작하기](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - 관리자가 아닌 사용자를 위한 elevated privileges로 패키지 설치](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - 다운로드](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - batch file에서 msi 만들기](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - 마법사 페이지](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - 명령줄 옵션](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - 명령줄 인수](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
