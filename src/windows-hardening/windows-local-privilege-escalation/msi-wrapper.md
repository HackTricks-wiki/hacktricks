# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper는 실행 파일이나 스크립트를 Windows Installer (`.msi`) 파일로 패키징할 수 있습니다. 무료 버전을 다운로드하고 실행한 다음, 패키징할 실행 파일을 선택합니다.<sup>[[3]](#references)</sup> 일련의 명령을 실행하려면 `cmd.exe`를 패키징하는 대신 입력 파일로 `.bat` 파일을 선택합니다.<sup>[[1]](#references)</sup>

![MSI Wrapper에서 소스 실행 파일 또는 배치 스크립트 선택](<../../images/image (417).png>)

실행 컨텍스트와 기타 설치 프로그램 속성을 신중하게 구성합니다.

![MSI Wrapper에서 애플리케이션 ID 및 보안 컨텍스트 구성](<../../images/image (312).png>)

![MSI Wrapper에서 설치 프로그램 속성 구성](<../../images/image (346).png>)

![MSI Wrapper 빌드 설정 검토](<../../images/image (1072).png>)

사용자 지정 바이너리를 패키징할 때 이러한 값을 변경할 수 있습니다.

나머지 마법사 페이지를 계속 진행한 다음 **Build**를 선택하여 설치 프로그램을 생성합니다.<sup>[[1]](#references)</sup>

> [!WARNING]
> MSI를 생성하는 것만으로는 elevated privileges가 부여되지 않습니다. 설치가 elevated되는지는 Windows Installer 정책, 패키지 컨텍스트 및 사용자의 권한 부여 여부에 따라 달라집니다. Microsoft는 사용자와 컴퓨터 모두에 `AlwaysInstallElevated`를 활성화하면 관리자가 아닌 사용자가 system privileges로 패키지를 설치할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper 문서 - 시작하기](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - 관리자가 아닌 사용자를 위한 elevated privileges를 사용한 패키지 설치](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - 다운로드](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
