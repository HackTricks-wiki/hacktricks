# 흥미로운 Windows 레지스트리 키

### 흥미로운 Windows 레지스트리 키

{{#include ../../../banners/hacktricks-training.md}}

### **Windows 버전 및 소유자 정보**

- **`Software\Microsoft\Windows NT\CurrentVersion`**에 위치하며, Windows 버전, 서비스 팩, 설치 시간 및 등록된 소유자의 이름을 간단하게 확인할 수 있습니다.

### **컴퓨터 이름**

- 호스트 이름은 **`System\ControlSet001\Control\ComputerName\ComputerName`** 아래에서 찾을 수 있습니다.

### **시간대 설정**

- 시스템의 시간대는 **`System\ControlSet001\Control\TimeZoneInformation`**에 저장됩니다.

### **접근 시간 추적**

- 기본적으로 마지막 접근 시간 추적은 꺼져 있습니다 (**`NtfsDisableLastAccessUpdate=1`**). 이를 활성화하려면 다음을 사용하세요:
`fsutil behavior set disablelastaccess 0`

### Windows 버전 및 서비스 팩

- **Windows 버전**은 에디션(예: Home, Pro)과 릴리스를 나타내며(예: Windows 10, Windows 11), **서비스 팩**은 수정 사항과 때때로 새로운 기능을 포함하는 업데이트입니다.

### 마지막 접근 시간 활성화

- 마지막 접근 시간 추적을 활성화하면 파일이 마지막으로 열렸던 시간을 확인할 수 있어, 포렌식 분석이나 시스템 모니터링에 중요할 수 있습니다.

### 네트워크 정보 세부사항

- 레지스트리는 **네트워크 유형(무선, 유선, 3G)** 및 **네트워크 범주(공용, 개인/홈, 도메인/작업)**를 포함한 광범위한 네트워크 구성 데이터를 보유하고 있어, 네트워크 보안 설정 및 권한을 이해하는 데 필수적입니다.

### 클라이언트 측 캐싱 (CSC)

- **CSC**는 공유 파일의 복사본을 캐싱하여 오프라인 파일 접근을 향상시킵니다. 다양한 **CSCFlags** 설정은 어떤 파일이 어떻게 캐시되는지를 제어하여, 간헐적인 연결이 있는 환경에서 성능과 사용자 경험에 영향을 미칩니다.

### 자동 시작 프로그램

- 다양한 `Run` 및 `RunOnce` 레지스트리 키에 나열된 프로그램은 시작 시 자동으로 실행되며, 시스템 부팅 시간에 영향을 미치고 악성 소프트웨어나 원치 않는 소프트웨어를 식별하는 데 관심의 지점이 될 수 있습니다.

### 셸백

- **셸백**은 폴더 보기 기본 설정을 저장할 뿐만 아니라, 폴더가 더 이상 존재하지 않더라도 폴더 접근에 대한 포렌식 증거를 제공합니다. 이는 다른 방법으로는 명백하지 않은 사용자 활동을 드러내는 데 매우 유용합니다.

### USB 정보 및 포렌식

- 레지스트리에 저장된 USB 장치에 대한 세부정보는 어떤 장치가 컴퓨터에 연결되었는지를 추적하는 데 도움이 되며, 이는 민감한 파일 전송이나 무단 접근 사건과 연결될 수 있습니다.

### 볼륨 일련 번호

- **볼륨 일련 번호**는 파일 시스템의 특정 인스턴스를 추적하는 데 중요할 수 있으며, 이는 다양한 장치 간에 파일 출처를 확립해야 하는 포렌식 시나리오에서 유용합니다.

### **종료 세부정보**

- 종료 시간 및 횟수(후자는 XP에만 해당)는 **`System\ControlSet001\Control\Windows`** 및 **`System\ControlSet001\Control\Watchdog\Display`**에 저장됩니다.

### **네트워크 구성**

- 자세한 네트워크 인터페이스 정보는 **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**를 참조하세요.
- VPN 연결을 포함한 첫 번째 및 마지막 네트워크 연결 시간은 **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**의 다양한 경로에 기록됩니다.

### **공유 폴더**

- 공유 폴더 및 설정은 **`System\ControlSet001\Services\lanmanserver\Shares`** 아래에 있습니다. 클라이언트 측 캐싱(CSC) 설정은 오프라인 파일 가용성을 결정합니다.

### **자동으로 시작되는 프로그램**

- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**와 `Software\Microsoft\Windows\CurrentVersion` 아래의 유사한 항목은 시작 시 실행되도록 설정된 프로그램을 자세히 설명합니다.

### **검색 및 입력된 경로**

- 탐색기 검색 및 입력된 경로는 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**에서 WordwheelQuery 및 TypedPaths에 따라 추적됩니다.

### **최근 문서 및 Office 파일**

- 최근에 접근한 문서 및 Office 파일은 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` 및 특정 Office 버전 경로에 기록됩니다.

### **가장 최근에 사용된 (MRU) 항목**

- 최근 파일 경로 및 명령을 나타내는 MRU 목록은 `NTUSER.DAT`의 다양한 `ComDlg32` 및 `Explorer` 하위 키에 저장됩니다.

### **사용자 활동 추적**

- 사용자 보조 기능은 실행 횟수 및 마지막 실행 시간을 포함한 애플리케이션 사용 통계를 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**에 기록합니다.

### **셸백 분석**

- 폴더 접근 세부정보를 드러내는 셸백은 `Software\Microsoft\Windows\Shell`의 `USRCLASS.DAT` 및 `NTUSER.DAT`에 저장됩니다. 분석을 위해 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)**를 사용하세요.

### **USB 장치 기록**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** 및 **`HKLM\SYSTEM\ControlSet001\Enum\USB`**는 연결된 USB 장치에 대한 풍부한 세부정보를 포함하고 있으며, 여기에는 제조업체, 제품 이름 및 연결 타임스탬프가 포함됩니다.
- 특정 USB 장치와 관련된 사용자는 장치의 **{GUID}**에 대해 `NTUSER.DAT` 하이브를 검색하여 확인할 수 있습니다.
- 마지막으로 마운트된 장치와 그 볼륨 일련 번호는 각각 `System\MountedDevices` 및 `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`를 통해 추적할 수 있습니다.

이 가이드는 Windows 시스템에서 상세한 시스템, 네트워크 및 사용자 활동 정보를 접근하기 위한 중요한 경로와 방법을 요약하여 명확성과 사용성을 목표로 합니다.

{{#include ../../../banners/hacktricks-training.md}}
