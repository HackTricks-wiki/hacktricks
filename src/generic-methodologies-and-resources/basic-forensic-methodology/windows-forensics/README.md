# Windows 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 일반 Windows 아티팩트

### Windows 10 알림

사용자별 알림 데이터베이스는 `%LOCALAPPDATA%\Microsoft\Windows\Notifications`에 있습니다(예: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). 초기 Windows 10 릴리스에서는 `appdb.dat`를 사용했으며, Anniversary Update(1607)에서 `wpndatabase.db`가 도입되었습니다. SQLite 데이터베이스에는 알림 페이로드와 시간 필드가 포함된 `Notification` 테이블이 있지만, 보존 기간과 사용 가능한 데이터는 릴리스 및 정리 정책에 따라 다릅니다.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline은 지원되는 애플리케이션, 문서 및 기타 사용자 활동의 기록을 포함할 수 있는 활동 기록 기능입니다. 기록 범위는 애플리케이션과 Windows 버전에 따라 달라집니다.<sup>[[4]](#references)</sup>

데이터베이스는 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`에 있습니다. SQLite로 열거나 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)로 파싱할 수 있으며, 출력은 [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md)로 검토할 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall 스냅샷(Copilot+ PC)

Recall은 지원되는 Windows 11 Copilot+ PC에서 사용자가 선택적으로 활성화할 수 있습니다. 현재 빌드에서는 Windows Hello 및 VBS 엔클레이브에 연결된 키로 스냅샷과 해당 인덱스를 암호화합니다. 오프라인으로 복사한 저장소를 일반 텍스트 SQLite 데이터베이스로 간주하지 마세요. 2024년 프리뷰와 정식 출시 버전은 접근 속성이 서로 다릅니다.<sup>[[77]](#references)</sup>

**실행 중이며 Recall이 활성화된 세션**에서는 동일 사용자의 `AIXHost.exe` 렌더링 프로세스가 별도의 접근 경로입니다. TotalRecall Reloaded 개념 증명은 해당 프로세스에 DLL을 주입하고 Recall COM 인터페이스를 호출합니다. 전체 기록을 추출하려면 여전히 사용자가 Windows Hello로 인증해야 합니다. 이는 오프라인 복호화나 Hello 우회가 아닙니다. 연구자는 Windows 11 ARM64에서 도구를 기록했으므로, 이를 사용하기 전에 대상 빌드와의 호환성을 확인하세요.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth`는 Hello 없이 `GetRecentCaptureThumbnail`을 사용해 최신 캡처의 고해상도 버전을 요청합니다. 인증 후 `--wait`를 사용하면 스크린샷, OCR 텍스트, 애플리케이션 및 창 컨텍스트를 포함한 캡처별 메타데이터를 추출할 수 있습니다. 출력은 타임스탬프가 포함된 `extraction_*` 디렉터리에 저장됩니다. 이는 개념 증명에서 확인한 빌드별 결과이며, Recall이 활성화되어 있거나 모든 화면이 캡처되었다는 보장은 아닙니다.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

로컬 신뢰 경계 외부에서 다운로드한 파일에는 영역 정보를 기록하는 **`Zone.Identifier` alternate data stream**이 포함될 수 있으며, URL과 같은 출처 메타데이터가 들어 있을 수 있습니다. 이 스트림의 존재 여부와 필드는 생성 프로그램 및 시스템 정책에 따라 달라집니다.<sup>[[6]](#references)</sup>

## **파일 백업**

### 휴지통

Vista 이상에서는 드라이브 루트의 **`$Recycle.bin`** 폴더에서 **Recycle Bin**을 찾을 수 있습니다(예: `C:\$Recycle.bin`).\
이 폴더에서 파일을 삭제하면 다음 두 파일이 생성됩니다.

- `$I{id}`: 삭제 시간과 원래 경로를 포함한 파일 정보
- `$R{id}`: 파일 내용

![파일 백업 - 휴지통: $R{id}: 파일 내용](<../../../images/image (1029).png>)

이 파일이 있으면 [**Rifiuti2**](https://github.com/abelcheung/rifiuti2)를 사용해 원래 경로와 삭제 시간을 추출할 수 있습니다(대상 Windows 릴리스에 맞는 버전을 사용하세요).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![파일 백업 - 휴지통: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### 볼륨 섀도 복사본

볼륨 섀도 복사 서비스(VSS)는 파일이 사용 중인 동안 볼륨의 특정 시점 섀도 복사본을 만들 수 있습니다. 섀도 복사본은 forensic image를 대체하지 않습니다.<sup>[[8]](#references)</sup>

복사본 메타데이터는 일반적으로 볼륨 루트의 `\System Volume Information`과 연결되며, 식별자는 시스템마다 다릅니다.

![휴지통 - 볼륨 섀도 복사본: 이러한 백업은 보통 파일 시스템 루트의 System Volume Information에 저장되며 이름은 다음에 표시된 UID로 구성됩니다...](<../../../images/image (94).png>)

적절한 forensic mounter로 image를 마운트한 후, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html)를 사용하면 사용 가능한 VSS 스냅샷을 열거하고 그 안의 파일을 탐색하거나 복사할 수 있습니다.<sup>[[9]](#references)</sup>

![휴지통 - 볼륨 섀도 복사본: ArsenalImageMounter로 forensic image를 마운트한 뒤 ShadowCopyView 도구를 사용해 섀도 복사본을 검사하고 파일을 추출할 수도 있습니다...](<../../../images/image (576).png>)

VSS registry writer 구성에는 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`가 포함됩니다. 이 키는 백업에서 제외할 파일과 키를 지정할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

![휴지통 - 볼륨 섀도 복사본: 레지스트리 항목 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore에는 백업하지 않을 파일과 키가 포함됩니다](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` 키에도 VSS 서비스 구성이 포함됩니다.<sup>[[8]](#references)</sup>

### Office 자동 저장 파일

AutoRecover 위치는 Office 애플리케이션, 버전 및 구성에 따라 다릅니다. Word의 경우 Microsoft 문서에는 기본 위치가 `%APPDATA%\Microsoft\Word`로 나와 있습니다. 실제 경로는 애플리케이션 설정에서 확인하세요.<sup>[[12]](#references)</sup>

## 셸 항목

셸 항목은 다른 파일에 접근하는 방법에 관한 정보를 포함하는 항목입니다.

### 최근 문서 (LNK)

Windows는 일반적으로 사용자가 항목을 열거나 다른 방식으로 접근할 때 최근 항목 바로 가기를 만듭니다.

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

폴더에 접근하면 해당 폴더와 관련된 상위 폴더의 링크도 생성될 수 있습니다.

이러한 링크 파일에는 대상 유형, 대상 MAC 시간, 볼륨 정보 및 대상 경로가 포함될 수 있습니다. 이 메타데이터는 삭제된 대상을 식별하는 데 도움이 될 수 있지만, 해당 항목이 특정 사용자에 의해 열렸다는 증거 자체는 아닙니다.<sup>[[13]](#references)[[14]](#references)</sup>

LNK 자체의 파일 시스템 타임스탬프와 내장된 대상 타임스탬프는 서로 다릅니다. 뒷받침하는 다른 아티팩트 없이 링크 생성 시각을 첫 사용 시각으로, 링크 수정 시각을 마지막 사용 시각으로 해석하지 마세요. 이 형식은 대상 타임스탬프를 링크 파일의 타임스탬프와 별도로 저장합니다.<sup>[[13]](#references)[[14]](#references)</sup>

기존 [**LinkParser**](http://4discovery.com/our-tools/) 링크는 과거에 사용되던 옵션으로 유지했지만, 검토 당시 문서를 확인할 수 없었습니다. 문서가 제공되는 명령줄 parser로는 [**LECmd**](https://github.com/EricZimmerman/LECmd)를 사용하세요.<sup>[[15]](#references)</sup>

이 도구들은 일반적으로 두 종류의 타임스탬프를 표시합니다.

- **대상 타임스탬프:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **링크 파일 타임스탬프:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

첫 번째 집합은 대상을, 두 번째 집합은 LNK 파일 자체를 나타냅니다. parser 문서와 파일 시스템 맥락을 고려해 둘 다 해석하세요.<sup>[[14]](#references)[[15]](#references)</sup>

Windows CLI 도구인 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행해도 같은 정보를 얻을 수 있습니다.<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

이 경우 정보는 CSV 파일에 저장됩니다.

### Jumplists

Jump Lists는 애플리케이션별 최근 항목 또는 작업별 항목 목록이며, 자동 또는 사용자 지정 방식일 수 있습니다.<sup>[[13]](#references)</sup>

Automatic Jump Lists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장되며, `{id}.automaticDestinations-ms`와 같은 이름을 사용합니다. ID는 애플리케이션을 식별합니다.

Custom Jump Lists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`에 저장됩니다. 애플리케이션은 생성할 작업 또는 항목 엔트리를 제어합니다.

파일 시스템의 생성 시간과 수정 시간은 Jump List 파일 자체를 나타내며, 목록에 있는 각 대상에 처음 및 마지막으로 접근한 시간을 자동으로 나타내지는 않습니다. 파싱한 엔트리를 파일 타임스탬프 및 다른 아티팩트와 대조하세요.<sup>[[13]](#references)</sup>

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)를 사용해 Jump Lists를 확인할 수 있습니다.<sup>[[5]](#references)</sup>

![최근 문서 (LNK) - Jumplists: JumplistExplorer를 사용해 jumplist를 확인할 수 있습니다](<../../../images/image (168).png>)

(_JumplistExplorer가 제공하는 타임스탬프는 jumplist 파일 자체와 관련이 있다는 점에 유의하세요_)

### Shellbags

[**이 링크에서 shellbags가 무엇인지 알아보세요.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

USB 사용 여부는 이동식 미디어에서 파일에 접근할 때 생성되는 다음과 같은 아티팩트로 뒷받침할 수 있습니다.

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com)와 같은 도구는 이러한 아티팩트를 USB 장치 기록과 대조하지만, 아티팩트의 가용성은 Windows 버전과 애플리케이션에 따라 다릅니다.<sup>[[18]](#references)</sup>

Windows XP 및 Windows 7 MTP 워크플로를 대상으로 기록된 테스트에서 일부 LNK는 원래 경로 대신 `WPDNSE` 폴더를 가리켰습니다.<sup>[[16]](#references)</sup>

![Shellbags - Windows USB 사용: 일부 LNK 파일은 원래 경로 대신 WPDNSE 폴더를 가리킬 수 있습니다](<../../../images/image (218).png>)

해당 연구에서는 `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 아래에 복사본이 생성되는 것을 확인했습니다. 테스트에서는 임시 파일이 재시작 후 남아 있지 않았으며, GUID는 shellbag 데이터와 대조할 수 있었습니다. 이를 보편적인 규칙이 아니라 OS, 장치 및 애플리케이션에 따라 달라지는 동작으로 취급하세요.<sup>[[16]](#references)</sup>

### Registry 정보

USB 연결 장치에 관한 흥미로운 정보가 어떤 registry 키에 포함되어 있는지 알아보려면 [이 페이지를 확인하세요](interesting-windows-registry-keys.md#usb-information).

### setupapi

Vista 이상에서는 장치 설치 활동을 확인하기 위해 `C:\Windows\inf\setupapi.dev.log`를 살펴보세요. 섹션 헤더에는 `Section start` 타임스탬프가 포함됩니다. 이 타임스탬프는 설치 처리를 기록한 것이므로, 정확한 물리적 연결 시각으로 간주하지 말고 다른 연결 증거와 대조해야 합니다.<sup>[[17]](#references)</sup>

![Registry 정보 - setupapi: USB 연결이 발생한 시점의 타임스탬프를 확인하려면 C: Windows inf setupapi.dev.log 파일에서 Section start를 검색하세요](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)를 사용하면 이미지에 연결된 적이 있는 USB 장치 정보를 확인할 수 있습니다.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective를 사용하면 이미지에 연결된 적이 있는 USB 장치 정보를 확인할 수 있습니다](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup`이라는 예약 작업은 오래된 드라이버 버전을 제거합니다. Adam Harrison가 문서화한 Windows 10 작업 정의는 30일 동안 비활성 상태인 드라이버도 대상으로 하므로, 이동식 장치 드라이버 증거가 정리될 수 있습니다. 이 동작을 일반화하기 전에 로컬 작업 정의와 Windows 빌드를 확인하세요.<sup>[[1]](#references)</sup>

작업은 다음 경로에 있습니다. `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Windows Plug and Play Cleanup 예약 작업의 XML 정의](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**작업의 주요 구성 요소 및 설정:**

- **pnpclean.dll**: 실제 정리 프로세스를 담당하는 DLL입니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 있으며, 일반 작업 스케줄링 엔진을 사용한다는 뜻입니다.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Task Scheduler가 정기 자동 유지 관리 중 매월 정리 작업을 시작하도록 지정합니다.
  - **Deadline ('P2M')**: 작업이 두 달 연속 실패하면 Task Scheduler가 긴급 자동 유지 관리 중 작업을 실행하도록 지시합니다.

이 설정은 정기 유지 관리를 예약하고 연속 실패 후 재시도합니다. 정확한 XML과 동작은 버전에 따라 다릅니다.<sup>[[1]](#references)</sup>

**자세한 내용은 다음을 확인하세요:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## 이메일

이메일에는 **흥미로운 부분이 두 가지 있습니다. 헤더와 이메일 내용**입니다. **헤더**에서 다음과 같은 정보를 찾을 수 있습니다.

- 이메일을 보낸 **사람**(이메일 주소, IP, 이메일을 전달한 메일 서버)
- 이메일을 보낸 **시점**

또한 `References` 및 `In-Reply-To` 헤더에는 답장과 대화를 연결하는 데 사용되는 메시지 ID가 포함될 수 있습니다.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - 이메일: 이메일을 보낸 시점](<../../../images/image (593).png>)

### Windows Mail App

이 애플리케이션은 이메일 내용을 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`와 같은 경로 아래의 보조 텍스트 또는 HTML 파일에 저장합니다. 정확한 번호가 붙은 폴더와 파일 구조는 아티팩트에 따라 다를 수 있습니다.<sup>[[75]](#references)</sup>

이메일의 **메타데이터**와 **연락처**는 **ESE 데이터베이스** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`에서 찾을 수 있습니다.<sup>[[75]](#references)</sup>

`store.vol`은 Extensible Storage Engine (ESE) 형식입니다. 복사본을 사용하고 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 ESE 파서를 이용하세요. 도구에 `.edb` 확장자가 필요한 경우 복사본의 이름만 변경하고, `Message` 테이블을 기준으로 삼기 전에 테이블 스키마를 확인하세요.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI 속성을 조사할 때 확인할 수 있는 표준 속성은 다음과 같습니다.

- `PidTagClientSubmitTime`: 클라이언트가 메시지를 제출한 UTC 시각입니다.
- `PidTagConversationIndex`: 대화 스레드에서 메시지가 차지하는 상대적 위치입니다.
- `PidTagEntryId`: 메시지 객체의 식별자입니다.
- `PidTagMessageFlags`: 제출됨, 읽음, 읽지 않음, 첨부 파일 포함 등의 상태 플래그입니다.
- `PidTagLastVerbExecuted`: 열기, 답장 또는 전달과 같이 메시지에 대해 마지막으로 기록된 작업입니다.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook 데이터 파일의 위치는 버전과 계정 유형에 따라 다릅니다. Microsoft는 PST/OST 파일의 일반적인 위치를 다음과 같이 안내합니다.

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry 경로 `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`에서 Outlook 프로필과 관련 데이터 파일 설정을 확인할 수 있습니다.

PST 파일에는 메시지, 연락처, 일정 데이터 및 기타 Outlook 항목이 포함될 수 있습니다. [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)로 복사본을 확인할 수 있습니다.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer 도구를 사용해 PST 파일을 열 수 있습니다](<../../../images/image (498).png>)

### Microsoft Outlook OST 파일

**OST 파일**은 Exchange 또는 Microsoft 365 계정의 로컬 캐시입니다. Cached Exchange Mode는 POP 또는 IMAP 계정에는 적용되지 않습니다. 오프라인 기간은 설정할 수 있으며 기본값은 보통 12개월입니다. PST/OST 크기 제한은 별도로 설정할 수 있습니다. OST 파일을 보려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### 첨부 파일 복구

손실된 첨부 파일은 다음 위치에서 복구할 수 있습니다.

- 레거시 Outlook/IE 구성의 경우: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- 최신 Outlook/IE11 구성의 경우: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX 파일

**Thunderbird**는 프로필 데이터를 `%APPDATA%\Thunderbird\Profiles`에 저장합니다. 메일 폴더는 계정별 `Mail` 또는 `ImapMail` 디렉터리의 확장자 없는 mbox 파일인 경우가 많습니다.<sup>[[29]](#references)[[30]](#references)</sup>

### 이미지 썸네일

- **Windows XP**: 썸네일 미리 보기는 일반적으로 폴더별 `thumbs.db` 파일에 저장되었습니다.
- **네트워크 폴더**: 관련 썸네일 동작이 활성화된 경우 UNC 폴더에 `thumbs.db` 파일이 생성될 수 있습니다. 모든 Windows 버전이나 정책에서 해당 파일이 생성된다고 가정하지 마세요.
- **Windows Vista 이상**: 시스템 썸네일 캐시는 `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 아래에 중앙 집중식으로 저장되며, 파일명은 **thumbcache_xxx.db**와 같은 형식입니다. [**Thumbsviewer**](https://thumbsviewer.github.io)는 레거시 `Thumbs.db`를 파싱할 수 있고, [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 최신 썸네일 캐시 데이터베이스를 파싱할 수 있습니다.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry 정보

시스템 및 사용자 구성 데이터를 저장하는 Windows Registry는 다음 위치의 hive 파일로 구성됩니다.

- `%WINDIR%\System32\Config`: 여러 `HKEY_LOCAL_MACHINE` 하위 키를 뒷받침하는 시스템 hive가 있습니다.
- `%USERPROFILE%\NTUSER.DAT`: 사용자 `HKEY_CURRENT_USER` hive가 있습니다.
- 일부 구형 Windows 설치에는 `%WINDIR%\System32\Config\RegBack\`에 복사본이 있습니다. Windows 10 version 1803 이상에서는 주기적 백업을 활성화하지 않는 한 이 디렉터리에 자동으로 파일이 채워지지 않습니다.<sup>[[34]](#references)[[35]](#references)</sup>
- 최신 Windows에서는 사용자별 shell 및 클래스 등록 데이터도 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`에 저장되는 경우가 많습니다.<sup>[[34]](#references)[[66]](#references)</sup>

### 도구

registry hive 분석에는 다음 도구가 유용합니다. 출력 결과에 의존하기 전에 각 도구가 지원하는 hive 형식과 버전을 확인하세요.

- **Registry Editor**: Windows에 설치되어 있습니다. 현재 세션의 Windows registry를 탐색하는 GUI입니다.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry 파일을 불러와 GUI에서 탐색할 수 있습니다. 흥미로운 정보가 있는 키를 강조 표시하는 Bookmarks도 포함되어 있습니다.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 불러온 registry를 GUI에서 탐색할 수 있으며, registry에서 흥미로운 정보를 강조 표시하는 plugins도 포함되어 있습니다.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): 불러온 registry hive에서 정보를 추출할 수 있는 또 다른 GUI 애플리케이션입니다.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### 삭제된 요소 복구

삭제된 hive cell은 해당 공간이 재사용될 때까지 남아 있을 수 있지만, 복구 가능성은 hive 상태와 파서에 따라 달라집니다. 복구된 삭제 키는 검증이 필요한 증거로 취급해야 하며, 반드시 정확한 기록이라고 간주해서는 안 됩니다.

### 마지막 쓰기 시간

Registry 키에는 마지막 쓰기 타임스탬프가 있습니다. Windows는 이를 키 또는 해당 키의 값 엔트리에 대해 노출하므로, 값마다 독립적인 수정 타임스탬프가 있는 것은 아닙니다.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive에는 로컬 사용자 및 그룹 계정 데이터가 포함되며, 시스템의 boot-key 자료로 보호되는 암호 해시도 포함됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users`에서 계정 식별자와 일부 로그온 및 정책 필드를 확인할 수 있습니다. 오프라인에서 해시를 추출하려면 관련 boot-key 자료를 복구하기 위해 `SYSTEM` hive도 필요합니다.<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry의 흥미로운 항목


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 실행된 프로그램

### 기본 Windows 프로세스

[일반적인 Windows 프로세스에 관한 기존 게시물](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)을 추가 자료로 참고할 수 있습니다. 프로세스 동작에 관한 주장은 최신 Windows 문서와 로컬 증거를 통해 대조 확인하세요.<sup>[[2]](#references)</sup>

### Windows Recent APPs

해당 기능이 제공되는 Windows 10 버전에서는 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`에 애플리케이션별 하위 키가 있으며, 마지막 사용 시간과 실행 횟수 등의 필드가 포함됩니다. 이 아티팩트는 이후 릴리스에서 제거되었으므로 대상 빌드를 확인하세요.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator가 제공되는 시스템에서는 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 또는 최신 경로인 `...\bam\State\UserSettings\{SID}`를 확인하세요. 값은 사용자 SID를 키로 사용하며, 추적된 실행 파일 경로와 FILETIME 형식의 실행 데이터를 포함할 수 있습니다. 이 아티팩트는 버전에 따라 다르므로 다른 증거와 대조해야 합니다.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch는 프로그램을 더 빠르게 시작할 수 있도록 리소스와 실행 메타데이터를 캐시합니다.

Prefetch 파일은 `C:\Windows\Prefetch`에 `.pf` 파일로 저장됩니다. 형식, 보존 기간 및 파일 수 제한은 Windows 버전에 따라 다릅니다. Microsoft 문서에 따르면 Windows 8 이상에서는 최근 실행 시각 8개와 최대 1024개 파일을 보존하므로, 과거의 고정 제한 설명을 일반화해서는 안 됩니다.<sup>[[13]](#references)</sup>

파일명은 일반적으로 `{program_name}-{hash}.pf` 형식이며, 해시는 경로와 인수 같은 실행 컨텍스트에서 파생됩니다. Windows 10 이상에서는 파일이 압축될 수 있습니다. 파일이 존재하면 실행 증거로 유용하지만, 그것만으로 사용자가 실행했다고 입증되지는 않으므로 다른 아티팩트와 대조해야 합니다.<sup>[[13]](#references)</sup>

이 파일을 확인하려면 [**PECmd.exe**](https://github.com/EricZimmerman/PECmd)를 사용할 수 있습니다. 이 도구는 디렉터리 파싱, CSV/HTML 출력 및 지원되는 Windows 10 Prefetch 파일의 압축 해제를 제공합니다.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**은 사용 이력을 활용해 로딩을 개선하여 Prefetch를 보완합니다. 이를 생성하는 시스템에서는 데이터베이스 파일이 일반적으로 `C:\Windows\Prefetch\Ag*.db`에 있으며, 형식과 존재 여부는 버전에 따라 다릅니다.<sup>[[41]](#references)</sup>

이러한 데이터베이스에는 애플리케이션 이름, 사용 횟수, 액세스한 파일 또는 볼륨, 경로, 시간 범위가 포함될 수 있지만, 정확한 실행 로그로 간주해서는 안 됩니다.<sup>[[41]](#references)</sup>

기존 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 링크는 파서 후보로 유지합니다. 사용하기 전에 도구 문서를 확인하여 현재 이용 가능 여부와 지원되는 출력 형식을 검증하세요.

### SRUM

**System Resource Usage Monitor**(SRUM)는 애플리케이션 및 사용자의 리소스 사용량을 기록합니다. Windows 8에서 도입되었으며, ESE 데이터베이스 `C:\Windows\System32\sru\SRUDB.dat`에 데이터를 저장합니다.<sup>[[13]](#references)</sup>

다음 정보를 제공합니다.

- AppID 및 경로
- 레코드와 연결된 사용자/SID
- 전송된 바이트
- 수신된 바이트
- 네트워크 인터페이스
- 연결 지속 시간
- 프로세스 지속 시간

수집 주기와 보존 기간은 구현 방식에 따라 다릅니다. 각 레코드가 정확히 60분 동안의 실행을 나타낸다고 가정하지 마세요.<sup>[[13]](#references)</sup>

현재 도구 버전에 문서화된 옵션을 사용하여 [**srum_dump**](https://github.com/MarkBaggett/srum-dump)로 데이터를 추출하고 검토할 수 있습니다.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**(또는 **ShimCache**)는 Windows 애플리케이션 호환성 인프라의 일부로, 호환성 판단을 위해 파일 메타데이터를 기록합니다. 하이브 경로, 레코드 형식, 보존 용량 및 필드는 Windows 버전에 따라 달라집니다. 최신 Windows에서는 ShimCache만으로 사용자가 파일을 실행했다고 입증할 수 없습니다. 관련 `SYSTEM` 하이브를 [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser)로 파싱하고, 출력 결과를 실행 아티팩트와 대조하세요.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): 저장된 정보를 파싱하려면 AppCompatCacheParser tool을 사용하는 것이 좋습니다](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 파일은 Windows에서 확인한 애플리케이션과 파일의 인벤토리를 기록하는 레지스트리 하이브입니다. 일반적으로 `C:\Windows\AppCompat\Programs\Amcache.hve`에 있습니다.

여기에는 연결되거나 연결되지 않은 파일 항목, 경로 및 SHA1 값이 포함될 수 있지만, 이 파일의 존재는 인벤토리 증거일 뿐이며 프로세스가 실행되었음을 그 자체로 입증하지는 않습니다.<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve**를 추출하고 분석하려면 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool을 사용하세요. 이 명령은 하이브를 파싱하고 CSV 출력을 작성합니다.<sup>[[44]](#references)</sup>

예시:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

생성된 CSV 파일 중 `Amcache_Unassociated file entries`는 인식된 프로그램과 연결되지 않은 파일을 조사할 때 유용할 수 있습니다.<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 시스템에서는 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에 최근에 관찰된 바이너리에 대한 정보가 포함되어 있을 수 있습니다. 사용 가능 여부와 의미는 버전에 따라 다릅니다.

[**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser)를 사용해 파일을 파싱할 수 있습니다.<sup>[[45]](#references)</sup>

### 예약된 작업

최신 작업의 증거는 `C:\Windows\System32\Tasks`에서, 레거시 작업의 증거는 `.job` 파일이 있는 `C:\Windows\Tasks`에서 찾을 수 있습니다. OS에 적합한 작업 정의 형식을 검사하세요.<sup>[[73]](#references)[[74]](#references)</sup>

### 서비스

Service Control Manager 데이터베이스는 `SYSTEM\CurrentControlSet\Services`에 있습니다(오프라인 SYSTEM 하이브의 경우 해당하는 control-set 키를 검사). 이 데이터베이스에는 실행 파일 경로와 시작 유형 등 서비스 및 드라이버 구성이 포함됩니다.<sup>[[72]](#references)</sup>

### **Windows Store**

설치된 Windows Store 앱은 `\ProgramData\Microsoft\Windows\AppRepository\` 아래에 표시될 수 있으며, 여기에는 **`StateRepository-Machine.srd`** 데이터베이스도 포함됩니다. 스키마와 경로는 Windows 릴리스에 따라 다릅니다.<sup>[[71]](#references)</sup>

이 데이터베이스에는 애플리케이션 식별자, 패키지 번호, 표시 이름이 포함될 수 있습니다. 식별자에 간격이 있다는 사실만으로 앱이 제거되었다고 단정할 수는 없습니다. 패키지 및 레지스트리 상태와 대조 확인하세요.

패키지 등록 정보는 `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`에도 나타날 수 있습니다. Microsoft는 제거된 사전 설치 앱을 위한 버전별 `Deprovisioned` 하위 키를 설명하고 있습니다. 모든 빌드에 `Deleted` 하위 키가 있다고 가정하지 마세요.<sup>[[70]](#references)</sup>

## Windows Events

공급자에 따라 Windows 이벤트에는 다음 정보가 포함될 수 있습니다.

- 발생한 일
- 이벤트 스키마 및 호스트 시간 맥락과 함께 해석해야 하는 `TimeCreated` 타임스탬프
- 관련 사용자
- 관련 호스트(호스트 이름, IP)
- 액세스한 자산(파일, 폴더, 프린터 또는 서비스).<sup>[[49]](#references)</sup>

Windows Vista 이전에는 이벤트 로그가 일반적으로 `C:\Windows\System32\config` 아래의 레거시 바이너리 형식을 사용했습니다. Vista 이후에는 Windows Event Log 형식을 사용하며, 보통 `C:\Windows\System32\winevt\Logs` 아래에 XML로 렌더링된 이벤트 데이터가 들어 있는 `.evtx` 파일을 저장합니다.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM 레지스트리는 채널 구성 정보를 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** 아래에 저장하며, 여기에는 설정된 파일 경로와 보존 설정이 포함됩니다.<sup>[[47]](#references)</sup>

Windows Event Viewer(**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com), [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)와 같은 도구로 확인할 수 있습니다.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows Security Event Logging 이해하기

Vista 이후 Security 채널은 일반적으로 `C:\Windows\System32\winevt\Logs\Security.evtx`에 저장됩니다. 최대 크기와 보존 정책은 설정할 수 있으며, 순환 로깅을 사용하는 경우 파일이 제한 크기에 도달하면 오래된 레코드가 덮어쓰일 수 있습니다. 관련 감사가 활성화되어 있으면 이 채널은 인증, 로그오프, 권한, 감사 정책 및 개체 액세스 이벤트를 기록할 수 있습니다.<sup>[[46]](#references)[[47]](#references)</sup>

### 사용자 인증을 위한 주요 Event ID:

- **Event ID 4624**: 계정 로그온 성공.<sup>[[50]](#references)</sup>
- **Event ID 4625**: 계정 로그온 실패.<sup>[[51]](#references)</sup>
- **Event ID 4634**: 로그온 세션 종료.<sup>[[52]](#references)</sup>
- **Event ID 4647**: 사용자가 로그오프를 시작함.<sup>[[53]](#references)</sup>
- **Event ID 4672**: 새 로그온에 특별 권한이 할당됨. 시스템 및 관리자 계정에서 흔히 발생하므로, 이 이벤트만으로 악성 활동을 입증할 수는 없습니다.<sup>[[54]](#references)</sup>

#### 4624, 4625, 4634, 4647에서 흔히 기록되는 로그온 유형:

- **Interactive (2)**: 로컬 대화형 로그온.
- **Network (3)**: 공유 리소스에 대한 액세스.
- **Batch (4)**: 배치 프로세스 로그온.
- **Service (5)**: 서비스 로그온.
- **Unlock (7)**: 워크스테이션 잠금 해제.
- **NetworkCleartext (8)**: 인증 패키지에 자격 증명을 평문으로 제공하는 네트워크 로그온.
- **NewCredentials (9)**: 아웃바운드 연결에 제공된 대체 자격 증명을 사용하는 로그온.
- **RemoteInteractive (10)**: Remote Desktop 또는 Terminal Services 로그온.
- **CachedInteractive (11)**: 캐시된 도메인 자격 증명을 사용하는 대화형 로그온.
- **CachedRemoteInteractive (12)**: 캐시된 원격 대화형 로그온.
- **CachedUnlock (13)**: 캐시된 자격 증명을 사용한 잠금 해제.<sup>[[50]](#references)[[51]](#references)</sup>

#### EventID 4625의 Status 및 Sub Status 코드:

- **0xC0000064**: 해당 사용자가 없음.
- **0xC000006A**: 사용자 이름은 맞지만 암호가 틀림.
- **0xC0000234**: 계정 잠김.
- **0xC0000072**: 계정 비활성화됨.
- **0xC000006F**: 허용된 시간 외의 로그온.
- **0xC0000070**: 워크스테이션 제한 위반.
- **0xC0000193**: 계정 만료됨.
- **0xC0000071**: 암호 만료됨.
- **0xC0000133**: 클라이언트와 서버의 시간 차이가 너무 큼.
- **0xC0000224**: 계정 암호를 변경해야 함.
- **0xC0000225**: `STATUS_NOT_FOUND`; 이 코드만으로 시스템 버그나 공격을 식별할 수는 없습니다.
- **0xC000015B**: 계정에 요청된 로그온 유형이 허용되지 않음.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **시간 변경**: 시스템 시간이 변경됨. 많은 이벤트는 일반적인 시간 서비스 보정을 반영하므로, 조작으로 판단하기 전에 행위자와 시간 출처를 대조 확인하세요.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, 6009:

- **전원 및 서비스 맥락**: 이벤트 12는 OS 시작, 13은 OS 종료, 1074는 계획된 종료 또는 재시작, 6008은 예기치 않은 종료, 6009는 부팅 시 Windows 버전을 기록합니다. 이벤트 6005와 6006은 각각 Event Log 서비스의 시작과 중지를 나타내며, 그 자체로 OS 시작과 종료를 입증하지는 않습니다.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **로그 삭제**: 이벤트 1102는 Security 감사 로그가 지워졌음을 기록합니다. 이 이벤트만으로 의도를 단정하지 말고 행위자와 전후 이벤트를 조사하세요.<sup>[[62]](#references)</sup>

#### USB 장치 추적을 위한 EventIDs:

- **20001 / 20003**: 최초 사용 또는 설치 활동을 확인하는 데 도움이 될 수 있는 `UserPnp` 장치 설치 이벤트.
- **10000 / 10100**: 장치 활동과 함께 발생할 수 있는 `DriverFrameworks-UserMode` 이벤트.
- **Event ID 112**: 삽입 관련 타임스탬프를 제공할 수 있는 `DeviceSetupManager/Admin` 활동.
- 공급자, 채널 및 이벤트 의미는 Windows 버전에 따라 다릅니다. 의미를 부여하기 전에 공급자 이름과 이벤트 페이로드를 확인하세요.<sup>[[59]](#references)</sup>

로그온 유형과 관련 자격 증명 자료의 실제 예시는 [Altered Security의 상세 가이드](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)를 참조하세요.<sup>[[60]](#references)</sup>

로그온 유형, 상태, 하위 상태, 소스 주소, 프로세스 필드 등 이벤트 세부 정보는 Event ID 4625의 맥락을 파악하는 데 도움이 됩니다. 상태 코드나 반복적인 실패 패턴은 조사 단서이지 결론이 아닙니다.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows Events 복구

이벤트 로그는 일반적으로 순환 방식이므로 로거가 덮어쓴 레코드는 복구할 수 없을 수 있습니다. 라이브 시스템에 접근하기 전에 포렌식 이미지나 작업 사본을 보존하세요. 검증된 파서나 카버(예: **Bulk_extractor**)는 해당 도구 버전이 대상 `.evtx` 데이터를 지원하는지 확인한 뒤에만 사용하고, 이벤트 복구를 시도한다는 이유만으로 실행 중인 시스템의 전원을 뽑지 마세요.<sup>[[46]](#references)</sup>

### Windows Events를 통한 일반적인 공격 식별

실용적인 event-ID 참고 자료는 기존 [Red Team Recipe](https://redteamrecipe.com/event-codes/) 링크를 참조하고, 예시를 위의 공급자 문서와 대조해 검증하세요.

#### Brute Force 공격

반복되는 Event ID 4625 실패를 이후의 4624 성공, 로그온 유형, 상태, 출처 및 계정 맥락과 대조하세요. 이러한 연속 기록은 조사가 필요한 징후이지 공격의 증거는 아닙니다.<sup>[[50]](#references)[[51]](#references)</sup>

#### 시간 변경

Event ID 4616은 시스템 시간 변경을 기록하며, 이는 타임라인 분석을 복잡하게 만들 수 있습니다. 시간 서비스 및 호스트 증거와 비교하세요.<sup>[[56]](#references)</sup>

#### USB 장치 추적

USB event ID는 공급자에 따라 다릅니다. `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100, `DeviceSetupManager/Admin` 112를 SetupAPI 및 레지스트리 아티팩트와 대조하세요.<sup>[[17]](#references)[[59]](#references)</sup>

#### 시스템 전원 이벤트

OS 시작, 종료, 재시작 및 예기치 않은 전원 상황을 파악하려면 12/13/1074/6008/6009를 사용하세요. 6005/6006은 Event Log 서비스의 시작/중지를 나타냅니다.<sup>[[57]](#references)[[58]](#references)</sup>

#### 로그 삭제

Security Event ID 1102는 Security 감사 로그가 지워졌음을 기록합니다. 책임 계정 및 프로세스와 대조해야 합니다.<sup>[[62]](#references)</sup>



## References

- [1] [Windows Plug and Play 정리](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 일반적인 Windows 프로세스 조사](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 알림의 디지털 포렌식 관점](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman 포렌식 도구](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier 및 Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS에서 레지스트리 백업 및 복원 작업](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [백업 및 복원을 위한 레지스트리 키](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover 위치에서 발생하는 Word 성능 문제](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [사고 대응 가이드북](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link 바이너리 파일 형식](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP 포렌식: 데이터 유출 아티팩트 식별](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI 장치 설치 로그 항목](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID 및 관련 형식](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook 데이터 파일 찾기 및 전송](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode 켜기](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [항목 일부만 동기화됨](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook 데이터 파일 크기 제한 구성](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [프로필 - Thunderbird가 사용자 데이터를 저장하는 위치](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird 계정 설정 및 mbox 디렉터리](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache 인터페이스](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [레지스트리 하이브](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [시스템 레지스트리가 RegBack에 백업되지 않음](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows 레지스트리 복구](https://www.mitec.cz/wrr.html)
- [38] [레지스트리를 원격으로 편집](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [암호 기술 개요](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch 증거](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [이벤트 로그 파일 형식](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog 레지스트리 키](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated 이벤트 속성](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [이벤트 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [이벤트 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [이벤트 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [이벤트 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [이벤트 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS 값](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [이벤트 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [시스템 이벤트 로그를 사용하여 예기치 않은 재부팅 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [진행 중인 종료 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10 USB 저장 장치 포렌식](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Windows 로그온 유형 완벽 가이드](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [이벤트 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [백그라운드 활동 조정자](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [레지스트리 - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop에서 PDF 첨부 파일의 빠른 인쇄가 중단됨](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows 레지스트리 파일](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [업데이트 중 제거한 앱이 다시 설치되지 않도록 하기](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK 및 Registry Viewer 테스트 결과](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [설치된 서비스 데이터베이스](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [작업](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler 서비스를 사용할 수 없어 예약된 작업이 오류와 함께 실패함](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail 데이터베이스 탐색](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: 인터넷 메시지 형식](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Windows 클라이언트용 Recall 관리](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
