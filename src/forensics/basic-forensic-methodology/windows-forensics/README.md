# Windows Artifacts

## Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}


## Generic Windows Artifacts

### Windows 10 Notifications

경로 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`에서 데이터베이스 `appdb.dat` (Windows 기념일 이전) 또는 `wpndatabase.db` (Windows 기념일 이후)를 찾을 수 있습니다.

이 SQLite 데이터베이스 안에는 흥미로운 데이터를 포함할 수 있는 모든 알림이 있는 `Notification` 테이블이 있습니다 (XML 형식).

### Timeline

Timeline은 방문한 웹 페이지, 편집된 문서 및 실행된 애플리케이션의 **연대기적 기록**을 제공하는 Windows의 특징입니다.

데이터베이스는 경로 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`에 있습니다. 이 데이터베이스는 SQLite 도구나 도구 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)로 열 수 있으며, **이 도구는** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **로 열 수 있는 2개의 파일을 생성합니다.**

### ADS (Alternate Data Streams)

다운로드된 파일은 **ADS Zone.Identifier**를 포함할 수 있으며, 이는 **어떻게** 인트라넷, 인터넷 등에서 **다운로드되었는지** 나타냅니다. 일부 소프트웨어(예: 브라우저)는 파일이 다운로드된 **URL**과 같은 **더 많은** **정보**를 추가하는 경우가 많습니다.

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10에서 **Recycle Bin**은 드라이브의 루트에 있는 폴더 **`$Recycle.bin`**에서 찾을 수 있습니다 (`C:\$Recycle.bin`).\
이 폴더에서 파일이 삭제되면 2개의 특정 파일이 생성됩니다:

- `$I{id}`: 파일 정보 (삭제된 날짜)
- `$R{id}`: 파일의 내용

![](<../../../images/image (486).png>)

이 파일들이 있으면 도구 [**Rifiuti**](https://github.com/abelcheung/rifiuti2)를 사용하여 삭제된 파일의 원래 주소와 삭제된 날짜를 얻을 수 있습니다 (Vista – Win10의 경우 `rifiuti-vista.exe` 사용).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### 볼륨 섀도 복사본

섀도 복사는 Microsoft Windows에 포함된 기술로, 컴퓨터 파일이나 볼륨의 **백업 복사본** 또는 스냅샷을 생성할 수 있습니다. 사용 중일 때도 가능합니다.

이 백업은 일반적으로 파일 시스템의 루트에 있는 `\System Volume Information`에 위치하며, 이름은 다음 이미지에 표시된 **UID**로 구성됩니다:

![](<../../../images/image (520).png>)

**ArsenalImageMounter**로 포렌식 이미지를 마운트하면, 도구 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html)를 사용하여 섀도 복사를 검사하고 섀도 복사 백업에서 **파일을 추출**할 수 있습니다.

![](<../../../images/image (521).png>)

레지스트리 항목 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`는 **백업하지 않을** 파일과 키를 포함합니다:

![](<../../../images/image (522).png>)

레지스트리 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`는 `볼륨 섀도 복사본`에 대한 구성 정보도 포함합니다.

### 오피스 자동 저장 파일

오피스 자동 저장 파일은 다음 위치에서 찾을 수 있습니다: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## 셸 항목

셸 항목은 다른 파일에 접근하는 방법에 대한 정보를 포함하는 항목입니다.

### 최근 문서 (LNK)

Windows는 사용자가 다음 위치에서 **파일을 열거나, 사용하거나, 생성할 때** 이러한 **바로 가기**를 **자동으로 생성**합니다:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

폴더가 생성되면, 해당 폴더, 상위 폴더 및 조상 폴더에 대한 링크도 생성됩니다.

이 자동 생성된 링크 파일은 **원본에 대한 정보**를 **포함**합니다. 예를 들어, **파일**인지 **폴더**인지, 해당 파일의 **MAC** **시간**, 파일이 저장된 **볼륨 정보**, **대상 파일의 폴더** 등이 있습니다. 이 정보는 파일이 삭제된 경우 복구하는 데 유용할 수 있습니다.

또한, 링크 파일의 **생성 날짜**는 원본 파일이 **처음 사용된** **시간**이며, 링크 파일의 **수정 날짜**는 원본 파일이 **마지막으로 사용된** **시간**입니다.

이 파일을 검사하려면 [**LinkParser**](http://4discovery.com/our-tools/)를 사용할 수 있습니다.

이 도구에서는 **2세트**의 타임스탬프를 찾을 수 있습니다:

- **첫 번째 세트:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **두 번째 세트:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

첫 번째 세트의 타임스탬프는 **파일 자체의 타임스탬프**를 참조합니다. 두 번째 세트는 **링크된 파일의 타임스탬프**를 참조합니다.

Windows CLI 도구 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행하여 동일한 정보를 얻을 수 있습니다.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
이 경우, 정보는 CSV 파일에 저장됩니다.

### 점프 리스트

이것은 각 애플리케이션에 대해 표시되는 최근 파일입니다. 각 애플리케이션에서 접근할 수 있는 **애플리케이션에 의해 사용된 최근 파일 목록**입니다. 이들은 **자동으로 생성되거나 사용자 정의**될 수 있습니다.

자동으로 생성된 **점프 리스트**는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장됩니다. 점프 리스트는 `{id}.autmaticDestinations-ms` 형식으로 이름이 지정되며, 초기 ID는 애플리케이션의 ID입니다.

사용자 정의 점프 리스트는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`에 저장되며, 일반적으로 파일과 관련하여 **중요한** 일이 발생했기 때문에 애플리케이션에 의해 생성됩니다(아마도 즐겨찾기로 표시됨).

어떤 점프 리스트의 **생성 시간**은 **파일에 처음 접근한 시간**을 나타내며, **수정 시간은 마지막 접근 시간**을 나타냅니다.

점프 리스트는 [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)를 사용하여 검사할 수 있습니다.

![](<../../../images/image (474).png>)

(_JumplistExplorer가 제공하는 타임스탬프는 점프 리스트 파일 자체와 관련이 있음을 유의하세요_)

### 셸백

[**이 링크를 따라가면 셸백에 대해 배울 수 있습니다.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

USB 장치가 사용되었음을 확인할 수 있는 방법은 다음과 같은 생성 덕분입니다:

- Windows 최근 폴더
- Microsoft Office 최근 폴더
- 점프 리스트

일부 LNK 파일은 원래 경로를 가리키는 대신 WPDNSE 폴더를 가리킵니다:

![](<../../../images/image (476).png>)

WPDNSE 폴더의 파일은 원본 파일의 복사본이므로 PC를 재시작하면 살아남지 않으며 GUID는 셸백에서 가져옵니다.

### 레지스트리 정보

[이 페이지를 확인하여](interesting-windows-registry-keys.md#usb-information) USB 연결 장치에 대한 흥미로운 정보를 포함하는 레지스트리 키를 배울 수 있습니다.

### setupapi

USB 연결이 발생한 시간을 알기 위해 `C:\Windows\inf\setupapi.dev.log` 파일을 확인하세요( `Section start`를 검색하세요).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB 탐지기

[**USBDetective**](https://usbdetective.com)를 사용하여 이미지에 연결된 USB 장치에 대한 정보를 얻을 수 있습니다.

![](<../../../images/image (483).png>)

### 플러그 앤 플레이 정리

'플러그 앤 플레이 정리'라는 예약 작업은 주로 구식 드라이버 버전을 제거하기 위해 설계되었습니다. 최신 드라이버 패키지 버전을 유지하는 지정된 목적과는 달리, 온라인 소스는 30일 동안 비활성 상태인 드라이버도 대상으로 한다고 제안합니다. 따라서 지난 30일 동안 연결되지 않은 이동식 장치의 드라이버는 삭제될 수 있습니다.

작업은 다음 경로에 위치합니다:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

작업의 내용을 보여주는 스크린샷이 제공됩니다:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**작업의 주요 구성 요소 및 설정:**

- **pnpclean.dll**: 이 DLL은 실제 정리 프로세스를 담당합니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 있으며, 일반 작업 스케줄링 엔진을 사용함을 나타냅니다.
- **MaintenanceSettings**:
- **Period ('P1M')**: 작업 스케줄러에 정기적인 자동 유지 관리 중 매월 정리 작업을 시작하도록 지시합니다.
- **Deadline ('P2M')**: 작업 스케줄러에 작업이 두 달 연속 실패할 경우 긴급 자동 유지 관리 중 작업을 실행하도록 지시합니다.

이 구성은 정기적인 유지 관리 및 드라이버 정리를 보장하며, 연속 실패 시 작업을 재시도할 수 있는 조항을 포함합니다.

**자세한 정보는 다음을 확인하세요:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## 이메일

이메일에는 **2개의 흥미로운 부분: 헤더와 이메일 내용**이 포함되어 있습니다. **헤더**에서 다음과 같은 정보를 찾을 수 있습니다:

- **누가** 이메일을 보냈는지 (이메일 주소, IP, 이메일을 리디렉션한 메일 서버)
- **언제** 이메일이 전송되었는지

또한, `References` 및 `In-Reply-To` 헤더 내에서 메시지의 ID를 찾을 수 있습니다:

![](<../../../images/image (484).png>)

### Windows 메일 앱

이 애플리케이션은 이메일을 HTML 또는 텍스트로 저장합니다. 이메일은 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`의 하위 폴더 내에서 찾을 수 있습니다. 이메일은 `.dat` 확장자로 저장됩니다.

이메일의 **메타데이터**와 **연락처**는 **EDB 데이터베이스** 내에서 찾을 수 있습니다: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

파일의 확장자를 `.vol`에서 `.edb`로 변경하면 도구 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)를 사용하여 열 수 있습니다. `Message` 테이블 내에서 이메일을 볼 수 있습니다.

### Microsoft Outlook

Exchange 서버 또는 Outlook 클라이언트를 사용할 때 MAPI 헤더가 생성됩니다:

- `Mapi-Client-Submit-Time`: 이메일이 전송된 시스템의 시간
- `Mapi-Conversation-Index`: 스레드의 자식 메시지 수 및 각 메시지의 타임스탬프
- `Mapi-Entry-ID`: 메시지 식별자.
- `Mappi-Message-Flags` 및 `Pr_last_Verb-Executed`: MAPI 클라이언트에 대한 정보 (메시지 읽음? 읽지 않음? 응답됨? 리디렉션됨? 부재 중?)

Microsoft Outlook 클라이언트에서는 모든 발신/수신 메시지, 연락처 데이터 및 일정 데이터가 PST 파일에 저장됩니다:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

레지스트리 경로 `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`는 사용 중인 파일을 나타냅니다.

PST 파일은 도구 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)를 사용하여 열 수 있습니다.

![](<../../../images/image (485).png>)

### Microsoft Outlook OST 파일

**OST 파일**은 Microsoft Outlook이 **IMAP** 또는 **Exchange** 서버로 구성될 때 생성되며, PST 파일과 유사한 정보를 저장합니다. 이 파일은 서버와 동기화되며, **지난 12개월** 동안의 데이터를 유지하고 **최대 50GB**의 크기를 가지며, PST 파일과 동일한 디렉토리에 위치합니다. OST 파일을 보려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.

### 첨부 파일 복구

잃어버린 첨부 파일은 다음에서 복구할 수 있습니다:

- **IE10**의 경우: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 및 그 이상**의 경우: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX 파일

**Thunderbird**는 **MBOX 파일**을 사용하여 데이터를 저장하며, 위치는 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`입니다.

### 이미지 썸네일

- **Windows XP 및 8-8.1**: 썸네일이 있는 폴더에 접근하면 삭제 후에도 이미지 미리보기를 저장하는 `thumbs.db` 파일이 생성됩니다.
- **Windows 7/10**: UNC 경로를 통해 네트워크에서 접근할 때 `thumbs.db`가 생성됩니다.
- **Windows Vista 및 이후 버전**: 썸네일 미리보기는 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`에 중앙 집중화되어 있으며, 파일 이름은 **thumbcache_xxx.db**입니다. [**Thumbsviewer**](https://thumbsviewer.github.io) 및 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 이러한 파일을 보기 위한 도구입니다.

### Windows 레지스트리 정보

Windows 레지스트리는 방대한 시스템 및 사용자 활동 데이터를 저장하며, 다음 파일에 포함되어 있습니다:

- `%windir%\System32\Config`에서 다양한 `HKEY_LOCAL_MACHINE` 하위 키에 대해.
- `%UserProfile%{User}\NTUSER.DAT`에서 `HKEY_CURRENT_USER`에 대해.
- Windows Vista 및 이후 버전은 `%Windir%\System32\Config\RegBack\`에 `HKEY_LOCAL_MACHINE` 레지스트리 파일을 백업합니다.
- 또한, 프로그램 실행 정보는 Windows Vista 및 Windows 2008 Server 이후부터 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`에 저장됩니다.

### 도구

레지스트리 파일을 분석하는 데 유용한 도구가 있습니다:

- **레지스트리 편집기**: Windows에 설치되어 있습니다. 현재 세션의 Windows 레지스트리를 탐색하는 GUI입니다.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): 레지스트리 파일을 로드하고 GUI를 통해 탐색할 수 있습니다. 흥미로운 정보를 가진 키를 강조하는 북마크도 포함되어 있습니다.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 다시 GUI가 있어 로드된 레지스트리를 탐색할 수 있으며, 로드된 레지스트리 내의 흥미로운 정보를 강조하는 플러그인도 포함되어 있습니다.
- [**Windows 레지스트리 복구**](https://www.mitec.cz/wrr.html): 로드된 레지스트리에서 중요한 정보를 추출할 수 있는 또 다른 GUI 애플리케이션입니다.

### 삭제된 요소 복구

키가 삭제되면 그렇게 표시되지만, 그 공간이 필요해질 때까지 제거되지 않습니다. 따라서 **Registry Explorer**와 같은 도구를 사용하면 이러한 삭제된 키를 복구할 수 있습니다.

### 마지막 수정 시간

각 Key-Value는 마지막으로 수정된 시간을 나타내는 **타임스탬프**를 포함합니다.

### SAM

파일/하이브 **SAM**은 시스템의 **사용자, 그룹 및 사용자 비밀번호** 해시를 포함합니다.

`SAM\Domains\Account\Users`에서 사용자 이름, RID, 마지막 로그인, 마지막 실패한 로그온, 로그인 카운터, 비밀번호 정책 및 계정 생성 시간을 얻을 수 있습니다. **해시**를 얻으려면 **SYSTEM** 파일/하이브도 **필요**합니다.

### Windows 레지스트리의 흥미로운 항목

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## 실행된 프로그램

### 기본 Windows 프로세스

[이 게시물](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)에서 의심스러운 행동을 감지하기 위한 일반 Windows 프로세스에 대해 배울 수 있습니다.

### Windows 최근 앱

레지스트리 `NTUSER.DAT`의 경로 `Software\Microsoft\Current Version\Search\RecentApps` 내에서 **실행된 애플리케이션**, **마지막 실행 시간**, **실행 횟수**에 대한 정보를 가진 하위 키를 찾을 수 있습니다.

### BAM (백그라운드 활동 조정기)

레지스트리 편집기를 사용하여 `SYSTEM` 파일을 열고 경로 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 내에서 **각 사용자가 실행한 애플리케이션**에 대한 정보를 찾을 수 있습니다(경로의 `{SID}`에 유의하세요) 및 **언제** 실행되었는지(시간은 레지스트리의 데이터 값 내에 있습니다).

### Windows 프리패치

프리패칭은 컴퓨터가 사용자가 **가까운 미래에 접근할 수 있는 콘텐츠를 표시하는 데 필요한 리소스를 조용히 가져오는** 기술입니다. 이를 통해 리소스에 더 빠르게 접근할 수 있습니다.

Windows 프리패치는 **실행된 프로그램의 캐시를 생성**하여 더 빠르게 로드할 수 있도록 합니다. 이러한 캐시는 경로 `C:\Windows\Prefetch` 내에 `.pf` 파일로 생성됩니다. XP/VISTA/WIN7에서는 128개의 파일 제한이 있으며, Win8/Win10에서는 1024개의 파일 제한이 있습니다.

파일 이름은 `{program_name}-{hash}.pf` 형식으로 생성됩니다(해시는 실행 파일의 경로와 인수에 기반합니다). W10에서는 이러한 파일이 압축됩니다. 파일의 존재만으로도 **프로그램이 실행되었음을** 나타냅니다.

파일 `C:\Windows\Prefetch\Layout.ini`는 **프리패치된 파일의 폴더 이름**을 포함합니다. 이 파일은 **실행 횟수**, **실행 날짜** 및 **프로그램에 의해 열린 파일**에 대한 정보를 포함합니다.

이 파일을 검사하려면 도구 [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)를 사용할 수 있습니다:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (487).png>)

### Superprefetch

**Superprefetch**는 **다음에 로드될 프로그램**을 예측하여 **프로그램을 더 빠르게 로드**하는 것과 같은 목표를 가지고 있습니다. 그러나, 이는 prefetch 서비스를 대체하지 않습니다.\
이 서비스는 `C:\Windows\Prefetch\Ag*.db`에 데이터베이스 파일을 생성합니다.

이 데이터베이스에서는 **프로그램**의 **이름**, **실행** **횟수**, **열린** **파일**, **액세스된** **볼륨**, **전체** **경로**, **시간대** 및 **타임스탬프**를 찾을 수 있습니다.

이 정보를 사용하여 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 도구에 접근할 수 있습니다.

### SRUM

**System Resource Usage Monitor** (SRUM) **는** **프로세스**에 의해 **소비된** **자원**을 **모니터링**합니다. W8에서 등장했으며, `C:\Windows\System32\sru\SRUDB.dat`에 ESE 데이터베이스에 데이터를 저장합니다.

다음과 같은 정보를 제공합니다:

- AppID 및 경로
- 프로세스를 실행한 사용자
- 전송된 바이트
- 수신된 바이트
- 네트워크 인터페이스
- 연결 지속 시간
- 프로세스 지속 시간

이 정보는 매 60분마다 업데이트됩니다.

이 파일에서 날짜를 얻으려면 [**srum_dump**](https://github.com/MarkBaggett/srum-dump) 도구를 사용할 수 있습니다.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**는 **ShimCache**로도 알려져 있으며, **Microsoft**에서 애플리케이션 호환성 문제를 해결하기 위해 개발한 **Application Compatibility Database**의 일부입니다. 이 시스템 구성 요소는 다음과 같은 다양한 파일 메타데이터를 기록합니다:

- 파일의 전체 경로
- 파일의 크기
- **$Standard_Information** (SI) 아래의 마지막 수정 시간
- ShimCache의 마지막 업데이트 시간
- 프로세스 실행 플래그

이러한 데이터는 운영 체제 버전에 따라 특정 위치의 레지스트리에 저장됩니다:

- XP의 경우, 데이터는 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` 아래에 저장되며, 96개의 항목을 수용할 수 있습니다.
- Server 2003 및 Windows 버전 2008, 2012, 2016, 7, 8, 10의 경우, 저장 경로는 `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`이며, 각각 512개 및 1024개의 항목을 수용합니다.

저장된 정보를 파싱하기 위해 [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser)의 사용이 권장됩니다.

![](<../../../images/image (488).png>)

### Amcache

**Amcache.hve** 파일은 시스템에서 실행된 애플리케이션에 대한 세부 정보를 기록하는 레지스트리 하이브입니다. 일반적으로 `C:\Windows\AppCompat\Programas\Amcache.hve`에 위치합니다.

이 파일은 최근에 실행된 프로세스의 기록을 저장하는 것으로 주목받으며, 실행 파일의 경로와 SHA1 해시를 포함합니다. 이 정보는 시스템에서 애플리케이션의 활동을 추적하는 데 매우 유용합니다.

**Amcache.hve**에서 데이터를 추출하고 분석하기 위해 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) 도구를 사용할 수 있습니다. 다음 명령은 AmcacheParser를 사용하여 **Amcache.hve** 파일의 내용을 파싱하고 결과를 CSV 형식으로 출력하는 방법의 예입니다:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
생성된 CSV 파일 중에서 `Amcache_Unassociated file entries`는 관련 없는 파일 항목에 대한 풍부한 정보를 제공하기 때문에 특히 주목할 만합니다.

가장 흥미로운 CVS 파일은 `Amcache_Unassociated file entries`입니다.

### RecentFileCache

이 아티팩트는 W7에서만 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에 존재하며, 일부 바이너리의 최근 실행에 대한 정보를 포함하고 있습니다.

파일을 파싱하려면 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 도구를 사용할 수 있습니다.

### Scheduled tasks

이들은 `C:\Windows\Tasks` 또는 `C:\Windows\System32\Tasks`에서 추출할 수 있으며 XML 형식으로 읽을 수 있습니다.

### Services

이들은 `SYSTEM\ControlSet001\Services` 레지스트리에서 찾을 수 있습니다. 어떤 것이 실행될 것인지와 언제 실행될 것인지 확인할 수 있습니다.

### **Windows Store**

설치된 애플리케이션은 `\ProgramData\Microsoft\Windows\AppRepository\`에서 찾을 수 있습니다. 이 저장소에는 데이터베이스 **`StateRepository-Machine.srd`** 내에 시스템에 설치된 **각 애플리케이션**에 대한 **로그**가 있습니다.

이 데이터베이스의 애플리케이션 테이블 내에서 "Application ID", "PackageNumber", "Display Name" 열을 찾을 수 있습니다. 이 열은 사전 설치된 애플리케이션과 설치된 애플리케이션에 대한 정보를 포함하고 있으며, 설치된 애플리케이션의 ID는 순차적이어야 하므로 일부 애플리케이션이 제거되었는지 확인할 수 있습니다.

레지스트리 경로 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 내에서도 **설치된 애플리케이션**을 찾을 수 있습니다.\
그리고 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`에서 **제거된** **애플리케이션**을 찾을 수 있습니다.

## Windows Events

Windows 이벤트 내에 나타나는 정보는 다음과 같습니다:

- 발생한 사건
- 타임스탬프 (UTC + 0)
- 관련된 사용자
- 관련된 호스트 (호스트 이름, IP)
- 접근된 자산 (파일, 폴더, 프린터, 서비스)

로그는 Windows Vista 이전에는 `C:\Windows\System32\config`에, Windows Vista 이후에는 `C:\Windows\System32\winevt\Logs`에 위치합니다. Windows Vista 이전에는 이벤트 로그가 이진 형식이었고, 이후에는 **XML 형식**으로 **.evtx** 확장자를 사용합니다.

이벤트 파일의 위치는 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**의 SYSTEM 레지스트리에서 찾을 수 있습니다.

Windows 이벤트 뷰어 (**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com) **또는** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**와 같은 다른 도구를 사용하여 시각화할 수 있습니다.

## Understanding Windows Security Event Logging

접근 이벤트는 `C:\Windows\System32\winevt\Security.evtx`에 위치한 보안 구성 파일에 기록됩니다. 이 파일의 크기는 조정 가능하며, 용량이 초과되면 이전 이벤트가 덮어씌워집니다. 기록된 이벤트에는 사용자 로그인 및 로그오프, 사용자 행동, 보안 설정 변경, 파일, 폴더 및 공유 자산 접근이 포함됩니다.

### 사용자 인증을 위한 주요 이벤트 ID:

- **EventID 4624**: 사용자가 성공적으로 인증되었음을 나타냅니다.
- **EventID 4625**: 인증 실패를 나타냅니다.
- **EventIDs 4634/4647**: 사용자 로그오프 이벤트를 나타냅니다.
- **EventID 4672**: 관리 권한으로 로그인했음을 나타냅니다.

#### EventID 4634/4647 내의 하위 유형:

- **Interactive (2)**: 직접 사용자 로그인.
- **Network (3)**: 공유 폴더 접근.
- **Batch (4)**: 배치 프로세스 실행.
- **Service (5)**: 서비스 시작.
- **Proxy (6)**: 프록시 인증.
- **Unlock (7)**: 비밀번호로 화면 잠금 해제.
- **Network Cleartext (8)**: 일반 텍스트 비밀번호 전송, 종종 IIS에서 발생.
- **New Credentials (9)**: 접근을 위한 다른 자격 증명 사용.
- **Remote Interactive (10)**: 원격 데스크톱 또는 터미널 서비스 로그인.
- **Cache Interactive (11)**: 도메인 컨트롤러와의 접촉 없이 캐시된 자격 증명으로 로그인.
- **Cache Remote Interactive (12)**: 캐시된 자격 증명으로 원격 로그인.
- **Cached Unlock (13)**: 캐시된 자격 증명으로 잠금 해제.

#### EventID 4625의 상태 및 하위 상태 코드:

- **0xC0000064**: 사용자 이름이 존재하지 않음 - 사용자 이름 열거 공격을 나타낼 수 있습니다.
- **0xC000006A**: 올바른 사용자 이름이지만 잘못된 비밀번호 - 비밀번호 추측 또는 무차별 대입 시도 가능성.
- **0xC0000234**: 사용자 계정이 잠김 - 여러 번의 로그인 실패로 인한 무차별 대입 공격 후 발생할 수 있습니다.
- **0xC0000072**: 계정 비활성화 - 비활성 계정에 대한 무단 접근 시도.
- **0xC000006F**: 허용된 시간 외 로그인 - 설정된 로그인 시간 외 접근 시도, 무단 접근의 가능성.
- **0xC0000070**: 워크스테이션 제한 위반 - 무단 위치에서 로그인 시도 가능성.
- **0xC0000193**: 계정 만료 - 만료된 사용자 계정으로 접근 시도.
- **0xC0000071**: 비밀번호 만료 - 만료된 비밀번호로 로그인 시도.
- **0xC0000133**: 시간 동기화 문제 - 클라이언트와 서버 간의 큰 시간 차이는 패스-더-티켓과 같은 더 정교한 공격을 나타낼 수 있습니다.
- **0xC0000224**: 필수 비밀번호 변경 필요 - 빈번한 필수 변경은 계정 보안을 불안정하게 하려는 시도를 나타낼 수 있습니다.
- **0xC0000225**: 보안 문제보다는 시스템 버그를 나타냅니다.
- **0xC000015b**: 거부된 로그인 유형 - 서비스 로그온을 시도하는 사용자와 같은 무단 로그인 유형으로 접근 시도.

#### EventID 4616:

- **시간 변경**: 시스템 시간 수정, 사건의 타임라인을 모호하게 할 수 있습니다.

#### EventID 6005 및 6006:

- **시스템 시작 및 종료**: EventID 6005는 시스템 시작을 나타내고, EventID 6006은 종료를 나타냅니다.

#### EventID 1102:

- **로그 삭제**: 보안 로그가 지워지는 경우, 이는 종종 불법 활동을 은폐하려는 신호입니다.

#### USB 장치 추적을 위한 이벤트 ID:

- **20001 / 20003 / 10000**: USB 장치 첫 연결.
- **10100**: USB 드라이버 업데이트.
- **EventID 112**: USB 장치 삽입 시간.

로그인 유형 및 자격 증명 덤핑 기회를 시뮬레이션하는 실용적인 예는 [Altered Security의 자세한 가이드](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)를 참조하십시오.

상태 및 하위 상태 코드를 포함한 이벤트 세부정보는 이벤트 원인에 대한 추가 통찰력을 제공하며, 특히 Event ID 4625에서 주목할 만합니다.

### Windows 이벤트 복구

삭제된 Windows 이벤트를 복구할 가능성을 높이기 위해, 의심되는 컴퓨터의 전원을 직접 분리하여 끄는 것이 좋습니다. **Bulk_extractor**, `.evtx` 확장자를 지정하는 복구 도구는 이러한 이벤트를 복구하려고 시도하는 데 권장됩니다.

### Windows 이벤트를 통한 일반 공격 식별

일반 사이버 공격을 식별하는 데 Windows 이벤트 ID를 활용하는 포괄적인 가이드는 [Red Team Recipe](https://redteamrecipe.com/event-codes/)를 방문하십시오.

#### 무차별 대입 공격

여러 EventID 4625 기록으로 식별되며, 공격이 성공하면 EventID 4624가 뒤따릅니다.

#### 시간 변경

EventID 4616에 기록되며, 시스템 시간 변경은 포렌식 분석을 복잡하게 만들 수 있습니다.

#### USB 장치 추적

USB 장치 추적에 유용한 시스템 이벤트 ID는 초기 사용을 위한 20001/20003/10000, 드라이버 업데이트를 위한 10100, 삽입 타임스탬프를 위한 DeviceSetupManager의 EventID 112가 포함됩니다.

#### 시스템 전원 이벤트

EventID 6005는 시스템 시작을 나타내고, EventID 6006은 종료를 나타냅니다.

#### 로그 삭제

보안 EventID 1102는 로그 삭제를 신호하며, 이는 포렌식 분석에 중요한 이벤트입니다.


{{#include ../../../banners/hacktricks-training.md}}
