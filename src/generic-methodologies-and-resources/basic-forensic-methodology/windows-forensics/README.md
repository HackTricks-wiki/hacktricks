# Windows 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 일반적인 Windows 아티팩트

### Windows 10 알림

경로 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`에서 데이터베이스 `appdb.dat`(Windows anniversary 이전) 또는 `wpndatabase.db`(Windows Anniversary 이후)를 찾을 수 있습니다.

이 SQLite 데이터베이스 내에서 모든 알림이 포함된 `Notification` 테이블을 찾을 수 있으며, 알림은 흥미로운 데이터를 포함할 수 있는 XML 형식으로 저장됩니다.

### Timeline

Timeline은 방문한 웹 페이지, 편집한 문서 및 실행한 애플리케이션의 **시간순 기록**을 제공하는 Windows 기능입니다.

데이터베이스는 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` 경로에 있습니다. 이 데이터베이스는 SQLite 도구 또는 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 도구로 열 수 있으며, **생성된 2개의 파일은** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) 도구로 열 수 있습니다.

### ADS (Alternate Data Streams)

다운로드한 파일에는 인트라넷, 인터넷 등에서 **어떻게 다운로드되었는지**를 나타내는 **ADS Zone.Identifier**가 포함될 수 있습니다. 일부 소프트웨어(예: 브라우저)는 일반적으로 파일이 다운로드된 **URL**과 같은 **추가 정보**도 저장합니다.

## **파일 백업**

### 휴지통

Vista/Win7/Win8/Win10에서는 드라이브 루트의 **`$Recycle.bin`** 폴더(`C:\$Recycle.bin`)에서 **휴지통**을 찾을 수 있습니다.\
이 폴더에서 파일이 삭제되면 2개의 특정 파일이 생성됩니다:

- `$I{id}`: 파일 정보 (삭제된 날짜}
- `$R{id}`: 파일 내용

![파일 백업 - 휴지통: $R{id}: 파일 내용](<../../../images/image (1029).png>)

이 파일이 있으면 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 도구를 사용하여 삭제된 파일의 원래 경로와 삭제된 날짜를 확인할 수 있습니다(Vista – Win10에서는 `rifiuti-vista.exe` 사용).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![파일 백업 - 휴지통: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy는 Microsoft Windows에 포함된 기술로, 컴퓨터 파일 또는 볼륨이 사용 중인 경우에도 **백업 복사본** 또는 스냅샷을 생성할 수 있습니다.

이러한 백업은 일반적으로 파일 시스템 루트의 `\System Volume Information`에 위치하며, 이름은 다음 이미지에 표시된 **UIDs**로 구성됩니다.

![휴지통 - Volume Shadow Copies: 이러한 백업은 일반적으로 파일 시스템 루트의 System Volume Information에 위치하며, 이름은 이미지에 표시된 UIDs로 구성됩니다](<../../../images/image (94).png>)

**ArsenalImageMounter**로 forensics 이미지를 마운트하면 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 도구를 사용하여 shadow copy를 검사하고 shadow copy 백업에서 **파일을 추출**할 수도 있습니다.

![휴지통 - Volume Shadow Copies: ArsenalImageMounter로 forensics 이미지를 마운트하면 ShadowCopyView 도구를 사용하여 shadow copy를 검사하고 shadow copy 백업에서 파일을 추출할 수도 있습니다](<../../../images/image (576).png>)

레지스트리 항목 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`에는 **백업하지 않을 파일과 키**가 포함되어 있습니다.

![휴지통 - Volume Shadow Copies: 레지스트리 항목 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore에는 백업하지 않을 파일과 키가 포함되어 있습니다](<../../../images/image (254).png>)

레지스트리 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`에도 `Volume Shadow Copies`에 대한 configuration 정보가 포함되어 있습니다.

### Office AutoSaved Files

Office autosaved files는 다음 위치에서 찾을 수 있습니다: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Shell item은 다른 파일에 액세스하는 방법에 대한 정보를 포함하는 item입니다.

### Recent Documents (LNK)

Windows는 사용자가 다음 위치에서 **파일을 열거나, 사용하거나, 생성할 때** 이러한 **shortcuts**를 **자동으로 생성**합니다.

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

폴더가 생성되면 해당 폴더, parent folder 및 grandparent folder에 대한 link도 생성됩니다.

이렇게 자동으로 생성된 link files에는 해당 항목이 **파일**인지 **폴더**인지, 파일의 **MAC** **times**, 파일이 저장된 **volume information**, 그리고 **target file의 folder**와 같은 **origin 정보**가 포함되어 있습니다. 이 정보는 파일이 삭제된 경우 해당 파일을 복구하는 데 유용할 수 있습니다.

또한 link file의 **생성 날짜**는 원본 파일이 **처음 사용된** 최초 **시점**이며, link file의 **수정 날짜**는 origin file이 사용된 **마지막** **시점**입니다.

이러한 파일을 검사하려면 [**LinkParser**](http://4discovery.com/our-tools/)를 사용할 수 있습니다.

이 도구에서는 **2개의 timestamp 집합**을 확인할 수 있습니다.

- **첫 번째 집합:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **두 번째 집합:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

첫 번째 timestamp 집합은 **파일 자체의 timestamps**를 나타냅니다. 두 번째 집합은 **linked file의 timestamps**를 나타냅니다.

Windows CLI 도구인 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행해 동일한 정보를 얻을 수 있습니다.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
이 경우 정보는 CSV 파일에 저장됩니다.

### Jumplists

이는 애플리케이션별로 표시되는 최근 파일입니다. 각 애플리케이션에서 액세스할 수 있는 **애플리케이션이 최근에 사용한 파일** 목록입니다. **자동으로 생성되거나 사용자 지정으로 생성**될 수 있습니다.

자동으로 생성된 **jumplists**는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장됩니다. jumplists는 `{id}.autmaticDestinations-ms` 형식으로 이름이 지정되며, 초기 ID는 애플리케이션의 ID입니다.

사용자 지정 jumplists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`에 저장됩니다. 일반적으로 파일에 **중요한 이벤트**가 발생했기 때문에 애플리케이션에서 생성합니다(예: 즐겨찾기로 표시된 경우).

모든 jumplist의 **생성 시간**은 **파일에 처음 액세스한 시간**을 나타내며, **수정 시간은 마지막으로 액세스한 시간**을 나타냅니다.

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)를 사용하여 jumplists를 검사할 수 있습니다.

![최근 문서(LNK) - Jumplists: JumplistExplorer를 사용하여 jumplists를 검사할 수 있습니다](<../../../images/image (168).png>)

(_JumplistExplorer가 제공하는 타임스탬프는 jumplist 파일 자체와 관련되어 있다는 점에 유의하세요_)

### Shellbags

[**Shellbags가 무엇인지 알아보려면 이 링크를 참조하세요.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

다음 항목의 생성을 통해 USB 장치가 사용되었음을 식별할 수 있습니다.

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

일부 LNK 파일은 원래 경로를 가리키는 대신 WPDNSE 폴더를 가리킨다는 점에 유의하세요.

![Shellbags - Windows USB 사용: 일부 LNK 파일은 원래 경로를 가리키는 대신 WPDNSE 폴더를 가리킵니다](<../../../images/image (218).png>)

WPDNSE 폴더의 파일은 원본 파일의 복사본이므로 PC를 다시 시작하면 유지되지 않으며, GUID는 shellbag에서 가져옵니다.

### Registry Information

USB 연결 장치에 대한 흥미로운 정보를 포함하는 registry 키를 알아보려면 [이 페이지를 확인하세요](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB 연결이 발생한 시점의 타임스탬프를 확인하려면 `C:\Windows\inf\setupapi.dev.log` 파일을 확인하세요(`Section start` 검색).

![Registry Information - setupapi: USB 연결이 발생한 시점의 타임스탬프를 확인하려면 C: Windows inf setupapi.dev.log 파일을 확인하세요(Section start 검색)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)를 사용하여 이미지에 연결된 적이 있는 USB 장치에 대한 정보를 얻을 수 있습니다.

![setupapi - USB Detective: USBDetective를 사용하여 이미지에 연결된 적이 있는 USB 장치에 대한 정보를 얻을 수 있습니다](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup'이라는 scheduled task는 주로 오래된 driver 버전을 제거하도록 설계되었습니다. 최신 driver package 버전을 유지한다는 명시된 목적과 달리, online sources에 따르면 30일 동안 비활성 상태였던 driver도 대상으로 지정합니다. 따라서 지난 30일 동안 연결되지 않은 removable device용 driver가 삭제될 수 있습니다.<sup>[[1]](#references)</sup>

task는 다음 경로에 있습니다: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

task의 내용을 보여 주는 screenshot이 제공됩니다: ![USB Detective - Plug and Play Cleanup: task는 다음 경로에 있습니다: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**task의 주요 구성 요소 및 설정:**

- **pnpclean.dll**: 이 DLL은 실제 cleanup process를 담당합니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 있으며, generic task scheduling engine을 사용한다는 의미입니다.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler가 일반적인 Automatic maintenance 중 매월 cleanup task를 시작하도록 지시합니다.
- **Deadline ('P2M')**: task가 2개월 연속 실패할 경우, Task Scheduler가 emergency Automatic maintenance 중 task를 실행하도록 지시합니다.

이 설정은 driver의 정기적인 maintenance 및 cleanup을 보장하며, 연속적인 실패가 발생할 경우 task를 다시 시도할 수 있도록 합니다.

**자세한 내용은 다음을 확인하세요:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Emails에는 **2가지 흥미로운 부분인 headers와 email content**가 포함되어 있습니다. **headers**에서는 다음과 같은 정보를 확인할 수 있습니다.

- Emails를 보낸 사람(email address, email을 redirect한 IP, mail servers)
- Email이 전송된 시점

또한 `References` 및 `In-Reply-To` headers에서 messages의 ID를 확인할 수 있습니다.

![Plug and Play Cleanup - Emails: Email이 전송된 시점](<../../../images/image (593).png>)

### Windows Mail App

이 application은 emails를 HTML 또는 text로 저장합니다. `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 내부의 하위 폴더에서 emails를 찾을 수 있습니다. Emails는 `.dat` extension으로 저장됩니다.

Emails의 **metadata**와 **contacts**는 **EDB database**인 `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 내부에서 확인할 수 있습니다.

파일의 **extension을 변경**하여 `.vol`에서 `.edb`로 바꾼 다음 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) tool을 사용하여 열 수 있습니다. `Message` table에서 emails를 확인할 수 있습니다.

### Microsoft Outlook

Exchange servers 또는 Outlook clients를 사용하면 일부 MAPI headers가 존재합니다.

- `Mapi-Client-Submit-Time`: email이 전송된 system time
- `Mapi-Conversation-Index`: thread의 child messages 수와 thread 내 각 message의 timestamp
- `Mapi-Entry-ID`: Message identifier
- `Mappi-Message-Flags` 및 `Pr_last_Verb-Executed`: MAPI client에 대한 정보(message read? no read? responded? redirected? out of the office?)

Microsoft Outlook client에서는 전송/수신한 모든 messages, contacts data 및 calendar data가 다음 위치의 PST file에 저장됩니다.

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`는 사용 중인 file을 나타냅니다.

[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) tool을 사용하여 PST file을 열 수 있습니다.

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer tool을 사용하여 PST file을 열 수 있습니다](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file**은 Microsoft Outlook이 **IMAP** 또는 **Exchange** server로 구성된 경우 생성되며, PST file과 유사한 정보를 저장합니다. 이 file은 server와 synchronize되며, **최대 50GB 크기**까지 **지난 12개월간의 data**를 보존하고 PST file과 동일한 directory에 있습니다. OST file을 확인하려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.

### Retrieving Attachments

손실된 attachments는 다음 위치에서 복구할 수 있습니다.

- **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 이상**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird**는 data를 저장하기 위해 **MBOX files**를 사용하며, 해당 files는 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`에 있습니다.

### Image Thumbnails

- **Windows XP 및 8-8.1**: thumbnails가 있는 folder에 액세스하면 삭제된 후에도 image previews를 저장하는 `thumbs.db` file이 생성됩니다.
- **Windows 7/10**: UNC path를 통해 network상에서 액세스할 때 `thumbs.db`가 생성됩니다.
- **Windows Vista 및 이후 버전**: Thumbnail previews는 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`에 중앙 집중화되며, **thumbcache_xxx.db**라는 이름의 files로 저장됩니다. [**Thumbsviewer**](https://thumbsviewer.github.io) 및 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 이러한 files를 확인하기 위한 tools입니다.

### Windows Registry Information

광범위한 system 및 user activity data를 저장하는 Windows Registry는 다음 files에 포함되어 있습니다.

- 다양한 `HKEY_LOCAL_MACHINE` subkeys의 경우 `%windir%\System32\Config`
- `HKEY_CURRENT_USER`의 경우 `%UserProfile%{User}\NTUSER.DAT`
- Windows Vista 및 이후 versions에서는 `%Windir%\System32\Config\RegBack\`에 `HKEY_LOCAL_MACHINE` registry files의 backup이 저장됩니다.
- 또한 Windows Vista 및 Windows 2008 Server 이후부터 program execution information은 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`에 저장됩니다.

### Tools

registry files를 분석하는 데 유용한 tools가 있습니다.

- **Registry Editor**: Windows에 설치되어 있습니다. 현재 session의 Windows Registry를 탐색하기 위한 GUI입니다.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file을 load하고 GUI를 통해 탐색할 수 있습니다. 또한 흥미로운 정보가 있는 keys를 강조 표시하는 Bookmarks도 포함되어 있습니다.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 마찬가지로 load된 registry를 탐색할 수 있는 GUI를 제공하며, load된 registry 내부의 흥미로운 정보를 강조 표시하는 plugins도 포함되어 있습니다.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): load된 registry에서 중요한 정보를 추출할 수 있는 또 다른 GUI application입니다.

### Recovering Deleted Element

key가 삭제되면 삭제된 것으로 표시되지만, 해당 key가 차지하는 space가 필요할 때까지 제거되지 않습니다. 따라서 **Registry Explorer**와 같은 tools를 사용하면 이러한 삭제된 keys를 복구할 수 있습니다.

### Last Write Time

각 Key-Value에는 마지막으로 수정된 시간을 나타내는 **timestamp**가 포함되어 있습니다.

### SAM

**SAM** file/hive에는 system의 **users, groups 및 users passwords**의 hashes가 포함되어 있습니다.

`SAM\Domains\Account\Users`에서 username, RID, last login, last failed logon, login counter, password policy 및 account 생성 시점을 확인할 수 있습니다. **hashes**를 얻으려면 **SYSTEM** file/hive도 **필요합니다**.

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[이 post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)에서 의심스러운 behaviours를 탐지하기 위한 일반적인 Windows processes에 대해 알아볼 수 있습니다.

### Windows Recent APPs

registry `NTUSER.DAT`의 `Software\Microsoft\Current Version\Search\RecentApps` path에서 **실행된 application**, 해당 application이 **마지막으로 실행된 시점**, **실행된 횟수**에 대한 정보가 포함된 subkeys를 확인할 수 있습니다.

### BAM (Background Activity Moderator)

registry editor를 사용하여 `SYSTEM` file을 열고 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` path로 이동하면 각 user가 **실행한 applications**에 대한 정보({SID}가 path에 포함되어 있음)와 해당 applications가 **실행된 시점**을 확인할 수 있습니다(time은 registry의 Data value 내부에 있습니다).

### Windows Prefetch

Prefetching은 user가 **가까운 미래에 액세스할 수 있는** content를 표시하는 데 필요한 resources를 computer가 조용히 **가져오도록** 하여 resources에 더 빠르게 액세스할 수 있도록 하는 technique입니다.

Windows prefetch는 실행된 programs의 **cache를 생성**하여 더 빠르게 load할 수 있도록 합니다. 이러한 caches는 `C:\Windows\Prefetch` path 내부에 `.pf` files로 생성됩니다. XP/VISTA/WIN7에서는 128개, Win8/Win10에서는 1024개의 file로 제한됩니다.

file name은 `{program_name}-{hash}.pf` 형식으로 생성됩니다(hash는 executable의 path와 arguments를 기반으로 합니다). W10에서는 이러한 files가 compressed됩니다. file이 존재한다는 사실만으로도 **해당 program이 어느 시점에 실행되었다**는 것을 나타낸다는 점에 유의하세요.

`C:\Windows\Prefetch\Layout.ini` file에는 prefetch된 files가 포함된 **folders의 names**가 들어 있습니다. 이 file에는 **execution 횟수**, execution **dates**, 그리고 program이 **open한 files**에 대한 **information**이 포함되어 있습니다.

이 files를 검사하려면 [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) tool을 사용할 수 있습니다:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**는 prefetch와 같은 목표를 가집니다. 다음에 무엇이 로드될지 예측하여 **프로그램을 더 빠르게 로드**합니다. 그러나 prefetch service를 대체하지는 않습니다.\
이 service는 `C:\Windows\Prefetch\Ag*.db`에 database files를 생성합니다.

이 database에서 **program**의 **name**, **executions 횟수**, **opened된 files**, **accessed된 volume**, **complete path**, **timeframes** 및 **timestamps**를 확인할 수 있습니다.

이 정보는 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) tool을 사용하여 확인할 수 있습니다.

### SRUM

**System Resource Usage Monitor** (SRUM)은 **process가 소비한** **resources**를 **monitoring**합니다. W8에서 등장했으며, `C:\Windows\System32\sru\SRUDB.dat`에 위치한 ESE database에 data를 저장합니다.

다음 정보를 제공합니다:

- AppID 및 Path
- process를 실행한 User
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

이 정보는 60분마다 업데이트됩니다.

[**srum_dump**](https://github.com/MarkBaggett/srum-dump) tool을 사용하여 이 file에서 data를 가져올 수 있습니다.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**는 **ShimCache**라고도 하며, 애플리케이션 호환성 문제를 해결하기 위해 **Microsoft**가 개발한 **Application Compatibility Database**의 일부입니다. 이 시스템 구성 요소는 다음을 포함한 다양한 파일 메타데이터를 기록합니다:

- 파일의 전체 경로
- 파일 크기
- **$Standard_Information** (SI)의 마지막 수정 시간
- ShimCache의 마지막 업데이트 시간
- 프로세스 실행 플래그

이러한 데이터는 운영 체제 버전에 따라 특정 위치의 레지스트리에 저장됩니다:

- XP의 경우 데이터는 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`에 저장되며, 96개의 항목을 저장할 수 있습니다.
- Server 2003 및 Windows 2008, 2012, 2016, 7, 8, 10의 경우 저장 경로는 `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`이며, 각각 512개 및 1024개의 항목을 저장할 수 있습니다.

저장된 정보를 파싱하려면 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser)을 사용하는 것이 좋습니다.

![SRUM - AppCompatCache (ShimCache): 저장된 정보를 파싱하려면 AppCompatCacheParser tool을 사용하는 것이 좋습니다](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 파일은 시스템에서 실행된 애플리케이션의 세부 정보를 기록하는 레지스트리 하이브입니다. 일반적으로 `C:\Windows\AppCompat\Programas\Amcache.hve`에 있습니다.

이 파일은 실행된 최근 프로세스의 레코드를 저장하는 것으로 잘 알려져 있으며, 실행 파일의 경로와 SHA1 해시도 포함합니다. 이 정보는 시스템에서 애플리케이션의 활동을 추적하는 데 매우 유용합니다.

**Amcache.hve**에서 데이터를 추출하고 분석하려면 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool을 사용할 수 있습니다. 다음 명령은 AmcacheParser를 사용하여 **Amcache.hve** 파일의 내용을 파싱하고 결과를 CSV 형식으로 출력하는 방법의 예시입니다:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
생성된 CSV 파일 중 `Amcache_Unassociated file entries`는 연결되지 않은 파일 항목에 대한 풍부한 정보를 제공하므로 특히 주목할 만합니다.

생성되는 CSV 파일 중 가장 흥미로운 것은 `Amcache_Unassociated file entries`입니다.

### RecentFileCache

이 artifact는 W7의 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에서만 찾을 수 있으며, 일부 바이너리의 최근 실행에 대한 정보를 포함합니다.

도구 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)를 사용하여 파일을 파싱할 수 있습니다.

### Scheduled tasks

`C:\Windows\Tasks` 또는 `C:\Windows\System32\Tasks`에서 추출한 후 XML로 읽을 수 있습니다.

### Services

레지스트리의 `SYSTEM\ControlSet001\Services`에서 찾을 수 있습니다. 무엇이 실행될 예정인지와 언제 실행되는지 확인할 수 있습니다.

### **Windows Store**

설치된 애플리케이션은 `\ProgramData\Microsoft\Windows\AppRepository\`\
에서 찾을 수 있습니다.\
이 repository에는 데이터베이스 **`StateRepository-Machine.srd`** 내부에 시스템에 **설치된 각 애플리케이션**에 대한 **log**가 있습니다.

이 데이터베이스의 Application 테이블에서 "Application ID", "PackageNumber", "Display Name" 열을 확인할 수 있습니다. 이 열에는 사전 설치 및 설치된 애플리케이션에 대한 정보가 있으며, 설치된 애플리케이션의 ID는 순차적이어야 하므로 일부 애플리케이션이 제거되었는지 확인할 수 있습니다.

레지스트리 경로 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
에서도 **설치된 애플리케이션**을 찾을 수 있습니다.\
그리고 **제거된** **애플리케이션**은 `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`에서 찾을 수 있습니다.

## Windows Events

Windows events에 표시되는 정보는 다음과 같습니다.

- 발생한 내용
- Timestamp (UTC + 0)
- 관련된 Users
- 관련된 Hosts (hostname, IP)
- 액세스된 Assets (files, folder, printer, services)

로그는 Windows Vista 이전에는 `C:\Windows\System32\config`에 있으며, Windows Vista 이후에는 `C:\Windows\System32\winevt\Logs`에 있습니다. Windows Vista 이전에는 event logs가 binary format이었으며, 이후에는 **XML format**이고 **.evtx** extension을 사용합니다.

event files의 위치는 SYSTEM registry의 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**에서 확인할 수 있습니다.

Windows Event Viewer (**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com) **또는** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**와 같은 다른 도구로 확인할 수 있습니다.

## Windows Security Event Logging 이해하기

Access events는 `C:\Windows\System32\winevt\Security.evtx`에 있는 security configuration file에 기록됩니다. 이 파일의 크기는 조정할 수 있으며, 용량에 도달하면 오래된 events가 덮어써집니다. 기록되는 events에는 user logins 및 logoffs, user actions, security settings 변경 사항뿐만 아니라 files, folders 및 shared assets에 대한 access도 포함됩니다.

### User Authentication을 위한 주요 Event IDs:

- **EventID 4624**: 사용자가 성공적으로 authenticated되었음을 나타냅니다.
- **EventID 4625**: authentication failure를 나타냅니다.
- **EventIDs 4634/4647**: user logoff events를 나타냅니다.
- **EventID 4672**: administrative privileges를 사용한 login을 나타냅니다.

#### EventID 4634/4647 내부의 Sub-types:

- **Interactive (2)**: 직접적인 user login입니다.
- **Network (3)**: shared folders에 대한 access입니다.
- **Batch (4)**: batch processes 실행입니다.
- **Service (5)**: services launches입니다.
- **Proxy (6)**: proxy authentication입니다.
- **Unlock (7)**: password를 사용하여 screen이 unlocked된 경우입니다.
- **Network Cleartext (8)**: 일반적으로 IIS에서 발생하는 clear text password transmission입니다.
- **New Credentials (9)**: access에 다른 credentials를 사용하는 경우입니다.
- **Remote Interactive (10)**: remote desktop 또는 terminal services login입니다.
- **Cache Interactive (11)**: domain controller에 contact하지 않고 cached credentials로 login하는 경우입니다.
- **Cache Remote Interactive (12)**: cached credentials를 사용한 remote login입니다.
- **Cached Unlock (13)**: cached credentials를 사용하여 unlock하는 경우입니다.

#### EventID 4625의 Status 및 Sub Status Codes:

- **0xC0000064**: User name이 존재하지 않음 - username enumeration attack을 나타낼 수 있습니다.
- **0xC000006A**: 올바른 user name이지만 password가 틀림 - 가능한 password guessing 또는 brute-force 시도입니다.
- **0xC0000234**: User account가 locked out됨 - 여러 failed logins로 이어지는 brute-force attack 이후에 발생할 수 있습니다.
- **0xC0000072**: Account가 disabled됨 - disabled accounts에 access하려는 unauthorized attempts입니다.
- **0xC000006F**: 허용된 시간 외의 logon - 설정된 login hours 외에 access하려는 시도로, unauthorized access의 징후일 수 있습니다.
- **0xC0000070**: Workstation restrictions 위반 - unauthorized location에서 login하려는 시도일 수 있습니다.
- **0xC0000193**: Account expiration - expired user accounts를 사용한 access attempts입니다.
- **0xC0000071**: Expired password - 오래된 passwords를 사용한 login attempts입니다.
- **0xC0000133**: Time sync issues - client와 server 간의 큰 time discrepancies는 pass-the-ticket과 같은 더 정교한 attacks를 나타낼 수 있습니다.
- **0xC0000224**: Mandatory password change required - 빈번한 mandatory changes는 account security를 불안정하게 만들려는 시도일 수 있습니다.
- **0xC0000225**: Security issue가 아니라 system bug를 나타냅니다.
- **0xC000015b**: Denied logon type - user가 service logon을 실행하려는 경우와 같이 unauthorized logon type을 사용한 access attempt입니다.

#### EventID 4616:

- **Time Change**: system time의 modification이며, events의 timeline을 숨길 수 있습니다.

#### EventID 6005 및 6006:

- **System Startup and Shutdown**: EventID 6005는 system starting을 나타내고, EventID 6006은 system shutting down을 나타냅니다.

#### EventID 1102:

- **Log Deletion**: Security logs가 cleared되었음을 나타내며, 이는 불법 활동을 은폐하기 위한 red flag인 경우가 많습니다.

#### USB Device Tracking을 위한 EventIDs:

- **20001 / 20003 / 10000**: USB device의 first connection입니다.
- **10100**: USB driver update입니다.
- **EventID 112**: USB device insertion 시간입니다.

이러한 login types와 credential dumping opportunities를 simulation하는 practical examples는 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)를 참조하십시오.

Status 및 sub-status codes를 포함한 event details는 event causes에 대한 추가적인 insight를 제공하며, 특히 Event ID 4625에서 주목할 만합니다.

### Windows Events 복구하기

삭제된 Windows Events를 복구할 가능성을 높이려면 suspect computer의 전원을 직접 플러그를 뽑아 끄는 것이 좋습니다. `.evtx` extension을 지정하는 recovery tool인 **Bulk_extractor**를 사용하여 이러한 events의 복구를 시도하는 것이 권장됩니다.

### Windows Events를 통한 일반적인 Attacks 식별

일반적인 cyber attacks를 식별하기 위해 Windows Event IDs를 사용하는 방법에 대한 comprehensive guide는 [Red Team Recipe](https://redteamrecipe.com/event-codes/)를 참조하십시오.

#### Brute Force Attacks

여러 EventID 4625 records로 식별할 수 있으며, attack이 성공하면 EventID 4624가 뒤따릅니다.

#### Time Change

EventID 4616으로 기록되며, system time 변경은 forensic analysis를 복잡하게 만들 수 있습니다.

#### USB Device Tracking

USB device tracking에 유용한 System EventIDs에는 initial use를 위한 20001/20003/10000, driver updates를 위한 10100, insertion timestamps를 제공하는 DeviceSetupManager의 EventID 112가 포함됩니다.

#### System Power Events

EventID 6005는 system startup을 나타내고, EventID 6006은 shutdown을 나타냅니다.

#### Log Deletion

Security EventID 1102는 logs의 deletion을 나타내며, forensic analysis를 위한 critical event입니다.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
