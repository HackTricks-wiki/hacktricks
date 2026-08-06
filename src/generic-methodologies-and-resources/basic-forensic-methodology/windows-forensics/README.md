# Windows 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 일반적인 Windows 아티팩트

### Windows 10 알림

`\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\Notifications` 경로에서 `appdb.dat` 데이터베이스(Windows anniversary 이전) 또는 `wpndatabase.db` 데이터베이스(Windows Anniversary 이후)를 찾을 수 있습니다.

이 SQLite 데이터베이스 내부에는 흥미로운 데이터를 포함할 수 있는 모든 알림(XML 형식)이 저장된 `Notification` 테이블이 있습니다.

### Timeline

Timeline은 방문한 웹 페이지, 편집한 문서 및 실행한 애플리케이션의 **시간순 기록**을 제공하는 Windows 기능입니다.

데이터베이스는 `\\Users\\<username>\\AppData\\Local\\ConnectedDevicesPlatform\\<id>\\ActivitiesCache.db` 경로에 있습니다. 이 데이터베이스는 SQLite 도구 또는 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 도구로 열 수 있으며, **이 도구로 생성된 2개의 파일은** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **도구로 열 수 있습니다**.

### ADS (Alternate Data Streams)

다운로드한 파일에는 인트라넷, 인터넷 등에서 **어떻게** **다운로드되었는지**를 나타내는 **ADS Zone.Identifier**가 포함될 수 있습니다. 일부 software(예: browsers)는 일반적으로 파일이 다운로드된 **URL**과 같은 **추가** **정보**까지 기록합니다.

## **파일 백업**

### Recycle Bin

Vista/Win7/Win8/Win10에서는 드라이브 루트의 **`$Recycle.bin`** 폴더(`C:\$Recycle.bin`)에서 **Recycle Bin**을 찾을 수 있습니다.\
이 폴더에서 파일을 삭제하면 2개의 특정 파일이 생성됩니다:

- `$I{id}`: 파일 정보 (삭제된 날짜}
- `$R{id}`: 파일 내용

![파일 백업 - Recycle Bin: $R{id}: 파일 내용](<../../../images/image (1029).png>)

이러한 파일이 있으면 [**Rifiuti**](https://github.com/abelcheung/rifiuti2) 도구를 사용하여 삭제된 파일의 원래 주소와 삭제된 날짜를 확인할 수 있습니다(Vista – Win10에서는 `rifiuti-vista.exe` 사용).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy는 사용 중인 경우에도 컴퓨터 파일 또는 볼륨의 **backup copies** 또는 스냅샷을 생성할 수 있는 Microsoft Windows에 포함된 기술입니다.

이러한 백업은 일반적으로 파일 시스템 루트의 `\System Volume Information`에 있으며, 이름은 다음 이미지에 표시된 **UIDs**로 구성됩니다.

![Recycle Bin - Volume Shadow Copies: 이러한 백업은 일반적으로 파일 시스템 루트의 System Volume Information에 있으며, 이름은 다음 이미지에 표시된 UIDs로 구성됩니다.](<../../../images/image (94).png>)

**ArsenalImageMounter**로 forensics image를 마운트하면 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) 도구를 사용하여 shadow copy를 검사하고 shadow copy 백업에서 **files를 extract**할 수도 있습니다.

![Recycle Bin - Volume Shadow Copies: ArsenalImageMounter로 forensics image를 마운트하면 ShadowCopyView 도구를 사용하여 shadow copy를 검사하고 shadow copy 백업에서 files를 extract할 수도 있습니다.](<../../../images/image (576).png>)

레지스트리 항목 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`에는 **backup하지 않을 files 및 keys**가 포함되어 있습니다.

![Recycle Bin - Volume Shadow Copies: 레지스트리 항목 HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore에는 backup하지 않을 files 및 keys가 포함되어 있습니다.](<../../../images/image (254).png>)

레지스트리 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`에도 `Volume Shadow Copies`에 대한 configuration information이 포함되어 있습니다.

### Office AutoSaved Files

office autosaved files는 다음 위치에서 찾을 수 있습니다: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

shell item은 다른 파일에 액세스하는 방법에 대한 information을 포함하는 item입니다.

### Recent Documents (LNK)

Windows는 사용자가 다음 위치에서 **file을 open, use 또는 create**할 때 이러한 **shortcuts**를 **automatically** **create**합니다.

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

폴더가 생성되면 해당 폴더, parent folder 및 grandparent folder에 대한 link도 생성됩니다.

이렇게 자동으로 생성된 link files에는 해당 항목이 **file**인지 **folder**인지, 해당 file의 **MAC times**, file이 저장된 **volume information**, 그리고 **target file의 folder**와 같은 **origin에 대한 information**이 포함됩니다. 이 information은 해당 files가 제거된 경우 복구하는 데 유용할 수 있습니다.

또한 link file의 **date created**는 원본 file이 **처음 사용된 첫 번째 time**이며, link file의 **date modified**는 origin file이 사용된 **마지막 time**입니다.

이러한 files를 검사하려면 [**LinkParser**](http://4discovery.com/our-tools/)를 사용할 수 있습니다.

이 tools에서는 **2 sets**의 timestamps를 확인할 수 있습니다.

- **First Set:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Second Set:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

첫 번째 timestamp set은 **file 자체의 timestamps**를 참조합니다. 두 번째 set은 **linked file의 timestamps**를 참조합니다.

Windows CLI tool인 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행해도 동일한 information을 얻을 수 있습니다.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
이 경우 정보는 CSV 파일 내부에 저장됩니다.

### Jumplists

각 애플리케이션별로 표시되는 최근 파일입니다. 각 애플리케이션에서 확인할 수 있는 **애플리케이션이 사용한 최근 파일** 목록입니다. **자동으로 생성되거나 사용자 지정으로 생성**될 수 있습니다.

자동으로 생성된 **jumplists**는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장됩니다. jumplists는 `{id}.autmaticDestinations-ms` 형식으로 이름이 지정되며, 앞의 ID는 애플리케이션의 ID입니다.

사용자 지정 jumplists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`에 저장됩니다. 일반적으로 파일에 **중요한 변경 사항**이 발생했을 때(예: 즐겨찾기로 표시된 경우) 애플리케이션에 의해 생성됩니다.

모든 jumplist의 **생성 시간**은 **파일에 처음 액세스한 시간**을 나타내며, **수정 시간은 마지막으로 액세스한 시간**을 나타냅니다.

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)를 사용하여 jumplists를 확인할 수 있습니다.

![최근 문서(LNK) - Jumplists: JumplistExplorer를 사용하여 jumplists를 확인할 수 있습니다](<../../../images/image (168).png>)

(_JumplistExplorer에서 제공하는 타임스탬프는 jumplist 파일 자체와 관련되어 있다는 점에 유의하세요_)

### Shellbags

[**이 링크를 따라 shellbags가 무엇인지 확인하세요.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

다음 항목이 생성되었는지 확인하여 USB 장치가 사용되었음을 식별할 수 있습니다.

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

일부 LNK 파일은 원래 경로를 가리키는 대신 WPDNSE 폴더를 가리킨다는 점에 유의하세요.

![Shellbags - Windows USB 사용: 일부 LNK 파일은 원래 경로를 가리키는 대신 WPDNSE 폴더를 가리킵니다](<../../../images/image (218).png>)

WPDNSE 폴더의 파일은 원본 파일의 복사본이므로 PC를 다시 시작하면 유지되지 않으며, GUID는 shellbag에서 가져옵니다.

### Registry Information

USB 연결 장치에 대한 흥미로운 정보를 포함하는 registry 키를 확인하려면 [이 페이지를 확인하세요](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB 연결이 발생한 시점의 타임스탬프를 확인하려면 `C:\Windows\inf\setupapi.dev.log` 파일을 확인하세요(`Section start`를 검색).

![Registry Information - setupapi: USB 연결이 발생한 시점의 타임스탬프를 확인하려면 C: Windows inf setupapi.dev.log 파일을 확인하세요(Section start 검색)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)를 사용하여 이미지에 연결된 적이 있는 USB 장치에 대한 정보를 얻을 수 있습니다.

![setupapi - USB Detective: USBDetective를 사용하여 이미지에 연결된 적이 있는 USB 장치에 대한 정보를 얻을 수 있습니다](<../../../images/image (452).png>)

### Plug and Play Cleanup

'Plug and Play Cleanup'이라는 scheduled task는 주로 오래된 driver 버전을 제거하기 위해 설계되었습니다. 최신 driver package 버전을 유지한다는 명시된 목적과는 달리, 온라인 자료에 따르면 30일 동안 비활성 상태였던 driver도 대상으로 지정합니다. 따라서 지난 30일 동안 연결되지 않은 removable device의 driver는 삭제될 수 있습니다.<sup>[[1]](#references)</sup>

task는 다음 경로에 있습니다: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

task의 내용을 보여 주는 screenshot은 다음과 같습니다: ![USB Detective - Plug and Play Cleanup: task는 다음 경로에 있습니다: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**task의 주요 구성 요소 및 설정:**

- **pnpclean.dll**: 실제 cleanup process를 담당하는 DLL입니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 있으며, generic task scheduling engine을 사용한다는 의미입니다.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler가 정기적인 Automatic maintenance 중 매월 cleanup task를 시작하도록 지시합니다.
- **Deadline ('P2M')**: task가 2개월 연속 실패하면 Task Scheduler가 emergency Automatic maintenance 중 task를 실행하도록 지시합니다.

이 configuration은 driver의 정기적인 maintenance 및 cleanup을 보장하며, 연속적인 실패가 발생할 경우 task를 다시 시도하도록 합니다.

**자세한 내용은 다음을 확인하세요:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Emails에는 **2가지 흥미로운 부분인 header와 email content**가 포함됩니다. **header**에서 다음과 같은 정보를 확인할 수 있습니다.

- Emails를 보낸 사람(Email address, email을 redirect한 IP, mail server)
- Email을 보낸 시점

또한 `References` 및 `In-Reply-To` header에서 message의 ID를 확인할 수 있습니다.

![Plug and Play Cleanup - Emails: Email을 보낸 시점](<../../../images/image (593).png>)

### Windows Mail App

이 application은 email을 HTML 또는 text로 저장합니다. `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 내부의 subfolder에서 emails를 확인할 수 있습니다. Emails는 `.dat` extension으로 저장됩니다.

Emails의 **metadata** 및 **contacts**는 **EDB database**인 `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 내부에서 확인할 수 있습니다.

파일의 **extension을** `.vol`에서 `.edb`로 변경하면 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) tool을 사용하여 열 수 있습니다. `Message` table에서 emails를 확인할 수 있습니다.

### Microsoft Outlook

Exchange server 또는 Outlook client를 사용하면 다음과 같은 MAPI header가 존재합니다.

- `Mapi-Client-Submit-Time`: Email을 보낸 시스템 시간
- `Mapi-Conversation-Index`: Thread의 child message 수와 thread의 각 message timestamp
- `Mapi-Entry-ID`: Message identifier입니다.
- `Mappi-Message-Flags` 및 `Pr_last_Verb-Executed`: MAPI client에 대한 정보(message를 읽었는가? 읽지 않았는가? 응답했는가? redirect했는가? 부재중인가?)

Microsoft Outlook client에서는 전송/수신한 모든 messages, contacts data 및 calendar data가 다음 경로의 PST file에 저장됩니다.

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`는 사용 중인 file을 나타냅니다.

[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) tool을 사용하여 PST file을 열 수 있습니다.

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer tool을 사용하여 PST file을 열 수 있습니다](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file**은 Microsoft Outlook이 **IMAP** 또는 **Exchange** server로 configuration되었을 때 생성되며, PST file과 유사한 정보를 저장합니다. 이 file은 server와 synchronize되며, **최근 12개월**의 data를 **최대 50GB 크기**까지 보존하고 PST file과 동일한 directory에 위치합니다. OST file을 확인하려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.

### Retrieving Attachments

손실된 attachments는 다음 위치에서 복구할 수 있습니다.

- **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 이상**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird**는 data를 저장하기 위해 **MBOX files**를 사용하며, `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`에 위치합니다.

### Image Thumbnails

- **Windows XP 및 8-8.1**: thumbnail이 있는 folder에 액세스하면 삭제된 후에도 image preview를 저장하는 `thumbs.db` file이 생성됩니다.
- **Windows 7/10**: UNC path를 통해 network에서 액세스할 때 `thumbs.db`가 생성됩니다.
- **Windows Vista 이상**: Thumbnail preview는 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`에 중앙 집중화되며, **thumbcache_xxx.db**라는 이름의 file로 저장됩니다. [**Thumbsviewer**](https://thumbsviewer.github.io) 및 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 이러한 files를 확인하는 tool입니다.

### Windows Registry Information

광범위한 system 및 user activity data를 저장하는 Windows Registry는 다음 files에 포함되어 있습니다.

- 다양한 `HKEY_LOCAL_MACHINE` subkey의 경우 `%windir%\System32\Config`.
- `HKEY_CURRENT_USER`의 경우 `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista 및 이후 version은 `%Windir%\System32\Config\RegBack\`에 `HKEY_LOCAL_MACHINE` registry files를 backup합니다.
- 또한 Windows Vista 및 Windows 2008 Server 이후부터 program execution information은 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`에 저장됩니다.

### Tools

registry files를 분석하는 데 유용한 tool은 다음과 같습니다.

- **Registry Editor**: Windows에 설치되어 있습니다. 현재 session의 Windows registry를 GUI로 탐색할 수 있습니다.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file을 load하고 GUI를 통해 탐색할 수 있습니다. 또한 흥미로운 information이 있는 key를 강조 표시하는 Bookmarks도 포함되어 있습니다.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 마찬가지로 load된 registry를 탐색할 수 있는 GUI를 제공하며, load된 registry 내부에서 흥미로운 information을 강조 표시하는 plugin도 포함되어 있습니다.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): load된 registry에서 중요한 information을 추출할 수 있는 또 다른 GUI application입니다.

### Recovering Deleted Element

key가 삭제되면 삭제된 것으로 표시되지만, 해당 key가 차지하는 공간이 필요해질 때까지 제거되지 않습니다. 따라서 [**Registry Explorer**]와 같은 tool을 사용하면 삭제된 key를 복구할 수 있습니다.

### Last Write Time

각 Key-Value에는 마지막으로 수정된 시간을 나타내는 **timestamp**가 포함됩니다.

### SAM

**SAM** file/hive에는 system의 **users, groups 및 user password** hashes가 포함되어 있습니다.

`SAM\Domains\Account\Users`에서 username, RID, 마지막 login, 마지막 failed logon, login counter, password policy 및 account 생성 시점을 확인할 수 있습니다. **hashes**를 가져오려면 **SYSTEM** file/hive도 **필요합니다**.

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

[이 post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)에서 suspicious behaviour를 탐지하기 위한 일반적인 Windows process에 대해 알아볼 수 있습니다.<sup>[[2]](#references)</sup>

### Windows Recent APPs

registry `NTUSER.DAT`의 `Software\Microsoft\Current Version\Search\RecentApps` path 내부에서 **실행된 application**, **마지막 실행 시점** 및 **실행 횟수**에 대한 정보가 포함된 subkey를 확인할 수 있습니다.

### BAM (Background Activity Moderator)

registry editor로 `SYSTEM` file을 열고 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` path 내부에서 각 user가 **실행한 application**에 대한 정보(path의 `{SID}`에 유의)와 해당 application이 실행된 **시간**을 확인할 수 있습니다(시간은 registry의 Data value 내부에 있습니다).

### Windows Prefetch

Prefetching은 user가 **가까운 미래에 액세스할 수 있는** content를 표시하는 데 필요한 리소스를 컴퓨터가 자동으로 **가져오도록** 하여 리소스에 더 빠르게 액세스할 수 있게 하는 technique입니다.

Windows prefetch는 실행된 program의 **cache**를 생성하여 더 빠르게 load할 수 있도록 합니다. 이러한 cache는 `C:\Windows\Prefetch` path 내부에 `.pf` file로 생성됩니다. XP/VISTA/WIN7에서는 128개, Win8/Win10에서는 1024개의 file로 제한됩니다.

File name은 `{program_name}-{hash}.pf` 형식으로 생성됩니다(hash는 executable의 path와 argument를 기반으로 합니다). W10에서는 이 files가 compressed됩니다. 단순히 file이 존재한다는 사실만으로도 **해당 program이 어느 시점에 실행되었음**을 나타낸다는 점에 유의하세요.

`C:\Windows\Prefetch\Layout.ini` file에는 prefetch되는 file의 **folder name**이 포함되어 있습니다. 이 file에는 **실행 횟수**, 실행 **dates** 및 program에 의해 **open된 files**에 대한 **information**이 포함되어 있습니다.

이 files를 확인하려면 [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) tool을 사용할 수 있습니다:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch**는 prefetch와 동일한 목적, 즉 다음에 로드될 항목을 예측하여 **프로그램을 더 빠르게 로드**하는 것을 목표로 합니다. 그러나 prefetch service를 대체하지는 않습니다.\
이 service는 `C:\Windows\Prefetch\Ag*.db`에 database files를 생성합니다.

이 database에서 **program**의 **name**, **executions 횟수**, **opened files**, **accessed volume**, **complete path**, **timeframes** 및 **timestamps**를 확인할 수 있습니다.

이 정보는 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) tool을 사용하여 확인할 수 있습니다.

### SRUM

**System Resource Usage Monitor** (SRUM)은 **process가 소비한 resources**를 **monitor**합니다. W8에서 등장했으며, `C:\Windows\System32\sru\SRUDB.dat`에 위치한 ESE database에 data를 저장합니다.

다음 정보를 제공합니다:

- AppID and Path
- process를 실행한 User
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

이 정보는 60분마다 업데이트됩니다.

[**srum_dump**](https://github.com/MarkBaggett/srum-dump) tool을 사용하여 이 file에서 date를 가져올 수 있습니다.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**는 **ShimCache**라고도 하며, 애플리케이션 호환성 문제를 해결하기 위해 **Microsoft**에서 개발한 **Application Compatibility Database**의 일부입니다. 이 시스템 구성 요소는 다음과 같은 다양한 파일 메타데이터를 기록합니다.

- 파일의 전체 경로
- 파일 크기
- **$Standard_Information** (SI)의 마지막 수정 시간
- ShimCache의 마지막 업데이트 시간
- 프로세스 실행 플래그

이러한 데이터는 운영 체제 버전에 따라 특정 위치의 레지스트리에 저장됩니다.

- XP의 경우 데이터는 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`에 저장되며, 96개의 항목을 저장할 수 있습니다.
- Server 2003 및 Windows 2008, 2012, 2016, 7, 8, 10의 경우 저장 경로는 `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`이며, 각각 512개 및 1024개의 항목을 저장할 수 있습니다.

저장된 정보를 파싱하려면 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser)을 사용하는 것이 좋습니다.

![SRUM - AppCompatCache (ShimCache): 저장된 정보를 파싱하려면 AppCompatCacheParser tool을 사용하는 것이 좋습니다](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** 파일은 시스템에서 실행된 애플리케이션의 세부 정보를 기록하는 레지스트리 hive입니다. 일반적으로 `C:\Windows\AppCompat\Programas\Amcache.hve`에 있습니다.

이 파일은 최근 실행된 프로세스의 레코드를 저장하는 것으로 알려져 있으며, 실행 파일의 경로와 SHA1 hash가 포함됩니다. 이 정보는 시스템에서 애플리케이션의 활동을 추적하는 데 매우 유용합니다.

**Amcache.hve**에서 데이터를 추출하고 분석하려면 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool을 사용할 수 있습니다. 다음 명령은 AmcacheParser를 사용하여 **Amcache.hve** 파일의 내용을 파싱하고 결과를 CSV 형식으로 출력하는 방법의 예시입니다:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
생성된 CSV 파일 중 `Amcache_Unassociated file entries`는 unassociated file entries에 대한 풍부한 정보를 제공하므로 특히 주목할 만합니다.

생성되는 CVS 파일 중 가장 흥미로운 파일은 `Amcache_Unassociated file entries`입니다.

### RecentFileCache

이 artifact는 W7에서만 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에 존재하며, 일부 binary의 최근 실행 정보가 포함되어 있습니다.

도구 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)를 사용하여 파일을 parse할 수 있습니다.

### Scheduled tasks

`C:\Windows\Tasks` 또는 `C:\Windows\System32\Tasks`에서 추출한 후 XML로 읽을 수 있습니다.

### Services

Registry의 `SYSTEM\ControlSet001\Services`에서 확인할 수 있습니다. 무엇이 실행될 예정인지와 언제 실행되는지 확인할 수 있습니다.

### **Windows Store**

설치된 application은 `\ProgramData\Microsoft\Windows\AppRepository\`에서 확인할 수 있습니다.\
이 repository에는 database **`StateRepository-Machine.srd`** 내부에 시스템에 **설치된 각 application**의 **log**가 있습니다.

이 database의 Application table에서는 다음 column을 확인할 수 있습니다: "Application ID", "PackageNumber", "Display Name". 이 column에는 pre-installed 및 installed application에 대한 정보가 있으며, 설치된 application의 ID가 순차적이어야 하므로 일부 application이 uninstalled되었는지 확인할 수 있습니다.

Registry path `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`에서도 **설치된 application**을 확인할 수 있습니다.\
**uninstalled** **application**은 다음 위치에서 확인할 수 있습니다: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Windows events에 나타나는 정보는 다음과 같습니다.

- 발생한 작업
- Timestamp (UTC + 0)
- 관련된 users
- 관련된 hosts (hostname, IP)
- access된 assets (files, folder, printer, services)

Log는 Windows Vista 이전에는 `C:\Windows\System32\config`에, Windows Vista 이후에는 `C:\Windows\System32\winevt\Logs`에 저장됩니다. Windows Vista 이전에는 event log가 binary format이었으며, 이후에는 **XML format**이고 **.evtx** extension을 사용합니다.

Event file의 위치는 SYSTEM registry의 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**에서 확인할 수 있습니다.

Windows Event Viewer (**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com) **또는** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**와** 같은 다른 도구를 사용하여 확인할 수 있습니다.

## Understanding Windows Security Event Logging

Access event는 `C:\Windows\System32\winevt\Security.evtx`에 있는 security configuration file에 기록됩니다. 이 file의 size는 조정할 수 있으며, capacity에 도달하면 오래된 event가 overwrite됩니다. 기록되는 event에는 user login 및 logoff, user action, security setting 변경, file, folder 및 shared asset access가 포함됩니다.

### Key Event IDs for User Authentication:

- **EventID 4624**: user가 authentication에 성공했음을 나타냅니다.
- **EventID 4625**: authentication failure를 나타냅니다.
- **EventIDs 4634/4647**: user logoff event를 나타냅니다.
- **EventID 4672**: administrative privilege를 사용한 login을 나타냅니다.

#### Sub-types within EventID 4634/4647:

- **Interactive (2)**: 직접적인 user login.
- **Network (3)**: shared folder에 대한 access.
- **Batch (4)**: batch process 실행.
- **Service (5)**: service launch.
- **Proxy (6)**: proxy authentication.
- **Unlock (7)**: password를 사용한 screen unlock.
- **Network Cleartext (8)**: 일반적으로 IIS에서 발생하는 clear text password 전송.
- **New Credentials (9)**: access에 다른 credentials 사용.
- **Remote Interactive (10)**: remote desktop 또는 terminal services login.
- **Cache Interactive (11)**: domain controller에 contact하지 않고 cached credentials를 사용한 login.
- **Cache Remote Interactive (12)**: cached credentials를 사용한 remote login.
- **Cached Unlock (13)**: cached credentials를 사용한 unlock.

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: user name이 존재하지 않음 - username enumeration attack을 나타낼 수 있습니다.
- **0xC000006A**: 올바른 user name이지만 password가 틀림 - password guessing 또는 brute-force 시도일 수 있습니다.
- **0xC0000234**: user account가 lockout됨 - 여러 login failure를 발생시킨 brute-force attack 이후에 나타날 수 있습니다.
- **0xC0000072**: account가 disabled됨 - disabled account에 access하려는 unauthorized 시도입니다.
- **0xC000006F**: 허용된 시간 외의 logon - 설정된 login hours 외에 access하려는 시도로, unauthorized access의 징후일 수 있습니다.
- **0xC0000070**: workstation restriction 위반 - unauthorized location에서 login하려는 시도일 수 있습니다.
- **0xC0000193**: account expiration - expired user account를 사용한 access 시도입니다.
- **0xC0000071**: expired password - 오래된 password를 사용한 login 시도입니다.
- **0xC0000133**: time sync issue - client와 server 간의 큰 시간 차이는 pass-the-ticket과 같은 더욱 정교한 attack을 나타낼 수 있습니다.
- **0xC0000224**: mandatory password change 필요 - 잦은 mandatory change는 account security를 불안정하게 만들려는 시도일 수 있습니다.
- **0xC0000225**: security issue가 아니라 system bug를 나타냅니다.
- **0xC000015b**: denied logon type - user가 service logon을 실행하려는 경우처럼 unauthorized logon type을 사용한 access 시도입니다.

#### EventID 4616:

- **Time Change**: system time 변경으로, event timeline을 숨길 수 있습니다.

#### EventID 6005 and 6006:

- **System Startup and Shutdown**: EventID 6005는 system startup을 나타내며, EventID 6006은 system shutdown을 나타냅니다.

#### EventID 1102:

- **Log Deletion**: Security log가 clear되었음을 나타내며, illicit activity를 은폐하려는 red flag인 경우가 많습니다.

#### EventIDs for USB Device Tracking:

- **20001 / 20003 / 10000**: USB device의 최초 connection.
- **10100**: USB driver update.
- **EventID 112**: USB device insertion time.

이러한 login type과 credential dumping 기회를 simulation하는 practical example은 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)를 참조하십시오.

Status 및 sub-status code를 포함한 event detail은 event 원인에 대한 추가 insight를 제공하며, 특히 Event ID 4625에서 주목할 만합니다.

### Recovering Windows Events

Deleted Windows Events를 복구할 가능성을 높이려면 suspect computer의 전원을 직접 plug를 뽑아 끄는 것이 좋습니다. `.evtx` extension을 지정하는 recovery tool인 **Bulk_extractor**를 사용하여 이러한 event를 복구해 볼 수 있습니다.

### Identifying Common Attacks via Windows Events

Windows Event ID를 사용하여 common cyber attack을 식별하는 방법에 대한 comprehensive guide는 [Red Team Recipe](https://redteamrecipe.com/event-codes/)를 참조하십시오.

#### Brute Force Attacks

여러 EventID 4625 record가 나타난 후 attack이 성공하면 EventID 4624가 나타나는 것으로 식별할 수 있습니다.

#### Time Change

EventID 4616으로 기록되며, system time 변경은 forensic analysis를 복잡하게 만들 수 있습니다.

#### USB Device Tracking

USB device tracking에 유용한 System EventID는 최초 사용 시 20001/20003/10000, driver update 시 10100, insertion timestamp에는 DeviceSetupManager의 EventID 112입니다.

#### System Power Events

EventID 6005는 system startup을 나타내며, EventID 6006은 shutdown을 나타냅니다.

#### Log Deletion

Security EventID 1102는 log deletion을 나타내며, forensic analysis에서 중요한 event입니다.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
