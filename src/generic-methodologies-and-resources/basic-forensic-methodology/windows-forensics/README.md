# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

사용자별 notification database는 `%LOCALAPPDATA%\Microsoft\Windows\Notifications`에 있습니다(예: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). 초기 Windows 10 릴리스에서는 `appdb.dat`를 사용했으며, Anniversary Update (1607)에서는 `wpndatabase.db`가 도입되었습니다. SQLite database에는 notification payload와 timing 필드가 포함된 `Notification` 테이블이 있지만, 보존 기간과 사용 가능한 데이터는 릴리스 및 정리 정책에 따라 달라집니다.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline은 지원되는 애플리케이션, 문서 및 기타 사용자 activity의 record를 포함할 수 있는 activity-history 기능입니다. 지원 범위는 애플리케이션과 Windows 버전에 따라 달라집니다.<sup>[[4]](#references)</sup>

database는 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`에 있습니다. SQLite로 열거나 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)로 파싱할 수 있으며, 해당 output은 [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md)로 검토할 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

로컬 trust boundary 외부에서 다운로드한 파일에는 **`Zone.Identifier` alternate data stream**이 포함될 수 있습니다. 이 stream은 zone 정보를 기록하며 URL과 같은 origin metadata를 포함할 수 있습니다. 존재 여부와 필드는 producer 및 system policy에 따라 달라집니다.<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

Vista 이상에서는 드라이브 루트의 **`$Recycle.bin`** 폴더에서 **Recycle Bin**을 찾을 수 있습니다(예: `C:\$Recycle.bin`).\
이 폴더에서 파일을 삭제하면 다음과 같은 2개의 특정 파일이 생성됩니다:

- `$I{id}`: 삭제 시간과 원본 경로를 포함한 파일 정보
- `$R{id}`: 파일의 content

![File Backups - Recycle Bin: $R{id}: 파일의 content](<../../../images/image (1029).png>)

이러한 파일이 있으면 [**Rifiuti2**](https://github.com/abelcheung/rifiuti2)를 사용하여 원본 경로와 삭제 시간을 추출할 수 있습니다(target Windows release에 적합한 버전을 사용하십시오).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![파일 백업 - 휴지통: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS)는 파일이 사용 중인 동안 볼륨의 특정 시점 shadow copy를 생성할 수 있지만, shadow copy는 forensic image를 대체하지 않습니다.<sup>[[8]](#references)</sup>

일반적으로 copy metadata는 볼륨 루트의 `\System Volume Information`과 연결되며, 식별자는 시스템에 따라 달라집니다.

![휴지통 - Volume Shadow Copies: 이러한 백업은 일반적으로 파일 시스템 루트의 System Volume Information에 있으며 이름은 다음에 표시된 UID로 구성됩니다...](<../../../images/image (94).png>)

적절한 forensic mounter를 사용해 image를 mount한 후 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html)를 사용하면 사용 가능한 VSS snapshot을 열거하고 해당 snapshot의 파일을 탐색하거나 복사할 수 있습니다.<sup>[[9]](#references)</sup>

![휴지통 - Volume Shadow Copies: ArsenalImageMounter로 forensic image를 mount하면 ShadowCopyView 도구를 사용해 shadow copy를 검사하고 파일을 추출할 수도 있습니다...](<../../../images/image (576).png>)

VSS registry writer configuration에는 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`가 포함되며, 이 위치에서 backup에서 제외할 파일과 key를 지정할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

![휴지통 - Volume Shadow Copies: HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore registry entry에는 backup하지 않을 파일과 key가 포함되어 있습니다](<../../../images/image (254).png>)

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key에도 VSS service configuration이 포함되어 있습니다.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover 위치는 Office application, version 및 configuration에 따라 달라집니다. Word의 경우 Microsoft는 `%APPDATA%\Microsoft\Word`를 기본 위치로 문서화하고 있습니다. 활성 경로는 application settings에서 확인하십시오.<sup>[[12]](#references)</sup>

## Shell Items

shell item은 다른 파일에 액세스하는 방법에 대한 정보를 포함하는 item입니다.

### Recent Documents (LNK)

Windows는 사용자가 item을 열거나 다른 방식으로 액세스할 때 일반적으로 recent-item shortcut을 생성합니다.

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Folder에 액세스하면 해당 folder와 관련 parent folder에 대한 link도 생성될 수 있습니다.

이러한 link 파일에는 target type, target MAC times, volume information 및 target path가 포함될 수 있습니다. 이러한 metadata는 삭제된 target을 식별하는 데 도움이 될 수 있지만, 이 artifact 자체만으로는 특정 사용자가 target을 열었다는 증거가 되지 않습니다.<sup>[[13]](#references)[[14]](#references)</sup>

LNK 자체의 filesystem timestamps와 내장된 target timestamps는 서로 다릅니다. 형식상 target timestamps가 link 파일의 timestamps와 별도로 저장되므로, 이를 뒷받침하는 다른 artifact 없이 link 생성 시점을 최초 사용 시점으로, link 수정 시점을 마지막 사용 시점으로 해석해서는 안 됩니다.<sup>[[13]](#references)[[14]](#references)</sup>

기존 [**LinkParser**](http://4discovery.com/our-tools/) link는 historical option으로 유지하지만, 검토 당시 documentation을 확인할 수 없었습니다. Documentation이 제공되는 command-line parser로는 [**LECmd**](https://github.com/EricZimmerman/LECmd)를 사용하십시오.<sup>[[15]](#references)</sup>

이러한 도구는 일반적으로 두 세트의 timestamps를 표시합니다.

- **Target timestamps:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Link-file timestamps:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

첫 번째 세트는 target을 가리키고, 두 번째 세트는 LNK 파일 자체를 가리킵니다. 두 세트 모두 parser documentation과 filesystem context를 함께 고려하여 해석하십시오.<sup>[[14]](#references)[[15]](#references)</sup>

Windows CLI 도구인 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행해 동일한 정보를 얻을 수 있습니다.<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
이 경우 정보는 CSV 파일 내부에 저장됩니다.

### Jumplists

Jump Lists는 애플리케이션별 최근 항목 또는 작업별 항목 목록이며, 자동 또는 사용자 지정 방식일 수 있습니다.<sup>[[13]](#references)</sup>

Automatic Jump Lists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장되며, 애플리케이션을 식별하는 ID가 포함된 `{id}.automaticDestinations-ms`와 같은 이름을 사용합니다.

Custom Jump Lists는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`에 저장되며, 어떤 작업 또는 항목을 생성할지는 애플리케이션이 제어합니다.

파일시스템에서 생성 및 수정된 시간은 Jump List 파일 자체를 설명하며, 목록에 있는 각 대상에 대한 최초 및 최종 접근 시간을 자동으로 나타내지는 않습니다. 파싱된 항목을 파일의 타임스탬프 및 다른 artifact와 상호 연관시켜야 합니다.<sup>[[13]](#references)</sup>

[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)를 사용하여 Jump Lists를 검사할 수 있습니다.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: JumplistExplorer를 사용하여 jumplists를 검사할 수 있습니다](<../../../images/image (168).png>)

(_JumplistExplorer에서 제공하는 타임스탬프는 jumplist 파일 자체와 관련되어 있다는 점에 유의하십시오_)

### Shellbags

[**shellbags가 무엇인지 알아보려면 이 링크를 참조하십시오.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

USB 사용 여부는 이동식 미디어에서 파일에 접근할 때 생성되는 다음과 같은 artifact를 통해 간접적으로 확인할 수 있습니다.

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

[**USBDetective**](https://usbdetective.com)와 같은 도구는 이러한 artifact를 USB 장치 기록과 상호 연관시키지만, artifact의 사용 가능 여부는 Windows 버전과 애플리케이션에 따라 달라집니다.<sup>[[18]](#references)</sup>

Windows XP 및 Windows 7 MTP workflow에 대해 문서화된 테스트에서는 일부 LNK가 원래 경로가 아닌 `WPDNSE` 폴더를 가리켰습니다.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: 일부 LNK 파일은 원래 경로 대신 WPDNSE 폴더를 가리킵니다](<../../../images/image (218).png>)

해당 연구에서는 `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` 아래에 복사본이 생성되는 것을 관찰했습니다. 테스트에서 임시 콘텐츠는 재시작 후에도 유지되지 않았으며, GUID는 shellbag 데이터와 상호 연관시킬 수 있었습니다. 이 동작을 보편적인 규칙이 아니라 OS, 장치 및 애플리케이션에 따라 달라지는 동작으로 취급해야 합니다.<sup>[[16]](#references)</sup>

### Registry Information

USB에 연결된 장치에 관한 흥미로운 정보가 포함된 registry key를 확인하려면 [이 페이지를 참조하십시오](interesting-windows-registry-keys.md#usb-information).

### setupapi

Vista 이상에서는 장치 설치 활동을 확인하기 위해 `C:\Windows\inf\setupapi.dev.log`를 검사하십시오. 섹션 헤더에는 `Section start` 타임스탬프가 포함되어 있습니다. 이는 setup 처리 과정을 기록하므로, 정확한 물리적 연결 시각으로 간주하기보다는 다른 연결 증거와 상호 연관시켜야 합니다.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: USB 연결이 발생한 시점의 타임스탬프를 확인하려면 C: Windows inf setupapi.dev.log 파일을 검사하십시오(Section start 검색)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)를 사용하여 image에 연결된 USB 장치에 관한 정보를 얻을 수 있습니다.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective를 사용하여 image에 연결된 USB 장치에 관한 정보를 얻을 수 있습니다](<../../../images/image (452).png>)

### Plug and Play Cleanup

`Plug and Play Cleanup`이라는 scheduled task는 오래된 driver 버전을 제거합니다. Adam Harrison가 문서화한 Windows 10 task definition은 30일 동안 비활성 상태인 driver도 대상으로 하므로, 이동식 장치 driver에 관한 증거가 정리될 수 있습니다. 이 동작을 일반화하기 전에 로컬 task definition과 Windows build를 확인하십시오.<sup>[[1]](#references)</sup>

task는 다음 경로에 있습니다: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML definition of the Windows Plug and Play Cleanup scheduled task](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Task의 주요 구성 요소 및 설정:**

- **pnpclean.dll**: 실제 cleanup process를 담당하는 DLL입니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 있으며, generic task scheduling engine을 사용한다는 의미입니다.
- **MaintenanceSettings**:
- **Period ('P1M')**: Task Scheduler가 정기적인 Automatic maintenance 중 매월 cleanup task를 시작하도록 지시합니다.
- **Deadline ('P2M')**: task가 2개월 연속 실패할 경우 Task Scheduler가 emergency Automatic maintenance 중 task를 실행하도록 지시합니다.

이 구성은 정기적인 maintenance를 예약하고 연속 실패 후 재시도하도록 합니다. 정확한 XML과 동작은 버전에 따라 달라집니다.<sup>[[1]](#references)</sup>

**자세한 내용은 다음을 참조하십시오:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Emails에는 **email의 2가지 흥미로운 부분인 headers와 content**가 포함됩니다. **headers**에서는 다음과 같은 정보를 확인할 수 있습니다.

- Emails를 보낸 사람(email address, IP, email을 redirect한 mail servers)
- Email이 전송된 시점

또한 `References` 및 `In-Reply-To` headers에는 reply를 conversation과 연결하는 데 사용되는 message ID가 포함될 수 있습니다.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: Email이 전송된 시점](<../../../images/image (593).png>)

### Windows Mail App

이 애플리케이션은 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`와 같은 경로 아래의 보조 text 또는 HTML 파일에 email content를 저장합니다. 정확한 번호가 매겨진 폴더 및 파일 layout은 artifact에 따라 달라질 수 있습니다.<sup>[[75]](#references)</sup>

Emails의 **metadata**와 **contacts**는 **ESE database**인 `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol` 내부에서 확인할 수 있습니다.<sup>[[75]](#references)</sup>

`store.vol`은 Extensible Storage Engine (ESE) format을 사용합니다. 복사본에서 작업하고 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 ESE parser를 사용하십시오. tool에서 `.edb` suffix를 요구하는 경우 복사본만 rename하고, `Message` table에 의존하기 전에 table schema를 확인하십시오.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Outlook MAPI properties를 검사할 때의 canonical properties는 다음과 같습니다.

- `PidTagClientSubmitTime`: client가 message를 submit한 UTC 시간입니다.
- `PidTagConversationIndex`: conversation thread에서 message의 상대적 위치입니다.
- `PidTagEntryId`: message object의 identifier입니다.
- `PidTagMessageFlags`: submitted, read, unread 또는 attachment 보유 여부와 같은 status flags입니다.
- `PidTagLastVerbExecuted`: open, reply 또는 forward와 같이 message에 대해 기록된 마지막 operation입니다.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file 위치는 version과 account type에 따라 달라집니다. Microsoft는 PST/OST 파일의 다음과 같은 일반적인 위치를 문서화하고 있습니다.

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`는 Outlook profile 및 연결된 data-file configuration을 식별할 수 있습니다.

PST 파일에는 messages, contacts, calendar data 및 기타 Outlook items가 포함될 수 있습니다. [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)를 사용하여 복사본을 검사할 수 있습니다.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Kernel PST Viewer 도구를 사용하여 PST 파일을 열 수 있습니다](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

**OST file**은 Exchange 또는 Microsoft 365 accounts를 위한 local cache입니다. Cached Exchange Mode는 POP 또는 IMAP accounts에 적용되지 않습니다. offline period는 configuration 가능하며 기본값은 대개 12개월입니다. PST/OST size limits는 별도의 configuration 설정입니다. OST file을 확인하려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

손실된 attachments는 다음 위치에서 복구할 수 있습니다.

- Legacy Outlook/IE configurations: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Newer Outlook/IE11 configurations: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird**는 `%APPDATA%\Thunderbird\Profiles` 아래에 profile data를 저장합니다. mail folders는 account별 `Mail` 또는 `ImapMail` directory 아래에서 일반적으로 extension이 없는 mbox 파일을 사용합니다.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews는 일반적으로 폴더별 `thumbs.db` 파일에 저장되었습니다.
- **Network folders**: 관련 thumbnail behavior가 enabled인 경우 UNC folder에 `thumbs.db` 파일이 여전히 생성될 수 있습니다. 모든 Windows version 또는 policy에서 해당 파일을 생성한다고 가정하지 마십시오.
- **Windows Vista and newer**: system thumbnail cache는 `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` 아래에 **thumbcache_xxx.db**와 같은 파일로 중앙화되어 있습니다. [**Thumbsviewer**](https://thumbsviewer.github.io)는 legacy `Thumbs.db`를 parse할 수 있으며, [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 modern thumbnail-cache databases를 parse할 수 있습니다.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

system 및 user configuration data를 저장하는 Windows Registry는 다음 위치의 hive files에 포함되어 있습니다.

- 다양한 `HKEY_LOCAL_MACHINE` subkeys를 뒷받침하는 machine hives는 `%WINDIR%\System32\Config`에 있습니다.
- 사용자의 `HKEY_CURRENT_USER` hive는 `%USERPROFILE%\NTUSER.DAT`에 있습니다.
- 일부 구형 Windows installations에는 `%WINDIR%\System32\Config\RegBack\`에 copies가 포함되어 있습니다. Windows 10 version 1803 이상에서는 periodic backup이 enabled되지 않는 한 이 directory가 자동으로 채워지지 않습니다.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell 및 class-registration data는 modern Windows에서 일반적으로 `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`에도 저장됩니다.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

일부 tools는 registry hives를 분석하는 데 유용합니다. output에 의존하기 전에 각 tool이 지원하는 hive formats와 version을 확인하십시오.

- **Registry Editor**: Windows에 설치되어 있습니다. 현재 session의 Windows registry를 GUI로 탐색할 수 있습니다.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): registry file을 load하고 GUI를 통해 탐색할 수 있습니다. 또한 흥미로운 정보가 있는 keys를 강조 표시하는 Bookmarks도 포함합니다.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 역시 loaded registry를 탐색할 수 있는 GUI를 제공하며, loaded registry 내부의 흥미로운 정보를 강조 표시하는 plugins도 포함합니다.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): loaded registry hive에서 정보를 추출할 수 있는 또 다른 GUI application입니다.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

삭제된 hive cells는 해당 공간이 재사용될 때까지 남아 있을 수 있지만, recovery 여부는 hive state와 parser에 따라 달라집니다. 복구된 deleted keys를 보장된 records가 아니라 validation이 필요한 evidence로 취급하십시오.

### Last Write Time

Registry keys에는 last-write timestamp가 있습니다. Windows는 이를 key 또는 해당 value entries에 대해 노출하므로, value가 반드시 독립적인 modification timestamp를 갖는 것은 아닙니다.<sup>[[69]](#references)</sup>

### SAM

**SAM** hive에는 local user 및 group account data가 포함되며, system의 boot-key material로 보호되는 password hashes도 포함됩니다.<sup>[[38]](#references)[[39]](#references)</sup>

`SAM\Domains\Account\Users`에서는 account identifiers와 일부 logon 및 policy fields를 얻을 수 있습니다. Offline hash extraction을 수행하려면 관련 boot-key material을 복구하기 위해 `SYSTEM` hive도 필요합니다.<sup>[[38]](#references)[[39]](#references)</sup>

### Windows Registry의 흥미로운 entries


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

기존의 [common Windows processes에 관한 post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)는 추가 reading 자료로 유지됩니다. 모든 process behavior 관련 주장에는 최신 Windows documentation 및 local evidence를 함께 사용하여 확인하십시오.<sup>[[2]](#references)</sup>

### Windows Recent APPs

해당 기능을 제공하는 Windows 10 versions에서는 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps`에 last-used time 및 launch count와 같은 fields가 포함된 application별 subkeys가 있습니다. 이 artifact는 이후 releases에서 제거되었으므로 target build를 확인하십시오.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Background Activity Moderator를 노출하는 systems에서는 `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` 또는 최신 `...\bam\State\UserSettings\{SID}` path를 검사하십시오. values는 user SID를 key로 사용하며 tracked executable paths 및 FILETIME과 유사한 execution data를 포함할 수 있습니다. 이 artifact는 version-dependent하므로 다른 evidence와 함께 확인해야 합니다.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching은 resources 및 launch metadata를 cache하여 programs가 더 빠르게 시작되도록 합니다.

Prefetch files는 `C:\Windows\Prefetch`에 `.pf` files로 저장됩니다. format, retention 및 file-count limits는 Windows version에 따라 달라집니다. Microsoft는 Windows 8 이상에서 마지막 8개의 execution times와 최대 1024개의 files를 보존한다고 문서화하고 있으므로, 이전의 고정 limit 요약을 일반화해서는 안 됩니다.<sup>[[13]](#references)</sup>

filename은 일반적으로 `{program_name}-{hash}.pf` 형식을 사용하며, hash는 path 및 arguments와 같은 execution context에서 파생됩니다. Windows 10 이상에서는 file을 compress할 수 있습니다. 파일의 존재는 유용한 execution evidence이지만 그 자체로 user가 실행했다는 증거는 아니므로 다른 artifact와 상호 연관시켜야 합니다.<sup>[[13]](#references)</sup>

이 files를 검사하려면 [**PECmd.exe**](https://github.com/EricZimmerman/PECmd)를 사용할 수 있습니다. 이 tool은 directory parsing, CSV/HTML output 및 해당 Windows 10 Prefetch files의 decompression support를 문서화하고 있습니다.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain**은 과거 사용 패턴을 활용해 로딩을 개선함으로써 Prefetch를 보완합니다. 이를 생성하는 시스템에서는 데이터베이스 파일이 일반적으로 `C:\Windows\Prefetch\Ag*.db`에 있으며, 형식과 존재 여부는 버전에 따라 다릅니다.<sup>[[41]](#references)</sup>

이러한 데이터베이스에는 애플리케이션 이름, 사용 횟수, 액세스한 파일 또는 볼륨, 경로 및 시간 범위가 포함될 수 있지만, 정확한 실행 로그로 간주해서는 안 됩니다.<sup>[[41]](#references)</sup>

기존 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 링크는 가능한 parser로 유지합니다. 사용하기 전에 해당 도구의 documentation을 기준으로 현재 사용 가능 여부와 지원되는 output을 확인하십시오.

### SRUM

**System Resource Usage Monitor** (SRUM)은 애플리케이션과 사용자의 리소스 사용량을 기록합니다. Windows 8에서 도입되었으며, ESE database `C:\Windows\System32\sru\SRUDB.dat`에 데이터를 저장합니다.<sup>[[13]](#references)</sup>

다음 정보를 제공합니다.

- AppID 및 Path
- 레코드와 연결된 User/SID
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

수집 주기와 보존 기간은 구현에 따라 다르므로 모든 레코드가 정확히 60분의 실행 구간을 나타낸다고 가정하지 마십시오.<sup>[[13]](#references)</sup>

현재 tool version에 문서화된 options를 사용하여 [**srum_dump**](https://github.com/MarkBaggett/srum-dump)로 데이터를 추출하고 검토할 수 있습니다.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

**AppCompatCache**는 **ShimCache**라고도 하며, Windows application-compatibility infrastructure의 일부로 호환성 결정을 위해 파일 metadata를 기록합니다. hive path, record format, retained capacity 및 fields는 Windows release에 따라 달라집니다. 최신 Windows에서는 ShimCache만으로 사용자가 파일을 실행했다는 사실을 입증할 수 없습니다. 관련 `SYSTEM` hive를 [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser)로 parse하고, 해당 output을 execution artifacts와 대조하십시오.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): 저장된 정보를 parse하려면 AppCompatCacheParser tool을 사용하는 것이 권장됩니다](<../../../images/image (75).png>)

### Amcache

**Amcache.hve** file은 Windows에서 관찰된 applications 및 files의 inventory를 기록하는 registry hive입니다. 일반적으로 `C:\Windows\AppCompat\Programs\Amcache.hve`에 있습니다.

associated 및 unassociated file entries, paths, SHA1 values가 포함될 수 있지만, 이 file의 존재는 inventory evidence일 뿐이며 process가 실행되었다는 사실을 자체적으로 입증하지는 않습니다.<sup>[[13]](#references)[[44]](#references)</sup>

**Amcache.hve**를 extract하고 analyze하려면 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool을 사용하십시오. 이 command는 hive를 parse하고 CSV output을 작성합니다.<sup>[[44]](#references)</sup>

예:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
생성된 CSV 파일 중 `Amcache_Unassociated file entries`는 인식된 프로그램과 연결되지 않은 파일을 조사할 때 유용할 수 있습니다.<sup>[[44]](#references)</sup>

### RecentFileCache

Windows 7 시스템에서는 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에 최근 관찰된 바이너리에 대한 정보가 포함되어 있을 수 있습니다. 사용 가능 여부와 의미는 버전에 따라 다릅니다.

[**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser)를 사용하여 파일을 파싱할 수 있습니다.<sup>[[45]](#references)</sup>

### Scheduled tasks

최신 task의 증거는 `C:\Windows\System32\Tasks`에서, 레거시 task의 증거는 `.job` 파일이 있는 `C:\Windows\Tasks`에서 찾을 수 있습니다. OS에 적합한 task 정의 형식을 검사해야 합니다.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Service Control Manager 데이터베이스는 `SYSTEM\CurrentControlSet\Services` 아래에 있습니다(오프라인 SYSTEM hive의 경우 해당 control-set key를 검사). 이 데이터베이스에는 executable path와 start type 같은 service 및 driver configuration이 포함됩니다.<sup>[[72]](#references)</sup>

### **Windows Store**

설치된 Windows Store application은 `\ProgramData\Microsoft\Windows\AppRepository\` 아래에 표시될 수 있으며, 여기에는 **`StateRepository-Machine.srd`** 데이터베이스가 포함됩니다. Schema와 path는 Windows release에 따라 달라집니다.<sup>[[71]](#references)</sup>

데이터베이스에는 application identifier, package number 및 display name이 포함될 수 있습니다. identifier의 공백만으로는 application이 uninstall되었다는 증거가 되지 않으므로 package 및 registry state와 대조해야 합니다.

Package registration은 `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` 아래에도 나타날 수 있습니다. Microsoft는 제거된 provisioned app에 대해 version-specific `Deprovisioned` subkey를 문서화하고 있습니다. 모든 build에 `Deleted` subkey가 존재한다고 가정하지 마십시오.<sup>[[70]](#references)</sup>

## Windows Events

Provider에 따라 Windows event에는 다음 정보가 포함될 수 있습니다.

- 발생한 일
- event schema와 host time context에 따라 해석해야 하는 `TimeCreated` timestamp
- 관련된 사용자
- 관련된 host(hostname, IP)
- 접근된 asset(file, folder, printer 또는 service).<sup>[[49]](#references)</sup>

Windows Vista 이전에는 event log가 일반적으로 `C:\Windows\System32\config` 아래의 legacy binary format을 사용했습니다. Vista 이후에는 Windows Event Log format을 사용하며, 일반적으로 `C:\Windows\System32\winevt\Logs` 아래에 저장되고 `.evtx` 파일에 XML로 렌더링된 event data가 포함됩니다.<sup>[[46]](#references)[[47]](#references)</sup>

SYSTEM registry는 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** 아래에 channel configuration을 저장하며, 여기에는 configured file path와 retention setting이 포함됩니다.<sup>[[47]](#references)</sup>

Windows Event Viewer(**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com) 및 [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) 같은 tool을 사용하여 확인할 수 있습니다.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Vista 이후 Security channel은 일반적으로 `C:\Windows\System32\winevt\Logs\Security.evtx`에 저장됩니다. 최대 크기와 retention policy를 설정할 수 있으며, circular logging을 사용하는 경우 파일이 제한 크기에 도달하면 오래된 record가 덮어써질 수 있습니다. 관련 auditing이 활성화되어 있으면 이 channel에 authentication, logoff, privilege, audit-policy 및 object-access event가 기록될 수 있습니다.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: 성공한 account logon입니다.<sup>[[50]](#references)</sup>
- **Event ID 4625**: 실패한 account logon입니다.<sup>[[51]](#references)</sup>
- **Event ID 4634**: logon session이 종료되었습니다.<sup>[[52]](#references)</sup>
- **Event ID 4647**: 사용자가 logoff를 시작했습니다.<sup>[[53]](#references)</sup>
- **Event ID 4672**: 새로운 logon에 special privilege가 할당되었습니다. 이는 system 및 administrator account에서 흔히 발생하므로, 그 자체로 malicious activity의 증거는 아닙니다.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: interactive local logon입니다.
- **Network (3)**: shared resource에 대한 access입니다.
- **Batch (4)**: batch-process logon입니다.
- **Service (5)**: service logon입니다.
- **Unlock (7)**: workstation unlock입니다.
- **NetworkCleartext (8)**: authentication package에 credential을 cleartext로 제공하는 network logon입니다.
- **NewCredentials (9)**: outbound connection에 사용할 제공된 alternate credential을 이용한 logon입니다.
- **RemoteInteractive (10)**: Remote Desktop 또는 Terminal Services logon입니다.
- **CachedInteractive (11)**: cached domain credential을 이용한 interactive logon입니다.
- **CachedRemoteInteractive (12)**: cached remote-interactive logon입니다.
- **CachedUnlock (13)**: cached credential을 이용한 unlock입니다.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: 해당 사용자가 없습니다.
- **0xC000006A**: 사용자 이름은 올바르지만 password가 잘못되었습니다.
- **0xC0000234**: account가 lockout되었습니다.
- **0xC0000072**: account가 disabled 상태입니다.
- **0xC000006F**: 허용된 시간 외에 logon이 발생했습니다.
- **0xC0000070**: workstation restriction을 위반했습니다.
- **0xC0000193**: account가 expired 상태입니다.
- **0xC0000071**: password가 expired 상태입니다.
- **0xC0000133**: client와 server의 시간 차이가 너무 큽니다.
- **0xC0000224**: account가 password를 변경해야 합니다.
- **0xC0000225**: `STATUS_NOT_FOUND`; 이 code만으로는 system bug나 attack을 식별할 수 없습니다.
- **0xC000015B**: 요청한 logon type이 account에 부여되지 않았습니다.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: system time이 변경되었습니다. 많은 event가 일반적인 time-service correction을 반영하므로, 이를 tampering으로 간주하기 전에 actor와 time source를 상호 연관 분석해야 합니다.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12는 OS start를, 13은 OS shutdown을, 1074는 planned shutdown 또는 restart를, 6008은 unexpected shutdown을, 6009는 boot 시 Windows version을 기록합니다. Event 6005와 6006은 각각 Event Log service의 start와 stop을 나타내며, 그 자체로 OS start와 shutdown의 증거는 아닙니다.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102는 Security audit log가 clear되었음을 기록합니다. 이 event만으로 의도를 가정하지 말고 actor와 주변 event를 조사해야 합니다.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: first-use 또는 installation activity를 파악하는 데 도움이 될 수 있는 `UserPnp` device-installation event입니다.
- **10000 / 10100**: device activity와 함께 나타날 수 있는 `DriverFrameworks-UserMode` event입니다.
- **Event ID 112**: insertion-related timestamp를 제공할 수 있는 `DeviceSetupManager/Admin` activity입니다.
- Provider, channel 및 event semantics는 Windows version에 따라 다르므로, 의미를 부여하기 전에 provider name과 event payload를 검사해야 합니다.<sup>[[59]](#references)</sup>

logon type과 관련 credential material에 대한 실용적인 예시는 [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)를 참조하십시오.<sup>[[60]](#references)</sup>

logon type, status, substatus, source address 및 process field를 포함한 event detail은 Event ID 4625의 context를 제공합니다. status code나 반복되는 failure pattern은 조사를 위한 lead이지 결론이 아닙니다.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

event log는 일반적으로 circular 방식이므로 logger에 의해 덮어써진 record는 복구할 수 없을 수 있습니다. live system과 상호작용하기 전에 forensic image 또는 working copy를 보존하십시오. **Bulk_extractor** 같은 validated parser 또는 carver는 tool version이 대상 `.evtx` data를 지원하는지 확인한 후에만 사용하고, event를 복구하려는 목적으로 실행 중인 system의 전원을 뽑지 마십시오.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

실용적인 event-ID reference는 기존 [Red Team Recipe](https://redteamrecipe.com/event-codes/) link를 참조하고, 해당 예시를 위의 provider documentation과 대조하여 검증하십시오.

#### Brute Force Attacks

반복되는 Event ID 4625 failure를 이후의 4624 success, logon type, status, source 및 account context와 상호 연관 분석하십시오. 이 sequence는 조사를 위한 indicator이지 attack의 증거는 아닙니다.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616은 system-time change를 기록하며, 이는 timeline analysis를 복잡하게 만들 수 있습니다. time-service 및 host evidence와 비교하십시오.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event ID는 provider-specific입니다. `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 및 `DeviceSetupManager/Admin` 112를 SetupAPI 및 registry artifact와 상호 연관 분석하십시오.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

OS start, shutdown, restart 및 unexpected-power context에는 12/13/1074/6008/6009를 사용하고, 6005/6006은 Event Log service의 start/stop을 나타냅니다.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102는 Security audit log가 clear되었음을 기록하며, responsible account 및 process와 상호 연관 분석해야 합니다.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - 일반적인 Windows Process 조사](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Windows 10 Notification에 대한 Digital Forensic 관점](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier 및 Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [VSS에서의 Registry backup 및 restore operation](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Backup 및 restore를 위한 Registry key](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [AutoRecover location에서의 Word performance issue](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Data Exfiltration Artifact 식별](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entry](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID 및 Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook data file 찾기 및 transfer](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode 활성화](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [일부 item만 synchronize됨](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Outlook data file의 size limit 구성](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Thunderbird가 user data를 저장하는 위치](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account setting 및 mbox directory](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry가 RegBack에 backup되지 않음](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry 원격 편집](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [System event log를 사용하여 unexpected reboot 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Shutdown in process 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Windows 10용 USB Storage Device Forensics](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Outlook Desktop에서 Quick Print가 PDF attachment를 print하지 않음](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry file](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Update 중 제거된 app이 다시 설치되지 않도록 방지](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK 및 Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [설치된 Service의 데이터베이스](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Task](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Task Scheduler Service Is Not Available 오류로 Scheduled Task가 실패함](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Windows Mail database 탐색](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
