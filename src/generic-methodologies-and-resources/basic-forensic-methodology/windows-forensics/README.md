# Dấu vết Windows

{{#include ../../../banners/hacktricks-training.md}}

## Dấu vết Windows chung

### Thông báo Windows 10

Cơ sở dữ liệu thông báo theo người dùng nằm tại `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (ví dụ: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Các bản phát hành Windows 10 đầu tiên sử dụng `appdb.dat`; Anniversary Update (1607) giới thiệu `wpndatabase.db`. Cơ sở dữ liệu SQLite này có bảng `Notification` chứa nội dung thông báo và các trường thời gian, tuy nhiên thời gian lưu giữ và dữ liệu sẵn có thay đổi tùy theo phiên bản phát hành và chính sách dọn dẹp.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline là tính năng lưu lịch sử hoạt động, có thể chứa bản ghi về các ứng dụng được hỗ trợ, tài liệu và hoạt động khác của người dùng; phạm vi dữ liệu phụ thuộc vào ứng dụng và phiên bản Windows.<sup>[[4]](#references)</sup>

Cơ sở dữ liệu nằm tại `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Có thể mở bằng SQLite hoặc phân tích bằng [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), sau đó xem kết quả bằng [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Các tệp được tải xuống từ bên ngoài ranh giới tin cậy cục bộ có thể chứa **luồng dữ liệu thay thế `Zone.Identifier`**, ghi lại thông tin vùng và có thể bao gồm siêu dữ liệu nguồn gốc như URL. Việc luồng này có tồn tại hay không và các trường dữ liệu của nó phụ thuộc vào chương trình tạo tệp và chính sách hệ thống.<sup>[[6]](#references)</sup>

## **Bản sao lưu tệp**

### Recycle Bin

Trên Vista trở lên, **Recycle Bin** nằm trong thư mục **`$Recycle.bin`** ở thư mục gốc của ổ đĩa (ví dụ: `C:\$Recycle.bin`).\
Khi một tệp bị xóa trong thư mục này, 2 tệp cụ thể sẽ được tạo:

- `$I{id}`: Thông tin tệp, bao gồm thời điểm xóa và đường dẫn ban đầu
- `$R{id}`: Nội dung của tệp

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Với các tệp này, bạn có thể dùng [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) để trích xuất đường dẫn ban đầu và thời điểm xóa (hãy dùng phiên bản phù hợp với bản phát hành Windows mục tiêu).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Sao lưu tệp - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) có thể tạo bản sao shadow tại một thời điểm của volume trong khi các tệp đang được sử dụng; bản sao shadow không thay thế cho forensic image.<sup>[[8]](#references)</sup>

Metadata của bản sao thường được liên kết với `\System Volume Information` ở thư mục gốc của volume, cùng các mã định danh khác nhau tùy hệ thống:

![Recycle Bin - Volume Shadow Copies: Các bản sao lưu này thường nằm trong System Volume Information ở thư mục gốc của hệ thống tệp và tên gồm các UID hiển thị trong...](<../../../images/image (94).png>)

Sau khi mount image bằng công cụ forensic mounter phù hợp, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) có thể liệt kê các snapshot VSS hiện có và duyệt hoặc sao chép tệp từ đó.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Sau khi mount forensic image bằng ArsenalImageMounter, có thể dùng công cụ ShadowCopyView để kiểm tra shadow copy và thậm chí trích xuất các tệp...](<../../../images/image (576).png>)

Cấu hình registry writer của VSS bao gồm `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, nơi có thể chỉ định các tệp và khóa bị loại trừ khỏi bản sao lưu:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Mục registry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore chứa các tệp và khóa không được sao lưu](<../../../images/image (254).png>)

Khóa `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` cũng chứa cấu hình dịch vụ VSS.<sup>[[8]](#references)</sup>

### Tệp Office AutoSaved

Vị trí AutoRecover thay đổi tùy theo ứng dụng Office, phiên bản và cấu hình. Với Word, Microsoft ghi nhận `%APPDATA%\Microsoft\Word` là vị trí mặc định; hãy kiểm tra cài đặt ứng dụng để biết đường dẫn đang dùng.<sup>[[12]](#references)</sup>

## Shell Items

Shell item là một mục chứa thông tin về cách truy cập một tệp khác.

### Tài liệu gần đây (LNK)

Windows thường tạo shortcut cho các mục gần đây khi người dùng mở hoặc truy cập một mục theo cách khác:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Việc truy cập thư mục cũng có thể tạo liên kết cho thư mục đó và các thư mục cha liên quan.

Các tệp liên kết này có thể chứa loại đối tượng đích, thời gian MAC của đối tượng đích, thông tin volume và đường dẫn đối tượng đích. Metadata đó có thể giúp xác định đối tượng đích đã bị xóa, nhưng bản thân artifact không chứng minh rằng một người dùng cụ thể đã mở đối tượng đích.<sup>[[13]](#references)[[14]](#references)</sup>

Timestamp hệ thống tệp của chính LNK và timestamp đối tượng đích được nhúng trong đó là hai loại riêng biệt. Không nên xem thời điểm tạo liên kết là lần sử dụng đầu tiên hoặc thời điểm sửa đổi liên kết là lần sử dụng cuối cùng nếu chưa có artifact khác corroborate; định dạng này lưu timestamp của đối tượng đích riêng với timestamp của tệp liên kết.<sup>[[13]](#references)[[14]](#references)</sup>

Liên kết [**LinkParser**](http://4discovery.com/our-tools/) hiện có được giữ lại như một lựa chọn mang tính lịch sử, nhưng không tìm thấy tài liệu trong quá trình rà soát. Để dùng parser dòng lệnh có tài liệu, hãy dùng [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Các công cụ này thường hiển thị hai bộ timestamp:

- **Timestamp của đối tượng đích:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Timestamp của tệp liên kết:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Bộ thứ nhất áp dụng cho đối tượng đích; bộ thứ hai áp dụng cho chính tệp LNK. Hãy diễn giải cả hai dựa trên tài liệu của parser và bối cảnh hệ thống tệp.<sup>[[14]](#references)[[15]](#references)</sup>

Bạn có thể lấy cùng thông tin bằng cách chạy công cụ CLI của Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

Trong trường hợp này, thông tin sẽ được lưu trong một tệp CSV.

### Jumplists

Jump Lists là danh sách các mục gần đây hoặc dành riêng cho tác vụ của từng ứng dụng, có thể được tạo tự động hoặc tùy chỉnh.<sup>[[13]](#references)</sup>

Automatic Jump Lists được lưu tại `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` và sử dụng tên như `{id}.automaticDestinations-ms`, trong đó ID xác định ứng dụng.

Custom Jump Lists được lưu tại `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; ứng dụng quyết định các mục tác vụ hoặc mục nội dung sẽ được tạo.

Thời gian tạo và sửa đổi của hệ thống tệp mô tả tệp Jump List, chứ không tự động cho biết lần truy cập đầu tiên và cuối cùng vào từng mục tiêu được liệt kê. Hãy đối chiếu các mục đã phân tích với dấu thời gian của tệp và các artifact khác.<sup>[[13]](#references)</sup>

Bạn có thể kiểm tra Jump Lists bằng [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Tài liệu gần đây (LNK) - Jumplists: Bạn có thể kiểm tra jumplists bằng JumplistExplorer](<../../../images/image (168).png>)

(_Lưu ý rằng dấu thời gian do JumplistExplorer cung cấp liên quan đến chính tệp jumplist_)

### Shellbags

[**Theo liên kết này để tìm hiểu shellbags là gì.**](interesting-windows-registry-keys.md#shellbags)

## Sử dụng USB trên Windows

Việc sử dụng USB đôi khi có thể được xác nhận chéo bằng các artifact được tạo khi tệp được truy cập từ phương tiện lưu trữ tháo rời, bao gồm:

- Thư mục Windows Recent
- Thư mục Microsoft Office Recent
- Jumplists

Các công cụ như [**USBDetective**](https://usbdetective.com) đối chiếu những artifact này với bản ghi thiết bị USB, nhưng khả năng có artifact phụ thuộc vào phiên bản Windows và ứng dụng.<sup>[[18]](#references)</sup>

Trong các thử nghiệm được ghi nhận với quy trình MTP trên Windows XP và Windows 7, một số LNK trỏ đến thư mục `WPDNSE` thay vì đường dẫn ban đầu.<sup>[[16]](#references)</sup>

![Shellbags - Sử dụng USB trên Windows: Lưu ý rằng một số tệp LNK thay vì trỏ đến đường dẫn ban đầu lại trỏ đến thư mục WPDNSE](<../../../images/image (218).png>)

Nghiên cứu đó ghi nhận các bản sao nằm trong `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; trong các thử nghiệm, nội dung tạm thời không còn sau khi khởi động lại và GUID có thể được đối chiếu với dữ liệu shellbag. Hãy xem đây là hành vi phụ thuộc vào hệ điều hành, thiết bị và ứng dụng, không phải quy tắc áp dụng phổ quát.<sup>[[16]](#references)</sup>

### Thông tin Registry

[Kiểm tra trang này để tìm hiểu](interesting-windows-registry-keys.md#usb-information) những khóa registry nào chứa thông tin đáng chú ý về các thiết bị USB được kết nối.

### setupapi

Trên Vista trở lên, hãy kiểm tra `C:\Windows\inf\setupapi.dev.log` để tìm hoạt động cài đặt thiết bị. Tiêu đề phần có dấu thời gian `Section start`; chúng ghi lại quá trình thiết lập và cần được đối chiếu với bằng chứng kết nối khác, thay vì xem là thời điểm cắm thiết bị vật lý chính xác.<sup>[[17]](#references)</sup>

![Thông tin Registry - setupapi: Kiểm tra tệp C: Windows inf setupapi.dev.log để lấy dấu thời gian về thời điểm kết nối USB (tìm Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Có thể dùng [**USBDetective**](https://usbdetective.com) để lấy thông tin về các thiết bị USB đã được kết nối với một image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: Có thể dùng USBDetective để lấy thông tin về các thiết bị USB đã được kết nối với một image](<../../../images/image (452).png>)

### Dọn dẹp Plug and Play

Tác vụ theo lịch có tên `Plug and Play Cleanup` xóa các phiên bản driver lỗi thời. Định nghĩa tác vụ Windows 10 được Adam Harrison ghi lại cũng nhắm đến các driver không hoạt động trong 30 ngày, do đó bằng chứng về driver của thiết bị tháo rời có thể bị dọn dẹp; hãy xác nhận định nghĩa tác vụ trên máy và phiên bản Windows trước khi khái quát hành vi này.<sup>[[1]](#references)</sup>

Tác vụ nằm tại đường dẫn sau: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Định nghĩa XML của tác vụ Plug and Play Cleanup theo lịch của Windows](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Các thành phần và cài đặt chính của tác vụ:**

- **pnpclean.dll**: DLL này thực hiện quá trình dọn dẹp.
- **UseUnifiedSchedulingEngine**: Được đặt thành `TRUE`, cho biết đang sử dụng công cụ lập lịch tác vụ chung.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Yêu cầu Task Scheduler khởi chạy tác vụ dọn dẹp hàng tháng trong quá trình bảo trì Tự động định kỳ.
  - **Deadline ('P2M')**: Yêu cầu Task Scheduler thực hiện tác vụ trong quá trình bảo trì Tự động khẩn cấp nếu tác vụ thất bại trong hai tháng liên tiếp.

Cấu hình này lên lịch bảo trì định kỳ và thử lại sau các lần thất bại liên tiếp; XML và hành vi cụ thể phụ thuộc vào phiên bản.<sup>[[1]](#references)</sup>

**Để biết thêm thông tin, hãy xem:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Email

Email có **2 phần đáng chú ý: header và nội dung**. Trong **header**, bạn có thể tìm thấy thông tin như:

- **Ai** đã gửi email (địa chỉ email, IP, mail server đã chuyển tiếp email)
- Email được gửi **khi nào**

Ngoài ra, các header `References` và `In-Reply-To` có thể chứa message ID dùng để liên kết các thư trả lời trong một cuộc hội thoại.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Email: Email được gửi khi nào](<../../../images/image (593).png>)

### Ứng dụng Windows Mail

Ứng dụng này lưu nội dung email trong các tệp văn bản hoặc HTML phụ tại những đường dẫn như `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; cấu trúc thư mục được đánh số và bố cục tệp chính xác có thể khác nhau tùy artifact.<sup>[[75]](#references)</sup>

**Metadata** của email và **danh bạ** có thể được tìm thấy trong **cơ sở dữ liệu ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` sử dụng định dạng Extensible Storage Engine (ESE). Hãy làm việc trên một bản sao và sử dụng trình phân tích ESE như [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); nếu công cụ yêu cầu hậu tố `.edb`, chỉ đổi tên bản sao và xác minh schema của bảng trước khi dựa vào bảng `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Khi kiểm tra các thuộc tính MAPI của Outlook, những thuộc tính chuẩn bao gồm:

- `PidTagClientSubmitTime`: thời điểm UTC mà ứng dụng gửi thư.
- `PidTagConversationIndex`: vị trí tương đối của thư trong chuỗi hội thoại.
- `PidTagEntryId`: mã định danh của đối tượng thư.
- `PidTagMessageFlags`: các cờ trạng thái như đã gửi, đã đọc, chưa đọc hoặc có tệp đính kèm.
- `PidTagLastVerbExecuted`: thao tác cuối cùng được ghi lại cho thư, chẳng hạn như mở, trả lời hoặc chuyển tiếp.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Vị trí tệp dữ liệu Outlook thay đổi tùy theo phiên bản và loại tài khoản. Microsoft ghi nhận các vị trí phổ biến sau cho tệp PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Đường dẫn registry `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` có thể cho biết profile Outlook và cấu hình tệp dữ liệu liên quan.

Tệp PST có thể chứa thư, danh bạ, dữ liệu lịch và các mục Outlook khác. Bạn có thể kiểm tra một bản sao bằng [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Ứng dụng Windows Mail - Microsoft Outlook: Bạn có thể mở tệp PST bằng công cụ Kernel PST Viewer](<../../../images/image (498).png>)

### Tệp OST của Microsoft Outlook

**Tệp OST** là bộ nhớ đệm cục bộ cho tài khoản Exchange hoặc Microsoft 365; Cached Exchange Mode không áp dụng cho tài khoản POP hoặc IMAP. Thời gian lưu ngoại tuyến có thể cấu hình và thường mặc định là 12 tháng, trong khi giới hạn kích thước PST/OST là các cài đặt riêng biệt có thể cấu hình. Có thể dùng [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) để xem tệp OST.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Truy xuất tệp đính kèm

Có thể khôi phục các tệp đính kèm bị mất từ:

- Với cấu hình Outlook/IE cũ: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Với cấu hình Outlook/IE11 mới hơn: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Tệp MBOX của Thunderbird

**Thunderbird** lưu dữ liệu profile tại `%APPDATA%\Thunderbird\Profiles`; các thư mục email thường sử dụng tệp mbox không có phần mở rộng, nằm trong các thư mục `Mail` hoặc `ImapMail` dành riêng cho từng tài khoản.<sup>[[29]](#references)[[30]](#references)</sup>

### Ảnh thu nhỏ

- **Windows XP**: Bản xem trước ảnh thu nhỏ thường được lưu trong các tệp `thumbs.db` riêng của từng thư mục.
- **Thư mục mạng**: Tệp `thumbs.db` vẫn có thể được tạo cho thư mục UNC khi bật hành vi tạo ảnh thu nhỏ tương ứng; không nên cho rằng mọi phiên bản hoặc chính sách Windows đều tạo tệp này.
- **Windows Vista trở lên**: Bộ nhớ đệm ảnh thu nhỏ của hệ thống được tập trung tại `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, với các tệp như **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) có thể phân tích `Thumbs.db` cũ, còn [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) có thể phân tích các cơ sở dữ liệu bộ nhớ đệm ảnh thu nhỏ hiện đại.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Thông tin Windows Registry

Windows Registry, nơi lưu cấu hình hệ thống và người dùng, được chứa trong các tệp hive tại:

- `%WINDIR%\System32\Config` dành cho các hive của máy, làm nền tảng cho nhiều subkey `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` dành cho hive `HKEY_CURRENT_USER` của người dùng.
- Một số bản cài Windows cũ có bản sao trong `%WINDIR%\System32\Config\RegBack\`; Windows 10 phiên bản 1803 trở lên không tự động điền dữ liệu vào thư mục này trừ khi bật sao lưu định kỳ.<sup>[[34]](#references)[[35]](#references)</sup>
- Dữ liệu shell và đăng ký lớp theo từng người dùng cũng thường được lưu trong `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` trên Windows hiện đại.<sup>[[34]](#references)[[66]](#references)</sup>

### Công cụ

Một số công cụ hữu ích để phân tích registry hive; hãy xác nhận các định dạng hive và phiên bản được từng công cụ hỗ trợ trước khi dựa vào kết quả:

- **Registry Editor**: Được cài sẵn trong Windows. Đây là GUI để duyệt registry Windows của phiên hiện tại.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Cho phép tải tệp registry và duyệt bằng GUI. Công cụ cũng có Bookmarks đánh dấu các khóa chứa thông tin đáng chú ý.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Công cụ này cũng có GUI cho phép duyệt registry đã tải, đồng thời có các plugin làm nổi bật thông tin đáng chú ý trong registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Một ứng dụng GUI khác có khả năng trích xuất thông tin từ registry hive đã tải.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Khôi phục phần tử đã xóa

Các cell của hive đã xóa có thể vẫn còn cho đến khi không gian của chúng được sử dụng lại, nhưng khả năng khôi phục phụ thuộc vào trạng thái hive và trình phân tích; hãy xem các key đã xóa được khôi phục là bằng chứng cần xác thực, không phải bản ghi được đảm bảo.

### Thời gian ghi cuối cùng

Các key registry có dấu thời gian ghi cuối cùng; Windows cung cấp dấu thời gian này cho key hoặc bất kỳ mục giá trị nào của nó, vì vậy một giá trị không nhất thiết có dấu thời gian sửa đổi độc lập riêng.<sup>[[69]](#references)</sup>

### SAM

Hive **SAM** chứa dữ liệu tài khoản người dùng và nhóm cục bộ, bao gồm các hash mật khẩu được bảo vệ bằng vật liệu boot-key của hệ thống.<sup>[[38]](#references)[[39]](#references)</sup>

Trong `SAM\Domains\Account\Users`, bạn có thể lấy mã định danh tài khoản cùng một số trường về đăng nhập và chính sách. Việc trích xuất hash ngoại tuyến cũng cần hive `SYSTEM` để khôi phục vật liệu boot-key liên quan.<sup>[[38]](#references)[[39]](#references)</sup>

### Các mục đáng chú ý trong Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Các chương trình đã chạy

### Các tiến trình Windows cơ bản

Một [bài viết về các tiến trình Windows phổ biến](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) được giữ lại để đọc thêm; hãy đối chiếu mọi nhận định về hành vi tiến trình với tài liệu Windows hiện hành và bằng chứng tại máy.<sup>[[2]](#references)</sup>

### Ứng dụng Windows gần đây

Trên các phiên bản Windows 10 có hỗ trợ, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` chứa các subkey theo từng ứng dụng với những trường như thời gian sử dụng gần nhất và số lần khởi chạy; artifact này đã bị loại bỏ trong các bản phát hành sau, vì vậy hãy xác minh build mục tiêu.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Trên các hệ thống có Background Activity Moderator, hãy kiểm tra `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` hoặc đường dẫn mới hơn là `...\bam\State\UserSettings\{SID}`. Các giá trị được gắn với SID của người dùng và có thể chứa đường dẫn executable được theo dõi cùng dữ liệu thực thi dạng FILETIME; artifact này phụ thuộc vào phiên bản và cần được đối chiếu với bằng chứng khác.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetch lưu bộ nhớ đệm tài nguyên và metadata khởi chạy để chương trình có thể khởi động nhanh hơn.

Tệp Prefetch được lưu dưới dạng `.pf` trong `C:\Windows\Prefetch`; định dạng, thời gian lưu và giới hạn số lượng tệp thay đổi tùy phiên bản Windows. Microsoft ghi nhận việc lưu tám thời điểm chạy gần nhất và tối đa 1024 tệp trên Windows 8 trở lên, do đó không nên khái quát các mô tả cũ về giới hạn cố định.<sup>[[13]](#references)</sup>

Tên tệp thường có dạng `{program_name}-{hash}.pf`, trong đó hash được tạo từ ngữ cảnh thực thi như đường dẫn và đối số; Windows 10 trở lên có thể nén tệp. Sự hiện diện của tệp là bằng chứng hữu ích cho việc thực thi, nhưng tự nó không chứng minh người dùng đã thực thi chương trình và cần được đối chiếu với các artifact khác.<sup>[[13]](#references)</sup>

Để kiểm tra các tệp này, bạn có thể dùng [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), công cụ có hỗ trợ phân tích thư mục, xuất CSV/HTML và giải nén các tệp Prefetch Windows 10 phù hợp.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** bổ trợ Prefetch bằng cách sử dụng các mẫu sử dụng trong quá khứ để cải thiện tốc độ tải. Trên các hệ thống tạo ra chúng, các tệp cơ sở dữ liệu thường nằm tại `C:\Windows\Prefetch\Ag*.db`; định dạng và việc có các tệp này hay không phụ thuộc vào phiên bản.<sup>[[41]](#references)</sup>

Các cơ sở dữ liệu này có thể chứa tên ứng dụng, số lần sử dụng, tệp hoặc volume đã truy cập, đường dẫn và khoảng thời gian, nhưng không nên xem chúng là nhật ký thực thi chính xác.<sup>[[41]](#references)</sup>

Liên kết [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) hiện có được giữ lại như một trình phân tích tiềm năng; trước khi sử dụng, hãy kiểm tra tình trạng khả dụng hiện tại và định dạng đầu ra được hỗ trợ theo tài liệu của công cụ.

### SRUM

**System Resource Usage Monitor** (SRUM) ghi lại mức sử dụng tài nguyên của các ứng dụng và người dùng. Tính năng này được giới thiệu trong Windows 8 và lưu dữ liệu trong cơ sở dữ liệu ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Dữ liệu cung cấp các thông tin sau:

- AppID và Path
- Người dùng/SID liên kết với bản ghi
- Số byte đã gửi
- Số byte đã nhận
- Giao diện mạng
- Thời lượng kết nối
- Thời lượng tiến trình

Chu kỳ thu thập và thời gian lưu giữ phụ thuộc vào cách triển khai; không nên cho rằng mỗi bản ghi đều đại diện cho một khoảng thực thi chính xác 60 phút.<sup>[[13]](#references)</sup>

Bạn có thể trích xuất và xem xét dữ liệu bằng [**srum_dump**](https://github.com/MarkBaggett/srum-dump), sử dụng các tùy chọn được tài liệu của phiên bản công cụ hiện tại hướng dẫn.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

**AppCompatCache**, còn được gọi là **ShimCache**, là một phần của hạ tầng tương thích ứng dụng Windows và ghi lại metadata của tệp để đưa ra quyết định tương thích. Đường dẫn hive, định dạng bản ghi, dung lượng lưu giữ và các trường thay đổi tùy theo phiên bản Windows; trên các phiên bản Windows hiện đại, chỉ riêng ShimCache không thể chứng minh rằng người dùng đã thực thi một tệp. Hãy phân tích hive `SYSTEM` liên quan bằng công cụ [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) và đối chiếu kết quả với các tạo tác thực thi.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Nên dùng công cụ AppCompatCacheParser để phân tích thông tin được lưu trữ](<../../../images/image (75).png>)

### Amcache

Tệp **Amcache.hve** là một hive registry lưu danh mục các ứng dụng và tệp mà Windows ghi nhận. Tệp thường nằm tại `C:\Windows\AppCompat\Programs\Amcache.hve`.

Tệp có thể chứa các mục tệp được liên kết hoặc không liên kết, đường dẫn và giá trị SHA1, nhưng sự hiện diện của nó chỉ là bằng chứng kiểm kê và tự nó không chứng minh rằng một tiến trình đã được thực thi.<sup>[[13]](#references)[[44]](#references)</sup>

Để trích xuất và phân tích **Amcache.hve**, hãy dùng công cụ [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Lệnh này phân tích hive và ghi kết quả đầu ra dạng CSV.<sup>[[44]](#references)</sup>

Ví dụ:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Trong số các tệp CSV được tạo, `Amcache_Unassociated file entries` có thể hữu ích khi điều tra các tệp không được liên kết với chương trình đã nhận diện.<sup>[[44]](#references)</sup>

### RecentFileCache

Trên các hệ thống Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` có thể chứa thông tin về các binary được quan sát gần đây; tính khả dụng và ý nghĩa phụ thuộc vào phiên bản.

Bạn có thể dùng [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) để phân tích tệp này.<sup>[[45]](#references)</sup>

### Scheduled tasks

Bằng chứng về scheduled task có thể nằm trong `C:\Windows\System32\Tasks` đối với task hiện đại và `C:\Windows\Tasks` cùng các tệp `.job` đối với task cũ; hãy kiểm tra định dạng định nghĩa task phù hợp với hệ điều hành.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Cơ sở dữ liệu Service Control Manager nằm trong `SYSTEM\CurrentControlSet\Services` (đối với hive SYSTEM ngoại tuyến, hãy kiểm tra khóa control-set tương ứng); cơ sở dữ liệu này chứa cấu hình service và driver, chẳng hạn như đường dẫn executable và kiểu khởi động.<sup>[[72]](#references)</sup>

### **Windows Store**

Các ứng dụng Windows Store đã cài đặt có thể được biểu diễn trong `\ProgramData\Microsoft\Windows\AppRepository\`, bao gồm cơ sở dữ liệu **`StateRepository-Machine.srd`**. Schema và đường dẫn thay đổi tùy phiên bản Windows.<sup>[[71]](#references)</sup>

Cơ sở dữ liệu có thể chứa mã định danh ứng dụng, số package và tên hiển thị. Bản thân các khoảng trống trong mã định danh không chứng minh rằng một ứng dụng đã bị gỡ cài đặt; hãy đối chiếu với trạng thái package và registry.

Các đăng ký package cũng có thể xuất hiện trong `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft có tài liệu về subkey `Deprovisioned` dành riêng cho từng phiên bản, dùng cho các ứng dụng đã provision bị gỡ bỏ; đừng cho rằng subkey `Deleted` tồn tại trên mọi bản build.<sup>[[70]](#references)</sup>

## Sự kiện Windows

Tùy theo provider, sự kiện Windows có thể chứa:

- Việc gì đã xảy ra
- Dấu thời gian `TimeCreated`, cần được diễn giải dựa trên schema sự kiện và ngữ cảnh thời gian của host
- Người dùng liên quan
- Host liên quan (hostname, IP)
- Tài sản được truy cập (tệp, thư mục, máy in hoặc service).<sup>[[49]](#references)</sup>

Trước Windows Vista, event log thường sử dụng định dạng nhị phân cũ trong `C:\Windows\System32\config`; Vista trở đi sử dụng định dạng Windows Event Log, thường nằm trong `C:\Windows\System32\winevt\Logs`, với các tệp `.evtx` chứa dữ liệu sự kiện được hiển thị dưới dạng XML.<sup>[[46]](#references)[[47]](#references)</sup>

Registry SYSTEM lưu cấu hình channel trong **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, bao gồm đường dẫn tệp và các thiết lập lưu giữ đã cấu hình.<sup>[[47]](#references)</sup>

Có thể xem chúng bằng Windows Event Viewer (**`eventvwr.msc`**) hoặc các công cụ như [**Event Log Explorer**](https://eventlogxp.com) và [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Tìm hiểu về ghi nhật ký sự kiện bảo mật Windows

Trên Vista trở đi, channel Security thường được lưu tại `C:\Windows\System32\winevt\Logs\Security.evtx`. Kích thước tối đa và chính sách lưu giữ có thể cấu hình; với ghi nhật ký vòng tròn, các bản ghi cũ có thể bị ghi đè khi tệp đạt giới hạn. Channel này có thể ghi lại các sự kiện xác thực, đăng xuất, đặc quyền, chính sách kiểm tra và truy cập đối tượng khi bật tính năng kiểm tra tương ứng.<sup>[[46]](#references)[[47]](#references)</sup>

### Các Event ID quan trọng về xác thực người dùng:

- **Event ID 4624**: Đăng nhập tài khoản thành công.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Đăng nhập tài khoản thất bại.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Phiên đăng nhập đã kết thúc.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Người dùng chủ động đăng xuất.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Đặc quyền đặc biệt được cấp cho một lần đăng nhập mới; điều này thường gặp ở tài khoản system và administrator, nên bản thân sự kiện này không chứng minh hoạt động độc hại.<sup>[[54]](#references)</sup>

#### Các loại đăng nhập thường được ghi trong 4624, 4625, 4634 và 4647:

- **Interactive (2)**: Đăng nhập tương tác cục bộ.
- **Network (3)**: Truy cập tài nguyên dùng chung.
- **Batch (4)**: Đăng nhập của tiến trình batch.
- **Service (5)**: Đăng nhập của service.
- **Unlock (7)**: Mở khóa workstation.
- **NetworkCleartext (8)**: Đăng nhập mạng cung cấp thông tin xác thực ở dạng cleartext cho authentication package.
- **NewCredentials (9)**: Đăng nhập sử dụng thông tin xác thực thay thế được cung cấp cho các kết nối đi.
- **RemoteInteractive (10)**: Đăng nhập Remote Desktop hoặc Terminal Services.
- **CachedInteractive (11)**: Đăng nhập tương tác sử dụng thông tin xác thực domain đã lưu trong cache.
- **CachedRemoteInteractive (12)**: Đăng nhập tương tác từ xa sử dụng cache.
- **CachedUnlock (13)**: Mở khóa bằng thông tin xác thực đã lưu trong cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Mã Status và Sub Status cho EventID 4625:

- **0xC0000064**: Không có người dùng này.
- **0xC000006A**: Tên người dùng đúng nhưng mật khẩu sai.
- **0xC0000234**: Tài khoản bị khóa.
- **0xC0000072**: Tài khoản bị vô hiệu hóa.
- **0xC000006F**: Đăng nhập ngoài khung giờ được phép.
- **0xC0000070**: Vi phạm giới hạn workstation.
- **0xC0000193**: Tài khoản hết hạn.
- **0xC0000071**: Mật khẩu hết hạn.
- **0xC0000133**: Chênh lệch thời gian giữa client và server quá lớn.
- **0xC0000224**: Tài khoản phải đổi mật khẩu.
- **0xC0000225**: `STATUS_NOT_FOUND`; chỉ riêng mã này không xác định được lỗi hệ thống hay cuộc tấn công.
- **0xC000015B**: Tài khoản không được cấp loại đăng nhập được yêu cầu.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Thay đổi thời gian**: Thời gian hệ thống đã thay đổi. Nhiều sự kiện phản ánh việc dịch vụ thời gian hiệu chỉnh định kỳ, vì vậy hãy đối chiếu tác nhân và nguồn thời gian trước khi xem đây là hành vi can thiệp.<sup>[[56]](#references)</sup>

#### Event ID 12, 13, 1074, 6005, 6006, 6008 và 6009:

- **Ngữ cảnh nguồn và dịch vụ**: Event 12 ghi nhận hệ điều hành khởi động, 13 ghi nhận hệ điều hành tắt, 1074 ghi nhận thao tác tắt hoặc khởi động lại theo kế hoạch, 6008 cho biết hệ thống tắt bất ngờ và 6009 ghi nhận phiên bản Windows khi khởi động. Event 6005 và 6006 lần lượt cho biết dịch vụ Event Log khởi động và dừng; bản thân chúng không chứng minh hệ điều hành đã khởi động hay tắt.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Xóa log**: Event 1102 ghi nhận audit log Security đã bị xóa; hãy điều tra tác nhân và các sự kiện xung quanh thay vì chỉ dựa vào sự kiện này để suy đoán ý định.<sup>[[62]](#references)</sup>

#### EventID theo dõi thiết bị USB:

- **20001 / 20003**: Sự kiện cài đặt thiết bị `UserPnp`, có thể giúp xác định hoạt động sử dụng lần đầu hoặc cài đặt.
- **10000 / 10100**: Sự kiện `DriverFrameworks-UserMode` có thể xuất hiện cùng hoạt động thiết bị.
- **Event ID 112**: Hoạt động `DeviceSetupManager/Admin`, có thể cung cấp dấu thời gian liên quan đến việc kết nối thiết bị.
- Provider, channel và ý nghĩa sự kiện thay đổi theo phiên bản Windows; hãy kiểm tra tên provider và payload sự kiện trước khi diễn giải.<sup>[[59]](#references)</sup>

Để xem ví dụ thực tế về các loại đăng nhập và thông tin xác thực liên quan, tham khảo [hướng dẫn chi tiết của Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Chi tiết sự kiện, bao gồm loại đăng nhập, status, substatus, địa chỉ nguồn và các trường process, cung cấp ngữ cảnh cho Event ID 4625; mã status hoặc mẫu lỗi lặp lại là manh mối điều tra, không phải kết luận.<sup>[[51]](#references)[[55]](#references)</sup>

### Khôi phục sự kiện Windows

Vì event log thường được ghi theo vòng tròn, các bản ghi bị logger ghi đè có thể không khôi phục được. Hãy bảo toàn forensic image hoặc bản sao đang làm việc trước khi tương tác với hệ thống đang chạy; chỉ sử dụng parser hoặc carver đã được xác thực, chẳng hạn **Bulk_extractor**, sau khi xác nhận phiên bản công cụ hỗ trợ dữ liệu `.evtx` mục tiêu; không rút nguồn một hệ thống đang chạy chỉ để thử khôi phục sự kiện.<sup>[[46]](#references)</sup>

### Nhận diện các cuộc tấn công phổ biến qua sự kiện Windows

Để xem tài liệu tham khảo thực tế về event ID, hãy tham khảo liên kết [Red Team Recipe](https://redteamrecipe.com/event-codes/) hiện có và xác thực các ví dụ trong đó bằng tài liệu provider ở trên.

#### Tấn công Brute Force

Đối chiếu các lần thất bại Event ID 4625 lặp lại với một lần thành công 4624 sau đó, loại đăng nhập, status, nguồn và ngữ cảnh tài khoản; chuỗi sự kiện này là dấu hiệu cần điều tra, không phải bằng chứng của một cuộc tấn công.<sup>[[50]](#references)[[51]](#references)</sup>

#### Thay đổi thời gian

Event ID 4616 ghi nhận thay đổi thời gian hệ thống, điều có thể gây phức tạp cho việc phân tích timeline; hãy đối chiếu với bằng chứng từ dịch vụ thời gian và host.<sup>[[56]](#references)</sup>

#### Theo dõi thiết bị USB

Các USB event ID phụ thuộc vào provider; hãy đối chiếu `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 và `DeviceSetupManager/Admin` 112 với các artifact SetupAPI và registry.<sup>[[17]](#references)[[59]](#references)</sup>

#### Sự kiện nguồn hệ thống

Dùng 12/13/1074/6008/6009 để xác định ngữ cảnh hệ điều hành khởi động, tắt, khởi động lại và mất nguồn bất ngờ; 6005/6006 đánh dấu thời điểm dịch vụ Event Log khởi động/dừng.<sup>[[57]](#references)[[58]](#references)</sup>

#### Xóa log

Security Event ID 1102 ghi nhận audit log Security đã bị xóa và cần được đối chiếu với tài khoản cũng như process chịu trách nhiệm.<sup>[[62]](#references)</sup>

## References

- [1] [Dọn dẹp Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Điều tra các process Windows phổ biến](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Góc nhìn pháp chứng số về thông báo của Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Các công cụ pháp chứng của Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier và Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Dịch vụ Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Các thao tác sao lưu và khôi phục registry bằng VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Các khóa registry dùng để sao lưu và khôi phục](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Sự cố hiệu năng Word tại vị trí AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Sổ tay hướng dẫn ứng phó sự cố](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Định dạng tệp nhị phân Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Pháp chứng USB MTP: Nhận diện artifact rò rỉ dữ liệu](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Các mục trong log cài đặt thiết bị SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID và các kiểu liên quan](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Tìm và chuyển các tệp dữ liệu Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Bật Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Chỉ một phần mục được đồng bộ hóa](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Cấu hình giới hạn kích thước cho tệp dữ liệu Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile - Nơi Thunderbird lưu dữ liệu người dùng](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Cài đặt tài khoản Thunderbird và thư mục mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Giao diện IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Các hive registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Registry hệ thống không được sao lưu vào RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Khôi phục Windows Registry](https://www.mitec.cz/wrr.html)
- [38] [Chỉnh sửa registry từ xa](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Tổng quan kỹ thuật về mật khẩu](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Bằng chứng Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Định dạng tệp Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Khóa registry Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Thuộc tính sự kiện TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: Các giá trị NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Khắc phục sự cố khởi động lại bất ngờ bằng system event log](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Khắc phục sự cố shutdown đang diễn ra](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Pháp chứng thiết bị lưu trữ USB trên Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Các loại đăng nhập Windows tuyệt vời](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Trình điều phối hoạt động nền](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print ngừng in tệp đính kèm PDF trong Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Các tệp Windows Registry](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Ngăn ứng dụng đã gỡ bỏ xuất hiện lại trong quá trình cập nhật](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Kết quả kiểm thử FTK và Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Cơ sở dữ liệu các service đã cài đặt](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks gặp lỗi Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Điều hướng cơ sở dữ liệu Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Định dạng thông điệp Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
