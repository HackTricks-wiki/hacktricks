# Đối tượng động AD (dynamicObject) — Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Cơ chế & kiến thức cơ bản về phát hiện

- Bất kỳ đối tượng nào được tạo bằng auxiliary class **`dynamicObject`** đều có **`entryTTL`** (bộ đếm ngược tính bằng giây) và **`msDS-Entry-Time-To-Die`** (thời điểm hết hạn tuyệt đối). Khi `entryTTL` về 0 **và đối tượng không có đối tượng con**, Garbage Collector sẽ xóa đối tượng mà không qua tombstone/recycle-bin, xóa thông tin người tạo/dấu thời gian và ngăn khôi phục.<sup>[[4]](#references)</sup>
- **`entryTTL` là thuộc tính operational/constructed**: hãy yêu cầu thuộc tính này một cách tường minh trong các truy vấn LDAP. Có thể làm mới TTL bằng cách cập nhật `entryTTL` trước khi hết hạn hoặc thông qua LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL tối thiểu/mặc định là các AVA áp dụng trên toàn forest tại **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` và `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft ghi nhận **86400s** là TTL mặc định và **900s** là TTL hợp lệ tối thiểu mặc định; phạm vi schema của `entryTTL` là **1–31557600s** (một giây đến một năm).<sup>[[3]](#references)</sup> Dynamic object **không được hỗ trợ trong các phân vùng Configuration/Schema**.
- **Không thể chuyển đổi từ static sang dynamic** và không có giai đoạn tombstone sau khi hết hạn. Các nhóm IR không thể dựa vào các cơ chế xử lý đối tượng đã xóa hoặc Recycle Bin; họ phải thu thập đối tượng còn tồn tại/metadata trước khi GC xóa nó.
- Việc làm mới **phụ thuộc replica**: nếu TTL được gia hạn quá sát thời điểm hết hạn, một replica writable khác hoặc GC vẫn có thể xóa đối tượng cục bộ trước khi bản làm mới được replicate. Vì vậy, TTL rất ngắn hiệu quả nhất khi attacker biết DC nào sẽ xử lý hành vi lạm dụng; trong khi đó, defender nên truy vấn **tất cả naming context / replica** trong quá trình triage.
- Việc xóa có thể chậm vài phút trên các DC có thời gian hoạt động ngắn (<24h), tạo ra một khoảng thời gian phản ứng ngắn để truy vấn/sao lưu thuộc tính. Hãy phát hiện bằng cách **cảnh báo khi có đối tượng mới mang `entryTTL`/`msDS-Entry-Time-To-Die`** và đối chiếu với SID mồ côi/liên kết bị hỏng.<sup>[[1]](#references)</sup>

### Đồ thị hết hạn và các trường hợp biên khi dọn dẹp tham chiếu

- Mọi đối tượng con bên dưới một đối tượng động đều phải là dynamic. Một đối tượng cha dynamic đã hết hạn chỉ được garbage-collect sau khi trở thành lá; nếu một đối tượng con có `msDS-Entry-Time-To-Die` muộn hơn, DC sẽ đẩy thời điểm hết hạn của đối tượng cha lên sau thời điểm hết hạn muộn nhất của đối tượng con. Do đó, một cây con dynamic có thể **ghim/gia hạn đối tượng cha tưởng như sắp biến mất**: hãy liệt kê toàn bộ cây con và đừng dùng `entryTTL` quan sát được của đối tượng cha làm hạn chót dọn dẹp.<sup>[[4]](#references)</sup>
- Việc dọn dẹp khi hết hạn **có xét đến schema link**. Các replica xóa các giá trị thuộc tính được liên kết tham chiếu đến đối tượng dynamic đã bị xóa, nhưng giữ lại các giá trị không được liên kết. Dự kiến các liên kết membership xuôi/ngược thông thường sẽ được dọn sạch, trong khi các tham chiếu dạng integer/SID/string như `primaryGroupID`, SID nhúng trong `nTSecurityDescriptor`, hoặc văn bản `gPLink` có thể tồn tại như dấu vết pháp chứng.<sup>[[4]](#references)</sup>

## Liệt kê nhanh / Triage trực tiếp

- Truy vấn **tất cả `namingContexts` từ RootDSE**, không chỉ domain NC. Hành vi lạm dụng dynamic có thể tồn tại trong **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) hoặc trong các application partition.
- Khi đối tượng còn tồn tại, hãy lập tức dump **replication metadata** cùng mọi thuộc tính được liên kết/ACL. Sau khi hết hạn, những gì còn lại có thể chỉ là **giá trị `gPLink` bị hỏng, SID mồ côi hoặc câu trả lời DNS được cache**.<sup>[[1]](#references)</sup>

```powershell
(Get-ADForest).Domains | ForEach-Object {
  Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
    $dc = $_.HostName
    (Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
      Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
        -Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
        Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
    }
  }
}
repadmin /showobjmeta <DC> <distinguishedName>
```

## Né tránh MAQ bằng Computer tự xóa

- **`ms-DS-MachineAccountQuota` = 10** mặc định cho phép mọi user đã xác thực tạo computer. Thêm `dynamicObject` khi tạo để computer tự xóa và **giải phóng slot quota**, đồng thời xóa sạch dấu vết.
- Chỉnh sửa Powermad bên trong `New-MachineAccount` (danh sách objectClass):
  ```powershell
  $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
  ```
- Nếu TTL được yêu cầu **thấp hơn `DynamicObjectMinTTL`**, hãy dự kiến máy chủ sẽ điều chỉnh hoặc từ chối tùy theo đường dẫn tạo; trong nhiều domain, mức sàn hiệu lực là **900s** và giá trị dự phòng/mặc định vẫn là **86400s**. ADUC có thể ẩn `entryTTL`, nhưng truy vấn LDP/LDAP sẽ hiển thị thuộc tính này.
- Khi đối tượng còn tồn tại, defender vẫn có thể xác định creator không có đặc quyền từ **`msDS-CreatorSID`** trên đối tượng computer. Khi dynamic computer hết hạn, thông tin quy kết đó biến mất cùng đối tượng.<sup>[[1]](#references)</sup>

## Ẩn tư cách thành viên nhóm chính

- Tạo một **dynamic security group**, sau đó đặt **`primaryGroupID`** của user thành RID của nhóm đó để tạo tư cách thành viên hiệu lực, **không hiển thị trong `memberOf`** nhưng vẫn được Kerberos/access token công nhận.<sup>[[1]](#references)</sup>
- TTL hết hạn sẽ **xóa nhóm bất chấp cơ chế bảo vệ xóa nhóm chính**, khiến user có `primaryGroupID` bị lỗi, trỏ đến một RID không tồn tại và không có tombstone để điều tra cách đặc quyền được cấp.
- Kết quả báo cáo phụ thuộc vào công cụ: **`Get-ADGroupMember` / `net group`** thường xác định được tư cách thành viên bắt nguồn từ nhóm chính, còn **`memberOf`** và **`Get-ADGroup -Properties member`** thì không. Để tìm hiểu thêm về kỹ thuật `primaryGroupID`, xem [trang khác này về lạm dụng DCShadow và PGID](dcshadow.md).
- Với các mục tiêu **không được AdminSDHolder bảo vệ**, attacker có thể kết hợp thủ thuật dynamic group với **DACL deny quyền đọc `primaryGroupID`** (hoặc thuộc tính `member` của nhóm) để ẩn liên kết khỏi nhiều quy trình LDAP/PowerShell, ngay cả trước khi nhóm hết hạn.<sup>[[2]](#references)</sup>

## Làm nhiễm SID mồ côi vào AdminSDHolder

- Thêm ACE cho một **dynamic user/group có thời hạn ngắn** vào **`CN=AdminSDHolder,CN=System,...`**. Sau khi TTL hết hạn, SID trở thành **không thể phân giải (“Unknown SID”)** trong ACL mẫu và **SDProp (~60 min)** sẽ lan truyền SID mồ côi đó đến tất cả đối tượng Tier-0 được bảo vệ.
- Điều tra pháp chứng mất khả năng quy kết vì principal đã biến mất (không có DN của đối tượng đã xóa). Theo dõi **principal mới dạng dynamic + SID mồ côi đột ngột xuất hiện trên AdminSDHolder/ACL đặc quyền**.<sup>[[1]](#references)</sup>

## Thực thi GPO động với dấu vết tự hủy

- Tạo đối tượng **`groupPolicyContainer`** dạng **dynamic** với **`gPCFileSysPath`** độc hại (ví dụ: SMB share theo kiểu GPODDITY) và **liên kết nó qua `gPLink`** với OU mục tiêu.
- Client xử lý policy và lấy nội dung từ SMB của attacker. Khi TTL hết hạn, đối tượng GPO (và `gPCFileSysPath`) biến mất; chỉ còn lại GUID **`gPLink`** bị hỏng, xóa bằng chứng LDAP về payload đã thực thi.
- Cách này giúp dọn dẹp gọn hơn so với kiểu **GPODDITY** truyền thống: thay vì tự khôi phục `gPCFileSysPath` ban đầu, AD tự động xóa GPC độc hại khi bộ đếm thời gian hết hạn.<sup>[[1]](#references)</sup> Xem [lạm dụng ACL để duy trì quyền truy cập](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) để biết chi tiết về giao thức và công cụ, tránh lặp lại nội dung ở đây.

## Chuyển hướng DNS tích hợp AD tạm thời

- Bản ghi AD DNS là các đối tượng **`dnsNode`** trong **DomainDnsZones/ForestDnsZones**. Tạo chúng dưới dạng **dynamic objects** cho phép chuyển hướng máy chủ tạm thời (thu thập thông tin xác thực/MITM). Client lưu đệm phản hồi A/AAAA độc hại; sau đó bản ghi tự xóa để zone trông sạch (DNS Manager có thể cần tải lại zone để làm mới chế độ xem).
- Phát hiện: cảnh báo khi **bất kỳ bản ghi DNS nào có `dynamicObject`/`entryTTL`** thông qua replication/event log; các bản ghi tồn tại thoáng qua hiếm khi xuất hiện trong log DNS tiêu chuẩn.<sup>[[1]](#references)</sup>

## Khoảng trống Delta Sync của Entra ID Hybrid (Lưu ý)

- Entra Connect delta sync dựa vào **tombstone** để phát hiện thao tác xóa. Một **user on-prem dạng dynamic** có thể được đồng bộ lên Entra ID, hết hạn và bị xóa mà không có tombstone—delta sync sẽ không xóa tài khoản cloud, để lại một **Entra user đang hoạt động nhưng mồ côi** cho đến khi thực hiện **initial/full sync** hoặc buộc dọn dẹp thủ công trên cloud.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects trong Active Directory: Mối đe dọa ẩn mình](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Khám phá hành vi, báo cáo và khai thác Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Cấu hình giới hạn TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Yêu cầu đối với DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
