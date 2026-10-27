# BloodHound & Các công cụ liệt kê Active Directory khác

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> LƯU Ý: Trang này tổng hợp một số tiện ích hữu ích nhất để **liệt kê** và **trực quan hóa** các mối quan hệ trong Active Directory. Để thu thập dữ liệu qua kênh **Active Directory Web Services (ADWS)** kín đáo, hãy xem tài liệu tham khảo ở trên.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) là một **trình xem và chỉnh sửa AD** nâng cao, cho phép:

* Duyệt cây thư mục bằng GUI
* Chỉnh sửa thuộc tính đối tượng và security descriptor
* Tạo / so sánh snapshot để phân tích ngoại tuyến

### Cách sử dụng nhanh

1. Khởi chạy công cụ và kết nối tới `dc01.corp.local` bằng bất kỳ thông tin đăng nhập domain nào.
2. Tạo snapshot ngoại tuyến qua `File ➜ Create Snapshot`.
3. So sánh hai snapshot bằng `File ➜ Compare` để phát hiện các thay đổi về quyền.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) trích xuất nhiều artefact từ một domain (ACL, GPO, trust, mẫu CA …) và tạo **báo cáo Excel**.

```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```

---

## BloodHound (trực quan hóa đồ thị)

[BloodHound](https://github.com/SpecterOps/BloodHound) sử dụng lý thuyết đồ thị để phát hiện các mối quan hệ đặc quyền ẩn bên trong AD tại chỗ, Entra ID và mọi dữ liệu bề mặt tấn công bổ sung mà bạn đưa vào thông qua OpenGraph.<sup>[[1]](#references)</sup>

### Triển khai (Docker CE)

```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```

### Bộ thu thập

* `SharpHound.exe` / `Invoke-BloodHound` – biến thể native hoặc PowerShell
* `RustHound-CE` – bộ thu thập CE đa nền tảng cho Linux, macOS và Windows
* `NetExec --bloodhound` – thu thập nhanh dựa trên LDAP từ Linux
* `AzureHound` – liệt kê Entra ID
* **SoaPy + BOFHound** – thu thập qua ADWS (xem link ở đầu)

> BloodHound CE `v8+` đã thay đổi định dạng đầu ra của bộ thu thập khi OpenGraph ra mắt. Sau khi nâng cấp từ BloodHound legacy hoặc các bản cài CE cũ hơn, hãy chạy lại discovery bằng các bộ thu thập hiện tại trước khi nhập dữ liệu.<sup>[[1]](#references)</sup>

#### Các chế độ SharpHound phổ biến

```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```

Các collector tạo JSON được nhập thông qua giao diện GUI của BloodHound.

#### SharpHound từ máy chủ Windows không tham gia domain

Nếu VM operator của bạn không tham gia domain mục tiêu, hãy trỏ DNS đến một DC, khởi chạy shell **network-only**, xác minh bạn có thể thấy `SYSVOL`/`NETLOGON` trên một DC, sau đó thu thập dữ liệu từ domain từ xa:

```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```

Điều này hữu ích cho các jump box dùng một lần hoặc máy trạm của người vận hành không nên tham gia domain.

#### Thu thập đa nền tảng từ Linux/macOS

```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```

`RustHound-CE` là lựa chọn mặc định tốt khi bạn muốn đầu ra tương thích với CE từ máy chủ không chạy Windows.<sup>[[2]](#references)</sup> `NetExec` rất tiện lợi khi bạn đã dùng nó để xác thực LDAP hoặc spraying và muốn nhập graph nhanh chóng. Với các bộ dữ liệu không thuộc AD, có thể mở rộng BloodHound OpenGraph bằng các collector như [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (ưu tiên đường dẫn OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) hoạt động trên BloodHound CE/OpenGraph khi graph quá lớn để pivot thủ công. Thay vì chỉ hỏi liệu một principal có thể tiếp cận một mục tiêu hay không, công cụ này tính các đường dẫn ngắn nhất từ nhiều người dùng và máy tính có đặc quyền thấp đến các đối tượng có giá trị cao, nhóm các đường dẫn dùng chung các cạnh và làm nổi bật điểm nghẽn chung cần được khắc phục trước tiên.<sup>[[4]](#references)</sup>

```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```

Khi đã nhập dữ liệu từ `MSSQLHound` và `ConfigManBearPig`, một phát hiện có thể kết nối [AD CS](ad-certificates.md), [lạm dụng MSSQL AD](abusing-ad-mssql.md) và [các đường tấn công SCCM](sccm-management-point-relay-sql-policy-secrets.md), thay vì xem chúng là các đầu mối riêng biệt.<sup>[[4]](#references)</sup> Ví dụ về đường tấn công kết hợp:

```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```

- Theo dõi **ngữ cảnh bảo mật hiệu lực** tại mọi cạnh. Một đường đi trở nên trọng yếu với domain ngay khi có chuyển tiếp thực thi dưới danh tính domain có đặc quyền, kể cả khi đường đi bắt đầu từ người dùng thông thường.
- Các phát hiện được nhóm lại rất hữu ích để **khắc phục điểm nghẽn**: loại bỏ một quyền SQL impersonation, linked-server trust, đường khai thác certificate template hoặc SCCM assignment có thể đồng thời loại bỏ nhiều đường đi ngắn nhất.
- Ưu tiên lại các phát hiện mức "medium" dựa trên **ngữ cảnh đồ thị**. SMB signing bị tắt, WebClient bị lộ, lỗi delegation hoặc SQL server có thể bị NTLM relay xứng đáng được ưu tiên cao hơn nếu node bị xâm phạm có đường đi tiếp đến Domain Admins, Domain Controllers, CA hoặc SCCM site server.
- Nếu bạn cũng có output `NTDS.dit` và hashcat potfile, `--pwd` sẽ đối chiếu các mật khẩu đã crack với thuộc tính BloodHound để bạn nhanh chóng phân biệt việc dùng lại mật khẩu thông thường với thông tin đăng nhập đã crack của các tài khoản có đặc quyền, có thể bị Kerberoast, có thể bị AS-REP roast hoặc liên quan đến đường đi.

### Thu thập đặc quyền và quyền đăng nhập

Các **token privilege** của Windows (ví dụ: `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) có thể bỏ qua kiểm tra DACL, vì vậy việc ánh xạ chúng trên toàn domain giúp phát hiện các cạnh LPE cục bộ mà đồ thị chỉ dựa trên ACL bỏ sót. **Quyền đăng nhập** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` và các quyền `SeDeny*` tương ứng) được LSA thực thi trước khi token được tạo, và quyền từ chối được ưu tiên, nên chúng ảnh hưởng đáng kể đến di chuyển ngang (đăng nhập RDP/SMB/tác vụ đã lên lịch/dịch vụ).<sup>[[3]](#references)</sup>

**Chạy collector với quyền nâng cao** khi có thể: UAC tạo token đã lọc cho admin tương tác (thông qua `NtFilterToken`), loại bỏ các privilege nhạy cảm và đánh dấu SID admin là deny-only. Nếu bạn liệt kê privilege từ shell không nâng cao, các privilege có giá trị cao sẽ không hiển thị và BloodHound sẽ không thu thập được các cạnh này.<sup>[[3]](#references)</sup>

Hiện có hai chiến lược thu thập SharpHound bổ trợ cho nhau:<sup>[[3]](#references)</sup>

- **Phân tích GPO/SYSVOL (kín đáo, quyền thấp):**
  1. Liệt kê GPO qua LDAP (`(objectCategory=groupPolicyContainer)`) và đọc `gPCFileSysPath` của từng mục.
  2. Tải `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` từ SYSVOL và phân tích phần `[Privilege Rights]`, nơi ánh xạ tên privilege/quyền đăng nhập với SID.
  3. Tra cứu liên kết GPO qua `gPLink` trên OU/site/domain, liệt kê máy tính trong các container được liên kết và gán các quyền đó cho những máy này.
  4. Ưu điểm: hoạt động với tài khoản người dùng thông thường và ít gây chú ý; nhược điểm: chỉ thấy các quyền được áp dụng qua GPO (bỏ sót các thay đổi cục bộ).

- **Liệt kê qua LSA RPC (ồn ào, chính xác):**
  - Từ ngữ cảnh có quyền admin cục bộ trên mục tiêu, mở Local Security Policy và gọi `LsaEnumerateAccountsWithUserRight` cho từng privilege/quyền đăng nhập để liệt kê các principal được gán qua RPC.
  - Ưu điểm: thu thập được các quyền được đặt cục bộ hoặc ngoài GPO; nhược điểm: tạo lưu lượng mạng ồn ào và cần quyền admin trên từng host.

**Ví dụ về đường khai thác được phát hiện nhờ các cạnh này:** `CanRDP` ➜ host nơi người dùng của bạn cũng có `SeBackupPrivilege` ➜ mở shell nâng cao để tránh token đã lọc ➜ dùng ngữ nghĩa backup để đọc các hive `SAM` và `SYSTEM` bất chấp DACL hạn chế ➜ exfiltrate và chạy `secretsdump.py` offline để lấy NT hash của tài khoản Administrator cục bộ, phục vụ di chuyển ngang/nâng quyền.<sup>[[3]](#references)</sup>

### Ưu tiên Kerberoasting bằng BloodHound

Dùng ngữ cảnh đồ thị để nhắm mục tiêu roasting hiệu quả:

1. Thu thập một lần bằng collector tương thích ADWS rồi phân tích offline:
   ```bash
   rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
   ```
2. Import ZIP, đánh dấu principal bị xâm phạm là đã chiếm quyền, rồi chạy các truy vấn tích hợp sẵn (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) để tìm các tài khoản SPN có quyền admin/infra.
3. Ưu tiên SPN theo phạm vi ảnh hưởng; kiểm tra `pwdLastSet`, `lastLogon` và các loại mã hóa được phép trước khi crack.
4. Chỉ yêu cầu các ticket đã chọn, crack offline, sau đó truy vấn lại BloodHound với quyền truy cập mới:
   ```bash
   netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
   ```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) liệt kê **Group Policy Objects** và làm nổi bật các cấu hình sai.

```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```

---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) thực hiện **kiểm tra tình trạng** của Active Directory và tạo báo cáo HTML kèm điểm đánh giá rủi ro.

```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```

## References

- [1] [BloodHound Community Edition v8 ra mắt với OpenGraph: Các đường tấn công danh tính vượt ra ngoài Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Vượt ra ngoài ACL: Lập bản đồ các đường leo thang đặc quyền Windows bằng BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: Lập bản đồ đường tấn công OpenGraph trong BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)
{{#include ../../banners/hacktricks-training.md}}
