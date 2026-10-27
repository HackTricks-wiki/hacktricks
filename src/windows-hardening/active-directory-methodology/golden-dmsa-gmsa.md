# Golden gMSA/dMSA Attack (Tính toán ngoại tuyến mật khẩu Managed Service Account)

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Windows Managed Service Account là các domain principal được thiết kế để chạy dịch vụ mà không cần quản trị viên xử lý mật khẩu có thời hạn sử dụng dài:

1. **gMSA** (group Managed Service Account) có thể được sử dụng bởi các máy tính được cấp quyền thông qua `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) được giới thiệu trong **Windows Server 2025**. Nó ràng buộc xác thực thông thường với danh tính máy được cấp quyền và có thể thay thế một service account cũ thông qua quy trình migration.

Đừng nhầm **Golden dMSA** với **BadSuccessor**. Golden dMSA yêu cầu chiếm được dữ liệu khóa gốc KDS và tính toán khóa của managed account; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) thay vào đó khai thác quyền kiểm soát đối tượng dMSA và các thuộc tính migration của nó.

DC không lưu trữ mật khẩu dạng clear-text được tạo độc lập cho từng gMSA. Nó tính toán mật khẩu account từ **KDS root key**, khóa Group Key Distribution Protocol (GKDI) được lập chỉ mục theo thời gian và SID của account. Các đối tượng root-key là đối tượng `msKds-ProvRootKey` nằm bên dưới `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; giá trị nhạy cảm là `msKds-RootKeyData`. `msDS-ManagedPasswordId` **không phải GUID**: đây là một key identifier dạng nhị phân chứa GUID của KDS root-key, các chỉ mục GKDI `L0`/`L1`/`L2` và metadata domain/forest. DC áp dụng KDF với label `GMSA PASSWORD` và SID dạng nhị phân làm context, sau đó chỉ cung cấp `MSDS-MANAGEDPASSWORD_BLOB` cho các principal được cấp quyền truy xuất mật khẩu gMSA.<sup>[[2]](#references)</sup>

Về hoạt động thông thường, dMSA có một điểm khác biệt: secret của nó được giữ trên DC và KDC cấp credential cho một máy được cấp quyền. Tuy nhiên, dMSA tái sử dụng cơ chế tính toán mật khẩu KDS/GKDI bên dưới. Golden dMSA tái tạo trực tiếp secret đó, do vậy bỏ qua luồng dự kiến ràng buộc với máy và Credential Guard trên service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Sau khi trích xuất KDS root key, attacker có thể tính toán mật khẩu cho các account gắn với khóa đó mà không cần đọc `msDS-ManagedPassword`. Cách này vượt qua ACL truy xuất mật khẩu ở cấp account và vẫn hiệu quả qua các lần xoay vòng mật khẩu thông thường trong khi root key bị chiếm đoạt vẫn còn được sử dụng. Với gMSA, `msDS-ManagedPasswordId` có thể đọc được và thường cung cấp chính xác key identifier. Với dMSA bị giới hạn ACL, Golden dMSA giảm số identifier còn thiếu xuống chỉ còn **1.024 ứng viên**.<sup>[[1]](#references)[[2]](#references)</sup>

### Điều kiện tiên quyết

* Đối tượng KDS root-key liên quan, thường thu được bằng quyền Enterprise Admin / Domain Admin ở forest root, `SYSTEM` trên DC, hoặc từ cơ sở dữ liệu hay bản sao lưu DC bị lộ.<sup>[[1]](#references)[[2]](#references)</sup>
* SID, DNS domain, tên forest và `sAMAccountName` của account mục tiêu.<sup>[[1]](#references)[[2]](#references)</sup>
* Để tính toán trực tiếp gMSA, cần `msDS-ManagedPasswordId` được mã hóa base64; với Golden dMSA, có thể đoán giá trị này.<sup>[[1]](#references)[[2]](#references)</sup>
* Máy Windows x64 có .NET Framework 4.7.2 để chạy [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Giai đoạn 1 - Trích xuất KDS root key

`GoldenDMSA` và [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) xuất các trường của đối tượng root-key thành một blob base64. Nếu không có tham số domain, các công cụ sẽ truy vấn forest root và yêu cầu quyền truy cập thư mục đủ cao. Khi có tham số domain/forest, `SYSTEM` trên DC có thể truy vấn bản sao naming context Configuration cục bộ của DC đó.<sup>[[1]](#references)[[2]](#references)</sup>

```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```

Ghi lại cả GUID khóa gốc và blob khóa gốc dạng base64. Bản xuất hive registry `SECURITY`/`SYSTEM` tự nó không phải là KDS root key: dữ liệu có thẩm quyền nằm trong phân vùng AD Configuration.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - Liệt kê các đối tượng gMSA / dMSA

Với gMSA, hãy lấy `sAMAccountName`, `objectSid` và `msDS-ManagedPasswordId` dạng nhị phân. Thuộc tính sau thường có thể đọc được ngay cả khi caller không được phép truy xuất `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>

```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
    Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```

ACL mặc định của dMSA có thể ngăn việc liệt kê LDAP với quyền thấp. `GoldenDMSA info` có thể truy vấn LDAP hoặc liệt kê các RID ứng viên rồi phân giải SID thông qua `LsaLookupSids` trên `\PIPE\lsarpc`, sau đó phân biệt dMSA với tài khoản máy tính và gMSA.<sup>[[1]](#references)[[3]](#references)</sup>

```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```

### Giai đoạn 3 - Dựng lại hoặc đoán `msDS-ManagedPasswordId`

Mã định danh khóa bao gồm `L0Index`, `L1Index` và `L2Index`, chứ không phải dấu thời gian tạo tài khoản theo sau bởi các bit ngẫu nhiên. Semperis phát hiện rằng quy trình tạo mật khẩu không sử dụng `L0Index` ứng viên, trong khi `L1Index` và `L2Index` mỗi giá trị chỉ nằm trong phạm vi `0..31`. Do đó, kẻ tấn công biết GUID của root key, domain, forest và SID có thể tạo tất cả `32 * 32 = 1,024` mã định danh ứng viên.<sup>[[1]](#references)</sup>

```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```

Các phép tính được thực hiện offline, nhưng việc xác định ứng viên đang hoạt động thường cần các lần thử xác thực. Điều này có thể tạo ra một loạt lỗi Kerberos pre-authentication hoặc xác thực NTLM trước khi tìm được key hợp lệ. Với các key Kerberos AES, salt của managed-account mà công cụ sử dụng là `UPPERCASE.DNS.DOMAIN` + `host` + UPN viết thường của tài khoản, không bao gồm ký tự `$` ở cuối (ví dụ: `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Giai đoạn 4 - Tính toán và sử dụng mật khẩu

Nếu biết chính xác identifier, hãy tính toán bộ đệm mật khẩu 256 byte và chuyển đổi nó thành dữ liệu NTLM/AES. Giá trị base64 do các công cụ này in ra là bộ đệm mật khẩu đã mã hóa, **không phải** chính `MSDS-MANAGEDPASSWORD_BLOB` trong LDAP.<sup>[[2]](#references)[[3]](#references)</sup>

```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```

Kết quả NTLM có thể được dùng ở nơi chấp nhận NTLM; AES key có thể được dùng cho overpass-the-hash / yêu cầu TGT trong trường hợp managed account chỉ dùng AES. Điều này mang lại các quyền, SPN, cấu hình delegation và quyền truy cập tài nguyên của managed service account bị compromise mà không cần thêm máy của attacker vào `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Lạm dụng phân vùng Configuration xuyên domain

Các KDS root-key object nằm trong forest Configuration naming context, được replicate đến các DC trong child domain. Do đó, `SYSTEM` trên DC của child domain có thể đọc KDS material của forest-root từ replica cục bộ trên DC child, dù Domain Admin của child domain không thể đọc trực tiếp object này từ DC của forest-root. Nếu attacker cũng có thể đọc `msDS-ManagedPasswordId` của gMSA thuộc parent domain, GoldenGMSA có thể tính password của account parent đó; SID filtering không ngăn được cuộc tấn công mật mã này.<sup>[[5]](#references)</sup>

```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```

## Phát hiện, cô lập và khôi phục

* Cấu hình SACL trên container **Master Root Keys**, kế thừa bởi các đối tượng `msKds-ProvRootKey`, để ghi nhận các lần đọc `msKds-RootKeyData` thành công. Khi bật kiểm tra Directory Service Access, thao tác trích xuất trực tuyến sẽ tạo sự kiện Security **4662**; điều tra các chủ thể không phải DC hoặc người vận hành Tier-0 được kỳ vọng. Đồng thời kiểm tra các thay đổi đối với những SACL này và ACL của đối tượng root-key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Tấn công từ miền con lên miền cha đọc đối tượng KDS từ bản sao cục bộ của DC miền con bị xâm nhập, do đó miền gốc của forest có thể không thấy lần đọc đó. Trong miền cha, kiểm tra các lần đọc `msDS-ManagedPasswordId` thành công (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) trên các đối tượng `msDS-GroupManagedServiceAccount` và điều tra các lần đọc do principal từ miền khác thực hiện.<sup>[[5]](#references)</sup>
* Đối chiếu quyền truy cập đối tượng KDS với các lần đăng nhập bất thường bằng tài khoản được quản lý và các đợt Kerberos/NTLM thất bại tăng đột biến đối với tài khoản dịch vụ có hậu tố `$`. Việc tính toán ngoại tuyến sau khi cơ sở dữ liệu/bản sao lưu đã bị đánh cắp sẽ không hiển thị trên DC đang hoạt động.<sup>[[1]](#references)[[3]](#references)</sup>
* Xoay vòng mật khẩu thông thường là không đủ sau khi root-key bị lộ. Quy trình khôi phục hiện tại của Microsoft tạo một KDS root key mới, khởi động lại KDS trên tất cả DC liên quan và chuyển các tài khoản bị ảnh hưởng sang key đó. Nếu không biết phạm vi/thời điểm bị lộ và không thể chờ quá trình chuyển đổi an toàn, hãy thay thế mọi gMSA đã sử dụng key bị xâm phạm; nếu biết phạm vi, Microsoft có tài liệu về quy trình authoritative restore để buộc chuyển đổi an toàn. Xác thực GUID key mới trong `msDS-ManagedPasswordId` trước khi xóa key cũ.<sup>[[4]](#references)</sup>
* Xem quyền truy cập cơ sở dữ liệu DC và bản sao lưu, replication phân vùng Configuration, cũng như việc quản trị KDS root-key là Tier-0. Giảm `ManagedPasswordIntervalInDays` sẽ giới hạn một số khoảng thời gian cần khôi phục, nhưng không thu hồi root-key đã bị xâm phạm.<sup>[[4]](#references)</sup>

## Công cụ

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - liệt kê dMSA/gMSA, tạo identifier, xác thực 1.024 candidate, tính toán mật khẩu và chuyển đổi NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - liệt kê gMSA/KDS và tính toán mật khẩu trực tuyến, ngoại tuyến và xuyên miền.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) và [`Impacket`](https://github.com/fortra/impacket) - sử dụng hoặc xác thực các khóa NTLM/AES đã suy ra trong quá trình kiểm thử được ủy quyền.



## References

- [1] [Golden dMSA - bỏ qua xác thực đối với Managed Service Account được ủy quyền](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Các cuộc tấn công Active Directory nhắm vào gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Kho GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Cách khôi phục sau cuộc tấn công Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter làm ranh giới bảo mật giữa các miền? Phần 5 - Tấn công trust Golden gMSA](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
