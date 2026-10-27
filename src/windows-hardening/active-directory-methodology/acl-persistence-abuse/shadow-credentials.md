# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu <a href="#3f17" id="3f17"></a>

**Xem bài viết gốc để biết [toàn bộ thông tin về kỹ thuật này](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Tóm lại, kiểm soát **`msDS-KeyCredentialLink`** của người dùng hoặc máy tính có thể cho phép attacker thêm key credential, xác thực dưới danh nghĩa đối tượng đó bằng PKINIT và—khi KDC cùng tài khoản hỗ trợ các luồng cần thiết—dùng ticket thu được với `S4U2Self`/user-to-user để lấy NT hash của đối tượng.<sup>[[1]](#references)</sup>

Bài viết trình bày phương pháp thiết lập **thông tin xác thực xác thực bằng cặp khóa công khai-riêng tư** để lấy **Service Ticket** riêng có chứa NTLM hash của mục tiêu. Quy trình này liên quan đến NTLM_SUPPLEMENTAL_CREDENTIAL được mã hóa bên trong Privilege Attribute Certificate (PAC), vốn có thể giải mã.<sup>[[1]](#references)</sup>

### Yêu cầu

Để áp dụng kỹ thuật này, cần đáp ứng một số điều kiện:<sup>[[1]](#references)</sup>

- Cần có ít nhất một Domain Controller chạy Windows Server 2016.
- Domain Controller phải được cài đặt chứng chỉ số xác thực máy chủ.
- Schema thư mục phải có `msDS-KeyCredentialLink`; DC chạy Windows Server 2016 trở lên và chứng chỉ hỗ trợ PKINIT trên KDC là các yêu cầu thực tế về nền tảng được nghiên cứu nêu ra. Hãy kiểm tra schema và tổ hợp DC của domain thay vì cho rằng chỉ nhãn functional level của domain quyết định khả năng khai thác.
- Cần có tài khoản được ủy quyền quyền chỉnh sửa thuộc tính msDS-KeyCredentialLink của đối tượng mục tiêu.

## Lạm dụng

Lạm dụng Key Trust trên các đối tượng máy tính bao gồm nhiều bước hơn việc lấy Ticket Granting Ticket (TGT) và NTLM hash. Các lựa chọn gồm:<sup>[[1]](#references)</sup>

1. Tạo **RC4 silver ticket** để hoạt động với tư cách người dùng có đặc quyền trên máy chủ dự định.
2. Dùng TGT với **S4U2Self** để mạo danh **người dùng có đặc quyền**; cần sửa đổi Service Ticket để thêm service class vào tên dịch vụ.

Một ưu điểm đáng kể của việc lạm dụng Key Trust là chỉ cần khóa riêng do attacker tạo, tránh phải ủy quyền cho các tài khoản có thể dễ bị tấn công và không cần tạo tài khoản máy tính—việc này có thể khó xóa bỏ.<sup>[[1]](#references)</sup>

## Công cụ

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker dùng DSInternals để thao tác `msDS-KeyCredentialLink` bằng C#. Whisker và phiên bản Python tương ứng **pyWhisker** hỗ trợ thêm, liệt kê, xóa từng mục và xóa toàn bộ key credential.<sup>[[2]](#references)[[4]](#references)</sup>

Các chức năng của **Whisker** gồm:

- **Add**: Tạo cặp khóa và thêm key credential.
- **List**: Hiển thị tất cả các mục key credential.
- **Remove**: Xóa key credential được chỉ định.
- **Clear**: Xóa toàn bộ key credential, có khả năng làm gián đoạn việc sử dụng WHfB hợp lệ.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker mang quy trình này đến **các hệ thống kiểu UNIX** với Impacket và PyDSInternals, bao gồm các thao tác liệt kê/thêm/xóa và nhập/xuất JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray liệt kê các đối tượng domain mà người vận hành có quyền như `GenericWrite`/`GenericAll`, cố gắng thêm key credentials trên diện rộng, đồng thời có các chế độ cleanup/đệ quy. Việc spray trên diện rộng gây gián đoạn và dễ bị phát hiện; hãy dùng các mục tiêu cụ thể và lưu lại từng DeviceID đã thêm để xóa chính xác.<sup>[[3]](#references)</sup>

ADWS có thể thực hiện thao tác ghi key credential khi LDAP trực tiếp bị lọc. Xem [quy trình SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Lạm dụng ánh xạ tài khoản Key Trust để chiếm quyền tài khoản](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Công cụ chiếm quyền tài khoản AD bằng cách thao túng msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Công cụ spray Shadow Credentials trên toàn domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Phiên bản Python của công cụ Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Hậu khai thác](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
