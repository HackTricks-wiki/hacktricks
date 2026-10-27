# Truy cập vật lý và không dây bí mật

{{#include ../banners/hacktricks-training.md}}

Để xem hướng dẫn triển khai chi tiết được chủ sở hữu phê duyệt, bao gồm rendezvous outbound, khôi phục nguồn điện/uplink, giảm thiểu bí mật lưu trên thiết bị, kiểm thử capture và giám sát khả năng bị phát hiện, hãy xem [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Thay đổi đường đi của mạng cũng có thể làm thay đổi nguồn gốc vật lý được nhận diện. Một tác nhân tinh vi có thể dùng một hệ thống bị xâm phạm ở gần đó, một thiết bị ẩn, mạng truy cập công cộng, backhaul di động hoặc bộ thu vệ tinh để khiến log của mục tiêu trỏ ra xa vị trí của người vận hành. Không phương án nào trong số này loại bỏ bằng chứng vật lý, vô tuyến hoặc từ nhà cung cấp; chúng chuyển việc quy kết sang các bộ dữ liệu khác.

## Ma trận kỹ thuật

| Kỹ thuật | Nguồn gốc được nhận diện | Điều kiện cần thiết | Bằng chứng có giá trị cao |
|---|---|---|---|
| Điểm trung chuyển không dây ở gần | doanh nghiệp/nhà ở cạnh mục tiêu | máy chủ dual-homed bị xâm phạm và có quyền truy cập Wi-Fi của mục tiêu | log endpoint trên máy chủ lân cận, kết nối RF và RADIUS/DHCP của mục tiêu |
| Mạng công cộng/khách | NAT của địa điểm hoặc điểm thoát tunnel | quyền truy cập hợp pháp hoặc vượt qua kiểm soát truy cập | captive portal, DHCP, kết nối AP, CCTV và hồ sơ thanh toán/vị trí |
| Thiết bị thả bí mật | địa chỉ có dây, Wi-Fi hoặc di động của mục tiêu/khu vực lân cận | đặt hoặc chuyển giao thiết bị trực tiếp | cổng switch/USB, RF, kiểm kê, nguồn điện và telemetry tunnel outbound |
| Router di động/eSIM | NAT của nhà mạng hoặc APN chuyên dụng | modem/SIM/thuê bao | IMEI/IMSI/eSIM, khu vực phủ sóng của trạm di động, tài khoản nhà mạng và thời điểm lưu lượng |
| Lạm dụng liên kết vệ tinh | địa chỉ thuê bao trong vùng phủ sóng của chùm vệ tinh | điểm yếu đặc thù giao thức và dịch vụ | định vị RF, luồng uplink, RTT/định tuyến bất khả thi và hồ sơ nhà cung cấp |

## Tấn công Nearest Neighbor

Volexity ghi nhận một chiến dịch APT28/GRU năm 2022, trong đó tác nhân ở xa mục tiêu cuối cùng. Tác nhân password-spray dịch vụ công khai của mục tiêu để lấy thông tin xác thực hợp lệ, nhưng MFA đã ngăn đăng nhập trực tiếp từ Internet. Wi-Fi doanh nghiệp của mục tiêu chấp nhận các thông tin xác thực đó mà không cần MFA. Tác nhân xâm nhập các tổ chức ở gần mục tiêu về mặt vật lý, tìm thấy một hệ thống dual-homed có khả năng kết nối không dây, rồi dùng hệ thống đó để xác thực vào Wi-Fi của mục tiêu. Volexity đặt tên cho phương thức này là **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Điểm mới nằm ở cách kết hợp. Không có operator nào di chuyển đến mục tiêu và MFA của dịch vụ hướng ra Internet vẫn hoạt động. Thiết bị của hàng xóm bị xâm nhập tạo điều kiện tiếp cận vật lý; credential mục tiêu bị đánh cắp cung cấp quyền truy cập logic; Wi-Fi của mục tiêu trở thành đường đi vượt qua ranh giới.

### Điều kiện tiên quyết và khả năng hiển thị

- Một hệ thống ở gần phải có thể được điều khiển từ xa và có radio tương thích hoặc có quyền truy cập vào một pivot khác ở gần.
- SSID mục tiêu phải phủ sóng đến hệ thống đó và Wi-Fi phải chấp nhận credential/chứng chỉ/trạng thái thiết bị có thể tái sử dụng.
- Pivot thường cần hai đường kết nối đồng thời: một đường về operator và một đường vào WLAN mục tiêu.
- Mục tiêu có thể thấy MAC station mới và username hợp lệ nhưng không có chứng chỉ thiết bị được quản lý, posture, lịch sử hoặc lượt ra vào tòa nhà như dự kiến.
- Log trên endpoint của hàng xóm có thể ghi nhận các lần quét wireless, profile mới, thay đổi interface, tunneling và hoạt động điều khiển từ xa.

### Phát hiện và phòng ngừa

1. Yêu cầu EAP-TLS dựa trên chứng chỉ và posture thiết bị được quản lý cho Wi-Fi doanh nghiệp; đừng coi password đã thất bại MFA trên Internet là đủ chỉ vì nó được gửi qua radio.
2. Đối chiếu xác thực RADIUS với danh tính MDM/NAC, mối liên kết station/thiết bị trước đây, vị trí AP, sự kiện kiểm soát ra vào vật lý và các phiên đồng thời.
3. Cảnh báo khi tài khoản kết nối lần đầu, từ rìa AP bất thường, không có chứng chỉ thiết bị được quản lý hoặc khi cùng danh tính đó đang hoạt động ở nơi khác.
4. Giám sát các endpoint có khả năng bridge interface. Trên Windows, Linux và thiết bị mạng, kiểm tra các WLAN profile bất thường, cấu hình forwarding/NAT, virtual adapter và tunnel tồn tại lâu dài.
5. Giảm vùng phủ sóng tràn không cần thiết bằng cách bố trí AP và hoạch định công suất hợp lý. Đây là biện pháp hỗ trợ, không phải xác thực.
6. Phối hợp ứng phó sự cố với các đơn vị thuê mặt bằng lân cận: nguồn phát radio cuối cùng có thể chính là nạn nhân.

[Lab hai tổ chức do mình sở hữu](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) tái hiện các dấu hiệu này mà không tấn công hàng xóm.

### Xác thực đường đi pivot trên Windows

Một máy chủ Windows có hai kết nối mạng không tự động bridge các interface của nó. Trước tiên, hãy kiểm kê adapter, route và trạng thái WLAN, sau đó chỉ kết nối thông qua profile đã được phê duyệt. Đối số `name` của `netsh wlan connect` xác định một profile đã cài đặt, không phải SSID và password tùy ý. So sánh bảng route trước và sau khi kết nối để bảo đảm default route mới không làm gián đoạn đường điều khiển hoặc khiến kết quả mất hiệu lực. Chỉ tiếp tục với các [kiểm tra sau khi kết nối](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) sau khi xác nhận đúng interface và route.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Artifact sự cố được Volexity công bố cho thấy một điểm khác biệt hữu ích khác. C# được nhúng trong đó mở WLAN API, liệt kê các giao diện, đọc XML EAP từ ổ đĩa và gọi `WlanSetProfileEapXmlUserData` cho một profile được chỉ định trên giao diện không dây đầu tiên. API này thiết lập thông tin xác thực EAP của người dùng trên một profile 802.1X hiện có, nhưng component được công bố không có `WlanConnect` hay logic dò tìm được mô tả trong báo cáo. Hãy xem đây là hoạt động cấp cấu hình profile thay vì một connector hoàn chỉnh, đồng thời kiểm tra profile thu được trong quá trình [đánh giá client và supplicant](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Địa điểm công cộng và Wi-Fi của bên thứ ba

Sử dụng Wi-Fi ở quán cà phê, khách sạn, sân bay hoặc khu vực đô thị sẽ thay đổi IP mà đích đến nhìn thấy. Điều đó không tạo ra sự ẩn danh. Địa điểm hoặc nhà cung cấp dịch vụ có thể lưu nhật ký về việc kết nối với AP, MAC thiết bị, DHCP lease, tài khoản captive portal, xác minh qua SMS/email và luồng lưu lượng. Việc có mặt tại địa điểm, CCTV, giao dịch mua hàng, dữ liệu vị trí di động và hồ sơ di chuyển có thể liên kết sự kiện kỹ thuật số với một người.

Một tác nhân có thể tìm cách giảm bớt một dấu vết bằng cách dùng địa chỉ MAC ngẫu nhiên, thiết bị riêng, tiền mặt hoặc tunnel. Tuy nhiên, vẫn có thể đối chiếu dữ liệu giữa các lớp thông qua thời điểm đến, quy luật ghé lại địa điểm, dấu vân tay vô tuyến, hành vi trên portal, thời điểm lưu lượng, hình ảnh camera và nhà cung cấp tunnel. VPN cũng chỉ chuyển dữ liệu về đích từ nhật ký của địa điểm sang nhật ký VPN; nó không xóa bỏ việc địa điểm biết thiết bị đã có mặt.

Đơn vị quản lý mạng truy cập công cộng nên cô lập client, chặn lưu lượng ngang hàng, sử dụng WPA2/3-Enterprise hoặc khóa riêng cho từng thiết bị khi khả thi, lưu giữ nhật ký DHCP/RADIUS/an ninh ở mức phù hợp, bảo vệ captive portal và công bố quy trình xử lý hành vi lạm dụng. Red team chỉ nên sử dụng địa điểm như vậy khi điều khoản sử dụng và phạm vi engagement cho phép; vượt qua portal, đánh cắp quyền truy cập hoặc nhắm mục tiêu khách khác không phải là lối tắt kiểm thử được ủy quyền.

## Thiết bị drop bí mật và warshipping

Thiết bị drop là một hệ thống nhỏ được đặt hoặc đưa vào một địa điểm, sau đó được điều khiển qua Ethernet, Wi-Fi hoặc mạng di động. “Warshipping” đóng gói thiết bị để việc giao hàng thông thường đưa nó vào bên trong phạm vi phủ sóng vô tuyến. Phần cứng có thể là máy tính bo mạch đơn, bộ sạc đã chỉnh sửa, thiết bị ngoại vi USB, thiết bị mạng hoặc modem chạy bằng pin.

Kiến trúc vận hành:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Thiết bị có thể cung cấp foothold từ xa, thực hiện đo đạc không dây, giả lập thiết bị ngoại vi dùng trong diễn tập được ủy quyền hoặc chuyển tiếp lưu lượng. Nguồn có vẻ là tại chỗ, nhưng thiết bị để lại dấu vết vật lý: số sê-ri, bao bì, dấu vân tay, camera, nhật ký ra vào, mức tiêu thụ điện, USB descriptor, quá trình thương lượng switchport, dấu vân tay DHCP, hành vi OUI/ngẫu nhiên hóa MAC, phát xạ RF và các kết nối rendezvous lặp lại.

### Biện pháp phòng vệ

- Duy trì quy trình tiếp nhận và kiểm kê tài sản; kiểm tra các thiết bị điện tử bất ngờ và kiện hàng gửi cho nhân viên không tồn tại.
- Dùng 802.1X/NAC cho truy cập có dây và không dây, vô hiệu hóa các cổng không sử dụng và đưa thiết bị lạ vào VLAN khắc phục hạn chế.
- Cảnh báo khi phát hiện dấu vân tay DHCP mới, MAC được quản trị cục bộ tồn tại dai dẳng, thiết bị USB mạng/HID mới, Wi-Fi Direct/Bluetooth trái phép và tunnel đi ra tồn tại lâu.
- Lập đường cơ sở cho hành vi của switchport, nguồn qua Ethernet, DNS và TLS. Một máy chủ nhỏ không có trong hồ sơ kiểm kê nhưng định kỳ tạo kết nối mã hóa là tín hiệu đáng chú ý hơn chỉ riêng “Raspberry Pi OUI”.
- Trong diễn tập, hãy kiểm kê, dán nhãn, xác định phạm vi, mã hóa, cung cấp remote kill, đặt hạn chót thu hồi và bảo đảm việc mất thiết bị không làm lộ thông tin xác thực có thể tái sử dụng.

## Kết nối backhaul qua mạng di động và eSIM

Modem di động tránh cổng Internet của mục tiêu và có thể giữ cho thiết bị cấy ghép truy cập được phía sau NAT của nhà mạng thông qua rendezvous đi ra. Địa chỉ di động có thể thay đổi hoặc được dùng chung; nhà mạng di động vẫn lưu giữ bằng chứng mạnh về thuê bao và mạng: danh tính SIM/eSIM, IMSI, IMEI thiết bị, địa chỉ/cổng được cấp, thời gian kết nối với trạm/khu vực phủ sóng, cùng hồ sơ tài khoản/thanh toán và roaming.

Từ góc độ doanh nghiệp, hãy phát hiện modem và hotspot cá nhân bất ngờ bằng khảo sát không dây/RF, kiểm kê USB/PCI trên endpoint, hạn chế qua MDM, giám sát SSID giả mạo và kiểm tra thực tế. Thiết bị cấy ghép dùng mạng di động để điều khiển vẫn có thể bị phát hiện qua hành vi Ethernet/Wi-Fi tại chỗ và phát xạ vô tuyến.

Trong các diễn tập được ủy quyền, tổ chức nên sở hữu gói thuê bao và modem, ghi lại các mã định danh cùng thông tin của người điều khiển, đồng thời xác minh điều khoản của nhà mạng/nhà cung cấp có cho phép lưu lượng đó hay không. Nhãn trả trước hoặc việc mua bằng tiền mã hóa không xóa được hồ sơ trạm phát, thiết bị hay điểm bán lẻ.

## Ngẫu nhiên hóa MAC và fingerprinting thiết bị

Các hệ thống hiện đại có thể sử dụng MAC ngẫu nhiên được quản trị cục bộ cho từng mạng. Điều này làm giảm khả năng theo dõi thụ động lâu dài bằng MAC xuất xưởng ổn định; nhưng không che giấu:

- thời điểm probe/association và tập hợp các khả năng mạng được yêu cầu;
- information element 802.11, tốc độ được hỗ trợ và hành vi riêng của nhà cung cấp;
- tùy chọn/tên máy chủ DHCP, mã định danh IPv6 và fingerprint trình duyệt/captive portal;
- danh tính 802.1X đã xác thực hoặc chứng chỉ;
- tài khoản ở tầng cao hơn, tunnel và mẫu lưu lượng; hoặc
- việc quan sát trực tiếp.

Đội phòng thủ không nên dùng danh sách cho phép MAC làm cơ chế xác thực. Hãy liên kết danh tính vô tuyến với chứng chỉ/trạng thái bảo mật thiết bị và xem MAC thay đổi là bình thường, trừ khi có ngữ cảnh khác bất thường.

## Chiếm quyền liên kết vệ tinh

Kaspersky ghi nhận Turla khai thác các điểm yếu trong dịch vụ Internet vệ tinh DVB-S một chiều đời cũ. Theo mô hình được báo cáo, một thuê bao từ xa hợp pháp gửi yêu cầu đi ra qua liên kết mặt đất nhưng nhận dữ liệu chiều xuống qua tín hiệu phát quảng bá vệ tinh diện rộng không mã hóa. Tác nhân nằm trong vùng phủ sóng vệ tinh có thể quan sát đường xuống, chọn IP của một thuê bao đang hoạt động và sắp xếp để các phản hồi C2 được gửi đến IP đó. Cả thuê bao hợp pháp lẫn tác nhân đều nhận được tín hiệu phát quảng bá; tác nhân trích xuất lưu lượng cho cổng đã chọn, trong khi thuê bao hợp pháp loại bỏ các gói tin không được yêu cầu. Sau đó, nhà điều hành C2 có vẻ như đang sử dụng địa chỉ của nhà cung cấp vệ tinh tại một khu vực địa lý khác.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Điều này chỉ áp dụng cho một giao thức/dịch vụ cụ thể, bị giới hạn băng thông và không tương đương với việc xâm nhập một terminal vệ tinh hai chiều hiện đại được mã hóa. Nó cũng không che giấu đường đi của yêu cầu gửi đi của tác nhân trước một giám sát viên có đủ năng lực. Các cơ hội phát hiện bao gồm định tuyến bất đối xứng/không thể xảy ra, lưu lượng đến một thuê bao không khởi tạo luồng đó, cổng đích bất thường, telemetry của nhà cung cấp, điều tra vị trí bộ thu/RF và cấu hình malware. Hãy dùng trường hợp này để chất vấn giả định rằng định vị địa lý IP C2 sẽ xác định vị trí của người điều khiển — không phải như một hướng dẫn triển khai.

## Bảng đối chiếu sự kiện vật lý với kỹ thuật số

Khi một nguồn có vẻ cục bộ bị nghi ngờ, hãy lập một dòng thời gian:

1. chuẩn hóa đồng hồ AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch và hệ thống kiểm soát ra vào vật lý;
2. xác định lần kết nối radio hoặc liên kết đầu tiên, không chỉ cảnh báo đầu tiên;
3. đối chiếu trạm với chứng chỉ, trạng thái thiết bị, dấu vân tay DHCP và vị trí switch/AP;
4. tìm hoạt động điều khiển từ xa/tunnel đồng thời trên các hệ thống lân cận;
5. xem xét việc giao nhận, khách đến thăm, sai lệch kiểm kê, camera và phát hiện RF theo chính sách/pháp luật hiện hành;
6. bảo quản thiết bị bị nghi ngờ và trạng thái mạng khả biến; không tùy tiện tắt rồi bật nguồn;
7. xác định liệu nguồn có vẻ là cơ sở hạ tầng do tác nhân kiểm soát hay là một nạn nhân khác.

## References

- [1] [Volexity — Tấn công Nearest Neighbor: Cách một APT của Nga vũ khí hóa các mạng Wi-Fi lân cận](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla vệ tinh: C2 của APT trên bầu trời](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Bổ sung phần cứng (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Hướng dẫn bảo mật mạng cục bộ không dây](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Mã hồ sơ WLAN PowerShell/C# đã biên tập](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Hàm WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
