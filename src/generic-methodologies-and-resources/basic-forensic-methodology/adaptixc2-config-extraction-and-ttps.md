# Trích xuất cấu hình và TTP của AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 là framework post-exploitation/C2 mã nguồn mở, có tính mô-đun, với beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) và hỗ trợ BOF.<sup>[[1]](#references)</sup> Trang này trình bày:
- Cách cấu hình được đóng gói bằng RC4 và nhúng vào beacon, cũng như cách trích xuất cấu hình đó
- Các dấu hiệu mạng/profile của listener HTTP/SMB/TCP
- Các TTP loader và persistence phổ biến được quan sát ngoài thực tế, kèm liên kết đến những trang kỹ thuật Windows liên quan

Các bản phát hành upstream gần đây cũng có listener beacon DNS/DoH và họ agent/listener Gopher riêng biệt. Vì vậy, hạ tầng Adaptix hiện đại có thể để lộ nhiều hơn các bề mặt HTTP/SMB/TCP ban đầu, ngay cả khi một mẫu cụ thể vẫn dùng beacon agent cổ điển.<sup>[[2]](#references)</sup>

## Profile và trường của beacon

AdaptixC2 hỗ trợ ba loại beacon chính:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 qua web với máy chủ/cổng/SSL, method, URI, header, user-agent và tên parameter tùy chỉnh có thể cấu hình
- BEACON_SMB: C2 ngang hàng qua named-pipe (intranet)
- BEACON_TCP: socket trực tiếp, có thể thêm marker ở đầu để làm nhiễu phần bắt đầu của giao thức

Đây là các bố cục beacon được ghi nhận công khai trong những phân tích Adaptix ban đầu và vẫn là điểm khởi đầu phổ biến nhất khi trích xuất từ phía mẫu.<sup>[[1]](#references)</sup> Tuy nhiên, các bản build upstream hiện tại cũng có extenders `BeaconDNS` và Gopher ở phía server, vì vậy không nên cho rằng mọi triển khai Adaptix đang hoạt động chỉ để lộ hạ tầng HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Các trường profile thường thấy trong cấu hình HTTP beacon (sau khi giải mã):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – dùng để phân tích kích thước response
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Các bản build BeaconHTTP gần đây cũng hỗ trợ operator chọn cách xoay vòng qua nhiều URI, user-agent, Host header và server, theo thứ tự tuần tự hoặc ngẫu nhiên.<sup>[[2]](#references)</sup> Từ góc độ hunting, điều này có nghĩa là một host bị nhiễm có thể phân tán callback qua nhiều đường dẫn và tổ hợp header mà không rời khỏi họ beacon cổ điển được đóng gói bằng RC4.

Ví dụ profile HTTP mặc định (từ một bản build beacon):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["172.16.196.1"],
  "ports": [4443],
  "http_method": "POST",
  "uri": "/uri.php",
  "parameter": "X-Beacon-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 2,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

Hồ sơ HTTP độc hại được quan sát (cuộc tấn công thực tế):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["tech-system[.]online"],
  "ports": [443],
  "http_method": "POST",
  "uri": "/endpoint/api",
  "parameter": "X-App-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 4,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

## Đóng gói cấu hình mã hóa và quy trình tải

Khi operator nhấp vào Create trong builder, AdaptixC2 nhúng profile đã mã hóa dưới dạng blob ở cuối beacon. Định dạng là:<sup>[[1]](#references)</sup>
- 4 byte: kích thước cấu hình (uint32, little‑endian)
- N byte: dữ liệu cấu hình được mã hóa bằng RC4
- 16 byte: khóa RC4

Loader của beacon sao chép khóa 16 byte từ cuối và giải mã RC4 khối N byte ngay tại chỗ:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Các hệ quả thực tế:<sup>[[1]](#references)</sup>
- Toàn bộ cấu trúc thường nằm trong phần PE .rdata.
- Quá trình trích xuất có tính xác định: đọc kích thước, đọc ciphertext có kích thước đó, đọc khóa 16 byte nằm ngay sau, rồi giải mã RC4.

## Quy trình trích xuất cấu hình (dành cho bên phòng thủ)

Viết một công cụ trích xuất mô phỏng logic của beacon:<sup>[[1]](#references)</sup>
1) Tìm blob bên trong PE (thường nằm trong .rdata). Cách tiếp cận thực tế là quét .rdata để tìm bố cục [size|ciphertext|khóa 16 byte] có vẻ hợp lý rồi thử RC4.
2) Đọc 4 byte đầu tiên → size (uint32 LE).
3) Đọc N=size byte tiếp theo → ciphertext.
4) Đọc 16 byte cuối → khóa RC4.
5) Giải mã ciphertext bằng RC4. Sau đó phân tích profile thuần văn bản như sau:
   - các giá trị vô hướng u32/boolean như đã lưu ý ở trên
   - các chuỗi có tiền tố độ dài (độ dài u32 theo sau bởi các byte; có thể có NUL ở cuối)
   - mảng: servers_count theo sau bởi số cặp [string, u32 port] tương ứng

Proof-of-concept Python tối giản, độc lập (không cần thư viện bên ngoài), hoạt động với blob đã trích xuất:

```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

class P:
    def __init__(self, buf: bytes):
        self.b = buf; self.o = 0
    def u32(self) -> int:
        v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def u8(self) -> int:
        v = self.b[self.o]; self.o += 1; return v
    def s(self) -> str:
        L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
        return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    cfg = {}
    cfg['agent_type']    = p.u32()
    cfg['use_ssl']       = bool(p.u8())
    n                    = p.u32()
    cfg['servers']       = []
    cfg['ports']         = []
    for _ in range(n):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method']   = p.s()
    cfg['uri']           = p.s()
    cfg['parameter']     = p.s()
    cfg['user_agent']    = p.s()
    cfg['http_headers']  = p.s()
    cfg['ans_pre_size']  = p.u32()
    cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
    cfg['kill_date']     = p.u32()
    cfg['working_time']  = p.u32()
    cfg['sleep_delay']   = p.u32()
    cfg['jitter_delay']  = p.u32()
    cfg['listener_type'] = 0
    cfg['download_chunk_size'] = 0x19000
    return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```

Mẹo:
- Khi tự động hóa, hãy dùng PE parser để đọc .rdata rồi áp dụng cửa sổ trượt: với mỗi offset o, thử size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], key ứng viên = 16 byte tiếp theo; giải mã RC4 rồi kiểm tra các trường chuỗi có giải mã thành UTF-8 và độ dài có hợp lý không.
- Phân tích profile SMB/TCP bằng cách tuân theo cùng quy ước tiền tố độ dài.

## Profile listener tùy chỉnh: đừng chỉ hard-code schema HTTP cổ điển

Định dạng đóng gói bên ngoài (`u32 size | RC4 ciphertext | 16-byte key`) có thể tái sử dụng, vì vậy các listener được actor tùy chỉnh có thể dùng cùng quy trình trích xuất nhưng thay đổi hoàn toàn bố cục trường sau giải mã.

Một ví dụ gần đây đáng chú ý là chiến dịch Tropic Trooper vào tháng 3 năm 2026, trong đó Adaptix beacon được trích xuất không chứa profile HTTP/TCP tiêu chuẩn. Thay vào đó, blob đã giải mã lưu các tham số truyền tải GitHub như sau:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (ví dụ `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Chiến lược parser thực tế:
- Trước tiên, phát hiện blob RC4 bên ngoài như thường lệ.
- Sau khi giải mã, hãy phân nhánh dựa trên các chuỗi sentinel và tính hợp lý của trường, thay vì lập tức ép dữ liệu vào HTTP parser.
- Các sentinel hữu ích gồm `api.github.com`, `/issues?state=open`, HTTP verb/URI, chuỗi dạng named pipe hoặc mảng server/port có vẻ hợp lệ.
- Nếu HTTP parser thất bại nhưng plaintext chứa các chuỗi UTF-8 có tiền tố độ dài nhất quán, hãy giữ lại mẫu và thử các schema thay thế thay vì loại bỏ vì cho là false positive.

Trong chiến dịch đó, listener tùy chỉnh dùng GitHub issues làm C2 transport, còn beacon truy vấn `ipinfo.io` để tìm IP bên ngoài của nó, vì GitHub API không trực tiếp tiết lộ địa chỉ nguồn của nạn nhân cho operator.<sup>[[5]](#references)</sup>

## Fingerprinting mạng và săn tìm

HTTP:<sup>[[1]](#references)</sup>
- Thường gặp: POST đến URI do operator chọn (ví dụ /uri.php, /endpoint/api)
- Tham số header tùy chỉnh được dùng làm beacon ID (ví dụ X‑Beacon‑Id, X‑App‑Id)
- User-agent giả dạng Firefox 20 hoặc các bản Chrome đương thời
- Nhịp polling thể hiện qua sleep_delay/jitter_delay
- Các bản dựng mới hơn có thể luân phiên URI, user-agent, Host header và server giữa các callback, vì vậy hãy gom cụm dựa trên tên header hiếm gặp, mẫu kích thước phản hồi, việc tái sử dụng TLS và thời gian, thay vì giả định chỉ có một cặp path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener named pipe SMB cho C2 intranet khi web egress bị hạn chế
- TCP beacon có thể thêm vài byte vào trước traffic để làm mờ điểm bắt đầu của protocol

Mặc định teamserver upstream hiện tại
- `profile.yaml` hiện được đóng gói với teamserver `0.0.0.0:4321`, endpoint `/endpoint`, tên file certificate/key `server.rsa.crt` và `server.rsa.key`, cùng các extender cho HTTP, SMB, TCP, DNS, Beacon agent và Gopher.<sup>[[2]](#references)</sup>
- Với các route không khớp, error handler mặc định trả về `Server: AdaptixC2` và `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Nội dung 404 mặc định chứa `AdaptixC2 404` và `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Các đợt quét trên Internet diện rộng năm 2026 phát hiện nhiều teamserver lộ ra trên cổng `4321` và nhiều beacon listener trên `43211`; do đó, cả hai cổng đều hữu ích làm điểm pivot ban đầu nhưng không nên coi là đầy đủ.<sup>[[4]](#references)</sup>

Dấu hiệu nhận diện listener DNS/DoH:<sup>[[4]](#references)</sup>
- Extender BeaconDNS hiện tại trả lời có thẩm quyền (`AA=true`)
- Các truy vấn không khớp với cấu trúc protocol beacon — đáng chú ý là tên có ít hơn 5 nhãn trước domain được cấu hình — thường được trả lời bằng `TXT "OK"`
- Nếu TTL cơ sở được cấu hình là 0, listener sẽ dùng giá trị cơ sở 10 giây và cộng thêm jitter tối đa 59 giây
- Vì vậy, các probe chủ động dùng nhãn ngắn rất hữu ích khi không có HTTP listener nào lộ ra

## TTP loader và persistence được ghi nhận trong các sự cố

Loader PowerShell chạy trong bộ nhớ:<sup>[[1]](#references)</sup>
- Tải payload Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Cấp phát bộ nhớ unmanaged, sao chép shellcode, đổi protection thành 0x40 (PAGE_EXECUTE_READWRITE) qua VirtualProtect.<sup>[[7]](#references)</sup>
- Thực thi qua dynamic invocation của .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Phần mềm có chữ ký bị trojan hóa / loader shellcode theo giai đoạn:<sup>[[5]](#references)</sup>
- Một chuỗi tấn công Tropic Trooper năm 2026 dùng executable SumatraPDF bị trojan hóa (loader TOSHIS), chuyển hướng `_security_init_cookie` sang mã độc thay vì vá PE entry point
- Loader phân giải API bằng hashing Adler-32, tải một PDF mồi, lấy shellcode giai đoạn hai, giải mã bằng AES-128-CBC qua WinCrypt (`CryptDeriveKey` từ seed hard-code), rồi thực thi phản chiếu Adaptix beacon trong bộ nhớ
- Sau đó, persistence chuyển sang scheduled task với các tên trông vô hại như `\MSDNSvc` hoặc `\MicrosoftUDN`, được cấu hình để khởi chạy lại agent khoảng hai giờ một lần

Tham khảo các trang này về thực thi trong bộ nhớ và các lưu ý về AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Các cơ chế persistence được ghi nhận:<sup>[[1]](#references)</sup>
- Shortcut trong Startup folder (.lnk) để khởi chạy lại loader khi đăng nhập
- Registry Run key (HKCU/HKLM ...\CurrentVersion\Run), thường dùng tên nghe có vẻ vô hại như "Updater" để chạy loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack bằng cách đặt msimg32.dll trong %APPDATA%\Microsoft\Windows\Templates cho các process dễ bị ảnh hưởng

Các phân tích chuyên sâu và bước kiểm tra kỹ thuật:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ý tưởng săn tìm
- PowerShell tạo các chuyển đổi RW→RX: VirtualProtect thành PAGE_EXECUTE_READWRITE bên trong powershell.exe.<sup>[[8]](#references)</sup>
- Các mẫu dynamic invocation (GetDelegateForFunctionPointer)
- Phản hồi HTTPS 404 không khớp có `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` hoặc `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Phản hồi DNS có `AA=true` và `TXT "OK"` cho các truy vấn ngắn dưới những domain đáng ngờ.<sup>[[4]](#references)</sup>
- Traffic GitHub API đến `/repos/<owner>/<repo>/issues`, sau đó là các truy vấn `ipinfo.io` từ cùng chuỗi loader/beacon.<sup>[[5]](#references)</sup>
- Startup .lnk trong thư mục Startup của người dùng hoặc thư mục Startup chung.<sup>[[1]](#references)</sup>
- Run key đáng ngờ (ví dụ "Updater") và tên loader như update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Mẫu PE bị trojan hóa chuyển hướng `_security_init_cookie` sang mã downloader trước khi hiển thị tài liệu mồi.<sup>[[5]](#references)</sup>
- Đường dẫn DLL có thể ghi bởi người dùng trong %APPDATA%\Microsoft\Windows\Templates chứa msimg32.dll.<sup>[[1]](#references)</sup>

## Ghi chú về các trường OpSec

- KillDate: dấu thời gian sau đó agent sẽ tự hết hạn.<sup>[[1]](#references)</sup>
- WorkingTime: khung giờ agent nên hoạt động để hòa vào hoạt động công việc.<sup>[[1]](#references)</sup>

Các trường này có thể được dùng để gom cụm và giải thích những khoảng thời gian không hoạt động.

## YARA và dấu hiệu tĩnh

Unit 42 đã công bố YARA cơ bản cho beacon (C/C++ và Go) và các hằng số API-hashing của loader.<sup>[[1]](#references)</sup> Hãy cân nhắc bổ sung các rule tìm bố cục [size|ciphertext|16-byte-key] gần cuối PE .rdata, các chuỗi profile HTTP mặc định và những dấu hiệu server/listener mới hơn như `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` và `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Một framework mã nguồn mở mới được tận dụng trong các cuộc tấn công ngoài thực tế (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Tài liệu Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting một framework C2 mã nguồn mở trên quy mô lớn (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper chuyển hướng sang AdaptixC2 và custom beacon listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Tài liệu Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Tài liệu Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Các hằng số memory protection – Tài liệu Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
