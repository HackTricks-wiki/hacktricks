# Trích xuất cấu hình AdaptixC2 và TTP

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 là một framework C2/post-exploitation mã nguồn mở, dạng mô-đun, hỗ trợ beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) và BOF.<sup>[[1]](#references)</sup> Trang này trình bày:
- Cách cấu hình được đóng gói bằng RC4 và nhúng vào beacon, cũng như cách trích xuất cấu hình đó
- Các dấu hiệu mạng/profile của listener HTTP/SMB/TCP
- Các TTP loader và persistence phổ biến được quan sát trong thực tế, kèm liên kết đến các trang về kỹ thuật Windows liên quan

Các bản phát hành upstream gần đây cũng có listener beacon DNS/DoH và dòng agent/listener Gopher riêng biệt. Vì vậy, hạ tầng Adaptix hiện đại có thể để lộ nhiều bề mặt hơn HTTP/SMB/TCP nguyên bản, ngay cả khi một mẫu cụ thể vẫn sử dụng agent beacon cổ điển.<sup>[[2]](#references)</sup>

## Profile và trường của beacon

AdaptixC2 hỗ trợ ba loại beacon chính:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 qua web với server/port/SSL, method, URI, header, user-agent và tên parameter tùy chỉnh
- BEACON_SMB: C2 ngang hàng qua named pipe (intranet)
- BEACON_TCP: socket trực tiếp, có thể thêm marker ở đầu để làm mờ điểm bắt đầu của protocol

Đây là các layout beacon được ghi lại công khai trong những phân tích Adaptix ban đầu và vẫn là điểm khởi đầu phổ biến nhất để trích xuất từ phía mẫu.<sup>[[1]](#references)</sup> Tuy nhiên, các bản upstream hiện tại cũng có extenders `BeaconDNS` và Gopher ở phía server. Vì vậy, đừng cho rằng mọi triển khai Adaptix đang hoạt động chỉ để lộ hạ tầng HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Phần tóm tắt trường và các mẫu JSON sau đây mô tả định dạng HTTP được phân tích vào năm 2025; chúng không phải là đặc tả parser cho các bản upstream mới hơn. Các trường thường gặp trong những mẫu đó (sau khi giải mã):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – dùng để phân tích kích thước phản hồi
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Các bản BeaconHTTP gần đây cũng hỗ trợ operator chọn xoay vòng qua nhiều URI, user-agent, Host header và server, theo thứ tự tuần tự hoặc ngẫu nhiên.<sup>[[2]](#references)</sup> Từ góc độ threat hunting, điều này có nghĩa là một máy bị nhiễm duy nhất có thể gọi về qua nhiều đường dẫn và tổ hợp header mà không rời khỏi dòng beacon đóng gói bằng RC4 cổ điển.

Ví dụ về profile HTTP mặc định (từ bản build beacon):<sup>[[1]](#references)</sup>

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

HTTP profile độc hại được quan sát (cuộc tấn công thực tế):<sup>[[1]](#references)</sup>

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

## Đóng gói cấu hình đã mã hóa và đường dẫn tải

Khi operator nhấp vào Create trong builder, AdaptixC2 biên dịch profile đã mã hóa vào beacon. Đừng cho rằng nó nằm ở cuối PE hoặc shellcode: hãy tìm các byte của profile bằng cách quét section hoặc lần theo `getProfile()` trong mẫu. Định dạng đóng gói là:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 byte: kích thước cấu hình (uint32, little-endian)
- N byte: dữ liệu cấu hình được mã hóa bằng RC4
- 16 byte: khóa RC4

Loader của beacon sao chép khóa 16 byte từ cuối và giải mã RC4 khối N byte ngay tại chỗ:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Các hàm ý thực tế:<sup>[[1]](#references)</sup>
- Toàn bộ cấu trúc thường nằm trong phần .rdata của PE.
- Việc trích xuất có tính xác định: đọc kích thước, đọc ciphertext có kích thước đó, đọc khóa 16 byte đặt ngay sau, rồi giải mã RC4.

## Quy trình trích xuất cấu hình (dành cho người phòng thủ)

Để triage mẫu nói chung trước khi trích xuất beacon, xem [Phân tích malware](malware-analysis.md).

Viết một extractor mô phỏng logic của beacon:<sup>[[1]](#references)</sup>
1) Xác định blob bên trong PE (thường nằm trong .rdata). Một cách thực tế là quét .rdata để tìm bố cục [size|ciphertext|khóa 16 byte] có vẻ hợp lý rồi thử RC4.
2) Đọc 4 byte đầu → kích thước (uint32 LE).
3) Đọc N=size byte tiếp theo → ciphertext.
4) Đọc 16 byte cuối → khóa RC4.
5) Giải mã RC4 ciphertext. Sau đó phân tích profile thuần văn bản theo định dạng:
   - Các giá trị vô hướng u32/boolean như đã nêu ở trên
   - Chuỗi có tiền tố độ dài (độ dài u32 theo sau là các byte; có thể có NUL ở cuối)
   - Mảng: servers_count theo sau là số cặp [string, u32 port] tương ứng

PoC Python HTTP đời cũ (độc lập, không cần dependency bên ngoài) dành cho blob đã trích xuất theo thứ tự trường năm 2025. Với các bản build stock gần đây, hãy dùng parser theo schema hiện tại bên dưới:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Phân tích các profile HTTP và DNS mặc định hiện tại

Upstream hiện tại trước tiên đóng gói sáu giá trị `u32` little-endian: watermark/type của agent, ngày kill, thời gian hoạt động, thời gian sleep, jitter và watermark/type của listener. Sau đó, dữ liệu dành riêng cho HTTP bắt đầu bằng một cờ SSL dài một byte. Khác với ví dụ legacy, dữ liệu này có các danh sách URI, user-agent và Host header kèm số lượng phần tử, tiếp theo là chế độ xoay vòng và cài đặt proxy. Vì vậy, parser legacy bắt đầu đọc cờ SSL từ trường ngày kill và cho kết quả sai trên các bản dựng này. Độ dài chuỗi và giá trị số nguyên trong profile này dùng mã hóa little-endian; chuỗi được đóng gói có thêm ký tự NUL ở cuối nếu không rỗng.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Với các helper `P` và `rc4` ở trên, hãy dùng parser này trên plaintext **HTTP mặc định** đã giải mã. Không đưa khóa RC4 vào các báo cáo công khai: profile HTTP có thể chứa tên người dùng và mật khẩu proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Phân tích một profile plaintext HTTP mặc định hiện tại</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Với DNS beacon mặc định, đọc cùng sáu trường `u32` phổ biến, sau đó đọc các chuỗi `domain`, `resolvers`, `doh_resolvers` và `qtype` có tiền tố độ dài. Đọc `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` và `dns_mode` dưới dạng `u32`, sau đó đọc chuỗi user-agent DoH có tiền tố độ dài. `dns_mode` phân biệt UDP, DoH và hai chiều fallback. Đây là một layout riêng: không đưa DNS plaintext qua HTTP parser.<sup>[[12]](#references)[[13]](#references)</sup>

Mẹo:
- Khi tự động hóa, dùng PE parser để đọc .rdata rồi áp dụng cửa sổ trượt: với mỗi offset o, thử size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = 16 byte tiếp theo; giải mã RC4 và kiểm tra các trường chuỗi có giải mã được thành UTF-8 hay không, đồng thời độ dài có hợp lý hay không.
- Parse profile SMB/TCP theo cùng quy ước tiền tố độ dài.

## Profile listener tùy chỉnh: đừng chỉ hard-code schema HTTP cổ điển

Định dạng đóng gói bên ngoài (`u32 size | RC4 ciphertext | 16-byte key`) có thể tái sử dụng, vì vậy listener được actor tùy chỉnh hóa vẫn có thể dùng cùng quy trình trích xuất dù layout trường sau giải mã thay đổi hoàn toàn.

Một ví dụ gần đây là chiến dịch Tropic Trooper tháng 3 năm 2026, trong đó Adaptix beacon được trích xuất không chứa profile HTTP/TCP tiêu chuẩn. Thay vào đó, blob đã giải mã lưu các tham số truyền tải GitHub như sau:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (ví dụ: `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Chiến lược parser thực tế:
- Trước tiên, phát hiện blob RC4 bên ngoài như thường lệ.
- Sau khi giải mã, hãy phân nhánh dựa trên các chuỗi sentinel và tính hợp lý của trường, thay vì lập tức ép dữ liệu vào HTTP parser.
- Các sentinel hữu ích gồm `api.github.com`, `/issues?state=open`, HTTP verb/URI, chuỗi có dạng named pipe hoặc mảng server/port có vẻ hợp lệ.
- Nếu HTTP parser thất bại nhưng plaintext chứa các chuỗi UTF-8 có tiền tố độ dài mạch lạc, hãy giữ lại mẫu và thử các schema khác thay vì loại bỏ mẫu đó như một false positive.

Trong chiến dịch này, listener tùy chỉnh dùng GitHub issues làm C2 transport, còn beacon truy vấn `ipinfo.io` để biết IP bên ngoài vì GitHub API không trực tiếp tiết lộ địa chỉ nguồn của victim cho operator.<sup>[[5]](#references)</sup> Với một quy trình handshake riêng dùng issue cùng file trong repository, xem [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Fingerprinting mạng và săn tìm

HTTP:<sup>[[1]](#references)</sup>
- Phổ biến: POST đến các URI do operator chọn (ví dụ: /uri.php, /endpoint/api)
- Tham số header tùy chỉnh được dùng làm beacon ID (ví dụ: X‑Beacon‑Id, X‑App‑Id)
- User-agent giả dạng Firefox 20 hoặc các bản Chrome đương thời
- Nhịp polling có thể quan sát qua sleep_delay/jitter_delay
- Các bản build mới hơn có thể xoay vòng URI, user-agent, Host header và server giữa các callback; vì vậy hãy gom nhóm dựa trên tên header ít phổ biến, mẫu kích thước phản hồi, việc tái sử dụng TLS và thời điểm, thay vì mặc định chỉ có một cặp path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener named pipe SMB cho C2 intranet khi lưu lượng web đi ra bị hạn chế
- TCP beacon có thể thêm vài byte trước lưu lượng để làm mờ điểm bắt đầu giao thức

Mặc định hiện tại của teamserver upstream
- `profile.yaml` hiện có cấu hình teamserver `0.0.0.0:4321`, endpoint `/endpoint`, tên file certificate/key `server.rsa.crt` và `server.rsa.key`, cùng các extender cho HTTP, SMB, TCP, DNS, Beacon agent và Gopher.<sup>[[2]](#references)</sup>
- Với các route không khớp, error handler mặc định trả về `Server: AdaptixC2` và `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Nội dung 404 mặc định chứa `AdaptixC2 404` và `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Các đợt quét trên toàn Internet năm 2026 phát hiện nhiều teamserver bị lộ trên cổng `4321` và nhiều beacon listener trên cổng `43211`, vì vậy cả hai cổng đều hữu ích làm điểm xuất phát để pivot nhưng không nên coi là đầy đủ.<sup>[[4]](#references)</sup>

Dấu hiệu fingerprint của listener DNS/DoH:<sup>[[4]](#references)</sup>
- BeaconDNS extender hiện tại trả lời có thẩm quyền (`AA=true`)
- Các truy vấn không khớp định dạng giao thức beacon — đáng chú ý là tên có ít hơn 5 label trước domain được cấu hình — thường được trả lời bằng `TXT "OK"`
- Nếu TTL cơ sở được cấu hình là zero, listener dùng giá trị cơ sở 10 giây và cộng thêm jitter tối đa 59 giây
- Điều này khiến các probe chủ động với label ngắn hữu ích khi không có HTTP listener lộ ra ngoài

## TTP của loader và persistence được ghi nhận trong các sự cố

Loader PowerShell chạy trong bộ nhớ:<sup>[[1]](#references)</sup>
- Tải payload Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Cấp phát bộ nhớ unmanaged, sao chép shellcode, đổi quyền bảo vệ thành 0x40 (PAGE_EXECUTE_READWRITE) qua VirtualProtect.<sup>[[7]](#references)</sup>
- Thực thi bằng dynamic invocation của .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Phần mềm có chữ ký bị trojan hóa / loader shellcode theo từng giai đoạn:<sup>[[5]](#references)</sup>
- Một chuỗi tấn công Tropic Trooper năm 2026 dùng executable SumatraPDF bị trojan hóa (TOSHIS loader), chuyển hướng `_security_init_cookie` vào mã độc thay vì patch PE entry point
- Loader phân giải API bằng cách băm Adler-32, tải PDF mồi nhử, lấy shellcode giai đoạn hai, giải mã bằng AES-128-CBC thông qua WinCrypt (`CryptDeriveKey` từ một seed hardcoded), rồi thực thi Adaptix beacon trong bộ nhớ theo cách reflective
- Sau đó, persistence chuyển sang scheduled task với tên trông có vẻ lành tính như `\MSDNSvc` hoặc `\MicrosoftUDN`, được cấu hình để khởi chạy lại agent khoảng hai giờ một lần

Xem các trang sau để tìm hiểu về thực thi trong bộ nhớ và các lưu ý về AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Các cơ chế persistence được quan sát:<sup>[[1]](#references)</sup>
- Shortcut (.lnk) trong Startup folder để khởi chạy lại loader khi đăng nhập
- Registry Run key (HKCU/HKLM ...\CurrentVersion\Run), thường dùng tên nghe có vẻ lành tính như "Updater" để khởi chạy loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack bằng cách thả msimg32.dll vào %APPDATA%\Microsoft\Windows\Templates để nhắm đến các process dễ bị ảnh hưởng

Tìm hiểu sâu và kiểm tra kỹ thuật:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ý tưởng săn tìm
- PowerShell tạo chuyển đổi RW→RX: VirtualProtect sang PAGE_EXECUTE_READWRITE bên trong powershell.exe.<sup>[[8]](#references)</sup>
- Mẫu dynamic invocation (GetDelegateForFunctionPointer)
- HTTPS 404 không khớp với `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` hoặc `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Phản hồi DNS có `AA=true` và `TXT "OK"` cho truy vấn ngắn dưới các domain đáng ngờ.<sup>[[4]](#references)</sup>
- Lưu lượng GitHub API đến `/repos/<owner>/<repo>/issues`, sau đó là các truy vấn `ipinfo.io` từ cùng chuỗi loader/beacon.<sup>[[5]](#references)</sup>
- .lnk trong Startup folder của người dùng hoặc folder Startup chung.<sup>[[1]](#references)</sup>
- Run key đáng ngờ (ví dụ: "Updater") và tên loader như update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Mẫu PE bị trojan hóa chuyển hướng `_security_init_cookie` vào mã downloader trước khi hiển thị tài liệu mồi nhử.<sup>[[5]](#references)</sup>
- Đường dẫn DLL cho phép người dùng ghi dưới %APPDATA%\Microsoft\Windows\Templates có chứa msimg32.dll.<sup>[[1]](#references)</sup>

## Lưu ý về các trường OpSec

- KillDate: timestamp sau đó agent tự hết hạn.<sup>[[1]](#references)</sup>
- WorkingTime: những giờ agent nên hoạt động để hòa lẫn với hoạt động kinh doanh.<sup>[[1]](#references)</sup>

Các trường này có thể được dùng để gom cụm và giải thích những khoảng thời gian không có hoạt động quan sát được.

## YARA và dấu hiệu tĩnh

Unit 42 đã công bố YARA cơ bản cho beacon (C/C++ và Go) cùng các hằng số API-hashing của loader.<sup>[[1]](#references)</sup> Hãy cân nhắc bổ sung các rule tìm layout [size|ciphertext|16-byte-key] gần cuối PE .rdata, các chuỗi profile HTTP mặc định và các dấu hiệu server/listener mới hơn như `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` và `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Framework mã nguồn mở mới được khai thác trong các cuộc tấn công thực tế (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [GitHub của AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Tài liệu Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting một framework C2 mã nguồn mở trên quy mô lớn (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper chuyển sang AdaptixC2 và listener Beacon tùy chỉnh (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Tài liệu Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Tài liệu Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Các hằng số bảo vệ bộ nhớ – Tài liệu Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Tạo profile AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser profile beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Tạo profile DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Đóng gói profile AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
