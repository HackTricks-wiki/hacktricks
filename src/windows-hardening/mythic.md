# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic là gì?

Mythic là framework command and control (C2) mã nguồn mở, dạng mô-đun và hỗ trợ cộng tác, được thiết kế cho red teaming. Framework này cho phép operator quản lý và triển khai agent (payload) trên nhiều hệ điều hành, bao gồm Windows, Linux và macOS. Mythic cung cấp giao diện trình duyệt để nhiều operator cùng giao nhiệm vụ, xử lý tệp, quản lý SOCKS/rpfwd và tạo payload.

Khác với các framework nguyên khối, bản thân repository Mythic **không** đi kèm các loại payload hay C2 profile. Agent, wrapper và C2 profile thường được cài đặt dưới dạng thành phần bên ngoài và có thể được cập nhật độc lập với Mythic core.

### Cài đặt

Để cài đặt Mythic, hãy làm theo hướng dẫn trong **[repo Mythic](https://github.com/its-a-feature/Mythic)** chính thức. Một cách khởi tạo phổ biến từ thư mục Mythic là:

```bash
sudo make
sudo ./mythic-cli start
```

Nếu Mythic đang chạy, bạn thường có thể thêm agent hoặc profile mới bằng `./mythic-cli install github ...`, sau đó khởi động lại Mythic hoặc chỉ cần khởi chạy trực tiếp component mới.

### Agents

Mythic hỗ trợ nhiều agent, là các **payload thực hiện tác vụ trên những hệ thống đã bị xâm nhập**. Mỗi agent có thể được tùy chỉnh theo nhu cầu cụ thể và chạy trên các hệ điều hành khác nhau.

Theo mặc định, Mythic không cài đặt agent nào. Các agent mã nguồn mở do cộng đồng phát triển có tại [**https://github.com/MythicAgents**](https://github.com/MythicAgents), và [**ma trận tính năng của cộng đồng**](https://mythicmeta.github.io/overview/agent_matrix.html) hữu ích để nhanh chóng kiểm tra các hệ điều hành, định dạng payload, wrapper và profile C2 được hỗ trợ.<sup>[[1]](#references)</sup>

Để cài đặt agent từ tổ chức đó, bạn có thể chạy:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Dạng `sudo -E` hữu ích khi bạn cài đặt từ môi trường không phải root. Bạn có thể thêm agent mới bằng lệnh trước đó ngay cả khi Mythic đang chạy.

### C2 Profiles

C2 profiles trong Mythic định nghĩa **cách agent giao tiếp với máy chủ Mythic**. Chúng chỉ định giao thức giao tiếp, phương thức mã hóa và các thiết lập khác. Bạn có thể tạo và quản lý C2 profiles thông qua giao diện web Mythic.

Theo mặc định, Mythic được cài đặt mà không có profile nào. Tuy nhiên, bạn có thể tải một số profile từ repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) bằng cách chạy:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Các profile hiện tại cần operator lưu ý:

- [`http`](https://github.com/MythicC2Profiles/http): lưu lượng GET/POST bất đồng bộ cơ bản.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): lưu lượng HTTP linh hoạt hơn với nhiều callback domain, chuyển đổi dự phòng/luân phiên round-robin, header/query parameter tùy chỉnh và các phép biến đổi message (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) được đặt trong cookie, header, query parameter hoặc body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): định hình message HTTP dựa trên JSON/TOML khi profile `http` tĩnh quá dễ nhận diện.

### Ghi chú về nền tảng hiện tại

- Nhiều agent và profile công khai hiện được cài đặt bằng remote container image dựng sẵn.
  Nếu bạn fork một component hoặc vá cục bộ nhưng Mythic vẫn dùng hành vi cũ, hãy kiểm tra các mục `.env` được tạo cho `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` và `*_USE_VOLUME`; bật
  `*_USE_BUILD_CONTEXT="true"` thường là cách để Mythic dựng lại từ Docker context cục bộ thay vì âm thầm dùng lại remote image.
- Browser script là một trong những tính năng nâng cao chất lượng trải nghiệm có giá trị nhất của Mythic đối với operator: chúng có thể chuyển đầu ra command thô thành bảng, trình xem ảnh chụp màn hình, liên kết tải xuống, liên kết tìm kiếm và nút tạo task tiếp theo trực tiếp từ giao diện UI. Các bản Mythic hiện tại cho phép mỗi operator tự dùng script riêng, bật/tắt script trên toàn cục hoặc theo từng task, và đạt kết quả tốt nhất khi agent trả về JSON có cấu trúc thay vì plaintext. Tính năng này đặc biệt hữu ích cho các workflow `ls`, `ps`, triage và file-browser lặp lại.<sup>[[4]](#references)[[6]](#references)</sup>
- Các bản Mythic mới hơn cũng hỗ trợ interactive tasking và mô hình Push C2, giúp giảm nhu cầu polling bằng `sleep 0` trong các hoạt động dùng nhiều PTY/SOCKS/rpfwd. Khi agent/profile hỗ trợ, cách này thường ít tốn tài nguyên hơn so với việc liên tục gửi check-in đến server chỉ để duy trì kênh tương tác.<sup>[[3]](#references)</sup>
- Các builder Mythic thời 3.4 hiện hiểu ngữ cảnh tốt hơn những gì các tài liệu cũ mô tả: build parameter có thể được nhóm hoặc ẩn dựa trên OS được chọn hay các build option khác, payload type có thể khai báo khả năng hỗ trợ nhiều C2 profile hoặc nhiều instance của cùng một C2 trong một lần build, và C2 parameter deviation cho phép agent ẩn các trường mà nó không thực sự triển khai. Điều này quan trọng khi bạn chuyển đổi giữa `http`, `httpx`, `smb`,
  `tcp` và `websocket`, vì phạm vi build an toàn/hợp lệ không còn là một biểu mẫu tĩnh phẳng.<sup>[[5]](#references)</sup>
- Nếu bạn đang xây dựng cặp agent/profile tùy chỉnh và không muốn dùng định dạng message JSON hoặc crypto mặc định của Mythic trên wire, hãy dùng
  `translation_container`: Mythic loại bỏ UUID, gửi blob đã mã hóa cùng key material cho translator qua gRPC và yêu cầu nhận lại byte theo định dạng gốc của agent. Đây là cách phù hợp để hỗ trợ binary protocol, custom framing hoặc mã hóa phía agent mà không cần viết lại toàn bộ server.
- Hãy nhớ rằng linked/P2P callback không chỉ chuyển tiếp tasking. Luồng `get_tasking` của Mythic còn có thể mang theo response cùng dữ liệu `delegates`, `socks`,
  `rpfwd` và `interactive`. Trên thực tế, một egress callback có thể phục vụ các callback bên trong và pivot channel trong cùng vòng polling; nếu các child agent tự thực hiện check-in định kỳ, `get_delegate_tasks=false` sẽ ngăn parent vô tình lấy các job đang chờ của callback bên trong.

### Wrapper payload

Wrapper payload cho phép bạn giữ nguyên logic của agent trong khi thay đổi cách biểu diễn trên đĩa của payload được phân phối hoặc lưu lại.

- `service_wrapper`: chuyển payload khác thành Windows service executable, hữu ích khi đường dẫn thực thi yêu cầu một service binary hợp lệ.
- `scarecrow_wrapper`: bọc shellcode tương thích bằng loader ScareCrow để tạo đầu ra có loader hỗ trợ, chẳng hạn EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo là agent Windows viết bằng C# sử dụng .NET Framework 4.0, được thiết kế để dùng trong các chương trình đào tạo của SpecterOps.<sup>[[2]](#references)</sup>

Cài đặt bằng:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Ghi chú về build/profile hiện tại

- Apollo hiện có thể tạo payload `WinExe`, `Shellcode`, `Service` và `Source`.
- Các profile Apollo thường dùng là `http`, `httpx`, `smb`, `tcp` và `websocket`.
- `httpx` thường linh hoạt hơn khi cần xoay vòng domain, hỗ trợ proxy, tùy chỉnh vị trí message và biến đổi message thay cho profile `http` tĩnh cũ hơn.
- Apollo là một trong những community agent có nhiều tính năng hoàn thiện hơn và hiện cung cấp các tích hợp phía Mythic như browser scripts, giao diện duyệt file/process, screenshots, keylogging, SOCKS, rpfwd, Push C2 và định tuyến P2P.
- Apollo hỗ trợ các wrapper payload như `service_wrapper` và `scarecrow_wrapper`.
- Apollo hỗ trợ tải command động, cho phép giữ payload ban đầu gọn nhẹ rồi tải thêm command hoặc Forge module sau này, thay vì biên dịch mọi khả năng post-ex vào build đầu tiên.
- Khi tạo đầu ra shellcode, builder Apollo hiện cũng cung cấp các lựa chọn định dạng Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) và cách xử lý bypass của Donut (`None`, `Abort on fail`, `Continue on fail`). Điều này hữu ích nếu mục tiêu cuối cùng là bọc lại shellcode bằng `service_wrapper`, `scarecrow_wrapper` hoặc custom loader.
- `register_file` và `register_assembly` là các primitive staging cho `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` và `powerpick`. Trong các build Apollo hiện tại, những artifact đã staging này được cache phía client dưới dạng blob AES256 được bảo vệ bằng DPAPI.
- Kết quả `ls` và `ps` tích hợp đặc biệt tốt với browser scripts và trình duyệt file/process của Mythic, giúp operator phân loại nhanh hơn đáng kể trong các hoạt động cộng tác.
- Các job fork-and-run của Apollo kế thừa cấu hình sacrificial process từ
  `spawnto_x86` / `spawnto_x64`, kế thừa lựa chọn process cha từ `ppid`, rồi
  sử dụng primitive injection hiện được chọn. Trên thực tế, điều này có nghĩa là
  việc tinh chỉnh OPSEC cho một command thường ảnh hưởng đồng thời đến `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` và `spawn`.
- Các backend injection Apollo hiện được tài liệu hóa gồm `CreateRemoteThread`,
  `QueueUserAPC` (kiểu early-bird) và `NtCreateThreadEx` thông qua syscalls. Dùng
  `get_injection_techniques` trước các hoạt động post-exploitation dễ gây chú ý và
  `set_injection_technique` nếu cần chuyển khỏi một primitive không phù hợp với
  target hoặc command bạn muốn chạy.
- `blockdlls` chỉ ảnh hưởng đến các sacrificial process được tạo cho job post-exploitation.
  Kết hợp với target `spawnto_x64` ít đáng ngờ hơn mặc định
  `rundll32.exe` trần, đây là một trong những thay đổi phía Apollo dễ thực hiện nhất
  trước khi chạy các task nặng về assembly/PowerShell.

### Quy trình build agent .NET có xét đến khả năng phát hiện

Một fork Apollo có xét đến khả năng phát hiện nên được xem là **bài toán của toàn bộ hệ thống build**, chứ không phải bước `obfuscate.exe` cuối cùng. Case study này bổ trợ cho [AV evasion methodology](av-bypass.md) tổng quát và các [.NET inspection tools](../reversing/reversing-tools-basic-methods/README.md): thay đổi wire identifier, metadata IL, cách đóng gói dependency, reflection và task được biên dịch động tạo thành một ranh giới tương thích.<sup>[[8]](#references)</sup>

#### Biến đổi protocol có xét đến YARA

Kiểm tra các rule công khai cho file/memory trước khi thay đổi code. Ví dụ, `Multi_Trojan_Mythic_4beb7e17` của Elastic khớp khi xuất hiện bất kỳ **7 trong 11** chuỗi Mythic JSON/action nào, bao gồm `task_id`, `post_response`, `c2_profile`, `get_tasking` và `get_delegate_tasks`. Đổi tên đủ số field có thể vượt qua ngưỡng này, nhưng đây là các giá trị protocol chứ không phải symbol chỉ mang tính hình thức: agent và phần triển khai server/profile tương ứng phải được thay đổi đồng bộ.<sup>[[7]](#references)[[8]](#references)</sup>

Việc này chỉ loại bỏ một tập đặc trưng tĩnh. Tần suất check-in, cấu trúc message, luồng task/response và quá trình dựng lại string lúc runtime vẫn có thể là chỉ dấu về hành vi hoặc memory; vì vậy, hãy xác thực cả artifact đã build lẫn một callback đã chạy, thay vì xem kết quả quét string sạch là thành công.<sup>[[8]](#references)</sup>

#### Merge trước khi áp dụng các phép biến đổi toàn cục

Nhúng resource bằng các công cụ như Costura sẽ lưu các assembly đi kèm dưới dạng resource nén. Vì vậy, obfuscator chỉ xử lý module bên ngoài sẽ bỏ sót tên type và metadata của chúng; ngược lại, obfuscate từng DLL độc lập có thể tạo ra tên không tương thích giữa các contract liên assembly. Trước tiên, hãy merge đầu ra build ở cấp IL (ví dụ bằng [ILRepack](https://github.com/gluck/il-repack)), sau đó áp dụng một rename map duy nhất lên module kết quả.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Một custom pass có thể sử dụng [dnlib](https://github.com/0xd4d/dnlib) để biến đổi managed IL/metadata và [AsmResolver](https://github.com/Washi1337/AsmResolver) để patch PE/resource sau khi ghi. Trong nghiên cứu tình huống, các lệnh `ldstr` đủ điều kiện được chuyển thành lời gọi integer-token/decryptor, sử dụng khóa rolling-XOR 16 byte mới; còn symbol và namespace được ánh xạ sang các tên có vẻ phù hợp với môi trường doanh nghiệp thay vì các định danh tuần tự ngắn. Các pass khác loại bỏ một số attribute của compiler/debugger, xóa các tham chiếu đến merger/embedding, đổi tên resource và patch thông tin phiên bản. Hãy tạo lại seed cho tên, dead code và vật liệu mã hóa ở mỗi lần build độc lập: thay đổi ciphertext sẽ loại bỏ các byte ổn định, nhưng decryptor ổn định hoặc mẫu biến đổi dễ nhận biết vẫn có thể trở thành chữ ký.<sup>[[8]](#references)</sup>

#### Giữ đồng bộ các task động với payload

Apollo có thể biên dịch source của task ở phía server, gửi các byte DLL và nạp chúng bằng `Assembly.Load()`. Khi các kiểu public của base agent được đổi tên, những task được biên dịch sau đó dựa trên API ban đầu sẽ không còn phân giải được. Hãy xem rename map được export là một artifact ABI dành riêng cho từng payload:<sup>[[8]](#references)</sup>

1. Gắn map và ngữ cảnh kiểu với đúng mã định danh payload/build.
2. Với mỗi lần build task, truy xuất map đó và viết lại một source tree tạm thời.
3. Chỉ viết lại các tham chiếu namespace, kiểu, kiểu lồng/generic, field và property đã được phân giải, sau đó biên dịch dựa trên assembly đã obfuscate và merge.
4. Từ chối map bị thiếu hoặc không khớp trước khi gửi task, đồng thời chạy kiểm thử khởi tạo sau khi biên dịch.

Thay thế toàn cục một cách mù quáng là không an toàn vì một định danh cũng có thể xuất hiện trong chuỗi, khai báo cục bộ, truy cập member, kiểu framework hoặc namespace không liên quan. Nếu vẫn sử dụng trình viết lại văn bản/regex, hãy bảo vệ rõ ràng các ngữ cảnh đó và kiểm thử hồi quy mỗi khi schema của map hoặc pass đổi tên thay đổi.<sup>[[8]](#references)</sup>

#### Không phụ thuộc namespace trong các contract reflection

Mã discovery kiểm tra `t.FullName.StartsWith("Tasks.")` sẽ phụ thuộc vào namespace và bị lỗi sau khi ánh xạ lại namespace. Thay vào đó, hãy discovery dựa trên một quan hệ kiểu ổn định, đồng thời giữ nguyên tên class của command nếu quá trình dispatch vẫn dùng `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Duy trì allowlist tường minh gồm các tên hiển thị qua reflection, trường serializer, entry point và API giữa các assembly không được đổi tên. Cuối cùng, decompile kết quả bằng ILSpy/dnSpy, quét cả phiên bản trên tệp lẫn trong bộ nhớ, và kiểm thử mọi đường dẫn command/loader trong EDR lab; một bản build khởi chạy thành công vẫn có thể chứa các task bị hỏng do đổi tên hoặc có hành vi chỉ bị phát hiện sau khi thực thi.<sup>[[8]](#references)</sup>

Agent này có rất nhiều command, khiến nó rất giống Beacon của Cobalt Strike nhưng có thêm một số tính năng. Trong số đó, nó hỗ trợ:

### Các thao tác thông dụng

- `cat`: In nội dung của một tệp
- `cd`: Thay đổi thư mục làm việc hiện tại
- `cp`: Sao chép một tệp từ vị trí này sang vị trí khác
- `ls`: Liệt kê các tệp và thư mục trong thư mục hiện tại hoặc đường dẫn được chỉ định
- `ifconfig`: Lấy thông tin về adapter và interface mạng
- `netstat`: Lấy thông tin về kết nối TCP và UDP
- `pwd`: In thư mục làm việc hiện tại
- `ps`: Liệt kê các process đang chạy trên hệ thống đích (kèm thông tin bổ sung)
- `jobs`: Liệt kê tất cả job đang chạy gắn với các task chạy lâu
- `download`: Tải một tệp từ hệ thống đích về máy cục bộ
- `upload`: Tải một tệp từ máy cục bộ lên hệ thống đích
- `reg_query`: Truy vấn các registry key và value trên hệ thống đích
- `reg_write_value`: Ghi một value mới vào registry key được chỉ định
- `sleep`: Thay đổi khoảng thời gian sleep của agent, quyết định tần suất agent liên lạc với Mythic server
- Và nhiều command khác; dùng `help` để xem danh sách đầy đủ các command hiện có.

### Leo thang đặc quyền

- `getprivs`: Bật nhiều đặc quyền nhất có thể trên token của thread hiện tại
- `getsystem`: Mở handle đến winlogon và nhân bản token, qua đó leo thang đặc quyền lên cấp SYSTEM
- `make_token`: Tạo một logon session mới và áp dụng cho agent, cho phép mạo danh người dùng khác
- `steal_token`: Đánh cắp primary token từ một process khác, cho phép agent mạo danh người dùng của process đó
- `pth`: Tấn công Pass-the-Hash, cho phép agent xác thực với tư cách một người dùng bằng NTLM hash của họ mà không cần mật khẩu dạng plaintext
- `mimikatz`: Chạy các command của Mimikatz để trích xuất credential, hash và thông tin nhạy cảm khác từ bộ nhớ hoặc cơ sở dữ liệu SAM
- `rev2self`: Đưa token của agent về primary token, qua đó hạ đặc quyền xuống cấp ban đầu
- `ppid`: Thay đổi process cha của các job post-exploitation bằng cách chỉ định một parent process ID mới, giúp kiểm soát tốt hơn context thực thi của job
- `printspoofer`: Thực thi các command của PrintSpoofer để vượt qua biện pháp bảo mật của print spooler, cho phép leo thang đặc quyền hoặc thực thi code
- `dcsync`: Đồng bộ Kerberos key của người dùng về máy cục bộ, cho phép crack mật khẩu offline hoặc thực hiện các cuộc tấn công tiếp theo
- `ticket_cache_add`: Thêm Kerberos ticket vào logon session hiện tại hoặc session được chỉ định, cho phép tái sử dụng ticket hoặc mạo danh

### Thực thi process

- `assembly_inject`: Cho phép inject .NET assembly loader vào process từ xa
- `blockdlls`: Chặn các DLL không có chữ ký của Microsoft được load vào các job post-exploitation
- `execute_assembly`: Thực thi .NET assembly trong context của agent
- `execute_coff`: Thực thi tệp COFF trong bộ nhớ, cho phép thực thi code đã biên dịch trong bộ nhớ
- `execute_pe`: Thực thi một executable không được quản lý (PE)
- `keylog_inject`: Inject keylogger vào process khác và gửi keystroke về giao diện keylog của Mythic
- `screenshot` / `screenshot_inject`: Chụp màn hình desktop hiện tại trực tiếp hoặc
  bằng cách inject screenshot assembly vào process/session đích
- `get_injection_techniques`: Hiển thị các kỹ thuật injection hiện có và kỹ thuật đang được chọn
- `inline_assembly`: Thực thi .NET assembly trong AppDomain dùng một lần, cho phép chạy code tạm thời mà không ảnh hưởng đến process chính của agent
- `register_assembly`: Đăng ký .NET assembly để thực thi sau này
- `register_file`: Đăng ký một tệp trong agent cache để dùng cho task `execute_*` hoặc PowerShell sau này
- `run`: Thực thi binary trên hệ thống đích, dùng PATH của hệ thống để tìm executable
- `set_injection_technique`: Thay đổi primitive injection được các job post-exploitation sử dụng
- `shinject`: Inject shellcode vào process từ xa, cho phép thực thi code tùy ý trong bộ nhớ
- `inject`: Inject shellcode của agent vào process từ xa, cho phép thực thi code của agent trong bộ nhớ
- `spawn`: Tạo một agent session mới trong executable được chỉ định, cho phép thực thi shellcode trong process mới
- `spawnto_x64` và `spawnto_x86`: Thay đổi binary mặc định được dùng trong các job post-exploitation thành đường dẫn được chỉ định, thay vì dùng `rundll32.exe` không có tham số, vốn rất dễ bị chú ý.

### Mythic Forge

Tính năng này cho phép **load** các tệp COFF/BOF từ Mythic Forge, một kho lưu trữ payload và công cụ đã biên dịch sẵn có thể thực thi trên hệ thống đích. Với tất cả command có thể load, ta có thể thực hiện các thao tác thông dụng bằng cách chạy chúng dưới dạng BOF trong process agent hiện tại (thường có OPSEC tốt hơn so với việc spawn process riêng).

Bắt đầu cài đặt chúng bằng:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Sau đó, dùng `forge_collections` để hiển thị các module COFF/BOF từ Mythic Forge, rồi chọn và tải chúng vào bộ nhớ của agent để thực thi. Theo mặc định, Apollo được thêm 2 collection sau:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Sau khi tải một module, nó sẽ xuất hiện trong danh sách dưới dạng một command khác, chẳng hạn `forge_bof_sa-whoami` hoặc `forge_bof_sa-netuser`.

Đối với BOF, hãy nhớ rằng Forge **không** chỉ chuyển một chuỗi đối số đơn giản đến Apollo. Nó ánh xạ các tham số BOF sang định dạng typed-array của Mythic, sau đó chuyển chúng vào luồng `execute_coff` của Apollo. Nếu BOF được tải từ Forge hoạt động bất thường, hãy kiểm tra các kiểu đối số BOF hoặc entrypoint mong đợi, thay vì chỉ xem command line bạn đã nhập. Cũng cần lưu ý rằng BOF loader mới hơn của Apollo đã thay đổi cách xử lý đối số so với các bản build rất cũ thời 2.3.1, vì vậy BOF lỗi thời hoặc collection cũ có thể không hoạt động chỉ vì yêu cầu marshaling đã thay đổi.

### Thực thi PowerShell và scripting

- `powershell_import`: Nhập một script PowerShell mới (.ps1) vào bộ nhớ đệm của agent để thực thi sau này
- `powershell`: Thực thi một command PowerShell trong ngữ cảnh của agent, hỗ trợ scripting và tự động hóa nâng cao
- `powerpick`: Inject một assembly loader PowerShell vào một sacrificial process rồi thực thi command PowerShell (không ghi log PowerShell).
- `psinject`: Thực thi PowerShell trong một process được chỉ định, cho phép chạy script có mục tiêu trong ngữ cảnh của process khác
- `shell`: Thực thi một command shell trong ngữ cảnh của agent, tương tự chạy command trong cmd.exe

### Di chuyển ngang

- `jump_psexec`: Dùng kỹ thuật PsExec để di chuyển ngang đến host mới bằng cách sao chép Apollo agent executable (apollo.exe) sang host đó rồi thực thi.
- `jump_wmi`: Dùng kỹ thuật WMI để di chuyển ngang đến host mới bằng cách sao chép Apollo agent executable (apollo.exe) sang host đó rồi thực thi.
- `link` và `unlink`: Tạo và ngắt các liên kết P2P (ví dụ qua SMB/TCP) giữa các callback.
- `wmiexecute`: Thực thi command trên hệ thống cục bộ hoặc hệ thống từ xa được chỉ định bằng WMI, có thể dùng thông tin đăng nhập để mạo danh.
- `net_dclist`: Lấy danh sách domain controller của domain được chỉ định, hữu ích để xác định các mục tiêu tiềm năng cho việc di chuyển ngang.
- `net_localgroup`: Liệt kê các nhóm cục bộ trên máy tính được chỉ định; mặc định là localhost nếu không chỉ định máy tính.
- `net_localgroup_member`: Lấy thông tin thành viên của nhóm cục bộ được chỉ định trên máy tính cục bộ hoặc từ xa, cho phép liệt kê người dùng trong các nhóm cụ thể.
- `net_shares`: Liệt kê các share từ xa và khả năng truy cập của chúng trên máy tính được chỉ định, hữu ích để xác định các mục tiêu tiềm năng cho việc di chuyển ngang.
- `socks`: Bật proxy tương thích SOCKS 5 trên mạng mục tiêu, cho phép tunnel traffic qua host đã bị xâm nhập. Tương thích với các công cụ như proxychains.
- `rpfwd`: Bắt đầu lắng nghe trên một port được chỉ định ở host mục tiêu và chuyển tiếp traffic qua Mythic đến IP và port từ xa, cho phép truy cập từ xa vào các service trên mạng mục tiêu.
- `listpipes`: Liệt kê tất cả named pipe trên hệ thống cục bộ, hữu ích cho việc di chuyển ngang hoặc leo thang đặc quyền thông qua tương tác với các cơ chế IPC.

Để xem các primitive thực thi WMI cấp thấp hơn được dùng bên dưới `jump_wmi` hoặc `wmiexecute`, hãy xem [WmiExec](lateral-movement/wmiexec.md). Để tìm hiểu các phương thức pivoting tổng quát hơn, hãy xem [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Các command khác
- `help`: Hiển thị thông tin chi tiết về các command cụ thể hoặc thông tin tổng quát về tất cả command hiện có trong agent.
- `clear`: Đánh dấu các task là 'cleared' để agent không thể lấy chúng. Bạn có thể chỉ định `all` để xóa tất cả task hoặc `task Num` để xóa một task cụ thể.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon là một agent viết bằng Golang, được biên dịch thành các executable **Linux và macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Ghi chú về build/profile hiện tại

- Các bản build Poseidon hiện tại nhắm đến Linux và macOS trên cả `x86_64` và `arm64`.
- Các định dạng đầu ra được hỗ trợ gồm executable native và các đầu ra kiểu shared library như `dylib` và `so`.
- Poseidon hỗ trợ `http`, `websocket`, `tcp` và `dynamichttp`; các builder hiện tại cung cấp cài đặt multi-egress như `egress_order` và ngưỡng failover.
- Metadata khả năng hiện tại của Poseidon cũng quảng bá browser scripts, tích hợp browser cho file/process, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd và P2P, nhờ đó nó có thể hoạt động như một pivot node Linux/macOS thực thụ thay vì chỉ là một remote shell đơn giản.
- Các tùy chọn lúc build như `proxy_bypass` và `garble` đáng để kiểm tra khi bạn cần hành vi mạng gọn gàng hơn hoặc obfuscation bổ sung cho binary Go.
- `pty` là một trong những lệnh cải thiện trải nghiệm mới hữu ích nhất cho hoạt động trên Linux/macOS vì nó mở một PTY tương tác và có thể mở một cổng phía Mythic để tương tác terminal đầy đủ hơn mà không cần dùng cách khắc phục cũ `sleep 0` + SOCKS.
- Tài liệu hiện tại của Poseidon đặc biệt đáng chú ý đối với tradecraft tập trung vào macOS: `jxa` thực thi JavaScript for Automation trong bộ nhớ, `screencapture` chụp desktop của người dùng đã đăng nhập, `clipboard_monitor` truyền các thay đổi của pasteboard, `execute_library` tải một dylib cục bộ và gọi một hàm trong đó, còn `libinject` buộc một process từ xa tải dylib trên đĩa.
- Với các job chạy lâu, hãy nhớ Poseidon thực thi công việc post-exploitation trong goroutine/thread hoạt động theo cơ chế hợp tác, chứ không thể bị buộc dừng ngay lập tức. Tài liệu cũng nêu rõ hiện chưa có cơ chế obfuscation agent tích hợp sẵn, vì vậy tradecraft ở cấp build/profile quan trọng hơn so với các implant thương mại được obfuscate mạnh.

Để tìm hiểu tradecraft dành riêng cho macOS xoay quanh các hoạt động dựa trên Mythic, lạm dụng JAMF hoặc ý tưởng MDM-as-C2, hãy xem [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Khi dùng trên Linux hoặc macOS, nó có một số lệnh thú vị:

### Các thao tác thường dùng

- `cat`: In nội dung của một file
- `cd`: Thay đổi thư mục làm việc hiện tại
- `chmod`: Thay đổi quyền của một file
- `config`: Xem cấu hình hiện tại và thông tin host
- `cp`: Sao chép file từ vị trí này sang vị trí khác
- `curl`: Thực hiện một request web đơn lẻ với header và method tùy chọn
- `upload`: Upload file lên target
- `download`: Download file từ hệ thống target về máy cục bộ
- Và nhiều lệnh khác

### Tìm kiếm thông tin nhạy cảm

- `triagedirectory`: Tìm các file đáng chú ý trong một thư mục trên host, chẳng hạn như file nhạy cảm hoặc thông tin xác thực.
- `getenv`: Lấy tất cả biến môi trường hiện tại.

### Tradecraft dành riêng cho macOS

- `jxa`: Thực thi JavaScript for Automation trong bộ nhớ thông qua `OSAScript`, hữu ích cho post-exploitation native trên macOS mà không cần tạo các file script riêng.
- `clipboard_monitor`: Kiểm tra pasteboard và báo các thay đổi về Mythic, hữu ích cho các quy trình đánh cắp thông tin xác thực/token dựa vào thao tác copy/paste.
- `screencapture`: Chụp desktop của người dùng trên macOS.
- `execute_library`: Tải một dylib từ đĩa và gọi một hàm được export cụ thể.
- `libinject`: Inject một shellcode stub buộc process macOS khác tải một dylib từ đĩa.
- `persist_launchd`: Tạo persistence LaunchAgent / LaunchDaemon trực tiếp từ agent.

### Di chuyển ngang

- `ssh`: SSH đến host bằng thông tin xác thực được chỉ định và mở PTY mà không tạo tiến trình ssh.
- `sshauth`: SSH đến các host được chỉ định bằng thông tin xác thực đã chọn. Bạn cũng có thể dùng lệnh này để thực thi một lệnh cụ thể trên các host từ xa qua SSH hoặc dùng nó để SCP file.
- `link_tcp`: Liên kết với agent khác qua TCP, cho phép các agent giao tiếp trực tiếp với nhau.
- `link_webshell`: Liên kết với agent bằng profile P2P webshell, cho phép truy cập từ xa vào giao diện web của agent.
- `rpfwd`: Bắt đầu hoặc dừng Reverse Port Forward, cho phép truy cập từ xa vào các dịch vụ trên mạng target.
- `socks`: Bắt đầu hoặc dừng proxy SOCKS5 trên mạng target, cho phép tunnel lưu lượng qua host đã bị compromise. Tương thích với các công cụ như proxychains.
- `portscan`: Quét các host để tìm port đang mở, hữu ích khi xác định target tiềm năng cho lateral movement hoặc các cuộc tấn công tiếp theo.

### Thực thi process

- `shell`: Thực thi một lệnh shell đơn thông qua /bin/sh, cho phép chạy lệnh trực tiếp trên hệ thống target.
- `run`: Thực thi một lệnh từ đĩa kèm tham số, cho phép chạy binary hoặc script trên hệ thống target.
- `pty`: Mở một PTY tương tác, cho phép tương tác trực tiếp với shell trên hệ thống target.

## References

- [1] [Ma trận tính năng Agent của cộng đồng Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README của Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Các điểm nổi bật của Mythic v3.2: Interactive Tasking, Push C2 và Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Tài liệu Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Các cập nhật Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Thay đổi hoạt động Red Team với những tính năng ẩn của Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Các quy tắc YARA Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Từ fork đến framework: Những gì chúng tôi học được về Agent Invasion khi sửa đổi Apollo](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
