# Tấn công macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Để biết thêm thông tin, hãy xem bài đăng gốc:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Đây là bản tóm tắt:<sup>[[1]](#references)</sup>

## Thông tin cơ bản về Mach Messages

Nếu bạn chưa biết Mach Messages là gì, hãy bắt đầu xem trang này:


{{#ref}}
../../
{{#endref}}

Trước mắt, hãy nhớ rằng ([định nghĩa tại đây](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages được gửi qua một _mach port_, một kênh **giao tiếp một bên nhận, nhiều bên gửi** được tích hợp trong mach kernel. **Nhiều process có thể gửi messages** đến một mach port, nhưng tại mỗi thời điểm, **chỉ một process có thể đọc từ port đó**. Tương tự file descriptors và sockets, mach ports được kernel cấp phát và quản lý; process chỉ thấy một số nguyên để chỉ định cho kernel biết chúng muốn sử dụng mach port nào.

## XPC Connection

Nếu bạn chưa biết cách thiết lập XPC connection, hãy xem:


{{#ref}}
../
{{#endref}}

## Tóm tắt lỗ hổng

Điều đáng chú ý là **abstraction của XPC là một kết nối một-một**, nhưng nó được xây dựng trên công nghệ **có thể có nhiều bên gửi, vì vậy:**

- Mach ports có một bên nhận, **nhiều bên gửi**.
- Audit token của XPC connection là audit token được **sao chép từ message nhận được gần nhất**.
- Việc lấy **audit token** của XPC connection rất quan trọng đối với nhiều **kiểm tra bảo mật**.<sup>[[1]](#references)</sup>

Mặc dù tình huống trên có vẻ thuận lợi, nhưng có một số trường hợp sẽ không gây ra vấn đề ([theo bài này](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens thường được dùng để kiểm tra quyền truy cập nhằm quyết định có chấp nhận một connection hay không. Vì việc này diễn ra thông qua một message gửi đến service port nên **connection vẫn chưa được thiết lập**. Các messages khác trên port này chỉ được xử lý như những yêu cầu kết nối bổ sung. Do đó, **các bước kiểm tra trước khi chấp nhận connection không dễ bị tấn công** (điều này cũng có nghĩa là audit token an toàn bên trong `-listener:shouldAcceptNewConnection:`). Vì vậy, chúng ta **cần tìm các XPC connections xác minh những hành động cụ thể**.
- XPC event handlers được xử lý đồng bộ. Điều này có nghĩa là event handler của một message phải hoàn tất trước khi được gọi cho message tiếp theo, kể cả trên các dispatch queues đồng thời. Vì vậy, bên trong **XPC event handler, audit token không thể bị ghi đè** bởi các messages thông thường khác (không phải reply!).<sup>[[1]](#references)</sup>

Có hai cách khác nhau để khai thác vấn đề này:

1. Variant 1:
   - **Exploit** kết nối với service **A** và service **B**.
     - Service **B** có thể gọi một **chức năng đặc quyền** trong service A mà người dùng không thể gọi.
   - Service **A** gọi **`xpc_connection_get_audit_token`** khi _**không**_ ở bên trong **event handler** cho một connection trong **`dispatch_async`**.
     - Do đó, một message **khác** có thể **ghi đè Audit Token** vì nó được dispatch bất đồng bộ bên ngoài event handler.
   - Exploit chuyển **quyền SEND đến service A** cho **service B**.
     - Như vậy, svc **B** thực sự sẽ **gửi** các **messages** đến service **A**.
   - **Exploit** cố **gọi** **hành động đặc quyền**. Trong một RC, svc **A** **kiểm tra** quyền thực hiện **hành động** này khi **svc B đã ghi đè Audit token** (cho phép exploit gọi hành động đặc quyền).
2. Variant 2:
   - Service **B** có thể gọi một **chức năng đặc quyền** trong service A mà người dùng không thể gọi.
   - Exploit kết nối với **service A**, nơi **gửi** cho exploit một **message chờ phản hồi** trên một port **reply** cụ thể.
   - Exploit gửi cho **service** B một message có kèm **reply port đó**.
   - Khi service **B phản hồi**, nó **gửi message đến service A**, **trong khi** **exploit** gửi một **message khác đến service A** để cố gọi **chức năng đặc quyền**, đồng thời chờ phản hồi từ service B ghi đè Audit token đúng thời điểm (Race Condition).

## Variant 1: gọi xpc_connection_get_audit_token bên ngoài event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Tình huống:

- Có hai mach services **`A`** và **`B`** mà chúng ta có thể kết nối (dựa trên sandbox profile và các bước kiểm tra quyền trước khi chấp nhận connection).
- _**A**_ phải có **kiểm tra quyền** đối với một hành động cụ thể mà **`B`** có thể vượt qua (nhưng ứng dụng của chúng ta thì không).
  - Ví dụ, nếu B có một số **entitlements** hoặc chạy dưới quyền **root**, nó có thể được phép yêu cầu A thực hiện hành động đặc quyền.
- Để kiểm tra quyền này, **`A`** lấy audit token bất đồng bộ, chẳng hạn bằng cách gọi `xpc_connection_get_audit_token` từ **`dispatch_async`**.

> [!CAUTION]
> Trong trường hợp này, attacker có thể kích hoạt **Race Condition** bằng cách tạo một **exploit** liên tục yêu cầu **A thực hiện một hành động**, đồng thời khiến **B gửi messages đến `A`**. Khi RC **thành công**, **audit token** của **B** sẽ được sao chép vào bộ nhớ **trong lúc** yêu cầu của **exploit** đang được A xử lý, giúp exploit **truy cập hành động đặc quyền vốn chỉ B mới có thể yêu cầu**.

Tình huống này xảy ra với **`A`** là `smd` và **`B`** là `diagnosticd`. Có thể dùng hàm [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) từ smb để cài đặt một privileged helper tool mới (dưới quyền **root**). Nếu một **process chạy dưới quyền root liên hệ với** **smd**, sẽ không có bước kiểm tra nào khác được thực hiện.

Do đó, service **B** là **`diagnosticd`** vì nó chạy dưới quyền **root** và có thể được dùng để **giám sát** một process. Khi bắt đầu giám sát, nó sẽ **gửi nhiều messages mỗi giây**.

Để thực hiện cuộc tấn công:

1. Tạo **connection** đến service có tên `smd` bằng giao thức XPC tiêu chuẩn.
2. Tạo **connection** thứ hai đến `diagnosticd`. Khác với quy trình thông thường, thay vì tạo và gửi hai mach ports mới, client port send right được thay bằng một bản sao của **send right** gắn với connection `smd`.
3. Kết quả là XPC messages có thể được gửi đến `diagnosticd`, nhưng các phản hồi từ `diagnosticd` được chuyển hướng đến `smd`. Đối với `smd`, các messages từ cả người dùng lẫn `diagnosticd` dường như đều xuất phát từ cùng một connection.

![Hình minh họa quy trình khai thác](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Bước tiếp theo là yêu cầu `diagnosticd` bắt đầu giám sát một process được chọn (có thể là process của chính người dùng). Đồng thời, một loạt messages 1004 thông thường được gửi đến `smd`. Mục đích là cài đặt một công cụ với đặc quyền nâng cao.
5. Hành động này gây ra race condition bên trong hàm `handle_bless`. Thời điểm thực hiện rất quan trọng: lời gọi hàm `xpc_connection_get_pid` phải trả về PID của process người dùng (vì công cụ đặc quyền nằm trong app bundle của người dùng). Tuy nhiên, hàm `xpc_connection_get_audit_token`, cụ thể là bên trong hàm con `connection_is_authorized`, phải tham chiếu đến audit token thuộc về `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: chuyển tiếp reply

Trong môi trường XPC (Cross-Process Communication), mặc dù các event handlers không chạy đồng thời, việc xử lý reply messages có hành vi đặc biệt. Cụ thể, có hai cách gửi messages chờ reply:

1. **`xpc_connection_send_message_with_reply`**: XPC message được nhận và xử lý trên một queue được chỉ định.
2. **`xpc_connection_send_message_with_reply_sync`**: Ngược lại, với phương thức này, XPC message được nhận và xử lý trên dispatch queue hiện tại.

Sự khác biệt này rất quan trọng vì nó cho phép **reply packets được phân tích đồng thời với lúc thực thi một XPC event handler**. Đáng chú ý, mặc dù `_xpc_connection_set_creds` có triển khai locking để ngăn audit token bị ghi đè một phần, cơ chế này không bảo vệ toàn bộ connection object. Vì vậy, audit token có thể bị thay thế trong khoảng thời gian giữa lúc phân tích packet và lúc thực thi event handler tương ứng.

Để khai thác lỗ hổng này, cần có thiết lập sau:

- Hai mach services, gọi là **`A`** và **`B`**, cả hai đều có thể thiết lập connection.
- Service **`A`** cần có bước kiểm tra quyền đối với một hành động cụ thể mà chỉ **`B`** mới có thể thực hiện (ứng dụng của người dùng không thể).
- Service **`A`** cần gửi một message chờ reply.
- Người dùng có thể gửi một message đến **`B`** và service này sẽ phản hồi.

Quy trình khai thác gồm các bước sau:

1. Chờ service **`A`** gửi một message chờ reply.
2. Thay vì phản hồi trực tiếp cho **`A`**, chiếm quyền reply port và dùng nó để gửi message đến service **`B`**.
3. Sau đó, gửi một message yêu cầu thực hiện hành động bị cấm, với kỳ vọng message này sẽ được xử lý đồng thời với reply từ **`B`**.<sup>[[1]](#references)</sup>

Dưới đây là hình minh họa tình huống tấn công đã mô tả:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Khó khăn khi phát hiện

- **Khó tìm các trường hợp sử dụng**: Việc tìm các trường hợp sử dụng `xpc_connection_get_audit_token` rất khó, cả bằng phương pháp phân tích tĩnh lẫn động.
- **Phương pháp**: Frida được dùng để hook hàm `xpc_connection_get_audit_token`, lọc các lời gọi không xuất phát từ event handlers. Tuy nhiên, phương pháp này chỉ áp dụng được cho process đã hook và cần process đó đang được sử dụng.
- **Công cụ phân tích**: Các công cụ như IDA/Ghidra được dùng để kiểm tra các mach services có thể truy cập, nhưng quá trình này tốn thời gian và phức tạp do các lời gọi liên quan đến dyld shared cache.
- **Hạn chế khi viết script**: Các nỗ lực viết script để phân tích lời gọi `xpc_connection_get_audit_token` từ các khối `dispatch_async` gặp trở ngại do việc phân tích blocks và tương tác với dyld shared cache khá phức tạp.<sup>[[1]](#references)</sup>

## Bản sửa lỗi <a href="#the-fix" id="the-fix"></a>

- **Báo cáo vấn đề**: Một báo cáo về các vấn đề chung và cụ thể được phát hiện trong `smd` đã được gửi đến Apple.
- **Phản hồi của Apple**: Apple đã khắc phục vấn đề trong `smd` bằng cách thay `xpc_connection_get_audit_token` bằng `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Bản chất của cách sửa lỗi**: Hàm `xpc_dictionary_get_audit_token` được xem là an toàn vì nó lấy audit token trực tiếp từ mach message gắn với XPC message nhận được. Tuy nhiên, hàm này không thuộc public API, tương tự `xpc_connection_get_audit_token`.
- **Chưa có cách sửa lỗi tổng quát hơn**: Chưa rõ vì sao Apple không đưa ra cách sửa toàn diện hơn, chẳng hạn loại bỏ các messages không khớp với audit token đã lưu của connection. Một nguyên nhân có thể là trong một số trường hợp (ví dụ, sử dụng `setuid`), audit token có thể thay đổi hợp lệ.
- **Tình trạng hiện tại**: Vấn đề vẫn tồn tại trên iOS 17 và macOS 14, gây khó khăn cho những người muốn xác định và tìm hiểu vấn đề này.<sup>[[1]](#references)</sup>

## Tìm các code paths dễ bị tấn công trong thực tế (2024–2025)

Khi kiểm tra các XPC services để tìm nhóm lỗi này, hãy tập trung vào việc kiểm tra quyền được thực hiện bên ngoài event handler của message hoặc đồng thời với quá trình xử lý reply.

Gợi ý phân loại tĩnh:
- Tìm các lời gọi `xpc_connection_get_audit_token` có thể được thực thi từ các blocks được đưa vào hàng đợi thông qua `dispatch_async`/`dispatch_after` hoặc các worker queues khác chạy bên ngoài message handler.
- Tìm các hàm kiểm tra quyền kết hợp trạng thái theo connection và theo message (ví dụ: lấy PID từ `xpc_connection_get_pid` nhưng lấy audit token từ `xpc_connection_get_audit_token`).
- Với NSXPC code, hãy xác minh rằng các bước kiểm tra được thực hiện trong `-listener:shouldAcceptNewConnection:` hoặc, với các bước kiểm tra theo từng message, implementation sử dụng audit token theo từng message (ví dụ: dictionary của message thông qua `xpc_dictionary_get_audit_token` trong lower-level code).

Mẹo phân loại động:
- Hook `xpc_connection_get_audit_token` và đánh dấu các lời gọi có user stack không chứa đường đi xử lý event (ví dụ: `_xpc_connection_mach_event`). Ví dụ Frida hook:

```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
  onEnter(args) {
    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).join('\n');
    if (!bt.includes('_xpc_connection_mach_event')) {
      console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
    }
  }
});
```

Ghi chú:
- Trên macOS, việc instrument các binary được bảo vệ/của Apple có thể yêu cầu tắt SIP hoặc sử dụng môi trường phát triển; nên ưu tiên kiểm thử các bản build của chính bạn hoặc các dịch vụ userland.
- Đối với các race condition chuyển tiếp phản hồi (Variant 2), hãy theo dõi việc phân tích đồng thời các gói phản hồi bằng cách fuzz thời điểm gọi `xpc_connection_send_message_with_reply` so với các request thông thường, rồi kiểm tra xem audit token hiệu lực được dùng trong quá trình authorization có thể bị ảnh hưởng hay không.

## Các primitive khai thác có thể bạn sẽ cần

- Thiết lập nhiều sender (Variant 1): tạo kết nối đến A và B; duplicate send right của client port của A và dùng nó làm client port của B để các phản hồi của B được chuyển đến A.

```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```

- Reply hijack (Variant 2): chiếm send-once right từ request đang chờ của A (reply port), sau đó gửi một message được tạo thủ công đến B bằng reply port đó để phản hồi của B đến A trong khi request có privileged của bạn đang được phân tích.

Các cách này yêu cầu tạo message mach cấp thấp cho định dạng bootstrap và message của XPC; hãy xem lại các trang giới thiệu về mach/XPC trong phần này để biết chính xác bố cục packet và các flag.

## Công cụ hữu ích

- XPC sniffing/kiểm tra động: gxpc (XPC sniffer mã nguồn mở) có thể giúp liệt kê các kết nối và quan sát traffic để xác thực thiết lập multi-sender và thời điểm. Ví dụ: `gxpc -p <PID> --whitelist <service-name>`.
- Kỹ thuật interposing dyld cổ điển cho libxpc: interpose vào `xpc_connection_send_message*` và `xpc_connection_get_audit_token` để ghi lại các vị trí gọi và stack trong quá trình kiểm thử black-box.



## References

- [1] [Sector 7 – Đừng nói cùng lúc! Nâng cao đặc quyền trên macOS bằng cách giả mạo Audit Token](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – Giới thiệu về nội dung bảo mật của macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)
{{#include ../../../../../../banners/hacktricks-training.md}}

