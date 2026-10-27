# Khai thác Kernel Race Condition thông qua các Slow Path của Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Vì sao việc kéo dài race window lại quan trọng

Nhiều lỗ hổng LPE trong Windows kernel tuân theo mẫu kinh điển `check_state(); NtOpenX("name"); privileged_action();`. Trên phần cứng hiện đại, một lệnh `NtOpenEvent`/`NtOpenSection` khi cache chưa nóng chỉ mất khoảng 2 µs để phân giải một tên ngắn, gần như không để lại thời gian để thay đổi trạng thái đã kiểm tra trước khi hành động bảo vệ được thực hiện. Bằng cách cố ý khiến bước 2, quá trình tra cứu trong Object Manager Namespace (OMNS), mất hàng chục micro giây, kẻ tấn công có đủ thời gian để thắng các race vốn khó ổn định, mà không cần thử hàng nghìn lần.<sup>[[1]](#references)</sup>

## Tóm lược nội bộ quá trình tra cứu của Object Manager

* **Cấu trúc OMNS** – Các tên như `\BaseNamedObjects\Foo` được phân giải lần lượt theo từng thư mục. Mỗi thành phần khiến kernel tìm/mở một *Object Directory* và so sánh các chuỗi Unicode. Các symbolic link (ví dụ: ký tự ổ đĩa) có thể được duyệt qua trên đường phân giải.
* **Giới hạn UNICODE_STRING** – Các đường dẫn OM được lưu trong một `UNICODE_STRING`, có trường `Length` dài 16 bit. Giới hạn tuyệt đối là 65 535 byte (32 767 codepoint UTF-16). Với các tiền tố như `\BaseNamedObjects\`, kẻ tấn công vẫn kiểm soát được khoảng 32 000 ký tự.
* **Điều kiện tiên quyết của kẻ tấn công** – Bất kỳ người dùng nào cũng có thể tạo object bên dưới các thư mục cho phép ghi, chẳng hạn `\BaseNamedObjects`. Khi mã dễ bị tấn công sử dụng tên bên trong thư mục này, hoặc đi theo một symbolic link dẫn đến đó, kẻ tấn công có thể kiểm soát hiệu năng tra cứu mà không cần đặc quyền đặc biệt.<sup>[[1]](#references)</sup>

## Primitive làm chậm #1 – Một component có độ dài tối đa

Chi phí phân giải một component gần như tuyến tính theo độ dài của nó, vì kernel phải so sánh Unicode với từng entry trong thư mục cha. Tạo một event có tên dài 32 kB ngay lập tức làm tăng độ trễ của `NtOpenEvent` từ khoảng 2 µs lên khoảng 35 µs trên Windows 11 24H2 (môi trường thử nghiệm Snapdragon X Elite).

```cpp
std::wstring path;
while (path.size() <= 32000) {
    auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
    printf("%zu,%f\n", path.size(), result);
    path += std::wstring(500, 'A');
}
```

*Ghi chú thực tế*

- Bạn có thể đạt giới hạn độ dài bằng bất kỳ kernel object có tên nào (events, sections, semaphores…).
- Symbolic links hoặc reparse points có thể trỏ một tên “victim” ngắn đến thành phần khổng lồ này, nhờ đó áp dụng slowdown một cách trong suốt.
- Vì mọi thứ đều nằm trong các namespace mà người dùng có thể ghi, payload hoạt động ở mức integrity tiêu chuẩn của người dùng.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Thư mục đệ quy sâu

Một biến thể mạnh hơn tạo ra một chuỗi hàng nghìn thư mục (`\BaseNamedObjects\A\A\...\X`). Mỗi bước đều kích hoạt logic phân giải thư mục (kiểm tra ACL, tra cứu hash, đếm reference), vì vậy độ trễ mỗi cấp cao hơn so với việc chỉ so sánh một chuỗi đơn lẻ. Với khoảng 16 000 cấp (bị giới hạn bởi cùng kích thước `UNICODE_STRING`), thời gian đo được vượt ngưỡng 35 µs mà các thành phần đơn dài đạt được.

```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
    dirs.emplace_back(CreateDirectory(L"A", last_dir));
    last_dir = dirs.back().get();
    if ((i % 500) == 0) {
        auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
        printf("%d,%f\n", i + 1, result);
    }
}
```

Tips:

* Thay phiên ký tự ở mỗi cấp (`A/B/C/...`) nếu thư mục cha bắt đầu từ chối các tên trùng lặp.
* Giữ một mảng handle để có thể xóa chuỗi liên kết gọn gàng sau khi khai thác, tránh làm ô nhiễm namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (phút thay vì microsecond)

Object directories hỗ trợ **shadow directories** (fallback lookups) và các hash table phân nhóm bucket cho entry. Lạm dụng cả hai cùng giới hạn reparse 64 thành phần của symbolic link để tăng độ trễ mà không vượt quá độ dài `UNICODE_STRING`:

1. Tạo hai thư mục dưới `\BaseNamedObjects`, ví dụ `A` (shadow) và `A\A` (target). Tạo thư mục thứ hai với thư mục thứ nhất làm shadow directory (`NtCreateDirectoryObjectEx`), để các lookup không tìm thấy trong `A` chuyển tiếp sang `A\A`.
2. Điền vào mỗi thư mục hàng nghìn **tên va chạm** cùng rơi vào một hash bucket (ví dụ, thay đổi các chữ số ở cuối nhưng giữ nguyên giá trị `RtlHashUnicodeString`). Lookup lúc này suy giảm thành quét tuyến tính O(n) bên trong một thư mục.
3. Tạo chuỗi khoảng 63 **object manager symbolic link** liên tục reparse vào hậu tố `A\A\…` dài, tiêu tốn ngân sách reparse. Mỗi lần reparse khởi động lại quá trình phân tích từ đầu, nhân chi phí va chạm lên nhiều lần.
4. Lookup thành phần cuối (`...\\0`) hiện mất **vài phút** trên Windows 11 khi mỗi thư mục có 16 000 va chạm, giúp gần như chắc chắn thắng race trong các kernel LPE chỉ có một lần thử.

```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```

*Vì sao điều này quan trọng*: Việc làm chậm kéo dài vài phút biến các LPE dựa trên race chỉ dùng được một lần thành exploit có tính xác định.<sup>[[1]](#references)</sup>

### Ghi chú retest năm 2025 & công cụ có sẵn

- James Forshaw đã đăng lại kỹ thuật này cùng các mốc thời gian được cập nhật trên Windows 11 24H2 (ARM64). Các thao tác mở cơ bản vẫn mất khoảng 2 µs; một thành phần 32 kB tăng thời gian này lên khoảng 35 µs, còn chuỗi shadow-dir + collision + 63-reparse vẫn đạt khoảng 3 phút, xác nhận các primitive vẫn hoạt động trên những bản build hiện tại. Mã nguồn và bộ công cụ đo hiệu năng nằm trong bài đăng Project Zero đã được cập nhật.<sup>[[1]](#references)</sup>
- Bạn có thể viết script thiết lập bằng gói `symboliclink-testing-tools` công khai: dùng `CreateObjectDirectory.exe` để tạo cặp shadow/target và chạy `NativeSymlink.exe` trong vòng lặp để tạo chuỗi 63 bước nhảy. Cách này tránh phải tự viết wrapper `NtCreate*` và giúp ACL nhất quán.<sup>[[2]](#references)</sup>

## Đo race window

Nhúng một bộ công cụ đo nhanh vào exploit để đo độ dài của window trên phần cứng máy nạn nhân. Đoạn mã bên dưới mở object đích `iterations` lần và trả về thời gian trung bình cho mỗi lần mở bằng `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>

```cpp
static double RunTest(const std::wstring name, int iterations,
        std::wstring create_name = L"", HANDLE root = nullptr) {
    if (create_name.empty()) {
        create_name = name;
    }
    ScopedHandle event_handle = CreateEvent(create_name, root);
    ObjectAttributes obja(name);
    std::vector<ScopedHandle> handles;
    Timer timer;
    for (int i = 0; i < iterations; ++i) {
        HANDLE open_handle;
        Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
        handles.emplace_back(open_handle);
    }
    return timer.GetTime(iterations);
}
```

Kết quả được đưa trực tiếp vào chiến lược điều phối race của bạn (ví dụ: số worker thread cần thiết, khoảng thời gian sleep, thời điểm sớm nhất bạn cần chuyển trạng thái dùng chung).

## Quy trình khai thác

1. **Xác định open dễ bị tổn thương** – Lần theo đường đi trong kernel (qua symbols, ETW, hypervisor tracing hoặc reverse) cho đến khi bạn tìm thấy lời gọi `NtOpen*`/`ObOpenObjectByName` duyệt qua một tên do attacker kiểm soát hoặc symbolic link trong thư mục có quyền ghi của user.
2. **Thay tên đó bằng một đường dẫn chậm**
   - Tạo component dài hoặc chuỗi thư mục bên dưới `\BaseNamedObjects` (hoặc một OM root khác có quyền ghi).
   - Tạo symbolic link để tên mà kernel mong đợi giờ phân giải thành đường dẫn chậm. Bạn có thể trỏ thao tác tra cứu thư mục của vulnerable driver đến cấu trúc của mình mà không cần chạm vào target ban đầu.
3. **Kích hoạt race**
   - Thread A (victim) thực thi đoạn code dễ bị tổn thương và bị chặn bên trong thao tác tra cứu chậm.
   - Thread B (attacker) chuyển trạng thái được bảo vệ (ví dụ: hoán đổi file handle, viết lại symbolic link, bật/tắt security của object) trong khi Thread A đang bận.
   - Khi Thread A tiếp tục và thực hiện thao tác có đặc quyền, nó thấy trạng thái cũ và thực hiện thao tác do attacker kiểm soát.
4. **Dọn dẹp** – Xóa chuỗi thư mục và symbolic link để tránh để lại dấu vết đáng ngờ hoặc làm gián đoạn các user IPC hợp lệ.<sup>[[1]](#references)</sup>

## Chuỗi khai thác áp dụng: Cloud Files placeholder có thể thay đổi + chuyển hướng đường dẫn Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), được công bố như một cách bypass RoguePlanet (CVE-2026-50656), minh họa một mô hình khai thác rộng hơn: khiến một scanner có đặc quyền phân loại một dạng biểu diễn của file logic, rồi thay đổi cả byte của file lẫn cách phân giải namespace trước khi remediation sử dụng file đó. PoC kết hợp TOCTOU trong Cloud Files hydration, cơ chế dự phòng shadow-directory của Object Manager, việc bắt tên do CLFS tạo ra và một link đến administrative share cục bộ để biến thao tác dọn dẹp của Defender thành một lần ghi DLL được bảo vệ.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Thay nội dung thông qua Cloud Files hydration

Đăng ký một thư mục do attacker ghi được làm Cloud Files sync root, kết nối callback `CF_CALLBACK_TYPE_FETCH_DATA` và tạo một placeholder có kích thước được quảng bá khớp với một trigger phát hiện xác định, chẳng hạn như EICAR ZIP. Lần fetch đầu tiên trả về trigger và chuyển trạng thái callback; các lần fetch sau trả về payload. Sau khi scanner phân loại dạng biểu diễn đầu tiên, lấy transfer key và khởi động lại hydration với metadata có kích thước bằng payload, rồi buộc hydration chạy đến EOF.<sup>[[4]](#references)</sup>

```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```

Ranh giới bảo mật thất bại nếu quá trình quét, kết luận và khắc phục chỉ tham chiếu đến một pathname hoặc danh tính placeholder: không yếu tố nào đảm bảo rằng lần hydration sau đó sẽ trả về đúng các byte đã được kiểm tra.<sup>[[4]](#references)</sup>

### 2. Chuyển một đường dẫn bất biến qua cơ chế dự phòng shadow-directory

Tạo một thư mục Object Manager đích và một thư mục thứ hai bằng `NtCreateDirectoryObjectEx`, truyền handle của thư mục đích làm thư mục shadow/fallback. Thêm một mục `WD_SCAN` cùng tên vào cả hai lớp phân giải: mục hiển thị trỏ đến thư mục làm việc thông thường, còn mục dự phòng trỏ đến `\CLFS\??\<working-directory>`. Chỉ cung cấp cho Defender đường dẫn bất biến bên dưới; xóa liên kết hiển thị khi thao tác đang diễn ra sẽ khiến cùng một chuỗi đường dẫn chuyển sang mục được CLFS hỗ trợ.<sup>[[4]](#references)</sup>

```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```

Điều này khác với việc chỉ sử dụng shadow directories để làm chậm quá trình tra cứu: attacker thay đổi **ý nghĩa** của một path đã được chấp nhận trước đó mà không sửa chuỗi của nó.<sup>[[4]](#references)</sup>

### 3. Bắt tên được tạo và cài đặt link dành riêng cho filename

Theo dõi working directory bằng `ReadDirectoryChangesW`. Khi nhận được `FILE_ACTION_ADDED` đầu tiên, xóa link `WD_SCAN` hiển thị để kích hoạt fallback lookup. Bắt filename được tạo thứ hai, mở file liên quan đến CLFS đó và khóa phạm vi `0..MAXLONGLONG` bằng `LockFileEx`. Trong khi thao tác có đặc quyền bị đình trệ, thay `WD_SCAN` trong directory hiển thị bằng một directory Object Manager thực và tạo một symbolic link con có tên lấy từ filename đã quan sát được (PoC loại bỏ bốn ký tự cuối). Trỏ nó đến destination được bảo vệ thông qua SMB cục bộ:<sup>[[4]](#references)</sup>

```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```

Tiến trình không có đặc quyền không thể tự ghi vào đích đó, nhưng ngữ cảnh SYSTEM của Defender có thể truy cập qua administrative share loopback. Kết hợp việc quan sát tên được tạo với một Object Manager link dành riêng cho tên tệp giúp không phải dự đoán trước artifact khắc phục.<sup>[[4]](#references)</sup>

### 4. Ổn định race cleanup và kích hoạt privileged loader

Trước khi quét, PoC lưu một PE hợp lệ (`ntdll.dll`) trong NTFS alternate data stream `:stream` của placeholder. Sau khi redirection tạo tệp cơ sở được bảo vệ, nó mở `phoneinfo.dll:stream` với quyền thực thi và giữ mapping `PAGE_EXECUTE_READ | SEC_IMAGE` tồn tại trong khi cleanup tiếp tục; các file/section object đang hoạt động hạn chế việc xóa hoặc thay thế trong race cuối cùng. Quá trình hydration được khởi động lại giờ trả về payload DLL thay vì EICAR, vì vậy tệp cơ sở được bảo vệ chứa mã do attacker kiểm soát.<sup>[[4]](#references)</sup>

Sau đó, một thao tác ghi được bảo vệ được chuyển thành thực thi SYSTEM bằng cách đặt một `Report.wer` được tạo thủ công trong `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` và gọi `\Microsoft\Windows\Windows Error Reporting\QueueReporting` thông qua Task Scheduler COM API. Trong chuỗi này, WER xử lý với đặc quyền cao và nạp `C:\Windows\System32\phoneinfo.dll` đã được cài cắm; kết nối named pipe được dùng làm tín hiệu thực thi payload.<sup>[[4]](#references)</sup>

### Các điểm pivot để phát hiện

Các tương quan hữu ích cụ thể hơn bất kỳ tên tệp tạm thời đơn lẻ nào và bao quát mọi lần chuyển đổi namespace trong chuỗi:<sup>[[4]](#references)</sup>

- Cloud Files provider mới được đăng ký, sau đó là phát hiện EICAR và `CF_OPERATION_TYPE_RESTART_HYDRATION` trên cùng placeholder.
- Các đường dẫn Object Manager chứa `WD_TARGET_*`, `WD_SHADOW_*` hoặc `WD_SCAN`, đặc biệt là đường dẫn quét bên dưới `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Tạo tệp CLFS, sau đó khóa toàn bộ tệp ở chế độ độc quyền và truy cập loopback vào `\\127.0.0.1\C$\Windows\System32\*.dll` từ một tiến trình bảo mật có đặc quyền.
- Tạo DLL trong System32 cùng với NTFS ADS, sau đó mapping stream bằng `SEC_IMAGE`.
- Tạo mục WER queue bởi attacker, sau đó chạy thủ công bất thường `\Microsoft\Windows\Windows Error Reporting\QueueReporting` và nạp image của DLL đã cài cắm.

## Chuỗi áp dụng: chuyển mount point được điều khiển bằng oplock nhắm vào quá trình khắc phục có đặc quyền

Một mẫu LPE có thể tái sử dụng xuất hiện khi scanner có đặc quyền kiểm tra tệp do attacker kiểm soát, rồi khắc phục bằng cách mở lại **pathname** thay vì tiếp tục dùng các handle đã xác thực. FalconFlank là ví dụ công khai nhắm vào workflow xóa macro Office của CrowdStrike Falcon; repository tuyên bố đã thử nghiệm trên Windows 11 25H2 và Windows Server 2025 khi bật policy liên quan, nhưng không công bố CVE, phạm vi build bị ảnh hưởng, tư vấn từ nhà cung cấp hoặc trạng thái bản vá. Vì vậy, hãy xem tuyên bố liên quan đến sản phẩm là chưa được xác minh và phụ thuộc vào build.<sup>[[5]](#references)[[6]](#references)</sup>

### Bố trí race

1. Tạo một cây thư mục có thể ghi với tên tương đối cuối cùng phù hợp với đích dự định. Ví dụ sử dụng `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, nhưng ban đầu ghi tài liệu macro OLE—không phải DLL PE—vào `bcrypt.dll`. Phát hiện dựa trên nội dung kích hoạt quá trình khắc phục trong khi basename do attacker kiểm soát vẫn được giữ nguyên để side-load sau đó.<sup>[[5]](#references)</sup>
2. Mở các thư mục với chế độ chia sẻ rộng và `FILE_OPEN_REPARSE_POINT`, sau đó yêu cầu RH oplock bất đồng bộ trên trigger bằng `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` và `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Chờ overlapped event và dùng thời điểm hoàn tất làm tín hiệu chuyển đường dẫn. Thông báo RH oplock-break chỉ mang tính cảnh báo, không chứng minh rằng mọi thao tác xung đột đều bị chặn; do đó, khả năng khai thác vẫn phụ thuộc vào chính xác chuỗi mở/khắc phục của tiến trình nạn nhân.<sup>[[5]](#references)[[7]](#references)</sup>
3. Sau break, xóa thư mục lá bằng `FileDispositionInformationEx` (information class 64) với các cờ xóa và POSIX semantics, đóng handle của nó rồi áp dụng `IO_REPARSE_TAG_MOUNT_POINT` lên thư mục cha hiện đã trống bằng `FSCTL_SET_REPARSE_POINT_EX`. Mount point chuyển hướng phần hậu tố không đổi vào cây được bảo vệ như `\\SystemRoot\\System32\\WindowsPowerShell`; việc đặt reparse point sẽ thất bại nếu thư mục không trống, điều này giải thích bước xóa trước đó.<sup>[[5]](#references)[[8]](#references)</sup>
4. Tiếp tục workflow có đặc quyền. Nếu workflow phân giải lại chuỗi mà không xác minh rằng chuỗi thư mục và object cuối cùng chính là những gì đã được kiểm tra trước đó, cùng pathname logic giờ sẽ trỏ đến thư mục được bảo vệ do attacker chọn. Trong ví dụ, thành công được kiểm tra bằng cách mở lại `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` với quyền đọc/ghi từ tiến trình ban đầu; việc này phân biệt primitive ghi confused-deputy với giai đoạn thực thi mã sau đó.<sup>[[5]](#references)</sup>
5. Thay tệp kết quả bằng DLL thật và kích hoạt privileged loader. PoC dùng `CreateTransaction` + `CreateFileTransacted`, truncate tệp, map phần thay thế có kích thước DLL, sao chép PE rồi commit; TxF gắn file handle và các thao tác tiếp theo dựa trên handle với transaction, nhưng đây là cơ chế thay thế sau race chứ không phải nguyên nhân gây lỗi ranh giới đặc quyền.<sup>[[5]](#references)[[9]](#references)</sup>
6. Cuối cùng, chạy một scheduled task có đặc quyền sẵn có, với executable kiểm tra tên tệp liền kề đã được cài cắm. FalconFlank gọi `\\Microsoft\\Windows\\Application Experience\\MareBackup`, chờ DLL kết nối đến `\\??\\pipe\\FALCONFLANK`, rồi xóa tệp đã cài cắm. Không nên chỉ dựa vào tên task để giả định token thu được—hãy xác minh tiến trình được khởi chạy, module path, integrity level và token trên build đã thử nghiệm.<sup>[[5]](#references)</sup>

Do đó, câu hỏi cốt lõi khi audit không phải là “service có xác thực đường dẫn đầu vào ban đầu không?” mà là “mọi thao tác thay đổi có đặc quyền có luôn gắn với cùng file và directory object đã mở mà quá trình xác thực đã kiểm tra không?” Giữ handle xuyên suốt quá trình kiểm tra và sử dụng, mở object con tương đối với handle thư mục đáng tin cậy, từ chối reparse tag bất ngờ và xác thực lại danh tính tệp trước khi thay đổi sẽ khắc phục nhóm lỗi thay thế pathname này.<sup>[[1]](#references)[[8]](#references)</sup>

### Phát hiện và phân loại PoC

Phát hiện có tín hiệu cao sẽ tương quan quá trình chuyển đổi namespace với thành phần có đặc quyền sử dụng nó: header OLE dưới basename DLL trong cây tạm thời có tên GUID, oplock break, xóa thư mục lá theo kiểu POSIX, tạo mount point nhắm đến thư mục Windows được bảo vệ, và tạo hoặc sửa đổi cùng basename bên dưới đích đó. Với ví dụ công khai, hãy bổ sung `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, việc chạy thủ công `MareBackup` và named pipe `FALCONFLANK` làm các điểm pivot cụ thể hơn; không dấu hiệu nào trong số này đủ để kết luận nếu đứng riêng.<sup>[[5]](#references)</sup>

Khi tái hiện PoC, cần lưu ý ba lỗi về độ tin cậy trong source đã công bố: nó gọi `FlushFileBuffers` với con trỏ byte-array nhúng thay vì file handle, kiểm tra `HRESULT` đã cũ sau `GetFolder`, `GetTask` và `Run`, đồng thời dùng các vòng lặp retry/wait không giới hạn để xóa thư mục, tạo reparse point, chờ oplock event và kết nối pipe.<sup>[[5]](#references)</sup>

## Các lưu ý vận hành

- **Kết hợp primitive** – Có thể dùng tên dài *ở mỗi cấp* trong chuỗi thư mục để tăng độ trễ hơn nữa, cho đến khi đạt giới hạn kích thước `UNICODE_STRING`.
- **Lỗi chỉ kích hoạt một lần** – Cửa sổ thời gian được mở rộng (từ hàng chục microsecond đến hàng phút) khiến các lỗi “single trigger” trở nên khả thi khi kết hợp với ghim CPU affinity hoặc preemption có hỗ trợ hypervisor.
- **Tác dụng phụ** – Việc làm chậm chỉ ảnh hưởng đến đường dẫn độc hại, vì vậy hiệu năng toàn hệ thống không bị ảnh hưởng; defender hiếm khi nhận thấy trừ khi họ giám sát sự tăng trưởng namespace.
- **Dọn dẹp** – Giữ handle đến mọi thư mục/object bạn tạo để có thể gọi `NtMakeTemporaryObject`/`NtClose` sau đó. Nếu không, các chuỗi thư mục không giới hạn có thể tồn tại qua các lần khởi động lại.
- **Race hệ thống tệp** – Nếu đường dẫn dễ bị tấn công cuối cùng được phân giải qua NTFS, bạn có thể đặt Oplock (ví dụ `SetOpLock.exe` từ cùng toolkit) lên tệp nền trong khi OM slowdown đang chạy, làm đóng băng thành phần sử dụng thêm vài millisecond mà không thay đổi OM graph.<sup>[[2]](#references)</sup>

## Ghi chú phòng thủ

- Code kernel dựa vào named object nên xác thực lại trạng thái nhạy cảm về bảo mật *sau khi* mở object, hoặc lấy reference trước khi kiểm tra (khép lại khoảng trống TOCTOU).
- Áp đặt giới hạn trên cho độ sâu/độ dài OM path trước khi dereference tên do người dùng kiểm soát. Từ chối tên quá dài buộc attacker quay lại cửa sổ microsecond.
- Theo dõi sự tăng trưởng namespace của Object Manager (ETW `Microsoft-Windows-Kernel-Object`) để phát hiện các chuỗi gồm hàng nghìn thành phần đáng ngờ bên dưới `\BaseNamedObjects`.

## References

- [1] [Project Zero – Kỹ thuật khai thác Windows: Thắng race condition bằng tra cứu đường dẫn](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Cách sử dụng Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
