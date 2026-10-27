# Tự động hóa WinDbg để đo đạc có mục tiêu

{{#include ../../banners/hacktricks-training.md}}

WinDbg và WinDbgX có thể chạy các lệnh debugger khi khởi động, khi xảy ra ngoại lệ và khi breakpoint được kích hoạt. Nhờ đó, phiên fuzzing hoặc reversing có thể chỉ thu thập trạng thái quanh một đường dẫn do input điều khiển, thay vì phải dừng thủ công tại mọi sự kiện.<sup>[[1]](#references)</sup>

## Bắt đầu tại một ngoại lệ hữu ích

`-c` chạy các lệnh tại điểm dừng đầu tiên của debugger. Thêm `;g` để tiếp tục sau khi thiết lập. Với một phiên WinDbg Classic không cần giám sát, `-logo` ghi cửa sổ lệnh vào tệp log, `-Q` tắt tính năng tự động lưu workspace và `-G` bỏ qua breakpoint cuối cùng để phiên kết thúc khi target thoát. WinDbgX cũng chấp nhận `-c`; các lệnh Startup đã cấu hình sẽ chạy sau đó.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Đối với lỗi truy cập, **`sxe av` dừng ở first chance**, **`sxd av` bỏ qua first chance nhưng dừng ở second chance nếu ngoại lệ chưa được xử lý**, còn **`sxi av` bỏ qua cả hai lần**. Mô tả `sxi`/`sxd` trong bài viết bị đảo ngược: Microsoft ghi rõ `sxd` là bộ lọc cho second chance, còn `sxi` là bỏ qua. Dùng `-c` cho lệnh xử lý ở first chance và `-c2` cho lệnh xử lý ở second chance; trình xử lý `-c` ở first chance không trở thành trình xử lý ở second chance chỉ vì bộ lọc là `sxd`. Xác nhận các bộ lọc đang hoạt động bằng `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

Lệnh đầu tiên thu thập các thanh ghi, stack trace và phân tích ngoại lệ chỉ khi xảy ra access violation chưa được xử lý. Lệnh thứ hai chạy `lm` khi một module được tải. Các sự kiện breakpoint (`bp`), tải module (`ld`) và access violation (`av`) có vòng đời khác nhau, vì vậy đừng bỏ qua toàn cục `bp` nếu đang dựa vào breakpoint của debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Kích hoạt breakpoint tốn kém bằng trigger có kiểm soát

Chọn một hàm có thể được script gọi hoặc được kiểm soát bằng input theo cách khác, để gọi ngay trước luồng cần quan sát. Đặt **action breakpoint** tại các lệnh gọi allocator, parser hoặc API cần kiểm tra. Vô hiệu hóa chúng bằng ID với `bd`. Đặt một **trigger breakpoint** có lệnh đính kèm để bật các ID đó bằng `be`, rồi tiếp tục bằng `g`; một trigger có kiểm soát thứ hai có thể vô hiệu hóa chúng lại. Kiểm tra ID bằng `bl` trước khi thiết lập trigger, vì ID phụ thuộc vào thứ tự tạo breakpoint. Cách này tách các điểm điều khiển nhẹ khỏi việc trace tốn kém, đồng thời hạn chế ảnh hưởng đến thời gian chạy và bố cục heap của mục tiêu.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Sau khi phân giải hai symbol, mẫu lệnh như bên dưới. Thay các symbol trong ngoặc vuông và ID của action breakpoint do `bl` trả về; đừng cho rằng ID đó là 0.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Các lệnh action breakpoint có thể in `@$ip` và `%y` (địa chỉ đã phân giải symbol), dump các đối số được chọn hoặc bộ nhớ, rồi tiếp tục. Nếu breakpoint có điều kiện chỉ ghi log các con trỏ trong một phạm vi đã chọn, hãy xác minh trước rằng phạm vi đó thực sự bao phủ đầu vào thử nghiệm; điều kiện sai sẽ âm thầm làm mất bằng chứng.<sup>[[1]](#references)</sup>

### Tìm trigger bằng symbol

Tìm kiếm trong tất cả module đã tải nếu chưa biết module triển khai. `bm` đặt breakpoint trên mọi symbol khớp; hãy gọi hàm có thể truy cập qua script và kiểm tra breakpoint nào được kích hoạt. Ví dụ, mã nguồn gọi `Math.cos(0)` trong renderer đang được debug, chứ không phải bất kỳ tiến trình trình duyệt nào.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Khi một hit xác định được chính xác function, dùng `lm a <symbol>` để tìm image chứa function đó và `? <symbol> - <module>` để tính offset tương đối với module. WinDbg có thể hiển thị cùng một tên module ngắn cho executable và DLL, vì vậy hãy xác minh đường dẫn image trước khi dùng offset trong một process khác. Thu hẹp các wildcard breakpoint thành symbol đã xác minh để tránh overhead.<sup>[[1]](#references)</sup>

### Tìm ứng viên khi không có symbol

`corelan_trigscan.py` dựa trên Frida của Corelan quét một module process đã chọn để tìm các mẫu lệnh dấu phẩy động, SSE, AVX và lượng giác. Công cụ xuất các lệnh breakpoint của WinDbg vào `corelan_trigscan.bps` và các tệp `.bps` được đánh số, nhỏ hơn. Chạy công cụ bằng Python và `frida-tools` trên target **khi không có debugger nào khác được gắn vào**; sau đó attach WinDbg vào cùng process/module và nạp một batch breakpoint có kích thước phù hợp.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Với một offset tương đối với module đã biết, hãy xác thực rằng nó vẫn vượt qua các ngưỡng trước khi nhập tất cả breakpoint được xuất ra:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` là mật độ instruction liên quan, `--min-relevant` và `--min-total` đặt ngưỡng tối thiểu về số lượng instruction, còn `--min-trig` yêu cầu các tín hiệu giống trig mạnh. Nếu bỏ sót một function đã biết, hãy truyền độ lệch tương đối với module của function đó vào `--check-offset` để kiểm tra prologue, mật độ, số lượng và các lời gọi gián tiếp. Một wrapper mỏng có thể có mật độ thấp và không có instruction trig. Hạ các ngưỡng xuống và nếu đang tìm wrapper, hãy dùng tùy chọn `--min-icall 1` thực tế của script (không phải `--min-ical`); các hàm được gọi trực tiếp sẽ được phân tích, nhưng không thể lần theo các target gián tiếp một cách đáng tin cậy. Các batch `--splitsize` nhỏ hơn sẽ hữu ích khi có nhiều breakpoint được tạo khiến WinDbg chạy chậm. Candidate chưa được xác nhận cho đến khi input dự kiến khiến breakpoint của nó được kích hoạt.<sup>[[1]](#references)[[6]](#references)</sup>

## Small debugger programs and PyKD

Dùng `.if` khi điều kiện đáng tin cậy, `.foreach` để lặp qua output phân tách bằng khoảng trắng và `.for` cùng pseudo-registers để duyệt bộ nhớ hoặc cấu trúc. `.foreach` **không** giữ nguyên các cột: chẳng hạn, output `lm` có độ rộng biến thiên là input không phù hợp, trong khi `lm 1m` tạo ra một tên module trên mỗi token. Trước tiên, hãy log dữ liệu chưa lọc nếu một điều kiện phỏng đoán có thể che khuất đường dẫn gây lỗi.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliases được tạo bằng `as name value` là các phép thay thế văn bản, không phải biến có kiểu. `al` liệt kê các alias, `ad name` xóa một alias, còn `${name}` buộc mở rộng rõ ràng. Tránh các tên như `bp`, `x` hoặc `r` vì alias có thể che khuất lệnh dựng sẵn. Biểu thức MASM phù hợp với phép tính con trỏ như `poi(@$t0)`; `@@c++(...)` có thể truy cập các trường có kiểu khi có symbol, tránh phải hard-code offset của cấu trúc.<sup>[[1]](#references)</sup>

Đặt các chuỗi lệnh dài hơn trong một tệp lệnh. `$$><filename` nối các dòng thành một khối lệnh duy nhất và cho phép thêm một lệnh debugger được phân tách bằng dấu chấm phẩy. Các cấu trúc điều khiển nhiều dòng vẫn có thể không ổn định; hãy viết mỗi câu lệnh `.if` hoặc `.for` trên một dòng. Có thể gọi cùng tệp đó bằng `-c` khi khởi động.<sup>[[1]](#references)[[8]](#references)</sup>

Với những logic khó viết bằng command language, PyKD cung cấp quyền truy cập các cấu trúc có kiểu, thanh ghi, bộ nhớ và đầu ra debugger từ Python. Ví dụ, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` truy cập các trường của PEB, `pykd.loadBytes(address, size)` đọc bộ nhớ, còn `pykd.dbgCommand("lm")` trả về đầu ra debugger để phân tích. Ưu tiên `loadChars`/`loadWChars` có giới hạn thay vì đọc chuỗi không giới hạn đối với dữ liệu có thể không kết thúc bằng ký tự kết thúc chuỗi. `disasm(address).asm(instruction)` của PyKD **ghi các byte mã máy tại địa chỉ đó**, vì vậy hãy lưu và khôi phục bộ nhớ ban đầu nếu dùng cách này để lấy opcode trong một tiến trình đang chạy.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Gỡ lỗi - Tự động hóa và viết script trong WinDBG(X) - Phần 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Thiết lập ngoại lệ)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Bật breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Tắt breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Đặt breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Mã nguồn trigscan của Corelan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Tùy chọn dòng lệnh WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Chạy tệp script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
