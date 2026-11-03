# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Nếu bạn có một pcap chứa giao tiếp USB của bàn phím như sau:

![USB Keystrokes: Nếu bạn có một pcap chứa giao tiếp USB của bàn phím như sau](<../../../images/image (962).png>)

Với bàn phím sử dụng **boot protocol** của HID, mỗi báo cáo Interrupt IN có bố cục cố định 8 byte: một byte modifier, một byte dự trữ và sáu byte keycode. Host so sánh các báo cáo liên tiếp và ánh xạ keycode sang HID usage để tái tạo các sự kiện phím.<sup>[[8]](#references)</sup>

Để phân loại sơ bộ dữ liệu capture nói chung, xem [Pcap Inspection](./).

## Kiến thức cơ bản về báo cáo USB HID

Báo cáo đầu vào bàn phím boot tiêu chuẩn có cấu trúc như sau.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Ý nghĩa |
| --- | --- |
| 0 | Bitmap modifier (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, v.v.). Có thể đặt nhiều bit cùng lúc. |
| 1 | Byte dự trữ; thông thường các báo cáo không sử dụng nên đặt byte này thành zero. Việc sử dụng riêng theo OEM hoặc hệ thống không có tính tương thích rộng. |
| 2-7 | Tối đa sáu keycode đồng thời ở định dạng USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` nghĩa là "không có phím nào". | 

Trong bố cục boot, usage ID `0x01` (`Keyboard ErrorRollOver`) được báo cáo ở tất cả các ô phím khi có hơn sáu phím không phải modifier được nhấn; nó cũng có thể báo hiệu một tổ hợp không thể nhận dạng.<sup>[[8]](#references)[[9]](#references)</sup> Hiểu bố cục này sẽ hữu ích khi bạn chỉ có các byte `usb.capdata` thô.

## Trích xuất dữ liệu HID từ PCAP

### Trước tiên, xác định giao diện bàn phím

Với các capture có nhiều lưu lượng, hãy xác định bàn phím HID trước khi dump các báo cáo. Điểm khởi đầu đáng tin cậy là phản hồi interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Lớp HID định nghĩa các giá trị giao diện sau:<sup>[[8]](#references)</sup>

- `subclass == 1` là Boot Interface Subclass; với `protocol == 1`, giá trị này xác định một bàn phím boot
- `protocol == 2` xác định một chuột boot
- `protocol == 0` nghĩa là không có boot protocol; hãy kiểm tra HID report descriptor thay vì mặc định rằng bố cục dài 8 byte

Giao diện hỗ trợ boot **không chứng minh rằng boot protocol đang hoạt động**. Thiết bị HID khởi tạo ở report protocol. Host chọn boot mode bằng `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` chọn report protocol. Nếu capture có quá trình enumeration, hãy kiểm tra request dành cho giao diện bàn phím (`wIndex`) trước khi dùng bộ giải mã boot tám byte. Nếu không có request này, hãy xác minh bố cục report quan sát được thay vì suy luận mode từ interface descriptor.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Once the interface is known, hãy cố định bộ lọc theo `usb.bus_id`, `usb.device_address` và, nếu có thể, `usb.bInterfaceNumber` trước khi xuất dữ liệu.

### Quy trình Wireshark

1. **Cô lập thiết bị**: lọc lưu lượng interrupt IN từ bàn phím, ví dụ: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Thêm các cột hữu ích**: nhấp chuột phải vào trường `Leftover Capture Data` (`usb.capdata`) và các trường `usbhid.*` bạn muốn (ví dụ: `usbhid.boot_report.keyboard.keycode_1`) để theo dõi các lần nhấn phím mà không cần mở từng frame.<sup>[[11]](#references)</sup>
3. **Ẩn các report trống**: áp dụng `!(usb.capdata == 00:00:00:00:00:00:00:00)` để loại bỏ các frame idle.
4. **Xuất dữ liệu để hậu xử lý**: `File -> Export Packet Dissections -> As CSV`, bao gồm `frame.number`, `usb.src`, `usb.capdata` và các trường modifier đã giải mã như `usbhid.boot_report.keyboard.modifier.left_shift` và `usbhid.boot_report.keyboard.modifier.right_alt` để viết script dựng lại dữ liệu sau đó.<sup>[[10]](#references)[[11]](#references)</sup>

### Quy trình dòng lệnh

Mẫu trích xuất kinh điển—xuất `usb.capdata`, loại bỏ các report idle và ánh xạ usage ID—xuất hiện trong bài phân tích gốc năm 2017 và hướng dẫn thực hành đi kèm.<sup>[[1]](#references)[[2]](#references)</sup>

Repository `ctf-usb-keyboard-parser` tự động hóa pipeline tshark + sed kinh điển:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Trong các bản ghi mới hơn, hãy ưu tiên trường `usbhid.data` đã được Wireshark giải mã và dùng `usb.capdata` làm phương án dự phòng; ghi một payload cho mỗi report vào tệp riêng cho từng thiết bị:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Các file riêng cho từng thiết bị có thể được đưa vào decoder sau khi chuẩn hóa định dạng hex mà decoder yêu cầu. Nếu capture đến từ bàn phím BLE được tunnel qua GATT, hãy lọc bằng `btatt.value && frame.len == 20` rồi dump payload hex trước khi giải mã.<sup>[[7]](#references)</sup>

### Khi report không phải là boot report 8 byte thông thường

Giao diện không phải boot hoặc report ID có thể làm thay đổi bố cục payload, vì vậy đừng cho rằng mọi keyboard report đều khớp với `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Ưu tiên `usbhid.data` hơn `usb.capdata` khi Wireshark đã phân tích lớp HID.
- Nếu mọi dòng đều bắt đầu bằng một prefix hoặc report ID cố định, hãy loại bỏ nó bằng decoder có xét offset thay vì cho rằng byte 0 luôn là modifier.<sup>[[7]](#references)</sup>
- Một số bản xuất USBPcap bỏ qua byte reserved, vì vậy decoder hỗ trợ `--no-reserved` hoặc offset tùy chỉnh sẽ giúp tiết kiệm thời gian.<sup>[[7]](#references)</sup>
- Nếu HID report descriptor hoặc BLE HOGP report map có trong capture, hãy dùng nó để khôi phục bố cục trường thực tế trước khi viết parser.

### Giải mã bitmap phím của report protocol

Với bàn phím có input report là bitmap thay vì sáu boot key slot, hãy tìm **HID report descriptor** trong lưu lượng enumeration. Bộ lọc này tìm các frame mà Wireshark đã giải mã được mục Report Size; hãy mở một frame và kiểm tra toàn bộ descriptor. Bắt đầu capture mới trước khi cắm bàn phím nếu không có descriptor trong capture.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Với mỗi báo cáo Input của bàn phím, hãy ghi lại `Report ID` (nếu có), `Usage Page` (`0x07` cho các phím bàn phím), `Usage Minimum/Maximum`, `Report Size`, `Report Count` và mỗi mục `Input` là **Variable** hay **Array**. Đếm tất cả các trường Input đứng trước và phần đệm hằng để tìm độ lệch bit của trường phím; các trường trong báo cáo không nhất thiết phải căn chỉnh theo byte. Trường Variable một bit với các usage bàn phím liên tiếp là bitmap trạng thái phím: bit 0 của trường tương ứng với usage đầu tiên được khai báo, bit 1 tương ứng với usage kế tiếp, v.v. Ngược lại, Array chứa các giá trị được phân giải theo dải usage của descriptor, chứ không phải mỗi bit ứng với một phím đang được nhấn. Nếu có khai báo Report ID, trước tiên hãy chọn các báo cáo có tiền tố đó và bỏ qua byte ID khi tính độ lệch trường. So sánh các tập usage đang được giữ giữa những báo cáo liên tiếp thuộc **cùng giao diện và Report ID** để chỉ xuất ra các lần nhấn mới.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Tự động hóa việc giải mã

- **ctf-usb-keyboard-parser** vẫn hữu ích cho các thử thách CTF nhanh và đã có sẵn trong repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) phân tích cả tệp `pcap` lẫn `pcapng` nguyên bản, hỗ trợ `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` và không cần tshark hay dependency bên ngoài nào khác, nên phù hợp với các sandbox biệt lập.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** bổ sung các công cụ trực quan hóa bàn phím, chuột và máy tính bảng. Bạn có thể chạy helper `extract_hid_data.sh` (backend tshark) hoặc `extract_hid_data.py` (backend scapy), rồi đưa tệp văn bản thu được vào decoder hoặc các module phát lại để xem các lần gõ phím diễn ra.<sup>[[7]](#references)</sup>

### Giải mã có trạng thái rất quan trọng

Bàn phím USB boot gửi báo cáo theo chu kỳ idle ngay cả khi không có sự kiện phím mới, vì vậy bản capture có thể chứa các báo cáo lặp lại trước sự kiện nhả phím. Một decoder thực tế nên:<sup>[[3]](#references)[[8]](#references)</sup>

- chỉ xuất ra các keycode mới được nhấn so với báo cáo trước đó
- duy trì trạng thái modifier (`Shift`, `Ctrl`, `AltGr`) từ byte 0 hoặc các trường đã phân tích như `usbhid.boot_report.keyboard.modifier.left_shift` và `usbhid.boot_report.keyboard.modifier.right_alt`
- theo dõi các phím bật/tắt trạng thái như `Caps Lock`, vì chỉ `Shift` không quyết định việc xuất chữ hoa
- nhớ rằng ID HID usage không phụ thuộc vào bố cục bàn phím: `0x1d` là vị trí phím `z`/`y` vật lý, tùy thuộc vào bố cục bàn phím của máy chủ.<sup>[[9]](#references)</sup>

## Decoder Python nhanh

```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
    raw = raw.strip().replace(':', '')
    if len(raw) != 16:
        continue
    modifier = int(raw[0:2], 16)
    keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
    current = {k for k in keycodes if k}
    newly_pressed = [k for k in keycodes if k and k not in prev]
    shift = bool(modifier & 0x22)
    for keycode in newly_pressed:
        if keycode == 0x39:
            caps = not caps
            continue
        char = SHIFTED.get(keycode) if shift else None
        if char is None:
            char = NORMAL.get(keycode, '?')
            if char.isalpha() and (shift ^ caps):
                char = char.upper()
        sys.stdout.write(char)
    prev = current
```

Dùng các dòng hex thuần đã trích xuất trước đó làm đầu vào để tái dựng sơ bộ ngay lập tức mà không cần đưa cả parser vào môi trường. Với các bố cục không phải US, cách này vẫn tái dựng vị trí phím vật lý, nhưng không nhất thiết là ký tự cuối cùng hiển thị trên máy của nạn nhân.

## Troubleshooting tips

- Nếu Wireshark không điền các trường `usbhid.*`, có thể descriptor báo cáo HID đã không được capture. Hãy rút rồi cắm lại bàn phím trong khi capture hoặc chuyển sang dùng dữ liệu thô `usb.capdata`.
- Với các bản capture bằng phần mềm trên Linux, `usbmon` là nguồn thông thường; trên Windows, Wireshark cần extcap **USBPcap** để xem các USB URB thô.<sup>[[4]](#references)</sup>
- Nếu bàn phím được kết nối qua hub hoặc dock, trước tiên hãy xác nhận interface descriptor, sau đó chỉ giải mã cặp device/interface đó. Các bản capture HID composite thường trộn lẫn báo cáo bàn phím và chuột.
- Bản capture trên Windows cần interface extcap **USBPcap**; hãy đảm bảo interface này vẫn còn sau khi nâng cấp Wireshark, vì thiếu extcap sẽ khiến danh sách thiết bị trống.<sup>[[4]](#references)</sup>
- Luôn đối chiếu bộ ba bus, device và interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ví dụ `1.9.1`) trước khi giải mã — trộn lẫn nhiều bàn phím hoặc thiết bị lưu trữ sẽ tạo ra các keystroke vô nghĩa.<sup>[[10]](#references)</sup>



## References

- [1] [Bài giải HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Phân tích bản capture gói tin bàn phím USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [Bài giải ACSC Quals 2023 - pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Thiết lập capture USB trong Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Định nghĩa lớp thiết bị cho thiết bị giao diện người dùng (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Bảng cách dùng HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Tham chiếu bộ lọc hiển thị Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Tham chiếu bộ lọc hiển thị Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Nhân Linux: Giới thiệu về descriptor báo cáo HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: bài giải ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
