# Phím nhấn USB

{{#include ../../../banners/hacktricks-training.md}}

Nếu bạn có một pcap chứa dữ liệu giao tiếp qua USB của bàn phím như sau:

![Phím nhấn USB: Nếu bạn có một pcap chứa dữ liệu giao tiếp qua USB của bàn phím như sau](<../../../images/image (962).png>)

Với bàn phím sử dụng **boot protocol** của HID, mỗi báo cáo Interrupt IN có bố cục cố định gồm 8 byte: một byte phím bổ trợ, một byte dự trữ và sáu byte mã phím. Máy chủ so sánh các báo cáo liên tiếp và ánh xạ mã phím sang các HID usage để dựng lại sự kiện nhấn phím.<sup>[[8]](#references)</sup>

## Cơ bản về báo cáo USB HID

Báo cáo đầu vào chuẩn của bàn phím boot có cấu trúc như sau.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Ý nghĩa |
| --- | --- |
| 0 | Bitmap phím bổ trợ (`0x02` = Shift trái, `0x20` = Shift phải, `0x40` = Alt phải, v.v.). Có thể bật nhiều bit cùng lúc. |
| 1 | Byte dự trữ; thông thường, các báo cáo không sử dụng byte này nên đặt giá trị bằng 0. Cách sử dụng riêng của OEM hoặc hệ thống không có tính di động. |
| 2-7 | Tối đa sáu mã phím đồng thời theo định dạng USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` nghĩa là "không có phím". |

Trong bố cục boot, usage ID `0x01` (`Keyboard ErrorRollOver`) được báo cáo trong tất cả các ô phím khi nhấn hơn sáu phím không phải phím bổ trợ; nó cũng có thể báo hiệu một tổ hợp không thể nhận dạng được.<sup>[[8]](#references)[[9]](#references)</sup> Hiểu bố cục này sẽ hữu ích khi bạn chỉ có các byte `usb.capdata` thô.

## Trích xuất dữ liệu HID từ PCAP

### Trước tiên, xác định giao diện bàn phím

Trong các bản capture có nhiều lưu lượng, hãy xác định bàn phím HID trước khi trích xuất các báo cáo. Điểm bắt đầu đáng tin cậy là phản hồi bộ mô tả giao diện:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Lớp HID định nghĩa các giá trị giao diện sau:<sup>[[8]](#references)</sup>

- `subclass == 1` là Boot Interface Subclass; với `protocol == 1`, giá trị này xác định bàn phím boot
- `protocol == 2` xác định chuột boot
- `protocol == 0` nghĩa là không có boot protocol; hãy kiểm tra HID report descriptor thay vì mặc định cho rằng bố cục dài 8 byte

Sau khi xác định được giao diện, hãy cố định bộ lọc theo `usb.bus_id`, `usb.device_address` và, nếu có thể, `usb.bInterfaceNumber` trước khi xuất dữ liệu.

### Quy trình Wireshark

1. **Cô lập thiết bị**: lọc lưu lượng interrupt IN từ bàn phím, ví dụ: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Thêm các cột hữu ích**: nhấp chuột phải vào trường `Leftover Capture Data` (`usb.capdata`) và các trường `usbhid.*` bạn muốn dùng (ví dụ: `usbhid.boot_report.keyboard.keycode_1`) để theo dõi thao tác gõ phím mà không cần mở từng frame.<sup>[[11]](#references)</sup>
3. **Ẩn các report rỗng**: áp dụng `!(usb.capdata == 00:00:00:00:00:00:00:00)` để loại bỏ các frame nhàn rỗi.
4. **Xuất dữ liệu để xử lý hậu kỳ**: `File -> Export Packet Dissections -> As CSV`, bao gồm `frame.number`, `usb.src`, `usb.capdata` và các trường modifier đã giải mã như `usbhid.boot_report.keyboard.modifier.left_shift` và `usbhid.boot_report.keyboard.modifier.right_alt` để viết script khôi phục dữ liệu sau đó.<sup>[[10]](#references)[[11]](#references)</sup>

### Quy trình dòng lệnh

Mẫu trích xuất kinh điển—kết xuất `usb.capdata`, loại bỏ các report nhàn rỗi và ánh xạ usage ID—xuất hiện trong bài phân tích gốc năm 2017 và hướng dẫn thực hành của bài này.<sup>[[1]](#references)[[2]](#references)</sup>

Repository `ctf-usb-keyboard-parser` tự động hóa quy trình tshark + sed kinh điển:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Trong các bản capture mới hơn, hãy ưu tiên trường `usbhid.data` đã được Wireshark giải mã và dùng `usb.capdata` làm phương án dự phòng; ghi mỗi payload vào một file riêng cho từng thiết bị:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Các tệp riêng cho từng thiết bị có thể được đưa vào decoder sau khi chuẩn hóa định dạng hex mà nó yêu cầu. Nếu bản capture đến từ bàn phím BLE được tunnel qua GATT, hãy lọc bằng `btatt.value && frame.len == 20` và dump payload hex trước khi decode.<sup>[[7]](#references)</sup>

### Khi report không phải là boot report 8 byte cổ điển

Một interface không phải boot hoặc report ID có thể làm thay đổi bố cục payload, vì vậy đừng cho rằng mọi keyboard report đều khớp với `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Ưu tiên `usbhid.data` thay cho `usb.capdata` khi Wireshark đã parse lớp HID.
- Nếu mỗi dòng đều bắt đầu bằng một tiền tố cố định hoặc report ID, hãy loại bỏ nó bằng decoder có xét đến offset thay vì giả định byte 0 luôn là modifier.<sup>[[7]](#references)</sup>
- Một số bản xuất USBPcap bỏ qua byte reserved, vì vậy decoder hỗ trợ `--no-reserved` hoặc offset tùy chỉnh sẽ giúp tiết kiệm thời gian.<sup>[[7]](#references)</sup>
- Nếu capture có HID report descriptor hoặc BLE HOGP report map, hãy dùng nó để khôi phục bố cục trường thực tế trước khi viết parser.

## Tự động hóa việc decode

- **ctf-usb-keyboard-parser** vẫn hữu ích cho các thử thách CTF nhanh và đã có sẵn trong repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parse trực tiếp cả tệp `pcap` lẫn `pcapng`, hiểu `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` và không cần tshark hay dependency bên ngoài nào khác, nên phù hợp với các sandbox cô lập.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** bổ sung trình trực quan hóa bàn phím, chuột và bảng vẽ. Bạn có thể chạy helper `extract_hid_data.sh` (backend tshark) hoặc `extract_hid_data.py` (backend scapy), sau đó đưa tệp văn bản kết quả vào decoder hoặc các module phát lại để xem các lần nhấn phím diễn ra.<sup>[[7]](#references)</sup>

### Giải mã có trạng thái rất quan trọng

Bàn phím USB boot gửi report theo tốc độ idle ngay cả khi không có sự kiện phím mới, vì vậy capture có thể chứa các report lặp lại trước sự kiện nhả phím. Một decoder thực tế nên:<sup>[[3]](#references)[[8]](#references)</sup>

- chỉ xuất các keycode mới được nhấn so với report trước đó
- duy trì trạng thái modifier (`Shift`, `Ctrl`, `AltGr`) từ byte 0 hoặc các trường đã parse như `usbhid.boot_report.keyboard.modifier.left_shift` và `usbhid.boot_report.keyboard.modifier.right_alt`
- theo dõi các phím chuyển trạng thái như `Caps Lock`, vì chỉ riêng Shift không quyết định chữ hoa
- nhớ rằng HID usage ID không phụ thuộc bố cục: `0x1d` tương ứng với vị trí phím vật lý `z`/`y`, tùy theo bố cục bàn phím của máy chủ.<sup>[[9]](#references)</sup>

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

Dùng các dòng hex thuần đã dump trước đó làm đầu vào để dựng lại sơ bộ ngay lập tức mà không cần đưa toàn bộ parser vào môi trường. Với layout không phải US, cách này vẫn dựng lại vị trí phím vật lý, nhưng không nhất thiết là ký tự cuối cùng hiển thị trên máy của nạn nhân.

## Mẹo khắc phục sự cố

- Nếu Wireshark không điền các trường `usbhid.*`, có thể descriptor báo cáo HID đã không được capture. Hãy rút rồi cắm lại bàn phím trong khi capture hoặc chuyển sang dùng `usb.capdata` thô.
- Trên Linux, nguồn capture bằng phần mềm thường dùng là `usbmon`; trên Windows, Wireshark cần extcap **USBPcap** để có thể thấy các USB URB thô.<sup>[[4]](#references)</sup>
- Nếu bàn phím được kết nối qua hub hoặc dock, trước tiên hãy xác nhận descriptor giao diện, sau đó chỉ giải mã cặp thiết bị/giao diện đó. Các bản capture HID tổng hợp thường trộn lẫn báo cáo bàn phím và chuột.
- Bản capture trên Windows cần giao diện extcap **USBPcap**; hãy đảm bảo giao diện này vẫn còn sau khi nâng cấp Wireshark, vì thiếu extcap sẽ khiến danh sách thiết bị trống.<sup>[[4]](#references)</sup>
- Luôn đối chiếu bộ ba bus, thiết bị và giao diện (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ví dụ `1.9.1`) trước khi giải mã — nhầm lẫn giữa nhiều bàn phím hoặc thiết bị lưu trữ sẽ tạo ra các phím bấm vô nghĩa.<sup>[[10]](#references)</sup>

## References

- [1] [Bài viết về HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Phân tích bản capture gói tin bàn phím USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [Bài giải ACSC Quals 2023 - pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Thiết lập capture USB trong Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Bộ giải mã USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Định nghĩa lớp thiết bị cho thiết bị giao diện người dùng (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Bảng mã sử dụng HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Tham chiếu bộ lọc hiển thị Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Tham chiếu bộ lọc hiển thị Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
