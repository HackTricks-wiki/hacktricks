# Tracing lệnh ARM CoreSight qua SWO

{{#include ../../banners/hacktricks-training.md}}

Có thể sử dụng [cổng debug SWD/JTAG](jtag.md) có thể truy cập để bật trace trực tiếp quá trình thực thi trên Cortex-M mà không cần instrument firmware. Cần có MCU hỗ trợ ETM và TPIU, đường SWO được đưa ra ngoài, bản firmware chính xác để giải mã và logic analyzer đủ nhanh với tốc độ bit SWO đã chọn. Khác với [các phép đo kênh bên dựa trên nguồn hoặc EM](side_channel_analysis.md), ETM là trace debug; ghi lại cả hai loại có thể giúp căn chỉnh hiện tượng rò rỉ quan sát được với mã đang thực thi. Việc căn chỉnh tương tự cũng có thể giúp xác định thời điểm [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM phát ra các sự kiện luồng điều khiển đã nén thay vì byte lệnh. Bộ giải mã dựng lại quá trình thực thi dựa trên image firmware tương ứng. ITM mang dữ liệu instrumentation phần mềm, còn TPIU đóng khung các nguồn trace và đưa tín hiệu ra qua cổng nối tiếp. Trước khi áp dụng bất kỳ giá trị thanh ghi nào, hãy kiểm tra các thành phần CoreSight và cách ghép kênh chân trong tài liệu tham khảo của target: ví dụ bên dưới dành cho STM32F401, không phải cấu hình Cortex-M dùng chung.<sup>[[1]](#references)</sup>

## Tìm đầu ra trace

Trên STM32F401, SWO bất đồng bộ sử dụng PB3. Trên bộ điều khiển được khảo sát, PB3 được nối với điện trở R15, tạo thành điểm đo dễ tiếp cận. Khi package hoặc net bị ẩn, hãy tạm cấu hình chân có thể dùng làm SWO đang nghi ngờ thành GPIO, rồi bật/tắt chân đó thông qua các lệnh ghi bộ nhớ SWD. Dùng probe để kiểm tra các điểm trên bo mạch, tìm dạng sóng tương ứng, rồi khôi phục cấu hình chân trace. Nối analyzer với mass chung và mức điện áp logic tương thích.<sup>[[1]](#references)</sup>

## Bật TPIU và ETM bằng OpenOCD

Các lệnh sau được đặt trong cấu hình OpenOCD sau khi chọn adapter phù hợp và `target/stm32f4x.cfg`. `setbits` giữ nguyên các bit không liên quan trong thanh ghi điều khiển, trong khi `mww` ghi đè toàn bộ word. Trước tiên, TPIU định tuyến trace bất đồng bộ; sau đó ETM được mở khóa, cấu hình ở chế độ lập trình, gán ID nguồn trace `1` và khởi chạy. Các giá trị này dựa trên cấu hình STM32F401 mà tác giả đã thử nghiệm thành công, vì vậy hãy điều chỉnh cho phù hợp với sơ đồ thanh ghi và cây xung nhịp của target.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Cấu hình thanh ghi trace OpenOCD cho STM32F401</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

Tốc độ SWO là `HCLK / (TPIU_ACPR + 1)`. Với HCLK 16 MHz và `ACPR=3`, hãy capture ở tốc độ 4 Mbaud. Trong PulseView, đặt bộ giải mã ETM phía trên bộ giải mã UART trên kênh SWO analyzer, đặt UART theo tốc độ thực tế trên dây và dùng source ID ETM đã cấu hình ở trên. Ví dụ sử dụng tốc độ lấy mẫu 24 MHz (sáu mẫu mỗi bit), trigger cạnh xuống và capture với 25% dữ liệu trước trigger. Sau khi cấu hình, hãy halt/reset target, bật capture rồi `resume`; xác minh đồng bộ ETM và đường đi PC hợp lý so với firmware, thay vì chỉ tin vào dữ liệu trông có vẻ đã được giải mã.<sup>[[1]](#references)</sup>

## Khôi phục sau khi thay đổi clock và pin-mux

Hai thao tác độc lập trong firmware có thể làm dừng trace đang hoạt động. Thay đổi PLL làm tăng HCLK, do đó tăng baud SWO trong khi `ACPR` vẫn giữ nguyên; khi đó tầng UART sẽ khôi phục sai byte và ETM replay trở nên vô nghĩa. Kiểm tra cấu hình RCC/PLL trong [phân tích firmware](../firmware-analysis/) và, với ví dụ STM32F401, nạp image Cortex-M tại `0x08000000` rồi import SVD của nó vào Ghidra để các lần ghi thanh ghi clock có tên. Đặt hardware breakpoint tại một lệnh Thumb dài hai byte *sau* khi khởi tạo clock. Trong ví dụ, `bp 0x080001fa 2 hw` rồi `resume` sẽ dừng sau khi thiết lập PLL; khi đang halt, `mww 0xe0040010 31` đặt bộ chia mới. Tính và đặt tốc độ UART mới, bật capture rồi `resume` lần nữa. Cách này capture đường đi sau khi chuyển đổi; nó không khôi phục phần chuyển đổi đã bị bỏ lỡ.<sup>[[1]](#references)</sup>

Riêng biệt, firmware có thể remap pad SWO sang một peripheral khác. Trong ví dụ, thiết lập alternate-function của GPIO đã chuyển PB3 sang I2C2 SDA, vì vậy không cài đặt bộ giải mã nào có thể khôi phục trace trên dây đó. Tìm phần khởi tạo GPIO liên quan trong firmware, sau đó thay các vị trí gọi nó bằng các Thumb NOP có kích thước tương ứng (`0xBF00` cho mỗi halfword) hoặc halt core và khôi phục cấu hình pin tương thích với trace thông qua SWD. Cả hai cách đều có thể vô hiệu hóa peripheral bị thay thế; thao tác khôi phục lúc runtime cũng có thể bị firmware ghi đè lần nữa. Khi khôi phục pin lúc runtime, hãy đặt bộ chia SWO theo HCLK hiện tại.<sup>[[1]](#references)</sup>

## References

- [1] [Theo dõi lệnh: ARM tracing trực tiếp với ETM, ITM và TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: Cấu hình STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
