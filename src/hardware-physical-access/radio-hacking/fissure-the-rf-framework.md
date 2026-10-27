# FISSURE - Framework RF

{{#include ../../banners/hacktricks-training.md}}

**Tìm hiểu và dịch ngược tín hiệu dựa trên SDR, độc lập với tần số**

FISSURE là framework RF và dịch ngược mã nguồn mở, được thiết kế cho mọi cấp độ kỹ năng, với các tính năng hỗ trợ phát hiện và phân loại tín hiệu, khám phá giao thức, thực thi tấn công, thao tác IQ, phân tích lỗ hổng, tự động hóa và AI/ML. Framework này được xây dựng nhằm thúc đẩy việc tích hợp nhanh các mô-đun phần mềm, radio, giao thức, dữ liệu tín hiệu, tập lệnh, sơ đồ luồng, tài liệu tham khảo và công cụ của bên thứ ba. FISSURE hỗ trợ quy trình làm việc bằng cách tập trung phần mềm tại một nơi, giúp các nhóm nhanh chóng làm quen và cùng sử dụng cấu hình nền tảng đã được kiểm chứng cho các bản phân phối Linux cụ thể.<sup>[[1]](#references)[[2]](#references)</sup>

Framework và các công cụ đi kèm FISSURE được thiết kế để phát hiện năng lượng RF, mô tả đặc tính tín hiệu, thu thập và phân tích mẫu, phát triển kỹ thuật truyền hoặc chèn tín hiệu, cũng như tạo payload hoặc thông điệp tùy chỉnh. FISSURE cũng cung cấp thông tin về giao thức và tín hiệu để nhận dạng, tạo gói tin và fuzzing, cùng các kho lưu trữ và danh sách phát phục vụ mô phỏng và kiểm thử lưu lượng.<sup>[[1]](#references)[[2]](#references)</sup>

Cơ sở mã Python và giao diện đồ họa giúp người mới bắt đầu tìm hiểu về RF và các công cụ dịch ngược. Nhà giáo dục có thể sử dụng các bài học tích hợp sẵn, còn nhà phát triển và nhà nghiên cứu có thể tích hợp mô-đun và quy trình làm việc của riêng mình. Các bản phát hành hiện tại cũng hỗ trợ các nút cảm biến phân tán, tích hợp TAK, quy trình định vị địa lý và triển khai Apptainer theo vai trò.<sup>[[1]](#references)[[3]](#references)</sup>

**Thông tin bổ sung**

* [Trang AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slide GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Bài viết GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Bản ghi Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Bắt đầu

**Được hỗ trợ**

FISSURE hiện dùng nhánh **`Python3`** cho hoạt động phát triển, với PyQt5 và GNU Radio 3.8 hoặc 3.10. Nhánh **`Python2_maint-3.7`** đã lỗi thời nhưng vẫn có sẵn cho các hệ điều hành cũ và công cụ của bên thứ ba cần GNU Radio 3.7. Tên nhánh trước đây là `Python3_maint-3.8` và `Python3_maint-3.10` chỉ còn mang tính lịch sử; hiện việc chọn phiên bản bảo trì GNU Radio được thực hiện từ nhánh `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Hệ điều hành | Nhánh FISSURE | Nhánh GNU Radio mặc định |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | sử dụng phiên bản Linux được hỗ trợ | sử dụng phiên bản tương ứng |

**Đang triển khai (beta)**

Các hệ điều hành này vẫn đang ở trạng thái beta. Chúng đang được phát triển và được xác định là còn thiếu một số tính năng. Các mục trong trình cài đặt có thể xung đột với chương trình hiện có hoặc không cài đặt được cho đến khi trạng thái beta được gỡ bỏ.

| Hệ điều hành | Nhánh FISSURE | Nhánh GNU Radio mặc định |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Một số công cụ của bên thứ ba không hoạt động trên mọi hệ điều hành. Hãy xem tài liệu [Xung đột đã biết và phần mềm bên thứ ba](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) hiện tại trước khi cài đặt.<sup>[[3]](#references)</sup>

**Cài đặt**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Bước submodule tải các module GNU Radio out-of-tree được FISSURE sử dụng và là bước bắt buộc khi cài đặt các module đó. Trình cài đặt cũng sẽ cài đặt các dependency PyQt còn thiếu cần thiết để khởi chạy GUI cài đặt.<sup>[[3]](#references)</sup>

Tiếp theo, chọn tùy chọn phù hợp nhất với hệ điều hành của bạn (tùy chọn sẽ được tự động phát hiện nếu hệ điều hành của bạn khớp với một tùy chọn).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Bạn nên cài đặt FISSURE trên một hệ điều hành sạch để tránh xung đột với các thành phần hiện có. Chọn tất cả các hộp kiểm được đề xuất (nút Default) để tránh lỗi khi sử dụng các công cụ khác nhau trong FISSURE. Trong quá trình cài đặt sẽ xuất hiện nhiều lời nhắc, chủ yếu yêu cầu quyền nâng cao và tên người dùng. Nếu một mục có phần "Verify" ở cuối, trình cài đặt sẽ chạy lệnh theo sau và tô màu hộp kiểm của mục đó xanh lá hoặc đỏ, tùy thuộc vào việc lệnh có tạo ra lỗi hay không. Các mục được chọn nhưng không có phần "Verify" sẽ vẫn có màu đen sau khi cài đặt.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Cách sử dụng**

Mở terminal và nhập:

```
fissure
```

Tham khảo menu Help của FISSURE để biết thêm chi tiết về cách sử dụng.

## Chi tiết

**Thành phần**

* Dashboard
* Central Hub (HIPRFISR)
* Nhận dạng tín hiệu mục tiêu (TSI)
* Khám phá giao thức (PD)
* Trình thực thi Flow Graph và Script (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Khả năng**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Bộ phát hiện tín hiệu**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Thao tác IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Tra cứu tín hiệu**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Nhận dạng mẫu**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Tấn công**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Danh sách phát tín hiệu**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Thư viện hình ảnh**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Tạo gói tin**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Tích hợp Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Máy tính CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Ghi nhật ký**_            |

**Phần cứng**

Các thiết bị phần cứng sau đây có mức độ tích hợp khác nhau trong FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Bộ chuyển đổi 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Bài học

FISSURE cung cấp một số hướng dẫn hữu ích giúp bạn làm quen với các công nghệ và kỹ thuật khác nhau. Nhiều bài hướng dẫn bao gồm các bước sử dụng những công cụ được tích hợp vào FISSURE.

* [Bài học 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Bài học 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Bài học 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Bài học 4: Bo mạch ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Bài học 5: Theo dõi radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Bài học 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Bài học 7: Kiểu dữ liệu](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Bài học 8: Khối GNU Radio tùy chỉnh](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Bài học 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Bài học 10: Kỳ thi vô tuyến nghiệp dư](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Bài học 11: Công cụ Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Bài học 12: Tạo USB có khả năng khởi động](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Bài học 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Bài học 14: Quạt trần](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Lộ trình

* [ ] Bổ sung thêm loại phần cứng, giao thức RF, tham số tín hiệu và công cụ phân tích
* [ ] Hỗ trợ thêm hệ điều hành
* [ ] Phát triển tài liệu học tập xoay quanh FISSURE (tấn công RF, Wi-Fi, GNU Radio, PyQt, v.v.)
* [ ] Tạo bộ điều chỉnh tín hiệu, bộ trích xuất đặc trưng và bộ phân loại tín hiệu với các kỹ thuật AI/ML có thể lựa chọn
* [ ] Triển khai cơ chế giải điều chế đệ quy để tạo bitstream từ các tín hiệu chưa xác định
* [ ] Chuyển các thành phần chính của FISSURE sang mô hình triển khai nút cảm biến tổng quát

## Đóng góp

Chúng tôi rất khuyến khích các đề xuất nhằm cải thiện FISSURE. Hãy để lại bình luận trên trang [Thảo luận](https://github.com/ainfosec/FISSURE/discussions) hoặc trong Discord Server nếu bạn có ý kiến về những nội dung sau:

* Đề xuất tính năng mới và thay đổi thiết kế
* Công cụ phần mềm kèm các bước cài đặt
* Bài học mới hoặc tài liệu bổ sung cho các bài học hiện có
* Giao thức RF đáng quan tâm
* Bổ sung phần cứng và loại SDR để tích hợp
* Script phân tích IQ bằng Python
* Sửa đổi và cải thiện hướng dẫn cài đặt

Các đóng góp giúp cải thiện FISSURE đóng vai trò quan trọng trong việc đẩy nhanh quá trình phát triển. Chúng tôi rất trân trọng mọi đóng góp của bạn. Nếu muốn đóng góp bằng cách phát triển mã nguồn, hãy fork repo và tạo pull request:

1. Fork project
2. Tạo nhánh tính năng (`git checkout -b feature/AmazingFeature`)
3. Commit các thay đổi (`git commit -m 'Add some AmazingFeature'`)
4. Push lên nhánh (`git push origin feature/AmazingFeature`)
5. Mở pull request

Bạn cũng có thể tạo [Issues](https://github.com/ainfosec/FISSURE/issues) để báo lỗi.

## Hợp tác

Liên hệ bộ phận Phát triển Kinh doanh của Assured Information Security, Inc. (AIS) để đề xuất và chính thức hóa các cơ hội hợp tác về FISSURE—dù là dành thời gian tích hợp phần mềm của bạn, nhờ đội ngũ tài năng tại AIS phát triển giải pháp cho các thách thức kỹ thuật của bạn, hay tích hợp FISSURE vào các nền tảng/ứng dụng khác.

## Giấy phép

GPL-3.0

Để biết chi tiết về giấy phép, xem tệp LICENSE.

## Liên hệ

Tham gia Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Theo dõi trên Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Phát triển Kinh doanh - Assured Information Security, Inc. - bd@ainfosec.com

## Ghi công

Chúng tôi ghi nhận và biết ơn những nhà phát triển sau:

[Danh sách ghi công](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Lời cảm ơn

Đặc biệt cảm ơn Tiến sĩ Samuel Mantravadi và Joseph Reith đã đóng góp cho dự án này.

## References

- [1] [FISSURE - Khung RF (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Bài báo về FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Tài liệu FISSURE - Cài đặt](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
