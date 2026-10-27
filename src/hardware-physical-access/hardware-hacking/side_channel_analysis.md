# Tấn công phân tích kênh phụ

{{#include ../../banners/hacktricks-training.md}}

Tấn công kênh phụ khôi phục bí mật bằng cách quan sát "leakage" vật lý hoặc vi kiến trúc có *tương quan* với trạng thái nội bộ nhưng *không* thuộc giao diện logic của thiết bị. Ví dụ bao gồm đo dòng điện tức thời mà smart card tiêu thụ và khai thác các hiệu ứng quản lý nguồn CPU qua mạng.

Với mục tiêu có phần cứng debug ARM có thể truy cập, [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) có thể cung cấp tham chiếu về đường thực thi bên cạnh các bản ghi công suất hoặc EM; đây là debug trace, không phải kênh leakage.<sup>[[17]](#references)</sup>

---

## Các kênh leakage chính

| Kênh | Mục tiêu thường gặp | Thiết bị đo |
|---------|---------------|-----------------|
| Mức tiêu thụ điện năng | Smart card, MCU IoT, FPGA | Oscilloscope cùng điện trở shunt hoặc đầu dò vi sai; CW503 là bộ cấp nguồn cho đầu dò/LNA, bản thân nó không phải đầu dò<sup>[[11]](#references)</sup> |
| Trường điện từ (EM) | CPU, RFID, bộ tăng tốc AES | Đầu dò H-field/near-field cùng bộ khuếch đại nhiễu thấp và oscilloscope hoặc bộ thu SDR như RTL-SDR<sup>[[13]](#references)</sup> |
| Thời gian thực thi / cache | CPU desktop và cloud | Bộ định thời độ chính xác cao (`rdtsc`/`rdtscp`) hoặc đo thời gian truyền từ xa |
| Âm thanh / cơ học | Bàn phím, máy in 3D, máy in, rơ-le và bộ điều chỉnh điện áp CPU | Micro MEMS hoặc máy đo rung laser<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Quang học và nhiệt | Đèn LED trạng thái, màn hình, DRAM và thiết bị ghép nhiệt | Photodiode, camera tốc độ cao hoặc camera hồng ngoại<sup>[[7]](#references)[[16]](#references)</sup> |
| Tiêm lỗi | Mật mã ASIC/MCU | Glitch xung nhịp/điện áp, EMFI hoặc tiêm laser |

---

## Phân tích công suất

### Simple Power Analysis (SPA)
Quan sát một trace duy nhất và liên hệ các đặc điểm dễ nhận thấy với những thao tác như rẽ nhánh, phép nhân modulo hoặc các chuỗi lệnh khác nhau.<sup>[[1]](#references)</sup>

Thiết lập chính xác phụ thuộc vào mục tiêu. Ví dụ sau sử dụng API capture cấp cao hiện tại của ChipWhisperer sau khi scope và target đã được kết nối và cấu hình:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
Thu thập nhiều trace, giả định một byte khóa `k`, tính toán mô hình rò rỉ Hamming-weight (HW) hoặc Hamming-distance (HD), rồi tính tương quan giữa mô hình đó với từng mẫu. Số lượng trace cần thiết phụ thuộc vào mục tiêu, nhiễu, căn chỉnh, các biện pháp đối phó và mô hình rò rỉ; không có ngưỡng cố định.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA là baseline tiêu chuẩn. Template attacks, phân tích mutual information và các phương pháp machine learning có thể hữu ích khi leakage là phi tuyến hoặc các trace được căn chỉnh kém.

---

## Phân tích điện từ (EMA)
Phân tích EM trường gần có thể quan sát hoạt động phụ thuộc dữ liệu mà không cần chèn shunt vào đường cấp nguồn. Phương pháp này không nhất thiết làm lộ cùng tín hiệu như trace công suất: vị trí và hướng đầu dò, băng thông, gain của tầng đầu vào, chất lượng trigger và khoảng cách đều quan trọng.

---

## Tấn công Timing và Vi kiến trúc
CPU hiện đại làm lộ bí mật thông qua các tài nguyên dùng chung:
* **Hertzbleed (2022)** – Dynamic voltage and frequency scaling phụ thuộc dữ liệu tạo ra một kênh timing từ xa. Bản trình diễn khôi phục khóa end-to-end ban đầu nhắm vào SIKE; các nghiên cứu tiếp theo thảo luận những primitive khác.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Thực thi tạm thời có thể làm lộ dữ liệu được các lệnh vector gather sử dụng qua các ranh giới bảo mật.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Việc xử lý sai trạng thái vector-register mang tính suy đoán có thể làm lộ dữ liệu từ cùng một lõi vật lý.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Tấn công thực thi tạm thời kết hợp phantom execution với huấn luyện trong thực thi tạm thời để tạo các gadget misprediction do kẻ tấn công kiểm soát.<sup>[[5]](#references)</sup>

---

## Tấn công Âm học và Quang học
Leakage âm học đã được dùng để khôi phục khóa RSA từ tiếng ồn của laptop trong một thử nghiệm có kiểm soát, bao gồm cả khi dùng micro điện thoại di động ở gần.<sup>[[6]](#references)</sup> Một nghiên cứu bàn phím riêng biệt năm 2023 phân loại lần nhấn phím với độ chính xác 95% khi huấn luyện bằng bản ghi từ điện thoại ở gần, và 93% khi huấn luyện bằng âm thanh Zoom; các con số này mô tả thử nghiệm trên thiết bị được huấn luyện trong bài báo đó, không áp dụng cho mọi bàn phím hay nạn nhân bất kỳ.<sup>[[9]](#references)</sup> Bức xạ quang học từ đèn LED trạng thái cũng có thể được đối chiếu với dữ liệu đang xử lý. Các kết quả này phụ thuộc vào mục tiêu và thiết lập cụ thể; không nên khái quát phạm vi hoặc tỷ lệ thành công của chúng cho các thiết bị không liên quan.<sup>[[7]](#references)</sup>

---

## Fault Injection và Phân tích lỗi vi sai (DFA)
Kết hợp các lỗi được kiểm soát với quan sát side-channel có thể thu hẹp phạm vi tìm kiếm khóa đối với một số thuật toán và cách triển khai. Các nền tảng phổ biến trong phòng thí nghiệm gồm tính năng voltage/clock glitching của ChipWhisperer và các công cụ EM fault-injection chuyên dụng như ChipSHOUTER hoặc PicoEMP. Mô tả “dưới 1 ns” trong bản thảo trước không nên được dùng làm thông số kỹ thuật: tài liệu hướng dẫn đã công bố của ChipSHOUTER liệt kê độ rộng xung được chèn điển hình là **15–80 ns** với đầu tip 1 mm và **24–480 ns** với đầu tip 4 mm (mặc dù jitter của trigger/xung được quy định bằng picosecond). Độ phân giải timing cần thiết, vị trí đặt đầu dò và số lượng đầu ra lỗi phụ thuộc vào mục tiêu và mô hình lỗi.<sup>[[1]](#references)[[10]](#references)</sup>

## Các Hướng Nghiên cứu Chưa được Xác minh được Giữ lại từ Bản thảo Trước

Bản thảo trước cũng nêu: một thiết lập EM **500 MHz–3 GHz** khôi phục khóa STM32 từ khoảng cách hơn **10 cm** bằng RTL-SDR; một đèn LED hoạt động DDR4 làm lộ khóa vòng AES trong chưa đầy một phút tại “Black Hat 2023”; và một nền tảng glitching RISC-V mã nguồn mở năm 2025 có tên **GlitchKit-R5**. Trong quá trình kiểm tra này, không tìm thấy bài báo chính, tài liệu hội nghị hay kho dự án phù hợp. Các chi tiết chính xác này được giữ lại làm đầu mối tìm kiếm/tái lập, không phải kết quả đã được xác lập hay khuyến nghị về công cụ.

---

## Quy trình Tấn công Điển hình
1. Xác định kênh leakage và điểm kết nối (chân VCC, tụ decoupling, điểm trường gần).
2. Chèn trigger (GPIO hoặc dựa trên mẫu).  
3. Thu thập đủ trace cho phép kiểm định thống kê đã chọn, đồng thời ghi lại plaintext/ciphertext và metadata khác.
4. Tiền xử lý (căn chỉnh, loại bỏ giá trị trung bình, lọc LP/HP, wavelet, PCA).
5. Khôi phục khóa bằng phương pháp thống kê hoặc ML (CPA, MIA, DL-SCA).
6. Xác thực và lặp lại với các giá trị ngoại lệ.

---

## Biện pháp Phòng thủ và Tăng cường Bảo mật
* Triển khai **constant-time** và các thuật toán memory-hard.
* **Masking/shuffling** – chia bí mật thành các share ngẫu nhiên; khả năng chống chịu bậc một được chứng nhận bằng TVLA.
* **Hiding** – bộ điều chỉnh điện áp trên chip, clock ngẫu nhiên hóa, logic dual-rail, tấm chắn EM.
* **Phát hiện lỗi** – tính toán dư thừa, chữ ký ngưỡng.
* **Vận hành** – tắt DVFS/turbo trong các kernel mật mã, cô lập SMT, cấm co-location trên cloud đa tenant.

---

## Công cụ và Framework
* **ChipWhisperer-Husky** (2024) – scope 500 MS/s + trigger Cortex-M; Python API như trên.<sup>[[1]](#references)</sup>
* **Riscure Inspector và các sản phẩm fault-injection** – công cụ phân tích thương mại và kiểm thử tự động.
* **scaaml** – công cụ SCA deep learning dựa trên TensorFlow và các bộ dữ liệu.<sup>[[12]](#references)</sup>
* **pyecsca** – bộ công cụ mã nguồn mở để reverse-engineering các triển khai ECC dạng black-box thông qua side-channel.<sup>[[8]](#references)</sup>

---

## References

- [1] [Tài liệu ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Bài báo về tấn công Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Khai thác việc thu thập dữ liệu mang tính suy đoán](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Phơi bày các bề mặt tấn công mới bằng huấn luyện trong thực thi tạm thời](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Trích xuất khóa RSA bằng phân tích mật mã âm học băng thông thấp](https://eprint.iacr.org/2013/857.pdf)
- [7] [Rò rỉ thông tin từ bức xạ quang học](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Tài liệu artifact pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Một cuộc tấn công side-channel âm học thực tiễn dựa trên deep learning nhắm vào bàn phím](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Hướng dẫn sử dụng ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Tài liệu ChipWhisperer — bộ cấp nguồn đầu dò CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Tài liệu Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Thực hiện các cuộc tấn công side-channel điện từ chi phí thấp bằng RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Giải mã sở hữu trí tuệ: Tấn công side-channel âm học và từ tính trên máy in 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Tấn công side-channel âm học trên máy in](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Theo dõi nhiệt độ bằng DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Theo dõi các chỉ thị: Tracing ARM trực tiếp với ETM, ITM và TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
