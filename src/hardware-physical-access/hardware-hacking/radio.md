# Radio

{{#include ../../banners/hacktricks-training.md}}

Để thực hiện công việc chuyên biệt theo giao thức sau khi nhận diện tín hiệu, xem [kiểm thử RFID/NFC, sub-GHz, hồng ngoại, BLE và LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) là trình phân tích tín hiệu số miễn phí dành cho GNU/Linux và macOS, được thiết kế để trích xuất thông tin từ các tín hiệu vô tuyến chưa xác định. Công cụ hỗ trợ thiết bị SDR thông qua SoapySDR và cung cấp các công cụ giải điều chế, phân tích theo thời gian thực cho FSK, PSK, ASK, video analog, tín hiệu dạng burst và kênh thoại analog.<sup>[[1]](#references)</sup>

### Cấu hình cơ bản

Sau khi cài đặt, bạn có thể cân nhắc cấu hình một số mục.\
Trong phần cài đặt (nút tab thứ hai), hãy chọn **thiết bị SDR** hoặc tệp đầu vào, tần số cần dò và tốc độ lấy mẫu. Tốc độ lên đến 2.56 Msps có thể phù hợp nếu máy chủ hỗ trợ.

![Cài đặt SigDigger hiển thị các tùy chọn thiết bị SDR, tệp đầu vào, tần số và tốc độ lấy mẫu](<../../images/image (245).png>)

Trong phần hành vi của GUI, bạn nên bật một số mục nếu PC của bạn hỗ trợ:

![SigDigger - Cấu hình cơ bản: Trong phần hành vi của GUI, bạn nên bật một số mục nếu PC của bạn hỗ trợ](<../../images/image (472).png>)

> [!TIP]
> Nếu bạn nhận thấy PC không thu được tín hiệu, hãy thử tắt OpenGL và giảm tốc độ lấy mẫu.

### Cách sử dụng

- Để **thu tín hiệu trong một khoảng thời gian và phân tích**, hãy giữ nút "Push to capture" trong khoảng thời gian cần thiết.

![Cấu hình cơ bản - Cách sử dụng: Để thu tín hiệu trong một khoảng thời gian và phân tích, hãy giữ nút "Push to capture" trong khoảng thời gian cần thiết](<../../images/image (960).png>)

- **Tuner** của SigDigger giúp **thu tín hiệu tốt hơn** (nhưng cũng có thể làm tín hiệu kém đi). Tốt nhất, hãy bắt đầu ở mức 0 rồi **tăng dần cho đến khi** thấy **nhiễu** gây ra **nhiều hơn** mức **cải thiện tín hiệu** bạn cần.

![Điều khiển tuner của SigDigger được điều chỉnh để cải thiện tín hiệu vô tuyến thu được](<../../images/image (1099).png>)

### Đồng bộ hóa với kênh vô tuyến

Với [**SigDigger** ](https://github.com/BatchDrake/SigDigger), hãy đồng bộ hóa với kênh bạn muốn nghe, cấu hình tùy chọn "Baseband audio preview", đặt băng thông để thu toàn bộ thông tin đang được truyền, rồi điều chỉnh Tuner đến mức ngay trước khi nhiễu bắt đầu tăng đáng kể:<sup>[[1]](#references)</sup>

![Kênh vô tuyến được đồng bộ hóa trong SigDigger với tùy chọn xem trước âm thanh baseband và băng thông đã cấu hình](<../../images/image (585).png>)

## Một số thủ thuật hữu ích

- Khi thiết bị gửi các burst thông tin, **phần đầu tiên thường là preamble**, vì vậy bạn **không cần lo lắng** nếu **không tìm thấy thông tin** ở đó **hoặc nếu có một vài lỗi**.
- Trong các frame thông tin, bạn thường sẽ **thấy các frame khác nhau được căn chỉnh với nhau**:

![Đồng bộ hóa với kênh vô tuyến - Một số thủ thuật hữu ích: Trong các frame thông tin, bạn thường sẽ thấy các frame khác nhau được căn chỉnh với nhau](<../../images/image (1076).png>)

![Đồng bộ hóa với kênh vô tuyến - Một số thủ thuật hữu ích: Trong các frame thông tin, bạn thường sẽ thấy các frame khác nhau được căn chỉnh với nhau](<../../images/image (597).png>)

- **Sau khi khôi phục các chuyển mức, bạn có thể cần giải mã chúng.** Với mã hóa Manchester, một hướng chuyển mức biểu thị `0` và hướng ngược lại biểu thị `1`; cực tính cụ thể tùy thuộc vào quy ước được sử dụng.
- Preamble có thể chứa một chuỗi các mức lấy mẫu giống nhau ngay cả khi payload sử dụng mã hóa Manchester, vì vậy hãy xác định ranh giới frame trước khi giải mã.

### Nhận diện kiểu điều chế bằng IQ

Có 3 cách lưu trữ thông tin trong tín hiệu: điều chế **biên độ**, **tần số** hoặc **pha**.\
Khi kiểm tra tín hiệu, có nhiều cách để xác định kiểu điều chế được sử dụng (xem thêm các cách khác bên dưới), nhưng một cách hiệu quả là kiểm tra biểu đồ IQ.

![Biểu đồ IQ của SigDigger dùng để xác định tín hiệu có điều chế biên độ, tần số hay pha](<../../images/image (788).png>)

- **Phát hiện AM**: Nếu biểu đồ IQ hiển thị, chẳng hạn, **2 vòng tròn** (có thể một vòng ở mức 0 và vòng kia ở biên độ khác), thì đây có thể là tín hiệu AM. Trong biểu đồ IQ, khoảng cách từ điểm 0 đến vòng tròn là biên độ tín hiệu, nên bạn có thể dễ dàng quan sát các biên độ khác nhau được sử dụng.
- **Phát hiện PM**: Như trong hình trước, nếu bạn thấy các vòng tròn nhỏ không liên quan với nhau thì có thể tín hiệu sử dụng điều chế pha. Trong biểu đồ IQ, góc giữa điểm và tọa độ 0,0 là pha của tín hiệu, nghĩa là có 4 pha khác nhau được sử dụng.
  - Lưu ý rằng nếu thông tin được mã hóa bằng sự thay đổi pha chứ không phải giá trị pha, bạn sẽ không thấy các pha khác nhau được phân biệt rõ ràng.
- **Phát hiện FM**: IQ không có trường để xác định tần số (khoảng cách đến tâm biểu thị biên độ, còn góc biểu thị pha).\
  Vì vậy, để nhận diện FM, về cơ bản bạn **chỉ nên thấy một vòng tròn** trên biểu đồ này.\
  Ngoài ra, độ lệch tần số làm thay đổi tốc độ quay quanh vòng tròn IQ. Do đó, trong SigDigger, thay đổi về tốc độ hoặc hướng quay có thể là dấu hiệu của FM.

## Ví dụ AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Nhận diện AM

#### Kiểm tra đường bao

Khi kiểm tra dữ liệu AM bằng [**SigDigger**](https://github.com/BatchDrake/SigDigger), **đường bao** của tín hiệu có thể cho thấy các mức biên độ khác biệt. Tín hiệu mẫu gửi thông tin dưới dạng các xung điều chế biên độ; một xung có dạng như sau:<sup>[[1]](#references)</sup>

![Đường bao tín hiệu AM trong SigDigger với các mức biên độ xung rõ ràng](<../../images/image (590).png>)

Đây là dạng sóng của một phần ký hiệu:

![Nhận diện AM - Kiểm tra đường bao: Dạng sóng của một phần ký hiệu](<../../images/image (734).png>)

#### Kiểm tra biểu đồ histogram

Bạn có thể **chọn toàn bộ tín hiệu** chứa thông tin, chọn chế độ **Amplitude** và **Selection**, rồi nhấp vào **Histogram**. Bạn sẽ thấy chỉ có 2 mức rõ ràng.

![Biểu đồ histogram biên độ trong SigDigger hiển thị hai mức rõ ràng của tín hiệu AM đã chọn](<../../images/image (264).png>)

Ví dụ, nếu chọn Frequency thay vì Amplitude cho tín hiệu AM này, bạn sẽ chỉ thấy 1 tần số (không thể điều chế thông tin theo tần số mà chỉ dùng 1 tần số).

![Biểu đồ histogram tần số trong SigDigger hiển thị một tần số của tín hiệu AM](<../../images/image (732).png>)

Nếu thấy nhiều tần số, có thể đây không phải FM; tần số tín hiệu có thể chỉ bị thay đổi do kênh truyền.

#### Với IQ

Trong ví dụ này, bạn có thể thấy **một vòng tròn lớn** cùng **nhiều điểm ở tâm**.

![Kiểm tra biểu đồ histogram - Với IQ: Ví dụ này cho thấy một vòng tròn lớn cùng nhiều điểm ở tâm](<../../images/image (222).png>)

### Tìm tốc độ ký hiệu

#### Với một ký hiệu

Chọn khoảng nhỏ nhất chứa rõ ràng một ký hiệu, rồi kiểm tra **Selection freq**. Trong ví dụ này, giá trị là 1.013 kHz, xấp xỉ 1 kHz.

![Tìm tốc độ ký hiệu - Với một ký hiệu: Chọn khoảng nhỏ nhất chứa rõ ràng một ký hiệu, rồi kiểm tra "Selection freq". Trong trường hợp này, giá trị là 1.013 kHz (tức 1 kHz).](<../../images/image (78).png>)

#### Với một nhóm ký hiệu

Bạn cũng có thể chỉ định số lượng ký hiệu cần chọn; SigDigger sẽ tính tần số của 1 ký hiệu (có lẽ chọn càng nhiều ký hiệu thì kết quả càng chính xác). Trong ví dụ này, tôi chọn 10 ký hiệu và "Selection freq" là 1.004 Khz:

![Tính tốc độ ký hiệu trong SigDigger bằng một nhóm gồm mười ký hiệu được chọn](<../../images/image (1008).png>)

### Lấy bit

Sau khi nhận diện AM và ước tính **tốc độ ký hiệu**, hãy chọn vùng tín hiệu, cấu hình lấy mẫu biên độ và các mức quyết định, chọn **Gardner clock recovery**, rồi nhấn **Sample**:

![Bảng Get Bits trong SigDigger được cấu hình để lấy mẫu AM, đặt tốc độ ký hiệu và khôi phục xung nhịp Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** nghĩa là nếu trước đó bạn đã chọn các khoảng để tìm tốc độ ký hiệu thì tốc độ đó sẽ được sử dụng.
- **Manual** nghĩa là sử dụng tốc độ ký hiệu đã nhập.
- Trong **Fixed interval selection**, bạn nhập số khoảng cần chọn và SigDigger sẽ tính tốc độ ký hiệu từ đó.
- **Gardner clock recovery** là lựa chọn mặc định hữu ích, nhưng vẫn cần tốc độ ký hiệu ước tính.

Sau khi nhấn Sample, màn hình sẽ hiển thị như sau:

![Với một nhóm ký hiệu - Lấy bit: Màn hình hiển thị sau khi nhấn Sample](<../../images/image (644).png>)

Để SigDigger xác định **khoảng mức** mang thông tin, hãy nhấp vào **mức thấp hơn** rồi giữ chuột và kéo đến mức cao nhất:

![Chọn khoảng mức trong SigDigger từ mức biên độ thấp đến mức cao](<../../images/image (439).png>)

Nếu có, chẳng hạn, **4 mức biên độ khác nhau**, bạn cần đặt **Bits per symbol thành 2** rồi chọn từ mức thấp nhất đến mức cao nhất.

Cuối cùng, bằng cách **tăng** **Zoom** và **thay đổi kích thước hàng**, bạn có thể xem các bit (và có thể chọn tất cả rồi sao chép để lấy toàn bộ bit):

![Với một nhóm ký hiệu - Lấy bit: Cuối cùng, bằng cách tăng Zoom và thay đổi kích thước hàng, bạn có thể xem các bit (và có thể chọn tất cả rồi sao chép để lấy toàn bộ bit)](<../../images/image (276).png>)

Nếu tín hiệu có nhiều hơn 1 bit trên mỗi ký hiệu (ví dụ: 2), SigDigger **không thể biết ký hiệu nào là** 00, 01, 10 hay 11. Vì vậy, công cụ sẽ dùng các **mức xám** khác nhau để biểu thị từng ký hiệu (và khi sao chép bit, công cụ sẽ dùng **các số từ 0 đến 3**; bạn sẽ cần xử lý chúng).

Với các kiểu mã hóa đường truyền như **Manchester**, hãy chuyển từng cặp chuyển mức hợp lệ (`01` hoặc `10`) thành một bit dữ liệu theo quy ước được sử dụng trong giao thức.

## Ví dụ FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Nhận diện FM

#### Kiểm tra tần số và dạng sóng

Ví dụ về tín hiệu truyền thông tin bằng điều chế FM:

![Nhận diện FM - Kiểm tra tần số và dạng sóng: Ví dụ về tín hiệu truyền thông tin bằng điều chế FM](<../../images/image (725).png>)

Phổ tín hiệu cho thấy rõ **hai tần số**, dù có thể khó phân biệt chúng trên dạng sóng miền thời gian:

![Dạng sóng FM trong SigDigger, trong đó khó phân biệt trực tiếp hai tần số](<../../images/image (717).png>)

Điều này xảy ra vì tín hiệu thu được được căn giữa giữa hai tần số, nên độ lệch tần số của chúng xấp xỉ đối nhau:

![Tín hiệu FM thu được trong SigDigger hiển thị hai tần số với độ lệch xấp xỉ đối nhau](<../../images/image (942).png>)

Nếu tần số đồng bộ **gần một tần số hơn tần số còn lại**, bạn có thể dễ dàng thấy 2 tần số khác nhau:

![Nhận diện FM - Kiểm tra tần số và dạng sóng: Nếu tần số đồng bộ gần một tần số hơn tần số còn lại, bạn có thể dễ dàng thấy 2 tần số khác nhau](<../../images/image (422).png>)

![Nhận diện FM - Kiểm tra tần số và dạng sóng: Nếu tần số đồng bộ gần một tần số hơn tần số còn lại, bạn có thể dễ dàng thấy 2 tần số khác nhau](<../../images/image (488).png>)

#### Kiểm tra biểu đồ histogram

Kiểm tra biểu đồ histogram tần số của tín hiệu chứa thông tin sẽ giúp bạn dễ dàng thấy 2 tín hiệu khác nhau:

![Kiểm tra tần số và dạng sóng - Kiểm tra biểu đồ histogram: Kiểm tra biểu đồ histogram tần số của tín hiệu chứa thông tin sẽ giúp bạn dễ dàng thấy 2 tín hiệu khác nhau](<../../images/image (871).png>)

Trong trường hợp này, nếu kiểm tra **biểu đồ histogram biên độ**, bạn sẽ chỉ thấy **một biên độ**, vì vậy tín hiệu **không thể là AM** (nếu thấy nhiều biên độ, có thể tín hiệu đã bị suy hao công suất trên kênh truyền):

![Biểu đồ histogram biên độ của tín hiệu FM trong SigDigger hiển thị một mức biên độ duy nhất](<../../images/image (817).png>)

Đây là biểu đồ histogram pha (cho thấy rõ tín hiệu không được điều chế theo pha):

![Kiểm tra tần số và dạng sóng - Kiểm tra biểu đồ histogram: Đây là biểu đồ histogram pha, cho thấy rõ tín hiệu không được điều chế theo pha](<../../images/image (996).png>)

#### Với IQ

IQ không có trường để xác định tần số (khoảng cách đến tâm biểu thị biên độ, còn góc biểu thị pha).\
Vì vậy, để nhận diện FM, về cơ bản bạn **chỉ nên thấy một vòng tròn** trên biểu đồ này.\
Ngoài ra, độ lệch tần số làm thay đổi tốc độ quay quanh vòng tròn IQ. Do đó, trong SigDigger, thay đổi về tốc độ hoặc hướng quay có thể là dấu hiệu của FM:

![Biểu đồ IQ trong SigDigger, trong đó FM xuất hiện dưới dạng thay đổi gia tốc quanh vòng tròn](<../../images/image (81).png>)

### Tìm tốc độ ký hiệu

Sau khi tìm thấy các tần số mang ký hiệu, bạn có thể dùng **cùng phương pháp như trong ví dụ AM** để tìm tốc độ ký hiệu.

### Lấy bit

Sau khi **xác định tín hiệu được điều chế theo tần số** và tìm được **tốc độ ký hiệu**, bạn có thể dùng **cùng phương pháp như trong ví dụ AM** để lấy bit.

## References

- [1] [SigDigger - Trình phân tích tín hiệu số miễn phí cho GNU/Linux và macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
