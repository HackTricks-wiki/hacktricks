# Thuật ngữ đầu tư

{{#include ../../banners/hacktricks-training.md}}

## Giao ngay

Giao dịch giao ngay trao đổi một tài sản để nhận ngay. Lệnh giới hạn xác định số lượng và giá giới hạn; lệnh chỉ được khớp khi thị trường có thể đáp ứng mức giá đó hoặc tốt hơn. Lệnh thị trường hướng đến việc khớp lệnh nhanh ở mức giá tốt nhất hiện có và có thể gặp hiện tượng trượt giá.<sup>[[4]](#references)</sup>

Lệnh dừng-giới hạn có một mức giá dừng dùng để kích hoạt lệnh giới hạn. Lệnh này có thể giới hạn giá khớp, nhưng không đảm bảo được khớp nếu thị trường vượt qua mức giới hạn.<sup>[[4]](#references)</sup>

## Hợp đồng tương lai

Hợp đồng tương lai là thỏa thuận tiêu chuẩn hóa để mua hoặc bán một loại hàng hóa hoặc công cụ tài chính cụ thể vào một ngày trong tương lai. Ví dụ, hai bên có thể thỏa thuận mức giá 70.000 USD cho một bitcoin, với thời điểm thanh toán sau sáu tháng.<sup>[[1]](#references)</sup>

Nếu giá thanh toán là 80.000 USD, bên mua có lãi và bên bán chịu lỗ so với giá hợp đồng 70.000 USD. Nếu giá là 60.000 USD, kết quả sẽ ngược lại. Hợp đồng tương lai giao dịch trên sàn được định giá theo thị trường và thường được đóng hoặc chuyển kỳ hạn trước khi đáo hạn, vì vậy đây chỉ là ví dụ minh họa đơn giản.<sup>[[2]](#references)</sup>

Nhà sản xuất và người tiêu dùng sử dụng hợp đồng tương lai để phòng ngừa rủi ro giá; những người tham gia khác dùng chúng để tìm kiếm lợi nhuận hoặc cung cấp thanh khoản.<sup>[[1]](#references)</sup>

- **Vị thế mua** thường có lãi khi giá hợp đồng tăng.
- **Vị thế bán** thường có lãi khi giá hợp đồng giảm.<sup>[[2]](#references)</sup>

### Phòng ngừa rủi ro bằng hợp đồng tương lai

Nếu một nhà quản lý quỹ dự đoán danh mục đầu tư sẽ giảm giá, họ có thể bán khống hợp đồng tương lai chỉ số cổ phiếu có mức tương quan đủ cao. Lãi từ vị thế phòng ngừa rủi ro bán khống có thể bù đắp một phần khoản lỗ của danh mục; rủi ro cơ sở khiến khoản bù đắp hiếm khi chính xác tuyệt đối. Hợp đồng tương lai bitcoin sẽ phòng ngừa mức độ tiếp xúc với bitcoin, chứ không tự động phòng ngừa danh mục cổ phiếu.

Nếu thị trường được phòng ngừa giảm, vị thế bán hợp đồng tương lai có thể sinh lời trong khi các tài sản nắm giữ mất giá. Nếu thị trường tăng, các tài sản nắm giữ có thể tăng giá trong khi vị thế phòng ngừa bị lỗ. Phòng ngừa rủi ro giúp giảm một số rủi ro nhất định chứ không tạo ra lợi nhuận được đảm bảo.<sup>[[1]](#references)</sup>

### Hợp đồng tương lai vĩnh cửu

Hợp đồng vĩnh cửu là sản phẩm phái sinh không có ngày đáo hạn cố định. Các sàn giao dịch tiền mã hóa thường sử dụng khoản thanh toán funding định kỳ để giúp giá hợp đồng duy trì gần với giá giao ngay của tài sản cơ sở; điều khoản tùy thuộc vào từng sàn.<sup>[[3]](#references)</sup>

Để xem các thử nghiệm lạm dụng funding rate trên những giao thức hợp đồng vĩnh cửu on-chain, hãy xem [Khai thác funding rate của hợp đồng vĩnh cửu](perpetual-funding-rate-exploitation.md).

Lãi và lỗ thay đổi khi giá đánh dấu biến động. Giá biến động 1% sẽ tạo ra mức biến động xấp xỉ 1% trên giá trị danh nghĩa của vị thế trước phí và funding, nhưng đòn bẩy có thể khiến tỷ lệ này lớn hơn nhiều so với phần tài sản thế chấp đã nộp.

### Hợp đồng tương lai có đòn bẩy

**Đòn bẩy** cho phép nhà giao dịch kiểm soát một vị thế có giá trị danh nghĩa lớn hơn với khoản ký quỹ nhỏ hơn. Khoản lỗ không phải lúc nào cũng giới hạn ở mức ký quỹ ban đầu: thanh lý, biến động giá đột ngột, phí và quy định của sàn có thể dẫn đến khoản lỗ lớn hơn.<sup>[[3]](#references)</sup>

Ví dụ, khoản ký quỹ 100 USD với đòn bẩy 50x cho phép kiểm soát vị thế 5.000 USD. Bỏ qua phí, funding và cơ chế thanh lý, biến động thuận lợi 1% sẽ tạo ra khoản lãi 50 USD (bằng 50% ký quỹ ban đầu), trong khi biến động bất lợi 1% sẽ gây lỗ 50 USD. Biến động bất lợi 2% tương đương 100 USD, dù thông thường sàn sẽ thanh lý vị thế trước khi toàn bộ ký quỹ bị mất.

Đòn bẩy khuếch đại cả lãi lẫn lỗ và khiến vị thế có thể bị thanh lý chỉ sau một biến động bất lợi tương đối nhỏ.

## Khác biệt giữa hợp đồng tương lai và quyền chọn

Người mua quyền chọn nhận được quyền, chứ không phải nghĩa vụ, thực hiện giao dịch theo các điều khoản của hợp đồng. Người bán quyền chọn có nghĩa vụ tương ứng nếu người mua thực hiện quyền. Người mua trả cho người bán một khoản phí quyền chọn để có quyền đó.<sup>[[4]](#references)</sup>

### 1. **Nghĩa vụ và quyền:**

* **Hợp đồng tương lai:** Khi mua hoặc bán hợp đồng tương lai, bạn tham gia vào một **thỏa thuận ràng buộc** để mua hoặc bán một tài sản ở mức giá cụ thể vào một ngày trong tương lai. Cả người mua lẫn người bán đều **có nghĩa vụ** thực hiện hợp đồng khi đáo hạn (trừ khi hợp đồng được đóng trước thời điểm đó).
* **Quyền chọn:** Với quyền chọn, bạn có **quyền, nhưng không có nghĩa vụ**, mua (trong trường hợp **quyền chọn mua**) hoặc bán (trong trường hợp **quyền chọn bán**) một tài sản ở mức giá cụ thể trước hoặc vào một ngày đáo hạn nhất định. **Người mua** có quyền thực hiện giao dịch, còn **người bán** có nghĩa vụ thực hiện giao dịch nếu người mua quyết định thực hiện quyền chọn.

### 2. **Rủi ro:**

* **Hợp đồng tương lai:** Cả hai bên đều có thể chịu khoản lỗ đáng kể. Việc khoản lỗ có giới hạn về mặt toán học hay không phụ thuộc vào vị thế và tài sản cơ sở: vị thế bán có thể có khoản lỗ lý thuyết không giới hạn, trong khi vị thế mua không thể lỗ vượt quá giá trị danh nghĩa nếu giá tài sản cơ sở không thể thấp hơn 0.
* **Quyền chọn:** Người mua không bán thêm quyền chọn thường chỉ có nguy cơ mất khoản phí đã trả. Người bán quyền chọn mua không có tài sản bảo đảm có thể đối mặt với khoản lỗ lý thuyết không giới hạn; các chiến lược bán quyền chọn khác có mức rủi ro giới hạn hoặc không giới hạn khác nhau.

### 3. **Chi phí:**

* **Hợp đồng tương lai:** Không có chi phí trả trước ngoài khoản ký quỹ cần thiết để duy trì vị thế, vì cả người mua lẫn người bán đều có nghĩa vụ hoàn tất giao dịch.
* **Quyền chọn:** Người mua phải trả trước **phí quyền chọn** để có quyền thực hiện quyền chọn. Khoản phí này về cơ bản là chi phí của quyền chọn.

### 4. **Tiềm năng lợi nhuận:**

* **Hợp đồng tương lai:** Lãi hoặc lỗ dựa trên chênh lệch giữa giá thị trường khi đáo hạn và giá đã thỏa thuận trong hợp đồng.
* **Quyền chọn:** Người mua có lãi khi thị trường biến động theo hướng có lợi và vượt qua giá thực hiện một mức lớn hơn khoản phí đã trả. Người bán có lãi bằng cách giữ khoản phí nếu quyền chọn không được thực hiện.

## References

- [1] [CFTC - Mục đích kinh tế của thị trường hợp đồng tương lai](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Những điều cơ bản về thị trường hợp đồng tương lai](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Hiểu các rủi ro khi giao dịch tiền tệ ảo](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Bảng thuật ngữ CFTC - Quyền chọn, phí quyền chọn và thực hiện quyền](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
