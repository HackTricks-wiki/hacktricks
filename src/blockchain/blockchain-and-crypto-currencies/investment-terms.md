# Các thuật ngữ đầu tư

{{#include ../../banners/hacktricks-training.md}}

## Giao dịch giao ngay

Giao dịch giao ngay là việc trao đổi tài sản để nhận ngay. Lệnh giới hạn chỉ định số lượng và giá giới hạn; lệnh chỉ được khớp khi thị trường có thể đáp ứng mức giá đó hoặc tốt hơn. Lệnh thị trường hướng đến việc khớp lệnh nhanh ở mức giá tốt nhất hiện có và có thể gặp hiện tượng trượt giá.<sup>[[4]](#references)</sup>

Lệnh dừng-giới hạn có giá dừng để kích hoạt lệnh giới hạn. Lệnh này có thể giới hạn giá khớp, nhưng không đảm bảo được khớp nếu thị trường vượt qua mức giá giới hạn.<sup>[[4]](#references)</sup>

## Hợp đồng tương lai

Hợp đồng tương lai là thỏa thuận tiêu chuẩn hóa về việc mua hoặc bán một loại hàng hóa hoặc công cụ tài chính xác định vào một ngày trong tương lai. Ví dụ, hai bên có thể thỏa thuận mức giá $70,000 cho một bitcoin, với ngày thanh toán sau sáu tháng.<sup>[[1]](#references)</sup>

Nếu giá thanh toán là $80,000, bên mua được lời và bên bán chịu lỗ so với giá hợp đồng $70,000. Nếu giá là $60,000, chiều hướng sẽ ngược lại. Hợp đồng tương lai giao dịch trên sàn thực tế được định giá theo thị trường và thường được đóng hoặc chuyển kỳ trước khi đáo hạn, nên đây chỉ là ví dụ đơn giản hóa.<sup>[[2]](#references)</sup>

Nhà sản xuất và người tiêu dùng sử dụng hợp đồng tương lai để phòng ngừa rủi ro giá; những người tham gia khác dùng chúng để tìm kiếm lợi nhuận hoặc cung cấp thanh khoản.<sup>[[1]](#references)</sup>

- **Vị thế mua** thường có lời khi giá hợp đồng tăng.
- **Vị thế bán** thường có lời khi giá hợp đồng giảm.<sup>[[2]](#references)</sup>

### Phòng ngừa rủi ro bằng hợp đồng tương lai

Nếu nhà quản lý quỹ dự đoán danh mục đầu tư sẽ giảm giá, họ có thể bán khống một hợp đồng tương lai chỉ số chứng khoán có mức tương quan đủ cao. Khoản lời từ vị thế bán khống dùng để phòng ngừa có thể bù đắp một phần khoản lỗ của danh mục; rủi ro cơ sở khiến khoản bù đắp hiếm khi chính xác tuyệt đối. Hợp đồng tương lai bitcoin sẽ phòng ngừa mức độ tiếp xúc với bitcoin, chứ không tự động phòng ngừa danh mục cổ phiếu.

Nếu thị trường được phòng ngừa giảm, vị thế bán hợp đồng tương lai có thể sinh lời trong khi giá trị các tài sản nắm giữ giảm. Nếu thị trường tăng, các tài sản nắm giữ có thể tăng giá trong khi vị thế phòng ngừa chịu lỗ. Phòng ngừa rủi ro giúp giảm một số rủi ro nhất định, chứ không tạo ra lợi nhuận được đảm bảo.<sup>[[1]](#references)</sup>

### Hợp đồng tương lai vĩnh cửu

Hợp đồng vĩnh cửu là công cụ phái sinh không có ngày đáo hạn cố định. Các nền tảng giao dịch crypto thường sử dụng các khoản thanh toán funding định kỳ để giúp giá hợp đồng duy trì gần với giá giao ngay của tài sản cơ sở; điều khoản khác nhau tùy nền tảng.<sup>[[3]](#references)</sup>

Lãi và lỗ thay đổi khi giá đánh dấu biến động. Mức biến động giá 1% tạo ra mức biến động xấp xỉ 1% trên giá trị danh nghĩa của vị thế, chưa tính phí và funding, nhưng đòn bẩy có thể khiến tỷ lệ này lớn hơn nhiều so với số tài sản thế chấp đã nộp.

### Hợp đồng tương lai có đòn bẩy

**Đòn bẩy** cho phép nhà giao dịch kiểm soát vị thế có giá trị danh nghĩa lớn hơn với khoản ký quỹ nhỏ hơn. Khoản lỗ không phải lúc nào cũng giới hạn ở mức ký quỹ ban đầu: thanh lý, biến động giá đột ngột, phí và quy định của nền tảng có thể dẫn đến khoản lỗ lớn hơn.<sup>[[3]](#references)</sup>

Ví dụ, $100 tiền ký quỹ với đòn bẩy 50x cho phép kiểm soát một vị thế trị giá $5,000. Bỏ qua phí, funding và cơ chế thanh lý, mức biến động có lợi 1% tạo ra khoản lời $50 (bằng 50% mức ký quỹ ban đầu), còn mức biến động bất lợi 1% tạo ra khoản lỗ $50. Mức biến động bất lợi 2% tương đương $100, nhưng nền tảng thường sẽ thanh lý vị thế trước khi toàn bộ tiền ký quỹ bị mất.

Đòn bẩy khuếch đại cả lợi nhuận lẫn thua lỗ và khiến vị thế có thể bị thanh lý sau một biến động bất lợi tương đối nhỏ.

## Sự khác nhau giữa hợp đồng tương lai và quyền chọn

Người mua quyền chọn có quyền, chứ không có nghĩa vụ, thực hiện giao dịch theo các điều khoản hợp đồng. Người bán quyền chọn có nghĩa vụ tương ứng nếu người mua thực hiện quyền. Người mua trả cho người bán một khoản phí quyền chọn để có quyền đó.<sup>[[4]](#references)</sup>

### 1. **Nghĩa vụ và quyền:**

* **Hợp đồng tương lai:** Khi mua hoặc bán hợp đồng tương lai, bạn tham gia vào **thỏa thuận có tính ràng buộc** để mua hoặc bán tài sản ở một mức giá cụ thể vào một ngày trong tương lai. Cả người mua lẫn người bán đều **có nghĩa vụ** thực hiện hợp đồng khi đáo hạn (trừ khi hợp đồng được đóng trước thời điểm đó).
* **Quyền chọn:** Với quyền chọn, bạn có **quyền nhưng không có nghĩa vụ** mua (đối với **quyền chọn mua**) hoặc bán (đối với **quyền chọn bán**) tài sản ở một mức giá cụ thể, trước hoặc vào một ngày đáo hạn nhất định. **Người mua** có quyền thực hiện giao dịch, còn **người bán** có nghĩa vụ thực hiện giao dịch nếu người mua quyết định thực hiện quyền chọn.

### 2. **Rủi ro:**

* **Hợp đồng tương lai:** Cả hai bên đều có thể chịu khoản lỗ đáng kể. Việc khoản lỗ có giới hạn về mặt toán học hay không phụ thuộc vào vị thế và tài sản cơ sở: vị thế bán có thể có khoản lỗ lý thuyết không giới hạn, trong khi vị thế mua không thể lỗ nhiều hơn giá trị danh nghĩa nếu giá tài sản cơ sở không thể xuống dưới 0.
* **Quyền chọn:** Người mua không bán thêm quyền chọn thường chỉ chịu rủi ro mất khoản phí đã trả. Người bán quyền chọn mua không được bảo đảm có thể phải chịu khoản lỗ lý thuyết không giới hạn; các chiến lược bán quyền chọn khác có mức rủi ro hữu hạn hoặc không giới hạn tùy trường hợp.

### 3. **Chi phí:**

* **Hợp đồng tương lai:** Không có chi phí trả trước ngoài khoản ký quỹ cần thiết để duy trì vị thế, vì cả người mua lẫn người bán đều có nghĩa vụ hoàn tất giao dịch.
* **Quyền chọn:** Người mua phải trả trước **phí quyền chọn** để có quyền thực hiện quyền chọn. Khoản phí này về cơ bản là chi phí của quyền chọn.

### 4. **Tiềm năng lợi nhuận:**

* **Hợp đồng tương lai:** Lãi hoặc lỗ dựa trên chênh lệch giữa giá thị trường khi đáo hạn và mức giá đã thỏa thuận trong hợp đồng.
* **Quyền chọn:** Người mua có lời khi thị trường biến động theo hướng có lợi, vượt qua giá thực hiện một mức lớn hơn khoản phí đã trả. Người bán có lời khi giữ được khoản phí nếu quyền chọn không được thực hiện.

## References

- [1] [CFTC - Mục đích kinh tế của thị trường hợp đồng tương lai](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Những điều cơ bản về thị trường hợp đồng tương lai](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Hiểu các rủi ro khi giao dịch tiền ảo](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Bảng thuật ngữ CFTC - Quyền chọn, phí quyền chọn và thực hiện quyền](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
