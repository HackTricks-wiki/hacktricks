# Phương pháp Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Fuzzing bằng ngữ pháp đột biến: Coverage và ngữ nghĩa

Trong **fuzzing bằng ngữ pháp đột biến**, input được đột biến nhưng vẫn **hợp lệ theo ngữ pháp**. Ở chế độ hướng dẫn bằng coverage, chỉ những mẫu kích hoạt **coverage mới** mới được lưu làm seed trong corpus. Với **các mục tiêu ngôn ngữ** (parser, trình thông dịch, engine), cách này có thể bỏ sót các lỗi cần đến **chuỗi ngữ nghĩa/dataflow**, trong đó output của một cấu trúc trở thành input của cấu trúc khác.<sup>[[1]](#references)</sup>

**Dạng lỗi:** fuzzer tìm được các seed lần lượt thực thi `document()` và `generate-id()` (hoặc các primitive tương tự), nhưng **không giữ được dataflow liên kết**, nên mẫu “gần với lỗi hơn” bị loại vì không bổ sung coverage. Với **từ 3 bước phụ thuộc trở lên**, việc kết hợp ngẫu nhiên trở nên tốn kém và feedback từ coverage không hướng dẫn được quá trình tìm kiếm.<sup>[[1]](#references)</sup>

**Hàm ý:** với các ngữ pháp có nhiều phụ thuộc, hãy cân nhắc **kết hợp các giai đoạn đột biến và sinh input** hoặc ưu tiên quá trình sinh input theo các mẫu **nối chuỗi hàm** (không chỉ dựa vào coverage).<sup>[[1]](#references)</sup>

## Những vấn đề về tính đa dạng của corpus

Mutation hướng dẫn bằng coverage có tính **tham lam**: mẫu tạo coverage mới được lưu ngay lập tức, thường giữ lại nhiều vùng không thay đổi. Theo thời gian, corpus trở thành tập hợp các mẫu **gần như trùng lặp**, ít đa dạng về cấu trúc. Việc rút gọn quá mạnh có thể loại bỏ ngữ cảnh hữu ích, vì vậy một giải pháp thỏa hiệp thiết thực là **rút gọn có xét đến ngữ pháp**, tức **dừng khi đạt ngưỡng token tối thiểu** (giảm nhiễu nhưng vẫn giữ đủ cấu trúc xung quanh để thuận tiện cho việc đột biến).<sup>[[1]](#references)</sup>

Một quy tắc thực tế cho corpus trong fuzzing đột biến là: **ưu tiên một tập nhỏ các seed khác biệt về cấu trúc và tối đa hóa coverage** hơn là một tập lớn chứa nhiều mẫu gần như trùng lặp. Trên thực tế, thường cần làm như sau.<sup>[[1]](#references)[[3]](#references)</sup>

- Bắt đầu từ **các mẫu thực tế** (corpus công khai, dữ liệu thu thập bằng crawling, traffic đã ghi lại, các tập tin từ hệ sinh thái mục tiêu).
- Chắt lọc chúng bằng **cách rút gọn corpus dựa trên coverage**, thay vì giữ lại mọi mẫu hợp lệ.
- Giữ seed **đủ nhỏ** để các đột biến tác động đến những trường có ý nghĩa, thay vì dành phần lớn số lượt chạy cho các byte không liên quan.
- Chạy lại bước rút gọn corpus sau những thay đổi lớn về harness/instrumentation, vì corpus “tốt nhất” sẽ thay đổi khi khả năng tiếp cận thay đổi.

## Đột biến có xét đến phép so sánh đối với giá trị magic

Một lý do phổ biến khiến fuzzer chững lại không phải là cú pháp mà là **các phép so sánh nghiêm ngặt**: byte magic, kiểm tra độ dài, chuỗi enum, checksum hoặc giá trị điều phối parser được kiểm soát bằng `memcmp`, bảng switch hoặc chuỗi phép so sánh. Đột biến thuần túy ngẫu nhiên gây lãng phí lượt chạy khi cố đoán các giá trị này từng byte một.

Với các mục tiêu này, hãy dùng **tracing phép so sánh** (ví dụ: quy trình làm việc kiểu AFL++ `CMPLOG` / Redqueen) để fuzzer có thể quan sát các toán hạng từ những phép so sánh thất bại và ưu tiên đột biến hướng đến các giá trị thỏa mãn chúng.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Ghi chú thực tế:**

- Cách này đặc biệt hữu ích khi mục tiêu chặn logic chuyên sâu bằng **chữ ký tệp**, **động từ giao thức**, **thẻ kiểu** hoặc **bit tính năng phụ thuộc phiên bản**.
- Kết hợp với **từ điển** được trích xuất từ mẫu thực tế, đặc tả giao thức hoặc nhật ký debug. Một từ điển nhỏ gồm token ngữ pháp, tên chunk, động từ và dấu phân cách thường hữu ích hơn một wordlist chung khổng lồ.
- Nếu mục tiêu thực hiện nhiều bước kiểm tra tuần tự, hãy xử lý các phép so sánh “magic” sớm nhất trước, sau đó tối giản lại corpus thu được để các giai đoạn sau bắt đầu bằng những tiền tố đã hợp lệ.

## Fuzzing API tệp ẩn ngôn ngữ tên tệp

Một tham số có tên `filename`, `path` hoặc `URL` có thể là điểm đầu vào của một trình thông dịch thay vì chỉ tra cứu tệp theo nghĩa đen. Ví dụ: CFITSIO Extended Filename Syntax (EFS) đánh giá các bộ chọn đặt trong ngoặc vuông, biểu thức hàng/pixel, cột được tính toán, biểu đồ histogram và phép biến đổi trước khi trả về đối tượng đã mở; một số dạng còn tạo bản sao tạm thời. Khi lập bản đồ bề mặt tấn công, hãy phân loại từng API mở/nhập là **đường dẫn literal** hoặc **đường dẫn được diễn giải**, sau đó fuzz điểm đầu vào thực tế mà ứng dụng gọi.<sup>[[20]](#references)[[22]](#references)</sup>

Để xem các primitive SSRF, sao chép tệp và xử lý giao thức phát sinh từ đó—cũng như các API đường dẫn literal an toàn hơn—tham khảo [Các ngôn ngữ nhỏ trong tên tệp làm primitive SSRF/tệp](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Tách đối tượng nền khỏi chương trình được fuzz

Khi ngữ pháp nằm trong phần hậu tố tên tệp, chỉ thay đổi byte của tệp được tham chiếu sẽ bỏ sót parser. Thay vào đó, một harness nhỏ có thể đọc từng testcase dưới dạng chuỗi rồi truyền nó cho API mở được diễn giải; chiến dịch CFITSIO đã tiếp cận được hầu hết parser và evaluator EFS bằng cách gọi `fits_open_file()` ở chế độ chỉ đọc. Hãy giữ riêng các tệp nền hợp lệ để việc thay đổi tập trung vào ngôn ngữ bộ chọn/biểu thức thay vì liên tục làm hỏng đường dẫn cơ sở.<sup>[[22]](#references)</sup>

Dùng các seed sao cho mỗi seed tiếp cận một họ ngữ pháp khác nhau, sau đó tạo từ điển gọn từ cả đặc tả lẫn mã nguồn lexer/parser. Nếu độ bao phủ chững lại trong khi các đầu vào liên tục thất bại ở cùng một nhánh lỗi cú pháp, hãy giữ lại các tiền tố hợp lệ và bổ sung dấu phân cách, toán tử, từ khóa, tên hàm và tên trường tiêu biểu thay vì chỉ tăng thời gian thay đổi ngẫu nhiên.<sup>[[22]](#references)</sup>

Chạy harness cùng từ điển ngữ pháp, ví dụ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Hạn chế tác dụng phụ của harness "read-only"

Cờ thư viện read-only không đảm bảo testcase không gây tác dụng phụ: ngôn ngữ tên tệp có thể ghi lại input, tạo tệp output hoặc tạo các đối tượng tạm thời. Chiến dịch CFITSIO ban đầu đã phá hủy các tệp seed và để lại những tệp ngoài dự kiến trên hệ thống tệp, nên cần dọn dẹp và cô lập.<sup>[[22]](#references)</sup>

- Cấp cho mỗi worker một thư mục làm việc có thể hủy và một thư mục tạm riêng.
- Cung cấp bản sao của các tệp lưu trữ chuẩn; không bao giờ để target sửa đổi bản duy nhất trong corpus.
- Tắt quyền truy cập mạng trừ khi backend từ xa là mục tiêu dự kiến, đồng thời giới hạn các đường dẫn có thể ghi bằng container, mount namespace hoặc sandbox tương đương.
- Đặt lại thư mục sau mỗi lần chạy hoặc mỗi batch worker, và xem các thay đổi hệ thống tệp ngoài dự kiến là những phát hiện bổ sung.

### Vòng lặp từ crash đến patch rồi fuzz

Hãy phân cụm các crash trước khi sửa để hàng nghìn artifact không biến thành hàng nghìn tác vụ patch. Trong đánh giá CFITSIO, AFLTriage đã thu gọn tập crash ban đầu xuống còn một vài nguyên nhân gốc; advisory sau đó cho thấy các lỗi riêng biệt, bao gồm kiểm tra kích thước đích không chính xác, con trỏ cũ sau `realloc()`, lỗi số học và các đường dọn dẹp parser không an toàn.<sup>[[21]](#references)[[22]](#references)</sup>

1. Rút gọn một input đại diện cho mỗi cụm và tái hiện lỗi bằng AddressSanitizer.
2. Ghi lại chính xác thao tác truy cập gây lỗi, vị trí trong mã nguồn, lịch sử cấp phát/giải phóng và trạng thái parser khiến invariant bị vi phạm.
3. Áp dụng một patch ứng viên có phạm vi hẹp rồi build lại với cùng cấu hình coverage và sanitizer.
4. Chạy lại reproducer ban đầu **và mọi input trong cụm**; đồng thời bật phát hiện leak vì một bản sửa lỗi an toàn bộ nhớ có thể làm hỏng quyền sở hữu trên đường xử lý lỗi.
5. Chạy kiểm thử chức năng với tệp thực, rồi tiếp tục từ queue đã tích lũy (hoặc nhập lại queue đó nếu engine yêu cầu thư mục output mới sau khi binary thay đổi).
6. Lặp lại: loại bỏ crash nông đầu tiên thường giúp các seed hiện có tiến sâu hơn vào trạng thái parser.

LLM có thể đẩy nhanh bước 2 và soạn bản nháp cho bước 3 nếu được cung cấp input gây crash, báo cáo sanitizer, harness và mã nguồn liên quan, nhưng patch của nó vẫn chưa đáng tin cậy. Việc chạy lại sanitizer và các cổng kiểm thử hồi quy—không phải phần giải thích của model—mới quyết định bản sửa có được chấp nhận hay không.<sup>[[22]](#references)</sup>

## Phản hồi phong phú hơn khi Edge Coverage gộp các đường đi khác nhau

Edge coverage thông thường không thể phân biệt hai lần thực thi đi qua cùng một helper từ các caller khác nhau hoặc có tổ hợp nhánh khác nhau bên trong một hàm. Điều này quan trọng trong các decoder dùng chung, bộ điều phối giao thức và helper của interpreter, nơi **đường đi** tới một edge quyết định trạng thái hiện hành. Theo dõi ngây thơ mọi ngữ cảnh gọi cũng nguy hiểm: coverage map và queue có thể phình to. Vì vậy, nghiên cứu về fuzzing nhạy ngữ cảnh khuyến nghị chỉ tinh chỉnh các ngữ cảnh tiềm năng, thay vì xem toàn bộ call graph là nhạy ngữ cảnh.<sup>[[14]](#references)</sup>

Các bản AFL++ gần đây hỗ trợ **Ball-Larus per-function path coverage** bên cạnh edge coverage thông thường. Cơ chế này gán một feature cho mỗi đường đi không chu trình qua một hàm; các cạnh quay lại của vòng lặp bị loại bỏ, nên phản hồi này phân biệt được các tổ hợp nhánh nhưng **không phân biệt số lần lặp của vòng lặp**. Hãy bắt đầu với level `1` ít nghiêm ngặt, sau đó chỉ áp dụng các chế độ nghiêm ngặt hơn cho mã parser/máy trạng thái đáng ngờ vì số lượng đường đi có thể tăng theo cấp số nhân.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Với một helper được gọi từ nhiều vị trí liên quan đến bảo mật, chế độ LTO có thể kết hợp từng đường đi của hàm với vị trí gọi trực tiếp của nó:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Hướng dẫn chiến dịch:** áp dụng feedback phong phú hơn một cách thận trọng và theo dõi chi phí coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Chạy song song một phiên bản edge-coverage thông thường; feedback phong phú hơn chỉ hữu ích nếu chi phí map/queue tăng thêm không làm giảm số executions mỗi giây.
- Dùng `AFL_LLVM_ALLOWLIST` để giới hạn instrumentation path/caller khi các thư viện nhiều template hoặc mã tiện ích chung chiếm phần lớn map.
- Có thể bỏ qua các hàm có quá nhiều đường đi không chu trình bằng AFL++; cảnh báo trong quá trình biên dịch cho thấy target cần allowlist hoặc mức độ nghiêm ngặt thấp hơn.
- Caller + path coverage chỉ hỗ trợ một cấp caller. Không kết hợp tính năng này với context stack sâu hơn.
- Path ID có thể thay đổi giữa các phiên bản LLVM major. Giữ cố định toolchain trong suốt chiến dịch và không đồng bộ các corpus dựa trên PATH như thể feature ID của chúng ổn định giữa các bản build.
- Feedback này bổ trợ cho `CMPLOG`: comparison tracing giải quyết câu hỏi **giá trị nào vượt qua guard**, còn feedback path/caller ghi nhận **lộ trình và tổ hợp nhánh nào đã dẫn đến đó**.

## Stateful Fuzzing: Các chuỗi là seed

Đối với **protocol**, **workflow đã xác thực** và **parser nhiều giai đoạn**, đơn vị đáng quan tâm thường không phải là một blob đơn lẻ mà là một **chuỗi message**. Nối toàn bộ transcript vào một file rồi mutation một cách mù quáng thường kém hiệu quả, vì fuzzer mutation mọi bước như nhau, ngay cả khi chỉ message về sau mới đưa chương trình vào trạng thái dễ phát sinh lỗi.<sup>[[4]](#references)</sup>

Một phương pháp hiệu quả hơn là coi **chính chuỗi đó là seed** và dùng **trạng thái có thể quan sát** (mã phản hồi, trạng thái protocol, giai đoạn parser, kiểu object được trả về) làm feedback bổ sung.<sup>[[4]](#references)</sup>

- Giữ ổn định các **message tiền tố hợp lệ** và tập trung mutation vào message **điều khiển chuyển trạng thái**.
- Lưu cache các identifier và giá trị do server tạo ra từ những phản hồi trước đó khi bước tiếp theo phụ thuộc vào chúng.
- Ưu tiên mutation/splicing theo từng message thay vì mutation toàn bộ transcript đã tuần tự hóa như một blob không phân biệt cấu trúc.
- Nếu protocol cung cấp các mã phản hồi có ý nghĩa, hãy dùng chúng làm **state oracle** ít tốn kém để ưu tiên các chuỗi tiến sâu hơn.

Đây cũng là lý do các lỗi yêu cầu xác thực, chuyển trạng thái ẩn hoặc lỗi parser “chỉ xảy ra sau handshake” thường bị bỏ sót khi fuzzing theo kiểu file thông thường: fuzzer phải giữ nguyên **thứ tự, trạng thái và các quan hệ phụ thuộc**, chứ không chỉ cấu trúc.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing driver nhiều client

Edge coverage cao vẫn có thể bỏ sót lỗi IPC-driver vì coverage không mô tả **quyền sở hữu object, số lượng tham chiếu, message đang chờ xử lý, thứ tự cleanup hoặc các interleaving giữa thread**. Trang [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) trình bày mô hình object của driver; ví dụ này tập trung vào harness của fuzzer. Android Binder là một mô hình hữu ích: chỉ đi đến được cả đường cấp phát lẫn đường giải phóng là chưa đủ nếu fuzzer không thể khiến nhiều process thao tác trên cùng một object kernel theo đúng thứ tự cần thiết.<sup>[[15]](#references)</sup>

#### Mô hình hóa protocol, không phải các buffer `ioctl` riêng lẻ

Biểu diễn một test case dưới dạng grammar có thứ tự gồm **danh tính client + thao tác + đối số có cấu trúc**. Binder LKL fuzzer sử dụng protobuf và `libprotobuf-mutator`, với một client context-manager tồn tại lâu dài và hai client thông thường. Sau đó, semantic harness giữ nguyên các mối quan hệ mà mutation byte mù quáng sẽ phá hủy.<sup>[[15]](#references)</sup>

- Lưu cache các giá trị được trả về từ những thao tác trước đó. Ví dụ, `BC_FREE_BUFFER` phải dùng lại con trỏ transaction-buffer được một `ioctl` trước đó trả về.
- Tạo các reply mặc định hợp lệ để giao dịch đồng bộ có thể hoàn tất và các thao tác sau vẫn có thể được tiếp cận.
- Từ chối các chuyển trạng thái không thể xảy ra, chẳng hạn giao dịch với chính nó hoặc có nhiều giao dịch đang chờ cùng một target.
- Giữ trạng thái khởi tạo singleton bên ngoài phần reset theo từng input. Binder chỉ cho phép một lần đăng ký `BINDER_SET_CONTEXT_MGR` mỗi lần boot, nên liên tục hủy rồi tạo lại client đó sẽ khiến các input sau không hợp lệ.

Một mẫu race về vòng đời hữu ích là để một client chuyển giao object, bắt đầu cleanup thread hoặc process, đồng thời khiến client nhận giải phóng transaction buffer. Trong ví dụ CVE-2020-0423, việc chuyển giao `BINDER_TYPE_WEAK_BINDER`, sau đó để `BINDER_THREAD_EXIT` chạy đua với `BC_FREE_BUFFER`, có thể giải phóng một `binder_work` nhúng trong khi đường cleanup của thread đang thoát vẫn sử dụng nó.<sup>[[15]](#references)</sup>

#### Khôi phục các interleaving có kiểm soát trong kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) liên kết mã kernel thực vào một harness userspace và cung cấp syscall interface thông qua `lkl_syscall`. Nhờ đó, protobuf state, coverage và KASAN dễ dàng được điều phối trong cùng một process. Tuy nhiên, LKL thường chạy một syscall mà không có kernel thread nào khác ngắt quãng nó. Với các chiến dịch tìm race, hãy chèn các điểm `schedule()` quanh những ranh giới lock/unlock và vòng đời được chọn, rồi để harness chọn ngẫu nhiên client tiếp theo tại mỗi lần yield. Hãy đặt các điểm này có mục tiêu vì mỗi điểm đều làm tăng không gian tìm kiếm lịch thực thi. Randomized scheduler được các nhà nghiên cứu mô tả **không** thuộc upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build và phát lại các seed hồi quy đã tuần tự hóa

Harness upstream cố định một phiên bản `libprotobuf-mutator` tương thích, bật instrumentation fuzzing của LKL và KASAN bằng `LKL_FUZZING=1`, đồng thời bật `CONFIG_MMU` cho Binder bằng `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Sau khi checkout một bản sửa đổi cố ý có lỗ hổng hoặc áp dụng các bản vá rollback được ghi lại ở upstream, một seed đã serialize có thể tái hiện toàn bộ quá trình chuyển trạng thái nhiều client mà không cần dựng lại nó trong một PoC C tùy biến:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Coi lỗi use-after-free của KASAN là xác nhận rằng seed đã đi đến đường đi vòng đời dễ bị lỗi. Điều này **không** chứng minh các primitive tiếp theo cần thiết để thực thi mã trong kernel hoặc leo thang đặc quyền.<sup>[[16]](#references)</sup>

## Mẹo đa dạng hóa trên một máy (kiểu Jackalope)

Một cách thực tế để kết hợp **tính mới do sinh tạo** với **tái sử dụng coverage** là **khởi động lại các worker chạy trong thời gian ngắn** để kiểm thử một server liên tục hoạt động. Mỗi worker bắt đầu với corpus rỗng, đồng bộ sau `T` giây, chạy thêm `T` giây trên corpus đã được kết hợp, đồng bộ lần nữa rồi thoát. Cách này tạo ra **các cấu trúc mới trong mỗi thế hệ** đồng thời vẫn tận dụng coverage đã tích lũy.<sup>[[1]](#references)[[2]](#references)</sup>

**Máy chủ:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Worker tuần tự (vòng lặp ví dụ):**

<details>
<summary>Vòng lặp khởi động lại worker của Jackalope</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Ghi chú:**

- `-in empty` buộc sử dụng **corpus mới** ở mỗi lần tạo.
- `-server_update_interval T` mô phỏng **đồng bộ trễ** (ưu tiên novelty trước, tái sử dụng sau).
- Ở chế độ grammar fuzzing, **đồng bộ máy chủ ban đầu mặc định bị bỏ qua** (không cần `-skip_initial_server_sync`).
- Giá trị `T` tối ưu **phụ thuộc vào target**; thường hiệu quả nhất khi chuyển đổi sau khi worker đã tìm được phần lớn coverage “dễ”.

## Snapshot Fuzzing Cho Các Target Khó Tạo Harness

Khi đoạn mã bạn muốn kiểm thử chỉ có thể truy cập được **sau một quá trình thiết lập tốn kém** (khởi động VM, hoàn tất đăng nhập, nhận packet, phân tích container, khởi tạo dịch vụ), một lựa chọn thay thế hữu ích là **snapshot fuzzing**: chụp trạng thái process hoặc VM đã sẵn sàng, đưa từng test case vào đường dẫn input của target, thực thi cho đến khi xảy ra crash/timeout, rồi khôi phục snapshot. Cách này tránh lặp lại bước khởi tạo hoặc các tiền tố giao thức, hữu ích cho **dịch vụ mạng**, **firmware**, **bề mặt tấn công sau xác thực** và **target chỉ có binary**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Chạy target cho đến khi trạng thái cần khảo sát sẵn sàng.
2. Chụp snapshot **bộ nhớ + thanh ghi** tại thời điểm đó.
3. Với mỗi test case, ghi input đã đột biến trực tiếp vào buffer liên quan của guest/process.
4. Thực thi cho đến khi xảy ra crash/timeout/reset.
5. Khôi phục snapshot; với target VM, chỉ khôi phục **các trang bị thay đổi** nếu được hỗ trợ, rồi lặp lại.

Đặt snapshot càng gần bước parse/dispatch tốn kém đầu tiên càng tốt, chẳng hạn sau `recv`/`read` hoặc điểm giải tuần tự hóa packet, đồng thời ghi lại buffer input mà target sử dụng. Cách này tuân theo nguyên tắc bố trí thích ứng: dịch snapshot sâu hơn vào quá trình xử lý input để tránh lặp lại các công việc trước đó.<sup>[[11]](#references)</sup>

### Snapshot gia tăng cho các trạng thái giao thức

Snapshot cố định tránh được chi phí thiết lập, nhưng tự nó không khám phá được các chuyển trạng thái cần nhiều thông điệp hợp lệ. Harness LibAFL-Qemu có thể theo dõi các lần ghi vào trường trạng thái giao thức và lưu snapshot mới khi trạng thái thay đổi. Trong [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful), harness theo dõi `tcpcb.t_state`, băm trạng thái và các cờ phản hồi để loại bỏ snapshot trùng lặp, đồng thời lưu các trang bị thay đổi so với snapshot cha. Trước khi đột biến thông điệp có cấu trúc tiếp theo, harness khôi phục snapshot đã chọn thông qua chuỗi snapshot cha. Testcase lưu `SnapshotId` và các byte input được tạo (`gen_bytes`); snapshot manager theo dõi quan hệ cha cần thiết để replay.<sup>[[27]](#references)[[28]](#references)</sup>

`SnapshotModule` ở chế độ user-mode của LibAFL-Qemu lưu các mapping và bộ nhớ target nhưng không lưu thanh ghi CPU; khi cần, hãy bảo toàn chúng riêng. Manager được mô tả hỗ trợ một cây snapshot gốc và không thể chia sẻ snapshot ID giữa các worker. Chế độ multi-snapshot cũng không thể trực tiếp tái sử dụng trạng thái shadow QASAN. Để triage offline, hãy tái tạo chuỗi input trong một process được instrument riêng. Khi dùng `AsanHostModule` và `DrCovModule`, `fuzzer.evaluate_input` chạy các callback `pre_exec`/`post_exec` cần thiết; chỉ gọi `qemu.run` thì không chạy các callback này.<sup>[[27]](#references)[[28]](#references)</sup>

### Phát hiện đọc vượt quá logical ring buffer

Việc đọc vượt quá *số lượng dữ liệu hợp lệ* của buffer có thể vẫn nằm trong vùng cấp phát của host và thoát khỏi khả năng phát hiện của ASAN thông thường. Ví dụ dữ liệu urgent của libslirp [libslirp urgent-data example](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) cũng gây underflow cho số byte không dấu. Nếu có mã nguồn, instrumentation phát hiện tràn số nguyên có dấu/không dấu có thể phát hiện tác động phụ đó; hãy phân biệt hiện tượng wrap số thứ tự TCP có chủ đích trước khi bỏ qua báo cáo. Một oracle mạnh hơn được đề xuất là poison vùng cấp phát ring tùy chỉnh, chỉ unpoison các vùng hợp lệ khi allocator nội bộ tiến lên, rồi poison lại các vùng đã giải phóng. LibAFL-Qemu cung cấp API poisoning ASAN cho các target khó instrument từ mã nguồn.<sup>[[27]](#references)</sup>

## Khảo sát Race Trong Linux Kernel Với MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) biến các race trong Linux kernel nhạy với timing thành các lịch truy cập bộ nhớ có thể lặp lại. Công cụ có thể tự động liệt kê các lần thực thi **A-B-A** với hai context, hoặc cho phép chuyên gia đặt các ràng buộc thứ tự trong terminal UI/GUI. Đây là công cụ nghiên cứu thử nghiệm, không phải một concurrency fuzzer hoàn chỉnh: hiện tại công cụ cần LLVM 23+ và kernel đã được vá của dự án; các công cụ dòng lệnh hỗ trợ hai test thread; còn lớp fuzzing userspace được đề xuất thì chưa được triển khai.<sup>[[17]](#references)[[18]](#references)</sup>

### Thu thập các điểm giao tiếp giữa các context

Build kernel đã instrument với các callback KASAN outline và hỗ trợ ghi nhận bộ nhớ KCOV đã được vá. README của dự án cũng khuyến nghị tắt tối ưu hóa sibling-call để call stack vẫn có thể sử dụng được.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) chuyển các truy cập được instrument thành lời gọi helper. Các bản vá kernel MAccConc tắt `asan-opt-same-temp` để các truy cập liên tiếp không bị gộp; cũng tắt tối ưu hóa `asan-opt-globals` khi cần phát hiện race trên biến toàn cục. KCOV chuyển các bản ghi thu được đến userspace. So sánh các truy cập từ những ngữ cảnh thực thi khác nhau và giữ lại các cặp có vùng byte chồng lấp, trong đó ít nhất một phía ghi; xem `kfree()` như một thao tác ghi để các chuyển đổi vòng đời cũng trở thành ứng viên.<sup>[[17]](#references)</sup>

Với công việc thoát khỏi task khởi tạo, chẳng hạn xử lý packet hoặc callback RCU, subsystem phải truyền tiếp remote-coverage handle của KCOV. Remote KCOV upstream là tính năng tùy chọn và không tự động khả dụng cho các công việc nền bất kỳ, nên việc không truyền handle có thể khiến một tương tác thực sự không được phát hiện.<sup>[[17]](#references)[[19]](#references)</sup>

### Xác định cùng một truy cập động trong mọi lần chạy

Không phát lại dựa trên địa chỉ heap cụ thể, vì địa chỉ có thể thay đổi sau mỗi lần cấp phát, hoặc chỉ dựa trên địa chỉ lệnh, vì địa chỉ này không đủ phân biệt trong các helper như `memcpy()` và `spin_lock()`. MAccConc sử dụng **stack trace có bổ sung bộ đếm**: mỗi frame xác định một callee cùng số lần gọi bên trong caller của nó, còn phần tử cuối xác định lệnh truy cập bộ nhớ. Các bản ghi vào/ra hàm của SanitizerCoverage cho phép userspace dựng lại định danh động này; định danh vẫn ổn định khi địa chỉ thay đổi và khi có nhiễu từ luồng điều khiển không liên quan.<sup>[[17]](#references)</sup>

### Chuyển các cặp ứng viên thành lịch thực thi cưỡng bức

Ioctl đã vá `KCOV_SET_DI` gắn một định danh truy cập có bổ sung bộ đếm với một hành động trên cờ dùng chung.<sup>[[17]](#references)</sup>

| Hành động | Ngữ nghĩa |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Đặt cờ *N* ngay trước truy cập được chọn. |
| `DI_STACK_WAIT` | Trước truy cập được chọn, quay vòng chờ đến khi cờ *N* được đặt hoặc hết giới hạn đã cấu hình. |
| `DI_STACK_WAKE_POST` | Đặt cờ *N* ngay sau truy cập được chọn. |

Với ràng buộc **A xảy ra trước B** một phần, gắn `DI_STACK_WAKE_POST` cho A và `DI_STACK_WAIT` cho B bằng cùng một cờ. Với lịch thực thi hai ngữ cảnh được chỉ định đầy đủ, bắt đầu bằng cách chặn B, sau đó để A đánh thức B và chờ tại điểm chuyển giao đầu tiên; tại điểm chuyển giao tiếp theo, B thực hiện thao tác ngược lại. Cách sau hoạt động như chuyển đổi ngữ cảnh xác định và được trình khám phá A-B-A tự động sử dụng.<sup>[[17]](#references)</sup>

Một chiến dịch tối thiểu là biên dịch test case bốn hook (`test_setup`, hai hàm thread và `test_end`) thành thư viện dùng chung, thu thập trace không có ràng buộc, rồi liệt kê các ứng viên A-B-A hoặc thêm ràng buộc thủ công quanh những truy cập đáng ngờ.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Diễn giải riêng các lần timeout với những lần sắp xếp lại thành công: thứ tự được yêu cầu có thể là bất khả thi vì một khóa hoặc phụ thuộc khởi tạo/công bố ngăn context thứ hai đi đến điểm injection. Cũng cần lưu ý các điểm mù của KASAN: truy cập trực tiếp vào stack thường không được hook, trừ khi có thể vượt ngoài giới hạn; biến toàn cục bị bỏ qua với cấu hình tối ưu hóa mặc định; và các compiler hiện tại không thể đồng thời tạo hook ASAN và TSAN. Ngoài ra, prototype mất buffer KCOV khi guest bị panic, vì vậy hãy duy trì một console/oracle sự cố độc lập.<sup>[[17]](#references)</sup>

Để fuzzing có hướng dẫn theo concurrency trong tương lai, hãy ghi lại tóm tắt truy cập bộ nhớ theo từng input hoặc syscall, ghép các thao tác có thể tạo thành điểm giao tiếp giữa các context, rồi chỉ khảo sát những tổ hợp đó. VM snapshot giúp ổn định trạng thái toàn cục và địa chỉ; nếu không dùng snapshot, metadata của vị trí cấp phát có thể trừu tượng hóa các object qua nhiều lần chạy. Đây là một phần mở rộng được đề xuất, không phải tính năng của các công cụ userspace MAccConc hiện tại.<sup>[[17]](#references)</sup>

## Phân tích nội quan Harness: Phát hiện sớm các Fuzzer nông

Khi một chiến dịch bị đình trệ, vấn đề thường không nằm ở mutator mà ở **harness**. Dùng **phân tích khả năng tiếp cận/độ bao phủ** để tìm các hàm có thể được gọi tĩnh từ fuzz target nhưng hiếm khi hoặc chưa bao giờ được bao phủ khi chạy thực tế. Những hàm đó thường chỉ ra một trong ba vấn đề sau.<sup>[[12]](#references)</sup>

- Harness đi vào target quá muộn hoặc quá sớm.
- Seed corpus thiếu hẳn một nhóm tính năng.
- Target thực sự cần **harness thứ hai** thay vì một harness “làm mọi thứ” quá cồng kềnh.

Nếu bạn dùng quy trình kiểu OSS-Fuzz / ClusterFuzz, Fuzz Introspector có thể so sánh khả năng tiếp cận tĩnh với độ bao phủ khi chạy thực tế và tạo báo cáo từ một lần chạy có giới hạn thời gian hoặc corpus công khai.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Dùng báo cáo để quyết định có nên thêm harness mới cho một đường đi parser chưa được kiểm thử, mở rộng corpus cho một tính năng cụ thể hay chia một harness nguyên khối thành các entry point nhỏ hơn.

## Chọn mục tiêu fuzz theo đồ thị trước và phân loại mutation sau

Nếu bạn đã có **các phát hiện từ phân tích tĩnh**, **các mutant còn sống sót sau kiểm thử mutation** và **báo cáo coverage**, đừng phân loại chúng thành các danh sách độc lập. Trước tiên, hãy xây dựng **call graph**, chú thích các node bằng **cyclomatic complexity**, **khả năng tiếp cận từ entrypoint/đầu vào không đáng tin cậy** và mọi phát hiện bên ngoài, sau đó đặt câu hỏi về đồ thị.<sup>[[5]](#references)[[6]](#references)</sup>

- Những hàm có độ phức tạp cao nào có thể được truy cập từ đầu vào không đáng tin cậy?
- Các mutant còn sống sót nào nằm trên đường đi từ parser/handler đến mã quan trọng về bảo mật?
- Những hàm nào là điểm nghẽn kiến trúc có **blast radius** lớn bất thường?

Cách này thường giúp phát hiện mục tiêu fuzz tốt hơn việc chỉ dựa vào "coverage thấp nhất". Một parser/decoder có **độ phức tạp cao** và đã xác nhận **có thể được truy cập từ bên ngoài** là ứng viên harness tốt hơn một helper nội bộ riêng lẻ có coverage thấp nhưng không có đường đi do kẻ tấn công kiểm soát.

### Quy trình phân loại thực tế

1. Xây dựng **đồ thị mã** từ codebase và trích xuất các chỉ số độ phức tạp/nhánh cho từng hàm.
2. Liệt kê các **entrypoint** nhận đầu vào do kẻ tấn công kiểm soát: request handler, decoder, importer, protocol parser, trình đọc CLI/file.
3. Chạy truy vấn đường đi từ các entrypoint đó đến các hàm ứng viên để phân biệt bề mặt tấn công có thể truy cập với mã chết/chỉ dùng nội bộ.
4. Ưu tiên các node kết hợp:
   - **cyclomatic complexity** cao
   - đã xác nhận **có thể truy cập từ đầu vào không đáng tin cậy**
   - **blast radius** lớn hoặc có nhiều thành phần phụ thuộc phía sau
   - có bằng chứng hỗ trợ như phát hiện **SARIF**, ghi chú kiểm toán hoặc mutant còn sống sót
5. Trước tiên, viết harness tập trung cho các node có điểm cao nhất, đặc biệt là **parser/codec** như bộ giải mã hex/Base64/IP/message.

### Mutant còn sống sót: tương đương hay có thể xử lý

Kiểm thử mutation thường tạo ra một danh sách mutant còn sống sót khá nhiễu. Trước khi xem mỗi mutant còn sống sót là một lỗ hổng bảo mật, hãy dùng đồ thị để đặt câu hỏi:

- Hàm bị đột biến có thể được truy cập từ entrypoint do kẻ tấn công kiểm soát không?
- Tất cả đường gọi có bị ràng buộc bởi các invariant mạnh hơn so với kiểm tra đã bị đột biến không?
- Node đó nằm trong mã chết, logic chỉ định dạng hay trong đường xử lý số học/parser có tác động lớn?

Các mutant còn sống sót nhưng không thể truy cập hoặc bị ràng buộc về cấu trúc thường là **mutant tương đương**. Các mutant còn **có thể truy cập** và tác động đến **điều kiện biên**, **đường tràn/carry** hoặc **phân tích cú pháp/số học quan trọng về bảo mật** nên được đưa vào:

- harness fuzz mới
- kiểm thử property/invariant trực tiếp
- các vector edge case có mục tiêu

### Đối chiếu các phát hiện bên ngoài lên đồ thị

Nếu pipeline SAST xuất **SARIF**, hãy ánh xạ các phát hiện lên node đồ thị theo **file + phạm vi dòng** rồi dùng đồ thị để mở rộng đánh giá tác động.<sup>[[6]](#references)</sup>

- tính **blast radius** của hàm bị gắn cờ
- kiểm tra xem phát hiện đó có nằm trên đường đi nào từ một entrypoint không
- nhóm các phát hiện gần nhau cùng quy về một điểm nghẽn

Cách này hữu ích khi quyết định có nên dành thời gian fuzz cho một hàm cụ thể hay không: một node **có thể truy cập**, **phức tạp** và đã có **phát hiện SAST** thường là mục tiêu tốt hơn một node chỉ phức tạp nhưng không có đường đi từ đầu vào của kẻ tấn công.

Ví dụ quy trình với Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

Phương pháp luận quan trọng là phần giao nhau: **độ phức tạp x mức độ phơi lộ x tác động**. Dùng biểu đồ để chọn các mục tiêu fuzz có giá trị bảo mật kỳ vọng cao nhất, sau đó dùng các trường hợp sống sót sau mutation để xác định những ranh giới và bất biến mà harness của bạn cần kiểm thử căng thẳng.<sup>[[5]](#references)</sup>

## Fuzzing vi sai các encoding khóa mật mã

Bắt đầu từ các khóa đã được serialize hợp lệ hoặc các test vector tiêu chuẩn. Mutation các trường đã encode mà không phá vỡ độ dài và cấu trúc cần thiết để đi đến các đường xử lý import và operation, rồi gửi cùng một byte đến các implementation độc lập. So sánh kết quả chấp nhận và lỗi. Chữ ký và ciphertext ngẫu nhiên cần oracle kiểm tra tính đúng đắn, chứ không phải so sánh từng byte: xác minh chữ ký hoặc so sánh shared secret từ một vòng encapsulation/decapsulation. Test vector xác lập tính tuân thủ cho các trường hợp đã biết; differential mutation thăm dò các encoding sai định dạng nằm ngoài phạm vi đó.<sup>[[23]](#references)[[26]](#references)</sup>

Với các định dạng khóa này, hãy dùng oracle đặc thù cho từng định dạng:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA expanded signing keys:** thay đổi các hệ số `s1` hoặc `s2` đã đóng gói để chúng nằm ngoài `[-η, η]`, đồng thời vẫn giữ cho khóa có thể parse. Kiểm tra xem quá trình import hoặc signing có từ chối khóa không và chữ ký tạo ra có xác minh được không. Việc khác biệt trong chấp nhận khóa không tự nó cấu thành vi phạm tiêu chuẩn, vì FIPS 204 không bắt buộc phải có các bước kiểm tra khóa riêng bổ sung. Xem [cơ chế rò rỉ có điều kiện](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM key pairs:** phân biệt các bước kiểm tra bắt buộc đối với khóa encapsulation và đầu vào decapsulation với bước kiểm tra tính nhất quán theo cặp (PCT) không bắt buộc đối với một cặp khóa được import. Thực hiện encapsulate bằng khóa công khai, decapsulate bằng khóa riêng, rồi so sánh shared secret; kết quả không khớp có thể làm gián đoạn liên lạc được mã hóa ngay cả khi từng khóa vượt qua bước kiểm tra đầu vào. Kiểm tra xem API xác thực đầu vào trong operation hay thông qua một lệnh gọi riêng; libcrux cung cấp `validate_public_key(pk)` và `validate_private_key(sk, ct)`, nhưng các hàm này không thay thế PCT.
- **XMSS/XMSSMT raw keys:** kiểm thử vòng lặp serialize và deserialize khóa **signing và verifying** trên nhiều bộ tham số, chứ không chỉ kiểm thử operation với khóa trong bộ nhớ. XMSS và XMSSMT có các namespace OID bốn byte riêng biệt, vì vậy parser chỉ kiểm tra OID và thử XMSS trước có thể phân loại nhầm khóa XMSSMT có OID trùng khớp rồi từ chối import. Parser RustCrypto được đề cập minh họa lỗi tương thích liên vận/khả dụng, không phải giả mạo chữ ký.

## Fuzzing Go với gosentry: Engine mạnh hơn, đầu vào có kiểu và kiểm tra vi sai

Nếu mục tiêu Go đã có harness `testing.F` gốc, một lộ trình nâng cấp thiết thực là chạy cùng harness đó với [gosentry](https://github.com/trailofbits/gosentry), một fork của Go toolchain vẫn giữ `go test -fuzz` nhưng thay backend bằng **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Điều này hữu ích khi Go fuzzer tích hợp bị khựng ở **các phép so sánh khó**, **đầu vào có kiểu** hoặc **các định dạng nặng về parser**. Phương pháp vẫn như cũ:

- Tiếp tục dùng `f.Add(...)` cho seed và `f.Fuzz(...)` cho callback.
- Dùng lại cùng harness, nhưng chạy bằng binary `go` của gosentry thay vì toolchain mặc định.
- Coi chiến dịch này như một lần chạy thông thường có hướng dẫn coverage, nhưng sử dụng cơ chế lập lịch/đột biến của LibAFL và các detector bổ trợ tốt hơn.

### Biến lỗi im lặng thành fuzz finding

Một vấn đề thường gặp trong các đợt đánh giá Go là hành vi nguy hiểm thường **không gây crash theo mặc định**. Với gosentry, bạn có thể biến một số trạng thái “xấu nhưng im lặng” thành finding.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` để khiến các đường đi ghi log/xử lý lỗi được chọn hoạt động như crash (hữu ích với các đường đi kiểu `log.Fatal`, vốn chỉ ghi log rồi tiếp tục).
- `--catch-races=true` để chạy lại các mục hàng đợi vừa phát hiện bằng Go race detector.
- `--catch-leaks=true` để chạy lại các mục hàng đợi mới bằng `goleak` và dừng khi phát hiện goroutine bị leak.
- Cơ chế xử lý hang của LibAFL giúp giữ **vòng lặp vô hạn / đầu vào rất chậm** dưới dạng fuzz finding thay vì để chúng biến mất như các timeout.
- Mặc định có sẵn kiểm tra tràn số học, cùng các kiểm tra cắt cụt tùy chọn thông qua instrumentation kiểu go-panikint.

Điều này đặc biệt hữu ích với các target mà tác động bảo mật là **lỗi parser không gây panic**, **lỗi đồng thời** hoặc **hang chỉ gây DoS**, thay vì hỏng bộ nhớ.

### Fuzzing nhận biết struct cho các Go API có kiểu

Go fuzzing tích hợp chủ yếu hướng đến các giá trị vô hướng như `[]byte`, `string` và số. Nếu mã đang kiểm thử nhận các đối tượng có kiểu, gosentry có thể fuzz trực tiếp **các giá trị phức hợp** (struct, slice, array, pointer) trong khi vẫn đột biến các byte bên dưới.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Hãy dùng cách này khi việc tạo một wire format giả chỉ dành cho fuzzing sẽ che khuất các lỗi logic phía sau phần mã parsing chỉ có trong harness. Với các chiến dịch differential hoặc dựa trên grammar, hãy giữ đầu vào của harness ở dạng một `[]byte` hoặc `string` duy nhất và thực hiện parsing bên trong callback.

### Fuzzing dựa trên grammar cho parser và đầu vào giao thức

Với parser, định dạng và ngôn ngữ đầu vào, gosentry có thể chạy **Nautilus grammar fuzzing** trên LibAFL. Grammar là một mảng JSON gồm các quy tắc sinh, và harness thường nên nhận một đối số `[]byte` hoặc `string` duy nhất.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Ghi chú về phương pháp:

- Dùng grammar mode khi các mutation ở cấp byte phần lớn bị loại ở những bước kiểm tra cú pháp ban đầu.
- Giữ grammar tập trung vào **tập con liên quan đến bảo mật** của ngôn ngữ/giao thức thay vì mô hình hóa toàn bộ đặc tả.
- Dùng các giá trị biên lớn trong terminal/nonterminal để kiểm tra các điểm biên của số nguyên, độ dài và máy trạng thái.
- Grammar mode giữ cho đầu vào hợp lệ theo grammar, nhưng target vẫn nhận **bytes/strings**, vì vậy việc phân tích cú pháp và kiểm tra ngữ nghĩa vẫn diễn ra bên trong mã được harness.

### Differential fuzzing: so sánh các triển khai, không chỉ các crash

Một phương pháp hiệu quả trong hệ sinh thái Go là **differential fuzzing dựa trên grammar**: tạo đầu vào có cấu trúc hợp lệ rồi đưa chúng vào hai parser, client hoặc engine chuyển trạng thái.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Hãy xem những trường hợp sau là phát hiện:

- một implementation bị panic trong khi implementation còn lại từ chối input một cách an toàn
- input được chấp nhận/từ chối không đồng nhất
- parse tree hoặc đối tượng đã giải mã khác nhau
- state transition, nonce, số dư hoặc state root khác nhau

Đây là cách thực tế để phát hiện **sự không khớp về đồng thuận**, **sự mơ hồ của parser** và **độ lệch giữa đặc tả với implementation** mà fuzzing chỉ tập trung vào crash thường bỏ sót.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tái sử dụng corpus của campaign để báo cáo coverage

Sau một campaign, chạy lại corpus queue đã lưu để tạo báo cáo coverage của Go mà không cần xuất corpus riêng theo cách thủ công.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Chạy lệnh từ **cùng package** và với cùng mục tiêu `-fuzz` để gosentry phân giải đúng trạng thái campaign đã lưu trong cache.

## References

- [1] [Fuzzing ngữ pháp đột biến](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ chuyên sâu](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet sau năm năm: Về Fuzzing giao thức theo hướng dẫn coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark biến code thành đồ thị](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing còn thiếu một nửa bộ công cụ. Chúng tôi fork toolchain để khắc phục.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer Greybox tốc độ cao cho các giao thức mạng có trạng thái, sử dụng snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Không có grammar, không thành vấn đề: Hướng tới Fuzzing Linux kernel mà không cần mô tả system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing hiệu quả với snapshot thích ứng và có thể thay đổi](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM của AFL++: coverage đường dẫn và caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing nhạy theo ngữ cảnh có tính dự đoán](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer Android Binder của LKL - tài liệu build và seed hồi quy](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Khám phá điều kiện race trong Linux kernel bằng cách kiểm soát thứ tự xen kẽ truy cập bộ nhớ](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage code cho Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Cú pháp tên tệp mở rộng của CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Thông báo bảo mật của Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing cú pháp tên tệp mở rộng của CFITSIO: 16 lỗ hổng an toàn bộ nhớ và phân loại hỗ trợ bởi Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing vi sai cho mật mã học](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Tiêu chuẩn cơ chế đóng gói khóa dựa trên mạng mô-đun](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Lỗi phân tích OID XMSSMT - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Tình hình triển khai mật mã hậu lượng tử](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Dùng snapshot để tìm ra CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
{{#include ../banners/hacktricks-training.md}}
