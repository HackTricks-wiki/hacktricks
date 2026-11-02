# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

Trong **mutational grammar fuzzing**, các input được mutation nhưng vẫn **hợp lệ theo grammar**. Ở chế độ coverage-guided, chỉ những sample kích hoạt **coverage mới** mới được lưu làm corpus seed. Với **các target ngôn ngữ** (parser, interpreter, engine), cách này có thể bỏ sót các bug cần đến **chuỗi semantic/dataflow**, trong đó output của một cấu trúc trở thành input của cấu trúc khác.<sup>[[1]](#references)</sup>

**Failure mode:** fuzzer tìm được các seed lần lượt thực thi `document()` và `generate-id()` (hoặc các primitive tương tự), nhưng **không giữ lại dataflow được nối chuỗi**, nên sample “gần bug hơn” bị loại vì không bổ sung coverage. Khi có **từ 3 bước phụ thuộc trở lên**, việc recombination ngẫu nhiên trở nên tốn kém và feedback từ coverage không hướng dẫn được quá trình tìm kiếm.<sup>[[1]](#references)</sup>

**Hệ quả:** với các grammar có nhiều dependency, hãy cân nhắc **kết hợp các giai đoạn mutational và generative** hoặc thiên về các pattern **function chaining** (không chỉ dựa trên coverage).<sup>[[1]](#references)</sup>

## Các vấn đề về độ đa dạng của corpus

Mutation có hướng dẫn bởi coverage mang tính **tham lam**: sample tạo coverage mới được lưu ngay, thường vẫn giữ nguyên nhiều vùng lớn. Theo thời gian, corpus trở thành các **bản gần trùng lặp** với độ đa dạng cấu trúc thấp. Minimize quá mạnh có thể loại bỏ context hữu ích, vì vậy một giải pháp dung hòa thiết thực là **minimization có nhận biết grammar**, **dừng khi đạt ngưỡng token tối thiểu** (giảm nhiễu nhưng vẫn giữ đủ cấu trúc xung quanh để thuận tiện cho mutation).<sup>[[1]](#references)</sup>

Một quy tắc thực tế cho corpus trong mutational fuzzing là: **ưu tiên một tập nhỏ các seed khác biệt về cấu trúc và tối đa hóa coverage** thay vì một tập lớn các bản gần trùng lặp. Trên thực tế, thường cần làm như sau.<sup>[[1]](#references)[[3]](#references)</sup>

- Bắt đầu từ **sample thực tế** (corpus công khai, dữ liệu thu thập bằng crawling, traffic đã capture, các tập file từ hệ sinh thái của target).
- Tinh giản chúng bằng **corpus minimization dựa trên coverage**, thay vì giữ lại mọi sample hợp lệ.
- Giữ seed **đủ nhỏ** để mutation tác động vào các field có ý nghĩa, thay vì dành phần lớn chu kỳ cho các byte không liên quan.
- Chạy lại corpus minimization sau những thay đổi lớn về harness/instrumentation, vì corpus “tốt nhất” sẽ thay đổi khi khả năng reachability thay đổi.

## Mutation nhận biết phép so sánh đối với các giá trị magic

Một lý do phổ biến khiến fuzzer chững lại không phải là syntax mà là **các phép so sánh nghiêm ngặt**: byte magic, kiểm tra độ dài, chuỗi enum, checksum hoặc giá trị dispatch của parser được kiểm soát bởi `memcmp`, bảng switch hoặc các phép so sánh nối tiếp. Mutation ngẫu nhiên thuần túy lãng phí chu kỳ để thử đoán các giá trị này từng byte một.

Với các target này, hãy dùng **comparison tracing** (ví dụ: workflow kiểu AFL++ `CMPLOG` / Redqueen) để fuzzer quan sát được các toán hạng từ những phép so sánh thất bại và điều chỉnh mutation theo hướng đáp ứng các phép so sánh đó.<sup>[[3]](#references)</sup>

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

- Cách này đặc biệt hữu ích khi mục tiêu chặn logic chuyên sâu sau **chữ ký tệp**, **động từ giao thức**, **thẻ kiểu** hoặc **bit tính năng phụ thuộc phiên bản**.
- Kết hợp với **từ điển** trích xuất từ mẫu thực tế, đặc tả giao thức hoặc nhật ký debug. Một từ điển nhỏ gồm token ngữ pháp, tên chunk, động từ và dấu phân cách thường hữu ích hơn một wordlist chung khổng lồ.
- Nếu mục tiêu thực hiện nhiều bước kiểm tra tuần tự, hãy xử lý các phép so sánh “magic” đầu tiên, sau đó tiếp tục thu gọn corpus thu được để các giai đoạn sau bắt đầu bằng những tiền tố đã hợp lệ.

## Fuzzing các API tệp ẩn một ngôn ngữ filename

Một tham số có tên `filename`, `path` hoặc `URL` có thể là điểm vào của một trình thông dịch chứ không phải thao tác tra cứu tệp thông thường. Ví dụ: CFITSIO Extended Filename Syntax (EFS) đánh giá các bộ chọn đặt trong ngoặc vuông, biểu thức hàng/pixel, cột được tính toán, histogram và phép biến đổi trước khi trả về đối tượng đã mở; một số dạng còn tạo các bản sao tạm thời. Khi lập bản đồ bề mặt tấn công, hãy phân loại từng API mở/nhập là **literal-path** hoặc **interpreted-path**, sau đó fuzz điểm vào production mà ứng dụng thực sự gọi.<sup>[[20]](#references)[[22]](#references)</sup>

Để tìm hiểu các primitive SSRF, sao chép tệp và trình xử lý giao thức phát sinh từ đó — cùng các API literal-path an toàn hơn — xem [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Tách đối tượng nền khỏi chương trình được fuzz

Khi ngữ pháp nằm trong hậu tố filename, chỉ thay đổi byte của tệp được tham chiếu sẽ bỏ sót parser. Thay vào đó, một harness nhỏ có thể đọc từng testcase dưới dạng chuỗi rồi truyền nó cho API mở interpreted; chiến dịch CFITSIO đã tiếp cận hầu hết parser và evaluator EFS bằng cách gọi `fits_open_file()` ở chế độ chỉ đọc. Hãy chuẩn bị riêng các tệp nền hợp lệ để những thay đổi có thể tập trung vào ngôn ngữ bộ chọn/biểu thức, thay vì liên tục làm hỏng đường dẫn cơ sở.<sup>[[22]](#references)</sup>

Dùng các seed để mỗi seed tiếp cận một nhóm ngữ pháp khác nhau, sau đó tạo một từ điển gọn từ cả đặc tả lẫn mã nguồn lexer/parser. Nếu độ bao phủ chững lại trong khi input liên tục thất bại tại cùng một nhánh lỗi cú pháp, hãy giữ lại các tiền tố hợp lệ và bổ sung dấu phân cách, toán tử, từ khóa, tên hàm cùng các tên trường tiêu biểu, thay vì chỉ tăng thời gian mutation ngẫu nhiên.<sup>[[22]](#references)</sup>

Chạy harness với từ điển ngữ pháp, ví dụ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Hạn chế tác dụng phụ từ harness "read-only"

Cờ thư viện read-only không đảm bảo testcase không gây tác dụng phụ: ngôn ngữ tên tệp có thể viết lại input, tạo tệp đầu ra hoặc tạo các đối tượng tạm thời. Chiến dịch CFITSIO ban đầu đã phá hủy các tệp seed và để lại những tệp ngoài dự kiến trên hệ thống tệp, nên cần dọn dẹp và cô lập.<sup>[[22]](#references)</sup>

- Cấp cho mỗi worker một working directory có thể loại bỏ và một thư mục tạm riêng.
- Cung cấp bản sao của các tệp nền chuẩn; không bao giờ để target sửa đổi bản duy nhất trong corpus.
- Tắt quyền truy cập mạng trừ khi backend từ xa là mục tiêu cần kiểm thử, đồng thời giới hạn các đường dẫn có thể ghi bằng container, mount namespace hoặc sandbox tương đương.
- Đặt lại thư mục sau mỗi lần thực thi hoặc mỗi batch worker, và xem mọi thay đổi hệ thống tệp ngoài dự kiến là phát hiện bổ sung.

### Vòng lặp crash-to-patch-to-fuzz

Phân cụm crash trước khi sửa để hàng nghìn artifact không biến thành hàng nghìn tác vụ patch. Trong đợt đánh giá CFITSIO, AFLTriage đã rút gọn tập crash ban đầu còn một vài nguyên nhân gốc; advisory sau đó cho thấy các lỗi riêng biệt, gồm kiểm tra sai kích thước đích, con trỏ cũ sau `realloc()`, lỗi số học và các đường dọn dẹp parser không an toàn.<sup>[[21]](#references)[[22]](#references)</sup>

1. Rút gọn một input đại diện cho mỗi cụm và tái hiện lỗi bằng AddressSanitizer.
2. Ghi lại chính xác thao tác truy cập gây lỗi, vị trí trong mã nguồn, lịch sử cấp phát/giải phóng và trạng thái parser khiến invariant không còn đúng.
3. Áp dụng một patch thử nghiệm có phạm vi hẹp và build lại với cùng cấu hình instrumentation cho coverage và sanitizer.
4. Chạy lại reproducer ban đầu **và mọi input trong cụm**; đồng thời bật phát hiện leak vì một bản sửa lỗi an toàn bộ nhớ có thể làm hỏng việc quản lý quyền sở hữu trên đường xử lý lỗi.
5. Chạy các bài kiểm thử chức năng bằng tệp thực, rồi tiếp tục từ queue đã tích lũy (hoặc nhập lại queue đó nếu engine yêu cầu thư mục output mới sau khi binary thay đổi).
6. Lặp lại: loại bỏ crash nông đầu tiên thường giúp các seed hiện có đi sâu hơn vào trạng thái parser.

LLM có thể đẩy nhanh bước 2 và soạn bản nháp cho bước 3 khi được cung cấp input gây crash, báo cáo sanitizer, harness và mã nguồn liên quan, nhưng patch của nó vẫn chưa đáng tin cậy. Việc chạy lại bằng sanitizer và các cổng kiểm thử hồi quy—không phải lời giải thích của model—mới quyết định bản sửa có được chấp nhận hay không.<sup>[[22]](#references)</sup>

## Phản hồi phong phú hơn khi Edge Coverage gộp các đường đi khác nhau

Edge coverage thông thường không phân biệt được hai lần thực thi đi qua cùng một helper nhưng được gọi từ các caller khác nhau hoặc chọn những tổ hợp nhánh khác nhau bên trong một hàm. Điều này quan trọng trong các bộ giải mã dùng chung, bộ điều phối protocol và helper của interpreter, nơi **đường đi** dẫn đến một edge quyết định trạng thái đang hoạt động. Theo dõi mọi calling context theo cách ngây thơ cũng rất nguy hiểm: coverage map và queue có thể phình to ngoài kiểm soát. Vì vậy, nghiên cứu về fuzzing nhạy theo context khuyến nghị chỉ tinh chỉnh các context tiềm năng thay vì áp dụng tính nhạy theo context cho toàn bộ call graph.<sup>[[14]](#references)</sup>

Các bản AFL++ gần đây cung cấp **Ball-Larus per-function path coverage** bên cạnh edge coverage thông thường. Cơ chế này gán một feature cho mỗi đường đi không chu trình qua một hàm; các loop back-edge bị loại bỏ, nên phản hồi này phân biệt được tổ hợp nhánh nhưng **không phân biệt số lần lặp vòng lặp**. Hãy bắt đầu với level `1` ít nghiêm ngặt hơn, rồi chỉ áp dụng các chế độ nghiêm ngặt hơn cho mã parser/state-machine đáng ngờ vì số lượng đường đi có thể tăng theo cấp số nhân.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Đối với một helper được gọi từ nhiều vị trí liên quan đến bảo mật, chế độ LTO có thể kết hợp từng đường dẫn hàm với vị trí gọi trực tiếp của nó:<sup>[[13]](#references)</sup>

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

**Hướng dẫn cho campaign:** áp dụng feedback phong phú hơn một cách thận trọng và theo dõi chi phí coverage-map/queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Chạy song song một phiên bản edge-coverage thông thường; feedback phong phú hơn chỉ hữu ích nếu chi phí queue/map tăng thêm không làm giảm số executions mỗi giây.
- Dùng `AFL_LLVM_ALLOWLIST` để giới hạn instrumentation path/caller khi các thư viện nhiều template hoặc mã tiện ích tổng quát chiếm phần lớn map.
- Có thể bỏ qua các hàm có quá nhiều đường đi không vòng lặp bằng AFL++; cảnh báo trong quá trình biên dịch là dấu hiệu cho thấy target cần allowlisting hoặc mức ít nghiêm ngặt hơn.
- Caller + path coverage chỉ hỗ trợ độ sâu caller bằng một. Không kết hợp nó với các context stack sâu hơn.
- Path ID có thể thay đổi giữa các phiên bản LLVM major. Giữ cố định toolchain trong suốt campaign và không đồng bộ các corpus dựa trên PATH như thể feature ID của chúng ổn định giữa các lần build.
- Feedback này bổ trợ cho `CMPLOG`: comparison tracing giải quyết câu hỏi **giá trị nào vượt qua một guard**, còn feedback path/caller lưu lại **tuyến đường và tổ hợp nhánh nào đã dẫn đến đó**.

## Fuzzing có trạng thái: Sequence là seed

Với **protocol**, **workflow đã xác thực** và **parser nhiều giai đoạn**, đơn vị đáng quan tâm thường không phải là một blob đơn lẻ mà là một **message sequence**. Nối toàn bộ transcript vào một file rồi đột biến tùy tiện thường kém hiệu quả vì fuzzer đột biến mọi bước như nhau, ngay cả khi chỉ message về sau mới đưa chương trình đến trạng thái dễ xảy ra lỗi.<sup>[[4]](#references)</sup>

Một cách hiệu quả hơn là coi **chính sequence đó là seed** và dùng **trạng thái có thể quan sát** (mã phản hồi, trạng thái protocol, giai đoạn parser, kiểu object trả về) làm feedback bổ sung.<sup>[[4]](#references)</sup>

- Giữ ổn định các **message tiền tố hợp lệ** và tập trung đột biến vào message **điều khiển chuyển trạng thái**.
- Lưu cache các identifier và giá trị do server tạo ra từ những phản hồi trước đó khi bước tiếp theo phụ thuộc vào chúng.
- Ưu tiên đột biến/splicing từng message thay vì đột biến toàn bộ transcript đã tuần tự hóa như một blob không rõ cấu trúc.
- Nếu protocol cung cấp các mã phản hồi có ý nghĩa, hãy dùng chúng làm **state oracle** ít tốn kém để ưu tiên các sequence tiến sâu hơn.

Đây cũng là lý do các bug cần xác thực, chuyển trạng thái ẩn hoặc bug parser “chỉ xuất hiện sau handshake” thường bị bỏ sót khi fuzzing kiểu file thông thường: fuzzer phải giữ được **thứ tự, trạng thái và các dependency**, chứ không chỉ cấu trúc.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing driver nhiều client

Edge coverage cao vẫn có thể bỏ sót bug trong IPC driver vì coverage không mô tả **quyền sở hữu object, reference count, message đang chờ, thứ tự cleanup hoặc các interleaving giữa thread**. Trang [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) trình bày mô hình object của driver; ví dụ này tập trung vào harness của fuzzer. Android Binder là một mô hình hữu ích: đi đến cả các đường cấp phát lẫn giải phóng vẫn chưa đủ nếu fuzzer không thể khiến nhiều process thao tác trên cùng một kernel object theo đúng thứ tự yêu cầu.<sup>[[15]](#references)</sup>

#### Mô hình hóa protocol, không phải các buffer `ioctl` riêng lẻ

Biểu diễn một test case dưới dạng grammar có thứ tự gồm **danh tính client + operation + đối số có cấu trúc**. Binder LKL fuzzer dùng protobuf và `libprotobuf-mutator`, với một client context-manager tồn tại lâu dài và hai client thông thường. Harness ngữ nghĩa sau đó giữ lại các mối liên hệ mà việc đột biến byte mù sẽ phá hủy.<sup>[[15]](#references)</sup>

- Lưu cache các giá trị được trả về từ những operation trước đó. Ví dụ, `BC_FREE_BUFFER` phải sử dụng lại con trỏ transaction-buffer được một `ioctl` trước đó trả về.
- Tạo các phản hồi mặc định hợp lệ để transaction đồng bộ có thể hoàn tất và các operation về sau vẫn có thể được tiếp cận.
- Từ chối các chuyển trạng thái bất khả thi như self-transaction hoặc nhiều transaction đang chờ cùng nhắm đến một target.
- Giữ trạng thái bootstrap singleton bên ngoài phần reset theo từng input. Binder chỉ cho phép đăng ký một `BINDER_SET_CONTEXT_MGR` mỗi lần boot, vì vậy việc liên tục hủy rồi tạo lại client đó sẽ khiến các input tiếp theo không còn hợp lệ.

Một template race về vòng đời hữu ích là để một client chuyển giao một object, bắt đầu cleanup bằng thread hoặc process, đồng thời khiến client nhận giải phóng transaction buffer. Trong ví dụ CVE-2020-0423, một lần chuyển giao `BINDER_TYPE_WEAK_BINDER`, tiếp theo là `BINDER_THREAD_EXIT` chạy đua với `BC_FREE_BUFFER`, có thể giải phóng một `binder_work` được nhúng trong object trong khi đường cleanup của thread đang thoát vẫn còn sử dụng nó.<sup>[[15]](#references)</sup>

#### Tái tạo interleaving có kiểm soát trong kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) liên kết mã kernel thực vào một harness userspace và cung cấp syscall interface thông qua `lkl_syscall`. Nhờ đó, có thể dễ dàng phối hợp protobuf state, coverage và KASAN trong cùng một process. Tuy nhiên, thông thường LKL chạy một syscall mà không có kernel thread nào khác ngắt giữa chừng. Với các campaign tìm race, hãy chèn các điểm `schedule()` quanh những ranh giới lock/unlock và vòng đời đã chọn, rồi để harness chọn ngẫu nhiên client tiếp theo tại mỗi điểm nhường lịch. Chỉ đặt các điểm này ở vị trí cần thiết vì mỗi điểm sẽ làm tăng không gian tìm kiếm lịch thực thi. Bộ lập lịch ngẫu nhiên được các nhà nghiên cứu mô tả **không** thuộc upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build và replay các seed regression đã tuần tự hóa

Harness upstream cố định một phiên bản `libprotobuf-mutator` tương thích, bật instrumentation fuzzing của LKL và KASAN bằng `LKL_FUZZING=1`, đồng thời bật `CONFIG_MMU` cho Binder với `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Sau khi checkout một phiên bản cố ý có lỗ hổng hoặc áp dụng các bản vá rollback được tài liệu hóa ở upstream, một serialized seed có thể tái tạo toàn bộ quá trình chuyển trạng thái đa client mà không cần dựng lại nó trong một proof of concept C tùy tiện:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Hãy xem lỗi use-after-free được KASAN phát hiện là xác nhận rằng seed đã đi vào đường xử lý vòng đời dễ bị tổn thương. Điều này **không** chứng minh các primitive tiếp theo cần thiết để thực thi mã kernel hoặc leo thang đặc quyền.<sup>[[16]](#references)</sup>

## Mẹo đa dạng hóa trên một máy (kiểu Jackalope)

Một cách thực tế để kết hợp **tính mới do tạo sinh** với **tái sử dụng coverage** là **khởi động lại các worker chạy trong thời gian ngắn** để fuzz một server chạy liên tục. Mỗi worker bắt đầu với corpus trống, đồng bộ sau `T` giây, chạy thêm `T` giây trên corpus đã hợp nhất, đồng bộ lần nữa rồi thoát. Cách này tạo ra **các cấu trúc mới trong mỗi thế hệ** đồng thời vẫn tận dụng coverage đã tích lũy.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Worker tuần tự (vòng lặp ví dụ):**

<details>
<summary>Vòng lặp khởi động lại worker Jackalope</summary>

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

- `-in empty` buộc tạo **corpus mới** ở mỗi lần tạo.
- `-server_update_interval T` mô phỏng gần đúng **đồng bộ trễ** (ưu tiên novelty trước, tái sử dụng sau).
- Trong chế độ grammar fuzzing, **mặc định sẽ bỏ qua lần đồng bộ server ban đầu** (không cần `-skip_initial_server_sync`).
- Giá trị `T` tối ưu **phụ thuộc vào target**; thường hiệu quả nhất là chuyển đổi sau khi worker đã tìm được phần lớn coverage “dễ”.

## Snapshot Fuzzing Cho Các Target Khó Tích Hợp Harness

Khi chỉ có thể truy cập đoạn code bạn muốn kiểm thử **sau một bước thiết lập tốn kém** (khởi động VM, hoàn tất đăng nhập, nhận packet, phân tích container, khởi tạo service), một lựa chọn thay thế hữu ích là **snapshot fuzzing**: chụp lại trạng thái process hoặc VM đã sẵn sàng, đưa từng test case vào đường dẫn input của target, thực thi cho đến khi xảy ra crash/timeout rồi khôi phục snapshot. Cách này tránh phải lặp lại quá trình khởi tạo hoặc các tiền tố protocol, hữu ích cho **network services**, **firmware**, **post-auth attack surfaces** và **binary-only targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Chạy target cho đến khi trạng thái cần thiết sẵn sàng.
2. Chụp snapshot **memory + registers** tại thời điểm đó.
3. Với mỗi test case, ghi input đã mutate trực tiếp vào buffer tương ứng của guest/process.
4. Thực thi cho đến khi xảy ra crash/timeout/reset.
5. Khôi phục snapshot; với các target VM, chỉ khôi phục **dirty pages** nếu được hỗ trợ, rồi lặp lại.

Đặt snapshot gần nhất có thể với bước parse/dispatch tốn kém đầu tiên, chẳng hạn sau điểm `recv`/`read` hoặc điểm deserialization packet, và ghi lại input buffer mà target sử dụng. Cách này tuân theo nguyên tắc bố trí thích ứng: di chuyển snapshot sâu hơn vào quá trình xử lý input để tránh lặp lại công việc.<sup>[[11]](#references)</sup>

## Khám Phá Race Trong Linux Kernel Với MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) biến các race trong Linux kernel nhạy với timing thành những lịch memory-access có thể lặp lại. Công cụ có thể tự động liệt kê các lần thực thi **A-B-A** với hai context hoặc cho phép analyst đặt các ràng buộc về thứ tự trong terminal UI/GUI. Đây là công cụ nghiên cứu thử nghiệm, không phải một concurrency fuzzer hoàn chỉnh: hiện tại công cụ cần LLVM 23+ và kernel đã được vá của dự án, các công cụ dòng lệnh hỗ trợ hai test thread, còn lớp fuzzing userspace được đề xuất thì chưa được triển khai.<sup>[[17]](#references)[[18]](#references)</sup>

### Thu thập các điểm giao tiếp giữa các context

Build kernel đã được instrument với KASAN outline callbacks và hỗ trợ ghi memory của KCOV đã được vá. README của dự án cũng khuyến nghị tắt tối ưu hóa sibling-call để call stack vẫn có thể sử dụng được.<sup>[[17]](#references)[[18]](#references)</sup>

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

Chế độ outline của KASAN (`asan-instrumentation-with-call-threshold=0`) chuyển các lần truy cập được instrument thành các lời gọi helper. Các bản vá kernel MAccConc tắt `asan-opt-same-temp` để những lần truy cập liên tiếp không bị gộp; cũng tắt tối ưu hóa `asan-opt-globals` khi cần phát hiện các race trên biến toàn cục. KCOV chuyển các bản ghi thu được đến userspace. So sánh các lần truy cập từ những ngữ cảnh thực thi khác nhau và giữ lại các cặp có phạm vi byte chồng lấn, trong đó ít nhất một phía ghi dữ liệu; xem `kfree()` như một thao tác ghi để các chuyển tiếp vòng đời cũng trở thành ứng viên.<sup>[[17]](#references)</sup>

Với công việc tiếp tục chạy ngoài task khởi tạo, chẳng hạn xử lý packet hoặc callback RCU, subsystem phải truyền tiếp một handle KCOV remote-coverage. KCOV remote trong upstream là tính năng opt-in và không tự động khả dụng cho mọi công việc chạy nền, vì vậy nếu thiếu bước truyền tiếp này, một tương tác có thật có thể không được phát hiện.<sup>[[17]](#references)[[19]](#references)</sup>

### Xác định cùng một lần truy cập động trong mọi lần chạy

Đừng replay dựa trên địa chỉ heap cụ thể vì địa chỉ có thể thay đổi sau mỗi lần cấp phát, hoặc chỉ dựa trên địa chỉ lệnh vì địa chỉ này không đủ để phân biệt bên trong các helper như `memcpy()` và `spin_lock()`. MAccConc sử dụng **stack trace có bổ sung bộ đếm**: mỗi frame xác định một callee cùng số lần gọi bên trong caller của nó, còn phần tử cuối xác định lệnh truy cập bộ nhớ. Các bản ghi vào/ra hàm của SanitizerCoverage cho phép userspace tái dựng định danh động này; định danh vẫn ổn định khi địa chỉ thay đổi và khi có nhiễu luồng điều khiển không liên quan.<sup>[[17]](#references)</sup>

### Chuyển các cặp ứng viên thành lịch thực thi cưỡng bức

IOCTL `KCOV_SET_DI` đã được vá sẽ gắn một định danh lần truy cập có bổ sung bộ đếm với một hành động trên shared flag.<sup>[[17]](#references)</sup>

| Hành động | Ngữ nghĩa |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Đặt flag *N* ngay trước lần truy cập được chọn. |
| `DI_STACK_WAIT` | Trước lần truy cập được chọn, spin cho đến khi flag *N* được đặt hoặc hết thời gian giới hạn đã cấu hình. |
| `DI_STACK_WAKE_POST` | Đặt flag *N* ngay sau lần truy cập được chọn. |

Để tạo ràng buộc **A-happens-before-B** một phần, gắn `DI_STACK_WAKE_POST` vào A và `DI_STACK_WAIT` vào B, dùng cùng một flag. Với lịch thực thi hai ngữ cảnh được xác định đầy đủ, hãy bắt đầu bằng cách chặn B, sau đó để A đánh thức B và chờ tại điểm chuyển giao đầu tiên; tại điểm chuyển giao tiếp theo, B thực hiện thao tác ngược lại. Cách sau hoạt động như chuyển đổi ngữ cảnh có tính xác định và được trình khám phá A-B-A tự động sử dụng.<sup>[[17]](#references)</sup>

Một chiến dịch tối thiểu là biên dịch test case bốn hook (`test_setup`, hai hàm thread và `test_end`) thành shared library, thu thập trace không có ràng buộc, sau đó liệt kê các ứng viên A-B-A hoặc thêm các ràng buộc thủ công quanh những lần truy cập đáng ngờ.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Diễn giải riêng timeout với các trường hợp sắp xếp lại thành công: thứ tự được yêu cầu có thể không khả thi vì khóa hoặc phụ thuộc khởi tạo/công bố khiến context thứ hai không thể đến điểm chèn của nó. Cũng cần lưu ý các điểm mù của KASAN: truy cập stack trực tiếp thường không được hook, trừ khi có khả năng vượt giới hạn; các biến toàn cục bị bỏ qua với cấu hình tối ưu hóa mặc định; và các compiler hiện tại không thể phát sinh đồng thời hook ASAN và TSAN. Ngoài ra, prototype sẽ mất buffer KCOV khi guest gặp panic, vì vậy hãy duy trì một console/oracle crash độc lập.<sup>[[17]](#references)</sup>

Để hỗ trợ fuzzing có hướng dẫn theo concurrency trong tương lai, hãy ghi lại tóm tắt truy cập bộ nhớ cho từng input hoặc syscall, ghép các thao tác có thể tạo thành điểm giao tiếp giữa các context, rồi chỉ khám phá những tổ hợp đó. VM snapshot giúp ổn định trạng thái toàn cục và địa chỉ; nếu không dùng snapshot, metadata về vị trí cấp phát có thể trừu tượng hóa các object qua nhiều lần chạy. Đây là một phần mở rộng được đề xuất, không phải tính năng hiện có của các công cụ userspace MAccConc.<sup>[[17]](#references)</sup>

## Phân tích nội quan Harness: Phát hiện sớm các fuzzer nông

Khi một chiến dịch bị đình trệ, vấn đề thường không nằm ở mutator mà ở **harness**. Dùng **phân tích nội quan về khả năng tiếp cận/độ bao phủ** để tìm các function có thể được gọi tĩnh từ mục tiêu fuzz nhưng hiếm khi hoặc chưa bao giờ được bao phủ khi chạy thực tế. Những function đó thường chỉ ra một trong ba vấn đề sau.<sup>[[12]](#references)</sup>

- Harness đi vào target quá muộn hoặc quá sớm.
- Seed corpus thiếu hẳn một nhóm tính năng.
- Target thực sự cần **harness thứ hai** thay vì một harness “làm mọi thứ” quá cồng kềnh.

Nếu bạn dùng quy trình kiểu OSS-Fuzz / ClusterFuzz, Fuzz Introspector có thể so sánh khả năng tiếp cận tĩnh với độ bao phủ khi chạy thực tế và tạo báo cáo từ một lần chạy có giới hạn thời gian hoặc corpus công khai.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Dùng báo cáo để quyết định có nên thêm harness mới cho một đường đi của parser chưa được kiểm thử, mở rộng corpus cho một tính năng cụ thể, hay chia một harness nguyên khối thành các entrypoint nhỏ hơn.

## Lựa chọn mục tiêu Fuzz theo đồ thị trước và phân loại Mutation

Nếu đã có **phát hiện từ phân tích tĩnh**, **mutation-testing survivors** và **báo cáo coverage**, đừng phân loại chúng thành các danh sách riêng biệt. Trước tiên, hãy xây dựng **call graph**, chú thích các node bằng **độ phức tạp cyclomatic**, **khả năng tiếp cận từ entrypoint/đầu vào không đáng tin cậy** và mọi phát hiện bên ngoài, rồi đặt câu hỏi về đồ thị.<sup>[[5]](#references)[[6]](#references)</sup>

- Những hàm có độ phức tạp cao nào có thể được tiếp cận từ đầu vào không đáng tin cậy?
- Những mutation survivor nào nằm trên đường đi từ parser/handler đến mã quan trọng về bảo mật?
- Những hàm nào là nút thắt kiến trúc với **blast radius** lớn bất thường?

Cách này thường tìm ra mục tiêu fuzz tốt hơn so với chỉ chọn mục tiêu có “coverage thấp nhất”. Một parser/decoder có **độ phức tạp cao** và được xác nhận là **có thể tiếp cận từ bên ngoài** là ứng viên harness tốt hơn một helper nội bộ riêng lẻ có coverage thấp nhưng không có đường đi do kẻ tấn công kiểm soát.

### Quy trình phân loại thực tế

1. Xây dựng **đồ thị mã** từ codebase và trích xuất các chỉ số độ phức tạp/nhánh cho từng hàm.
2. Liệt kê các **entrypoint** nhận đầu vào do kẻ tấn công kiểm soát: request handler, decoder, importer, protocol parser, CLI/file reader.
3. Chạy các truy vấn đường đi từ những entrypoint đó đến các hàm ứng viên để phân biệt bề mặt tấn công có thể tiếp cận với mã chết/chỉ dùng nội bộ.
4. Ưu tiên các node kết hợp:
   - **độ phức tạp cyclomatic** cao
   - đã xác nhận **có thể tiếp cận từ đầu vào không đáng tin cậy**
   - **blast radius** lớn hoặc có nhiều thành phần phụ thuộc phía sau
   - có bằng chứng bổ trợ như phát hiện **SARIF**, ghi chú audit hoặc mutation survivor
5. Trước tiên, viết harness tập trung cho các node có điểm cao nhất, đặc biệt là **parser/codec** như bộ giải mã hex/Base64/IP/message.

### Mutation survivor: tương đương hay cần xử lý

Mutation testing thường tạo ra danh sách survivor nhiễu. Trước khi xem mọi survivor là lỗ hổng bảo mật, hãy dùng đồ thị để đặt câu hỏi:

- Hàm bị đột biến có thể được tiếp cận từ entrypoint do kẻ tấn công kiểm soát không?
- Mọi đường gọi có bị ràng buộc bởi các bất biến mạnh hơn điều kiện kiểm tra bị đột biến không?
- Node đó nằm trong mã chết, logic chỉ xử lý định dạng, hay trong đường xử lý số học/parser có tác động lớn?

Các survivor vẫn không thể tiếp cận hoặc bị ràng buộc về cấu trúc thường là **equivalent mutant**. Các survivor vẫn **có thể tiếp cận** và liên quan đến **điều kiện biên**, **đường xử lý overflow/carry** hoặc **phân tích cú pháp/số học quan trọng về bảo mật** nên được đưa vào:

- harness fuzz mới
- kiểm thử property/invariant trực tiếp
- các vector edge-case có mục tiêu

### Liên hệ các phát hiện bên ngoài với đồ thị

Nếu pipeline SAST xuất **SARIF**, hãy ánh xạ các phát hiện lên node của đồ thị theo **file + khoảng dòng** rồi dùng đồ thị để mở rộng phạm vi ảnh hưởng.<sup>[[6]](#references)</sup>

- tính **blast radius** của hàm bị đánh dấu
- kiểm tra xem phát hiện có nằm trên đường đi nào từ entrypoint không
- nhóm các phát hiện gần nhau nếu chúng cùng quy về một nút thắt

Cách này hữu ích khi quyết định có nên dành thời gian fuzz cho một hàm cụ thể hay không: node **có thể tiếp cận**, **phức tạp** và đã có **phát hiện SAST** thường là mục tiêu tốt hơn node chỉ phức tạp nhưng không có đường đi từ đầu vào của kẻ tấn công.

Quy trình ví dụ với Trailmark.<sup>[[6]](#references)</sup>

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

Phương pháp luận quan trọng nằm ở giao điểm: **độ phức tạp x mức độ phơi lộ x tác động**. Dùng biểu đồ để chọn các mục tiêu fuzz có giá trị bảo mật kỳ vọng cao nhất, sau đó dùng các mutation vượt qua kiểm tra để xác định những ranh giới và bất biến mà harness cần kiểm thử chuyên sâu.<sup>[[5]](#references)</sup>

## Differential fuzzing các encoding khóa mật mã

Bắt đầu từ các khóa đã serialize hợp lệ hoặc các test vector tiêu chuẩn. Thay đổi các trường đã encode nhưng vẫn giữ nguyên độ dài và cấu trúc cần thiết để đi đến các luồng import và thao tác, sau đó gửi cùng một byte đến các implementation độc lập. So sánh khả năng chấp nhận và lỗi. Chữ ký và ciphertext ngẫu nhiên cần oracle kiểm tra tính đúng đắn, không phải so sánh từng byte: xác minh chữ ký hoặc so sánh shared secret từ một vòng encapsulation/decapsulation. Test vector xác lập sự phù hợp với tiêu chuẩn cho các trường hợp đã biết; differential mutation thăm dò các encoding sai định dạng nằm ngoài phạm vi đó.<sup>[[23]](#references)[[26]](#references)</sup>

Với các định dạng khóa này, hãy dùng oracle đặc thù cho từng định dạng:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Khóa ký ML-DSA đã mở rộng:** thay đổi các hệ số `s1` hoặc `s2` đã đóng gói để nằm ngoài `[-η, η]`, đồng thời giữ cho khóa vẫn parse được. Kiểm tra xem import hoặc signing có từ chối khóa hay không, và liệu chữ ký tạo ra có xác minh được không. Chỉ riêng sự khác biệt về khả năng chấp nhận không cấu thành vi phạm tiêu chuẩn, vì FIPS 204 không bắt buộc phải kiểm tra bổ sung đối với khóa riêng. Xem [cơ chế rò rỉ có điều kiện](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Cặp khóa ML-KEM:** tách biệt các bước kiểm tra bắt buộc đối với khóa encapsulation và đầu vào decapsulation khỏi bước kiểm tra tính nhất quán cặp (PCT) tùy chọn trên một cặp khóa được import. Thực hiện encapsulate bằng khóa công khai, decapsulate bằng khóa riêng, rồi so sánh shared secret; kết quả không khớp có thể làm gián đoạn giao tiếp mã hóa ngay cả khi từng khóa vượt qua kiểm tra đầu vào. Kiểm tra xem API xác thực đầu vào trong lúc thực hiện thao tác hay qua một lời gọi riêng; libcrux cung cấp `validate_public_key(pk)` và `validate_private_key(sk, ct)`, nhưng các hàm này không thay thế PCT.
- **Khóa raw XMSS/XMSSMT:** kiểm thử vòng lặp serialize rồi deserialize **khóa ký và khóa xác minh** trên nhiều bộ tham số, thay vì chỉ kiểm thử thao tác với khóa trong bộ nhớ. XMSS và XMSSMT có các không gian OID bốn byte riêng biệt, nên parser chỉ dựa vào OID và thử XMSS trước có thể phân loại nhầm khóa XMSSMT bị trùng OID rồi từ chối import. Parser RustCrypto được báo cáo là ví dụ về lỗi interoperability/availability, không phải giả mạo chữ ký.

## Fuzzing Go với gosentry: Engine mạnh hơn, đầu vào có kiểu và kiểm tra khác biệt

Nếu mục tiêu Go đã có harness `testing.F` gốc, một hướng nâng cấp thực tế là chạy cùng harness đó bằng [gosentry](https://github.com/trailofbits/gosentry), một fork của toolchain Go vẫn giữ `go test -fuzz` nhưng thay backend bằng **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Điều này hữu ích khi native Go fuzzer bị đình trệ trước **các phép so sánh khó**, **đầu vào có kiểu**, hoặc **các định dạng phụ thuộc nhiều vào parser**. Phương pháp vẫn giữ nguyên:

- Tiếp tục dùng `f.Add(...)` cho các seed và `f.Fuzz(...)` cho callback.
- Dùng lại cùng harness, nhưng chạy bằng binary `go` của gosentry thay vì toolchain tiêu chuẩn.
- Xem campaign thu được như một lần chạy thông thường có định hướng coverage, nhưng sử dụng cơ chế lập lịch/đột biến của LibAFL và các detector bổ trợ tốt hơn.

### Biến lỗi thầm lặng thành phát hiện fuzz

Một vấn đề thường gặp trong các đợt đánh giá Go là hành vi nguy hiểm thường **không** gây crash theo mặc định. Với gosentry, bạn có thể biến một số trạng thái “xấu nhưng thầm lặng” thành phát hiện.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` để biến các đường dẫn logging/error được chọn thành hành vi giống crash (hữu ích với các đường dẫn kiểu `log.Fatal`, vốn nếu không thì chỉ ghi log rồi tiếp tục).
- `--catch-races=true` để chạy lại các mục mới phát hiện trong queue bằng Go race detector.
- `--catch-leaks=true` để chạy lại các mục mới trong queue bằng `goleak` và dừng khi phát hiện goroutine leak.
- Cơ chế xử lý hang của LibAFL giúp giữ **vòng lặp vô hạn / đầu vào rất chậm** dưới dạng phát hiện fuzz thay vì để chúng biến mất dưới dạng timeout.
- Mặc định có sẵn các kiểm tra tràn số học, cùng các kiểm tra truncation tùy chọn thông qua instrumentation kiểu go-panikint.

Điều này đặc biệt hữu ích với các mục tiêu mà tác động bảo mật là **lỗi parser không gây panic**, **lỗi đồng thời**, hoặc **tình trạng treo chỉ gây DoS** thay vì hỏng bộ nhớ.

### Fuzzing nhận biết struct cho các API Go có kiểu

Native Go fuzzing chủ yếu hỗ trợ các kiểu vô hướng như `[]byte`, `string` và số. Nếu mã đang được kiểm thử nhận các đối tượng có kiểu, gosentry có thể fuzz trực tiếp **các giá trị tổng hợp** (struct, slice, array, pointer) trong khi vẫn đột biến các byte bên dưới.<sup>[[7]](#references)[[8]](#references)</sup>

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

Dùng cách này khi việc tạo một wire format giả chỉ để fuzzing sẽ che giấu các lỗi logic phía sau phần mã phân tích cú pháp chỉ có trong harness. Với các chiến dịch differential hoặc dựa trên grammar, hãy giữ đầu vào của harness dưới dạng một `[]byte` hoặc `string` duy nhất và phân tích cú pháp bên trong callback.

### Fuzzing dựa trên grammar cho parser và đầu vào giao thức

Với parser, định dạng và ngôn ngữ đầu vào, gosentry có thể chạy **Nautilus grammar fuzzing** trên LibAFL. Grammar là một mảng JSON gồm các quy tắc sản xuất, và harness thường nên nhận một đối số `[]byte` hoặc `string` duy nhất.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Ghi chú về methodology:

- Sử dụng grammar mode khi các mutation ở cấp byte phần lớn bị loại ở các bước kiểm tra cú pháp ban đầu.
- Giữ grammar tập trung vào **tập con liên quan đến bảo mật** của ngôn ngữ/giao thức, thay vì mô hình hóa toàn bộ đặc tả.
- Dùng các giá trị biên lớn trong terminals/nonterminals để kiểm tra các giới hạn về số nguyên, độ dài và state machine.
- Grammar mode giữ cho input hợp lệ theo grammar, nhưng target vẫn nhận **bytes/strings**, vì vậy việc phân tích cú pháp và kiểm tra ngữ nghĩa vẫn diễn ra bên trong code được harness.

### Differential fuzzing: so sánh các implementation, không chỉ các crash

Một phương pháp hiệu quả trong hệ sinh thái Go là **grammar-based differential fuzzing**: tạo input có cấu trúc hợp lệ rồi đưa chúng vào hai parser, client hoặc state-transition engine.<sup>[[7]](#references)[[8]](#references)</sup>

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

- một implementation panic trong khi implementation kia từ chối một cách an toàn
- đầu vào được chấp nhận/từ chối không khớp nhau
- parse tree hoặc đối tượng đã giải mã khác nhau
- trạng thái, nonce, số dư hoặc state root chuyển đổi khác nhau

Đây là cách thực tế để tìm ra **các sai lệch đồng thuận**, **sự mơ hồ của parser** và **sự lệch pha giữa spec với implementation** mà fuzzing chỉ tìm crash thường bỏ sót.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tái sử dụng corpus của chiến dịch để báo cáo độ bao phủ

Sau một chiến dịch, chạy lại corpus queue đã lưu để tạo báo cáo coverage của Go mà không cần xuất corpus riêng theo cách thủ công.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Chạy lệnh từ **cùng package** và với target `-fuzz` **giống nhau** để gosentry phân giải đúng trạng thái campaign đã lưu trong cache.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Fuzzing ngữ pháp đột biến](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ chuyên sâu](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet năm năm sau: Về fuzzing giao thức được hướng dẫn bởi độ bao phủ](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark biến code thành đồ thị](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Fuzzing trong Go thiếu một nửa bộ công cụ. Chúng tôi fork toolchain để khắc phục điều đó.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer greybox nhanh cho các giao thức mạng có trạng thái bằng snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Không có grammar, không vấn đề: Hướng tới fuzzing Linux kernel mà không cần mô tả system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing hiệu quả với snapshot thích ứng và có thể thay đổi](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM của AFL++: độ bao phủ path và caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing dự đoán, nhạy theo ngữ cảnh](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Bảo mật Tấn công Android - Fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL Android Binder - tài liệu build và regression-seed](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Khảo sát các race condition trong Linux kernel bằng cách kiểm soát thứ tự xen kẽ của truy cập bộ nhớ](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: độ bao phủ code cho fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Cú pháp tên file mở rộng của CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Thông báo bảo mật của Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing cú pháp tên file mở rộng của CFITSIO: 16 lỗ hổng an toàn bộ nhớ và phân loại có Codex hỗ trợ](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing vi sai cho mật mã học](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Tiêu chuẩn cơ chế đóng gói khóa dựa trên mạng tinh thể mô-đun](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Lỗi phân tích cú pháp OID của XMSSMT - issue #1442 của RustCrypto](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Thực trạng triển khai mật mã hậu lượng tử](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
