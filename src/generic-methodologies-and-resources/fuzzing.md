# Phương pháp Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage và Ngữ nghĩa

Trong **mutational grammar fuzzing**, các input được biến đổi nhưng vẫn **hợp lệ theo grammar**. Ở chế độ coverage-guided, chỉ những mẫu tạo ra **coverage mới** mới được lưu làm corpus seed. Với **các mục tiêu ngôn ngữ** (parser, interpreter, engine), cách này có thể bỏ sót những bug đòi hỏi **chuỗi semantic/dataflow**, trong đó đầu ra của một cấu trúc trở thành đầu vào của cấu trúc khác.<sup>[[1]](#references)</sup>

**Dạng lỗi:** fuzzer tìm được các seed riêng lẻ kích hoạt `document()` và `generate-id()` (hoặc primitive tương tự), nhưng **không giữ được dataflow nối chuỗi**, nên mẫu “gần bug hơn” bị loại vì không tạo thêm coverage. Khi có **từ 3 bước phụ thuộc trở lên**, việc tái tổ hợp ngẫu nhiên trở nên tốn kém và phản hồi coverage không thể định hướng quá trình tìm kiếm.<sup>[[1]](#references)</sup>

**Hàm ý:** với các grammar có nhiều phụ thuộc, hãy cân nhắc **kết hợp các giai đoạn mutational và generative** hoặc ưu tiên tạo các mẫu **function chaining** (không chỉ dựa vào coverage).<sup>[[1]](#references)</sup>

## Những cạm bẫy về độ đa dạng của Corpus

Mutation có hướng dẫn bởi coverage mang tính **tham lam**: mẫu tạo coverage mới được lưu ngay, thường giữ lại nhiều vùng không thay đổi. Theo thời gian, corpus trở thành tập hợp các mẫu **gần trùng lặp**, có độ đa dạng cấu trúc thấp. Việc tối giản quá mạnh có thể loại bỏ ngữ cảnh hữu ích; vì vậy, một giải pháp dung hòa thiết thực là **tối giản có nhận biết grammar**, với điều kiện **dừng khi đạt ngưỡng token tối thiểu** (loại bỏ phần nhiễu nhưng vẫn giữ đủ cấu trúc xung quanh để thuận tiện cho mutation).<sup>[[1]](#references)</sup>

Một quy tắc corpus thiết thực cho mutational fuzzing là: **ưu tiên một tập nhỏ các seed khác nhau về cấu trúc nhưng tối đa hóa coverage** hơn là một tập lớn gồm các mẫu gần trùng lặp. Trên thực tế, điều này thường gồm những việc sau.<sup>[[1]](#references)[[3]](#references)</sup>

- Bắt đầu từ **các mẫu thực tế** (corpus công khai, dữ liệu thu thập bằng crawling, traffic đã ghi lại, các tập file từ hệ sinh thái của mục tiêu).
- Chắt lọc chúng bằng **tối giản corpus dựa trên coverage** thay vì giữ lại mọi mẫu hợp lệ.
- Giữ seed **đủ nhỏ** để mutation tác động đến các trường có ý nghĩa, thay vì tiêu tốn hầu hết chu kỳ vào các byte không liên quan.
- Chạy lại quá trình tối giản corpus sau những thay đổi lớn về harness/instrumentation, vì corpus “tốt nhất” sẽ thay đổi khi khả năng reachability thay đổi.

## Mutation Có Nhận Biết Phép So Sánh Đối Với Giá Trị Magic

Một lý do phổ biến khiến fuzzer chững lại không phải là cú pháp, mà là **các phép so sánh chặt**: byte magic, kiểm tra độ dài, chuỗi enum, checksum hoặc giá trị điều phối parser được bảo vệ bằng `memcmp`, bảng switch hoặc các phép so sánh nối tiếp. Mutation ngẫu nhiên thuần túy lãng phí chu kỳ để thử đoán các giá trị này từng byte một.

Với các mục tiêu này, hãy dùng **comparison tracing** (ví dụ: quy trình kiểu AFL++ `CMPLOG` / Redqueen) để fuzzer có thể quan sát các toán hạng từ những phép so sánh thất bại và ưu tiên mutation hướng đến các giá trị thỏa mãn chúng.<sup>[[3]](#references)</sup>

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

**Ghi chú thực tiễn:**

- Cách này đặc biệt hữu ích khi mục tiêu chặn logic chuyên sâu phía sau **chữ ký file**, **protocol verb**, **type tag** hoặc **bit tính năng phụ thuộc phiên bản**.
- Kết hợp với **dictionary** trích xuất từ mẫu thực tế, đặc tả protocol hoặc debug log. Một dictionary nhỏ gồm token grammar, tên chunk, verb và dấu phân cách thường hữu ích hơn wordlist chung khổng lồ.
- Nếu mục tiêu thực hiện nhiều bước kiểm tra tuần tự, hãy xử lý các phép so sánh “magic” sớm nhất trước, sau đó tiếp tục tối giản corpus thu được để các giai đoạn sau bắt đầu bằng những prefix đã hợp lệ.

## Fuzzing File API Ẩn Ngôn ngữ Filename

Tham số có tên `filename`, `path` hoặc `URL` có thể là điểm vào của một trình thông dịch, chứ không phải thao tác tra cứu file thông thường. Ví dụ, CFITSIO Extended Filename Syntax (EFS) xử lý các selector trong dấu ngoặc vuông, biểu thức hàng/pixel, cột tính toán, histogram và phép biến đổi trước khi trả về object đã mở; một số dạng còn tạo bản sao tạm thời. Khi lập bản đồ attack surface, hãy phân loại từng API open/import là **literal-path** hoặc **interpreted-path**, sau đó fuzz entry point trong môi trường production mà ứng dụng thực sự gọi.<sup>[[20]](#references)[[22]](#references)</sup>

Để tìm hiểu các primitive SSRF, sao chép file và protocol handler có thể khai thác được, cùng những API literal-path an toàn hơn, xem [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Tách object nền khỏi chương trình được fuzz

Khi grammar nằm trong hậu tố filename, chỉ thay đổi byte của file được tham chiếu sẽ bỏ sót parser. Thay vào đó, một harness nhỏ có thể đọc mỗi testcase dưới dạng chuỗi rồi truyền chuỗi đó cho API open đã được diễn giải; chiến dịch CFITSIO đã tiếp cận phần lớn parser và evaluator của EFS bằng cách gọi `fits_open_file()` ở chế độ chỉ đọc. Hãy duy trì sẵn các file nền hợp lệ riêng biệt để các thay đổi tập trung vào ngôn ngữ selector/expression thay vì liên tục làm hỏng path cơ sở.<sup>[[22]](#references)</sup>

Dùng các seed khác nhau để mỗi seed tiếp cận một nhóm grammar riêng, sau đó tạo một dictionary gọn từ cả đặc tả lẫn mã nguồn lexer/parser. Nếu coverage chững lại trong khi input liên tục thất bại ở cùng một nhánh lỗi cú pháp, hãy giữ lại các prefix hợp lệ và bổ sung dấu phân cách, toán tử, keyword, tên hàm và tên trường tiêu biểu thay vì chỉ tăng thời gian random-mutation.<sup>[[22]](#references)</sup>

Chạy harness với grammar dictionary, ví dụ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Kiểm soát tác dụng phụ của harness “read-only”

Cờ thư viện read-only không đảm bảo testcase không gây tác dụng phụ: ngôn ngữ tên tệp có thể ghi đè đầu vào, tạo tệp đầu ra hoặc tạo các đối tượng tạm thời. Chiến dịch CFITSIO ban đầu đã phá hủy các tệp seed và để lại những tệp không mong muốn trên hệ thống tệp, vì vậy cần dọn dẹp và cô lập.<sup>[[22]](#references)</sup>

- Cấp cho mỗi worker một thư mục làm việc dùng một lần và một thư mục tạm riêng.
- Chỉ cung cấp bản sao của các tệp nền tảng chuẩn; không bao giờ để target sửa đổi bản duy nhất của corpus.
- Tắt quyền truy cập mạng trừ khi backend từ xa là mục tiêu dự kiến, đồng thời giới hạn các đường dẫn có thể ghi bằng container, mount namespace hoặc sandbox tương đương.
- Đặt lại thư mục sau mỗi lần chạy hoặc mỗi batch worker, và xem mọi thay đổi hệ thống tệp bất ngờ là phát hiện bổ sung.

### Vòng lặp crash-to-patch-to-fuzz

Phân cụm crash trước khi sửa để hàng nghìn artifact không biến thành hàng nghìn tác vụ vá lỗi. Trong đánh giá CFITSIO, AFLTriage đã rút gọn tập crash ban đầu xuống còn một vài nguyên nhân gốc; advisory sau đó cho thấy các lỗi riêng biệt, bao gồm kiểm tra kích thước đích không chính xác, con trỏ cũ sau `realloc()`, lỗi số học và các đường dọn dẹp parser không an toàn.<sup>[[21]](#references)[[22]](#references)</sup>

1. Rút gọn một đầu vào đại diện cho mỗi cụm và tái hiện lỗi bằng AddressSanitizer.
2. Ghi lại chính xác thao tác truy cập gây lỗi, vị trí trong mã nguồn, lịch sử cấp phát/giải phóng và trạng thái parser khiến bất biến bị vi phạm.
3. Áp dụng một bản vá ứng viên có phạm vi hẹp và biên dịch lại với cùng cấu hình instrumentation cho coverage và sanitizer.
4. Chạy lại reproducer ban đầu **và mọi đầu vào trong cụm**; đồng thời bật phát hiện leak vì một bản sửa lỗi an toàn bộ nhớ có thể làm hỏng quyền sở hữu tài nguyên trên đường xử lý lỗi.
5. Chạy kiểm thử chức năng với tệp thực, rồi tiếp tục từ queue đã tích lũy (hoặc nhập lại queue đó nếu engine yêu cầu thư mục đầu ra mới sau khi thay đổi binary).
6. Lặp lại: loại bỏ crash nông đầu tiên thường giúp các seed hiện có đi sâu hơn vào parser.

LLM có thể đẩy nhanh bước 2 và soạn bản nháp cho bước 3 khi được cung cấp đầu vào gây crash, báo cáo sanitizer, harness và mã nguồn liên quan, nhưng bản vá của nó vẫn không đáng tin cậy. Việc chạy lại bằng sanitizer và các cổng kiểm thử hồi quy—chứ không phải lời giải thích của model—mới quyết định bản sửa lỗi có được chấp nhận hay không.<sup>[[22]](#references)</sup>

## Phản hồi phong phú hơn khi Edge Coverage gộp các đường đi khác nhau

Edge coverage thông thường không thể phân biệt hai lần thực thi đi qua cùng một helper nhưng được gọi từ các caller khác nhau, hoặc có các tổ hợp nhánh khác nhau bên trong một function. Điều này quan trọng trong các decoder dùng chung, bộ điều phối giao thức và helper của interpreter, nơi **đường đi** đến một edge quyết định trạng thái hiện tại. Theo dõi mọi ngữ cảnh gọi một cách ngây thơ cũng rất nguy hiểm: coverage map và queue có thể phình to. Vì vậy, nghiên cứu về fuzzing nhạy theo ngữ cảnh khuyến nghị chỉ tinh chỉnh các ngữ cảnh tiềm năng thay vì áp dụng tính nhạy theo ngữ cảnh cho toàn bộ call graph.<sup>[[14]](#references)</sup>

Các bản AFL++ gần đây hỗ trợ **Ball-Larus per-function path coverage** bên cạnh edge coverage thông thường. Cơ chế này gán một feature cho mỗi đường đi không chu trình qua một function; các cạnh quay lại của vòng lặp bị loại bỏ, nên phản hồi này phân biệt được các tổ hợp nhánh nhưng **không phân biệt số lần lặp của vòng lặp**. Hãy bắt đầu với level `1` ít nghiêm ngặt, sau đó chỉ áp dụng các chế độ nghiêm ngặt hơn cho mã parser/máy trạng thái đáng ngờ vì số lượng đường đi có thể tăng theo cấp số nhân.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Đối với một helper được gọi từ nhiều vị trí liên quan đến bảo mật, chế độ LTO có thể kết hợp từng đường đi của hàm với vị trí gọi trực tiếp tương ứng:<sup>[[13]](#references)</sup>

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

**Hướng dẫn cho campaign:** áp dụng feedback phong phú hơn một cách thận trọng và theo dõi chi phí coverage-map/queue của nó.<sup>[[13]](#references)[[14]](#references)</sup>

- Chạy song song một instance edge-coverage thông thường; feedback phong phú hơn chỉ hữu ích nếu chi phí map/queue tăng thêm không làm giảm số execution mỗi giây.
- Dùng `AFL_LLVM_ALLOWLIST` để giới hạn instrumentation theo path/caller khi các thư viện nhiều template hoặc code tiện ích chung chiếm phần lớn map.
- Có thể bỏ qua các function có quá nhiều đường đi không có chu trình bằng AFL++; các cảnh báo trong quá trình biên dịch cho thấy target cần allowlisting hoặc một level ít nghiêm ngặt hơn.
- Caller + path coverage chỉ hỗ trợ một độ sâu caller. Không kết hợp nó với các context stack sâu hơn.
- Path ID có thể thay đổi giữa các phiên bản major của LLVM. Giữ cố định toolchain trong suốt campaign và không đồng bộ các corpus dựa trên PATH như thể feature ID của chúng ổn định giữa các lần build.
- Feedback này bổ trợ cho `CMPLOG`: comparison tracing giải quyết câu hỏi **giá trị nào vượt qua một guard**, còn feedback path/caller giữ lại thông tin **route và tổ hợp branch nào đã đưa luồng thực thi đến đó**.

## Fuzzing có trạng thái: Sequence là Seed

Với **protocol**, **workflow cần xác thực** và **parser nhiều giai đoạn**, đơn vị đáng quan tâm thường không phải một blob riêng lẻ mà là một **message sequence**. Nối toàn bộ transcript vào một file rồi mutate một cách mù quáng thường kém hiệu quả, vì fuzzer mutate mọi bước như nhau, ngay cả khi chỉ message ở giai đoạn sau mới đưa chương trình đến trạng thái dễ phát sinh lỗi.<sup>[[4]](#references)</sup>

Một cách hiệu quả hơn là coi **sequence chính là seed** và dùng **trạng thái có thể quan sát** (mã phản hồi, trạng thái protocol, giai đoạn parser, kiểu object được trả về) làm feedback bổ sung.<sup>[[4]](#references)</sup>

- Giữ ổn định các **message prefix hợp lệ** và tập trung mutation vào message **điều khiển chuyển trạng thái**.
- Cache các identifier và giá trị do server tạo ra từ những phản hồi trước đó khi bước tiếp theo phụ thuộc vào chúng.
- Ưu tiên mutation/splicing theo từng message thay vì mutate toàn bộ transcript đã serialize như một blob không rõ cấu trúc.
- Nếu protocol cung cấp các mã phản hồi có ý nghĩa, hãy dùng chúng làm **state oracle** chi phí thấp để ưu tiên các sequence tiến sâu hơn.

Đây cũng là lý do các bug cần xác thực, chuyển trạng thái ẩn hoặc bug parser “chỉ xảy ra sau handshake” thường bị bỏ sót khi fuzzing kiểu file thông thường: fuzzer phải giữ được **thứ tự, trạng thái và các quan hệ phụ thuộc**, chứ không chỉ cấu trúc.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing driver nhiều client

Edge coverage cao vẫn có thể bỏ sót bug trong IPC driver, vì coverage không mô tả **quyền sở hữu object, reference count, message đang chờ, thứ tự cleanup hoặc các interleaving giữa thread**. Trang [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) trình bày mô hình object của driver; ví dụ này tập trung vào harness của fuzzer. Android Binder là một mô hình hữu ích: chỉ đi đến cả các path cấp phát và giải phóng là chưa đủ nếu fuzzer không thể khiến nhiều process thao tác lên cùng một kernel object theo đúng thứ tự cần thiết.<sup>[[15]](#references)</sup>

#### Mô hình hóa protocol, không phải các buffer `ioctl` riêng lẻ

Biểu diễn một test case dưới dạng grammar có thứ tự gồm **danh tính client + operation + argument có cấu trúc**. Binder LKL fuzzer dùng protobuf và `libprotobuf-mutator`, với một client context manager tồn tại lâu dài và hai client thông thường. Sau đó, một semantic harness giữ nguyên các mối quan hệ mà byte mutation mù quáng có thể phá hỏng.<sup>[[15]](#references)</sup>

- Cache các giá trị được trả về từ những operation trước đó. Ví dụ, `BC_FREE_BUFFER` phải dùng lại con trỏ transaction-buffer được trả về từ một `ioctl` trước đó.
- Tạo các reply mặc định hợp lệ để synchronous transaction có thể hoàn tất và các operation tiếp theo vẫn có thể được thực thi.
- Từ chối các chuyển trạng thái không hợp lệ, chẳng hạn self-transaction hoặc nhiều transaction đang chờ cùng một target.
- Giữ trạng thái bootstrap singleton bên ngoài phần reset theo từng input. Binder chỉ cho phép đăng ký `BINDER_SET_CONTEXT_MGR` một lần mỗi lần boot, nên liên tục hủy rồi tạo lại client đó sẽ khiến các input sau không hợp lệ.

Một mẫu lifetime-race hữu ích là để một client chuyển một object, bắt đầu cleanup bằng thread hoặc process, đồng thời để client nhận giải phóng transaction buffer. Trong ví dụ CVE-2020-0423, việc chuyển `BINDER_TYPE_WEAK_BINDER`, rồi để `BINDER_THREAD_EXIT` chạy đua với `BC_FREE_BUFFER`, có thể giải phóng một `binder_work` nhúng trong object trong khi path cleanup của thread đang thoát vẫn còn sử dụng nó.<sup>[[15]](#references)</sup>

#### Tái tạo các interleaving có kiểm soát trong kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) liên kết code kernel thực vào một harness userspace và cung cấp syscall interface thông qua `lkl_syscall`. Nhờ đó, có thể dễ dàng phối hợp protobuf state, coverage và KASAN trong cùng một process. Tuy nhiên, LKL thường chạy một syscall mà không bị kernel thread khác ngắt. Với các campaign race, hãy chèn các điểm `schedule()` quanh những ranh giới lock/unlock và lifetime đã chọn, rồi để harness chọn ngẫu nhiên client tiếp theo tại mỗi lần yield. Giới hạn các điểm này ở những vị trí cần thiết, vì mỗi điểm làm tăng gấp bội không gian tìm kiếm lịch thực thi. Randomized scheduler được các nhà nghiên cứu mô tả **không** thuộc upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build và replay các regression seed đã serialize

Harness upstream cố định một phiên bản `libprotobuf-mutator` tương thích, bật instrumentation cho LKL fuzzing và KASAN bằng `LKL_FUZZING=1`, đồng thời bật `CONFIG_MMU` cho Binder bằng `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Sau khi checkout một revision cố ý có lỗ hổng hoặc áp dụng các bản vá rollback được ghi lại ở upstream, một seed được tuần tự hóa có thể tái hiện toàn bộ quá trình chuyển trạng thái nhiều client mà không cần dựng lại nó trong một proof of concept C tùy biến:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Hãy xem KASAN use-after-free thu được là bằng chứng xác nhận seed đã đi vào đường dẫn vòng đời dễ bị lỗi. Điều này **không** chứng minh các primitive tiếp theo cần thiết để thực thi mã trong kernel hoặc leo thang đặc quyền.<sup>[[16]](#references)</sup>

## Mẹo tạo tính đa dạng trên một máy (Kiểu Jackalope)

Một cách thực tế để kết hợp **tính mới do generative tạo ra** với **việc tái sử dụng coverage** là **khởi động lại các worker chạy trong thời gian ngắn** khi kiểm thử một server chạy liên tục. Mỗi worker bắt đầu với corpus trống, sync sau `T` giây, chạy thêm `T` giây trên corpus đã kết hợp, sync lần nữa rồi thoát. Cách này tạo ra **các cấu trúc mới ở mỗi thế hệ**, đồng thời vẫn tận dụng coverage đã tích lũy.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Các worker tuần tự (vòng lặp ví dụ):**

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

- `-in empty` buộc tạo **corpus mới** trong mỗi lần sinh.
- `-server_update_interval T` mô phỏng **đồng bộ trễ** (ưu tiên novelty trước, tái sử dụng sau).
- Trong chế độ grammar fuzzing, **mặc định bỏ qua đồng bộ server ban đầu** (không cần `-skip_initial_server_sync`).
- Giá trị `T` tối ưu **phụ thuộc vào target**; thường hiệu quả nhất khi chuyển đổi sau khi worker đã tìm được phần lớn coverage “dễ”.

## Snapshot Fuzzing Cho Các Target Khó Tạo Harness

Khi code bạn muốn kiểm thử chỉ có thể truy cập được **sau một bước thiết lập tốn kém** (khởi động VM, hoàn tất đăng nhập, nhận packet, phân tích container, khởi tạo service), một giải pháp thay thế hữu ích là **snapshot fuzzing**: chụp trạng thái sẵn sàng của process hoặc VM, đưa từng test case vào đường dẫn input của target, thực thi cho đến khi xảy ra crash/timeout, rồi khôi phục snapshot. Cách này tránh phải lặp lại bước khởi tạo hoặc các prefix giao thức, hữu ích cho **network service**, **firmware**, **bề mặt tấn công sau xác thực** và **target chỉ có binary**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Chạy target đến khi trạng thái cần kiểm thử sẵn sàng.
2. Chụp snapshot **memory + registers** tại thời điểm đó.
3. Với mỗi test case, ghi input đã mutate trực tiếp vào buffer phù hợp trong guest/process.
4. Thực thi cho đến khi xảy ra crash/timeout/reset.
5. Khôi phục snapshot; với target VM, chỉ khôi phục **các trang đã bị thay đổi** nếu được hỗ trợ, rồi lặp lại.

Đặt snapshot gần nhất có thể với bước parse/dispatch tốn kém đầu tiên, chẳng hạn sau điểm `recv`/`read` hoặc giải tuần tự hóa packet, và ghi lại input buffer mà target sử dụng. Cách này tuân theo nguyên tắc bố trí thích ứng: đưa snapshot sâu hơn vào quy trình xử lý input để tránh lặp lại công việc.<sup>[[11]](#references)</sup>

## Khảo Sát Race Trong Linux Kernel Với MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) biến các race trong Linux kernel nhạy cảm với thời gian thành những lịch truy cập bộ nhớ có thể lặp lại. Công cụ có thể tự động liệt kê các lần thực thi **A-B-A** trong hai context hoặc cho phép analyst đặt các ràng buộc thứ tự trong terminal UI/GUI. Đây là công cụ nghiên cứu thử nghiệm, không phải một concurrency fuzzer hoàn chỉnh: hiện tại, công cụ cần LLVM 23+ và kernel đã được patch của dự án; các công cụ dòng lệnh hỗ trợ hai test thread, còn lớp userspace fuzzing được đề xuất thì chưa được triển khai.<sup>[[17]](#references)[[18]](#references)</sup>

### Thu thập các điểm giao tiếp giữa các context

Build kernel đã instrument với các callback KASAN outline và hỗ trợ ghi nhớ của KCOV đã được patch. README của dự án cũng khuyến nghị tắt sibling-call optimization để call stack vẫn sử dụng được.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) chuyển các truy cập được instrument thành các lời gọi helper. Các bản vá kernel của MAccConc tắt `asan-opt-same-temp` để các truy cập liên tiếp không bị gộp; cũng tắt tối ưu hóa `asan-opt-globals` khi cần thấy các race trên biến toàn cục. KCOV chuyển các bản ghi thu được đến userspace. So sánh các truy cập từ những ngữ cảnh thực thi khác nhau và giữ lại các cặp có phạm vi byte chồng lấp, trong đó ít nhất một phía ghi dữ liệu; mô hình hóa `kfree()` như một thao tác ghi để cả các chuyển đổi vòng đời cũng trở thành ứng viên.<sup>[[17]](#references)</sup>

Với công việc tiếp diễn ngoài task khởi tạo, chẳng hạn như xử lý packet hoặc callback RCU, subsystem phải truyền tiếp handle remote-coverage của KCOV. Remote KCOV upstream là tùy chọn và không tự động khả dụng cho mọi công việc nền, vì vậy việc không truyền tiếp có thể khiến một tương tác thực sự không được ghi nhận.<sup>[[17]](#references)[[19]](#references)</sup>

### Xác định cùng một truy cập động ở mỗi lần chạy

Không phát lại dựa trên địa chỉ heap cụ thể, vốn có thể thay đổi sau mỗi lần cấp phát, hoặc chỉ dựa trên địa chỉ lệnh, vốn không đủ để phân biệt bên trong các helper như `memcpy()` và `spin_lock()`. MAccConc dùng **stack trace có bộ đếm**: mỗi frame xác định một callee cùng số lần được gọi bên trong caller của nó, còn phần tử cuối cùng xác định lệnh truy cập bộ nhớ. Các bản ghi function-entry/exit của SanitizerCoverage cho phép userspace dựng lại định danh động này; định danh vẫn ổn định khi địa chỉ thay đổi và khi có nhiễu luồng điều khiển không liên quan.<sup>[[17]](#references)</sup>

### Chuyển các cặp ứng viên thành lịch thực thi cưỡng bức

Ioctl đã được vá `KCOV_SET_DI` liên kết một định danh truy cập có bộ đếm với một thao tác trên shared flag.<sup>[[17]](#references)</sup>

| Thao tác | Ngữ nghĩa |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Đặt flag *N* ngay trước truy cập được chọn. |
| `DI_STACK_WAIT` | Trước truy cập được chọn, spin cho đến khi flag *N* được đặt hoặc hết giới hạn đã cấu hình. |
| `DI_STACK_WAKE_POST` | Đặt flag *N* ngay sau truy cập được chọn. |

Để tạo ràng buộc **A-happens-before-B** một phần, gắn `DI_STACK_WAKE_POST` với A và `DI_STACK_WAIT` với B bằng cùng một flag. Với lịch thực thi hai ngữ cảnh được xác định hoàn toàn, bắt đầu bằng cách chặn B, sau đó để A đánh thức B và chờ tại điểm chuyển giao đầu tiên; B thực hiện thao tác ngược lại tại lần chuyển giao tiếp theo. Cách thứ hai hoạt động như chuyển đổi ngữ cảnh xác định và được trình khám phá A-B-A tự động sử dụng.<sup>[[17]](#references)</sup>

Một chiến dịch tối thiểu là biên dịch test case bốn hook (`test_setup`, hai hàm thread và `test_end`) thành shared library, thu thập trace không có ràng buộc, sau đó liệt kê các ứng viên A-B-A hoặc thêm ràng buộc thủ công quanh những truy cập đáng ngờ.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Diễn giải timeout tách biệt với việc sắp xếp lại thành công: thứ tự được yêu cầu có thể không khả thi vì lock hoặc phụ thuộc khởi tạo/công bố khiến context thứ hai không thể đến điểm injection. Đồng thời, hãy lưu ý các điểm mù của KASAN: truy cập stack trực tiếp thường không được hook trừ khi có khả năng vượt biên, biến global bị bỏ qua với tùy chọn tối ưu hóa mặc định, và các compiler hiện tại không thể đồng thời tạo hook ASAN và TSAN. Cuối cùng, prototype mất buffer KCOV khi guest bị panic, vì vậy hãy duy trì một crash console/oracle độc lập.<sup>[[17]](#references)</sup>

Để hỗ trợ fuzzing có hướng dẫn đồng thời trong tương lai, hãy ghi lại tóm tắt truy cập bộ nhớ theo từng input hoặc syscall, ghép các thao tác có thể tạo thành điểm giao tiếp liên context, rồi chỉ khám phá những tổ hợp đó. VM snapshot giúp ổn định trạng thái global và địa chỉ; nếu không dùng snapshot, metadata vị trí cấp phát có thể trừu tượng hóa các object qua nhiều lần chạy. Đây là một đề xuất mở rộng, không phải tính năng hiện có của các công cụ userspace MAccConc.<sup>[[17]](#references)</sup>

## Phân tích nội quan Harness: Sớm phát hiện Fuzzer có độ bao phủ nông

Khi một chiến dịch bị đình trệ, vấn đề thường không nằm ở mutator mà ở **harness**. Dùng **phân tích nội quan về khả năng tiếp cận/độ bao phủ** để tìm các hàm có thể được gọi về mặt tĩnh từ fuzz target nhưng hiếm khi hoặc không bao giờ được bao phủ khi chạy thực tế. Những hàm đó thường chỉ ra một trong ba vấn đề sau.<sup>[[12]](#references)</sup>

- Harness đi vào target quá muộn hoặc quá sớm.
- Seed corpus thiếu hẳn một nhóm tính năng.
- Target thực sự cần **một harness thứ hai** thay vì một harness “làm mọi thứ” quá cồng kềnh.

Nếu bạn sử dụng quy trình kiểu OSS-Fuzz / ClusterFuzz, Fuzz Introspector có thể so sánh khả năng tiếp cận tĩnh với độ bao phủ khi chạy thực tế và tạo báo cáo từ một lần chạy có giới hạn thời gian hoặc corpus công khai.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Dùng báo cáo để quyết định có nên thêm harness mới cho đường đi của parser chưa được kiểm thử, mở rộng corpus cho một tính năng cụ thể hay tách một harness nguyên khối thành các entry point nhỏ hơn.

## Lựa chọn mục tiêu fuzzing ưu tiên đồ thị và phân loại mutation

Nếu đã có các **phát hiện từ phân tích tĩnh**, **mutation-testing survivors** và **báo cáo coverage**, đừng phân loại chúng thành các danh sách riêng biệt. Trước tiên, hãy xây dựng **call graph**, chú thích các node bằng **độ phức tạp cyclomatic**, **khả năng đi tới từ entrypoint/đầu vào không đáng tin cậy** và mọi phát hiện bên ngoài, sau đó đặt câu hỏi về đồ thị.<sup>[[5]](#references)[[6]](#references)</sup>

- Những function có độ phức tạp cao nào có thể được đi tới từ đầu vào không đáng tin cậy?
- Những mutation survivor nào nằm trên đường đi từ parser/handler đến code trọng yếu về bảo mật?
- Function nào là điểm nghẽn kiến trúc có **blast radius** lớn bất thường?

Cách này thường tìm ra các mục tiêu fuzz tốt hơn so với chỉ chọn nơi có “coverage thấp nhất”. Một parser/decoder có **độ phức tạp cao** và được xác nhận là **có thể tiếp cận từ bên ngoài** là ứng viên harness tốt hơn một helper nội bộ riêng lẻ có coverage yếu nhưng không có đường đi chịu sự kiểm soát của kẻ tấn công.

### Quy trình phân loại thực tế

1. Xây dựng **code graph** từ codebase và trích xuất các chỉ số về độ phức tạp/nhánh cho từng function.
2. Liệt kê các **entrypoint** nhận đầu vào do kẻ tấn công kiểm soát: request handler, decoder, importer, protocol parser, CLI/file reader.
3. Chạy truy vấn đường đi từ các entrypoint đó đến các function ứng viên để phân biệt bề mặt tấn công có thể tiếp cận với code chết/chỉ dùng nội bộ.
4. Ưu tiên các node kết hợp:
   - **độ phức tạp cyclomatic** cao
   - được xác nhận là **có thể tiếp cận từ đầu vào không đáng tin cậy**
   - **blast radius** lớn hoặc có nhiều thành phần phụ thuộc phía sau
   - có bằng chứng hỗ trợ như phát hiện **SARIF**, ghi chú audit hoặc mutation survivor
5. Trước tiên, viết harness tập trung cho các node có điểm cao nhất, đặc biệt là **parser/codec** như bộ giải mã hex/Base64/IP/message.

### Mutation survivor: tương đương hay cần xử lý

Mutation testing thường tạo ra một danh sách survivor nhiều nhiễu. Trước khi xem mọi survivor là lỗ hổng bảo mật, hãy dùng đồ thị để đặt câu hỏi:

- Function bị đột biến có thể được gọi từ một entrypoint do kẻ tấn công kiểm soát không?
- Có phải mọi đường gọi đều bị ràng buộc bởi các invariant mạnh hơn điều kiện kiểm tra bị đột biến không?
- Node đó nằm trong code chết, logic chỉ phục vụ định dạng hay đường xử lý số học/parser có tác động lớn?

Các survivor vẫn không thể tiếp cận hoặc bị ràng buộc về cấu trúc thường là **equivalent mutant**. Các survivor vẫn **có thể tiếp cận** và liên quan đến **điều kiện biên**, **đường xử lý overflow/carry** hoặc **số học/phân tích cú pháp trọng yếu về bảo mật** nên được chuyển thành:

- harness fuzz mới
- kiểm thử trực tiếp các thuộc tính/invariant
- bộ vector edge case có mục tiêu

### Ánh xạ các phát hiện bên ngoài lên đồ thị

Nếu pipeline SAST xuất ra **SARIF**, hãy ánh xạ các phát hiện lên node của đồ thị theo **file + phạm vi dòng** rồi dùng đồ thị để mở rộng đánh giá tác động.<sup>[[6]](#references)</sup>

- tính **blast radius** của function bị gắn cờ
- kiểm tra xem phát hiện đó có nằm trên đường đi nào từ một entrypoint không
- nhóm các phát hiện gần nhau nếu chúng cùng hội tụ vào một điểm nghẽn

Cách này hữu ích khi quyết định có nên dành thời gian fuzz cho một function cụ thể hay không: một node **có thể tiếp cận**, **phức tạp** và đã có **phát hiện SAST** thường là mục tiêu tốt hơn một node chỉ phức tạp nhưng không có đường đi chịu sự kiểm soát của kẻ tấn công.

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

Phương pháp luận quan trọng là giao điểm của: **độ phức tạp x mức độ phơi lộ x tác động**. Dùng biểu đồ để chọn các fuzz target có giá trị bảo mật kỳ vọng cao nhất, sau đó dùng các mutation survivor để xác định những ranh giới và bất biến mà harness của bạn cần kiểm thử kỹ.<sup>[[5]](#references)</sup>

## Fuzzing Go với gosentry: Engine mạnh hơn, đầu vào có kiểu và kiểm tra vi sai

Nếu target Go đã có harness `testing.F` gốc, một hướng nâng cấp thiết thực là chạy cùng harness đó với [gosentry](https://github.com/trailofbits/gosentry), một Go toolchain được fork, vẫn giữ `go test -fuzz` nhưng thay backend bằng **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Điều này hữu ích khi Go fuzzer mặc định bị khựng trước **các phép so sánh khó**, **đầu vào có kiểu**, hoặc **các định dạng nặng về parser**. Phương pháp vẫn như cũ:

- Tiếp tục dùng `f.Add(...)` để thêm seed và `f.Fuzz(...)` cho callback.
- Dùng lại cùng harness, nhưng chạy bằng binary `go` của gosentry thay vì toolchain mặc định.
- Xem campaign thu được như một lần chạy coverage-guided bình thường, nhưng có scheduling/mutation của LibAFL và các detector hỗ trợ tốt hơn.

### Biến lỗi im lặng thành phát hiện từ fuzzing

Một vấn đề thường gặp trong các cuộc đánh giá Go là hành vi nguy hiểm thường **không** gây crash theo mặc định. Với gosentry, bạn có thể biến một số trạng thái “xấu nhưng im lặng” thành phát hiện.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` để khiến các đường dẫn logging/error được chọn hoạt động như crash (hữu ích với các đường dẫn kiểu `log.Fatal` vốn chỉ ghi log rồi tiếp tục).
- `--catch-races=true` để chạy lại các queue entry mới được phát hiện bằng Go race detector.
- `--catch-leaks=true` để chạy lại các queue entry mới bằng `goleak` và dừng khi phát hiện goroutine leak.
- Cơ chế xử lý hang của LibAFL để giữ **vòng lặp vô hạn / đầu vào rất chậm** làm phát hiện từ fuzzing, thay vì để chúng biến mất dưới dạng timeout.
- Mặc định có sẵn kiểm tra tràn số học, cùng các kiểm tra truncation tùy chọn thông qua instrumentation kiểu go-panikint.

Điều này đặc biệt hữu ích với các target mà tác động bảo mật là **lỗi parser không gây panic**, **lỗi đồng thời**, hoặc **hang chỉ gây DoS**, thay vì memory corruption.

### Fuzzing nhận biết struct cho các Go API có kiểu

Go fuzzing mặc định chủ yếu mong đợi các giá trị scalar như `[]byte`, `string` và số. Nếu code được kiểm thử xử lý các object có kiểu, gosentry có thể fuzz trực tiếp **các giá trị tổ hợp** (struct, slice, array, pointer), đồng thời vẫn mutation các byte bên dưới.<sup>[[7]](#references)[[8]](#references)</sup>

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

Hãy dùng cách này khi việc tạo một wire format giả chỉ để fuzzing sẽ che giấu lỗi logic sau phần mã parsing chỉ có trong harness. Với các chiến dịch differential hoặc grammar-based, hãy giữ đầu vào của harness dưới dạng một `[]byte` hoặc `string` duy nhất và thực hiện parsing bên trong callback.

### Grammar-based fuzzing cho parser và đầu vào giao thức

Với parser, định dạng và ngôn ngữ đầu vào, gosentry có thể chạy **Nautilus grammar fuzzing** trên LibAFL. Grammar là một mảng JSON gồm các production rule, và harness thường nên nhận một đối số `[]byte` hoặc `string` duy nhất.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Ghi chú về methodology:

- Sử dụng grammar mode khi các phép biến đổi ở cấp byte hầu hết đều bị loại ở bước kiểm tra cú pháp ban đầu.
- Giữ grammar tập trung vào **tập con liên quan đến bảo mật** của ngôn ngữ/giao thức, thay vì mô hình hóa toàn bộ đặc tả.
- Dùng các giá trị biên lớn trong terminals/nonterminals để kiểm tra các trường hợp biên về số nguyên, độ dài và state machine.
- Grammar mode giữ cho input hợp lệ theo grammar, nhưng target vẫn nhận **bytes/strings**, nên việc parse và kiểm tra ngữ nghĩa vẫn diễn ra bên trong code được harness.

### Differential fuzzing: so sánh các implementation, không chỉ tìm crash

Một phương pháp hiệu quả trong hệ sinh thái Go là **grammar-based differential fuzzing**: tạo input có cấu trúc hợp lệ rồi đưa vào hai parser, client hoặc bộ máy chuyển trạng thái.<sup>[[7]](#references)[[8]](#references)</sup>

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

- một implementation panic trong khi implementation còn lại từ chối một cách bình thường
- đầu vào được chấp nhận/từ chối không khớp nhau
- parse tree hoặc đối tượng đã giải mã khác nhau
- state transition, nonce, balance hoặc state root khác nhau

Đây là cách thực tế để tìm ra **consensus mismatch**, **parser ambiguity** và **spec-vs-implementation drift** mà fuzzing chỉ tìm crash thường bỏ sót.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Tái sử dụng corpus của campaign để tạo báo cáo coverage

Sau một campaign, chạy lại corpus queue đã lưu để tạo báo cáo coverage của Go mà không cần xuất corpus riêng theo cách thủ công.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Chạy lệnh từ **cùng package** và với **cùng target `-fuzz`** để gosentry phân giải đúng trạng thái campaign đã lưu trong cache.



## References

- [1] [Fuzzing grammar đột biến](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ chuyên sâu](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet sau năm năm: Fuzzing giao thức theo hướng dẫn của coverage](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark biến mã thành đồ thị](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing thiếu một nửa bộ công cụ. Chúng tôi fork toolchain để khắc phục.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Greybox fuzzer nhanh cho các giao thức mạng có trạng thái bằng snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Không có grammar, chẳng sao: Hướng tới fuzzing Linux kernel mà không cần mô tả system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing hiệu quả với snapshot thích ứng và có thể thay đổi](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM của AFL++: coverage đường dẫn và caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing nhạy theo ngữ cảnh có tính dự đoán](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL Android Binder - tài liệu build và seed hồi quy](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Khám phá các điều kiện race trong Linux kernel bằng cách kiểm soát đan xen truy cập bộ nhớ](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: coverage mã cho fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Cú pháp tên tệp mở rộng CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Thông báo bảo mật của Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing cú pháp tên tệp mở rộng CFITSIO: 16 lỗ hổng an toàn bộ nhớ và phân loại hỗ trợ bởi Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
{{#include ../banners/hacktricks-training.md}}
