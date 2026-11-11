# Phương pháp luận Fuzzing

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage so với ngữ nghĩa

Trong **mutational grammar fuzzing**, các input được biến đổi nhưng vẫn **hợp lệ theo grammar**. Ở chế độ hướng dẫn theo coverage, chỉ những mẫu tạo ra **coverage mới** mới được lưu làm seed của corpus. Với **các mục tiêu ngôn ngữ** (parser, interpreter, engine), cách này có thể bỏ sót các bug cần đến **chuỗi ngữ nghĩa/luồng dữ liệu**, trong đó đầu ra của một cấu trúc trở thành đầu vào của cấu trúc khác.<sup>[[1]](#references)</sup>

**Dạng lỗi:** fuzzer tìm được các seed lần lượt kích hoạt `document()` và `generate-id()` (hoặc các primitive tương tự), nhưng **không giữ lại luồng dữ liệu được nối chuỗi**, nên mẫu “gần với bug hơn” bị loại vì không làm tăng coverage. Khi có **từ 3 bước phụ thuộc trở lên**, việc tái kết hợp ngẫu nhiên trở nên tốn kém, còn phản hồi coverage không định hướng được quá trình tìm kiếm.<sup>[[1]](#references)</sup>

**Hệ quả:** với các grammar có nhiều phụ thuộc, hãy cân nhắc **kết hợp các giai đoạn mutational và generative** hoặc ưu tiên các mẫu **nối chuỗi function** (không chỉ dựa vào coverage).<sup>[[1]](#references)</sup>

## Những vấn đề về tính đa dạng của corpus

Mutation hướng dẫn theo coverage có tính **tham lam**: một mẫu tạo coverage mới được lưu ngay, thường vẫn giữ lại nhiều vùng lớn không thay đổi. Theo thời gian, corpus trở thành tập hợp các **bản gần trùng lặp** với độ đa dạng cấu trúc thấp. Việc tối giản quá mức có thể loại bỏ ngữ cảnh hữu ích, vì vậy một giải pháp dung hòa thực tế là **tối giản có nhận biết grammar**, với điều kiện **dừng sau khi đạt ngưỡng token tối thiểu** (giảm nhiễu nhưng vẫn giữ đủ cấu trúc xung quanh để thuận tiện cho mutation).<sup>[[1]](#references)</sup>

Một quy tắc thực tế cho corpus khi dùng mutational fuzzing là: **ưu tiên một tập nhỏ các seed khác nhau về cấu trúc nhưng tối đa hóa coverage** thay vì một đống lớn các bản gần trùng lặp. Trên thực tế, điều này thường có nghĩa là:<sup>[[1]](#references)[[3]](#references)</sup>

- Bắt đầu từ **các mẫu thực tế** (corpus công khai, dữ liệu thu thập bằng crawling, traffic đã ghi lại, các tập tin từ hệ sinh thái mục tiêu).
- Tinh giản chúng bằng **tối giản corpus dựa trên coverage** thay vì giữ mọi mẫu hợp lệ.
- Giữ các seed **đủ nhỏ** để mutation tác động vào các trường có ý nghĩa, thay vì tiêu tốn phần lớn số chu kỳ vào các byte không liên quan.
- Chạy lại bước tối giản corpus sau những thay đổi lớn đối với harness/instrumentation, vì corpus “tốt nhất” sẽ thay đổi khi khả năng tiếp cận các đường thực thi thay đổi.

## Chương trình được tạo có kích thước lớn và sai lệch do timeout

Khi fuzzing compiler và interpreter, input có thể cần vượt qua **ngưỡng kích thước mã được tạo** thay vì đi qua một nhánh parser mới. Trong [ví dụ về offset exception handler](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) của V8, một testcase hợp lệ cần có hơn 256 MiB bytecode thì offset handler bị cắt ngắn mới gây ảnh hưởng. Các cấu trúc `yield*` lặp lại có thể đạt đến ngưỡng đó, nhưng việc biên dịch testcase mất vài giây trên bản debug. Việc ưu tiên input nhỏ và timeout thực thi ngắn có thể gây bất lợi cho loại trường hợp này, ngay cả khi coverage grammar cao. Khi kiểm tra các offset được đóng gói hoặc metadata nhạy cảm với độ dài, hãy xem xét riêng các ngưỡng kích thước và chính sách timeout; đây là khuyến nghị rút ra từ dạng lỗi được báo cáo.<sup>[[29]](#references)</sup>

## Mutation nhận biết phép so sánh cho các giá trị magic

Một lý do phổ biến khiến fuzzer chững lại không phải là cú pháp mà là **các phép so sánh khó vượt qua**: byte magic, kiểm tra độ dài, chuỗi enum, checksum hoặc giá trị điều phối parser được bảo vệ bằng `memcmp`, bảng switch hoặc chuỗi phép so sánh lồng nhau. Mutation ngẫu nhiên thuần túy lãng phí chu kỳ để đoán các giá trị này từng byte một.

Với những mục tiêu này, hãy dùng **tracing phép so sánh** (ví dụ: quy trình kiểu AFL++ `CMPLOG` / Redqueen) để fuzzer có thể quan sát các toán hạng từ những phép so sánh thất bại và ưu tiên mutation hướng đến các giá trị thỏa mãn chúng.<sup>[[3]](#references)</sup>

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

- Điều này đặc biệt hữu ích khi mục tiêu khóa logic chuyên sâu phía sau **chữ ký tệp**, **động từ giao thức**, **thẻ kiểu** hoặc **bit tính năng phụ thuộc phiên bản**.
- Kết hợp với **dictionaries** được trích xuất từ mẫu thực tế, đặc tả giao thức hoặc nhật ký debug. Một dictionary nhỏ chứa token ngữ pháp, tên chunk, động từ và dấu phân cách thường hữu ích hơn một wordlist chung khổng lồ.
- Nếu mục tiêu thực hiện nhiều bước kiểm tra tuần tự, hãy giải quyết các phép so sánh “magic” sớm nhất trước, sau đó lại tối giản corpus thu được để các giai đoạn sau bắt đầu bằng những tiền tố đã hợp lệ.

## Fuzzing API tệp ẩn một ngôn ngữ tên tệp

Một tham số có tên `filename`, `path` hoặc `URL` có thể là điểm vào của một interpreter thay vì chỉ tra cứu tệp theo nghĩa đen. Ví dụ, CFITSIO Extended Filename Syntax (EFS) đánh giá các bộ chọn trong ngoặc vuông, biểu thức hàng/pixel, cột được tính toán, histogram và phép biến đổi trước khi trả về đối tượng đã mở; một số dạng còn tạo bản sao tạm thời. Khi lập bản đồ bề mặt tấn công, hãy phân loại từng API mở/nhập là **literal-path** hoặc **interpreted-path**, sau đó fuzz điểm vào production mà các ứng dụng thực sự gọi.<sup>[[20]](#references)[[22]](#references)</sup>

Để tìm hiểu các primitive SSRF, sao chép tệp và trình xử lý giao thức phát sinh từ việc này — cũng như các API literal-path an toàn hơn — xem [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Giữ đối tượng nền tách biệt với chương trình được fuzz

Khi ngữ pháp nằm trong hậu tố tên tệp, chỉ sửa đổi byte của tệp được tham chiếu sẽ bỏ sót parser. Thay vào đó, một harness nhỏ có thể đọc testcase dưới dạng chuỗi rồi truyền chuỗi đó cho API mở interpreted; chiến dịch CFITSIO đã tiếp cận hầu hết parser và evaluator EFS bằng cách gọi `fits_open_file()` ở chế độ chỉ đọc. Hãy giữ sẵn các tệp nền hợp lệ riêng biệt để các đột biến tập trung vào ngôn ngữ bộ chọn/biểu thức thay vì liên tục làm hỏng đường dẫn cơ sở.<sup>[[22]](#references)</sup>

Sử dụng các seed sao cho mỗi seed tiếp cận một nhóm ngữ pháp khác nhau, rồi tạo dictionary gọn từ cả đặc tả lẫn mã nguồn lexer/parser. Nếu coverage chững lại trong khi các input liên tục thất bại tại cùng một nhánh lỗi cú pháp, hãy giữ lại các tiền tố hợp lệ và bổ sung dấu phân cách, toán tử, từ khóa, tên hàm và tên trường tiêu biểu thay vì chỉ tăng thời gian đột biến ngẫu nhiên.<sup>[[22]](#references)</sup>

Chạy harness với dictionary ngữ pháp, ví dụ:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Kiểm soát tác dụng phụ của harness "read-only"

Cờ thư viện read-only không đảm bảo testcase không gây tác dụng phụ: ngôn ngữ tên tệp có thể viết lại đầu vào, tạo tệp đầu ra hoặc tạo các đối tượng tạm thời. Chiến dịch CFITSIO ban đầu đã phá hủy các tệp seed và để lại những tệp ngoài dự kiến trên hệ thống tệp, vì vậy cần dọn dẹp và cô lập.<sup>[[22]](#references)</sup>

- Cấp cho mỗi worker một thư mục làm việc có thể hủy và một thư mục tạm riêng.
- Cung cấp các bản sao của tệp nền chuẩn; không bao giờ để target sửa đổi bản corpus duy nhất.
- Tắt quyền truy cập mạng trừ khi backend từ xa là mục tiêu, đồng thời giới hạn các đường dẫn có thể ghi bằng container, mount namespace hoặc sandbox tương đương.
- Đặt lại thư mục sau mỗi lần chạy hoặc mỗi batch worker, và xem các thay đổi hệ thống tệp ngoài dự kiến là phát hiện bổ sung.

### Vòng lặp crash-to-patch-to-fuzz

Phân nhóm crash trước khi sửa để hàng nghìn artifact không biến thành hàng nghìn tác vụ vá lỗi. Trong đợt đánh giá CFITSIO, AFLTriage đã giảm tập crash ban đầu xuống còn một vài nguyên nhân gốc; advisory sau đó nêu các lỗi riêng biệt, gồm kiểm tra sai kích thước đích, con trỏ cũ sau `realloc()`, lỗi số học và các đường dọn dẹp parser không an toàn.<sup>[[21]](#references)[[22]](#references)</sup>

1. Rút gọn một đầu vào tiêu biểu cho mỗi nhóm và tái hiện lỗi bằng AddressSanitizer.
2. Ghi lại chính xác thao tác truy cập gây lỗi, vị trí trong mã nguồn, lịch sử cấp phát/giải phóng và trạng thái parser khiến bất biến bị vi phạm.
3. Áp dụng một bản vá ứng viên có phạm vi hẹp và build lại với cùng cấu hình instrumentation cho coverage và sanitizer.
4. Chạy lại reproducer ban đầu **và mọi đầu vào trong nhóm**; đồng thời bật leak detection vì bản sửa lỗi an toàn bộ nhớ có thể làm hỏng việc quản lý quyền sở hữu trên đường xử lý lỗi.
5. Chạy các bài kiểm tra chức năng với tệp thực, sau đó tiếp tục từ queue đã tích lũy (hoặc nhập lại queue đó nếu engine yêu cầu thư mục đầu ra mới sau khi binary thay đổi).
6. Lặp lại: loại bỏ crash nông đầu tiên thường giúp các seed hiện có tiến sâu hơn vào trạng thái parser.

LLM có thể đẩy nhanh bước 2 và phác thảo bước 3 khi được cung cấp đầu vào gây crash, báo cáo sanitizer, harness và mã nguồn liên quan, nhưng bản vá của nó vẫn không đáng tin cậy. Việc sửa lỗi được chấp nhận hay không phải do các bước kiểm tra sanitizer và regression quyết định, chứ không phải phần giải thích của model.<sup>[[22]](#references)</sup>

## Phản hồi phong phú hơn khi Edge Coverage gộp các đường đi khác nhau

Edge coverage thông thường không phân biệt được hai lần thực thi đi qua cùng một helper từ các caller khác nhau hoặc kết hợp các nhánh khác nhau bên trong một hàm. Điều này quan trọng trong các decoder dùng chung, bộ điều phối giao thức và helper của interpreter, nơi **đường đi** dẫn đến một edge quyết định trạng thái đang hoạt động. Theo dõi mọi calling context một cách ngây thơ cũng nguy hiểm: coverage map và queue có thể phình to. Vì vậy, nghiên cứu về fuzzing nhạy theo context khuyến nghị chỉ tinh chỉnh các context tiềm năng thay vì áp dụng tính nhạy theo context cho toàn bộ call graph.<sup>[[14]](#references)</sup>

Các bản build AFL++ gần đây cung cấp **Ball-Larus per-function path coverage** bên cạnh edge coverage thông thường. Tính năng này gán một feature cho mỗi đường đi không chu trình qua một hàm; các cạnh quay lại của vòng lặp bị loại bỏ, nên phản hồi này phân biệt được các kết hợp nhánh nhưng **không phân biệt được số lần lặp vòng lặp**. Hãy bắt đầu với level `1` ít nghiêm ngặt, sau đó chỉ áp dụng các chế độ nghiêm ngặt hơn cho mã parser/state-machine đáng ngờ vì số lượng đường đi có thể tăng theo cấp số nhân.<sup>[[13]](#references)</sup>

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

- Chạy song song một instance edge-coverage thông thường; feedback phong phú hơn chỉ hữu ích nếu chi phí map/queue tăng thêm không làm giảm quá nhiều số lần thực thi mỗi giây.
- Dùng `AFL_LLVM_ALLOWLIST` để giới hạn instrumentation theo path/caller khi các thư viện nhiều template hoặc mã tiện ích tổng quát chiếm phần lớn map.
- Có thể bỏ qua các hàm có quá nhiều path không chu trình bằng AFL++; cảnh báo khi biên dịch là dấu hiệu cho thấy target cần allowlisting hoặc một level ít nghiêm ngặt hơn.
- Caller + path coverage chỉ hỗ trợ một caller depth. Không kết hợp tính năng này với các context stack sâu hơn.
- Path ID có thể thay đổi giữa các phiên bản major của LLVM. Giữ nguyên toolchain trong suốt campaign và không đồng bộ các corpus dựa trên PATH như thể feature ID của chúng ổn định giữa các lần build.
- Feedback này bổ trợ cho `CMPLOG`: comparison tracing xác định **giá trị nào vượt qua guard**, còn path/caller feedback lưu lại **route và tổ hợp branch nào đã dẫn tới đó**.

## Fuzzing có trạng thái: Chuỗi là Seed

Với **protocol**, **workflow đã xác thực** và **parser nhiều giai đoạn**, đơn vị đáng quan tâm thường không phải là một blob đơn lẻ mà là một **chuỗi message**. Nối toàn bộ transcript vào một file rồi đột biến một cách mù quáng thường không hiệu quả, vì fuzzer đột biến mọi bước như nhau, ngay cả khi chỉ message phía sau mới đi tới trạng thái dễ xảy ra lỗi.<sup>[[4]](#references)</sup>

Cách hiệu quả hơn là coi **bản thân chuỗi** là seed và dùng **trạng thái có thể quan sát** (mã phản hồi, trạng thái protocol, giai đoạn parser, kiểu object được trả về) làm feedback bổ sung.<sup>[[4]](#references)</sup>

- Giữ ổn định các **message prefix hợp lệ** và tập trung đột biến vào message **điều khiển chuyển trạng thái**.
- Lưu các định danh và giá trị do server tạo ra từ những phản hồi trước đó khi bước tiếp theo phụ thuộc vào chúng.
- Ưu tiên đột biến/splicing từng message thay vì đột biến toàn bộ transcript đã serialize như một blob không rõ cấu trúc.
- Nếu protocol cung cấp các mã phản hồi có ý nghĩa, hãy dùng chúng làm **state oracle** ít tốn kém để ưu tiên các chuỗi tiến sâu hơn.

Đây cũng là lý do các bug cần xác thực, chuyển trạng thái ẩn hoặc bug parser “chỉ xảy ra sau handshake” thường bị bỏ sót khi fuzzing kiểu file thông thường: fuzzer phải duy trì **thứ tự, trạng thái và các dependency**, chứ không chỉ cấu trúc.<sup>[[4]](#references)</sup>

### Android Binder: fuzzing driver nhiều client

Edge coverage cao vẫn có thể bỏ sót bug trong IPC driver vì coverage không mô tả **quyền sở hữu object, reference count, message đang chờ, thứ tự cleanup hoặc sự xen kẽ giữa các thread**. Trang [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) trình bày mô hình object của driver; ví dụ này tập trung vào harness của fuzzer. Android Binder là một mô hình hữu ích: chỉ đi qua cả các path cấp phát và giải phóng là chưa đủ nếu fuzzer không thể khiến nhiều process thao tác trên cùng một kernel object theo đúng thứ tự cần thiết.<sup>[[15]](#references)</sup>

#### Mô hình hóa protocol, không phải các buffer `ioctl` riêng lẻ

Biểu diễn một test case dưới dạng grammar có thứ tự gồm **danh tính client + operation + đối số có cấu trúc**. Binder LKL fuzzer dùng protobuf và `libprotobuf-mutator`, với một client context-manager tồn tại lâu dài và hai client thông thường. Sau đó, harness ngữ nghĩa duy trì các mối liên hệ mà việc đột biến byte mù quáng sẽ phá hủy.<sup>[[15]](#references)</sup>

- Lưu các giá trị được trả về từ những operation trước đó. Ví dụ, `BC_FREE_BUFFER` phải dùng lại con trỏ transaction-buffer được một `ioctl` trước đó trả về.
- Tạo các reply mặc định hợp lệ để transaction đồng bộ có thể hoàn tất và các operation tiếp theo vẫn có thể được thực thi.
- Từ chối các chuyển trạng thái bất khả thi như transaction tới chính mình hoặc nhiều transaction đang chờ cùng một target.
- Giữ trạng thái khởi tạo singleton bên ngoài quá trình reset theo từng input. Binder chỉ cho phép đăng ký `BINDER_SET_CONTEXT_MGR` một lần mỗi lần boot, vì vậy việc liên tục hủy rồi tạo lại client đó sẽ khiến các input sau không hợp lệ.

Một mẫu race hữu ích liên quan đến vòng đời là để một client chuyển một object, khởi chạy quá trình cleanup của thread hoặc process, đồng thời khiến client nhận giải phóng transaction buffer. Trong ví dụ CVE-2020-0423, việc chuyển `BINDER_TYPE_WEAK_BINDER`, sau đó để `BINDER_THREAD_EXIT` đua với `BC_FREE_BUFFER`, có thể giải phóng một `binder_work` được nhúng trong object trong khi đường cleanup của thread đang thoát vẫn còn sử dụng nó.<sup>[[15]](#references)</sup>

#### Tạo lại các tình huống xen kẽ có kiểm soát trong kernel userspace

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) liên kết mã kernel thực vào một harness userspace và cung cấp giao diện syscall thông qua `lkl_syscall`. Nhờ vậy, có thể dễ dàng phối hợp protobuf state, coverage và KASAN trong cùng một process. Tuy nhiên, LKL thường chạy một syscall mà không có kernel thread khác ngắt quãng. Với các campaign tìm race, hãy chèn các điểm `schedule()` quanh những ranh giới lock/unlock và vòng đời đã chọn, rồi để harness chọn ngẫu nhiên client tiếp theo tại mỗi lần nhường chạy. Chỉ đặt các điểm này ở những vị trí cụ thể vì mỗi điểm đều làm tăng không gian tìm kiếm lịch thực thi. Randomized scheduler được các nhà nghiên cứu mô tả **không** thuộc upstream Binder fuzzer.<sup>[[15]](#references)</sup>

#### Build và phát lại các regression seed đã serialize

Harness upstream cố định một phiên bản `libprotobuf-mutator` tương thích, bật instrumentation cho LKL fuzzing và KASAN bằng `LKL_FUZZING=1`, đồng thời bật `CONFIG_MMU` cho Binder bằng `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Sau khi checkout một revision cố ý chứa lỗ hổng hoặc áp dụng các bản vá rollback được tài liệu hóa ở upstream, một seed đã serialize có thể tái hiện toàn bộ quá trình chuyển trạng thái đa client mà không cần dựng lại nó trong một proof of concept C tùy biến:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Hãy xem KASAN use-after-free là dấu hiệu xác nhận seed đã đi đến đường dẫn vòng đời dễ bị tổn thương. Điều này **không** chứng minh các primitive về sau cần thiết để thực thi mã kernel hoặc leo thang đặc quyền.<sup>[[16]](#references)</sup>

## Mẹo đa dạng hóa trên một máy (kiểu Jackalope)

Một cách thực tế để kết hợp **tính mới do sinh tạo** với **việc tái sử dụng coverage** là **khởi động lại các worker chạy ngắn hạn** để kiểm thử một server chạy liên tục. Mỗi worker bắt đầu với corpus rỗng, đồng bộ sau `T` giây, chạy thêm `T` giây trên corpus đã kết hợp, đồng bộ lần nữa rồi thoát. Cách này tạo ra **các cấu trúc mới ở mỗi thế hệ** đồng thời tận dụng coverage đã tích lũy.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Các worker tuần tự (ví dụ vòng lặp):**

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
- `-server_update_interval T` mô phỏng **đồng bộ trễ** (ưu tiên novelty trước, tái sử dụng sau).
- Trong chế độ grammar fuzzing, **đồng bộ server ban đầu được bỏ qua theo mặc định** (không cần `-skip_initial_server_sync`).
- Giá trị `T` tối ưu **phụ thuộc vào target**; thường hiệu quả nhất là chuyển đổi sau khi worker đã tìm được phần lớn coverage “dễ”.

## Snapshot Fuzzing Cho Các Target Khó Tạo Harness

Khi đoạn code bạn muốn kiểm thử chỉ có thể truy cập **sau một bước thiết lập tốn kém** (khởi động VM, hoàn tất đăng nhập, nhận packet, parse container, khởi tạo service), một lựa chọn thay thế hữu ích là **snapshot fuzzing**: chụp trạng thái process hoặc VM đã sẵn sàng, đưa từng test case vào đường dẫn input của target, thực thi đến khi xảy ra crash/timeout, rồi khôi phục snapshot. Cách này tránh phải lặp lại bước khởi tạo hoặc các tiền tố protocol, hữu ích cho **network service**, **firmware**, **bề mặt tấn công sau xác thực** và **target chỉ có binary**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Chạy target cho đến khi trạng thái cần thiết sẵn sàng.
2. Chụp snapshot **memory + register** tại thời điểm đó.
3. Với mỗi test case, ghi input đã bị mutate trực tiếp vào buffer liên quan của guest/process.
4. Thực thi đến khi xảy ra crash/timeout/reset.
5. Khôi phục snapshot; với target là VM, chỉ khôi phục **các trang đã thay đổi** nếu được hỗ trợ, rồi lặp lại.

Đặt snapshot gần nhất có thể với bước parse/dispatch tốn kém đầu tiên, chẳng hạn sau một điểm `recv`/`read` hoặc giải tuần tự packet, và ghi lại buffer input mà target sử dụng. Cách này tuân theo nguyên tắc bố trí thích ứng: di chuyển snapshot sâu hơn vào quá trình xử lý input để tránh lặp lại công việc.<sup>[[11]](#references)</sup>

### Snapshot tăng dần cho các trạng thái protocol

Snapshot cố định giúp tránh chi phí thiết lập, nhưng bản thân nó không khám phá được các chuyển trạng thái cần nhiều message hợp lệ. Harness LibAFL-Qemu có thể theo dõi các lần ghi vào một trường trạng thái protocol và lưu snapshot mới khi trạng thái thay đổi. Trong [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful), harness theo dõi `tcpcb.t_state`, hash trạng thái và các cờ phản hồi để loại bỏ snapshot trùng lặp, đồng thời lưu các trang đã thay đổi so với snapshot cha. Trước khi mutate message có cấu trúc tiếp theo, harness khôi phục snapshot đã chọn theo chuỗi snapshot cha. Testcase lưu `SnapshotId` và các byte input đã tạo (`gen_bytes`); snapshot manager theo dõi quan hệ cha cần thiết để replay.<sup>[[27]](#references)[[28]](#references)</sup>

`SnapshotModule` user-mode của LibAFL-Qemu lưu các mapping và memory của target nhưng không lưu register CPU; khi cần, hãy lưu riêng các register này. Manager được mô tả chỉ hỗ trợ một cây snapshot gốc và không thể chia sẻ ID snapshot giữa các worker. Chế độ multi-snapshot cũng không thể trực tiếp tái sử dụng trạng thái shadow của QASAN. Để triage offline, hãy tái tạo chuỗi input trong một process riêng có instrumentation. Khi dùng `AsanHostModule` và `DrCovModule`, `fuzzer.evaluate_input` chạy các callback `pre_exec`/`post_exec` cần thiết; chỉ gọi `qemu.run` thì không.<sup>[[27]](#references)[[28]](#references)</sup>

### Phát hiện đọc vượt quá logical ring buffer

Một lần đọc vượt quá *số lượng dữ liệu hợp lệ* của buffer có thể vẫn nằm trong vùng cấp phát trên host và không bị ASAN thông thường phát hiện. Ví dụ về dữ liệu khẩn cấp trong [libslirp](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) cũng làm underflow một số đếm byte unsigned. Khi có source, instrumentation phát hiện integer overflow có dấu/không dấu có thể phát hiện tác động phụ đó; hãy phân biệt với hiện tượng wrap số thứ tự TCP có chủ ý trước khi bỏ qua các báo cáo. Một oracle mạnh hơn được đề xuất là poison vùng cấp phát ring tùy chỉnh, chỉ unpoison các phạm vi hợp lệ khi allocator nội bộ tiến lên, rồi poison lại các vùng đã được giải phóng. LibAFL-Qemu cung cấp API poisoning ASAN cho các target khó áp dụng instrumentation trên source.<sup>[[27]](#references)</sup>

## Khám Phá Race Trong Linux Kernel Với MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) biến các race nhạy với timing trong Linux kernel thành những lịch truy cập memory có thể lặp lại. Công cụ có thể tự động liệt kê các lần thực thi **A-B-A** trong hai context, hoặc cho phép analyst đặt các ràng buộc thứ tự thông qua terminal UI/GUI. Đây là công cụ nghiên cứu thử nghiệm, không phải một concurrency fuzzer hoàn chỉnh: hiện tại, công cụ cần LLVM 23+ và kernel đã được patch của dự án; các công cụ command-line hỗ trợ hai test thread, còn lớp fuzzing userspace được đề xuất vẫn chưa được triển khai.<sup>[[17]](#references)[[18]](#references)</sup>

### Thu thập các điểm giao tiếp giữa các context

Build kernel đã instrument với callback KASAN outline và hỗ trợ ghi nhận memory của KCOV đã được patch. README của dự án cũng khuyến nghị tắt tối ưu hóa sibling-call để call stack vẫn hữu dụng.<sup>[[17]](#references)[[18]](#references)</sup>

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

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) chuyển các truy cập đã được instrument thành các lời gọi helper. Các bản vá kernel MAccConc vô hiệu hóa `asan-opt-same-temp` để các truy cập liên tiếp không bị gộp; cũng vô hiệu hóa tối ưu hóa `asan-opt-globals` khi cần phát hiện các race trên biến toàn cục. KCOV chuyển các bản ghi thu được đến userspace. So sánh các truy cập từ những execution context khác nhau và giữ lại các cặp có vùng byte chồng lấn, trong đó ít nhất một phía có thao tác ghi; xem `kfree()` như một thao tác ghi để các chuyển đổi vòng đời cũng trở thành ứng viên.<sup>[[17]](#references)</sup>

Với công việc tiếp tục chạy ngoài task khởi tạo, chẳng hạn xử lý packet hoặc callback RCU, subsystem phải truyền tiếp handle remote-coverage của KCOV. Remote KCOV ở upstream là tùy chọn và không tự động khả dụng cho các công việc nền bất kỳ, vì vậy việc không truyền tiếp handle có thể khiến một tương tác thực sự không được ghi nhận.<sup>[[17]](#references)[[19]](#references)</sup>

### Nhận diện cùng một truy cập động trong mỗi lần chạy

Không replay dựa trên địa chỉ heap cụ thể, vì địa chỉ có thể thay đổi sau mỗi lần cấp phát, hoặc chỉ dựa trên địa chỉ instruction, vì địa chỉ này không đủ để phân biệt bên trong các helper như `memcpy()` và `spin_lock()`. MAccConc sử dụng **stack trace có bổ sung bộ đếm**: mỗi frame xác định một callee cùng số lần được gọi bên trong caller của nó, còn phần tử cuối cùng xác định instruction truy cập bộ nhớ. Các bản ghi entry/exit của hàm SanitizerCoverage cho phép userspace dựng lại identifier động này; identifier vẫn ổn định khi địa chỉ thay đổi và khi có nhiễu từ luồng điều khiển không liên quan.<sup>[[17]](#references)</sup>

### Chuyển các cặp ứng viên thành lịch thực thi bị ép buộc

Ioctl `KCOV_SET_DI` đã được vá liên kết một identifier truy cập có bổ sung bộ đếm với một hành động trên shared flag.<sup>[[17]](#references)</sup>

| Action | Semantics |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Đặt flag *N* ngay trước truy cập được chọn. |
| `DI_STACK_WAIT` | Trước truy cập được chọn, spin cho đến khi flag *N* được đặt hoặc hết giới hạn đã cấu hình. |
| `DI_STACK_WAKE_POST` | Đặt flag *N* ngay sau truy cập được chọn. |

Để áp đặt một ràng buộc **A-happens-before-B** một phần, gắn `DI_STACK_WAKE_POST` với A và `DI_STACK_WAIT` với B, dùng cùng một flag. Với một lịch thực thi hai context được xác định đầy đủ, bắt đầu bằng cách chặn B, sau đó để A đánh thức B và chờ tại điểm chuyển giao đầu tiên; tại lần chuyển giao tiếp theo, B thực hiện thao tác ngược lại. Cách thứ hai hoạt động như chuyển đổi context có tính xác định và được trình khám phá A-B-A tự động sử dụng.<sup>[[17]](#references)</sup>

Một campaign tối thiểu là biên dịch test case bốn hook (`test_setup`, hai hàm thread và `test_end`) thành shared library, thu thập trace không có ràng buộc, rồi liệt kê các ứng viên A-B-A hoặc thêm các ràng buộc thủ công quanh những truy cập đáng ngờ.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Diễn giải timeout riêng với các lần sắp xếp lại thành công: thứ tự được yêu cầu có thể không thực hiện được vì lock hoặc phụ thuộc khởi tạo/công bố khiến context thứ hai không thể đến điểm injection. Cũng cần lưu ý các điểm mù của KASAN: truy cập stack trực tiếp thường không được hook, trừ khi có khả năng vượt giới hạn; biến toàn cục bị bỏ qua với tùy chọn tối ưu hóa mặc định; và các compiler hiện tại không thể đồng thời phát sinh hook ASAN và TSAN. Prototype sẽ mất buffer KCOV khi guest gặp panic, vì vậy hãy duy trì một console/oracle sự cố độc lập.<sup>[[17]](#references)</sup>

Để hỗ trợ fuzzing có hướng dẫn theo concurrency trong tương lai, hãy ghi lại tóm tắt truy cập bộ nhớ theo từng input hoặc syscall, ghép các operation có thể tạo thành điểm giao tiếp giữa các context, rồi chỉ khám phá những tổ hợp đó. VM snapshot giúp ổn định trạng thái và địa chỉ toàn cục; nếu không dùng snapshot, metadata của allocation site có thể trừu tượng hóa các object qua nhiều lần chạy. Đây là phần mở rộng được đề xuất, không phải tính năng của các công cụ userspace MAccConc hiện tại.<sup>[[17]](#references)</sup>

## Harness Introspection: Tìm các fuzzer nông từ sớm

Khi một campaign bị đình trệ, vấn đề thường không nằm ở mutator mà ở **harness**. Dùng **phân tích nội quan về khả năng tiếp cận/độ bao phủ** để tìm các function có thể được gọi về mặt tĩnh từ fuzz target của bạn nhưng hiếm khi hoặc chưa bao giờ được bao phủ khi chạy thực tế. Những function đó thường cho thấy một trong ba vấn đề sau.<sup>[[12]](#references)</sup>

- Harness đi vào target quá muộn hoặc quá sớm.
- Seed corpus thiếu hẳn một nhóm tính năng.
- Target thực sự cần **harness thứ hai** thay vì một harness “làm mọi thứ” quá lớn.

Nếu dùng quy trình kiểu OSS-Fuzz / ClusterFuzz, Fuzz Introspector có thể so sánh khả năng tiếp cận tĩnh với độ bao phủ khi chạy thực tế và tạo báo cáo từ một lần chạy có giới hạn thời gian hoặc corpus công khai.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Dùng báo cáo để quyết định có nên thêm harness mới cho một nhánh parser chưa được kiểm thử, mở rộng corpus cho một tính năng cụ thể hay chia một harness nguyên khối thành các entry point nhỏ hơn.

## Lựa chọn mục tiêu fuzzing theo đồ thị và phân loại mutation

Nếu bạn đã có các **phát hiện từ static analysis**, **mutation-testing survivor** và **báo cáo coverage**, đừng phân loại chúng thành các danh sách độc lập. Trước tiên, hãy xây dựng **call graph**, chú thích các node bằng **độ phức tạp cyclomatic**, **khả năng tiếp cận từ entrypoint/đầu vào không đáng tin cậy** và mọi phát hiện bên ngoài, rồi đặt câu hỏi về đồ thị.<sup>[[5]](#references)[[6]](#references)</sup>

- Những hàm có độ phức tạp cao nào có thể được gọi từ đầu vào không đáng tin cậy?
- Những mutation survivor nào nằm trên đường đi từ parser/handler đến code trọng yếu về bảo mật?
- Những hàm nào là nút thắt kiến trúc với **phạm vi ảnh hưởng** lớn bất thường?

Cách này thường giúp tìm ra mục tiêu fuzzing tốt hơn so với chỉ chọn nơi có “coverage thấp nhất”. Một parser/decoder có **độ phức tạp cao** và đã xác nhận **có thể được gọi từ bên ngoài** là ứng viên harness tốt hơn một helper nội bộ riêng lẻ có coverage thấp nhưng không có đường đi nhận dữ liệu do kẻ tấn công kiểm soát.

### Quy trình phân loại thực tế

1. Xây dựng **đồ thị code** từ codebase và trích xuất các chỉ số về độ phức tạp/nhánh cho từng hàm.
2. Liệt kê các **entrypoint** nhận đầu vào do kẻ tấn công kiểm soát: request handler, decoder, importer, protocol parser, CLI/file reader.
3. Chạy truy vấn đường đi từ các entrypoint đó đến những hàm ứng viên để phân biệt bề mặt tấn công có thể tiếp cận với code đã chết/chỉ dùng nội bộ.
4. Ưu tiên các node kết hợp những yếu tố sau:
   - **độ phức tạp cyclomatic** cao
   - đã xác nhận **có thể tiếp cận từ đầu vào không đáng tin cậy**
   - **phạm vi ảnh hưởng** lớn hoặc có nhiều thành phần phụ thuộc phía sau
   - có bằng chứng hỗ trợ như phát hiện **SARIF**, ghi chú audit hoặc mutation survivor
5. Trước tiên, hãy viết các harness tập trung cho những node có điểm cao nhất, đặc biệt là **parser/codec** như bộ giải mã hex/Base64/IP/message.

### Mutation survivor: tương đương hay đáng xử lý

Mutation testing thường tạo ra một danh sách survivor nhiễu. Trước khi xem mọi survivor là lỗ hổng bảo mật, hãy dùng đồ thị để đặt câu hỏi:

- Hàm bị đột biến có thể được gọi từ một entrypoint nhận dữ liệu do kẻ tấn công kiểm soát không?
- Mọi đường gọi có bị ràng buộc bởi các invariant mạnh hơn điều kiện kiểm tra bị đột biến không?
- Node nằm trong code đã chết, logic chỉ định dạng dữ liệu hay đường xử lý số học/parser có tác động cao?

Các survivor vẫn không thể tiếp cận hoặc bị ràng buộc về cấu trúc thường là **mutant tương đương**. Các survivor vẫn **có thể tiếp cận** và liên quan đến **điều kiện biên**, **đường xử lý tràn/carry** hoặc **số học/phân tích cú pháp trọng yếu về bảo mật** cần được ưu tiên để bổ sung:

- harness fuzzing mới
- kiểm thử thuộc tính/invariant trực tiếp
- vector kiểm thử trường hợp biên có mục tiêu

### Đối chiếu các phát hiện bên ngoài lên đồ thị

Nếu pipeline SAST của bạn xuất **SARIF**, hãy ánh xạ các phát hiện lên node trong đồ thị theo **file + khoảng dòng** và dùng đồ thị để mở rộng phạm vi tác động.<sup>[[6]](#references)</sup>

- tính **phạm vi ảnh hưởng** của hàm bị đánh dấu
- kiểm tra xem phát hiện có nằm trên đường đi từ entrypoint nào không
- gom nhóm các phát hiện gần nhau nếu chúng cùng quy về một nút thắt

Điều này hữu ích khi quyết định có nên dành thời gian fuzzing cho một hàm cụ thể hay không: một node **có thể tiếp cận**, **phức tạp** và đã có **phát hiện SAST** thường là mục tiêu tốt hơn node chỉ phức tạp nhưng không có đường đi từ đầu vào của kẻ tấn công.

Quy trình mẫu với Trailmark.<sup>[[6]](#references)</sup>

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

Phương pháp luận quan trọng là phần giao nhau: **độ phức tạp x mức độ phơi nhiễm x tác động**. Dùng biểu đồ để chọn các mục tiêu fuzz có giá trị bảo mật kỳ vọng cao nhất, sau đó dùng các đột biến còn sống sót để xác định những ranh giới và bất biến mà harness cần kiểm tra kỹ.<sup>[[5]](#references)</sup>

## Fuzzing vi sai các mã hóa khóa mật mã

Bắt đầu từ các khóa đã tuần tự hóa hợp lệ hoặc các bộ vector kiểm thử tiêu chuẩn. Đột biến các trường đã mã hóa mà không phá vỡ độ dài và cấu trúc cần thiết để tiếp cận các đường đi import và thao tác, sau đó gửi cùng một byte đến các triển khai độc lập. So sánh việc chấp nhận và lỗi. Chữ ký và bản mã ngẫu nhiên cần oracle kiểm tra tính đúng đắn, không phải so sánh từng byte: xác minh chữ ký hoặc so sánh các bí mật dùng chung thu được từ một lượt đóng gói/mở gói. Bộ vector kiểm thử xác lập tính phù hợp với tiêu chuẩn cho các trường hợp đã biết; đột biến vi sai thăm dò các mã hóa sai lệch ngoài phạm vi đó.<sup>[[23]](#references)[[26]](#references)</sup>

Với các định dạng khóa này, hãy dùng oracle đặc thù cho từng định dạng:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Khóa ký mở rộng ML-DSA:** thay đổi các hệ số `s1` hoặc `s2` được đóng gói để chúng nằm ngoài `[-η, η]`, đồng thời giữ khóa ở trạng thái có thể phân tích cú pháp. Kiểm tra xem quá trình import hoặc ký có từ chối khóa hay không, và liệu chữ ký tạo ra có xác minh được hay không. Chỉ riêng khác biệt trong việc chấp nhận không phải là vi phạm tiêu chuẩn, vì FIPS 204 không bắt buộc kiểm tra bổ sung đối với khóa riêng. Xem [cơ chế rò rỉ có điều kiện](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **Cặp khóa ML-KEM:** tách biệt các bước kiểm tra bắt buộc đối với khóa đóng gói và đầu vào giải đóng gói khỏi bước kiểm tra tính nhất quán theo cặp (PCT) tùy chọn trên một cặp khóa đã import. Đóng gói bằng khóa công khai, giải đóng gói bằng khóa riêng và so sánh các bí mật dùng chung; kết quả không khớp có thể làm gián đoạn giao tiếp được mã hóa, ngay cả khi từng khóa đều vượt qua bước kiểm tra đầu vào. Kiểm tra xem API xác thực đầu vào trong thao tác hay thông qua một lệnh gọi riêng; libcrux cung cấp `validate_public_key(pk)` và `validate_private_key(sk, ct)`, nhưng các hàm này không thay thế PCT.
- **Khóa thô XMSS/XMSSMT:** kiểm thử các lượt tuần tự hóa rồi phân tích ngược khóa **ký và xác minh** trên nhiều bộ tham số, thay vì chỉ kiểm thử thao tác với khóa trong bộ nhớ. XMSS và XMSSMT có các không gian OID bốn byte riêng biệt, vì vậy một trình phân tích cú pháp chỉ kiểm tra OID theo thứ tự ưu tiên XMSS có thể phân loại nhầm khóa XMSSMT trùng OID và từ chối import. Trình phân tích cú pháp RustCrypto được báo cáo là ví dụ về lỗi tương tác/khả dụng, không phải giả mạo chữ ký.

## Fuzzing Go với gosentry: Engine mạnh hơn, đầu vào có kiểu và kiểm tra vi sai

Nếu mục tiêu Go đã có harness `testing.F` gốc, một hướng nâng cấp thiết thực là chạy cùng harness đó với [gosentry](https://github.com/trailofbits/gosentry), một Go toolchain được fork, vẫn dùng `go test -fuzz` nhưng thay backend bằng **LibAFL**.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Điều này hữu ích khi Go fuzzer gốc bị đình trệ trước **các phép so sánh khó**, **đầu vào có kiểu**, hoặc **các định dạng nặng về parser**. Phương pháp vẫn giữ nguyên:

- Tiếp tục dùng `f.Add(...)` cho seed và `f.Fuzz(...)` cho callback.
- Dùng lại cùng harness, nhưng chạy bằng binary `go` của gosentry thay vì toolchain tiêu chuẩn.
- Xem campaign thu được như một lần chạy coverage-guided thông thường, nhưng có cơ chế lập lịch/mutation của LibAFL và các detector hỗ trợ tốt hơn.

### Biến các lỗi im lặng thành phát hiện từ fuzzing

Một vấn đề thường gặp trong các bài đánh giá Go là hành vi nguy hiểm thường **không** gây crash theo mặc định. Với gosentry, bạn có thể biến một số trạng thái “xấu nhưng im lặng” thành phát hiện.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` để khiến các đường dẫn ghi log/báo lỗi được chọn hoạt động như crash (hữu ích với các đường dẫn kiểu `log.Fatal` vốn chỉ ghi log rồi tiếp tục).
- `--catch-races=true` để chạy lại các mục mới được phát hiện trong queue bằng Go race detector.
- `--catch-leaks=true` để chạy lại các mục mới trong queue bằng `goleak` và dừng khi phát hiện goroutine bị leak.
- Cơ chế xử lý hang của LibAFL để giữ **vòng lặp vô hạn / đầu vào xử lý rất chậm** làm phát hiện từ fuzzing thay vì để chúng biến mất dưới dạng timeout.
- Mặc định có sẵn các kiểm tra tràn số học, cùng các kiểm tra truncation tùy chọn thông qua instrumentation kiểu go-panikint.

Điều này đặc biệt có giá trị với các mục tiêu mà tác động bảo mật là **lỗi parser không gây panic**, **lỗi đồng thời**, hoặc **hang chỉ gây DoS** thay vì memory corruption.

### Fuzzing nhận biết struct cho các API Go có kiểu

Go fuzzing gốc chủ yếu hỗ trợ các giá trị vô hướng như `[]byte`, `string` và số. Nếu mã đang được kiểm thử sử dụng các đối tượng có kiểu, gosentry có thể fuzz trực tiếp **các giá trị tổ hợp** (struct, slice, array, pointer) trong khi vẫn mutation các byte bên dưới.<sup>[[7]](#references)[[8]](#references)</sup>

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

Hãy dùng cách này khi việc tạo một wire format giả chỉ để fuzzing sẽ khiến các lỗi logic bị che khuất bởi mã phân tích cú pháp chỉ có trong harness. Với các chiến dịch differential hoặc grammar-based, hãy giữ đầu vào của harness dưới dạng một `[]byte` hoặc `string` duy nhất và phân tích cú pháp bên trong callback.

### Fuzzing dựa trên grammar cho parser và đầu vào giao thức

Với parser, định dạng và ngôn ngữ đầu vào, gosentry có thể chạy **Nautilus grammar fuzzing** dựa trên LibAFL. Grammar là một mảng JSON gồm các quy tắc sản sinh, và harness thường nên nhận một đối số `[]byte` hoặc `string` duy nhất.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Ghi chú về phương pháp:

- Dùng grammar mode khi các mutation ở cấp byte hầu hết đều bị loại ở những bước kiểm tra cú pháp ban đầu.
- Giữ grammar tập trung vào **tập con liên quan đến bảo mật** của ngôn ngữ/giao thức thay vì mô hình hóa toàn bộ đặc tả.
- Dùng các giá trị biên lớn trong terminals/nonterminals để kiểm thử các giới hạn của số nguyên, độ dài và máy trạng thái.
- Grammar mode giữ cho input hợp lệ theo grammar, nhưng target vẫn nhận **bytes/strings**, vì vậy việc phân tích cú pháp và kiểm tra ngữ nghĩa vẫn diễn ra bên trong code được harness.

### Differential fuzzing: so sánh các implementation, không chỉ tìm crash

Một phương pháp hiệu quả trong hệ sinh thái Go là **grammar-based differential fuzzing**: tạo input có cấu trúc hợp lệ rồi đưa chúng vào hai parser, client hoặc engine chuyển trạng thái.<sup>[[7]](#references)[[8]](#references)</sup>

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

Coi những trường hợp sau là kết quả:

- một triển khai bị panic trong khi triển khai kia từ chối đầu vào một cách an toàn
- đầu vào được chấp nhận/từ chối không khớp nhau
- cây phân tích cú pháp hoặc đối tượng đã giải mã khác nhau
- trạng thái chuyển đổi, nonce, số dư hoặc state root khác nhau

Đây là một cách thực tế để tìm ra **các điểm không khớp về đồng thuận**, **sự mơ hồ của parser** và **sự sai lệch giữa đặc tả với triển khai** mà fuzzing chỉ tìm lỗi crash thường bỏ sót.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Dùng lại corpus của campaign để báo cáo coverage

Sau một campaign, chạy lại corpus hàng đợi đã lưu để tạo báo cáo coverage của Go mà không cần xuất corpus riêng theo cách thủ công.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Chạy lệnh từ **cùng package** và với **cùng mục tiêu `-fuzz`** để gosentry phân giải đúng trạng thái campaign được lưu trong cache.

## References

- [1] [Fuzzing ngữ pháp đột biến](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [Fuzzing AFL++ chuyên sâu](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet sau năm năm: Fuzzing giao thức dựa trên độ phủ](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark chuyển mã thành đồ thị](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go fuzzing còn thiếu một nửa bộ công cụ. Chúng tôi fork toolchain để khắc phục](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Fuzzer greybox nhanh cho các giao thức mạng có trạng thái, sử dụng snapshot](https://arxiv.org/abs/2202.03643)
- [10] [Không có ngữ pháp cũng không sao: Hướng tới fuzzing Linux kernel mà không cần mô tả system call](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Fuzzing hiệu quả với snapshot thích ứng và có thể thay đổi](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [Instrumentation LLVM của AFL++: độ phủ đường dẫn và caller](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Fuzzing dự đoán, nhạy theo ngữ cảnh](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Blog Android Offensive Security - Fuzzing Binder](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [Fuzzer LKL Android Binder - tài liệu build và seed hồi quy](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Khảo sát các điều kiện race trong Linux kernel với các thứ tự xen kẽ truy cập bộ nhớ được kiểm soát](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: độ phủ mã cho fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Cú pháp tên tệp mở rộng của CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Thông báo bảo mật của Doyensec: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing cú pháp tên tệp mở rộng của CFITSIO: 16 lỗ hổng an toàn bộ nhớ và phân loại có hỗ trợ của Codex](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Fuzzing vi sai cho mật mã](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Tiêu chuẩn cơ chế đóng gói khóa dựa trên mạng mô-đun](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Lỗi phân tích OID XMSSMT - RustCrypto issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Tình hình triển khai mật mã hậu lượng tử](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Dùng snapshot để tìm ra CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero - Fuzzer đối đầu AI: So sánh Fuzzilli và BigSleep trên các JavaScript engine](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
