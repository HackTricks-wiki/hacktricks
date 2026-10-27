# Path Traversal khi giải nén archive ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Tổng quan

Nhiều định dạng archive (ZIP, RAR, TAR, 7-ZIP, v.v.) cho phép mỗi mục chứa **đường dẫn nội bộ** riêng. Khi tiện ích giải nén tuân theo đường dẫn đó một cách mù quáng, một tên tệp được tạo thủ công có chứa `..` hoặc **đường dẫn tuyệt đối** (ví dụ: `C:\Windows\System32\`) sẽ được ghi ra ngoài thư mục do người dùng chọn.  
Loại lỗ hổng này thường được gọi là *Zip-Slip* hoặc **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Hậu quả có thể từ ghi đè các tệp tùy ý đến trực tiếp đạt được **remote code execution (RCE)** bằng cách thả payload vào vị trí **tự động chạy**, chẳng hạn như thư mục *Startup* của Windows.

## Nguyên nhân gốc rễ

1. Attacker tạo một archive trong đó một hoặc nhiều header tệp chứa:
   * Các chuỗi traversal tương đối (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Đường dẫn tuyệt đối (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Hoặc **symlink** được tạo thủ công để trỏ ra ngoài thư mục đích (thường gặp trong ZIP/TAR trên *nix*). 
2. Victim giải nén archive bằng một công cụ có lỗ hổng, công cụ này tin cậy đường dẫn được nhúng (hoặc đi theo symlink) thay vì làm sạch đường dẫn hoặc buộc giải nén bên trong thư mục đã chọn.
3. Tệp được ghi vào vị trí do attacker kiểm soát và được thực thi/tải vào lần tiếp theo hệ thống hoặc người dùng kích hoạt đường dẫn đó.

### Path traversal với .NET `Path.Combine` + `ZipArchive`

Một anti-pattern phổ biến trong .NET là kết hợp đích dự kiến với `ZipArchiveEntry.FullName` do **người dùng kiểm soát**, rồi giải nén mà không chuẩn hóa đường dẫn:<sup>[[4]](#references)[[8]](#references)</sup>

```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
    foreach (var entry in zip.Entries)
    {
        var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
        entry.ExtractToFile(dest);
    }
}
```

- Nếu `entry.FullName` bắt đầu bằng `..\\` thì nó vượt ra ngoài thư mục; nếu đó là **đường dẫn tuyệt đối**, thành phần bên trái sẽ bị loại bỏ hoàn toàn, dẫn đến **ghi tệp tùy ý** theo danh tính của mục được giải nén.
- Archive proof-of-concept để ghi vào thư mục `app` nằm cùng cấp, được một scanner theo lịch giám sát:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Thả ZIP đó vào inbox được giám sát sẽ tạo ra `C:\samples\app\0xdf.txt`, chứng minh có thể traversal ra ngoài `C:\samples\queue\` và mở đường cho các primitive tiếp theo (ví dụ: DLL hijacks).

### Root giải nén do người dùng kiểm soát

Ngoài tên member trong archive, hãy kiểm tra cả **thư mục được truyền cho extractor**. Ứng dụng có thể lấy thư mục đó từ tiêu đề, tên project hoặc trường khác trong request. Giá trị như `../../../../app/module` có thể đưa root giải nén ra ngoài khu vực upload trước khi extractor xử lý bất kỳ member nào. Trong trường hợp đó, ngay cả archive chỉ chứa basename an toàn `api.py` cũng có thể ghi đè mã ứng dụng.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Đây là ranh giới cô lập riêng, khác với Zip-Slip cổ điển. Hãy xác thực cả thư mục gốc giải nén sau khi phân giải và mọi đường dẫn thành viên sau khi phân giải. Có thể kiểm tra thư mục gốc bằng các thành phần đường dẫn thay vì tiền tố chuỗi:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Để kiểm tra an toàn, hãy tải lên một archive hợp lệ có chứa một canary file và đặt các chuỗi traversal vào từng trường có thể chọn thư mục giải nén. Theo dõi cả thư mục đích dự kiến lẫn một đường dẫn bên ngoài dùng một lần. Nếu đích có thể truy cập một module đã được import, việc ghi đè module đó có thể dẫn đến code execution khi worker tải lại module; HTTP 500 hoặc kết nối bị reset trong quá trình tải lại không chứng minh rằng thao tác ghi đã thất bại.<sup>[[14]](#references)[[15]](#references)</sup> Xem thêm [phương pháp kiểm thử file upload](../pentesting-web/file-upload/).

## Các kỹ thuật nâng cao để thoát khỏi thư mục giải nén

Hãy xem việc giải nén là một chuỗi thao tác thay đổi filesystem, không phải các bước kiểm tra tên file độc lập. Một entry có thể an toàn khi được phân tích nhưng trở nên không an toàn sau khi một member trước đó tạo hoặc thay thế một link; vấn đề tương tự cũng xảy ra khi extractor lưu cache một thư mục là an toàn rồi sau đó thay đổi loại của thư mục đó.<sup>[[11]](#references)</sup>

### Chuyển hướng qua link và xung đột entry

* **Ghi xuyên qua symlink**: tạo `pivot -> /tmp`, rồi giải nén một member thông thường thành `pivot/PWNED.txt`. Nếu extractor đi theo member đầu tiên khi tạo member thứ hai, thao tác ghi sẽ thoát khỏi thư mục mà không cần `..` trong tên thứ hai.
* **Xung đột cache thư mục/TOCTOU**: tạo thư mục `d/sub/`, thay `d/sub` bằng symlink trỏ đến `/tmp`, rồi tạo `d/sub/PWNED.txt`. Cách này nhắm đến các extractor chỉ xác thực hoặc lưu cache thư mục một lần và không kiểm tra lại trước khi ghi file cuối cùng.
* **Đọc/ghi đè qua hardlink**: TAR và RAR có thể biểu diễn hardlink. Hardlink trỏ đến một file có sẵn trên host có thể làm lộ nội dung nếu một thành phần sau đó phục vụ tên đã giải nén; một entry thông thường bị xung đột có thể thay vào đó ghi đè inode được liên kết. Cách này bị giới hạn bởi quy tắc cùng filesystem và quyền tạo hardlink của hệ điều hành.
* **Chuyển hướng qua link có sẵn hoặc giữa các archive**: thử lại với thư mục đích không rỗng. Một archive có thể tạo link, rồi lần giải nén sau ghi xuyên qua link đó, ngay cả khi mỗi archive đều vượt qua bước kiểm tra tên trong header không lưu trạng thái.<sup>[[11]](#references)</sup>

### Xung đột do quy tắc tương đương của filesystem

So sánh tên theo ngữ nghĩa của filesystem sẽ nhận các tên đó. Các trường hợp khác biệt hữu ích gồm `LINK` và `link` trên filesystem không phân biệt chữ hoa chữ thường, cách viết Unicode NFC và NFD, các tên tương đương theo quy tắc tương thích như `ﬁle` và `file`, các member trùng lặp làm thay đổi đường dẫn từ thư mục thành symlink, và dấu gạch chéo ngược chỉ được hiểu là dấu phân cách trên Windows. Cũng hãy kiểm tra tên có ADS trên NTFS. Những trường hợp này có thể khiến validator thấy hai đường dẫn trong khi filesystem chỉ phân giải thành một.<sup>[[5]](#references)[[11]](#references)</sup>

Vì vậy, một bộ mẫu kiểm thử gọn nên kiểm tra các tổ hợp có thứ tự gồm **directory → symlink → child**, **symlink → file thông thường bị xung đột**, **hardlink → file thông thường bị xung đột**, dấu `/` và `\` trộn lẫn, tên tuyệt đối/có gốc, và các wrapper nén như `.tar.gz`. Chỉ chạy bộ kiểm thử trong VM/container dùng một lần và theo dõi cả thư mục đích lẫn đường dẫn canary bên ngoài dự kiến.<sup>[[11]](#references)</sup>

Sự nhập nhằng về cấu trúc chỉ có ở ZIP có thể khiến bước quét trước và extractor thực tế nhìn thấy các tên entry hoặc cây thư mục khác nhau. Xem [Sự nhầm lẫn giữa parser local-header và central-directory](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) thay vì chỉ tin vào kết quả của một thư viện ZIP duy nhất.

## Ví dụ thực tế – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR cho Windows và các thành phần RAR/UnRAR trên Windows không xác thực tên file trong quá trình giải nén. Lỗ hổng này dùng alternate data streams (ADS) của NTFS để vượt qua đường dẫn giải nén đã chọn và ghi file vào các vị trí ngoài dự kiến.<sup>[[5]](#references)</sup>
Một archive RAR độc hại chứa entry như:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

sẽ nằm **bên ngoài** thư mục đầu ra đã chọn và bên trong thư mục *Startup* của người dùng. ESET phát hiện các tệp LNK độc hại được giải nén vào đó và thực thi khi người dùng đăng nhập, tạo cơ chế duy trì quyền truy cập và con đường dẫn đến RCE.<sup>[[5]](#references)</sup>

### Tạo Archive PoC (Linux/Mac)

Vì CVE-2025-8088 sử dụng đường dẫn traversal trong tên ADS, hãy dùng trình tạo chuyên dụng để tạo RAR, sau đó chỉ thử giải nén trong một phòng lab cô lập với bản WinRAR dễ bị tấn công.<sup>[[5]](#references)</sup>

### Khai thác được ghi nhận ngoài thực tế

ESET báo cáo các chiến dịch spear-phishing của RomCom (Storm-0978/UNC2596), trong đó các archive RAR đính kèm khai thác CVE-2025-8088 để triển khai backdoor tùy chỉnh và hỗ trợ các hoạt động ransomware.<sup>[[5]](#references)</sup>

## Các trường hợp mới hơn (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Lỗi**: Các mục ZIP là **symbolic link** bị tham chiếu theo đích trong quá trình giải nén, cho phép kẻ tấn công thoát khỏi thư mục đích và ghi đè các đường dẫn tùy ý. Tương tác của người dùng chỉ là *mở/giải nén* archive.<sup>[[1]](#references)</sup>
* **Bị ảnh hưởng**: Các bản dựng 7-Zip trước **25.00**. Lỗi xử lý symbolic link đã được khắc phục trong **25.00** (tháng 7 năm 2025) và các bản sau.<sup>[[1]](#references)[[10]](#references)</sup>
* **Đường dẫn tác động**: Ghi đè `Start Menu/Programs/Startup` hoặc các vị trí chạy dịch vụ → mã chạy vào lần đăng nhập tiếp theo hoặc khi dịch vụ khởi động lại.
* **Fixture xử lý symlink nhanh (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Archive này chứa một mục symlink trỏ ra ngoài thư mục giải nén; hãy dùng một đích dùng một lần và xác minh rằng extractor không đi theo symlink đó. Bài kiểm tra write-through cũng cần một mục regular-file nằm bên dưới symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Lỗi**: `archiver.Unarchive()` có thể giải nén một symlink trong ZIP, rồi dereference symlink đó khi một member regular tiếp theo có cùng tên, biến một thao tác ghi có vẻ nằm trong thư mục gốc thành thao tác ghi ra ngoài thư mục gốc.<sup>[[2]](#references)</sup>
* **Bị ảnh hưởng**: `github.com/mholt/archiver` ≤ 3.5.1 (dự án hiện đã deprecated).<sup>[[2]](#references)</sup>
* **Khắc phục**: Chuyển sang `mholt/archives` ≥ 0.1.0 hoặc từ chối các link và phân giải lại từng đích ngay trước khi mở.<sup>[[2]](#references)</sup>
* **Trình tạo collision tối giản** (sau đó gọi `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### Bypass bộ lọc giải nén TAR của CPython (CVE-2026-11940)

Ngay cả `tarfile.extractall(filter="data")` và `filter="tar"` cũng từng có lỗ hổng bypass thứ tự link. Trong trường hợp này, một hardlink tham chiếu đến một symlink được lưu trữ ở đường dẫn sâu hơn; quá trình giải nén dự phòng xác thực symlink tương đối tại vị trí sâu đó nhưng tạo lại nó ở vị trí nông hơn của hardlink, nơi cùng target tương đối có thể thoát ra ngoài. Đây là một bài kiểm tra tổng quát hữu ích: khiến quá trình xác thực và tạo đối tượng không thống nhất về thư mục cơ sở hoặc kiểu member cuối cùng.<sup>[[12]](#references)</sup>

### Hardlink của Node `tar` thoát khỏi target qua chuỗi symlink (GHSA-83g3-92jg-28cx)

Package `tar` của Node.js chấp nhận `tar.extract()` với một hardlink có target trông như nằm trong phạm vi xét theo cú pháp đường dẫn, nhưng thực tế lại phân giải ra ngoài thư mục gốc giải nén thông qua hai symlink được tạo trước đó. Cuộc tấn công hoạt động với các tùy chọn giải nén mặc định: việc kiểm tra thư mục cha của đích chỉ áp dụng cho tên hardlink nằm trong thư mục gốc, còn target của hardlink được chuyển cho filesystem mà không phân giải toàn bộ chuỗi để kiểm tra xem nó có nằm trong phạm vi hay không. `tar` ≤ 7.5.7 bị ảnh hưởng; phiên bản 7.5.8 đã vá lỗi này.<sup>[[13]](#references)</sup>

Fixture kiểm thử quan trọng là **mối quan hệ có thứ tự** giữa các member, không phải những tên cụ thể này:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Nếu giải nén thành công, `exfil` vẫn hiển thị bên trong cây đầu ra nhưng dùng chung inode với tệp bên ngoài được chọn; đọc nó sẽ làm lộ nội dung tệp đó, còn ghi vào nó sẽ sửa đổi tệp gốc. Bypass này cho thấy vì sao chỉ kiểm tra pathname cuối cùng, loại bỏ tiền tố tuyệt đối hoặc chặn `..` trong header hardlink là chưa đủ: hãy xác thực các đích liên kết sau khi áp dụng toàn bộ trạng thái filesystem đã được giải nén trước đó.<sup>[[13]](#references)</sup>

## Detection Tips

* **Kiểm tra tĩnh** – Liệt kê cả tên member lẫn đích liên kết. Đánh dấu `../`, `..\\`, đường dẫn tuyệt đối/có gốc, symlink, hardlink, tệp đặc biệt, tên trùng lặp, thay đổi kiểu và các trường hợp trùng lặp tương đương về chữ hoa/thường hoặc Unicode. Giữ nguyên thứ tự entry khi rà soát vì exploit có thể phụ thuộc vào các member trước đó.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalisation** – Đảm bảo parent đã phân giải cùng basename cuối vẫn nằm bên dưới destination đã phân giải (so sánh các thành phần của path, không dùng tiền tố chuỗi thô). Kiểm tra lại sau mỗi member đứng trước; kiểm tra `realpath(join(dest, name))` một lần duy nhất dễ bị thay thế link và có thể thất bại khi leaf chưa được tạo.<sup>[[3]](#references)[[11]](#references)</sup>
* **Trích xuất trong sandbox** – Giải nén vào một thư mục mới, có thể hủy, bằng extractor có kiểm tra path/symlink (ví dụ: các kiểm tra bảo mật mặc định của bsdtar hoặc 7-Zip ≥ 25.00), sau đó xác minh cây thư mục không chứa link trỏ ra ngoài. Việc cô lập phải ngăn một vụ thoát sandbox đã bị kích hoạt tiếp cận được các path trên host.<sup>[[1]](#references)[[9]](#references)</sup>
* **Các thao tác đọc về sau cũng quan trọng** – Một symlink hoặc hardlink còn sót lại có thể trở thành primitive đọc file tùy ý khi previewer, CDN, trình duyệt file hoặc pipeline package về sau mở hoặc phục vụ tên đã giải nén, ngay cả khi bản thân quá trình giải nén không tạo file bên ngoài.<sup>[[11]](#references)</sup>
* **Giám sát endpoint** – Cảnh báo khi có executable mới được ghi vào các vị trí `Startup`/`Run`/`cron` ngay sau khi WinRAR/7-Zip/v.v. mở archive.

## Giảm thiểu & Gia cố

1. **Cập nhật extractor** – WinRAR 7.13+, 7-Zip 25.00+ và Node `tar` 7.5.8+ đã có các bản sửa cho những vấn đề về path/symlink/link-target được trích dẫn.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Giải nén archive với tùy chọn “**Do not extract paths**” / “**Ignore paths**” khi có thể. Với đầu vào không đáng tin cậy, hãy từ chối symbolic link, hardlink, device và FIFO trừ khi ứng dụng cần dùng chúng một cách rõ ràng.<sup>[[9]](#references)[[11]](#references)</sup>
3. Giải nén vào **thư mục mới, trống**. Không gộp các member không đáng tin cậy vào cây thư mục có chứa path mà attacker có thể thay thế, và không tái sử dụng thư mục đã được cài sẵn bởi archive trước đó.<sup>[[11]](#references)</sup>
4. Trên Unix, hạ quyền và cô lập destination trong **chroot/mount namespace**; trên Windows, dùng **AppContainer** hoặc sandbox. Chỉ quét sau khi giải nén là không đủ vì thao tác ghi thoát khỏi vùng giới hạn xảy ra trước khi quét.<sup>[[11]](#references)</sup>
5. Trong code tùy chỉnh, áp dụng quy tắc separator/case/Unicode của OS đích và xác thực cả member lẫn link target. Phân giải và mở destination mà không đi theo link; không tách bước kiểm tra containment khỏi thao tác tạo/thay thế sau đó. Validator phải dùng chính xác cùng base và ngữ nghĩa giả lập link như đường dẫn ghi file.<sup>[[11]](#references)[[12]](#references)</sup>

## Các trường hợp bị ảnh hưởng khác / trong quá khứ

* 2018 – Snyk đưa ra cảnh báo *Zip-Slip* quy mô lớn, ảnh hưởng đến nhiều thư viện Java/Go/JS.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) có lỗi path traversal khi giải nén TAR trong slug (đã sửa ở v0.16.3).<sup>[[7]](#references)</sup>
* Mọi logic giải nén tùy chỉnh chỉ xác thực chuỗi trong header mà không xác thực link target và path cuối cùng trên filesystem được dùng cho mỗi thao tác ghi.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – Lỗi ZIP path traversal qua symlink của 7-Zip (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [Nghiên cứu của JFrog – Zip-Slip trong mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Ngăn Zip Slip trong .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – Chuỗi HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Nghiên cứu của ESET – Cập nhật công cụ WinRAR ngay: RomCom và các nhóm khác đang khai thác lỗ hổng zero-day (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Công bố công khai lỗ hổng ghi đè file tùy ý nghiêm trọng: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug dễ bị tấn công Zip Slip (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Phương thức Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Các cờ giải nén an toàn của bsdtar](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Báo cáo khai thác Proof-of-Concept cho CVE-2025-11001 trong 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Vọc vui với zip-slip, tar-slip, symlink, hardlink, collision và nhiều thứ khác](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Bypass bộ lọc giải nén tarfile CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar: thoát khỏi hardlink target qua chuỗi symlink](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [PoC CVE của Rhino Security Labs – root giải nén SCORM do người dùng kiểm soát](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Nhiều lỗ hổng trong Frappe LMS dẫn đến Remote Code Execution](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
