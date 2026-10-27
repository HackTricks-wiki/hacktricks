# Mẹo về PNG

{{#include ../../../banners/hacktricks-training.md}}

**Tệp PNG** rất phổ biến trong **CTF**, **ứng phó sự cố** và **triển khai malware** vì chúng **không mất dữ liệu**, **dựa trên chunk** và nhiều công cụ vẫn có thể hiển thị chúng dù chứa **metadata bổ sung**, **payload được nối thêm** hoặc **chunk bị hỏng một phần**.

Hãy xem PNG là một **container**, không chỉ là một hình ảnh.

## Kiểm tra nhanh

Hãy bắt đầu bằng các bước kiểm tra ở cấp container trước khi chuyển sang stego LSB. Để thực hiện quy trình bit-plane/LSB, hãy xem [trang chuyên về stego hình ảnh](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Những thứ hữu ích cần tìm:

- **Các chunk phụ bất thường** như `tEXt`, `zTXt`, `iTXt`, `eXIf` hoặc `iCCP`
- **Lỗi CRC** hoặc độ dài chunk không hợp lệ
- **Dữ liệu bổ sung sau `IEND`**
- **Nhiều marker `IEND`** hoặc các mảnh `IDAT` có thể khôi phục nằm sau điểm kết thúc chính thức của tệp
- Tệp vừa là PNG hợp lệ **vừa** trông giống ZIP/PDF/script khi carve

Hãy nhớ cấu trúc hợp lệ tối thiểu thường là:

- `IHDR` (phải đứng đầu)
- `IDAT` (một hoặc nhiều chunk liên tiếp)
- `IEND` (phải đứng cuối)

## Dữ liệu dư sau `IEND`

Một trong những dấu hiệu PNG có giá trị cao nhất là **dữ liệu được nối thêm sau chunk `IEND` cuối cùng**. Nhiều decoder bỏ qua phần này, khiến nó hữu ích cho:

- **Stego đơn giản / payload ẩn**
- **PNG polyglots**
- **Malware staging**
- **Khôi phục dữ liệu ảnh cũ** từ các trình chỉnh sửa bị lỗi

Phát hiện nhanh:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Tìm kiếm byte `IEND` chỉ là một gợi ý: các byte tương tự có thể xuất hiện trong dữ liệu chunk hoặc trong phần trailer giả mạo. Để carve đáng tin cậy, hãy duyệt các chunk có tiền tố độ dài, bắt đầu từ chữ ký PNG và dừng tại `IEND` cấu trúc đầu tiên; [trình duyệt chunk bên dưới](#extract-ancillary-chunk-payloads) cũng lưu phần trailer.<sup>[[6]](#references)</sup>

Ngoài ra, hãy thử trực tiếp các trình phân tích cú pháp archive thông dụng trên PNG hoặc phần trailer đã carve:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Khôi phục kiểu Acropalypse từ ảnh chụp màn hình đã cắt/che

Một thủ thuật pháp chứng PNG gần đây rất thiết thực là kiểm tra xem trình chỉnh sửa ảnh chụp màn hình có **ghi đè** lên tệp PNG mà không **cắt ngắn** tệp cũ trước hay không. Trong những trường hợp đó, byte từ **ảnh trước đó** có thể còn lại sau `IEND`, và đôi khi có thể khôi phục một phần dữ liệu `IDAT` bổ sung.

Vấn đề này được biết đến rộng rãi qua **aCropalypse** (Google Pixel Markup) và sự cố liên quan đến **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Trên thực tế, nếu tệp PNG đã "cắt" hoặc "che" vẫn chứa dữ liệu cũ ở cuối tệp, bạn có thể khôi phục một phần ảnh chụp màn hình ban đầu.<sup>[[1]](#references)</sup>

Quy trình thực tế:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Các dấu hiệu đủ mạnh để cần phân tích sâu hơn:

- `pngcheck` báo cáo **có dữ liệu bổ sung sau `IEND`**
- Bạn tìm thấy **nhiều hơn một `IEND`**
- Bạn tìm thấy **các chunk `IDAT` bổ sung** sau phần cuối có vẻ là của ảnh
- Ảnh chụp màn hình được tạo từ một thiết bị/trình chỉnh sửa được biết là đã bị ảnh hưởng

Nếu gặp trường hợp này, hãy đưa tệp vào **công cụ khôi phục aCropalypse** trước khi tin rằng phần che đã an toàn.

## Lạm dụng chunk có ý nghĩa trong thực tế

Các chunk PNG thú vị nhất trong quá trình điều tra thường không phải là những chunk hình ảnh hiển nhiên, mà là các chunk có thể chứa **văn bản**, **metadata** hoặc **byte payload**:

- `tEXt` / `zTXt` / `iTXt` – metadata văn bản và văn bản đã nén
- `eXIf` – dữ liệu EXIF bên trong PNG
- `iCCP` – profile ICC được nhúng
- `PLTE` – dữ liệu bảng màu trong ảnh dùng indexed color, nhưng cũng hữu ích trong các tình huống giấu payload.<sup>[[2]](#references)</sup>

Dump chúng bằng:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Để duy trì payload tấn công bên trong các chunk PNG (ví dụ: các thủ thuật **PLTE**, **IDAT** hoặc **tEXt** vẫn tồn tại sau một số biến đổi hình ảnh bằng PHP), hãy xem ghi chú chi tiết hơn tập trung vào upload tại đây:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Trích xuất payload từ các chunk phụ trợ

Kẻ tấn công có thể đặt các byte tùy ý vào một **chunk phụ trợ không xác định trước `IEND`**. Các bộ giải mã PNG thông thường có thể bỏ qua chunk phụ trợ không xác định, trong khi một script lấy ảnh dưới dạng byte có thể đọc và sử dụng payload; chỉ mở PNG sẽ không thực thi payload đó.<sup>[[4]](#references)[[6]](#references)</sup> Nghiên cứu ban đầu trình diễn một chunk tùy chỉnh được nén và mã hóa.<sup>[[4]](#references)</sup> Một ví dụ trên trình duyệt sau đó dùng các byte đã trích xuất để cung cấp HTML hoặc một tệp tải xuống.<sup>[[5]](#references)</sup>

Chữ cái đầu tiên viết thường trong tên chunk biểu thị *phụ trợ*; chữ cái thứ hai viết thường biểu thị *riêng tư*. Ví dụ: `paMP` là riêng tư, còn `pAMP` dùng không gian tên công khai dù tên sau được tạo ra cho phần trình diễn.<sup>[[4]](#references)[[6]](#references)</sup> Một chunk có cấu trúc `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC bao gồm type và data. Hãy phân tích cấu trúc này thay vì tìm tên type trong dữ liệu `IDAT` đã nén. Trình duyệt chunk sau đây xác thực giới hạn và CRC, xuất payload của các chunk phụ trợ dưới dạng byte thô, đồng thời ghi mọi byte nằm sau `IEND` theo cấu trúc vào `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Trích xuất các chunk phụ trợ và phần cuối PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Kiểm tra các byte được trích xuất bằng `file`, `strings` hoặc `binwalk`; chỉ giải nén nếu dữ liệu mang thực sự được nén.<sup>[[4]](#references)</sup> Mã hóa lại có thể loại bỏ dữ liệu mang, vì vậy hãy so sánh byte của dữ liệu đã tải lên và dữ liệu nhận lại trước khi dựa vào nó.<sup>[[2]](#references)[[6]](#references)</sup>

## Sửa PNG bị hỏng

Để kiểm tra tính toàn vẹn và xác định chính xác vùng bị hỏng, **pngcheck** vẫn là một trong những công cụ đầu tiên tốt nhất:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Nếu tệp bị hỏng chứ không phải cố ý chứa mã độc, **PCRT** có thể hữu ích trong CTF và môi trường lab để sửa các vấn đề thường gặp như header sai, giá trị IHDR không đúng, lỗi CRC hoặc bố cục chunk sai định dạng.

Nếu mục tiêu của bạn là **làm sạch** một PNG chứa dữ liệu trailer đáng ngờ nhưng vẫn giữ nguyên hình ảnh hiển thị, ExifTool có thể xóa rõ ràng phần trailer:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Với bằng chứng nhạy cảm, luôn làm việc trên **bản sao** và lưu lại giá trị hash của bản gốc trước khi thử sửa chữa.



## References

- [1] [Khai thác aCropalypse: Khôi phục các tệp PNG bị cắt cụt](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payload PHP tồn tại dai dẳng trong PNG: Cách chèn mã PHP vào ảnh và giữ nguyên mã trong đó](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Các chunk phụ trợ là nơi hoàn hảo để lưu trữ thông tin nhạy cảm](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Sử dụng các chunk phụ trợ hợp lệ để tuồn dữ liệu đến một endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Đặc tả Portable Network Graphics (PNG) (Ấn bản thứ ba)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
