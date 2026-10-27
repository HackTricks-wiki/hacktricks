# Phân tích tệp video và âm thanh

{{#include ../../../banners/hacktricks-training.md}}

**Thao tác với tệp âm thanh và video** là nội dung phổ biến trong **các thử thách CTF về điều tra số**, khai thác **steganography** và phân tích metadata để ẩn hoặc tiết lộ thông điệp bí mật. Các công cụ như **[mediainfo](https://mediaarea.net/en/MediaInfo)** và **`exiftool`** rất cần thiết để kiểm tra metadata của tệp và xác định loại nội dung.<sup>[[1]](#references)</sup>

Trong các thử thách về âm thanh, **[Audacity](http://www.audacityteam.org/)** là công cụ hàng đầu để xem dạng sóng và phân tích spectrogram, rất cần thiết để tìm ra văn bản được mã hóa trong âm thanh. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** được khuyên dùng để phân tích spectrogram chi tiết. **Audacity** cho phép chỉnh sửa âm thanh, chẳng hạn như làm chậm hoặc đảo ngược bản nhạc để phát hiện thông điệp ẩn. **[Sox](http://sox.sourceforge.net/)** là tiện ích dòng lệnh nổi bật trong việc chuyển đổi và chỉnh sửa tệp âm thanh.<sup>[[1]](#references)</sup>

Thao tác trên **Least Significant Bits (LSB)** là kỹ thuật phổ biến trong steganography âm thanh và video, khai thác các khối có kích thước cố định trong tệp đa phương tiện để nhúng dữ liệu một cách kín đáo. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** hữu ích để giải mã thông điệp được ẩn dưới dạng **DTMF tones** hoặc **Morse code**.<sup>[[1]](#references)</sup>

Các thử thách về video thường liên quan đến định dạng container chứa cả luồng âm thanh lẫn video. **[FFmpeg](http://ffmpeg.org/)** là công cụ được dùng phổ biến để phân tích và thao tác với các định dạng này, có khả năng tách luồng và phát nội dung. Với nhà phát triển, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** tích hợp các khả năng của FFmpeg vào Python, hỗ trợ tương tác nâng cao có thể lập trình bằng script.<sup>[[1]](#references)</sup>

Loạt công cụ này cho thấy sự đa dạng cần có trong các thử thách CTF, nơi người tham gia phải sử dụng nhiều kỹ thuật phân tích và thao tác để tìm ra dữ liệu ẩn trong các tệp âm thanh và video.

## References

- [1] [Phân tích tệp video và âm thanh – Cẩm nang CTF của Trail of Bits](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
