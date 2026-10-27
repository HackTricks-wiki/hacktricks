# Bypass Secure-Boot của MediaTek bl2_ext (Thực thi mã EL3)

{{#include ../../banners/hacktricks-training.md}}

Trang này ghi lại một cách phá vỡ Secure-Boot thực tế trên nhiều nền tảng MediaTek bằng cách lợi dụng lỗ hổng xác minh khi cấu hình bootloader của thiết bị (seccfg) ở trạng thái "unlocked". Lỗ hổng cho phép chạy bl2_ext đã được patch ở ARM EL3 để vô hiệu hóa việc xác minh chữ ký ở các giai đoạn sau, làm sụp đổ chuỗi tin cậy và cho phép tải tùy ý TEE/GZ/LK/Kernel chưa ký.<sup>[[1]](#references)</sup>

> Cảnh báo: Patch ở giai đoạn khởi động sớm có thể khiến thiết bị bị brick vĩnh viễn nếu offset không chính xác. Luôn giữ bản dump đầy đủ và có sẵn phương án khôi phục đáng tin cậy.

## Luồng khởi động bị ảnh hưởng (MediaTek)

- Luồng thông thường: BootROM → Preloader → bl2_ext (EL3, đã xác minh) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Luồng dễ bị tấn công: Khi seccfg được đặt thành unlocked, Preloader có thể bỏ qua việc xác minh bl2_ext. Preloader vẫn chuyển điều khiển đến bl2_ext ở EL3, vì vậy bl2_ext được tạo thủ công có thể tải các thành phần chưa được xác minh ở những giai đoạn sau.

Ranh giới tin cậy chính:
- bl2_ext thực thi ở EL3 và chịu trách nhiệm xác minh TEE, GenieZone, LK/AEE và kernel. Nếu bản thân bl2_ext không được xác thực, có thể dễ dàng bypass các bước còn lại trong chuỗi.<sup>[[1]](#references)</sup>

## Nguyên nhân gốc

Trên các thiết bị bị ảnh hưởng, Preloader không thực thi việc xác thực phân vùng bl2_ext khi seccfg cho biết trạng thái "unlocked". Điều này cho phép flash bl2_ext do kẻ tấn công kiểm soát và chạy ở EL3.

Bên trong bl2_ext, có thể patch hàm chính sách xác minh để luôn báo rằng không cần xác minh (hoặc luôn xác minh thành công), buộc chuỗi khởi động chấp nhận các image TEE/GZ/LK/Kernel chưa ký. Vì patch này chạy ở EL3, nó vẫn có hiệu lực ngay cả khi các thành phần phía sau tự triển khai bước kiểm tra riêng.<sup>[[1]](#references)</sup>

## Chuỗi khai thác thực tế

1. Thu thập các phân vùng bootloader (Preloader, bl2_ext, LK/AEE, v.v.) từ gói OTA/firmware, đọc dữ liệu bằng EDL/DA hoặc dump phần cứng.
2. Xác định routine xác minh bl2_ext và patch để luôn bỏ qua/chấp nhận xác minh.
3. Flash bl2_ext đã sửa đổi bằng fastboot, DA hoặc các kênh bảo trì tương tự vẫn được phép sử dụng trên thiết bị unlocked.
4. Khởi động lại; Preloader chuyển điều khiển đến bl2_ext đã patch ở EL3, sau đó bl2_ext tải các image phía sau chưa ký (TEE/GZ/LK/Kernel đã patch) và vô hiệu hóa việc thực thi kiểm tra chữ ký.<sup>[[1]](#references)</sup>

Nếu thiết bị được cấu hình ở trạng thái locked (seccfg locked), Preloader được kỳ vọng sẽ xác minh bl2_ext. Ở cấu hình đó, cuộc tấn công này sẽ thất bại, trừ khi có một lỗ hổng khác cho phép tải bl2_ext chưa ký.

## Phân loại (log khởi động expdb)

- Dump log boot/expdb quanh thời điểm tải bl2_ext. Nếu `img_auth_required = 0` và thời gian xác minh certificate xấp xỉ 0 ms, có khả năng bước xác minh đã bị bỏ qua.<sup>[[1]](#references)</sup>

Ví dụ trích đoạn log:

```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```

- Một số thiết bị bỏ qua bước xác minh bl2_ext ngay cả khi đã khóa; các đường dẫn bootloader phụ lk2 cũng cho thấy lỗ hổng tương tự. Nếu Preloader sau OTA ghi log `img_auth_required = 1` cho bl2_ext khi thiết bị đang mở khóa, thì nhiều khả năng cơ chế thực thi đã được khôi phục.<sup>[[1]](#references)[[2]](#references)</sup>

## Vị trí logic xác minh

- Kiểm tra liên quan thường nằm trong image bl2_ext, bên trong các hàm có tên tương tự `verify_img` hoặc `sec_img_auth`.
- Phiên bản đã được vá buộc hàm trả về thành công hoặc bỏ qua hoàn toàn lệnh gọi xác minh.<sup>[[1]](#references)</sup>

Ví dụ về cách vá (mang tính khái niệm):
- Tìm hàm gọi `sec_img_auth` đối với các image TEE, GZ, LK và kernel.
- Thay phần thân hàm bằng một stub trả về thành công ngay lập tức, hoặc ghi đè nhánh điều kiện xử lý lỗi xác minh.

Đảm bảo bản vá giữ nguyên thiết lập stack/frame và trả về các mã trạng thái mà bên gọi mong đợi.<sup>[[1]](#references)</sup>

## Quy trình PoC của Fenrir (Nothing/CMF)

Fenrir là bộ công cụ vá tham khảo cho vấn đề này (hỗ trợ đầy đủ Nothing Phone (2a); hỗ trợ một phần CMF Phone 1).<sup>[[1]](#references)</sup> Các bước tổng quát:
- Đặt image bootloader của thiết bị tại `bin/<device>.bin`.
- Tạo image đã vá để vô hiệu hóa chính sách xác minh bl2_ext.
- Flash payload tạo ra (có sẵn công cụ hỗ trợ fastboot).

```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```

Sử dụng kênh flashing khác nếu không có fastboot.

## Ghi chú về patch EL3

- bl2_ext chạy trong ARM EL3. Sự cố tại đây có thể làm thiết bị bị brick cho đến khi được flash lại qua EDL/DA hoặc test point.
- Sử dụng logging/UART dành riêng cho bo mạch để xác nhận đường thực thi và chẩn đoán sự cố.
- Sao lưu tất cả phân vùng sẽ chỉnh sửa và thử nghiệm trước trên phần cứng không dùng cho mục đích khác.<sup>[[1]](#references)</sup>

## Hệ quả

- Thực thi mã EL3 sau Preloader và toàn bộ chuỗi tin cậy bị sụp đổ trong phần còn lại của quá trình khởi động.
- Có thể khởi động TEE/GZ/LK/Kernel chưa ký, vượt qua các yêu cầu của secure/verified boot và cho phép xâm nhập dai dẳng.<sup>[[1]](#references)</sup>

## Ghi chú về thiết bị

- Đã xác nhận hỗ trợ: Nothing Phone (2a) (Pacman)
- Đã biết là hoạt động (hỗ trợ chưa hoàn chỉnh): CMF Phone 1 (Tetris)
- Đã quan sát: Vivo X80 Pro được cho là không xác minh bl2_ext ngay cả khi bị khóa<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) đã bật lại xác minh bl2_ext; fenrir `pacman-v2.0` khôi phục bypass bằng cách kết hợp Preloader beta với LK đã patch<sup>[[3]](#references)</sup>
- Các bài viết trong ngành nêu bật những nhà cung cấp khác dựa trên lk2 cũng đang phát hành thiết bị có cùng lỗi logic, vì vậy có thể sẽ có thêm nhiều trường hợp tương tự trong các bản MTK 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Đọc dữ liệu MTK DA và thao tác seccfg bằng Penumbra

Penumbra là một crate/CLI/TUI viết bằng Rust, tự động hóa việc tương tác với preloader/bootrom MTK qua USB để thực hiện các thao tác ở DA mode. Khi có quyền truy cập vật lý vào thiết bị dễ bị tấn công (cho phép DA extensions), công cụ này có thể tìm cổng USB MTK, tải blob Download Agent (DA) và gửi các lệnh đặc quyền như thay đổi trạng thái khóa seccfg và đọc dữ liệu phân vùng.<sup>[[5]](#references)</sup>

- **Thiết lập môi trường/driver**: Trên Linux, cài đặt `libudev`, thêm người dùng vào nhóm `dialout` và tạo quy tắc udev hoặc chạy bằng `sudo` nếu không thể truy cập node thiết bị. Hỗ trợ Windows không ổn định; đôi khi chỉ hoạt động sau khi thay driver MTK bằng WinUSB bằng Zadig (theo hướng dẫn của dự án).
- **Quy trình**: Đọc payload DA (ví dụ: `std::fs::read("../DA_penangf.bin")`), dò tìm cổng MTK bằng `find_mtk_port()` và tạo session bằng `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Sau khi `init()` hoàn tất quá trình bắt tay và thu thập thông tin thiết bị, kiểm tra các cơ chế bảo vệ qua các bitfield của `dev_info.target_config()` (bit 0 được đặt → SBC đang bật). Vào DA mode và thử `set_seccfg_lock_state(LockFlag::Unlock)`—thao tác này chỉ thành công nếu thiết bị chấp nhận extensions. Có thể dump phân vùng bằng `read_partition("lk_a", &mut progress_cb, &mut writer)` để phân tích hoặc patch ngoại tuyến.
- **Tác động bảo mật**: Mở khóa seccfg thành công sẽ mở lại các đường flashing cho boot image chưa ký, cho phép xâm nhập dai dẳng như kỹ thuật patch EL3 bl2_ext được mô tả ở trên. Đọc dữ liệu phân vùng cung cấp firmware artifact để reverse engineering và tạo image đã chỉnh sửa.

<details>
<summary>Phiên DA Rust + mở khóa seccfg + dump phân vùng (Penumbra)</summary>

```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
    let da = std::fs::read("../DA_penangf.bin")?;
    let mtk_port = loop {
        if let Some(port) = find_mtk_port().await {
            break port;
        }
    };

    let mut dev = DeviceBuilder::default()
        .with_mtk_port(mtk_port)
        .with_da_data(da)
        .build()?;

    dev.init().await?;
    let cfg = dev.dev_info.target_config().await;
    println!("SBC: {}", (cfg & 0x1) != 0);

    dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

    let mut progress = |_read: usize, _total: usize| {};
    let mut writer = BufWriter::new(File::create("lk_a.bin")?);
    dev.read_partition("lk_a", &mut progress, &mut writer).await?;
    writer.flush().await?;
    Ok(())
}
```
</details>

## References

- [1] [Fenrir – bypass secure-boot bl2_ext của MediaTek (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Phát hành PoC exploit cho lỗ hổng thực thi mã trên Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Bản phát hành Fenrir pacman-v2.0 (gói bypass NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – PoC Fenrir phá vỡ secure boot trên Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – công cụ flash/readback DA & seccfg của MTK](https://github.com/shomykohai/penumbra)
{{#include ../../banners/hacktricks-training.md}}
