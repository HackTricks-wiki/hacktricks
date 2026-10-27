# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## Local storage emulators and account keys

Một trình giả lập Blob tương thích với Azure chạy trong container có thể truy cập được từ host hoặc mạng bridge, ngay cả khi dịch vụ lưu trữ không được mở ra bên ngoài. Kiểm tra cấu hình cục bộ có thể đọc được và metadata của tệp sao lưu để tìm tên tài khoản và khóa, nhưng không in khóa trong quá trình liệt kê thông thường. [Azurite hỗ trợ khóa tài khoản cục bộ tùy chỉnh](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access) có thể cấp quyền truy cập rộng vào dữ liệu của tài khoản tương ứng. Chỉ có tệp khóa không đồng nghĩa với việc có thể leo thang quyền: hãy xác nhận endpoint có thể truy cập, tài khoản và khóa được chấp nhận, đồng thời blob cụ thể thực sự chứa thông tin xác thực có thể dùng được cho một danh tính có đặc quyền cao hơn. Nếu blob chứa khóa riêng SSH, khóa công khai tương ứng cũng phải được cấp quyền cho danh tính đó và phải cho phép truy cập SSH. Hãy bảo vệ và xoay vòng khóa khi xác nhận đã bị lộ.

## OneDrive

Trong Windows, bạn có thể tìm thấy thư mục OneDrive tại `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Trong `logs\Personal`, có thể tìm thấy tệp `SyncDiagnostics.log` chứa một số dữ liệu thú vị về các tệp đã đồng bộ:<sup>[[3]](#references)</sup>

- Kích thước tính bằng byte
- Ngày tạo
- Ngày sửa đổi
- Số lượng tệp trên cloud
- Số lượng tệp trong thư mục
- **CID**: ID duy nhất của người dùng OneDrive
- Thời gian tạo báo cáo
- Dung lượng ổ cứng của hệ điều hành

Sau khi tìm thấy CID, bạn nên **tìm kiếm các tệp chứa ID này**. Bạn có thể tìm thấy các tệp có tên _**\<CID>.ini**_ và _**\<CID>.dat**_ chứa thông tin thú vị như tên các tệp đã đồng bộ với OneDrive.<sup>[[3]](#references)</sup>

## Google Drive

Trong Windows, bạn có thể tìm thấy thư mục Google Drive chính tại `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Thư mục này chứa tệp Sync_log.log ghi lại các phiên đồng bộ của client Google Drive và các sự kiện tạo, sửa đổi, xóa tệp.<sup>[[4]](#references)[[6]](#references)</sup>

Tệp **`Cloud_graph\Cloud_graph.db`** là một cơ sở dữ liệu sqlite.<sup>[[6]](#references)</sup> Tệp này chứa bảng **`cloud_graph_entry`**. Trong bảng này, bạn có thể tìm thấy **tên** các **tệp** đã **đồng bộ**, thời gian sửa đổi, kích thước và checksum MD5 của tệp.

Bảng **`cloud_entry`** trong cơ sở dữ liệu **`snapshot.db`** liên quan có thể giữ lại các bản ghi đã xóa cùng tên tệp, dấu thời gian, kích thước và checksum.<sup>[[4]](#references)</sup>

Dữ liệu bảng trong cơ sở dữ liệu **`Sync_config.db`** chứa địa chỉ email của tài khoản, đường dẫn đến các thư mục được chia sẻ và phiên bản Google Drive.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox sử dụng **cơ sở dữ liệu SQLite** để quản lý các tệp.<sup>[[2]](#references)</sup> Trong\
Bạn có thể tìm thấy các cơ sở dữ liệu trong các thư mục:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

Các cơ sở dữ liệu chính gồm:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

Phần mở rộng ".dbx" có nghĩa là các **cơ sở dữ liệu** đã được **mã hóa**. Dropbox sử dụng **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Để hiểu rõ hơn về cách mã hóa Dropbox sử dụng, bạn có thể đọc [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).<sup>[[1]](#references)[[2]](#references)</sup>

Tuy nhiên, thông tin chính là:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

Ngoài thông tin đó, để giải mã các cơ sở dữ liệu, bạn vẫn cần:<sup>[[2]](#references)</sup>

- **Khóa DPAPI đã mã hóa**: Bạn có thể tìm thấy khóa này trong registry tại `NTUSER.DAT\Software\Dropbox\ks\client` (xuất dữ liệu này dưới dạng binary)
- Các hive **`SYSTEM`** và **`SECURITY`**
- **Khóa chính DPAPI**: Có thể tìm thấy tại `\Users\<username>\AppData\Roaming\Microsoft\Protect`
- **Tên người dùng** và **mật khẩu** của người dùng Windows

Sau đó, bạn có thể sử dụng công cụ [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![Google Drive - Dropbox: Sau đó, bạn có thể sử dụng công cụ DataProtectionDecryptor](<../../../images/image (443).png>)

Nếu mọi việc diễn ra như mong đợi, công cụ sẽ cho biết **khóa chính** mà bạn cần **dùng để khôi phục khóa ban đầu**. Để khôi phục khóa ban đầu, chỉ cần sử dụng [công thức cyber_chef](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>) này và nhập khóa chính làm "passphrase" trong công thức.

Giá trị hex thu được là khóa cuối cùng dùng để mã hóa các cơ sở dữ liệu; có thể giải mã chúng bằng:<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

Cơ sở dữ liệu **`config.dbx`** chứa:

- **Email**: Email của người dùng
- **usernamedisplayname**: Tên của người dùng
- **dropbox_path**: Đường dẫn đến thư mục Dropbox
- **Host_id: Hash** dùng để xác thực với cloud. Chỉ có thể thu hồi thông tin này trên web.
- **Root_ns**: Định danh người dùng

Cơ sở dữ liệu **`filecache.db`** chứa thông tin về tất cả các tệp và thư mục được đồng bộ với Dropbox. Bảng `File_journal` chứa nhiều thông tin hữu ích nhất:<sup>[[5]](#references)</sup>

- **Server_path**: Đường dẫn đến tệp trên server (đường dẫn này có tiền tố là `host_id` của client).
- **local_sjid**: Phiên bản của tệp
- **local_mtime**: Ngày sửa đổi
- **local_ctime**: Ngày tạo

Các bảng khác trong cơ sở dữ liệu này chứa những thông tin thú vị hơn:

- **block_cache**: Hash của tất cả các tệp và thư mục trên Dropbox
- **block_ref**: Liên kết hash ID trong bảng `block_cache` với file ID trong bảng `file_journal`
- **mount_table**: Các thư mục được chia sẻ trên Dropbox
- **deleted_fields**: Các tệp Dropbox đã xóa
- **date_added**

## References

- [1] [Phân tích quan trọng về bảo mật phần mềm Dropbox (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Tìm hiểu về giải mã DBX của Dropbox](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Phân tích pháp chứng lưu trữ đám mây (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [Vụ rò rỉ dữ liệu NIST CFReDS: Đáp án về vụ rò rỉ](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Pháp chứng Dropbox](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Dấu vết sử dụng Google Drive trên Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}
