# macOS Hassas Konumlar & İlginç Daemonlar

{{#include ../../../banners/hacktricks-training.md}}

## Parolalar

### Gölge Parolalar

Gölge parola, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumundaki plist'lerde saklanır.\
Aşağıdaki tek satırlık komut, **kullanıcılar hakkında tüm bilgileri** (hash bilgileri dahil) dökmek için kullanılabilir:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Bu tür scriptler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**şu**](https://github.com/octomagon/davegrohl.git) **hashcat** **formatına** dönüştürmek için kullanılabilir.

Tüm hizmet dışı hesapların kimlik bilgilerini hashcat formatında `-m 7100` (macOS PBKDF2-SHA512) dökecek alternatif bir tek satırlık komut:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
Başka bir kullanıcının `ShadowHashData`sını elde etmenin bir yolu `dscl` kullanmaktır: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

Bu dosya **yalnızca** sistem **tek kullanıcı modunda** çalıştığında kullanılır (bu nedenle çok sık değildir).

### Anahtar Zinciri Dökümü

Şifrelerin şifresinin çözüldüğünü **dökme** işlemi için güvenlik ikili dosyasını kullanırken, kullanıcıdan bu işlemi onaylaması için birkaç istem olacaktır.
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
> Bu yorumdan [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) yola çıkarak, bu araçların Big Sur'da artık çalışmadığı anlaşılıyor.

### Keychaindump Genel Bakış

**keychaindump** adlı bir araç, macOS anahtar zincirlerinden şifreleri çıkarmak için geliştirilmiştir, ancak Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşmaktadır; bu durum bir [tartışmada](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) belirtilmiştir. **keychaindump** kullanmak, saldırganın erişim sağlaması ve **root** ayrıcalıklarını yükseltmesi gerektirir. Araç, anahtar zincirinin kullanıcı girişi sırasında varsayılan olarak kilidinin açılmasını kullanarak, uygulamaların kullanıcı şifresini tekrar tekrar istemeden erişim sağlamasına olanak tanır. Ancak, bir kullanıcı her kullanım sonrası anahtar zincirini kilitlemeyi tercih ederse, **keychaindump** etkisiz hale gelir.

**Keychaindump**, Apple tarafından yetkilendirme ve kriptografik işlemler için bir daemon olarak tanımlanan **securityd** adlı belirli bir süreci hedef alarak çalışır; bu, anahtar zincirine erişim için kritik öneme sahiptir. Çıkarma süreci, kullanıcının giriş şifresinden türetilen bir **Master Key**'in tanımlanmasını içerir. Bu anahtar, anahtar zinciri dosyasını okumak için gereklidir. **Master Key**'i bulmak için, **keychaindump** `vmmap` komutunu kullanarak **securityd**'nin bellek yığınını tarar ve `MALLOC_TINY` olarak işaretlenmiş alanlarda potansiyel anahtarları arar. Bu bellek konumlarını incelemek için aşağıdaki komut kullanılır:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Potansiyel anahtarları belirledikten sonra, **keychaindump** yığınlar arasında anahtar için bir aday olduğunu gösteren belirli bir deseni (`0x0000000000000018`) arar. Bu anahtarı kullanmak için daha fazla adım, deşifre etme dahil, gereklidir; bu adımlar **keychaindump**'ın kaynak kodunda belirtilmiştir. Bu alana odaklanan analistler, anahtar zincirini şifrelemek için gerekli verilerin **securityd** sürecinin belleğinde saklandığını unutmamalıdır. **keychaindump**'ı çalıştırmak için bir örnek komut:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), OSX anahtar zincirinden adli olarak sağlam bir şekilde aşağıdaki türde bilgileri çıkarmak için kullanılabilir:

- Hashlenmiş Anahtar Zinciri şifresi, [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırmak için uygun
- İnternet Şifreleri
- Genel Şifreler
- Özel Anahtarlar
- Genel Anahtarlar
- X509 Sertifikaları
- Güvenli Notlar
- Appleshare Şifreleri

Anahtar zincirini açma şifresi, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) kullanılarak elde edilen bir anahtar veya SystemKey gibi bir açma dosyası verildiğinde, Chainbreaker ayrıca düz metin şifreleri sağlayacaktır.

Anahtar Zincirini açmanın bu yöntemlerinden biri olmadan, Chainbreaker mevcut olan tüm diğer bilgileri gösterecektir.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Anahtar zinciri anahtarlarını (şifrelerle birlikte) SystemKey ile dökme**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Anahtar zinciri anahtarlarını dökme (şifrelerle) hash'i kırma**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Anahtar zinciri anahtarlarını (şifrelerle birlikte) bellek dökümü ile dökme**

[Bu adımları izleyin](../index.html#dumping-memory-with-osxpmem) **bellek dökümü** gerçekleştirmek için
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Kullanıcı parolasını kullanarak anahtar zinciri anahtarlarını (şifrelerle birlikte) dökme**

Eğer kullanıcının parolasını biliyorsanız, bunu **kullanıcıya ait anahtar zincirlerini dökmek ve şifrelerini çözmek için** kullanabilirsiniz.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** dosyası, **kullanıcının giriş şifresini** tutan bir dosyadır, ancak yalnızca sistem sahibi **otomatik girişi etkinleştirmişse**. Bu nedenle, kullanıcı şifre istenmeden otomatik olarak giriş yapacaktır (bu çok güvenli değildir).

Şifre, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** anahtarı ile xored olarak saklanır. Kullanıcının şifresi anahtardan daha uzunsa, anahtar yeniden kullanılacaktır.\
Bu, şifreyi geri almayı oldukça kolay hale getirir, örneğin [**bu script**](https://gist.github.com/opshope/32f65875d45215c3677d) gibi scriptler kullanarak.

## Veritabanlarındaki İlginç Bilgiler

### Mesajlar
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Bildirimler

Notifications verilerini `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` içinde bulabilirsiniz.

En ilginç bilgiler **blob** içinde olacak. Bu nedenle, o içeriği **çıkar**manız ve **insan** **okunabilir** hale **dönüştürmeniz** veya **`strings`** kullanmanız gerekecek. Erişmek için şunu yapabilirsiniz:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notlar

Kullanıcıların **notları** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` içinde bulunabilir.
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## Tercihler

macOS uygulamalarında tercihler **`$HOME/Library/Preferences`** içinde bulunur ve iOS'ta ise `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` içindedir.

macOS'ta cli aracı **`defaults`** **Tercihler dosyasını** **değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`** XPC hizmetleri `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent`'ı talep eder ve tercihler gibi işlemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

Dosya `/System/Library/OpenDirectory/permissions.plist` düğüm niteliklerine uygulanan izinleri içerir ve SIP tarafından korunur.\
Bu dosya, belirli kullanıcıların UUID (ve uid değil) ile belirli hassas bilgilere, örneğin `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys` gibi bilgilere erişim izni verir:
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

Bildirimler için ana daemon **`/usr/sbin/notifyd`**'dir. Bildirim almak için, istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kaydolması gerekir (bunları `sudo lsmp -p <pid notifyd>` ile kontrol edin). Daemon, `/etc/notify.conf` dosyası ile yapılandırılabilir.

Bildirimler için kullanılan adlar, benzersiz ters DNS notasyonlarıdır ve bir bildirim bunlardan birine gönderildiğinde, bunu işleyebileceğini belirten istemci(ler) bunu alacaktır.

Mevcut durumu döküp (ve tüm adları görmek) için notifyd sürecine SIGUSR2 sinyali göndererek oluşturulan dosyayı okuyabilirsiniz: `/var/run/notifyd_<pid>.status`:
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

**Dağıtılmış Bildirim Merkezi** ana ikili dosyası **`/usr/sbin/distnoted`** olan, bildirim göndermenin başka bir yoludur. Bazı XPC hizmetlerini açığa çıkarır ve istemcileri doğrulamaya çalışmak için bazı kontroller yapar.

### Apple Push Bildirimleri (APN)

Bu durumda, uygulamalar **konular** için kaydolabilir. İstemci, **`apsd`** aracılığıyla Apple'ın sunucularıyla iletişim kurarak bir token oluşturacaktır.\
Daha sonra, sağlayıcılar da bir token oluşturacak ve istemcilere mesaj göndermek için Apple'ın sunucularıyla bağlantı kurabilecektir. Bu mesajlar, bekleyen uygulamaya bildirimi iletecek olan **`apsd`** tarafından yerel olarak alınacaktır.

Tercihler `/Library/Preferences/com.apple.apsd.plist` konumunda bulunmaktadır.

macOS'ta `/Library/Application\ Support/ApplePushService/aps.db` ve iOS'ta `/var/mobile/Library/ApplePushService` konumunda bulunan yerel bir mesaj veritabanı vardır. 3 tabloya sahiptir: `incoming_messages`, `outgoing_messages` ve `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Aynı zamanda daemon ve bağlantılar hakkında bilgi almak da mümkündür:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Kullanıcı Bildirimleri

Bu, kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda bir mesajla pop-up gösterme imkanı sağlar.
- **Bülten Panosu**: Bu, iOS'ta kaybolan ve Bildirim Merkezi'nde saklanan bir banner gösterir.
- **`NSUserNotificationCenter`**: Bu, MacOS'taki iOS bülten panosudur. Bildirimlerin bulunduğu veritabanı `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumundadır.

{{#include ../../../banners/hacktricks-training.md}}
