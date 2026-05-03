# SMB Arbitrary Port Üzerinden Local NTLM Reflection

{{#include ../../banners/hacktricks-training.md}}

Son Windows build'leri, **SMB client desteğine alternatif TCP portları** ekledi. Bu özellik, saldırgan şu koşulları sağlayabildiğinde **local NTLM authentication**'ı bir **SYSTEM local privilege escalation**'a dönüştürmek için kötüye kullanılabilir:

1. Bir saldırganın kontrol ettiği listener'a **445 dışı bir port** üzerinden SMB connection açmak
2. Bu TCP connection'ı açık tutmak
3. Bir **privileged local client**'ı **aynı SMB share path**'ine erişmeye zorlamak
4. Ortaya çıkan **local NTLM authentication**'ı makinenin gerçek SMB service'ine relay etmek

Bu, **CVE-2026-24294** arkasındaki primitive'dir ve **March 2026**'da patched edildi.

## Neden çalışır

Eski CMTI / serialized-SPN reflection trick burada anlatılıyor:

{{#ref}}
../ntlm/README.md
{{#endref}}

Bu daha yeni variant, marshalled hostname gerektirmez. Bunun yerine iki SMB client davranışını kötüye kullanır:

- **Alternative port support** on **Windows 11 24H2** and **Windows Server 2025**, `net use \\host\share /tcpport:<port>` ile kullanıcılara açılır
- **SMB connection reuse / multiplexing**, burada birden fazla authenticated session aynı TCP connection üzerinden taşınabilir

Bu da düşük yetkili bir kullanıcının önce SMB client'tan yüksek porttaki bir saldırgan SMB server'a bir TCP connection oluşturmasını, ardından privileged bir service'i **aynı UNC path**'ine erişmeye zorlamasını sağlar. Eğer Windows mevcut TCP connection'ı yeniden kullanmaya karar verirse, privileged NTLM exchange saldırganın kontrol ettiği transport üzerinden gönderilir ve local SMB server'a relay edilebilir.

## Önkoşullar

- Hedef SMB alternative ports desteklemeli:
- **Windows 11 24H2** veya sonrası
- **Windows Server 2025** veya sonrası
- Saldırgan, seçilen yüksek bir portta local veya remote SMB server çalıştırabilmeli
- Saldırgan, privileged bir service'i bir UNC path'e erişmeye zorlayabilmeli
- Privileged authentication mutlaka **NTLM local authentication** olmalı
- Hedef relay yapılabilir olmalı:
- Synacktiv, bunun varsayılan olarak **Windows Server 2025** üzerinde çalıştığını bildirdi
- Onların chain'i **Windows 11 24H2** üzerinde çalışmadı, çünkü outbound SMB signing orada varsayılan olarak zorunlu

## Userland ve internals

Komut satırından bu özellik basit görünür:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, istemci `WNetAddConnection4W` ile undocumented `lpUseOptions` verisini kullanır. İlgili seçenek `TraP` (transport parameters)’dır; bu veri sonunda bir FSCTL üzerinden kernel SMB client’a ulaşır ve `mrxsmb` tarafından parse edilir.

Important practical notes:

- **UNC syntax hâlâ bir port alanına sahip değil**
- **`net use` logon session başınadır**
- Bypass hâlâ çalışır çünkü **TCP connection ve SMB session ayrı object’lerdir**
- Exploit’in SMB client’ın daha önce oluşturulmuş TCP connection’ı yeniden kullanmasına bağlı olması durumunda, **aynı share path**’in yeniden kullanılması zorunludur

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Sunucu, kontrol ettiğiniz herhangi bir credential çifti kabul edebilir; örneğin `user:user`. Bu adımın amacı henüz privilege escalation değil, sadece Windows SMB client’ın listener’ınıza yeniden kullanılabilir bir TCP connection açmasını ve bunu açık tutmasını sağlamaktır.

### 2. Ayrıcalıklı bir service’i aynı UNC path’e zorla

**PetitPotam** gibi bir coercion primitive kullanarak **aynı** `\\192.168.56.3\share` path’ine erişimi zorlayın. Eğer zorlanan client privileged ise ve target name local ise (`localhost` veya local bir IP/host), Windows **NTLM local authentication** gerçekleştirir.

TCP connection yeniden kullanıldığı için, bu privileged NTLM exchange doğrudan gerçek local SMB server’a değil, attacker SMB service’e gider.

### 3. Privileged authentication’ı local SMB’ye geri relay et

Attacker-controlled SMB service, captured privileged NTLM exchange’i `ntlmrelayx.py`’ye forward eder; bu da onu machine’in gerçek SMB listener’ına relay eder ve `NT AUTHORITY\SYSTEM` olarak bir session elde eder.

Public writeup’tan tipik tooling:

- Yeniden kullanılan TCP connection üzerinden privileged auth almak için custom port üzerinde `smbserver.py`
- Captured NTLM’i local SMB’ye relay etmek için `ntlmrelayx.py`
- Privileged authentication’ı zorlamak için `PetitPotam.exe` veya başka bir coercion primitive

## Operator notları

- Bu bir **local privilege escalation** tekniğidir, genel bir remote relay hilesi değildir
- Attacker-controlled SMB service, ilk share mount için kullanılan **aynı TCP connection** üzerinde privileged authentication’ı handle etmelidir
- Zorlanan erişim **farklı bir share path**’e giderse, Windows farklı bir connection açabilir ve zincir bozulur
- SMB signing gereksinimleri, arbitrary-port adımı çalışsa bile relay’i bozabilir
- Yalnızca Kerberos material’ınız varsa veya local NTLM’i zorlayamıyorsanız, bu varyant tek başına yeterli değildir

## Detection ve hardening

- **March 2026 Patch Tuesday** ile gelen **CVE-2026-24294** yamasını uygulayın
- `net use` veya `New-SmbMapping` kullanımında **default olmayan SMB portları** için izleme yapın
- Workstation veya server’lardan **yüksek TCP portlarına** giden olağandışı outbound SMB trafiği için alarm üretin
- **EFSRPC / PetitPotam-style** tetikleyiciler gibi coercion fırsatlarını gözden geçirin
- Mümkün olan yerlerde SMB signing’i zorunlu kılın; Synacktiv, bunun Windows 11 24H2 üzerinde relay’lerini engellediğini özellikle belirtiyor

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
