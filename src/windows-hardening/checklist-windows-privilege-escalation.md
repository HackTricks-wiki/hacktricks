# Чекліст - Локальне підвищення привілеїв у Windows

{{#include ../banners/hacktricks-training.md}}

### **Найкращий tool для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Інформація про систему](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримати [**інформацію про систему**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукати **kernel** [**exploits за допомогою scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Використати **Google для пошуку** **kernel exploits**
- [ ] Використати **searchsploit для пошуку** **kernel exploits**
- [ ] Цікава інформація в [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Паролі в [**історії PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Цікава інформація в [**налаштуваннях Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Диски**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-updaters сторонніх агентів / зловживання IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Перевірка logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірити налаштування [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)і [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірити, чи активний [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Захист LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Кешовані credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірити, чи є будь-який [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Захист адміністратора / тихе підвищення через UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Поширення registry accessibility Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Привілеї користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірити [**привілеї** **поточного** користувача](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Чи є ви [**членом будь-якої привілейованої групи**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірити, чи маєте ви [активними будь-які з цих tokens](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Перевірити, чи маєте ви [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), щоб читати raw volumes і обходити file ACLs
- [ ] [**Сеанси користувачів**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірити[ **домашні каталоги користувачів**](windows-local-privilege-escalation/index.html#home-folders) (доступ?)
- [ ] Перевірити [**політику паролів**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що знаходиться[ **в Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірити **поточну** [**інформацію про** **мережу**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірити **приховані локальні services**, обмежені ззовні

### [Запущені процеси](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Права доступу до files і folders**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) бінарних файлів процесів
- [ ] [**Добування паролів із memory**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Небезпечні GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Викрасти credentials за допомогою **цікавих процесів** через `ProcDump.exe`? (firefox, chrome тощо ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **змінити будь-який service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **змінити** **binary**, який **виконується** будь-яким **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **змінити** **registry** будь-якого **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися перевагами **не взятого в лапки** **path** до binary **service**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: перелічити й активувати привілейовані services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] [**Права на запис для встановлених applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applications, що запускаються під час старту**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Вразливі** **Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **записувати в будь-яку папку всередині PATH**?
- [ ] Чи є відомий binary service, який **намагається завантажити будь-яку неіснуючу DLL**?
- [ ] Чи можете ви **записувати** в будь-яку **папку з binaries**?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перелічити мережу (shares, interfaces, routes, neighbours, ...)
- [ ] Особливо перевірити мережеві services, які слухають localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] credentials [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Чи є credentials у [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), які можна використати?
- [ ] Цікаві [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Паролі збережених [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Цікава інформація в [**збережених RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Паролі в [**нещодавно виконаних commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Паролі [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe існує**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files і Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **і** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys у registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Паролі в [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Будь-яка [**резервна копія SAM і SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Якщо присутній [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), спробувати читати raw volumes для `SAM`, `SYSTEM`, матеріалів DPAPI і `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Кешований GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Пароль у [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Цікава інформація у [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Хочете [**запросити credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Цікаві [**files у Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інші [**registry, що містять credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Усередині [**даних Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у files і registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до handler будь-якого процесу, запущеного адміністратором?

### [Імперсонація клієнта Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірити, чи можете ви цим зловживати

## References

- [1] [Project Zero - Обхід захисту адміністратора через зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
