# Чекліст - Локальне підвищення привілеїв у Windows

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Інформація про систему](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримати [**інформацію про систему**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукати **kernel** [**exploits за допомогою скриптів**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Використати **Google для пошуку** **kernel exploits**
- [ ] Використати **searchsploit для пошуку** **kernel exploits**
- [ ] Цікава інформація в [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Паролі в [**історії PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Цікава інформація в [**налаштуваннях Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Диски**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Автооновлювачі сторонніх агентів / зловживання IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Перерахування журналювання/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірити налаштування [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)і [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірити, чи активний [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Захист LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірити, чи є [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Захист адміністратора / тиха ескалація через UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Поширення accessibility registry у Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Привілеї користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірити [**привілеї**](windows-local-privilege-escalation/index.html#users-and-groups) **поточного** користувача
- [ ] Чи є ви [**членом будь-якої привілейованої групи**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірити, чи ввімкнені [будь-які з цих токенів](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Перевірити, чи маєте ви [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) для читання raw volumes і обходу ACL файлів
- [ ] [**Сеанси користувачів**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірити[ **домашні каталоги користувачів**](windows-local-privilege-escalation/index.html#home-folders) (доступ?)
- [ ] Перевірити [**політику паролів**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що знаходиться[ **в буфері обміну**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірити **поточну** [**мережеву** **інформацію**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірити **приховані локальні служби**, обмежені для зовнішнього доступу

### [Запущені процеси](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Дозволи на файли та каталоги**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) бінарних файлів процесів
- [ ] [**Видобування паролів із пам'яті**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Незахищені GUI-застосунки**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Викрасти облікові дані за допомогою **цікавих процесів** через `ProcDump.exe` ? (firefox, chrome тощо ...)

### [Служби](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **змінити будь-яку службу**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **змінити** **бінарний файл**, який **виконується** будь-якою **службою**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **змінити** **реєстр** будь-якої **служби**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися **шляхом** **бінарного файлу служби без лапок**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Тригери служб: перерахувати та запустити привілейовані служби](windows-local-privilege-escalation/service-triggers.md)

### [**Застосунки**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Дозволи на запис** для [**встановлених застосунків**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Застосунки автозапуску**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Вразливі** [**драйвери**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **записувати в будь-який каталог усередині PATH**?
- [ ] Чи є відомий бінарний файл служби, який **намагається завантажити неіснуючу DLL**?
- [ ] Чи можете ви **записувати** в будь-який **каталог бінарних файлів**?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу (спільні ресурси, інтерфейси, маршрути, сусіди, ...)
- [ ] Особливо перевірити мережеві служби, що прослуховують localhost (127.0.0.1)

### [Облікові дані Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Облікові дані [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Облікові дані [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), які можна використати?
- [ ] Цікаві [**облікові дані DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Паролі збережених [**мереж Wifi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Цікава інформація в [**збережених RDP-з'єднаннях**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Паролі в [**нещодавно виконаних командах**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Паролі в [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**Існує AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Облікові дані?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Файли та реєстр (облікові дані)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**облікові дані**](windows-local-privilege-escalation/index.html#putty-creds) **і** [**ключі SSH-хостів**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Ключі SSH у реєстрі**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Паролі в [**unattended-файлах**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Будь-яка [**резервна копія SAM і SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Якщо присутній [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), спробувати читати raw volumes для `SAM`, `SYSTEM`, матеріалів DPAPI та `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Кешований пароль GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Пароль у [**конфігураційному файлі IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Цікава інформація у [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Хочете [**запросити облікові дані**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Цікаві [**файли в Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інші [**розділи реєстру, що містять облікові дані**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Усередині [**даних браузера**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, історія, закладки, ...)?
- [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у файлах і реєстрі
- [ ] [**Інструменти**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до будь-якого handler процесу, запущеного адміністратором?

### [Імперсонація клієнта Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірити, чи можете ви цим зловживати

## References

- [1] [Project Zero - Обхід захисту адміністратора через зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
