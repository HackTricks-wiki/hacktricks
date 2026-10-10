# Перелік перевірки — локальне підвищення привілеїв у Windows

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Інформація про систему](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримайте [**інформацію про систему**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукайте **kernel** [**exploits за допомогою скриптів**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Використовуйте **Google для пошуку** **kernel exploits**
- [ ] Використовуйте **searchsploit для пошуку** **kernel exploits**
- [ ] Чи є цікава інформація в [**змінних середовища**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Чи є паролі в [**історії PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Чи є цікава інформація в [**налаштуваннях Інтернету**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Диски**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Автоматичні оновлювачі сторонніх агентів / зловживання IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Перелік журналів/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірте налаштування [**аудиту** ](windows-local-privilege-escalation/index.html#audit-settings)і [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірте [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірте, чи активний [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Захист LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірте, чи є [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Захист адміністратора / тихе підвищення привілеїв UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Поширення записів реєстру доступності Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Привілеї користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірте [**привілеї** поточного **користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Чи є ви [**членом привілейованої групи**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірте, чи ввімкнено у вас [будь-які з цих токенів](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Перевірте, чи маєте ви [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), щоб читати raw volumes і обходити ACL файлів
- [ ] [**Сеанси користувачів**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірте[ **домашні каталоги користувачів**](windows-local-privilege-escalation/index.html#home-folders) (доступ?)
- [ ] Перевірте [**політику паролів**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що[ **міститься в буфері обміну**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірте **поточну** [**інформацію про мережу**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірте наявність **прихованих локальних служб**, доступ до яких ззовні обмежений

### [Запущені процеси](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Дозволи на файли та папки**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) бінарних файлів процесів
- [ ] [**Пошук паролів у пам’яті**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Незахищені GUI-програми**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Викрадіть облікові дані за допомогою **цікавих процесів** через `ProcDump.exe`? (firefox, chrome тощо...)

### [Служби](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **змінити будь-яку службу**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **змінити** **бінарний файл**, який **виконує** будь-яка **служба**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **змінити** **реєстр** будь-якої **служби**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися **шляхом** до бінарного файлу **служби без лапок**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Тригери служб: перелік і запуск привілейованих служб](windows-local-privilege-escalation/service-triggers.md)

### [**Програми**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Дозволи на запис** [**до встановлених програм**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Програми автозапуску**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Вразливі** [**драйвери**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **записувати в будь-яку папку в PATH**?
- [ ] Чи є відома бінарна програма служби, яка **намагається завантажити неіснуючу DLL**?
- [ ] Чи можете ви **записувати** в будь-яку **папку з бінарними файлами**?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перерахуйте мережеві ресурси (спільні ресурси, інтерфейси, маршрути, сусідні вузли...)
- [ ] Зверніть особливу увагу на мережеві служби, що прослуховують localhost (127.0.0.1)

### [Облікові дані Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Облікові дані [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Чи є облікові дані [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), якими можна скористатися?
- [ ] Чи є цікаві [**облікові дані DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Паролі збережених [**мереж Wi-Fi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Чи є цікава інформація в [**збережених RDP-підключеннях**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Чи є паролі в [**нещодавно виконаних командах**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Паролі в [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Чи існує [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Облікові дані?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Файли та реєстр (облікові дані)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**облікові дані**](windows-local-privilege-escalation/index.html#putty-creds) **і** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-ключі в реєстрі**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Чи є паролі в [**файлах unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Чи є резервні копії [**SAM і SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Якщо доступний [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), спробуйте читати raw volumes, щоб отримати `SAM`, `SYSTEM`, матеріали DPAPI та `MachineKeys`
- [ ] [**Хмарні облікові дані**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Кешований пароль GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Пароль у [**файлі конфігурації IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Чи є цікава інформація в [**веб-журналах**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Хочете [**запросити облікові дані**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Чи є цікаві [**файли в кошику**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інші [**розділи реєстру з обліковими даними**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Чи є щось у [**даних браузера**](windows-local-privilege-escalation/index.html#browsers-history) (бази даних, історія, закладки...)?
- [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у файлах і реєстрі
- [ ] [**Інструменти**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Leaked обробники](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до будь-якого обробника процесу, запущеного адміністратором?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірте, чи можете ви цим зловживати

## References

- [1] [Project Zero — Обхід захисту адміністратора за допомогою зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec — RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
