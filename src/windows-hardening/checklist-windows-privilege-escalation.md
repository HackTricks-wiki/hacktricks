# Контрольний список — локальне підвищення привілеїв у Windows

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Системна інформація](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримати [**системну інформацію**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукати **експлойти ядра за допомогою скриптів**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Шукати **експлойти** ядра в **Google**
- [ ] Шукати **експлойти** ядра за допомогою **searchsploit**
- [ ] Є цікава інформація в [**змінних середовища**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Є паролі в [**історії PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Є цікава інформація в [**налаштуваннях інтернету**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Диски**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Експлойт WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Автоматичні оновлювачі сторонніх агентів / зловживання IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Перелік засобів журналювання/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірити налаштування [**аудиту** ](windows-local-privilege-escalation/index.html#audit-settings)і [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірити, чи активний [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Захист LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Захист облікових даних**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірити, чи є [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Захист адміністратора / приховане підвищення привілеїв UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Поширення параметрів реєстру спеціальних можливостей Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Привілеї користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірити [**привілеї** поточного **користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Ви [**входите до привілейованої групи**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірити, чи є [ці привілеї в поточному токені](windows-local-privilege-escalation/access-tokens.md), навіть якщо вони позначені як **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Увімкнути вимкнений привілей можна лише тоді, коли він уже є в токені.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Перевірити наявність [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) як права на обслуговування томів. Сам по собі він не надає доступу на читання сирого тому; для відкриття диска або тому також потрібні окремі дозволи.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Сеанси користувачів**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірити[ **домашні каталоги користувачів**](windows-local-privilege-escalation/index.html#home-folders) (доступ?)
- [ ] Перевірити [**політику паролів**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що є[ **в буфері обміну**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірити **поточну** [**інформацію про мережу**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірити **приховані локальні служби**, недоступні ззовні

### [Запущені процеси](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Дозволи на файли й папки**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) виконуваних файлів процесів
- [ ] [**Пошук паролів у пам’яті**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Незахищені GUI-застосунки**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Викрасти облікові дані за допомогою **цікавих процесів** через `ProcDump.exe`? (firefox, chrome тощо ...)

### [Служби](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **змінити якусь службу**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **змінити** **бінарний файл**, який **виконує** якась **служба**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **змінити** **реєстр** якоїсь **служби**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися **шляхом** до **бінарного файлу** **служби без лапок**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Тригери служб: перелічити й запускати привілейовані служби](windows-local-privilege-escalation/service-triggers.md)

### [**Застосунки**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Дозволи на запис** для [**встановлених застосунків**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Застосунки, що запускаються під час старту системи**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Вразливі** [**драйвери**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **записувати в будь-яку папку з PATH**?
- [ ] Чи є відома бінарна служба, яка **намагається завантажити неіснуючу DLL**?
- [ ] Чи можете ви **записувати** в будь-яку **папку з бінарними файлами**?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перелічити мережеві ресурси (спільні ресурси, інтерфейси, маршрути, сусідні вузли, ...)
- [ ] Особливо перевірити мережеві служби, що слухають на localhost (127.0.0.1)

### [Облікові дані Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Облікові дані [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Є [облікові дані **Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), які можна використати?
- [ ] Є цікаві [**облікові дані DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Паролі збережених [**мереж Wi-Fi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Є цікава інформація в [**збережених RDP-з’єднаннях**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Є паролі в [**нещодавно виконаних командах**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Паролі в [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**Існує AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Облікові дані?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Файли та реєстр (облікові дані)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**облікові дані**](windows-local-privilege-escalation/index.html#putty-creds) **та** [**ключі SSH-хостів**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Ключі SSH у реєстрі**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Є паролі в [**файлах автоматичної інсталяції**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Є резервна копія [**SAM і SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Якщо доступ на читання сирого тому дозволено окремо, перевірте можливий витік `SAM`, `SYSTEM`, матеріалів DPAPI та `MachineKeys`; не робіть висновок про наявність такого доступу лише на підставі **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] [**Хмарні облікові дані**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Кешований пароль GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Є пароль у [**файлі конфігурації IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Є цікава інформація у [**веб-журналах**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Хочете [**запросити облікові дані**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Є цікаві [**файли в кошику**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інші [**розділи реєстру з обліковими даними**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Дані [**браузера**](windows-local-privilege-escalation/index.html#browsers-history) (бази даних, історія, закладки, ...)?
- [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у файлах і реєстрі
- [ ] [**Інструменти**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до якогось handler процесу, запущеного адміністратором?

### [Імперсонування клієнта іменованого каналу](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірити, чи можна цим зловживати



## References

- [1] [Project Zero — обхід захисту адміністратора за допомогою зловживання UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec — RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft — привілеї](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft — зміна привілеїв у токені](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft — CreateFile для фізичних дисків і томів](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft — керування привілеями у файловій системі](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
