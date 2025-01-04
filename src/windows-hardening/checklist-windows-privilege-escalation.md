# Чеклист - Локальне підвищення привілеїв Windows

{{#include ../banners/hacktricks-training.md}}

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Інформація про систему](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримати [**інформацію про систему**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукати **експлойти ядра** [**за допомогою скриптів**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Використовувати **Google для пошуку** експлойтів ядра
- [ ] Використовувати **searchsploit для пошуку** експлойтів ядра
- [ ] Цікава інформація в [**змінних середовища**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Паролі в [**історії PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Цікава інформація в [**налаштуваннях Інтернету**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Диски**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Експлойт WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Перерахування журналів/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірити [**налаштування аудиту**](windows-local-privilege-escalation/index.html#audit-settings) та [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірити, чи активний [**WDigest**](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**Захист LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірити, чи є [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Привілеї користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірити [**привілеї поточного користувача**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Чи є ви [**членом будь-якої привілейованої групи**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірити, чи є у вас [будь-які з цих токенів, активованих](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Сесії користувачів**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірити [**домашні папки користувачів**](windows-local-privilege-escalation/index.html#home-folders) (доступ?)
- [ ] Перевірити [**Політику паролів**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що [**всередині буфера обміну**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірити **поточну** [**мережеву** **інформацію**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірити **приховані локальні служби**, обмежені для зовнішнього доступу

### [Запущені процеси](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Бінарні файли процесів [**дозволи на файли та папки**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Видобуток паролів з пам'яті**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Небезпечні GUI додатки**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Вкрасти облікові дані з **цікавих процесів** за допомогою `ProcDump.exe` ? (firefox, chrome тощо ...)

### [Служби](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **модифікувати будь-яку службу**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **модифікувати** **бінарний файл**, який **виконується** будь-якою **службою**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **модифікувати** **реєстр** будь-якої **служби**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися будь-яким **нецитованим шляхом** бінарного файлу **служби**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Додатки**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Записати** [**дозволи на встановлені додатки**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Додатки автозавантаження**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Вразливі** [**драйвери**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **записувати в будь-яку папку всередині PATH**?
- [ ] Чи є відомий бінарний файл служби, який **намагається завантажити будь-який неіснуючий DLL**?
- [ ] Чи можете ви **записувати** в будь-якій **папці бінарних файлів**?

### [Мережа](windows-local-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу (спільні ресурси, інтерфейси, маршрути, сусіди тощо ...)
- [ ] Уважно перевірити мережеві служби, що слухають на localhost (127.0.0.1)

### [Облікові дані Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Облікові дані Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] [**Облікові дані Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), які ви могли б використовувати?
- [ ] Цікаві [**облікові дані DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Паролі збережених [**Wifi мереж**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Цікава інформація в [**збережених RDP з'єднаннях**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Паролі в [**недавніх командах**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Паролі [**менеджера облікових даних віддаленого робочого столу**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Чи існує [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Облікові дані?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? Завантаження DLL з боку?

### [Файли та реєстр (Облікові дані)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Облікові дані**](windows-local-privilege-escalation/index.html#putty-creds) **та** [**SSH ключі хоста**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH ключі в реєстрі**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Паролі в [**непідконтрольних файлах**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Будь-яка [**резервна копія SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Облікові дані хмари**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Кешований GPP пароль**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Пароль у [**файлі конфігурації IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Цікава інформація в [**веб** **журналах**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Чи хочете ви [**попросити облікові дані**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Цікаві [**файли в кошику**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інші [**реєстри, що містять облікові дані**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Всередині [**даних браузера**](windows-local-privilege-escalation/index.html#browsers-history) (бази даних, історія, закладки тощо)?
- [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у файлах та реєстрі
- [ ] [**Інструменти**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Витік обробників](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до будь-якого обробника процесу, запущеного адміністратором?

### [Імітація клієнта Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірте, чи можете ви це зловживати

{{#include ../banners/hacktricks-training.md}}
