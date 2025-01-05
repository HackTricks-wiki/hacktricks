# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext та amfid

Він зосереджується на забезпеченні цілісності коду, що виконується в системі, надаючи логіку перевірки підпису коду XNU. Він також здатний перевіряти права доступу та виконувати інші чутливі завдання, такі як дозволення налагодження або отримання портів завдань.

Більше того, для деяких операцій kext надає перевагу зв'язку з демоном користувацького простору `/usr/libexec/amfid`. Ця довірча взаємозв'язок була зловживана в кількох джейлбрейках.

AMFI використовує **MACF** політики і реєструє свої хуки в момент запуску. Також, запобігання його завантаженню або вивантаженню може викликати паніку ядра. Однак існують деякі аргументи завантаження, які дозволяють ослабити AMFI:

- `amfi_unrestricted_task_for_pid`: Дозволити task_for_pid без необхідних прав доступу
- `amfi_allow_any_signature`: Дозволити будь-який підпис коду
- `cs_enforcement_disable`: Аргумент системного рівня, що використовується для відключення примусу підпису коду
- `amfi_prevent_old_entitled_platform_binaries`: Скасувати платформні бінарники з правами доступу
- `amfi_get_out_of_my_way`: Повністю відключає amfi

Це деякі з політик MACF, які він реєструє:

- **`cred_check_label_update_execve:`** Оновлення мітки буде виконано і поверне 1
- **`cred_label_associate`**: Оновити слот mac мітки AMFI з міткою
- **`cred_label_destroy`**: Видалити слот mac мітки AMFI
- **`cred_label_init`**: Перемістити 0 в слот mac мітки AMFI
- **`cred_label_update_execve`:** Перевіряє права доступу процесу, щоб визначити, чи слід дозволити змінювати мітки.
- **`file_check_mmap`:** Перевіряє, чи mmap отримує пам'ять і встановлює її як виконувану. У цьому випадку перевіряє, чи потрібна валідація бібліотеки, і якщо так, викликає функцію валідації бібліотеки.
- **`file_check_library_validation`**: Викликає функцію валідації бібліотеки, яка перевіряє, серед іншого, чи завантажує платформний бінарник інший платформний бінарник або чи має процес і новий завантажений файл однаковий TeamID. Деякі права доступу також дозволять завантажити будь-яку бібліотеку.
- **`policy_initbsd`**: Налаштовує довірені ключі NVRAM
- **`policy_syscall`**: Перевіряє політики DYLD, такі як чи має бінарник необмежені сегменти, чи слід дозволити змінні середовища... це також викликається, коли процес запускається через `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Перевіряє, чи повинні інші процеси з правами SEND на порт завдання процесу зберігати їх, коли процес виконує новий бінарник. Платформні бінарники дозволені, право `get-task-allow` це дозволяє, права `task_for_pid-allow` дозволені, а бінарники з однаковим TeamID.
- **`proc_check_expose_task`**: примусити права доступу
- **`amfi_exc_action_check_exception_send`**: Повідомлення про виключення надсилається налагоджувачу
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Життєвий цикл мітки під час обробки виключень (налагодження)
- **`proc_check_get_task`**: Перевіряє права доступу, такі як `get-task-allow`, які дозволяють іншим процесам отримувати порт завдань, і `task_for_pid-allow`, які дозволяють процесу отримувати порти завдань інших процесів. Якщо жоден з цих варіантів не підходить, викликає `amfid permitunrestricteddebugging`, щоб перевірити, чи це дозволено.
- **`proc_check_mprotect`**: Відмовити, якщо `mprotect` викликано з прапором `VM_PROT_TRUSTED`, що вказує на те, що регіон повинен розглядатися так, ніби має дійсний підпис коду.
- **`vnode_check_exec`**: Викликається, коли виконувані файли завантажуються в пам'ять і встановлює `cs_hard | cs_kill`, що вб'є процес, якщо будь-яка з сторінок стане недійсною
- **`vnode_check_getextattr`**: MacOS: Перевірка `com.apple.root.installed` та `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Як отримати + com.apple.private.allow-bless та еквівалент прав доступу внутрішнього інсталятора
- **`vnode_check_signature`**: Код, який викликає XNU для перевірки підпису коду, використовуючи права доступу, кеш довіри та `amfid`
- **`proc_check_run_cs_invalid`**: Перехоплює виклики `ptrace()` (`PT_ATTACH` та `PT_TRACE_ME`). Перевіряє наявність будь-яких прав доступу `get-task-allow`, `run-invalid-allow` та `run-unsigned-code`, і якщо жоден з них не підходить, перевіряє, чи дозволено налагодження.
- **`proc_check_map_anon`**: Якщо mmap викликано з прапором **`MAP_JIT`**, AMFI перевірить право `dynamic-codesigning`.

`AMFI.kext` також надає API для інших розширень ядра, і можливо знайти його залежності за допомогою:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Це демон, що працює в режимі користувача, який використовує `AMFI.kext` для перевірки підписів коду в режимі користувача.\
Для того, щоб `AMFI.kext` міг спілкуватися з демоном, він використовує mach-повідомлення через порт `HOST_AMFID_PORT`, який є спеціальним портом `18`.

Зверніть увагу, що в macOS більше неможливо, щоб процеси root захоплювали спеціальні порти, оскільки вони захищені `SIP`, і лише launchd може їх отримати. В iOS перевіряється, що процес, який надсилає відповідь, має жорстко закодований CDHash `amfid`.

Можна побачити, коли `amfid` запитується для перевірки бінарного файлу та його відповідь, відлагоджуючи його та встановлюючи точку зупинки в `mach_msg`.

Коли повідомлення отримується через спеціальний порт, **MIG** використовується для надсилання кожної функції до функції, яку вона викликає. Основні функції були реверсовані та пояснені в книзі.

## Provisioning Profiles

Профіль налаштування може бути використаний для підписання коду. Є **Developer** профілі, які можуть бути використані для підписання коду та його тестування, та **Enterprise** профілі, які можуть бути використані на всіх пристроях.

Після того, як додаток подається до Apple Store, якщо його затверджують, він підписується Apple, і профіль налаштування більше не потрібен.

Профіль зазвичай використовує розширення `.mobileprovision` або `.provisionprofile` і може бути вивантажений за допомогою:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Хоча іноді їх називають сертифікованими, ці профілі налаштувань мають більше, ніж сертифікат:

- **AppIDName:** Ідентифікатор програми
- **AppleInternalProfile**: Позначає це як внутрішній профіль Apple
- **ApplicationIdentifierPrefix**: Додається до AppIDName (так само, як TeamIdentifier)
- **CreationDate**: Дата у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Масив (зазвичай один) сертифікат(ів), закодованих у форматі Base64
- **Entitlements**: Права, дозволені для цього профілю
- **ExpirationDate**: Дата закінчення у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Назва програми, така ж, як AppIDName
- **ProvisionedDevices**: Масив (для сертифікатів розробника) UDID, для яких цей профіль є дійсним
- **ProvisionsAllDevices**: Логічне значення (true для корпоративних сертифікатів)
- **TeamIdentifier**: Масив (зазвичай один) алфавітно-цифровий рядок(и), що використовується для ідентифікації розробника для міжпрограмної взаємодії
- **TeamName**: Людське ім'я, що використовується для ідентифікації розробника
- **TimeToLive**: Термін дії (в днях) сертифіката
- **UUID**: Універсальний унікальний ідентифікатор для цього профілю
- **Version**: В даний час встановлено на 1

Зверніть увагу, що запис прав міститиме обмежений набір прав, і профіль налаштувань зможе надати лише ці конкретні права, щоб запобігти наданню приватних прав Apple.

Зверніть увагу, що профілі зазвичай розташовані в `/var/MobileDeviceProvisioningProfiles`, і їх можна перевірити за допомогою **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

Це зовнішня бібліотека, яку `amfid` викликає, щоб запитати, чи слід дозволити щось чи ні. Історично це зловживалося в джейлбрейкінгу шляхом запуску зламаної версії, яка дозволяла все.

У macOS це знаходиться в `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI підтримує список відомих хешів, які підписані ad-hoc, що називається **Trust Cache** і знаходиться в секції kext `__TEXT.__const`. Зверніть увагу, що в дуже специфічних і чутливих операціях можливо розширити цей Trust Cache за допомогою зовнішнього файлу.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
