# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext та amfid

Він зосереджений на забезпеченні цілісності коду, що виконується в системі, реалізуючи логіку перевірки code signature у XNU. Він також може перевіряти entitlements і виконувати інші чутливі завдання, як-от дозволяти debugging або отримувати task ports.

Крім того, для деяких операцій kext надає перевагу зверненню до daemon `/usr/libexec/amfid`, що працює в user space. Цією довірою між компонентами зловживали в кількох jailbreak.

У новіших версіях macOS AMFI більше не представлений у зручному вигляді як окремий on-disk kext, тому reversing зазвичай означає роботу з **kernelcache** або **KDK**, а не перегляд `/System/Library/Extensions`.

AMFI використовує політики **MACF** і реєструє свої hooks одразу після запуску. Також запобігання його завантаженню або вивантаження може спричинити kernel panic. Однак існують boot arguments, які дають змогу послабити AMFI:

- `amfi_unrestricted_task_for_pid`: Дозволяє task_for_pid без необхідних entitlements
- `amfi_allow_any_signature`: Дозволяє будь-який code signature
- `cs_enforcement_disable`: Загальносистемний аргумент, що вимикає code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Позбавляє platform binaries з entitlements відповідного статусу
- `amfi_get_out_of_my_way`: Повністю вимикає amfi

Ось деякі політики MACF, які він реєструє:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`**: Виконується оновлення label і повертається 1
- **`cred_label_associate`**: Оновлює mac label slot AMFI за допомогою label
- **`cred_label_destroy`**: Видаляє mac label slot AMFI
- **`cred_label_init`**: Переміщує 0 у mac label slot AMFI
- **`cred_label_update_execve:`**: Перевіряє entitlements процесу, щоб визначити, чи дозволено йому змінювати labels.
- **`file_check_mmap:`**: Перевіряє, чи mmap отримує пам’ять і встановлює її як executable. У такому разі перевіряє, чи потрібна library validation, і якщо так, викликає функцію library validation.
- **`file_check_library_validation`**: Викликає функцію library validation, яка, серед іншого, перевіряє, чи platform binary завантажує інший platform binary, або чи мають процес і новий завантажений файл однаковий TeamID. Певні entitlements також дозволяють завантажувати будь-яку library.
- **`policy_initbsd`**: Налаштовує довірені NVRAM Keys
- **`policy_syscall`**: Перевіряє DYLD policies, наприклад, чи має binary unrestricted segments і чи слід дозволити env vars... Також викликається, коли процес запускається через `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Перевіряє, чи повинні інші процеси з правами SEND на task port процесу зберігати їх після виконання процесом нового binary. Platform binaries отримують дозвіл, entitlement `get-task-allow` також його надає, entitlement `task_for_pid-allow` дозволяє це, як і binaries з однаковим TeamID.
- **`proc_check_expose_task`**: Застосовує entitlements
- **`amfi_exc_action_check_exception_send`**: Exception message надсилається debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Життєвий цикл label під час обробки exception (debugging)
- **`proc_check_get_task`**: Перевіряє entitlements, як-от `get-task-allow`, який дозволяє іншим процесам отримувати task port процесу, і `task_for_pid-allow`, який дозволяє процесу отримувати task ports інших процесів. Якщо немає жодного з них, він звертається до `amfid permitunrestricteddebugging`, щоб перевірити, чи дозволено це.
- **`proc_check_mprotect`**: Забороняє операцію, якщо `mprotect` викликається з flag `VM_PROT_TRUSTED`, який вказує, що region слід обробляти так, ніби він має дійсний code signature.
- **`vnode_check_exec`**: Викликається, коли executable files завантажуються в пам’ять, і встановлює `cs_hard | cs_kill`, що завершить процес, якщо будь-яка зі сторінок стане недійсною<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Перевіряє `com.apple.root.installed` і `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Як get + entitlements `com.apple.private.allow-bless` та `internal-installer-equivalent`
- **`vnode_check_signature`**: Код, який викликає XNU для перевірки code signature за допомогою entitlements, trust cache і `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Перехоплює виклики `ptrace()` (`PT_ATTACH` і `PT_TRACE_ME`). Перевіряє наявність будь-якого з entitlements `get-task-allow`, `run-invalid-allow` і `run-unsigned-code`, а якщо жодного немає, перевіряє, чи дозволено debugging.
- **`proc_check_map_anon`**: Якщо mmap викликається з flag **`MAP_JIT`**, AMFI перевіряє entitlement `dynamic-codesigning`.

`AMFI.kext` також надає API для інших kernel extensions, і його dependencies можна знайти за допомогою:
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

Це daemon, що працює в режимі користувача, який `AMFI.kext` використовує для перевірки code signatures у режимі користувача.\
Щоб `AMFI.kext` міг взаємодіяти з daemon, він використовує mach messages через port `HOST_AMFID_PORT`, який є спеціальним port `18`.

Зверніть увагу, що в macOS root processes більше не можуть перехоплювати special ports, оскільки вони захищені `SIP`, і отримати їх може лише launchd. В iOS перевіряється, що process, який надсилає відповідь, має hardcoded CDHash `amfid`.

Можна побачити, коли `amfid` запитують перевірити binary, а також його відповідь, якщо виконати debugging і встановити breakpoint у `mach_msg`.

Після отримання message через special port для надсилання кожної function до function, яку вона викликає, використовується **MIG**. Основні functions були reversed та пояснені в книзі.

### DYLD policy and library validation

Recent версії `dyld` дуже рано викликають `amfi_check_dyld_policy_self()` з `configureProcessRestrictions()`, щоб запитати в AMFI, чи може process використовувати `DYLD_*` path variables, interposing, fallback paths, embedded variables або tolerувати невдалу вставку library. Тому під час triage injection surface недостатньо перевіряти лише Mach-O load commands: також потрібно перевіряти entitlements і runtime flags, які AMFI перетворить на `dyld` policy.

Практичний triage loop має такий вигляд:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
У сучасній macOS багато бінарних файлів Apple більше не містять `com.apple.security.cs.disable-library-validation` безпосередньо, а натомість постачаються з `com.apple.private.security.clear-library-validation`. У такому разі library validation не вимикається під час `execve`: процес має викликати `csops(..., CS_OPS_CLEAR_LV, ...)` для самого себе, а XNU дозволяє цю операцію процесу, що її викликає, лише за наявності entitlement. З offensive perspective це важливо, оскільки target може стати injectable лише **після** досягнення code path, який явно очищує LV (наприклад, незадовго до завантаження optional plugins).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile можна використовувати для підписування code. Існують **Developer** profiles, які можна використовувати для підписування code і його тестування, а також **Enterprise** profiles, які можна використовувати на всіх пристроях.

Після того як App подано до Apple Store і його схвалено, Apple підписує його, і provisioning profile більше не потрібен.

Profile зазвичай має розширення `.mobileprovision` або `.provisionprofile`, а його вміст можна отримати за допомогою:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Хоча їх іноді називають сертифікованими, ці provisioning profiles містять не лише сертифікат:

- **AppIDName:** Ідентифікатор застосунку
- **AppleInternalProfile**: Позначає цей профіль як внутрішній профіль Apple
- **ApplicationIdentifierPrefix**: Додається перед AppIDName (те саме, що TeamIdentifier)
- **CreationDate**: Дата у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Масив із (зазвичай одним) сертифікатом(ами), закодованими як дані Base64
- **Entitlements**: Дозволені entitlements разом з entitlements для цього профілю
- **ExpirationDate**: Дата завершення дії у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Назва застосунку, така сама, як AppIDName
- **ProvisionedDevices**: Масив (для сертифікатів розробника) UDID, для яких цей профіль є дійсним
- **ProvisionsAllDevices**: Логічне значення (true для корпоративних сертифікатів)
- **TeamIdentifier**: Масив із (зазвичай одним) буквено-цифровим рядком(ами), що використовується для ідентифікації розробника з метою взаємодії між застосунками
- **TeamName**: Зрозуміла для людини назва, що використовується для ідентифікації розробника
- **TimeToLive**: Термін дії (у днях) сертифіката
- **UUID**: Універсальний унікальний ідентифікатор цього профілю
- **Version**: Наразі має значення 1

Зверніть увагу, що запис entitlements міститиме обмежений набір entitlements, а provisioning profile зможе надавати лише ці конкретні entitlements, щоб запобігти наданню приватних entitlements Apple.

Зверніть увагу, що профілі зазвичай розташовані в `/var/MobileDeviceProvisioningProfiles`, і їх можна перевірити за допомогою **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Це зовнішня бібліотека, яку викликає `amfid`, щоб визначити, чи слід щось дозволити. Історично її зловживано в jailbreaking: запускалася backdoored-версія, яка дозволяла все.

У macOS вона знаходиться всередині `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches — це не лише концепція iOS. У сучасній macOS, особливо на **Apple silicon**, static trust cache та loadable trust caches є частиною Secure Boot chain. Коли **CodeDirectory hash** Mach-O присутній у ньому, AMFI може надати йому **platform privilege** без виконання додаткових перевірок автентичності під час запуску. Це також означає, що Apple може прив’язувати platform binaries до певної версії ОС і запобігати повторному використанню старіших бінарних файлів, підписаних Apple, у новіших системах.<sup>[[6]](#references)</sup>

У нових випусках macOS метадані trust cache також пов’язані з **launch constraints**, тому скопійовані системні застосунки та бінарні файли, запущені від неправильного parent/location, можуть бути відхилені AMFI, навіть якщо вони все ще підписані Apple. Докладний workflow вилучення та reversing описано в:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

У дослідженнях iOS і jailbreak ви й надалі зустрічатимете традиційну модель **loadable trust caches**, що використовується для whitelist бінарних файлів із ad-hoc підписом.

## Посилання

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
