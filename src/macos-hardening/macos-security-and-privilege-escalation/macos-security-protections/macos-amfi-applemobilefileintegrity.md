# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Він зосереджений на забезпеченні цілісності коду, що виконується в системі, надаючи логіку, яка стоїть за перевіркою code signature в XNU. Він також може перевіряти entitlements і виконувати інші чутливі завдання, такі як дозвіл debug або отримання task ports.

Крім того, для деяких операцій kext надає перевагу зверненню до daemon у user space `/usr/libexec/amfid`. Ці відносини довіри використовувалися в кількох jailbreaks.

У recent macOS versions AMFI більше не доступний зручно як окремий on-disk kext, тому reversing зазвичай означає роботу з **kernelcache** або **KDK** замість перегляду `/System/Library/Extensions`.

AMFI використовує політики **MACF** і реєструє свої hooks у момент запуску. Також запобігання його завантаженню або його unloading може викликати kernel panic. Однак є деякі boot arguments, які дозволяють послабити AMFI:

- `amfi_unrestricted_task_for_pid`: Дозволяє `task_for_pid` без необхідних entitlements
- `amfi_allow_any_signature`: Дозволяє будь-який code signature
- `cs_enforcement_disable`: Системний аргумент, що використовується для вимкнення code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Відкликає platform binaries з entitlements
- `amfi_get_out_of_my_way`: Повністю вимикає amfi

Ось деякі з MACF policies, які він реєструє:

- **`cred_check_label_update_execve:`** Оновлення label буде виконано і поверне 1
- **`cred_label_associate`**: Оновлює слот mac label в AMFI значенням label
- **`cred_label_destroy`**: Видаляє слот mac label в AMFI
- **`cred_label_init`**: Встановлює 0 у слоті mac label в AMFI
- **`cred_label_update_execve`:** Перевіряє entitlements процесу, щоб визначити, чи дозволено йому змінювати labels.
- **`file_check_mmap`:** Перевіряє, чи `mmap` отримує memory і встановлює її як executable. У такому разі перевіряє, чи потрібна library validation, і якщо так, викликає функцію library validation.
- **`file_check_library_validation`**: Викликає функцію library validation, яка серед іншого перевіряє, чи platform binary завантажує інший platform binary, або чи process і новий завантажений файл мають однаковий TeamID. Певні entitlements також дозволяють завантажувати будь-яку library.
- **`policy_initbsd`**: Налаштовує довірені NVRAM Keys
- **`policy_syscall`**: Перевіряє DYLD policies, наприклад, чи binary має unrestricted segments, чи слід дозволяти env vars... це також викликається, коли process запускається через `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Перевіряє, чи під час виконання process нового binary інші process із SEND правами на task port цього process повинні зберегти їх чи ні. Platform binaries дозволені, entitlement `get-task-allow` дозволяє це, entitlements `task_for_pid-allow` дозволені, а також binaries з однаковим TeamID.
- **`proc_check_expose_task`**: примусово перевіряє entitlements
- **`amfi_exc_action_check_exception_send`**: Повідомлення exception надсилається debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Життєвий цикл label під час обробки exception (debugging)
- **`proc_check_get_task`**: Перевіряє entitlements, такі як `get-task-allow`, який дозволяє іншим process отримувати task port, і `task_for_pid-allow`, який дозволяє process отримувати task ports інших process. Якщо жодного з них немає, він звертається до `amfid permitunrestricteddebugging`, щоб перевірити, чи це дозволено.
- **`proc_check_mprotect`**: Відхиляє, якщо `mprotect` викликається з прапором `VM_PROT_TRUSTED`, що вказує: область має розглядатися так, ніби вона має валідний code signature.
- **`vnode_check_exec`**: Викликається, коли executable files завантажуються в memory, і встановлює `cs_hard | cs_kill`, що завершить process, якщо будь-яка зі сторінок стане невалідною
- **`vnode_check_getextattr`**: MacOS: Перевіряє `com.apple.root.installed` і `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Як get + `com.apple.private.allow-bless` і internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Код, який викликає XNU для перевірки code signature за допомогою entitlements, trust cache і `amfid`
- **`proc_check_run_cs_invalid`**: Перехоплює виклики `ptrace()` (`PT_ATTACH` і `PT_TRACE_ME`). Перевіряє наявність entitlements `get-task-allow`, `run-invalid-allow` і `run-unsigned-code`, а якщо жодного немає, перевіряє, чи дозволено debugging.
- **`proc_check_map_anon`**: Якщо `mmap` викликається з прапором **`MAP_JIT`**, AMFI перевірятиме entitlement `dynamic-codesigning`.

`AMFI.kext` також надає API для інших kernel extensions, і можна знайти його dependencies за допомогою:
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

Це daemon у user mode, який `AMFI.kext` використовуватиме для перевірки code signatures у user mode.\
Щоб `AMFI.kext` міг спілкуватися з daemon, він використовує mach messages через порт `HOST_AMFID_PORT`, який є спеціальним портом `18`.

Зауважте, що в macOS більше не можна для root processes hijack special ports, оскільки вони захищені `SIP`, і лише launchd може їх отримати. В iOS перевіряється, що процес, який надсилає response назад, має CDHash hardcoded of `amfid`.

Можна побачити, коли `amfid` запитується на перевірку binary і response від нього, налагоджуючи його та встановивши breakpoint у `mach_msg`.

Після того як message отримано через special port, використовується **MIG**, щоб передати кожну function до function, яку вона викликає. Основні functions були reversed і пояснені всередині book.

### DYLD policy and library validation

Пізніші версії `dyld` дуже рано викликають `amfi_check_dyld_policy_self()` з `configureProcessRestrictions()`, щоб запитати AMFI, чи може process використовувати `DYLD_*` path variables, interposing, fallback paths, embedded variables або tolerates failed library insertion. Тому під час triaging injection surface недостатньо перевіряти лише Mach-O load commands: також потрібно перевіряти entitlements і runtime flags, які AMFI перетворить на `dyld` policy.

Практичний triage loop такий:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
На сучасних macOS багато Apple binary більше не мають `com.apple.security.cs.disable-library-validation` напряму і замість цього постачаються з `com.apple.private.security.clear-library-validation`. У такому випадку library validation не вимикається під час `execve`: процес має викликати `csops(..., CS_OPS_CLEAR_LV, ...)` для самого себе, і XNU дозволяє цю операцію лише для calling process, коли entitlement присутній. З offensive perspective це важливо, бо target може стати injectable лише **після** того, як він дійде до code path, що явно очищає LV (наприклад, незадовго до завантаження optional plugins).

## Provisioning Profiles

A provisioning profile can be used to sign code. There are **Developer** profiles that can be used to sign code and test it, and **Enterprise** profiles which can be used in all devices.

After an App is submitted to the Apple Store, if approved, it's signed by Apple and the provisioning profile is no longer needed.

A profile usually use the extension `.mobileprovision` or `.provisionprofile` and can be dumped with:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Хоча інколи їх називають certificated, ці provisioning profiles містять більше, ніж сертифікат:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Позначає це як Apple Internal profile
- **ApplicationIdentifierPrefix**: Додається перед AppIDName (те саме, що TeamIdentifier)
- **CreationDate**: Дата у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Масив (зазвичай одного) certificate(s), закодованих як Base64 data
- **Entitlements**: entitlements, дозволені з entitlements для цього profile
- **ExpirationDate**: Дата закінчення у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Application Name, те саме, що AppIDName
- **ProvisionedDevices**: Масив (для developer certificates) UDID, для яких цей profile valid
- **ProvisionsAllDevices**: Булеве значення (true для enterprise certificates)
- **TeamIdentifier**: Масив (зазвичай одного) буквено-цифрового string(s), що використовується для ідентифікації developer для міждодаткової взаємодії
- **TeamName**: Людиночитабельна назва, що використовується для ідентифікації developer
- **TimeToLive**: Термін дії (у днях) certificate
- **UUID**: Universally Unique Identifier для цього profile
- **Version**: Наразі встановлено на 1

Зверніть увагу, що запис entitlements міститиме обмежений набір entitlements, і provisioning profile зможе надавати лише ці конкретні entitlements, щоб запобігти наданню Apple private entitlements.

Зверніть увагу, що profiles зазвичай розташовані в `/var/MobileDeviceProvisioningProfiles`, і їх можна перевірити за допомогою **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Це зовнішня library, яку викликає `amfid`, щоб запитати, чи слід дозволити щось чи ні. Історично це зловживалося в jailbreaking шляхом запуску backdoored версії, яка дозволяла все.

У macOS це знаходиться всередині `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches — це не лише концепція iOS. На сучасному macOS, особливо на **Apple silicon**, static trust cache і loadable trust caches є частиною Secure Boot chain. Коли **CodeDirectory hash** Mach-O присутній там, AMFI може надати йому **platform privilege** без додаткових перевірок authenticity під час launch time. Це також означає, що Apple може прив’язувати platform binaries до конкретної OS version і запобігати replay старих Apple-signed binaries на новіших системах.

У нещодавніх macOS releases metadata trust-cache також пов’язана з **launch constraints**, тому copied system apps і binaries, запущені з неправильного parent/location, можуть бути відхилені AMFI навіть якщо вони все ще Apple-signed. Детальний workflow extraction і reversing описано в:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

В iOS і jailbreak research ви й далі знайдете традиційну модель **loadable trust caches**, яку використовують для whitelist ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
