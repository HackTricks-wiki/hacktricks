# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Він зосереджується на забезпеченні цілісності коду, що виконується в системі, надаючи логіку для перевірки code signature в XNU. Також він може перевіряти entitlements і виконувати інші чутливі задачі, такі як дозвіл debugging або отримання task ports.

Крім того, для деяких операцій kext віддає перевагу зверненню до user space daemon `/usr/libexec/amfid`. Цією trust relationship зловживали в кількох jailbreaks.

У новіших версіях macOS AMFI вже не так зручно доступний як окремий on-disk kext, тому reverse engineering зазвичай означає роботу з **kernelcache** або **KDK** замість перегляду `/System/Library/Extensions`.

AMFI використовує політики **MACF** і реєструє свої hooks у момент запуску. Також запобігання його завантаженню або його unloading може спричинити kernel panic. Однак є деякі boot arguments, які дозволяють послабити AMFI:

- `amfi_unrestricted_task_for_pid`: Дозволяє `task_for_pid` без потрібних entitlements
- `amfi_allow_any_signature`: Дозволяє будь-який code signature
- `cs_enforcement_disable`: Системний аргумент, що вимикає enforcement code signing
- `amfi_prevent_old_entitled_platform_binaries`: Знецінює platform binaries з entitlements
- `amfi_get_out_of_my_way`: Повністю вимикає amfi

Ось деякі з політик MACF, які він реєструє:

- **`cred_check_label_update_execve:`** Оновлення label буде виконано і поверне 1
- **`cred_label_associate`**: Оновлює слот mac label в AMFI значенням label
- **`cred_label_destroy`**: Видаляє слот mac label в AMFI
- **`cred_label_init`**: Встановлює 0 у слот mac label в AMFI
- **`cred_label_update_execve`:** Перевіряє entitlements процесу, щоб визначити, чи дозволено йому змінювати labels.
- **`file_check_mmap`:** Перевіряє, чи `mmap` отримує memory і позначає її як executable. У такому разі перевіряє, чи потрібна library validation, і якщо так, викликає функцію library validation.
- **`file_check_library_validation`**: Викликає функцію library validation, яка серед іншого перевіряє, чи platform binary завантажує інший platform binary, або чи процес і новий завантажений файл мають однаковий TeamID. Деякі entitlements також дозволяють завантажувати будь-яку library.
- **`policy_initbsd`**: Налаштовує довірені NVRAM Keys
- **`policy_syscall`**: Перевіряє політики DYLD, наприклад, чи binary має unrestricted segments, чи слід дозволити env vars... це також викликається, коли процес запускається через `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Перевіряє, чи коли процес виконує новий binary, інші процеси з SEND правами на task port цього процесу повинні зберегти їх чи ні. Platform binaries дозволені, `get-task-allow` entitle дозволяє це, `task_for_pid-allow` entitle дозволяє це, і binaries з тим самим TeamID.
- **`proc_check_expose_task`**: enforce entitlements
- **`amfi_exc_action_check_exception_send`**: Exception message надсилається debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Життєвий цикл label під час обробки exception (debugging)
- **`proc_check_get_task`**: Перевіряє entitlements на кшталт `get-task-allow`, який дозволяє іншим процесам отримувати task port, і `task_for_pid-allow`, який дозволяє процесу отримувати task ports інших процесів. Якщо жодного з них немає, звертається до `amfid permitunrestricteddebugging`, щоб перевірити, чи це дозволено.
- **`proc_check_mprotect`**: Відмовляє, якщо `mprotect` викликається з прапорцем `VM_PROT_TRUSTED`, що означає, що область має розглядатися так, ніби вона має valid code signature.
- **`vnode_check_exec`**: Викликається, коли executable файли завантажуються в memory, і встановлює `cs_hard | cs_kill`, що вб’є процес, якщо будь-яка зі сторінок стане недійсною
- **`vnode_check_getextattr`**: MacOS: Перевіряє `com.apple.root.installed` і `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Як get + `com.apple.private.allow-bless` і internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Код, який викликає XNU для перевірки code signature за допомогою entitlements, trust cache і `amfid`
- **`proc_check_run_cs_invalid`**: Перехоплює виклики `ptrace()` (`PT_ATTACH` і `PT_TRACE_ME`). Перевіряє наявність entitlements `get-task-allow`, `run-invalid-allow` і `run-unsigned-code`, і якщо жодного немає, перевіряє, чи дозволено debugging.
- **`proc_check_map_anon`**: Якщо `mmap` викликається з прапорцем **`MAP_JIT`**, AMFI перевіряє entitlement `dynamic-codesigning`.

`AMFI.kext` також надає API для інших kernel extensions, і знайти його dependencies можна за допомогою:
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
Щоб `AMFI.kext` міг взаємодіяти з daemon, він використовує mach messages через port `HOST_AMFID_PORT`, який є special port `18`.

Зверніть увагу, що в macOS більше неможливо для root processes hijack special ports, оскільки вони захищені `SIP`, і лише launchd може отримати їх. В iOS перевіряється, що process, який надсилає response назад, має CDHash, hardcoded для `amfid`.

Можна побачити, коли `amfid` запитується на перевірку binary і його response, відлагоджуючи його та встановивши breakpoint у `mach_msg`.

Після того як message отримано через special port, **MIG** використовується для надсилання кожної function до function, яку він викликає. Основні functions були reversed і пояснені всередині книги.

### DYLD policy and library validation

Починаючи з recent `dyld` versions, `amfi_check_dyld_policy_self()` викликається дуже рано з `configureProcessRestrictions()`, щоб запитати AMFI, чи може process використовувати `DYLD_*` path variables, interposing, fallback paths, embedded variables або tolerate failed library insertion. Тому під час triaging injection surface недостатньо перевірити лише Mach-O load commands: також потрібно перевірити entitlements і runtime flags, які AMFI транслюватиме в `dyld` policy.

Практичний triage loop такий:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
На сучасному macOS багато Apple binary більше не мають `com.apple.security.cs.disable-library-validation` напряму, а натомість постачаються з `com.apple.private.security.clear-library-validation`. У такому випадку library validation не вимикається під час `execve`: процес має викликати `csops(..., CS_OPS_CLEAR_LV, ...)` для самого себе, і XNU дозволяє цю операцію лише для calling process, коли entitlement присутній. З offensive perspective це важливо, бо target може стати injectable лише **після** того, як він дійде до code path, що явно очищає LV (наприклад, незадовго до завантаження optional plugins).

## Provisioning Profiles

A provisioning profile can be used to sign code. There are **Developer** profiles that can be used to sign code and test it, and **Enterprise** profiles which can be used in all devices.

After an App is submitted to the Apple Store, if approved, it's signed by Apple and the provisioning profile is no longer needed.

A profile usually use the extension `.mobileprovision` or `.provisionprofile` and can be dumped with:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Хоча інколи їх називають certificated, ці provisioning profiles містять більше, ніж certificate:

- **AppIDName:** Ідентифікатор застосунку
- **AppleInternalProfile**: Позначає це як Apple Internal profile
- **ApplicationIdentifierPrefix**: Додається перед AppIDName (те саме, що TeamIdentifier)
- **CreationDate**: Дата у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Масив (зазвичай один) certificate(ів), закодованих як Base64 data
- **Entitlements**: entitlements, дозволені для цього profile
- **ExpirationDate**: Дата закінчення дії у форматі `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Application Name, те саме, що AppIDName
- **ProvisionedDevices**: Масив (для developer certificates) UDID, для яких цей profile є дійсним
- **ProvisionsAllDevices**: Boolean (true для enterprise certificates)
- **TeamIdentifier**: Масив (зазвичай один) алфавітно-цифрових string(ів), що використовуються для ідентифікації developer для міжаплікаційної взаємодії
- **TeamName**: Людинозрозуміла назва, що використовується для ідентифікації developer
- **TimeToLive**: Термін дії (у днях) certificate
- **UUID**: Universally Unique Identifier для цього profile
- **Version**: Наразі встановлено на 1

Зверніть увагу, що запис entitlements міститиме обмежений набір entitlements, і provisioning profile зможе надавати лише ці конкретні entitlements, щоб не давати Apple private entitlements.

Зверніть увагу, що profiles зазвичай розташовані в `/var/MobileDeviceProvisioningProfiles`, і їх можна перевірити за допомогою **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Це зовнішня library, яку викликає `amfid`, щоб запитати, чи слід щось дозволити чи ні. Історично це зловживалося в jailbreaking шляхом запуску backdoored версії, яка дозволяла все.

У macOS це знаходиться всередині `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches — це не лише концепція iOS. На сучасному macOS, особливо на **Apple silicon**, static trust cache і loadable trust caches є частиною Secure Boot chain. Коли **CodeDirectory hash** Mach-O присутній там, AMFI може надати йому **platform privilege** без додаткових перевірок authenticity під час launch time. Це також означає, що Apple може прив’язати platform binaries до конкретної версії OS і запобігти replay старіших Apple-signed binaries на новіших системах.

У recent macOS releases metadata trust-cache також пов’язана з **launch constraints**, тому copied system apps і binaries, запущені з неправильного parent/location, можуть бути відхилені AMFI, навіть якщо вони все ще Apple-signed. Детальний workflow extraction і reversing описано в:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

В iOS і jailbreak research ви й далі знайдете традиційну модель **loadable trust caches**, що використовується для whitelist ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
