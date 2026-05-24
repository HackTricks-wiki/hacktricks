# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** розшифровується як **Mandatory Access Control Framework**, це система безпеки, вбудована в операційну систему, щоб допомагати захищати ваш комп'ютер. Вона працює, встановлюючи **жорсткі правила про те, хто або що може отримувати доступ до певних частин системи**, таких як файли, застосунки та системні ресурси. Автоматично застосовуючи ці правила, MACF гарантує, що лише авторизовані користувачі та процеси можуть виконувати певні дії, зменшуючи ризик несанкціонованого доступу або шкідливої активності.

Зверніть увагу, що MACF насправді не приймає жодних рішень, оскільки вона лише **перехоплює** дії; рішення залишаються за **policy modules** (kernel extensions), які вона викликає, як-от `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` і `mcxalr.kext`.

- Policy може бути enforcing (повертати 0 non-zero для деяких операцій)
- Policy може бути monitoring (повертати 0, щоб не заперечувати, але piggyback на hook для виконання чогось)
- MACF static policy встановлюється під час boot і НІКОЛИ не буде видалена
- MACF dynamic policy встановлюється KEXT (kextload) і теоретично може бути kextunloaded
- В iOS дозволені лише static policies, а в macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process виконує syscall/mach trap
2. Відповідна function викликається всередині kernel
3. Function викликає MACF
4. MACF перевіряє policy modules, які попросили hook цю function у своїй policy
5. MACF викликає відповідні policies
6. Policies вказують, чи дозволяють вони, чи забороняють дію

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Зазвичай functions, що перевіряють permissions за допомогою MACF, викликатимуть macro `MAC_CHECK`. Як у випадку syscall для створення socket, який викличе function `mac_socket_check_create`, що викликає `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Крім того, macro `MAC_CHECK` визначено в security/mac_internal.h як:
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Зауважте, що перетворивши `check` на `socket_check_create` і `args...` у `(cred, domain, type, protocol)`, ви отримаєте:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Розгортання helper macros показує конкретний control flow:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
Іншими словами, `MAC_CHECK(socket_check_create, ...)` спочатку проходить static policies, умовно блокує та ітерує dynamic policies, емiтить DTrace probes навколо кожного hook і зводить код повернення кожного hook в один результат `error` через `mac_error_select()`.


### Labels

MACF uses **labels** that then the policies checking if they should grant some access or not will use. Код оголошення struct labels можна [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), which is then used inside the **`struct ucred`** in [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) in the **`cr_label`** part. The label contains flags and s number of **slots** that can be used by **MACF policies to allocate pointers**. For example Sanbox will point to the container profile

## MACF Policies

A MACF Policy defined **rule and conditions to be applied in certain kernel operations**.

A kernel extension could configure a `mac_policy_conf` struct and then register it calling `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
Легко ідентифікувати kernel extensions, які конфігурують ці політики, перевіряючи виклики до `mac_policy_register`. Крім того, перевіряючи disassemble extension, також можна знайти використану структуру `mac_policy_conf`.

Зауважте, що MACF policies можуть реєструватися й скасовуватися також **динамічно**.

Одне з основних полів `mac_policy_conf` — це **`mpc_ops`**. Це поле визначає, які opreations policy цікавлять. Зауважте, що їх сотні, тож можна занулити всі, а потім вибрати лише ті, які policy цікавлять. З [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Майже всі hooks будуть викликані MACF, коли одна з цих операцій перехоплюється. Однак **`mpo_policy_*`** hooks є винятком, тому що **`mpo_hook_policy_init()`** — це callback, який викликається під час реєстрації (тобто після **`mac_policy_register()`**), а **`mpo_hook_policy_initbsd()`** викликається під час пізньої реєстрації, коли BSD subsystem вже належним чином ініціалізовано.

Крім того, hook **`mpo_policy_syscall`** може бути зареєстрований будь-яким kext, щоб надати приватний **ioctl** style call **interface**. Тоді user client зможе викликати **`mac_syscall`** (#381), вказуючи як параметри **policy name** з integer **code** та необов’язковими **arguments**.\
Наприклад, **`Sandbox.kext`** активно використовує це.

Перевірка **`__DATA.__const*`** kext дає змогу визначити структуру `mac_policy_ops`, яка використовується під час реєстрації policy. Це можна знайти, оскільки її pointer знаходиться за зміщенням усередині `mpo_policy_conf`, а також через кількість NULL pointers, які будуть у цій області.

Крім того, також можна отримати список kexts, які налаштували policy, вивантаживши з memory структуру **`_mac_policy_list`**, яка оновлюється щоразу, коли реєструється policy.

Також можна використати tool `xnoop`, щоб вивантажити всі policies, зареєстровані в system:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
А потім виведіть усі перевірки з check policy за допомогою:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## MACF initialization in XNU

### Early bootstrap and `mac_policy_init()`

- MACF ініціалізується дуже рано. У `bootstrap_thread` (у startup code XNU), після `ipc_bootstrap`, XNU викликає `mac_policy_init()` (у `mac_base.c`).
- `mac_policy_init()` ініціалізує глобальний `mac_policy_list` (масив або список слотів policy) і налаштовує інфраструктуру для MAC (Mandatory Access Control) всередині XNU.
- Пізніше викликається `mac_policy_initmach()`, яка обробляє kernel side реєстрації policy для вбудованих або bundled policy.

### `mac_policy_initmach()` and loading “security extensions”

- `mac_policy_initmach()` перевіряє kernel extensions (kexts), які preloaded (або в списку “policy injection”), і аналізує їх Info.plist на наявність ключа `AppleSecurityExtension`.
- Kexts, які оголошують `<key>AppleSecurityExtension</key>` (або `true`) у своєму Info.plist, вважаються “security extensions” — тобто такими, що реалізують MAC policy або підключаються до MACF infrastructure.
- Приклади Apple kexts із цим ключем включають **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, серед інших (як ти вже перелічив).
- Kernel переконується, що ці kexts завантажуються early, а потім викликає їх registration routines (через `mac_policy_register`) під час boot, вставляючи їх у `mac_policy_list`.

- Кожен policy module (kext) надає структуру `mac_policy_conf`, з hooks (`mpc_ops`) для різних MAC operations (vnode checks, exec checks, label updates, etc.).
- Load time flags можуть включати `MPC_LOADTIME_FLAG_NOTLATE`, що означає “must be loaded early” (тобто пізні спроби registration відхиляються).
- Після реєстрації кожен module отримує handle і займає слот у `mac_policy_list`.
- Коли MAC hook викликається пізніше (наприклад, vnode access, exec, etc.), MACF ітерує всі зареєстровані policies, щоб ухвалити спільне рішення.

- Зокрема, **AMFI** (Apple Mobile File Integrity) — це така security extension. Його Info.plist містить `AppleSecurityExtension`, що позначає його як security policy.
- У межах kernel boot логіка завантаження kernel забезпечує, що “security policy” (AMFI, etc.) уже активна до того, як на неї починають спиратися багато subsystems. Наприклад, kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

Під час написання kext, який використовує MAC framework (тобто викликає `mac_policy_register()` тощо), ви повинні оголосити залежності від KPI (Kernel Programming Interfaces), щоб kext linker (kxld) міг розв’язати ці символи. Тому, щоб оголосити, що `kext` залежить від MACF, потрібно вказати це в `Info.plist` з `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), тоді kext буде посилатися на символи на кшталт `mac_policy_register`, `mac_policy_unregister` і вказівники функцій MAC hook. Щоб розв’язати їх, ви повинні вказати `com.apple.kpi.dsep` як залежність.

Приклад фрагмента Info.plist (всередині вашого .kext):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## MACF у сучасних випусках macOS

У сучасній macOS політики безпеки Apple зазвичай краще розглядати не як окремі вільні `.kext` bundles. Починаючи з **macOS 11**, kernel extensions пов’язуються в **kernel collections**; на **Apple Silicon** немає окремого **SystemKC**, а сторонні kext стають завантажуваними лише після включення в **Auxiliary Kernel Collection (AuxKC)** і перезавантаження. Для дослідження MACF це означає, що вбудовані політики, такі як **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** або **Quarantine**, зазвичай простіше перелічити за допомогою `kmutil`, ніж із застарілими інструментами на кшталт `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> On Apple Silicon, if a security kext is not in the BootKC, check the AuxKC next. This is usually more useful than hunting for a standalone bundle under `/System/Library/Extensions`.

## MACF Callouts

It's common to find callouts to MACF defined in code like: **`#if CONFIG_MAC`** conditional blocks. Moreover, inside these blocks it's possible to find calls to `mac_proc_check*` which calls MACF to **check for permissions** to perform certain actions. Moreover, the format of the MACF callouts is: **`mac_<object>_<opType>_opName`**.

The object is one of the following: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
The `opType` is usually check which will be used to allow or deny the action. However, it's also possible to find `notify`, which will allow the kext to react to the given action.

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Then, it's possible to find the code of `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Який викликає макрос `MAC_CHECK`, код якого можна знайти в [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Який пройде по всіх зареєстрованих MAC політиках, викликаючи їхні функції та зберігаючи результат у змінній error, яку можна буде перевизначити лише `mac_error_select` через success-коди, тож якщо будь-яка перевірка не пройде, повна перевірка також не пройде і дію не буде дозволено.

> [!TIP]
> Однак пам’ятайте, що не всі MACF callouts використовуються лише для заборони дій. Наприклад, `mac_priv_grant` викликає macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), яке надасть запитуваний privilege, якщо будь-яка policy відповість 0:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Ці callas призначені для перевірки та надання (десятків) **privileges**, визначених у [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Деякий kernel code викликав би `priv_check_cred()` з [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) з KAuth credentials процесу та одним із codes privilege, що викличе `mac_priv_check`, щоб перевірити, чи будь-яка policy **забороняє** надання privilege, а потім викликає `mac_priv_grant`, щоб перевірити, чи будь-яка policy надає `privilege`.

### proc_check_syscall_unix

Цей hook дозволяє перехоплювати всі system calls. У `bsd/dev/[i386|arm]/systemcalls.c` можна побачити оголошену function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), яка містить цей code:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Який перевірятиме в процесі, що викликає, **bitmask**, чи повинен поточний syscall викликати `mac_proc_check_syscall_unix`. Це тому, що syscalls викликаються дуже часто, тож цікаво уникати виклику `mac_proc_check_syscall_unix` щоразу.

Зауважте, що функція `proc_set_syscall_filter_mask()`, яка встановлює bitmask syscalls у процесі, викликається Sandbox, щоб задавати masks для процесів у sandbox.

## Exposed MACF syscalls

Можна взаємодіяти з MACF через деякі syscalls, визначені в [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
Для offensive reversing, **`__mac_syscall`** досі є одним із найкращих userland chokepoints. Він містить **policy name** (наприклад `"Sandbox"` або `"AMFI"`), **policy-specific selector/code** і вказівник на **opaque argument blob**, який буде оброблено `mpo_policy_syscall`. Це дуже корисно під час reversing undocumented operations спочатку з userland і лише пізніше при переході до kernel implementation. Sandbox зазвичай досягає його через `__sandbox_ms`, а AMFI використовує той самий механізм для dyld policy decisions.

## Practical offensive research notes

Останні macOS bugs рідко прямо "break MACF". Натомість вони зазвичай зловживають **desynchronisation між рішенням MACF / Sandbox / TCC і privileged action, яке відбувається пізніше**.

### Broker path checks vs real privileged action

Повторюваний pattern — це privileged daemon, який виконує **userland pre-check** (наприклад `sandbox_check_by_audit_token()`) на одній версії path, а потім виконує real privileged sink з **іншим або non-canonical attacker-controlled path**. Останні дослідження `diskarbitrationd` / `storagekitd` — хороший приклад: **directory traversal** плюс **symlink swaps** дозволяють attacker пройти sandbox validation демона, а потім змонтувати поверх sensitive locations, таких як `~/Library/Application Support/com.apple.TCC`, перетворюючи bug на **sandbox escape**, **local privilege escalation** або **TCC bypass** залежно від вибраного mount point.

Під час auditing root brokers, reachable from the sandbox, спочатку шукайте:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers для path canonicalisation
- privileged sinks, такі як `mount`, `rename`, `copyfile`, helper-tool XPC methods, або будь-що, що пізніше торкається attacker-controlled paths як root

### Trusted deputies with private entitlements

Ще один practical pattern — уникати direct attack на MACF hooks і натомість зловживати **trusted process**, який уже має права, потрібні для перетину boundary. Останні дослідження Safari/TCC — хороший приклад: цікава primitive була не "disable TCC in the kernel", а зміна local policy/configuration так, щоб Apple-signed process з **`com.apple.private.tcc.allow`** виконав sensitive action від вашого імені. На практиці high-value auditing targets — це Apple daemons/apps, які поєднують:

- **private entitlements** або FDA-like reach
- writable config / database / mount point / policy file
- пізнішу sensitive operation, mediated by **Sandbox**, **AMFI**, **TCC** або іншою MACF policy

Для глибшого product-specific reversing дивіться dedicated pages на [macOS Sandbox](macos-sandbox/README.md) і [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
