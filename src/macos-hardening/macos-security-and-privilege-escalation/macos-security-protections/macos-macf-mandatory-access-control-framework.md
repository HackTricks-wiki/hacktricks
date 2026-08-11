# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

**MACF** розшифровується як **Mandatory Access Control Framework** — вбудована в операційну систему система безпеки, призначена для захисту комп’ютера. Вона працює шляхом встановлення **суворих правил щодо того, хто або що може отримувати доступ до певних частин системи**, зокрема до файлів, застосунків і системних ресурсів. Автоматично застосовуючи ці правила, MACF гарантує, що лише авторизовані користувачі та процеси можуть виконувати певні дії, зменшуючи ризик несанкціонованого доступу або шкідливої активності.

Зверніть увагу, що MACF фактично не приймає жодних рішень, оскільки лише **перехоплює** дії, а рішення залишає за **модулями політик** (розширеннями ядра), які вона викликає, такими як `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` і `mcxalr.kext`.

- Політика може застосовувати обмеження (повертати 0 або ненульове значення під час певної операції)
- Політика може здійснювати моніторинг (повертати 0, щоб не заперечувати, але використовувати hook для виконання певної дії)
- Статична політика MACF встановлюється під час завантаження й НІКОЛИ не видаляється
- Динамічна політика MACF встановлюється KEXT (`kextload`) і теоретично може бути вивантажена за допомогою `kextunload`
- В iOS дозволені лише статичні політики, а в macOS — статичні та динамічні.<sup>[[7]](#references)</sup>

### Потік

1. Процес виконує syscall/mach trap
2. Усередині ядра викликається відповідна функція
3. Функція викликає MACF
4. MACF перевіряє модулі політик, які вказали у своїй політиці, що потрібно встановити hook для цієї функції
5. MACF викликає відповідні політики
6. Політики вказують, чи дозволяють вони дію, чи забороняють її

> [!CAUTION]
> Apple — єдина компанія, яка може використовувати MAC Framework KPI.

Зазвичай функції, що перевіряють дозволи за допомогою MACF, викликають макрос `MAC_CHECK`. Наприклад, у випадку syscall для створення socket буде викликана функція `mac_socket_check_create`, яка викликає `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Крім того, макрос `MAC_CHECK` визначений у файлі security/mac_internal.h як:<sup>[[3]](#references)</sup>
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
Зверніть увагу, що, перетворивши `check` на `socket_check_create`, а `args...` на `(cred, domain, type, protocol)`, ви отримуєте:
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
Розгортання допоміжних макросів показує конкретний потік керування:
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
Іншими словами, `MAC_CHECK(socket_check_create, ...)` спочатку проходить статичні політики, за потреби блокує та перебирає динамічні політики, генерує DTrace probes навколо кожного hook і зводить коди повернення всіх hook до єдиного результату `error` через `mac_error_select()`.


### Labels

MACF використовує **labels**, які потім застосовують політики, що перевіряють, чи слід надавати певний доступ. Код оголошення структури labels можна [знайти тут](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h); потім вона використовується всередині **`struct ucred`** [тут](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), у частині **`cr_label`**. Label містить прапорці та певну кількість **slots**, які можуть використовуватися **політиками MACF для виділення вказівників**. Наприклад, Sandbox вказуватиме на профіль контейнера

## MACF Policies

Політика MACF визначає **правила та умови, які застосовуються під час певних операцій ядра**.

Kernel extension може налаштувати структуру `mac_policy_conf`, а потім зареєструвати її, викликавши `mac_policy_register`. З [цього джерела](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered entry-point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
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
Легко ідентифікувати kernel extensions, які налаштовують ці політики, перевіривши виклики `mac_policy_register`. Крім того, перевіривши дизасемблювання extension, також можна знайти використовувану структуру `mac_policy_conf`.

Зверніть увагу, що політики MACF можна реєструвати та скасовувати також **динамічно**.

Одним із головних полів `mac_policy_conf` є **`mpc_ops`**. Це поле визначає, які операції становлять інтерес для політики. Їх сотні, тому можна обнулити всі записи, а потім вибрати лише ті, які потрібні політиці. Звідси: [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Майже всі hooks будуть викликатися MACF після перехоплення однієї з таких операцій. Однак hooks **`mpo_policy_*`** є винятком, оскільки **`mpo_hook_policy_init()`** — це callback, який викликається під час реєстрації (тобто після **`mac_policy_register()`**), а **`mpo_hook_policy_initbsd()`** викликається під час пізньої реєстрації, після належної ініціалізації підсистеми BSD.

Крім того, hook **`mpo_policy_syscall`** може бути зареєстрований будь-яким kext для надання приватного **ioctl**-подібного **інтерфейсу** викликів. Після цього user client зможе викликати `mac_syscall` (#381), передаючи як параметри **назву policy** з цілим **кодом** і необов'язковими **аргументами**.\
Наприклад, **`Sandbox.kext`** активно це використовує.

Перевірка **`__DATA.__const*`** kext дає змогу ідентифікувати структуру `mac_policy_ops`, яка використовується під час реєстрації policy. Її можна знайти, оскільки її вказівник розташований за певним зміщенням у `mpo_policy_conf`, а також за кількістю NULL-вказівників, які будуть у цій області.

Крім того, можна отримати список kext, які налаштували policy, виконавши дамп структури **`_mac_policy_list`** з пам'яті. Ця структура оновлюється після реєстрації кожної policy.

Також можна скористатися інструментом `xnoop`, щоб вивести всі policy, зареєстровані в системі:
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
А потім виведіть усі перевірки політики за допомогою:
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
## Ініціалізація MACF в XNU

### Раннє завантаження та mac_policy_init()

- MACF ініціалізується дуже рано. У `bootstrap_thread` (у коді запуску XNU), після `ipc_bootstrap`, XNU викликає `mac_policy_init()` (у `mac_base.c`).
- `mac_policy_init()` ініціалізує глобальний `mac_policy_list` (масив або список слотів політик) і налаштовує інфраструктуру для MAC (Mandatory Access Control) у XNU.
- Пізніше викликається `mac_policy_initmach()`, яка обробляє реєстрацію політик на рівні kernel для вбудованих або bundled політик.

### `mac_policy_initmach()` і завантаження “security extensions”

- `mac_policy_initmach()` перевіряє kernel extensions (kexts), які попередньо завантажені (або перебувають у списку “policy injection”), і перевіряє їхній Info.plist на наявність ключа `AppleSecurityExtension`.
- Kexts, які оголошують `<key>AppleSecurityExtension</key>` (або `true`) у своєму Info.plist, вважаються “security extensions” — тобто такими, що реалізують MAC policy або підключаються до інфраструктури MACF.
- Приклади Apple kexts із цим ключем включають **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** та інші, які ви вже перелічили.
- Kernel забезпечує раннє завантаження цих kexts, а потім викликає їхні процедури реєстрації (через `mac_policy_register`) під час boot, додаючи їх до `mac_policy_list`.

- Кожен policy module (kext) надає структуру `mac_policy_conf` з hooks (`mpc_ops`) для різних MAC-операцій (перевірки vnode, перевірки exec, оновлення label тощо).
- Прапорці часу завантаження можуть містити `MPC_LOADTIME_FLAG_NOTLATE`, що означає “must be loaded early” (тому спроби пізньої реєстрації відхиляються).
- Після реєстрації кожен module отримує handle і займає слот у `mac_policy_list`.
- Коли пізніше викликається MAC hook (наприклад, для доступу до vnode, exec тощо), MACF перебирає всі зареєстровані policies, щоб ухвалити колективне рішення.

- Зокрема, **AMFI** (Apple Mobile File Integrity) є такою security extension. Його Info.plist містить `AppleSecurityExtension`, що позначає його як security policy.
- Під час boot kernel load logic забезпечує активацію “security policy” (AMFI тощо) до того, як від неї почнуть залежати багато підсистем. Наприклад, kernel “prepares for tasks ahead by loading … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Залежність від KPI та com.apple.kpi.dsep у MAC policy kexts

Під час написання kext, який використовує MAC framework (тобто викликає `mac_policy_register()` тощо), необхідно оголосити залежності від KPI (Kernel Programming Interfaces), щоб linker kext (kxld) міг розв’язати ці symbols. Тож, щоб оголосити, що `kext` залежить від MACF, потрібно вказати це в `Info.plist` за допомогою `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), після чого kext звертатиметься до таких symbols, як `mac_policy_register`, `mac_policy_unregister` і покажчиків на MAC hook functions. Щоб розв’язати їх, потрібно додати `com.apple.kpi.dsep` як dependency.

Приклад фрагмента Info.plist (усередині вашого .kext):
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

У сучасній macOS до політик безпеки Apple зазвичай не найкраще підходити як до окремих автономних пакетів `.kext`. Починаючи з **macOS 11**, розширення ядра об’єднуються в **kernel collections**; на **Apple Silicon** окремого **SystemKC** немає, а сторонні kext стають доступними для завантаження лише після їх додавання до **Auxiliary Kernel Collection (AuxKC)** і перезавантаження. Для дослідження MACF це означає, що вбудовані політики, такі як **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** або **Quarantine**, зазвичай простіше перелічувати за допомогою `kmutil`, ніж за допомогою застарілих інструментів, таких як `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> На Apple Silicon, якщо security kext відсутній у BootKC, спочатку перевірте AuxKC. Зазвичай це корисніше, ніж шукати standalone bundle у `/System/Library/Extensions`.

## Виклики MACF

Поширено знаходити виклики MACF у коді, наприклад у conditional blocks на кшталт: **`#if CONFIG_MAC`**. Крім того, всередині цих блоків можна знайти виклики `mac_proc_check*`, які звертаються до MACF, щоб **перевірити дозволи** на виконання певних дій. Формат викликів MACF такий: **`mac_<object>_<opType>_opName`**.

Object може мати одне з таких значень: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` зазвичай має значення check, яке використовується для дозволу або заборони дії. Однак також можна зустріти `notify`, що дозволяє kext реагувати на відповідну дію.

Приклад можна знайти тут: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Після цього код `mac_file_check_mmap` можна знайти тут: [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Який викликає макрос `MAC_CHECK`, код якого можна знайти в [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Який проходить через усі зареєстровані політики mac, викликає їхні функції та зберігає результат у змінній `error`. Її можна перевизначити лише за допомогою `mac_error_select` кодами успішного виконання, тому, якщо будь-яка перевірка завершується невдачею, уся перевірка завершується невдало, і дія не буде дозволена.

> [!TIP]
> Однак пам’ятайте, що не всі MACF callouts використовуються лише для заборони дій. Наприклад, `mac_priv_grant` викликає макрос [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), який надає запитаний privilege, якщо будь-яка політика повертає 0:
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

Ці виклики призначені для перевірки та надання десятків **privileges**, визначених у [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Деякий kernel code викликає `priv_check_cred()` з [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), передаючи KAuth credentials процесу та код одного з privileges. Ця функція викликає `mac_priv_check`, щоб перевірити, чи **забороняє** якась політика надання privilege, а потім викликає `mac_priv_grant`, щоб перевірити, чи надає privilege якась політика.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Цей hook дає змогу перехоплювати всі system calls. У `bsd/dev/[i386|arm]/systemcalls.c` можна побачити оголошену функцію [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), яка містить такий код:
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
Який перевіряє **bitmask** у процесі, що викликає його, щоб визначити, чи має поточний syscall викликати `mac_proc_check_syscall_unix`. Це пов’язано з тим, що syscalls викликаються дуже часто, тому доцільно уникати виклику `mac_proc_check_syscall_unix` щоразу.

Зверніть увагу, що функція `proc_set_syscall_filter_mask()`, яка встановлює bitmask syscalls у процесі, викликається Sandbox для встановлення масок у sandboxed processes.

## Відкриті syscalls MACF

Взаємодія з MACF можлива через деякі syscalls, визначені в [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Для offensive reversing **`__mac_syscall`** досі є однією з найкращих chokepoint-точок у userland. Він передає **назву policy** (наприклад, `"Sandbox"` або `"AMFI"`), **селектор/код, специфічний для policy**, і вказівник на **непрозорий blob аргументів**, який обробляється через `mpo_policy_syscall`. Це дуже корисно під час reversing недокументованих операцій спочатку з userland і лише потім переходу до реалізації в kernel. Sandbox зазвичай звертається до нього через `__sandbox_ms`, а AMFI використовує той самий механізм для policy-рішень dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Практичні нотатки offensive research

Нещодавні macOS-баги рідко безпосередньо "ламають MACF". Натомість вони зазвичай використовують **десинхронізацію між рішенням MACF / Sandbox / TCC і привілейованою дією, яка виконується пізніше**.

### Перевірки шляхів broker-а проти реальної привілейованої дії

Поширений патерн полягає в тому, що привілейований daemon виконує **попередню перевірку в userland** (наприклад, `sandbox_check_by_audit_token()`) для однієї версії шляху, а потім виконує реальний privileged sink з **іншим або неканонічним шляхом, контрольованим attacker**. Нещодавні дослідження `diskarbitrationd` / `storagekitd` є хорошим прикладом: **обхід каталогів** разом із **підміною symlink-ів** дає змогу attacker пройти sandbox validation daemon-а, а потім змонтувати файлову систему поверх чутливих розташувань, таких як `~/Library/Application Support/com.apple.TCC`, перетворивши баг на **sandbox escape**, **local privilege escalation** або **TCC bypass** залежно від обраної точки монтування.<sup>[[6]](#references)</sup>

Під час аудиту root broker-ів, доступних із sandbox, спочатку шукайте:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helper-и канонікалізації шляхів
- privileged sink-и, такі як `mount`, `rename`, `copyfile`, XPC-методи helper tool-ів або будь-що, що згодом звертається до шляхів, контрольованих attacker, з правами root

### Trusted deputy з private entitlements

Інший практичний патерн полягає в тому, щоб не атакувати MACF hooks безпосередньо, а натомість зловживати **trusted process**, який уже має права, необхідні для перетину межі. Нещодавні дослідження Safari/TCC є хорошим прикладом: цікавою primitive була не "деактивація TCC у kernel", а зміна локальної policy/configuration, щоб Apple-signed process із **`com.apple.private.tcc.allow`** виконав чутливу дію від вашого імені.<sup>[[8]](#references)</sup> На практиці цінними цілями для аудиту є Apple daemons/apps, які поєднують:

- **private entitlements** або доступ рівня FDA
- writable config / database / mount point / policy file
- подальшу чутливу операцію, яку контролює **Sandbox**, **AMFI**, **TCC** або інша MACF policy

Для глибшого product-specific reversing перегляньте окремі сторінки про [macOS Sandbox](macos-sandbox/README.md) і [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (повний вектор операцій MACF policy)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (макроси `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (коди привілеїв, що використовуються `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Виявлення вразливостей Apple: аудит diskarbitrationd і storagekitd, частина 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — інструмент перехресного посилання XNU](https://newosxbook.com/xxr/index.php)
- [8] [Нова вразливість macOS, "HM Surf", може призвести до несанкціонованого доступу до даних (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
