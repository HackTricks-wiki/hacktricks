# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

**MACF** означає **Фреймворк обов'язкового контролю доступу**, який є системою безпеки, вбудованою в операційну систему для захисту вашого комп'ютера. Він працює шляхом встановлення **строгих правил щодо того, хто або що може отримувати доступ до певних частин системи**, таких як файли, додатки та системні ресурси. Автоматично застосовуючи ці правила, MACF забезпечує, що тільки авторизовані користувачі та процеси можуть виконувати конкретні дії, зменшуючи ризик несанкціонованого доступу або зловмисних дій.

Зауважте, що MACF сам по собі не приймає рішень — він лише **перехоплює** дії та передає рішення **модулям політик** (kernel extensions), яким він викликає, наприклад `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` та `mcxalr.kext`.

- Політика може бути примусовою (повертати 0 або ненульове значення при певній операції)
- Політика може бути моніторинговою (повертати 0, тобто не заперечувати, але використати hook для виконання чогось)
- Статична політика MACF встановлюється під час завантаження і НІКОЛИ не буде видалена
- Динамічна політика MACF встановлюється через KEXT (kextload) і теоретично може бути kextunloaded
- В iOS дозволені тільки статичні політики, а в macOS — статичні + динамічні.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Послідовність

1. Процес виконує syscall/mach trap
2. Відповідна функція викликається всередині ядра
3. Функція викликає MACF
4. MACF перевіряє модулі політик, які попросили зробити hook цієї функції у своїй політиці
5. MACF викликає відповідні політики
6. Політики вказують, чи дозволяють вони чи забороняють цю дію

> [!CAUTION]
> Apple — єдина компанія, яка може використовувати MAC Framework KPI.

Зазвичай функції, які перевіряють дозволи через MACF, викликають макрос `MAC_CHECK`. Наприклад, у випадку syscall для створення сокета викликається функція `mac_socket_check_create`, яка викликає `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Крім того, макрос `MAC_CHECK` визначений у security/mac_internal.h як:
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
Зверніть увагу, що, перетворивши `check` у `socket_check_create`, а `args...` — у `(cred, domain, type, protocol)`, ви отримаєте:
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
Іншими словами, `MAC_CHECK(socket_check_create, ...)` спочатку обходить статичні політики, умовно блокує й перебирає динамічні політики, виводить DTrace probes навколо кожного hook і зводить коди повернення кожного hook'а в єдиний результат `error` через `mac_error_select()`.


### Labels

MACF використовує **labels**, які політики потім використовують для перевірки, чи слід надати доступ. Оголошення структури labels можна [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), яке потім використовується всередині **`struct ucred`** в [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) у частині **`cr_label`**. Label містить прапорці та певну кількість **slots**, які можуть бути використані **MACF policies to allocate pointers**. Наприклад Sanbox вказуватиме на container profile

## MACF Policies

MACF Policy визначає **правила та умови, які застосовуються до певних операцій ядра**.

Розширення ядра може налаштувати структуру `mac_policy_conf` і потім зареєструвати її, викликаючи `mac_policy_register`. З [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Легко ідентифікувати розширення ядра, які конфігурують ці політики, перевіряючи виклики `mac_policy_register`. Більше того, аналізуючи дизасемблювання розширення, також можливо знайти використовувану структуру `mac_policy_conf`.

Зверніть увагу, що політики MACF можуть реєструватися та зніматися також **динамічно**.

Одне з основних полів `mac_policy_conf` — **`mpc_ops`**. Це поле вказує, якими операціями політика зацікавлена. Зауважте, їх сотні, тож можна обнулити всі і потім вибрати лише ті, які цікавлять політику. З [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Практично всі hooks будуть викликані MACF, коли одна з цих операцій буде перехоплена. Проте **`mpo_policy_*`** hooks є винятком, оскільки `mpo_hook_policy_init()` — це callback, який викликається під час реєстрації (тобто після `mac_policy_register()`), а `mpo_hook_policy_initbsd()` викликається під час пізньої реєстрації, коли підсистема BSD правильно ініціалізована.

Більше того, **`mpo_policy_syscall`** hook може бути зареєстрований будь-яким kext для експонування приватного **ioctl** style call **interface**. Тоді user client зможе викликати `mac_syscall` (#381), вказавши як параметри **policy name** з цілим **code** та необов'язковими **arguments**.\
Наприклад, **`Sandbox.kext`** часто це використовує.

Перевірка **`__DATA.__const*`** kext'а дозволяє ідентифікувати структуру `mac_policy_ops`, яка використовувалася під час реєстрації політики. Її можна знайти, оскільки її вказівник знаходиться на офсеті всередині `mpo_policy_conf`, а також через кількість NULL вказівників, які будуть у тій ділянці.

Крім того, також можна отримати список kexts, що налаштували політику, дампуючи з пам'яті структуру **`_mac_policy_list`**, яка оновлюється при реєстрації кожної політики.

Ви також можете використати інструмент `xnoop` щоб дампнути всі політики, зареєстровані в системі:
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
А потім виведіть усі перевірки check policy за допомогою:
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

### Ранній bootstrap та mac_policy_init()

- MACF ініціалізується дуже рано. У `bootstrap_thread` (в стартовому коді XNU), після `ipc_bootstrap`, XNU викликає `mac_policy_init()` (в `mac_base.c`).
- `mac_policy_init()` ініціалізує глобальний `mac_policy_list` (масив або список слотів політик) і налаштовує інфраструктуру для MAC (Mandatory Access Control) в XNU.
- Пізніше викликається `mac_policy_initmach()`, який обробляє частину реєстрації політик на боці ядра для вбудованих або пакетних політик.

### `mac_policy_initmach()` та завантаження “security extensions”

- `mac_policy_initmach()` перевіряє kernel extensions (kexts), які попередньо завантажені (або знаходяться в “policy injection” списку), і інспектує їх Info.plist на наявність ключа `AppleSecurityExtension`.
- Kexts, що оголошують `<key>AppleSecurityExtension</key>` (або `true`) в Info.plist, вважаються “security extensions” — тобто такими, що реалізують MAC policy або підключаються до інфраструктури MACF.
- Прикладами Apple kexts з цим ключем є **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, серед інших (як ви вже перераховували).
- Ядро гарантує, що ці kexts завантажуються рано, потім під час завантаження викликає їхні процедури реєстрації (через `mac_policy_register`), вставляючи їх у `mac_policy_list`.

- Кожен модуль політики (kext) надає структуру `mac_policy_conf` з хуками (`mpc_ops`) для різних MAC-операцій (перевірки vnode, перевірки exec, оновлення міток тощо).
- Прапори часу завантаження можуть включати `MPC_LOADTIME_FLAG_NOTLATE`, що означає «повинні бути завантажені рано» (тому спроби пізньої реєстрації відхиляються).
- Після реєстрації кожен модуль отримує дескриптор і займає слот у `mac_policy_list`.
- Коли пізніше виконується MAC-hook (наприклад, доступ до vnode, exec тощо), MACF ітерує всі зареєстровані політики, щоб прийняти колективне рішення.

- Зокрема, **AMFI** (Apple Mobile File Integrity) є такою security extension. У його Info.plist міститься `AppleSecurityExtension`, що маркує його як security policy.
- В рамках завантаження ядра логіка завантаження гарантує, що «security policy» (AMFI тощо) уже активна до того, як багато підсистем будуть від неї залежати. Наприклад, ядро «приготується до майбутніх завдань, завантаживши … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.»
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
## Залежність KPI & com.apple.kpi.dsep у MAC policy kexts

Під час написання kext, який використовує MAC framework (тобто викликає `mac_policy_register()` тощо), ви повинні оголосити залежності від KPIs (Kernel Programming Interfaces), щоб лінкер kext (kxld) міг розв’язати ці символи. Тому, щоб вказати, що ваш `kext` залежить від MACF, потрібно зазначити це в `Info.plist` за допомогою `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); тоді kext буде посилатися на символи на кшталт `mac_policy_register`, `mac_policy_unregister` та вказівники функцій MAC hook. Щоб розв’язати їх, потрібно додати `com.apple.kpi.dsep` у список залежностей.

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
## Виклики MACF

Зазвичай у коді можна знайти виклики MACF, визначені в умовних блоках, таких як: **`#if CONFIG_MAC`**. Крім того, всередині цих блоків можна знайти виклики `mac_proc_check*`, які звертаються до MACF для **перевірки дозволів** на виконання певних дій. Формат викликів MACF виглядає так: **`mac_<object>_<opType>_opName`**.

Об'єкт може бути одним із наступних: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` зазвичай — це check, який використовується для дозволу або заборони дії. Однак також можна знайти `notify`, який дозволяє kext реагувати на відповідну дію.

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

Далі можна знайти код `mac_file_check_mmap` у [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Який викликає макрос `MAC_CHECK`, код якого можна знайти за адресою [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Який пройде по всіх зареєстрованих mac політиках, викликаючи їхні функції та зберігаючи результат у змінній error, яку можна буде перезаписати лише через `mac_error_select` за успішними кодами — тому якщо будь-яка перевірка зазнає невдачі, вся перевірка провалиться і дія не буде дозволена.

> [!TIP]
> Проте пам'ятайте, що не всі виклики MACF використовуються лише для відмови в діях. Наприклад, `mac_priv_grant` викликає макрос [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), який надасть запитаний привілей, якщо хоча б одна політика відповість 0:
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

These callas are meant to check and provide (tens of) **privileges** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Деякий код ядра викликає `priv_check_cred()` з [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) з KAuth-креденціалами процесу та одним із кодів привілеїв; цей виклик звертається до `mac_priv_check`, щоб перевірити, чи якась політика **відмовляє** у наданні привілею, а потім викликає `mac_priv_grant`, щоб перевірити, чи якась політика надає цей `privilege`.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
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
Який перевіряє у викликаючого процесу **bitmask**, чи має поточний syscall викликати `mac_proc_check_syscall_unix`. Це тому, що syscalls викликаються дуже часто, тож цікаво уникати виклику `mac_proc_check_syscall_unix` щоразу.

Зауважте, що функція `proc_set_syscall_filter_mask()`, яка встановлює bitmask syscalls у процесі, викликається Sandbox для встановлення масок на sandboxed процесах.

## Доступні MACF syscalls

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
## Посилання

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
