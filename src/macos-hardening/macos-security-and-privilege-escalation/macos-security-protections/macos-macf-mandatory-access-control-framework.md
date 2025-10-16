# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**MACF** oznacza **Mandatory Access Control Framework**, czyli system bezpieczeństwa wbudowany w system operacyjny, mający na celu ochronę Twojego komputera. Działa poprzez ustalanie **ścisłych reguł dotyczących tego, kto lub co może uzyskać dostęp do określonych części systemu**, takich jak pliki, aplikacje i zasoby systemowe. Poprzez automatyczne egzekwowanie tych reguł, MACF zapewnia, że tylko uprawnieni użytkownicy i procesy mogą wykonywać określone działania, zmniejszając ryzyko nieautoryzowanego dostępu lub złośliwych działań.

Należy pamiętać, że MACF samo w sobie nie podejmuje decyzji — jedynie **przechwytuje** działania i pozostawia decyzje modułom polityki (rozszerzeniom jądra), które wywołuje, takim jak `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Polityka może być egzekwująca (return 0 non-zero on some operation)
- Polityka może jedynie monitorować (return 0, so as not to object but piggyback on hook to do something)
- Statyczna polityka MACF jest instalowana przy starcie i NIGDY nie zostanie usunięta
- Dynamiczna polityka MACF jest instalowana przez KEXT (kextload) i hipotetycznie może zostać kextunloaded
- W iOS dozwolone są tylko polityki statyczne, a w macOS — zarówno statyczne, jak i dynamiczne.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Przepływ

1. Proces wykonuje syscall/mach trap
2. Odpowiednia funkcja jest wywoływana w jądrze
3. Funkcja wywołuje MACF
4. MACF sprawdza moduły polityki, które zażądały hook tej funkcji w swojej polityce
5. MACF wywołuje odpowiednie polityki
6. Polityki wskazują, czy pozwalają, czy odrzucają daną akcję

> [!CAUTION]
> Apple jest jedyną firmą, która może używać MAC Framework KPI.

Zazwyczaj funkcje sprawdzające uprawnienia przy użyciu MACF wywołują makro `MAC_CHECK`. Na przykład w przypadku syscall tworzącego socket zostanie wywołana funkcja `mac_socket_check_create`, która wywołuje `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Ponadto makro `MAC_CHECK` jest zdefiniowane w security/mac_internal.h jako:
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
Zauważ, że przekształcając `check` w `socket_check_create` i `args...` w `(cred, domain, type, protocol)` otrzymujesz:
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
Rozwinięcie makr pomocniczych pokazuje konkretny przepływ sterowania:
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
Innymi słowy, `MAC_CHECK(socket_check_create, ...)` najpierw przechodzi przez polityki statyczne, warunkowo blokuje i iteruje przez polityki dynamiczne, emituje sondy DTrace wokół każdego hooka i scala kod zwracany przez każdy hook do pojedynczego wyniku `error` za pomocą `mac_error_select()`.


### Labels

MACF używa **labels**, których polityki wykorzystują do sprawdzania, czy powinny przyznać dostęp, czy nie. Deklarację struktury labels można [znaleźć tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), która jest następnie używana wewnątrz **`struct ucred`** w [**tutaj**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) w części **`cr_label`**. Etykieta zawiera flagi oraz liczbę **slots**, które mogą być użyte przez **MACF policies to allocate pointers**. Na przykład Sanbox będzie wskazywał na profil kontenera

## MACF Policies

Polityka MACF definiuje **zasady i warunki do zastosowania przy określonych operacjach jądra**.

Rozszerzenie jądra może skonfigurować strukturę `mac_policy_conf`, a następnie zarejestrować ją wywołując `mac_policy_register`. Zobacz [tutaj](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Łatwo zidentyfikować rozszerzenia jądra konfigurowujące te polityki, sprawdzając wywołania `mac_policy_register`. Ponadto, analizując disasemblację rozszerzenia, można również znaleźć używaną strukturę `mac_policy_conf`.

Zwróć uwagę, że polityki MACF mogą być rejestrowane i wyrejestrowywane również **dynamicznie**.

Jedno z głównych pól struktury `mac_policy_conf` to **`mpc_ops`**. To pole określa, którymi operacjami polityka jest zainteresowana. Zwróć uwagę, że jest ich setki, więc można wyzerować wszystkie, a następnie wybrać tylko te, którymi polityka jest zainteresowana. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Prawie wszystkie hooks będą wywoływane przez MACF, gdy jedna z tych operacji zostanie przechwycona. Jednak **`mpo_policy_*`** hooks są wyjątkiem, ponieważ `mpo_hook_policy_init()` jest callbackiem wywoływanym przy rejestracji (czyli po `mac_policy_register()`), a `mpo_hook_policy_initbsd()` jest wywoływany podczas późnej rejestracji, gdy podsystem BSD poprawnie się zainicjalizuje.

Co więcej, hook **`mpo_policy_syscall`** może być zarejestrowany przez dowolny kext, aby udostępnić prywatny interfejs wywołań w stylu **ioctl**. Wtedy klient użytkownika będzie mógł wywołać `mac_syscall` (#381), podając jako parametry **policy name** z całkowitym **code** i opcjonalnymi **arguments**.\
Na przykład, **`Sandbox.kext`** często z tego korzysta.

Sprawdzenie **`__DATA.__const*`** kexta pozwala zidentyfikować strukturę `mac_policy_ops` używaną podczas rejestracji polityki. Można ją znaleźć, ponieważ jej wskaźnik znajduje się pod pewnym offsetem wewnątrz `mpo_policy_conf` oraz ze względu na liczbę wskaźników NULL, które będą w tym obszarze.

Ponadto możliwe jest również uzyskanie listy kextów, które skonfigurowały politykę, poprzez zrzut pamięci struktury **`_mac_policy_list`**, która jest aktualizowana przy rejestracji każdej polityki.

Możesz też użyć narzędzia `xnoop`, aby zrzucić wszystkie polityki zarejestrowane w systemie:
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
A następnie zrzucić wszystkie kontrole check policy za pomocą:
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
## Inicjalizacja MACF w XNU

### Wczesny bootstrap i mac_policy_init()

- MACF jest inicjalizowany bardzo wcześnie. W `bootstrap_thread` (w kodzie startowym XNU), po `ipc_bootstrap`, XNU wywołuje `mac_policy_init()` (w `mac_base.c`).
- `mac_policy_init()` inicjalizuje globalną listę `mac_policy_list` (tablicę lub listę slotów polityk) i konfiguruje infrastrukturę dla MAC (Mandatory Access Control) w XNU.
- Później wywoływane jest `mac_policy_initmach()`, które obsługuje po stronie jądra rejestrację polityk dla polityk wbudowanych lub dołączonych.

### `mac_policy_initmach()` i ładowanie „security extensions”

- `mac_policy_initmach()` bada kernel extensions (kexts), które są preloaded (lub znajdują się na liście „policy injection”), i sprawdza ich Info.plist pod kątem klucza `AppleSecurityExtension`.
- Kexty, które deklarują `<key>AppleSecurityExtension</key>` (lub `true`) w swoim Info.plist, są uznawane za „security extensions” — tj. takie, które implementują politykę MAC lub podłączają się do infrastruktury MACF.
- Przykłady kextów Apple z tym kluczem to **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** i inne.
- Jądro zapewnia, że te kexty są ładowane wcześnie, a następnie podczas rozruchu wywołuje ich procedury rejestracyjne (przez `mac_policy_register`), wstawiając je do `mac_policy_list`.

- Każdy moduł polityki (kext) dostarcza strukturę `mac_policy_conf`, z hookami (`mpc_ops`) dla różnych operacji MAC (sprawdzania vnode, sprawdzeń exec, aktualizacji etykiet itp.).
- Flagi czasu ładowania mogą zawierać `MPC_LOADTIME_FLAG_NOTLATE`, co oznacza „musi być załadowany wcześnie” (więc próby późnej rejestracji są odrzucane).
- Po zarejestrowaniu każdy moduł otrzymuje uchwyt i zajmuje slot w `mac_policy_list`.
- Gdy później wywoływany jest hook MAC (np. dostęp do vnode, exec itd.), MACF przechodzi przez wszystkie zarejestrowane polityki, aby podjąć decyzję zbiorczą.

- W szczególności **AMFI** (Apple Mobile File Integrity) jest takim „security extension”. Jego Info.plist zawiera `AppleSecurityExtension`, oznaczając go jako politykę bezpieczeństwa.
- W ramach rozruchu jądra logika ładowania zapewnia, że „security policy” (AMFI itp.) jest już aktywna zanim wiele podsystemów będzie od niej zależnych. Na przykład jądro „przygotowuje się do nadchodzących zadań przez załadowanie … polityki bezpieczeństwa, w tym AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Zależność KPI i com.apple.kpi.dsep w kextach polityki MAC

Podczas pisania kexta, który używa frameworku MAC (np. wywołując `mac_policy_register()` itd.), musisz zadeklarować zależności od KPI (Kernel Programming Interfaces), aby linker kextów (kxld) mógł rozwiązać te symbole. Aby zadeklarować, że `kext` zależy od MACF, musisz to wskazać w `Info.plist` za pomocą `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), wtedy kext będzie odwoływał się do symboli takich jak `mac_policy_register`, `mac_policy_unregister` oraz wskaźników funkcji hooków MAC. Aby je rozwiązać, musisz wymienić `com.apple.kpi.dsep` jako zależność.

Przykładowy fragment Info.plist (wewnątrz twojego .kext):
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
## Wywołania MACF

Często można znaleźć odwołania do MACF zdefiniowane w kodzie, takie jak bloki warunkowe **`#if CONFIG_MAC`**. Ponadto wewnątrz tych bloków można znaleźć wywołania `mac_proc_check*`, które wywołują MACF w celu **sprawdzenia uprawnień** do wykonania określonych działań. Ponadto format wywołań MACF to: **`mac_<object>_<opType>_opName`**.

Obiekt może być jednym z następujących: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` to zwykle `check`, które służy do zezwolenia lub odmowy działania. Jednak można też znaleźć `notify`, które pozwala `kext` zareagować na dane działanie.

Przykład znajdziesz w https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621:

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

Następnie można znaleźć kod `mac_file_check_mmap` w https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174
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
Które wywołuje makro `MAC_CHECK`, którego kod można znaleźć w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Który przejdzie przez wszystkie zarejestrowane mac policies, wywołując ich funkcje i zapisując wynik w zmiennej error, którą można nadpisać jedynie przez `mac_error_select` przy kodach sukcesu — więc jeśli jakakolwiek kontrola się nie powiedzie, cała weryfikacja zakończy się niepowodzeniem i akcja nie zostanie dozwolona.

> [!TIP]
> Jednak pamiętaj, że nie wszystkie MACF callouts są używane wyłącznie do odrzucania akcji. Na przykład, `mac_priv_grant` wywołuje makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), które przyzna żądany przywilej, jeśli którakolwiek polityka odpowie 0:
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

These callas are meant to check and provide (tens of) **przywileje** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Some kernel code would call `priv_check_cred()` from [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) with the KAuth credentials of the process and one of the privileges code which will call `mac_priv_check` to see if any policy **odmawia** giving the privilege and then it calls `mac_priv_grant` to see if any policy grants the `privilege`.

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
Które sprawdza w **bitmask** procesu wywołującego, czy bieżący syscall powinien wywołać `mac_proc_check_syscall_unix`. Dzieje się tak, ponieważ syscalls są wywoływane tak często, że warto unikać wywoływania `mac_proc_check_syscall_unix` za każdym razem.

Zauważ, że funkcja `proc_set_syscall_filter_mask()`, która ustawia bitmaskę syscalli w procesie, jest wywoływana przez Sandbox, aby ustawić maski na sandboxed processes.

## Udostępnione MACF syscalls

Można wchodzić w interakcję z MACF przez niektóre syscalls zdefiniowane w [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Bibliografia

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
