# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**MACF** oznacza **Mandatory Access Control Framework**, czyli system bezpieczeństwa wbudowany w system operacyjny, który pomaga chronić komputer. Działa on poprzez ustawianie **ścisłych reguł dotyczących tego, kto lub co może uzyskiwać dostęp do określonych części systemu**, takich jak pliki, aplikacje i zasoby systemowe. Egzekwując te reguły automatycznie, MACF zapewnia, że tylko autoryzowani użytkownicy i procesy mogą wykonywać określone działania, zmniejszając ryzyko nieautoryzowanego dostępu lub złośliwych aktywności.

Zwróć uwagę, że MACF tak naprawdę nie podejmuje żadnych decyzji, ponieważ jedynie **przechwytuje** działania; decyzje pozostawia **modułom polityk** (rozszerzeniom jądra), które wywołuje, takim jak `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Polityka może być egzekwująca (zwraca 0 niezerowe przy niektórych operacjach)
- Polityka może monitorować (zwraca 0, aby nie sprzeciwiać się, ale korzystać z hooka, by coś zrobić)
- Statyczna polityka MACF jest instalowana podczas boot i NIGDY nie zostanie usunięta
- Dynamiczna polityka MACF jest instalowana przez KEXT (kextload) i teoretycznie może zostać odładowana przez kextunload
- W iOS dozwolone są tylko statyczne polityki, a w macOS statyczne + dynamiczne.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process wykonuje syscall/mach trap
2. Odpowiednia funkcja jest wywoływana wewnątrz jądra
3. Funkcja wywołuje MACF
4. MACF sprawdza moduły polityk, które zażądały podpięcia się do tej funkcji w swojej polityce
5. MACF wywołuje odpowiednie polityki
6. Polityki wskazują, czy zezwalają na działanie, czy je odrzucają

> [!CAUTION]
> Apple jest jedynym podmiotem, który może używać MAC Framework KPI.

Zwykle funkcje sprawdzające uprawnienia za pomocą MACF będą wywoływać makro `MAC_CHECK`. Jak w przypadku syscall do utworzenia socket, który wywoła funkcję `mac_socket_check_create`, a ta wywoła `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Co więcej, makro `MAC_CHECK` jest zdefiniowane w security/mac_internal.h jako:
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
Zauważ, że przekształcając `check` na `socket_check_create` oraz `args...` na `(cred, domain, type, protocol)` otrzymujesz:
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
Rozwinięcie helper macros pokazuje konkretny przepływ sterowania:
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
Innymi słowy, `MAC_CHECK(socket_check_create, ...)` najpierw przechodzi przez statyczne policies, warunkowo blokuje i iteruje po dynamicznych policies, emituje DTrace probes wokół każdego hooka i sprowadza kod zwrotny każdego hooka do jednego wyniku `error` przez `mac_error_select()`.


### Labels

MACF używa **labels**, które potem policies sprawdzające, czy powinny przyznać jakiś access, czy nie, będą używać. Definicję struktury labels można [znaleźć tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a następnie jest ona używana wewnątrz **`struct ucred`** w [**tym miejscu**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) w części **`cr_label`**. Label zawiera flags i liczbę **slots**, które mogą być użyte przez **MACF policies do alokowania pointers**. Na przykład Sanbox wskaże na container profile

## MACF Policies

MACF Policy definiuje **rule i conditions, które mają być zastosowane w określonych kernel operations**.

Rozszerzenie kernela mogłoby skonfigurować strukturę `mac_policy_conf` i następnie zarejestrować ją, wywołując `mac_policy_register`. Z [tutaj](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Łatwo zidentyfikować rozszerzenia jądra konfigurujące te polityki, sprawdzając wywołania do `mac_policy_register`. Ponadto, analizując disassemble rozszerzenia, można też znaleźć używaną strukturę `mac_policy_conf`.

Zwróć uwagę, że polityki MACF mogą być rejestrowane i wyrejestrowywane także **dynamicznie**.

Jednym z głównych pól `mac_policy_conf` jest **`mpc_ops`**. To pole określa, którymi operacjami polityka jest zainteresowana. Zwróć uwagę, że są ich setki, więc możliwe jest wyzerowanie wszystkich, a następnie wybranie tylko tych, które interesują politykę. Z [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Prawie wszystkie hooki będą wywoływane przez MACF, gdy jedna z tych operacji zostanie przechwycona. Jednak hooki **`mpo_policy_*`** są wyjątkiem, ponieważ **`mpo_hook_policy_init()`** jest wywołaniem zwrotnym uruchamianym podczas rejestracji (czyli po **`mac_policy_register()`**), a **`mpo_hook_policy_initbsd()`** jest wywoływane podczas późnej rejestracji, gdy podsystem BSD został już poprawnie zainicjalizowany.

Ponadto hook **`mpo_policy_syscall`** może być zarejestrowany przez dowolny kext, aby udostępnić prywatny **ioctl**-owy styl wywołania **interface**. Następnie klient użytkownika będzie mógł wywołać **`mac_syscall`** (#381), podając jako parametry **nazwę polityki** z całkowitym **code** oraz opcjonalnymi **arguments**.\
Na przykład **`Sandbox.kext`** bardzo często z tego korzysta.

Sprawdzenie **`__DATA.__const*`** kextu pozwala zidentyfikować strukturę `mac_policy_ops` używaną podczas rejestracji polityki. Można ją znaleźć, ponieważ jej wskaźnik znajduje się na określonym offsecie w **`mpo_policy_conf`**, a także ze względu na liczbę wskaźników NULL, które będą w tym obszarze.

Ponadto można też uzyskać listę kextów, które skonfigurowały politykę, zrzucając z pamięci strukturę **`_mac_policy_list`**, która jest aktualizowana przy każdej zarejestrowanej polityce.

Możesz również użyć narzędzia `xnoop`, aby zrzucić wszystkie polityki zarejestrowane w systemie:
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
I wtedy zrzucić wszystkie kontrole policy z:
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

### Wczesny bootstrap i `mac_policy_init()`

- MACF jest inicjalizowane bardzo wcześnie. W `bootstrap_thread` (w kodzie startowym XNU), po `ipc_bootstrap`, XNU wywołuje `mac_policy_init()` (w `mac_base.c`).
- `mac_policy_init()` inicjalizuje globalne `mac_policy_list` (tablicę lub listę slotów polityk) i ustawia infrastrukturę dla MAC (Mandatory Access Control) w XNU.
- Później wywoływane jest `mac_policy_initmach()`, które obsługuje kernel side rejestracji polityk dla wbudowanych lub dołączonych polityk.

### `mac_policy_initmach()` i ładowanie „security extensions”

- `mac_policy_initmach()` sprawdza kernel extensions (kexts), które są wczytane wcześniej (lub znajdują się na liście „policy injection”) i analizuje ich Info.plist pod kątem klucza `AppleSecurityExtension`.
- Kexts, które deklarują `<key>AppleSecurityExtension</key>` (lub `true`) w swoim Info.plist, są uznawane za „security extensions” — czyli takie, które implementują MAC policy lub integrują się z infrastrukturą MACF.
- Przykłady kextów Apple z tym kluczem obejmują **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, między innymi (jak już wymieniłeś).
- Kernel zapewnia, że te kexts są ładowane wcześnie, a następnie wywołuje ich routine rejestracyjne (przez `mac_policy_register`) podczas bootowania, wstawiając je do `mac_policy_list`.

- Każdy moduł policy (kext) dostarcza strukturę `mac_policy_conf`, z hookami (`mpc_ops`) dla różnych operacji MAC (vnode checks, exec checks, label updates, itd.).
- Flagi czasu ładowania mogą zawierać `MPC_LOADTIME_FLAG_NOTLATE`, co oznacza „musi zostać załadowany wcześnie” (więc późniejsze próby rejestracji są odrzucane).
- Po rejestracji każdy moduł otrzymuje handle i zajmuje slot w `mac_policy_list`.
- Gdy później zostaje wywołany MAC hook (na przykład vnode access, exec, itd.), MACF iteruje po wszystkich zarejestrowanych politykach, aby podjąć wspólną decyzję.

- W szczególności **AMFI** (Apple Mobile File Integrity) jest taką security extension. Jego Info.plist zawiera `AppleSecurityExtension`, oznaczając go jako security policy.
- W ramach kernel boot logika ładowania kernela zapewnia, że „security policy” (AMFI, itd.) jest już aktywna, zanim wiele subsystemów zacznie od niej zależeć. Na przykład kernel „przygotowuje się na nadchodzące zadania, ładując … security policy, including AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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

Podczas pisania kexta, który korzysta z frameworka MAC (tj. wywołuje `mac_policy_register()` itp.), musisz zadeklarować zależności od KPI (Kernel Programming Interfaces), aby linker kexta (kxld) mógł rozwiązać te symbole. WIĘC aby zadeklarować, że `kext` zależy od MACF, musisz wskazać to w `Info.plist` za pomocą `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), wtedy kext będzie odwoływał się do symboli takich jak `mac_policy_register`, `mac_policy_unregister` oraz wskaźników funkcji hooków MAC. Aby je rozwiązać, musisz dodać `com.apple.kpi.dsep` jako zależność.

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
## MACF w nowoczesnych wersjach macOS

W nowoczesnym macOS polityki bezpieczeństwa Apple zwykle nie są najlepiej analizowane jako luźne, samodzielne pakiety `.kext`. Od **macOS 11**, rozszerzenia jądra są łączone w **kernel collections**; na **Apple Silicon** nie ma oddzielnego **SystemKC**, a kexty firm trzecich stają się ładowalne dopiero po zbudowaniu do **Auxiliary Kernel Collection (AuxKC)** i ponownym uruchomieniu. W badaniach MACF oznacza to, że wbudowane polityki, takie jak **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** lub **Quarantine**, zwykle łatwiej wyliczyć za pomocą `kmutil` niż przestarzałych narzędzi, takich jak `kextstat`.
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

To common jest znaleźć callouts do MACF zdefiniowane w kodzie w takich warunkach jak: **`#if CONFIG_MAC`**. Co więcej, wewnątrz tych bloków można znaleźć wywołania `mac_proc_check*`, które wywołują MACF, aby **sprawdzić uprawnienia** do wykonania określonych działań. Dodatkowo format callouts MACF to: **`mac_<object>_<opType>_opName`**.

Obiekt jest jednym z następujących: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` to zwykle `check`, które będzie używane do zezwolenia lub odmowy wykonania akcji. Jednak możliwe jest też znalezienie `notify`, które pozwoli kext zareagować na daną akcję.

Przykład można znaleźć w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Następnie można znaleźć kod `mac_file_check_mmap` w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Który wywołuje makro `MAC_CHECK`, którego kod można znaleźć w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Który przejdzie przez wszystkie zarejestrowane polityki MAC, wywołując ich funkcje i zapisując wynik do zmiennej error, którą można nadpisać tylko przez `mac_error_select` kodami sukcesu, więc jeśli jakakolwiek kontrola zawiedzie, cała kontrola zakończy się niepowodzeniem i akcja nie zostanie dozwolona.

> [!TIP]
> Jednak pamiętaj, że nie wszystkie callouty MACF służą tylko do odmawiania akcji. Na przykład `mac_priv_grant` wywołuje makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), które przyzna żądane uprawnienie, jeśli jakakolwiek polityka odpowie `0`:
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
>    });                                                           \
> } while (0)
> ```

### priv_check & priv_grant

Te wywołania mają na celu sprawdzanie i przyznawanie (dziesiątek) **privileges** zdefiniowanych w [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Niektóre fragmenty kodu jądra wywołują `priv_check_cred()` z [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) z poświadczeniami KAuth procesu i jednym z kodów privileges, co wywoła `mac_priv_check`, aby sprawdzić, czy jakaś polityka **odmawia** nadania uprawnienia, a następnie wywołuje `mac_priv_grant`, aby sprawdzić, czy jakaś polityka przyznaje `privilege`.

### proc_check_syscall_unix

Ten hook pozwala przechwycić wszystkie wywołania systemowe. W `bsd/dev/[i386|arm]/systemcalls.c` można zobaczyć zadeklarowaną funkcję [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), która zawiera ten kod:
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
Która sprawdzi w procesie wywołującym **bitmask**, czy bieżący syscall powinien wywołać `mac_proc_check_syscall_unix`. Dzieje się tak, ponieważ syscalle są wywoływane tak często, że interesujące jest unikanie wywoływania `mac_proc_check_syscall_unix` za każdym razem.

Zwróć uwagę, że funkcja `proc_set_syscall_filter_mask()`, która ustawia bitmask syscalli w procesie, jest wywoływana przez Sandbox, aby ustawiać maski na procesach objętych sandboxem.

## Exposed MACF syscalls

Możliwe jest interakcja z MACF przez niektóre syscalle zdefiniowane w [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Do ofensywnego reverse engineeringu, **`__mac_syscall`** nadal jest jednym z najlepszych userlandowych punktów kontrolnych. Przenosi **nazwę polityki** (na przykład `"Sandbox"` lub `"AMFI"`), **specyficzny dla polityki selektor/kod** oraz wskaźnik do **opaque argument blob**, który będzie obsłużony przez `mpo_policy_syscall`. Jest to bardzo przydatne przy reverse engineeringu nieudokumentowanych operacji najpierw z userland, a dopiero później przy przejściu do implementacji w kernelu. Sandbox zwykle dociera do tego przez `__sandbox_ms`, a AMFI używa tego samego mechanizmu do decyzji polityki dyld.

## Praktyczne notatki z ofensywnych badań

Ostatnie błędy macOS rzadko bezpośrednio „łamą MACF”. Zamiast tego zwykle wykorzystują **desynchronizację między decyzją MACF / Sandbox / TCC a uprzywilejowaną akcją, która ঘটে później**.

### Kontrole ścieżki w brokerze vs rzeczywista uprzywilejowana akcja

Powtarzający się wzorzec to uprzywilejowany daemon wykonujący **userlandowy pre-check** (na przykład `sandbox_check_by_audit_token()`) na jednej wersji ścieżki, a później uruchamiający prawdziwy uprzywilejowany sink z **inną lub niekanoniczną ścieżką kontrolowaną przez atakującego**. Ostatnie badania nad `diskarbitrationd` / `storagekitd` są dobrym przykładem: **directory traversal** plus **symlink swaps** pozwalają atakującemu przejść walidację sandboxa przez demona, a następnie zamontować coś nad wrażliwymi lokalizacjami, takimi jak `~/Library/Application Support/com.apple.TCC`, zamieniając błąd w **sandbox escape**, **local privilege escalation** lub **TCC bypass** w zależności od wybranego punktu montowania.

Podczas audytu root brokerów osiągalnych z sandboxa, najpierw grepuj:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers do kanonikalizacji ścieżek
- uprzywilejowane sinki takie jak `mount`, `rename`, `copyfile`, metody XPC helper-tool, albo cokolwiek, co później dotyka ścieżek kontrolowanych przez atakującego jako root

### Zaufani deputowani z prywatnymi entitlementami

Innym praktycznym wzorcem jest unikanie bezpośredniego atakowania hooków MACF i zamiast tego wykorzystanie **zaufanego procesu**, który już ma uprawnienia potrzebne do przekroczenia granicy. Ostatnie badania nad Safari/TCC są dobrym przykładem: interesującym prymitywem nie było „wyłączenie TCC w kernelu”, lecz zmodyfikowanie lokalnej polityki/konfiguracji tak, aby podpisany przez Apple proces z **`com.apple.private.tcc.allow`** wykonał wrażliwą akcję w Twoim imieniu. W praktyce, wysokowartościowe cele audytu to demony/aplikacje Apple, które łączą:

- **private entitlements** lub zasięg podobny do FDA
- zapisywalny config / database / mount point / policy file
- późniejszą wrażliwą operację mediowaną przez **Sandbox**, **AMFI**, **TCC** lub inną politykę MACF

Do głębszego, specyficznego dla produktu reverse engineeringu, sprawdź dedykowane strony o [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).

## Referencje

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
