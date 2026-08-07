# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**MACF** oznacza **Mandatory Access Control Framework** — system bezpieczeństwa wbudowany w system operacyjny, który pomaga chronić komputer. Działa poprzez ustanawianie **ścisłych reguł określających, kto lub co może uzyskiwać dostęp do określonych części systemu**, takich jak pliki, aplikacje i zasoby systemowe. Automatyczne egzekwowanie tych reguł sprawia, że MACF zapewnia możliwość wykonywania określonych działań wyłącznie autoryzowanym użytkownikom i procesom, zmniejszając ryzyko nieautoryzowanego dostępu lub złośliwych działań.

Należy pamiętać, że MACF w rzeczywistości nie podejmuje żadnych decyzji, ponieważ jedynie **przechwytuje** działania, a podejmowanie decyzji pozostawia **modułom polityk** (rozszerzeniom kernela), które wywołuje, takim jak `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Polityka może wymuszać działanie (zwracać 0 lub wartość różną od zera dla określonej operacji)
- Polityka może monitorować działanie (zwracać 0, aby nie zgłaszać sprzeciwu, ale wykorzystać hook do wykonania określonej czynności)
- Statyczna polityka MACF jest instalowana podczas boot i NIGDY nie zostanie usunięta
- Dynamiczna polityka MACF jest instalowana przez KEXT (`kextload`) i hipotetycznie może zostać usunięta za pomocą `kextunloaded`
- W iOS dozwolone są wyłącznie polityki statyczne, natomiast w macOS — statyczne i dynamiczne.<sup>[[7]](#references)</sup>

### Przepływ

1. Proces wykonuje syscall/mach trap
2. Odpowiednia funkcja jest wywoływana wewnątrz kernela
3. Funkcja wywołuje MACF
4. MACF sprawdza moduły polityk, które w swoich politykach zażądały podpięcia hooka do tej funkcji
5. MACF wywołuje odpowiednie polityki
6. Polityki wskazują, czy zezwalają na działanie, czy je odrzucają

> [!CAUTION]
> Apple jest jedynym podmiotem, który może korzystać z MAC Framework KPI.

Zwykle funkcje sprawdzające uprawnienia za pomocą MACF wywołują makro `MAC_CHECK`. Tak jest w przypadku syscall służącego do utworzenia socketu, który wywołuje funkcję `mac_socket_check_create`, a ta wywołuje `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Ponadto makro `MAC_CHECK` jest zdefiniowane w pliku security/mac_internal.h jako:<sup>[[3]](#references)</sup>
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
Zauważ, że przekształcając `check` w `socket_check_create` oraz `args...` w `(cred, domain, type, protocol)`, otrzymujesz:
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
Innymi słowy, `MAC_CHECK(socket_check_create, ...)` najpierw przechodzi przez statyczne policies, następnie warunkowo blokuje dostęp i iteruje po dynamic policies, emituje sondy DTrace wokół każdego hooka oraz scala kod zwrotny każdego hooka w pojedynczy wynik `error` za pomocą `mac_error_select()`.


### Labels

MACF używa **labels**, z których następnie korzystają policies sprawdzające, czy powinny przyznać dany dostęp. Kod deklaracji struktury labels można znaleźć [tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), a następnie jest ona używana wewnątrz **`struct ucred`** [tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), w części **`cr_label`**. Label zawiera flagi oraz pewną liczbę **slots**, które mogą być używane przez **MACF policies do przydzielania pointers**. Na przykład Sanbox będzie wskazywać na container profile

## MACF Policies

MACF Policy definiuje **rules i conditions, które mają być stosowane podczas określonych operacji kernela**.

Kernel extension może skonfigurować strukturę `mac_policy_conf`, a następnie zarejestrować ją, wywołując `mac_policy_register`. Z [tego miejsca](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Łatwo zidentyfikować kernel extensions konfigurujące te policies, sprawdzając wywołania `mac_policy_register`. Ponadto, sprawdzając disassembly extension, można również znaleźć używaną strukturę `mac_policy_conf`.

Należy pamiętać, że policies MACF mogą być rejestrowane i wyrejestrowywane również **dynamicznie**.

Jednym z głównych pól `mac_policy_conf` jest **`mpc_ops`**. To pole określa, którymi operacjami interesuje się policy. Należy pamiętać, że jest ich setki, więc można wyzerować je wszystkie, a następnie wybrać tylko te, które interesują policy. Zobacz [tutaj](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Prawie wszystkie hooki będą wywoływane zwrotnie przez MACF, gdy jedna z tych operacji zostanie przechwycona. Jednak hooki **`mpo_policy_*`** są wyjątkiem, ponieważ `mpo_hook_policy_init()` jest callbackiem wywoływanym podczas rejestracji (czyli po `mac_policy_register()`), a `mpo_hook_policy_initbsd()` jest wywoływany podczas późnej rejestracji, gdy podsystem BSD zostanie prawidłowo zainicjalizowany.

Ponadto hook **`mpo_policy_syscall`** może zostać zarejestrowany przez dowolny kext w celu udostępnienia prywatnego interfejsu wywołań w stylu **ioctl**. Następnie user client będzie mógł wywołać `mac_syscall` (#381), podając jako parametry **nazwę polityki**, całkowity **code** oraz opcjonalne **arguments**.\
Na przykład **`Sandbox.kext`** często z tego korzysta.

Sprawdzając **`__DATA.__const*`** kextu, można zidentyfikować strukturę `mac_policy_ops` używaną podczas rejestracji polityki. Można ją znaleźć, ponieważ jej wskaźnik znajduje się pod określonym offsetem w `mpo_policy_conf`, a także ze względu na liczbę wskaźników NULL znajdujących się w tym obszarze.

Ponadto można uzyskać listę kextów, które skonfigurowały politykę, zrzucając z pamięci strukturę **`_mac_policy_list`**, która jest aktualizowana za każdym razem, gdy rejestrowana jest polityka.

Można również użyć narzędzia `xnoop`, aby zrzucić wszystkie polityki zarejestrowane w systemie:
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
Następnie zrzut wszystkich kontroli check policy za pomocą:
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
- `mac_policy_init()` inicjalizuje globalną `mac_policy_list` (tablicę lub listę slotów policy) i konfiguruje infrastrukturę MAC (Mandatory Access Control) w XNU.
- Później wywoływana jest `mac_policy_initmach()`, która obsługuje rejestrację policy po stronie kernela dla wbudowanych lub dołączonych policy.

### `mac_policy_initmach()` i ładowanie „security extensions”

- `mac_policy_initmach()` analizuje kernel extensions (kexts), które są wstępnie załadowane (lub znajdują się na liście „policy injection”), i sprawdza ich Info.plist pod kątem klucza `AppleSecurityExtension`.
- Kexts deklarujące `<key>AppleSecurityExtension</key>` (lub `true`) w swoim Info.plist są uznawane za „security extensions” — czyli takie, które implementują MAC policy lub podpinają się do infrastruktury MACF.
- Przykłady Apple kexts zawierających ten klucz to **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** i inne (zgodnie z wcześniejszą listą).
- Kernel zapewnia, że te kexts zostaną załadowane wcześnie, a następnie wywołuje ich routines rejestracyjne (przez `mac_policy_register`) podczas bootu, wstawiając je do `mac_policy_list`.

- Każdy moduł policy (kext) dostarcza strukturę `mac_policy_conf` z hooks (`mpc_ops`) dla różnych operacji MAC (sprawdzanie vnode, sprawdzanie exec, aktualizacje labeli itd.).
- Flagi czasu ładowania mogą zawierać `MPC_LOADTIME_FLAG_NOTLATE`, oznaczającą „musi zostać załadowany wcześnie” (dlatego późniejsze próby rejestracji są odrzucane).
- Po zarejestrowaniu każdy moduł otrzymuje handle i zajmuje slot w `mac_policy_list`.
- Gdy później wywoływany jest MAC hook (na przykład podczas dostępu do vnode, exec itd.), MACF iteruje po wszystkich zarejestrowanych policy, aby podejmować wspólne decyzje.

- W szczególności **AMFI** (Apple Mobile File Integrity) jest takim security extension. Jego Info.plist zawiera `AppleSecurityExtension`, oznaczając je jako security policy.
- W ramach bootu kernela mechanizm ładowania kernela zapewnia, że „security policy” (AMFI itd.) jest już aktywna, zanim wiele subsystemów zacznie na niej polegać. Na przykład kernel „przygotowuje się do obsługi zadań, ładując … security policy, w tym AppleMobileFileIntegrity (AMFI), Sandbox i Quarantine policy”.
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
## Zależność od KPI i com.apple.kpi.dsep w kextach zasad MAC

Podczas tworzenia kexta korzystającego z frameworka MAC (tj. wywołującego `mac_policy_register()` itd.) należy zadeklarować zależności od KPI (Kernel Programming Interfaces), aby linker kextów (kxld) mógł rozwiązać te symbole. Aby zadeklarować zależność `kext` od MACF, należy wskazać ją w pliku `Info.plist` za pomocą `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); następnie kext będzie odwoływać się do symboli takich jak `mac_policy_register`, `mac_policy_unregister` oraz wskaźników funkcji hooków MAC. Aby je rozwiązać, należy wymienić `com.apple.kpi.dsep` jako zależność.

Przykładowy fragment pliku Info.plist (wewnątrz pliku `.kext`):
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

W nowoczesnym macOS do polityk bezpieczeństwa Apple zwykle nie należy podchodzić jak do luźnych, samodzielnych pakietów `.kext`. Od **macOS 11** rozszerzenia jądra są linkowane do **kernel collections**; na **Apple Silicon** nie ma osobnego **SystemKC**, a kexty firm trzecich mogą zostać załadowane dopiero po zbudowaniu ich w **Auxiliary Kernel Collection (AuxKC)** i ponownym uruchomieniu systemu. W przypadku badań nad MACF oznacza to, że wbudowane polityki, takie jak **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** czy **Quarantine**, zwykle łatwiej wyliczyć za pomocą `kmutil` niż przy użyciu przestarzałych narzędzi, takich jak `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Na Apple Silicon, jeśli security kext nie znajduje się w BootKC, w następnej kolejności sprawdź AuxKC. Zwykle jest to bardziej użyteczne niż wyszukiwanie standalone bundle w `/System/Library/Extensions`.

## MACF Callouts

Często można znaleźć callouts do MACF zdefiniowane w kodzie, na przykład w blokach warunkowych **`#if CONFIG_MAC`**. Ponadto wewnątrz tych bloków można znaleźć wywołania `mac_proc_check*`, które wywołują MACF w celu **sprawdzenia uprawnień** do wykonania określonych działań. Format callouts MACF to: **`mac_<object>_<opType>_opName`**.

Obiekt jest jednym z następujących: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` to zwykle check, który służy do zezwalania na działanie lub jego odrzucania. Można jednak również znaleźć `notify`, które pozwala kext zareagować na dane działanie.

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
Które wywołuje makro `MAC_CHECK`, którego kod można znaleźć pod adresem [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
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
Który przejdzie przez wszystkie zarejestrowane policies MAC, wywołując ich funkcje i zapisując wynik w zmiennej `error`, którą `mac_error_select` może nadpisać wyłącznie kodami sukcesu, więc jeśli dowolne sprawdzenie zakończy się niepowodzeniem, całe sprawdzenie zakończy się niepowodzeniem, a działanie nie zostanie dozwolone.

> [!TIP]
> Należy jednak pamiętać, że nie wszystkie callouty MACF służą wyłącznie do odrzucania działań. Na przykład `mac_priv_grant` wywołuje makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), które przyzna żądany privilege, jeśli dowolna policy odpowie wartością 0:
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

Te wywołania służą do sprawdzania i przyznawania (dziesiątek) **privileges** zdefiniowanych w [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Część kodu kernela wywołuje `priv_check_cred()` z [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), przekazując credentials KAuth procesu oraz jeden z kodów privileges. Funkcja ta wywołuje `mac_priv_check`, aby sprawdzić, czy którakolwiek policy **odmawia** przyznania privilege, a następnie wywołuje `mac_priv_grant`, aby sprawdzić, czy którakolwiek policy przyznaje `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Ten hook umożliwia przechwytywanie wszystkich system calls. W `bsd/dev/[i386|arm]/systemcalls.c` można znaleźć zadeklarowaną funkcję [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), która zawiera następujący kod:
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
Który sprawdzi w procesie wywołującym **bitmask**, aby określić, czy bieżący syscall powinien wywołać `mac_proc_check_syscall_unix`. Wynika to z faktu, że syscalls są wywoływane tak często, że warto unikać wywoływania `mac_proc_check_syscall_unix` za każdym razem.

Należy zauważyć, że funkcja `proc_set_syscall_filter_mask()`, która ustawia maskę bitową syscalli w procesie, jest wywoływana przez Sandbox w celu ustawienia masek w procesach objętych sandboxem.

## Upublicznione syscalls MACF

Możliwe jest interakcja z MACF za pomocą niektórych syscalli zdefiniowanych w [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
W przypadku offensive reversingu **`__mac_syscall`** nadal pozostaje jednym z najlepszych chokepointów w userlandzie. Przekazuje **nazwę policy** (na przykład `"Sandbox"` lub `"AMFI"`), **selector/code** zależny od policy oraz wskaźnik do **opaque argument blob**, który zostanie obsłużony przez `mpo_policy_syscall`. Jest to bardzo przydatne podczas reverse engineeringu nieudokumentowanych operacji najpierw z poziomu userlandu, a dopiero później przechodzenia do implementacji w kernelu. Sandbox często dociera do niego przez `__sandbox_ms`, a AMFI używa tego samego mechanizmu do podejmowania decyzji dotyczących policy dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktyczne uwagi dotyczące offensive research

Najnowsze bugi w macOS rzadko bezpośrednio „omijają MACF”. Zamiast tego zwykle wykorzystują **desynchronizację między decyzją MACF / Sandbox / TCC a uprzywilejowaną akcją wykonywaną później**.

### Sprawdzanie ścieżki przez brokera a rzeczywista uprzywilejowana akcja

Powtarzającym się wzorcem jest uprzywilejowany daemon wykonujący **userland pre-check** (na przykład `sandbox_check_by_audit_token()`) dla jednej wersji ścieżki, a następnie wykonujący rzeczywisty privileged sink z użyciem **innej lub niekanonicznej ścieżki kontrolowanej przez attackera**. Najnowsze badania `diskarbitrationd` / `storagekitd` są dobrym przykładem: **directory traversal** wraz z **symlink swaps** pozwalają attackerowi przejść walidację Sandbox daemona, a następnie zamontować system plików wrażliwych lokalizacjach, takich jak `~/Library/Application Support/com.apple.TCC`, zmieniając bug w **sandbox escape**, **local privilege escalation** lub **TCC bypass** — zależnie od wybranego punktu montowania.<sup>[[6]](#references)</sup>

Podczas audytowania root brokerów dostępnych z sandboxa najpierw wyszukaj:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpery do canonicalisation ścieżek
- uprzywilejowane sinki, takie jak `mount`, `rename`, `copyfile`, metody XPC helper-toolów lub wszystko, co później dotyka ścieżek kontrolowanych przez attackera jako root

### Zaufane deputies z prywatnymi entitlements

Innym praktycznym wzorcem jest ominięcie bezpośredniego atakowania hooków MACF i zamiast tego wykorzystanie **trusted process**, który już posiada uprawnienia niezbędne do przekroczenia granicy. Najnowsze badania Safari/TCC są dobrym przykładem: interesującym primitive'em nie było „wyłączenie TCC w kernelu”, lecz modyfikacja lokalnej policy/konfiguracji, aby proces podpisany przez Apple, posiadający **`com.apple.private.tcc.allow`**, wykonał wrażliwą akcję w imieniu attackera.<sup>[[8]](#references)</sup> W praktyce celami audytu o wysokiej wartości są daemony/aplikacje Apple, które łączą:

- **private entitlements** lub dostęp podobny do FDA
- zapisywalny config / database / mount point / policy file
- późniejszą wrażliwą operację obsługiwaną przez **Sandbox**, **AMFI**, **TCC** lub inną policy MACF

W celu przeprowadzenia głębszego, produktowego reverse engineeringu sprawdź dedykowane strony dotyczące [macOS Sandbox](macos-sandbox/README.md) oraz [macOS TCC](macos-tcc/README.md).

## Referencje

- [1] [XNU — `security/mac_policy.h` (pełny wektor operacji policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (makra `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (kody uprawnień używane przez `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Odkrywanie podatności Apple: audyt diskarbitrationd i storagekitd, część 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — narzędzie XNU Cross Reference](https://newosxbook.com/xxr/index.php)
- [8] [Nowa podatność macOS, „HM Surf”, może prowadzić do nieautoryzowanego dostępu do danych (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)

{{#include ../../../banners/hacktricks-training.md}}
