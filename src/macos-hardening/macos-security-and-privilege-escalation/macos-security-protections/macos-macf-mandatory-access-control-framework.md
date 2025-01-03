# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**MACF** oznacza **Framework Obowiązkowej Kontroli Dostępu**, który jest systemem zabezpieczeń wbudowanym w system operacyjny, aby pomóc chronić komputer. Działa poprzez ustalanie **ścisłych zasad dotyczących tego, kto lub co może uzyskać dostęp do określonych części systemu**, takich jak pliki, aplikacje i zasoby systemowe. Dzięki automatycznemu egzekwowaniu tych zasad, MACF zapewnia, że tylko autoryzowani użytkownicy i procesy mogą wykonywać określone działania, co zmniejsza ryzyko nieautoryzowanego dostępu lub złośliwych działań.

Należy zauważyć, że MACF nie podejmuje rzeczywistych decyzji, ponieważ po prostu **przechwytuje** działania, pozostawiając decyzje modułom **polityki** (rozszerzenia jądra), które wywołuje, takim jak `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

### Przepływ

1. Proces wykonuje syscall/mach trap
2. Odpowiednia funkcja jest wywoływana wewnątrz jądra
3. Funkcja wywołuje MACF
4. MACF sprawdza moduły polityki, które zażądały podpięcia tej funkcji w swojej polityce
5. MACF wywołuje odpowiednie polityki
6. Polityki wskazują, czy zezwalają na działanie, czy je odrzucają

> [!OSTRZEŻENIE]
> Apple jest jedyną firmą, która może korzystać z KPI Framework MAC.

### Etykiety

MACF używa **etykiet**, które następnie polityki sprawdzają, czy powinny przyznać dostęp, czy nie. Kod deklaracji struktury etykiet można [znaleźć tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), który jest następnie używany wewnątrz **`struct ucred`** w [**tutaj**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) w części **`cr_label`**. Etykieta zawiera flagi i liczbę **slotów**, które mogą być używane przez **polityki MACF do alokacji wskaźników**. Na przykład Sanbox będzie wskazywał na profil kontenera.

## Polityki MACF

Polityka MACF definiuje **zasady i warunki, które mają być stosowane w określonych operacjach jądra**.&#x20;

Rozszerzenie jądra może skonfigurować strukturę `mac_policy_conf`, a następnie zarejestrować ją, wywołując `mac_policy_register`. Z [tutaj](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Łatwo jest zidentyfikować rozszerzenia jądra konfigurowane przez te polityki, sprawdzając wywołania do `mac_policy_register`. Co więcej, sprawdzając disassemblację rozszerzenia, można również znaleźć używaną strukturę `mac_policy_conf`.

Należy zauważyć, że polityki MACF mogą być rejestrowane i deregisterowane również **dynamicznie**.

Jednym z głównych pól `mac_policy_conf` jest **`mpc_ops`**. To pole określa, które operacje interesują politykę. Należy zauważyć, że jest ich setki, więc możliwe jest wyzerowanie wszystkich z nich, a następnie wybranie tylko tych, którymi polityka jest zainteresowana. Stąd: [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Prawie wszystkie haki będą wywoływane przez MACF, gdy jedna z tych operacji zostanie przechwycona. Jednak haki **`mpo_policy_*`** są wyjątkiem, ponieważ `mpo_hook_policy_init()` jest wywołaniem zwrotnym wywoływanym podczas rejestracji (więc po `mac_policy_register()`), a `mpo_hook_policy_initbsd()` jest wywoływane podczas późnej rejestracji, gdy podsystem BSD został poprawnie zainicjowany.

Ponadto hak **`mpo_policy_syscall`** może być rejestrowany przez dowolny kext, aby udostępnić prywatny interfejs wywołań w stylu **ioctl**. Następnie klient użytkownika będzie mógł wywołać `mac_syscall` (#381), określając jako parametry **nazwa polityki** z całkowitą **liczbą** i opcjonalnymi **argumentami**.\
Na przykład **`Sandbox.kext`** używa tego często.

Sprawdzając **`__DATA.__const*`** kextu, można zidentyfikować strukturę `mac_policy_ops` używaną podczas rejestracji polityki. Można ją znaleźć, ponieważ wskaźnik znajduje się w przesunięciu wewnątrz `mpo_policy_conf`, a także z powodu liczby wskaźników NULL, które będą w tym obszarze.

Ponadto możliwe jest również uzyskanie listy kextów, które skonfigurowały politykę, poprzez zrzut z pamięci struktury **`_mac_policy_list`**, która jest aktualizowana przy każdej zarejestrowanej polityce.

## Inicjalizacja MACF

MACF jest inicjowane bardzo wcześnie. Jest konfigurowane w `bootstrap_thread` XNU: po `ipc_bootstrap` następuje wywołanie `mac_policy_init()`, które inicjuje `mac_policy_list`, a chwilę później wywoływana jest `mac_policy_initmach()`. Między innymi ta funkcja pobiera wszystkie kexty Apple z kluczem `AppleSecurityExtension` w ich Info.plist, takie jak `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` i `TMSafetyNet.kext` i je ładuje.

## Wywołania MACF

Często można znaleźć wywołania do MACF zdefiniowane w kodzie, takie jak: **`#if CONFIG_MAC`** bloki warunkowe. Ponadto wewnątrz tych bloków można znaleźć wywołania do `mac_proc_check*`, które wywołują MACF, aby **sprawdzić uprawnienia** do wykonania określonych działań. Ponadto format wywołań MACF to: **`mac_<object>_<opType>_opName`**.

Obiekt to jeden z następujących: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` zazwyczaj to check, które będzie używane do zezwolenia lub odmowy działania. Jednak można również znaleźć `notify`, co pozwoli kextowi zareagować na dane działanie.

Możesz znaleźć przykład w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&#x26;maxprot);
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
Który przejdzie przez wszystkie zarejestrowane polityki mac, wywołując ich funkcje i przechowując wynik w zmiennej error, która będzie mogła być nadpisana tylko przez `mac_error_select` za pomocą kodów sukcesu, więc jeśli jakiekolwiek sprawdzenie nie powiedzie się, całe sprawdzenie nie powiedzie się, a akcja nie będzie dozwolona.

> [!TIP]
> Jednak pamiętaj, że nie wszystkie wywołania MACF są używane tylko do odrzucania działań. Na przykład `mac_priv_grant` wywołuje makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), które przyzna żądane uprawnienie, jeśli jakakolwiek polityka odpowie 0:
>
> ```c
> /*
>  * MAC_GRANT wykonuje wyznaczone sprawdzenie, przechodząc przez listę
>  * modułów polityki i sprawdzając z każdym, co sądzą o
>  * żądaniu. W przeciwieństwie do MAC_CHECK, przyznaje, jeśli jakiekolwiek polityki zwracają '0',
>  * a w przeciwnym razie zwraca EPERM. Zauważ, że zwraca swoją wartość przez
>  * 'error' w zakresie wywołującego.
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     error = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

Te wywołania mają na celu sprawdzenie i przyznanie (dziesiątek) **uprawnień** zdefiniowanych w [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Niektóre kody jądra wywołają `priv_check_cred()` z [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) z poświadczeniami KAuth procesu i jednym z kodów uprawnień, które wywołają `mac_priv_check`, aby sprawdzić, czy jakakolwiek polityka **odrzuca** przyznanie uprawnienia, a następnie wywołuje `mac_priv_grant`, aby sprawdzić, czy jakakolwiek polityka przyznaje `uprawnienie`.

### proc_check_syscall_unix

Ten hak pozwala na przechwytywanie wszystkich wywołań systemowych. W `bsd/dev/[i386|arm]/systemcalls.c` można zobaczyć zadeklarowaną funkcję [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), która zawiera ten kod:
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
Który sprawdzi w wywołującym procesie **bitmaskę**, czy bieżące wywołanie syscalls powinno wywołać `mac_proc_check_syscall_unix`. Dzieje się tak, ponieważ wywołania syscalls są wywoływane tak często, że warto unikać wywoływania `mac_proc_check_syscall_unix` za każdym razem.

Zauważ, że funkcja `proc_set_syscall_filter_mask()`, która ustawia bitmaskę wywołań syscalls w procesie, jest wywoływana przez Sandbox w celu ustawienia masek na procesach w piaskownicy.

## Ekspozycja syscalls MACF

Możliwe jest interakcja z MACF za pomocą niektórych wywołań syscalls zdefiniowanych w [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
## Odniesienia

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
