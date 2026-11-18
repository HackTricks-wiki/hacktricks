# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**MACF** to skrót od **Mandatory Access Control Framework** — systemu zabezpieczeń wbudowanego w system operacyjny, który pomaga chronić komputer. Działa poprzez ustanawianie **ścisłych reguł określających, kto lub co może uzyskiwać dostęp do określonych części systemu**, takich jak pliki, aplikacje i zasoby systemowe. Automatyczne egzekwowanie tych reguł sprawia, że MACF zapewnia, iż tylko autoryzowani użytkownicy i procesy mogą wykonywać określone działania, zmniejszając ryzyko nieautoryzowanego dostępu lub złośliwych działań.

Zwróć uwagę, że MACF tak naprawdę nie podejmuje żadnych decyzji — jedynie **przechwytuje** działania, pozostawiając decyzje **modułom polityk** (rozszerzeniom jądra), które wywołuje, takim jak `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` i `mcxalr.kext`.

- Polityka może egzekwować reguły (zwracać wartość różną od 0 dla niektórych operacji)
- Polityka może monitorować działania (zwracać 0, aby nie zgłaszać sprzeciwu, ale wykorzystać hook do wykonania jakiejś czynności)
- Statyczna polityka MACF jest instalowana podczas uruchamiania i NIGDY nie zostanie usunięta
- Dynamiczna polityka MACF jest instalowana przez KEXT (`kextload`) i teoretycznie może zostać wyładowana przez `kextunload`
- W iOS dozwolone są tylko statyczne polityki, a w macOS — statyczne i dynamiczne.<sup>[[7]](#references)</sup>

### Przepływ

1. Proces wykonuje syscall lub pułapkę mach
2. Odpowiednia funkcja zostaje wywołana w jądrze
3. Funkcja wywołuje MACF
4. MACF sprawdza moduły polityk, które w swoich politykach zażądały podpięcia się pod tę funkcję
5. MACF wywołuje odpowiednie polityki
6. Polityki wskazują, czy zezwalają na działanie, czy je blokują

> [!CAUTION]
> Tylko Apple może korzystać z KPI MAC Framework.

Funkcje sprawdzające uprawnienia za pomocą MACF zwykle wywołują makro `MAC_CHECK`. Na przykład syscall tworzący socket wywoła funkcję `mac_socket_check_create`, która wywołuje `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Ponadto makro `MAC_CHECK` jest zdefiniowane w pliku security/mac_internal.h w następujący sposób:<sup>[[3]](#references)</sup>
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

Innymi słowy, `MAC_CHECK(socket_check_create, ...)` najpierw przechodzi przez statyczne polityki, warunkowo blokuje dostęp i iteruje po dynamicznych politykach, emituje sondy DTrace wokół każdego hooka, a następnie sprowadza kody zwracane przez wszystkie hooki do pojedynczego wyniku `error` za pomocą `mac_error_select()`.


### Etykiety

MACF używa **etykiet**, z których korzystają następnie polityki sprawdzające, czy należy przyznać dostęp. Kod deklaracji struktury etykiet można [znaleźć tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h). Struktura ta jest następnie używana wewnątrz **`struct ucred`**, [tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), w części **`cr_label`**. Etykieta zawiera flagi i pewną liczbę **slotów**, których **polityki MACF mogą używać do przydzielania wskaźników**. Na przykład Sandbox przechowuje wskaźnik do profilu kontenera.

## Polityki MACF

Polityka MACF definiuje **reguły i warunki stosowane podczas określonych operacji jądra**.

Rozszerzenie jądra może skonfigurować strukturę `mac_policy_conf`, a następnie ją zarejestrować, wywołując `mac_policy_register`. Z [tego źródła](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Łatwo zidentyfikować rozszerzenia jądra konfigurujące te polityki, sprawdzając wywołania `mac_policy_register`. Ponadto, analizując kod asemblera rozszerzenia, można znaleźć używaną strukturę `mac_policy_conf`.

Pamiętaj, że polityki MACF można również rejestrować i wyrejestrowywać **dynamicznie**.

Jednym z głównych pól `mac_policy_conf` jest **`mpc_ops`**. To pole określa, które operacje są interesujące dla danej polityki. Jest ich setki, dlatego można wyzerować wszystkie wpisy, a następnie wybrać tylko te wymagane przez politykę. Z [tego źródła](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Prawie wszystkie hooki są wywoływane przez MACF, gdy jedna z tych operacji zostanie przechwycona. Wyjątkiem są jednak hooki **`mpo_policy_*`**, ponieważ `mpo_hook_policy_init()` to callback wywoływany podczas rejestracji (czyli po `mac_policy_register()`), a `mpo_hook_policy_initbsd()` jest wywoływany podczas późnej rejestracji, gdy podsystem BSD został już prawidłowo zainicjowany.

Ponadto hook **`mpo_policy_syscall**` może zostać zarejestrowany przez dowolny kext, aby udostępnić prywatny **interfejs** wywołań w stylu **ioctl**. Następnie klient user może wywołać `mac_syscall` (#381), podając jako parametry **nazwę polityki**, liczbę całkowitą **code** i opcjonalne **argumenty**.\
Na przykład `Sandbox.kext` często z tego korzysta.

Sprawdzając **`__DATA.__const*`** kextu, można zidentyfikować strukturę `mac_policy_ops` używaną podczas rejestracji polityki. Można ją odnaleźć, ponieważ jej wskaźnik znajduje się pod określonym offsetem w `mpo_policy_conf`, a także na podstawie liczby wskaźników NULL znajdujących się w tym obszarze.

Można też uzyskać listę kextów, które skonfigurowały politykę, zrzucając z pamięci strukturę **`_mac_policy_list`**, aktualizowaną przy rejestracji każdej polityki.

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

Następnie zrzucić wszystkie kontrole check policy za pomocą:

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

- MACF jest inicjalizowany bardzo wcześnie. W `bootstrap_thread` (w kodzie uruchamiania XNU), po `ipc_bootstrap`, XNU wywołuje `mac_policy_init()` (w `mac_base.c`).  
- `mac_policy_init()` inicjalizuje globalną `mac_policy_list` (tablicę lub listę slotów na polityki) i konfiguruje infrastrukturę MAC (Mandatory Access Control) w XNU.  
- Później wywoływana jest funkcja `mac_policy_initmach()`, która obsługuje rejestrowanie polityk po stronie jądra dla wbudowanych lub dołączonych polityk.

### `mac_policy_initmach()` i ładowanie „rozszerzeń zabezpieczeń”

- `mac_policy_initmach()` analizuje rozszerzenia jądra (kexts), które są wstępnie załadowane (lub znajdują się na liście „policy injection”), i sprawdza w ich plikach Info.plist klucz `AppleSecurityExtension`.  
- Kexty, które w pliku Info.plist deklarują `<key>AppleSecurityExtension</key>` (lub `true`), są uznawane za „rozszerzenia zabezpieczeń” — czyli takie, które implementują politykę MAC lub korzystają z infrastruktury MACF.  
- Przykłady kextów Apple zawierających ten klucz to między innymi **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext** i **AppleSystemPolicy.kext** (jak już wymieniono).  
- Jądro dba o to, aby te kexty zostały załadowane odpowiednio wcześnie, a następnie podczas uruchamiania wywołuje ich procedury rejestracji (za pośrednictwem `mac_policy_register`), dodając je do `mac_policy_list`.

  - Każdy moduł polityki (kext) udostępnia strukturę `mac_policy_conf` z hookami (`mpc_ops`) dla różnych operacji MAC (kontrole vnode, kontrole exec, aktualizacje etykiet itp.).  
  - Flagi czasu ładowania mogą obejmować `MPC_LOADTIME_FLAG_NOTLATE`, oznaczającą, że moduł „musi zostać załadowany wcześnie” (próby późnej rejestracji są więc odrzucane).  
  - Po zarejestrowaniu każdy moduł otrzymuje uchwyt i zajmuje slot w `mac_policy_list`.  
  - Gdy później wywoływany jest hook MAC (na przykład podczas dostępu do vnode lub operacji exec), MACF iteruje po wszystkich zarejestrowanych politykach, aby wspólnie podjąć decyzję.

- W szczególności **AMFI** (Apple Mobile File Integrity) jest takim rozszerzeniem zabezpieczeń. W jego pliku Info.plist znajduje się `AppleSecurityExtension`, oznaczający go jako politykę bezpieczeństwa. 
- W ramach uruchamiania jądra logika ładowania dba o to, aby „polityka bezpieczeństwa” (AMFI itp.) była już aktywna, zanim zaczną od niej zależeć liczne podsystemy. Na przykład jądro „przygotowuje się do nadchodzących zadań, ładując … politykę bezpieczeństwa, w tym AppleMobileFileIntegrity (AMFI), Sandbox i politykę Quarantine”. 

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

## Zależność od KPI i com.apple.kpi.dsep w kextach z zasadami MAC

Podczas pisania kexta korzystającego z frameworka MAC (czyli wywołującego m.in. `mac_policy_register()`), musisz zadeklarować zależności od KPI (Kernel Programming Interfaces), aby linker kextów (kxld) mógł rozpoznać te symbole. Zatem, aby zadeklarować, że `kext` zależy od MACF, musisz wskazać to w pliku `Info.plist` za pomocą `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Następnie kext będzie odwoływać się do symboli takich jak `mac_policy_register`, `mac_policy_unregister` oraz wskaźników na funkcje MAC hook. Aby je rozpoznać, musisz wymienić `com.apple.kpi.dsep` jako zależność.

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

W nowoczesnym macOS polityki bezpieczeństwa Apple zwykle nie są luźnymi, samodzielnymi pakietami `.kext`. Od **macOS 11** rozszerzenia jądra są łączone w **kolekcje jądra**; na **Apple Silicon** nie ma osobnego **SystemKC**, a kexty innych firm można załadować dopiero po wbudowaniu ich w **Auxiliary Kernel Collection (AuxKC)** i ponownym uruchomieniu systemu. W badaniach MACF oznacza to, że wbudowane polityki, takie jak **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** czy **Quarantine**, zwykle łatwiej wyliczyć za pomocą `kmutil` niż przestarzałych narzędzi, takich jak `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> Na Apple Silicon, jeśli security kext nie znajduje się w BootKC, sprawdź następnie AuxKC. Zwykle jest to bardziej przydatne niż szukanie samodzielnego bundle w `/System/Library/Extensions`.

## Wywołania MACF

Często można znaleźć wywołania MACF zdefiniowane w kodzie, na przykład w blokach warunkowych **`#if CONFIG_MAC`**. Ponadto wewnątrz tych bloków można znaleźć wywołania `mac_proc_check*`, które wywołują MACF, aby **sprawdzić uprawnienia** do wykonania określonych działań. Format wywołań MACF to: **`mac_<object>_<opType>_opName`**.

Obiekt to jeden z następujących: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` to zazwyczaj `check`, które służy do zezwalania na działanie lub jego blokowania. Można jednak znaleźć także `notify`, które pozwala kext zareagować na dane działanie.

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

Co wywołuje makro `MAC_CHECK`, którego kod można znaleźć w [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Ta funkcja przechodzi przez zarejestrowane polityki i łączy wyniki za pomocą `mac_error_select()`. Wartość 0 zwrócona przez późniejszą kontrolę nie może unieważnić wcześniejszej odmowy; jeśli kilka polityk odmawia, funkcja wybiera błąd według priorytetu (na przykład `EACCES` przed `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Pamiętaj jednak, że nie wszystkie wywołania MACF służą wyłącznie do odmawiania dostępu do działań. Na przykład `mac_priv_grant` wywołuje makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), które przyzna żądane uprawnienie, jeśli którakolwiek polityka zwróci 0:
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

Te wywołania służą do sprawdzania i przyznawania (dziesiątek) **uprawnień** zdefiniowanych w [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Niektóre fragmenty kodu jądra wywołują `priv_check_cred()` z [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c), przekazując poświadczenia KAuth procesu i kod jednego z uprawnień. Funkcja ta wywołuje `mac_priv_check`, aby sprawdzić, czy którakolwiek z polityk **odmawia** przyznania uprawnienia, a następnie wywołuje `mac_priv_grant`, aby sprawdzić, czy którakolwiek z polityk przyznaje to `uprawnienie`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Ten hook umożliwia przechwytywanie wszystkich wywołań systemowych. W pliku `bsd/dev/[i386|arm]/systemcalls.c` można znaleźć deklarację funkcji [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), która zawiera następujący kod:

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

Który sprawdzi **maskę bitową** w procesie wywołującym, aby ustalić, czy bieżący syscall powinien wywołać `mac_proc_check_syscall_unix`. Dzieje się tak, ponieważ syscalls są wywoływane bardzo często, więc warto unikać wywoływania `mac_proc_check_syscall_unix` za każdym razem.

Zwróć uwagę, że funkcja `proc_set_syscall_filter_mask()`, która ustawia maskę bitową syscalls w procesie, jest wywoływana przez Sandbox w celu ustawienia masek w procesach objętych sandboxem.

## Syscalls MACF

Można wchodzić w interakcję z MACF za pomocą niektórych syscalls zdefiniowanych w [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

W przypadku offensive reversing **`__mac_syscall`** nadal jest jednym z najlepszych punktów kontrolnych w userlandzie. Przekazuje **nazwę policy** (na przykład `"Sandbox"` lub `"AMFI"`), specyficzny dla policy selektor/kod oraz wskaźnik do **nieprzezroczystego bloku argumentów**, który zostanie obsłużony przez `mpo_policy_syscall`. Jest to bardzo przydatne podczas odwracania nieudokumentowanych operacji: najpierw w userlandzie, a dopiero później po przejściu do implementacji w kernelu. Sandbox często dociera do niego przez `__sandbox_ms`, a AMFI używa tego samego mechanizmu do podejmowania decyzji dotyczących policy dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktyczne wskazówki dotyczące badań ofensywnych

Najnowsze błędy w macOS rzadko „przełamują MACF” bezpośrednio. Zamiast tego zwykle wykorzystują **desynchronizację między decyzją MACF / Sandbox / TCC a późniejszą uprzywilejowaną operacją**.

### Atrybuty uruchamiania specyficzne dla policy jako dane wejściowe MACF

`posix_spawnattr_setmacpolicyinfo_np()` dołącza nazwę policy i nieprzezroczyste bajty do żądania `posix_spawn()`. XNU wyszukuje te bajty według `mpc_name` każdej zarejestrowanej policy i przekazuje je do jej hooka etykiety exec; hook launch-constraints również odczytuje pasujące bajty. Jest to osobna od `__mac_syscall` ścieżka danych wejściowych MACF, kontrolowana przez atakującego. Sprawdź, czy policy traktuje te bajty jako *dodatkowe ograniczenie*, czy pozwala im zastąpić istniejącą policy procesu nadrzędnego lub pliku wykonywalnego.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

W ramach kontrolowanego testu zacznij od ograniczonego procesu nadrzędnego i uruchom ten sam proces potomny **bez** atrybutu specyficznego dla policy oraz **z** nim. Porównaj efektywny dostęp procesu potomnego do zasobu, z którego proces nadrzędny nie może korzystać; samo pomyślne uruchomienie nie dowodzi przekroczenia granicy.<sup>[[12]](#references)[[13]](#references)</sup>

Podczas odwracania policy prześledź `mpo_cred_label_update_execve` i `mpo_proc_check_launch_constraints`, a następnie sprawdź, czy wywołujący może przekazać ten atrybut.<sup>[[10]](#references)[[11]](#references)</sup> Historycznie AMFI akceptowało przekazane launch constraints zamiast wbudowanych; Sandbox mógł zastosować do procesu potomnego nazwany wbudowany profil zamiast zachować ograniczenia procesu nadrzędnego.<sup>[[13]](#references)[[12]](#references)</sup> Oba zachowania zostały poprawione, więc nie zakładaj, że występują w obecnych systemach.<sup>[[13]](#references)[[12]](#references)</sup>

Zobacz [analizę launch-constraints](macos-launch-environment-constraints.md), aby poznać przypadek AMFI, oraz [debugowanie Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/), aby przetestować efektywną policy procesu potomnego.

### Kontrole ścieżek w brokerze a rzeczywista uprzywilejowana operacja

Powtarzającym się wzorcem jest sytuacja, w której uprzywilejowany daemon wykonuje **wstępną kontrolę w userlandzie** (na przykład `sandbox_check_by_audit_token()`) dla jednej wersji ścieżki, a później realizuje właściwą uprzywilejowaną operację przy użyciu **innej lub niekanonicznej ścieżki kontrolowanej przez atakującego**. Niedawne badania nad `diskarbitrationd` / `storagekitd` są dobrym przykładem: **directory traversal** oraz **podmiana symlinków** pozwalają atakującemu przejść walidację Sandbox w daemonie, a następnie zamontować system plików w wrażliwych lokalizacjach, takich jak `~/Library/Application Support/com.apple.TCC`, zmieniając błąd w **sandbox escape**, **local privilege escalation** lub **TCC bypass**, zależnie od wybranego punktu montowania.<sup>[[6]](#references)</sup>

Podczas audytu brokerów działających jako root, dostępnych z Sandbox, najpierw wyszukaj:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, funkcje kanonikalizacji ścieżek
- uprzywilejowane operacje docelowe, takie jak `mount`, `rename`, `copyfile`, metody XPC helper-tool lub dowolny kod, który później jako root korzysta ze ścieżek kontrolowanych przez atakującego

### Zaufane procesy pośredniczące z prywatnymi entitlementami

Innym praktycznym wzorcem jest uniknięcie bezpośredniego atakowania hooków MACF i zamiast tego wykorzystanie **zaufanego procesu**, który ma już uprawnienia potrzebne do przekroczenia granicy. Niedawne badania nad Safari/TCC są dobrym przykładem: interesującym prymitywem nie było „wyłączenie TCC w kernelu”, lecz modyfikowanie lokalnej policy/konfiguracji tak, aby proces podpisany przez Apple, posiadający **`com.apple.private.tcc.allow`**, wykonał wrażliwą operację w imieniu atakującego.<sup>[[8]](#references)</sup> W praktyce priorytetowymi celami audytu są daemony/aplikacje Apple łączące:

- **prywatne entitlementy** lub zasięg podobny do FDA
- zapisywalną konfigurację / bazę danych / punkt montowania / plik policy
- późniejszą wrażliwą operację kontrolowaną przez **Sandbox**, **AMFI**, **TCC** lub inną policy MACF

Aby przeprowadzić dokładniejsze odwracanie konkretnego produktu, zajrzyj na dedykowane strony dotyczące [macOS Sandbox](macos-sandbox/README.md) i [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (pełny wektor operacji policy MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (makra `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (kody uprawnień używane przez `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [Wywołanie systemowe AMFI (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Odkrywanie podatności Apple: audyt diskarbitrationd i storagekitd — część 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — narzędzie do wyszukiwania odwołań w XNU](https://newosxbook.com/xxr/index.php)
- [8] [Nowa podatność w macOS „HM Surf” może prowadzić do nieautoryzowanego dostępu do danych (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — ustawianie atrybutu policy dla posix_spawn](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — przekazywanie atrybutu etykiety exec specyficznego dla policy](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — przekazywanie policy launch-constraints](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Ucieczka z Apple Sandbox przez uruchomienie pliku wykonywalnego](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Omijanie Launch Constraints w macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
