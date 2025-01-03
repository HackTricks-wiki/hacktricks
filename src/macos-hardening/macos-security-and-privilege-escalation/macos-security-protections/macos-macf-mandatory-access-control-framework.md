# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

**MACF** steht für **Mandatory Access Control Framework**, ein Sicherheitssystem, das in das Betriebssystem integriert ist, um Ihren Computer zu schützen. Es funktioniert, indem es **strenge Regeln festlegt, wer oder was auf bestimmte Teile des Systems zugreifen kann**, wie Dateien, Anwendungen und Systemressourcen. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko unbefugten Zugriffs oder bösartiger Aktivitäten verringert wird.

Beachten Sie, dass MACF keine Entscheidungen trifft, da es lediglich **Aktionen abfängt**; die Entscheidungen überlässt es den **Richtlinienmodulen** (Kernel-Erweiterungen), die es aufruft, wie `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

### Ablauf

1. Der Prozess führt einen syscall/mach trap aus
2. Die relevante Funktion wird im Kernel aufgerufen
3. Die Funktion ruft MACF auf
4. MACF überprüft die Richtlinienmodule, die angefordert haben, diese Funktion in ihrer Richtlinie zu hooken
5. MACF ruft die relevanten Richtlinien auf
6. Die Richtlinien geben an, ob sie die Aktion erlauben oder ablehnen

> [!CAUTION]
> Apple ist der einzige, der das MAC Framework KPI verwenden kann.

### Labels

MACF verwendet **Labels**, die dann von den Richtlinien überprüft werden, ob sie den Zugriff gewähren sollen oder nicht. Der Code der Deklaration der Labels-Struktur kann [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) gefunden werden, der dann innerhalb der **`struct ucred`** in [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet wird. Das Label enthält Flags und eine Anzahl von **Slots**, die von **MACF-Richtlinien zur Zuweisung von Zeigern** verwendet werden können. Zum Beispiel wird Sandbox auf das Containerprofil verweisen.

## MACF-Richtlinien

Eine MACF-Richtlinie definiert **Regeln und Bedingungen, die auf bestimmte Kerneloperationen angewendet werden**.&#x20;

Eine Kernel-Erweiterung könnte eine `mac_policy_conf`-Struktur konfigurieren und sie dann registrieren, indem sie `mac_policy_register` aufruft. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Es ist einfach, die Kernel-Erweiterungen, die diese Richtlinien konfigurieren, zu identifizieren, indem man die Aufrufe von `mac_policy_register` überprüft. Darüber hinaus ist es auch möglich, beim Disassemblieren der Erweiterung die verwendete `mac_policy_conf`-Struktur zu finden.

Beachten Sie, dass MACF-Richtlinien auch **dynamisch** registriert und deregistriert werden können.

Eines der Hauptfelder der `mac_policy_conf` ist das **`mpc_ops`**. Dieses Feld gibt an, an welchen Operationen die Richtlinie interessiert ist. Beachten Sie, dass es Hunderte davon gibt, sodass es möglich ist, alle auf Null zu setzen und dann nur die auszuwählen, an denen die Richtlinie interessiert ist. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Die **`mpo_policy_*`** Hooks sind jedoch eine Ausnahme, da `mpo_hook_policy_init()` ein Callback ist, das bei der Registrierung aufgerufen wird (also nach `mac_policy_register()`) und `mpo_hook_policy_initbsd()` während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem ordnungsgemäß initialisiert wurde.

Darüber hinaus kann der **`mpo_policy_syscall`** Hook von jedem Kext registriert werden, um einen privaten **ioctl**-Stilaufruf **Schnittstelle** bereitzustellen. Dann kann ein Benutzerclient `mac_syscall` (#381) aufrufen und als Parameter den **Policy-Namen** mit einem ganzzahligen **Code** und optionalen **Argumenten** angeben.\
Zum Beispiel verwendet **`Sandbox.kext`** dies häufig.

Durch Überprüfung des Kexts **`__DATA.__const*`** ist es möglich, die `mac_policy_ops` Struktur zu identifizieren, die bei der Registrierung der Policy verwendet wird. Es ist möglich, sie zu finden, da ihr Zeiger an einem Offset innerhalb von `mpo_policy_conf` liegt und auch wegen der Anzahl der NULL-Zeiger, die sich in diesem Bereich befinden werden.

Darüber hinaus ist es auch möglich, die Liste der Kexts zu erhalten, die eine Policy konfiguriert haben, indem man die Struktur **`_mac_policy_list`** aus dem Speicher dumpet, die mit jeder registrierten Policy aktualisiert wird.

## MACF-Initialisierung

MACF wird sehr früh initialisiert. Es wird im `bootstrap_thread` von XNU eingerichtet: nach `ipc_bootstrap` erfolgt ein Aufruf von `mac_policy_init()`, der die `mac_policy_list` initialisiert, und kurz darauf wird `mac_policy_initmach()` aufgerufen. Unter anderem wird diese Funktion alle Apple-Kexts mit dem Schlüssel `AppleSecurityExtension` in ihrer Info.plist wie `ALF.kext`, `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext` und `TMSafetyNet.kext` abrufen und laden.

## MACF-Callouts

Es ist üblich, Callouts zu MACF in Code zu finden, wie: **`#if CONFIG_MAC`** bedingte Blöcke. Darüber hinaus ist es innerhalb dieser Blöcke möglich, Aufrufe von `mac_proc_check*` zu finden, die MACF aufrufen, um **Berechtigungen zu überprüfen**, um bestimmte Aktionen durchzuführen. Darüber hinaus hat das Format der MACF-Callouts die Form: **`mac_<object>_<opType>_opName`**.

Das Objekt ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check, der verwendet wird, um die Aktion zu erlauben oder abzulehnen. Es ist jedoch auch möglich, `notify` zu finden, was dem Kext erlaubt, auf die gegebene Aktion zu reagieren.

Ein Beispiel finden Sie unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

Dann ist es möglich, den Code von `mac_file_check_mmap` unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) zu finden.
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
Welches das `MAC_CHECK`-Makro aufruft, dessen Code in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) gefunden werden kann.
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
Welche alle registrierten mac-Richtlinien durchläuft, ihre Funktionen aufruft und die Ausgabe in der Fehler-Variable speichert, die nur durch `mac_error_select` durch Erfolgscodes überschreibbar ist, sodass, wenn eine Überprüfung fehlschlägt, die gesamte Überprüfung fehlschlägt und die Aktion nicht erlaubt wird.

> [!TIP]
> Denken Sie jedoch daran, dass nicht alle MACF-Callouts nur dazu verwendet werden, Aktionen zu verweigern. Zum Beispiel ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das das angeforderte Privileg gewährt, wenn eine Richtlinie mit einer 0 antwortet:
>
> ```c
> /*
>  * MAC_GRANT führt die vorgesehene Überprüfung durch, indem es die Richtlinien
>  * Modulliste durchläuft und mit jeder überprüft, wie sie über die
>  * Anfrage denkt. Im Gegensatz zu MAC_CHECK gewährt es, wenn eine der Richtlinien '0' zurückgibt,
>  * und gibt andernfalls EPERM zurück. Beachten Sie, dass es seinen Wert über
>  * 'error' im Geltungsbereich des Aufrufers zurückgibt.
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

Diese Aufrufe sind dazu gedacht, (Dutzende von) **Privilegien** zu überprüfen und bereitzustellen, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definiert sind.\
Einige Kernel-Code würde `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Anmeldeinformationen des Prozesses und einem der Privilegien-Codes aufrufen, der `mac_priv_check` aufruft, um zu sehen, ob eine Richtlinie das Gewähren des Privilegs **verweigert** und dann `mac_priv_grant` aufruft, um zu sehen, ob eine Richtlinie das `Privileg` gewährt.

### proc_check_syscall_unix

Dieser Hook ermöglicht es, alle Systemaufrufe abzufangen. In `bsd/dev/[i386|arm]/systemcalls.c` ist es möglich, die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die diesen Code enthält:
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
Welche im aufrufenden Prozess **Bitmaske** überprüft, ob der aktuelle Syscall `mac_proc_check_syscall_unix` aufrufen sollte. Dies liegt daran, dass Syscalls so häufig aufgerufen werden, dass es interessant ist, zu vermeiden, `mac_proc_check_syscall_unix` jedes Mal aufzurufen.

Beachten Sie, dass die Funktion `proc_set_syscall_filter_mask()`, die die Bitmaske für Syscalls in einem Prozess festlegt, von Sandbox aufgerufen wird, um Masken für sandboxed Prozesse festzulegen.

## Exponierte MACF-Syscalls

Es ist möglich, über einige in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definierte Syscalls mit MACF zu interagieren:
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
## Referenzen

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
