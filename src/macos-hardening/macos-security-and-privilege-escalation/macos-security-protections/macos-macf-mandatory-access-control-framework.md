# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**MACF** steht für **Mandatory Access Control Framework**, ein in das Betriebssystem integriertes Sicherheitssystem, das dabei hilft, deinen Computer zu schützen. Es funktioniert, indem es **strikte Regeln darüber festlegt, wer oder was auf bestimmte Teile des Systems zugreifen kann**, wie Dateien, Anwendungen und Systemressourcen. Durch das automatische Durchsetzen dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko unbefugten Zugriffs oder bösartiger Aktivitäten reduziert wird.

Beachte, dass MACF selbst keine Entscheidungen trifft, da es Aktionen nur **abfängt**; die Entscheidungen werden den **Policy-Modulen** (Kernel-Erweiterungen) überlassen, die es aufruft, z. B. `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine Policy kann durchsetzen (return 0 non-zero on some operation)
- Eine Policy kann überwachen (return 0, so as not to object but piggyback on hook to do something)
- Eine statische MACF-Policy wird beim Boot installiert und WIRD NIEMALS entfernt
- Eine dynamische MACF-Policy wird von einer KEXT installiert (kextload) und könnte hypothetisch mit kextunloaded entfernt werden
- In iOS sind nur statische Policies erlaubt; in macOS sind statische + dynamische erlaubt.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Ablauf

1. Ein Prozess führt einen syscall/mach trap aus
2. Die relevante Funktion wird im Kernel aufgerufen
3. Die Funktion ruft MACF auf
4. MACF prüft die Policy-Module, die verlangt haben, diese Funktion in ihrer Policy zu hooken
5. MACF ruft die relevanten Policies auf
6. Die Policies geben an, ob sie die Aktion zulassen oder verweigern

> [!CAUTION]
> Apple ist der Einzige, der das MAC Framework KPI verwenden kann.

In der Regel rufen Funktionen, die Berechtigungen mit MACF prüfen, das Makro `MAC_CHECK` auf. Zum Beispiel ruft ein Syscall zum Erstellen eines Sockets die Funktion `mac_socket_check_create` auf, die wiederum `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in security/mac_internal.h definiert als:
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
Beachte, dass durch die Umwandlung von `check` in `socket_check_create` und von `args...` in `(cred, domain, type, protocol)` Folgendes entsteht:
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
Das Erweitern der Hilfs-Makros zeigt den konkreten Kontrollfluss:
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
Mit anderen Worten führt `MAC_CHECK(socket_check_create, ...)` zuerst die statischen Policies aus, sperrt bedingt und iteriert über die dynamischen Policies, emittiert die DTrace-Probes um jeden Hook und fasst die Rückgabecodes aller Hooks via `mac_error_select()` zu einem einzigen `error`-Ergebnis zusammen.


### Labels

MACF verwendet **labels**, die von den Policies genutzt werden, um zu prüfen, ob ein Zugriff gewährt werden soll oder nicht. Der Code der Labels-Struct-Deklaration ist [hier zu finden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), die dann innerhalb der **`struct ucred`** in [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im **`cr_label`**-Teil verwendet wird. Das Label enthält Flags und eine Anzahl von **slots**, die von **MACF policies genutzt werden können, um Pointer zuzuweisen**. Zum Beispiel zeigt Sanbox auf das Container-Profil

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die bei bestimmten Kernel-Operationen angewendet werden**.

Eine Kernel-Erweiterung kann eine `mac_policy_conf`-Struct konfigurieren und diese dann durch Aufruf von `mac_policy_register` registrieren. Aus [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Es ist einfach, die Kernel-Erweiterungen zu identifizieren, die diese Policies konfigurieren, indem man die Aufrufe von `mac_policy_register` überprüft. Außerdem ist es durch das Disassemblieren der Erweiterung möglich, die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Policies auch **dynamisch** registriert und deregistriert werden können.

Eines der wichtigsten Felder der `mac_policy_conf` ist das **`mpc_ops`**. Dieses Feld gibt an, an welchen Operationen die Policy interessiert ist. Beachte, dass es Hunderte davon gibt, daher ist es möglich, alle auf Null zu setzen und anschließend nur diejenigen auszuwählen, an denen die Policy interessiert ist. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Allerdings sind die **`mpo_policy_*`**-Hooks eine Ausnahme, weil `mpo_hook_policy_init()` ein Callback ist, das bei der Registrierung aufgerufen wird (also nach `mac_policy_register()`), und `mpo_hook_policy_initbsd()` während einer späten Registrierung aufgerufen wird, sobald das BSD-Subsystem korrekt initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem kext registriert werden, um eine private **ioctl**-artige Aufruf-**Schnittstelle** bereitzustellen. Ein User-Client wird dann in der Lage sein, `mac_syscall` (#381) aufzurufen und dabei als Parameter den **policy name** mit einem ganzzahligen **code** und optionalen **arguments** anzugeben.\
Zum Beispiel nutzt der **`Sandbox.kext`** das häufig.

Das Überprüfen des kext-Abschnitts **`__DATA.__const*`** ermöglicht es, die `mac_policy_ops`-Struktur zu identifizieren, die bei der Registrierung der Policy verwendet wird. Man kann sie finden, weil ihr Pointer in einem Offset innerhalb von `mpo_policy_conf` liegt und auch wegen der Anzahl an NULL pointers, die in diesem Bereich vorhanden sind.

Außerdem ist es möglich, die Liste der kexts zu erhalten, die eine Policy konfiguriert haben, indem man aus dem Speicher die Struktur **`_mac_policy_list`** ausliest, die mit jeder registrierten Policy aktualisiert wird.

Man kann auch das Tool `xnoop` verwenden, um alle im System registrierten Policies zu dumpen:
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
Und dann dumpen Sie alle checks der check policy mit:
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
## MACF-Initialisierung in XNU

### Früher Bootstrap und mac_policy_init()

- MACF wird sehr früh initialisiert. In `bootstrap_thread` (im XNU-Startup-Code) ruft XNU nach `ipc_bootstrap` `mac_policy_init()` (in `mac_base.c`) auf.
- `mac_policy_init()` initialisiert die globale `mac_policy_list` (ein Array oder eine Liste von Policy-Slots) und richtet die Infrastruktur für MAC (Mandatory Access Control) innerhalb von XNU ein.
- Später wird `mac_policy_initmach()` aufgerufen, das die Kernel-Seite der Policy-Registrierung für eingebaute oder gebündelte Policies behandelt.

### `mac_policy_initmach()` und das Laden von “security extensions”

- `mac_policy_initmach()` untersucht kernel extensions (kexts), die vorgeladen sind (oder in einer “policy injection”-Liste stehen), und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist angeben, gelten als “security extensions” — also solche, die eine MAC-Policy implementieren oder sich in die MACF-Infrastruktur einklinken.
- Beispiele für Apple-kexts mit diesem Schlüssel sind **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, unter anderen (wie bereits aufgelistet).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft dann während des Bootvorgangs ihre Registrierungsroutinen (über `mac_policy_register`) auf, wobei sie in die `mac_policy_list` eingefügt werden.

- Jedes Policy-Modul (kext) liefert eine `mac_policy_conf`-Struktur mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen (vnode-Checks, exec-Checks, Label-Updates usw.).
- Die Ladezeit-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was „muss früh geladen werden“ bedeutet (sodass späte Registrierungsversuche abgelehnt werden).
- Nach der Registrierung erhält jedes Modul einen Handle und belegt einen Slot in der `mac_policy_list`.
- Wenn später ein MAC-Hook aufgerufen wird (zum Beispiel bei vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um kollektive Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Deren Info.plist enthält `AppleSecurityExtension`, wodurch sie als Security-Policy markiert ist.
- Im Rahmen des Kernel-Boots sorgt die Kernel-Lade-Logik dafür, dass die “security policy” (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme davon abhängen. Zum Beispiel bereitet der Kernel Aufgaben vor, indem er … security policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.
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
## KPI-Abhängigkeit & com.apple.kpi.dsep in MAC policy kexts

Beim Schreiben eines kext, das das MAC-Framework verwendet (z. B. Aufrufe von `mac_policy_register()` usw.), müssen Sie Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext-Linker (kxld) diese Symbole auflösen kann. Um also anzugeben, dass ein `kext` von MACF abhängt, müssen Sie dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`); das kext wird dann auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und MAC-Hook-Funktionszeiger verweisen. Um diese aufzulösen, müssen Sie `com.apple.kpi.dsep` als Abhängigkeit auflisten.

Beispiel Info.plist Ausschnitt (innerhalb Ihres .kext):
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
## MACF-Aufrufe

Es ist üblich, Aufrufe an MACF im Code zu finden, z. B. in bedingten Blöcken wie: **`#if CONFIG_MAC`**. Innerhalb dieser Blöcke findet man außerdem Aufrufe wie `mac_proc_check*`, die MACF aufrufen, um **Berechtigungen zu prüfen**, bevor bestimmte Aktionen ausgeführt werden. Das Format der MACF-Aufrufe ist: **`mac_<object>_<opType>_opName`**.

Das Objekt ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check, der verwendet wird, um die Aktion zu erlauben oder zu verweigern. Es ist jedoch auch möglich, `notify` zu finden, wodurch das kext auf die jeweilige Aktion reagieren kann.

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

Den Code von `mac_file_check_mmap` findet man in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
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
Das ruft das `MAC_CHECK`-Makro auf, dessen Code unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) zu finden ist.
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
Which will go over all the registered mac policies calling their functions and storing the output inside the error variable, which will only be overridable by `mac_error_select` by success codes so if any check fails the complete check will fail and the action won't be allowed.

> [!TIP]
> Behalte aber im Hinterkopf, dass nicht alle MACF-Aufrufe nur dazu dienen, Aktionen zu verweigern. Zum Beispiel ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das das angeforderte Privileg gewährt, wenn irgendeine Richtlinie mit 0 antwortet:
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

Diese Aufrufe dienen dazu, (Dutzende von) **Privilegien** abzufragen und bereitzustellen, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definiert sind.\
Einige Kernel-Komponenten rufen `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Credentials des Prozesses und einem der Privileg-Codes auf; dieser ruft dann `mac_priv_check` auf, um zu prüfen, ob eine Richtlinie die Vergabe des Privilegs **verweigert**, und anschließend `mac_priv_grant`, um zu prüfen, ob eine Richtlinie das `privilege` gewährt.

### proc_check_syscall_unix

Dieser Hook erlaubt das Abfangen aller Systemaufrufe. In `bsd/dev/[i386|arm]/systemcalls.c` kann man die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) sehen, die folgenden Code enthält:
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
Damit wird in der **bitmask** des aufrufenden Prozesses überprüft, ob der aktuelle syscall `mac_proc_check_syscall_unix` aufgerufen werden sollte. Dies liegt daran, dass syscalls so häufig aufgerufen werden, dass es sinnvoll ist, nicht bei jedem Aufruf `mac_proc_check_syscall_unix` aufzurufen.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die bitmask für syscalls in einem Prozess setzt, von Sandbox aufgerufen wird, um Masken für gesandboxte Prozesse zu setzen.

## Exponierte MACF syscalls

Es ist möglich, mit MACF über einige in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definierte syscalls zu interagieren:
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
## Quellen

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
