# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** steht für **Mandatory Access Control Framework**, ein Sicherheitssystem, das in das Betriebssystem eingebaut ist, um deinen Computer zu schützen. Es arbeitet, indem es **strikte Regeln dafür festlegt, wer oder was auf bestimmte Teile des Systems zugreifen darf**, wie Dateien, Anwendungen und Systemressourcen. Durch das automatische Durchsetzen dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko von unbefugtem Zugriff oder bösartigen Aktivitäten reduziert wird.

Beachte, dass MACF eigentlich keine Entscheidungen trifft, da es Aktionen nur **abfängt**; die Entscheidungen überlässt es den **policy modules** (kernel extensions), die es aufruft, wie `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine policy kann enforcing sein (gibt 0 nicht-null bei einer Operation zurück)
- Eine policy kann monitoring sein (gibt 0 zurück, um nicht zu widersprechen, aber den Hook mitzunutzen, um etwas zu tun)
- Eine MACF static policy wird beim Boot installiert und wird NIEMALS entfernt
- Eine MACF dynamic policy wird von einem KEXT installiert (kextload) und kann hypothetisch mit kextunloaded entfernt werden
- In iOS sind nur static policies erlaubt und in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Prozess führt einen syscall/mach trap aus
2. Die relevante Funktion wird im Kernel aufgerufen
3. Die Funktion ruft MACF auf
4. MACF prüft policy modules, die angefordert haben, diese Funktion in ihrer policy zu hooken
5. MACF ruft die relevanten policies auf
6. Policies geben an, ob sie die Aktion erlauben oder verweigern

> [!CAUTION]
> Apple is the only one that can use the MAC Framework KPI.

Normalerweise rufen die Funktionen, die Berechtigungen mit MACF prüfen, das Makro `MAC_CHECK` auf. Wie im Fall eines syscalls zum Erstellen eines sockets, der die Funktion `mac_socket_check_create` aufruft, welche wiederum `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in security/mac_internal.h als folgt definiert:
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
Beachte, dass du, wenn du `check` in `socket_check_create` und `args...` in `(cred, domain, type, protocol)` umwandelst, Folgendes erhältst:
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
Das Erweitern der Helper-Makros zeigt den konkreten Kontrollfluss:
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
In other words, `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt und iteriert dann bedingt über dynamische Policies, emittiert die DTrace-Probes um jeden Hook herum und reduziert den Rückgabecode jedes Hooks über `mac_error_select()` auf das einzelne `error`-Ergebnis.


### Labels

MACF uses **labels**, die dann von den Policies verwendet werden, die prüfen, ob sie bestimmten Access gewähren sollen oder nicht. Die Code-Definition der labels-struct kann [hier gefunden werden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), und wird dann [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im **`struct ucred`**-Teil **`cr_label`** verwendet. Das label enthält Flags und eine Anzahl von **slots**, die von **MACF policies zum Zuweisen von pointers** verwendet werden können. Zum Beispiel wird Sanbox auf das container profile zeigen

## MACF Policies

Eine MACF Policy definiert **rules und conditions, die auf bestimmte kernel operations angewendet werden**.

Eine kernel extension könnte eine `mac_policy_conf`-Struktur konfigurieren und sie dann durch Aufruf von `mac_policy_register` registrieren. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Es ist einfach, die Kernel-Extensions zu identifizieren, die diese Policies konfigurieren, indem man die Aufrufe von `mac_policy_register` überprüft. Außerdem ist es durch das Disassemble der Extension auch möglich, die verwendete `mac_policy_conf`-Struct zu finden.

Beachte, dass MACF-Policies auch **dynamisch** registriert und deregistriert werden können.

Eines der Hauptfelder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld gibt an, für welche Operationen sich die Policy interessiert. Beachte, dass es Hunderte davon gibt, daher ist es möglich, alle auf null zu setzen und dann nur die auszuwählen, an denen die Policy interessiert ist. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Allerdings sind die **`mpo_policy_*`**-Hooks eine Ausnahme, weil **`mpo_hook_policy_init()`** ein Callback ist, das bei der Registrierung aufgerufen wird (also nach **`mac_policy_register()`**) und **`mpo_hook_policy_initbsd()`** während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem korrekt initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem kext registriert werden, um eine private **ioctl**-artige **interface** bereitzustellen. Dann kann ein User Client **`mac_syscall`** (#381) aufrufen und dabei als Parameter den **policy name** mit einem Integer **code** und optionalen **arguments** angeben.\
Zum Beispiel nutzt **`Sandbox.kext`** das sehr häufig.

Durch Prüfen von **`__DATA.__const*`** des kext ist es möglich, die `mac_policy_ops`-Struktur zu identifizieren, die bei der Registrierung der Policy verwendet wird. Man kann sie finden, weil ihr Pointer an einem Offset innerhalb von `mpo_policy_conf` liegt und auch wegen der Anzahl der NULL-Pointer, die sich in diesem Bereich befinden.

Außerdem ist es auch möglich, die Liste der kexts zu erhalten, die eine Policy konfiguriert haben, indem man aus dem Speicher die Struktur **`_mac_policy_list`** dumpt, die bei jeder registrierten Policy aktualisiert wird.

Du könntest auch das Tool `xnoop` verwenden, um alle im System registrierten Policies zu dumpen:
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
Und dann alle Prüfungen von check policy mit dumpen:
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

### Frühes Bootstrap und `mac_policy_init()`

- MACF wird sehr früh initialisiert. In `bootstrap_thread` (im XNU-Startcode) ruft XNU nach `ipc_bootstrap` `mac_policy_init()` auf (in `mac_base.c`).
- `mac_policy_init()` initialisiert die globale `mac_policy_list` (ein Array oder eine Liste von Policy-Slots) und richtet die Infrastruktur für MAC (Mandatory Access Control) innerhalb von XNU ein.
- Später wird `mac_policy_initmach()` aufgerufen, das die Kernel-Seite der Policy-Registrierung für integrierte oder gebündelte Policies verarbeitet.

### `mac_policy_initmach()` und das Laden von „security extensions“

- `mac_policy_initmach()` untersucht Kernel-Extensions (kexts), die vorab geladen wurden (oder in einer „policy injection“-Liste stehen), und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als „security extensions“ — also solche, die eine MAC-Policy implementieren oder sich in die MACF-Infrastruktur einklinken.
- Beispiele für Apple-kexts mit diesem Schlüssel sind **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** und andere (wie du bereits aufgelistet hast).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft dann während des Bootvorgangs ihre Registrierungsroutinen auf (via `mac_policy_register`), wobei sie in die `mac_policy_list` eingetragen werden.

- Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur bereit, mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen (vnode-Prüfungen, exec-Prüfungen, Label-Updates usw.).
- Die Load-Time-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was bedeutet: „muss früh geladen werden“ (späte Registrierungsversuche werden also abgelehnt).
- Nach der Registrierung erhält jedes Modul ein Handle und belegt einen Slot in `mac_policy_list`.
- Wenn später ein MAC-Hook ausgelöst wird (zum Beispiel vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um gemeinsame Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Seine Info.plist enthält `AppleSecurityExtension` und markiert es damit als Security-Policy.
- Im Rahmen des Kernel-Boots stellt die Kernel-Lade-Logik sicher, dass die „security policy“ (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme davon abhängen. Zum Beispiel „bereitet der Kernel sich auf bevorstehende Aufgaben vor, indem er … security policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.“
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

Beim Schreiben eines kext, der das MAC framework verwendet (d. h. `mac_policy_register()` usw. aufruft), musst du Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext- linker (kxld) diese Symbole auflösen kann. Um also zu deklarieren, dass ein `kext` von MACF abhängt, musst du dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`), dann verweist der kext auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und MAC hook function pointers. Um diese aufzulösen, musst du `com.apple.kpi.dsep` als Abhängigkeit angeben.

Beispiel für einen Info.plist-Ausschnitt (innerhalb deines .kext):
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
## MACF auf modernen macOS-Versionen

Auf modernen macOS-Versionen werden Apples Sicherheitsrichtlinien in der Regel nicht am besten als lose eigenständige `.kext`-Bundles betrachtet. Seit **macOS 11** werden Kernel-Extensions in **kernel collections** eingebunden; auf **Apple Silicon** gibt es kein separates **SystemKC**, und Drittanbieter-kexts werden erst ladbar, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** integriert wurden und ein Neustart erfolgt ist. Für die MACF-Analyse bedeutet das, dass eingebaute Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** mit `kmutil` in der Regel einfacher zu enumerieren sind als mit veralteten Tools wie `kextstat`.
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

Es ist üblich, Callouts zu MACF in Code wie **`#if CONFIG_MAC`**-bedingten Blöcken zu finden. Außerdem ist es innerhalb dieser Blöcke möglich, Aufrufe von `mac_proc_check*` zu finden, die MACF aufrufen, um **Berechtigungen zu prüfen**, um bestimmte Aktionen auszuführen. Außerdem lautet das Format der MACF-Callouts: **`mac_<object>_<opType>_opName`**.

Das Object ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check, der verwendet wird, um die Aktion zu erlauben oder zu verweigern. Es ist jedoch auch möglich, `notify` zu finden, was es dem kext ermöglicht, auf die angegebene Aktion zu reagieren.

Du kannst ein Beispiel in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) finden:

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

Dann ist es möglich, den Code von `mac_file_check_mmap` in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) zu finden
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
Which is calling the `MAC_CHECK` macro, whose code can be found in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Welche über alle registrierten MAC-Richtlinien iteriert, ihre Funktionen aufruft und die Ausgabe in der Variable `error` speichert, die nur durch `mac_error_select` mittels Success-Codes überschrieben werden kann. Wenn also eine Prüfung fehlschlägt, schlägt die gesamte Prüfung fehl und die Aktion wird nicht erlaubt.

> [!TIP]
> Beachte jedoch, dass nicht alle MACF callouts nur dazu verwendet werden, Aktionen zu verweigern. Zum Beispiel ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das die angeforderte Berechtigung gewährt, wenn eine Policy mit `0` antwortet:
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

Diese callas dienen dazu, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten **privileges** zu prüfen und bereitzustellen.\
Einige Kernel-Codes würden `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth credentials des Prozesses und einem der privileges codes aufrufen, was `mac_priv_check` aufruft, um zu sehen, ob eine Policy die Gewährung der Berechtigung **verweigert**, und anschließend ruft es `mac_priv_grant` auf, um zu prüfen, ob eine Policy das `privilege` gewährt.

### proc_check_syscall_unix

Dieser Hook erlaubt es, alle system calls abzufangen. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die diesen Code enthält:
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
Welches im aufrufenden Prozess-**Bitmask** prüft, ob der aktuelle Syscall `mac_proc_check_syscall_unix` aufrufen soll. Das liegt daran, dass Syscalls so häufig aufgerufen werden, dass es interessant ist, zu vermeiden, `mac_proc_check_syscall_unix` jedes Mal aufzurufen.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die Bitmask-Syscalls in einem Prozess setzt, von Sandbox aufgerufen wird, um Masken auf sandboxes Prozessen zu setzen.

## Exposed MACF syscalls

Es ist möglich, mit MACF über einige in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definierte Syscalls zu interagieren:
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
Für offensives Reversing ist **`__mac_syscall`** immer noch einer der besten Userland-Chokepoints. Er übergibt einen **Policy-Namen** (zum Beispiel `"Sandbox"` oder `"AMFI"`), einen **policy-spezifischen Selector/Code** und einen Pointer auf den **opaque argument blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn man undocumented operations zuerst aus Userland heraus zurückentwickelt und erst später in die Kernel-Implementierung wechselt. Sandbox erreicht ihn typischerweise über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld policy decisions.

## Praktische offensive Research-Notizen

Jüngste macOS-Bugs "brechen MACF" selten direkt. Stattdessen missbrauchen sie meist eine **Desynchronisation zwischen einer MACF / Sandbox / TCC-Entscheidung und der später ausgeführten privilegierten Aktion**.

### Broker-Pfadprüfungen vs. echte privilegierte Aktion

Ein wiederkehrendes Muster ist ein privilegierter Daemon, der einen **Userland-Pre-Check** (zum Beispiel `sandbox_check_by_audit_token()`) auf einer Version eines Pfads durchführt und später den eigentlichen privilegierten Sink mit einem **anderen oder nicht-kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Aktuelle `diskarbitrationd` / `storagekitd`-Research ist ein gutes Beispiel: **directory traversal** plus **symlink swaps** erlauben es dem Angreifer, die Sandbox-Validierung des Daemons zu bestehen und dann über sensible Orte wie `~/Library/Application Support/com.apple.TCC` zu mounten, wodurch der Bug je nach gewähltem Mount-Point zu einem **sandbox escape**, **local privilege escalation** oder **TCC bypass** wird.

Beim Auditing von Root-Brokern, die aus der Sandbox erreichbar sind, suche zuerst nach:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Pfad-Kanonisierungs-Helper
- privilegierten Sinks wie `mount`, `rename`, `copyfile`, Helper-Tool-XPC-Methoden oder allem, was später als root auf vom Angreifer kontrollierte Pfade zugreift

### Vertrauenswürdige Deputies mit privaten Entitlements

Ein weiteres praktisches Muster ist, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** zu missbrauchen, der bereits die nötigen Rechte besitzt, um die Grenze zu überschreiten. Aktuelle Safari/TCC-Research ist ein gutes Beispiel: Die interessante Primitive war nicht "TCC im Kernel deaktivieren", sondern die lokale Policy/Konfiguration so zu verändern, dass ein Apple-signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion in deinem Namen ausführt. In der Praxis sind hochwertige Auditing-Ziele Apple-Daemons/Apps, die Folgendes kombinieren:

- **private entitlements** oder FDA-ähnlichen Zugriff
- eine beschreibbare Config / Database / Mount-Point / Policy-Datei
- eine spätere sensible Operation, vermittelt durch **Sandbox**, **AMFI**, **TCC** oder eine andere MACF-Policy

Für tieferes produkt-spezifisches Reversing siehe die dedizierten Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md).

## Referenzen

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
