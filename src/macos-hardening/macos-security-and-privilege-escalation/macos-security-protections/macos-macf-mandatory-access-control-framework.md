# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**MACF** steht für **Mandatory Access Control Framework** und ist ein Sicherheitssystem, das in das Betriebssystem eingebaut ist, um deinen Computer zu schützen. Es funktioniert, indem es **strikte Regeln darüber festlegt, wer oder was auf bestimmte Teile des Systems zugreifen darf**, wie Dateien, Anwendungen und Systemressourcen. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko von unbefugtem Zugriff oder bösartigen Aktivitäten reduziert wird.

Beachte, dass MACF eigentlich keine Entscheidungen trifft, sondern Aktionen nur **abfängt**. Die Entscheidungen überlässt es den **policy modules** (kernel extensions), die es aufruft, wie `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine policy kann durchsetzen (bei einer Operation 0 ungleich 0 zurückgeben)
- Eine policy kann überwachen (0 zurückgeben, also keinen Einwand erheben, aber den Hook nutzen, um etwas zu tun)
- Eine MACF static policy wird beim Booten installiert und wird NIE entfernt
- Eine MACF dynamic policy wird von einem KEXT (kextload) installiert und könnte hypothetisch kextunloaded werden
- In iOS sind nur static policies erlaubt, und in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. Process führt einen syscall/mach trap aus
2. Die relevante Funktion wird innerhalb des Kernels aufgerufen
3. Die Funktion ruft MACF auf
4. MACF prüft policy modules, die für ihre policy das Hooken dieser Funktion angefordert haben
5. MACF ruft die relevanten policies auf
6. Policies geben an, ob sie die Aktion erlauben oder verweigern

> [!CAUTION]
> Apple ist die einzige, die das MAC Framework KPI verwenden kann.

Normalerweise rufen die Funktionen, die Berechtigungen mit MACF prüfen, das Makro `MAC_CHECK` auf. Wie im Fall eines syscalls zum Erstellen eines sockets, der die Funktion `mac_socket_check_create` aufruft, welche `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in security/mac_internal.h wie folgt definiert:
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
Beachte, dass du durch das Transformieren von `check` in `socket_check_create` und `args...` in `(cred, domain, type, protocol)` Folgendes erhältst:
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
In anderen Worten, `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt und iteriert dann bedingt über dynamische Policies, emittiert die DTrace-Probes um jeden Hook herum und reduziert den Rückgabecode jedes Hooks über `mac_error_select()` zu einem einzelnen `error`-Resultat.


### Labels

MACF verwendet **labels**, die dann von den Policies genutzt werden, um zu prüfen, ob sie bestimmten Zugriff gewähren sollen oder nicht. Der Code der Deklaration der labels-Struktur kann [hier gefunden werden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), und wird dann in **`struct ucred`** [**hier**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet. Das label enthält Flags und eine Anzahl von **slots**, die von **MACF policies zum Zuweisen von Pointern** verwendet werden können. Zum Beispiel wird Sanbox auf das container profile zeigen

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die auf bestimmte kernel operations angewendet werden**.

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
Es ist leicht, die Kernel-Extensions zu identifizieren, die diese Policies konfigurieren, indem man die Aufrufe von `mac_policy_register` überprüft. Außerdem ist es durch die Analyse des Disassemblies der Extension auch möglich, die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Policies auch **dynamisch** registriert und deregistriert werden können.

Eines der Hauptfelder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld gibt an, an welchen opreations die Policy interessiert ist. Beachte, dass es hundres davon gibt, daher ist es möglich, alle auf null zu setzen und dann nur die auszuwählen, an denen die Policy interessiert ist. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Allerdings sind die **`mpo_policy_*`**-Hooks eine Ausnahme, weil **`mpo_hook_policy_init()`** ein Callback ist, das bei der Registrierung aufgerufen wird (also nach **`mac_policy_register()`**), und **`mpo_hook_policy_initbsd()`** während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem korrekt initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem kext registriert werden, um eine private **ioctl**-ähnliche Call-**Schnittstelle** bereitzustellen. Dann kann ein User Client **`mac_syscall`** (#381) aufrufen und dabei als Parameter den **Policy-Namen** mit einem ganzzahligen **Code** und optionalen **Argumenten** angeben.\
Zum Beispiel nutzt **`Sandbox.kext`** dies sehr häufig.

Durch das Prüfen von **`__DATA.__const*`** des kext ist es möglich, die **`mac_policy_ops`**-Struktur zu identifizieren, die bei der Registrierung der Policy verwendet wird. Man kann sie finden, weil sich ihr Pointer an einem Offset innerhalb von **`mpo_policy_conf`** befindet und auch wegen der Anzahl der NULL-Pointer, die in diesem Bereich vorhanden sein werden.

Außerdem ist es auch möglich, die Liste der kexts zu erhalten, die eine Policy konfiguriert haben, indem man die Struktur **`_mac_policy_list`** aus dem Speicher dumpt, die bei jeder registrierten Policy aktualisiert wird.

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
Und dann alle Checks der Check Policy mit ausgeben:
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
- Später wird `mac_policy_initmach()` aufgerufen, das die Kernel-Seite der Policy-Registrierung für eingebaute oder gebündelte Policies behandelt.

### `mac_policy_initmach()` und das Laden von “security extensions”

- `mac_policy_initmach()` untersucht Kernel Extensions (kexts), die vorab geladen sind (oder in einer “policy injection”-Liste), und prüft in deren Info.plist den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als “security extensions” — also solche, die eine MAC-Policy implementieren oder in die MACF-Infrastruktur einhängen.
- Beispiele für Apple-kexts mit diesem Schlüssel sind **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** und andere (wie du bereits aufgelistet hast).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft dann während des Bootvorgangs ihre Registrierungsroutinen auf (über `mac_policy_register`), wobei sie in die `mac_policy_list` eingefügt werden.

- Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur bereit, mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen (vnode-Prüfungen, exec-Prüfungen, Label-Updates usw.).
- Die Load-Time-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was bedeutet: “muss früh geladen werden” (späte Registrierungsversuche werden also abgelehnt).
- Sobald ein Modul registriert ist, erhält es einen Handle und belegt einen Slot in der `mac_policy_list`.
- Wenn später ein MAC-Hook aufgerufen wird (zum Beispiel vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um gemeinsame Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Seine Info.plist enthält `AppleSecurityExtension` und markiert es damit als Security-Policy.
- Im Rahmen des Kernel-Boots stellt die Kernel-Ladelogik sicher, dass die “security policy” (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme davon abhängen. Zum Beispiel “bereitet der Kernel sich auf bevorstehende Aufgaben vor, indem er … security policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox und Quarantine policy.”
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

Beim Schreiben eines kext, der das MAC framework verwendet (d. h. `mac_policy_register()` usw. aufruft), musst du Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext linker (kxld) diese Symbole auflösen kann. UM also zu deklarieren, dass ein `kext` von MACF abhängt, musst du dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`), dann verweist der kext auf Symbole wie `mac_policy_register`, `mac_policy_unregister` und MAC hook function pointers. Um diese aufzulösen, musst du `com.apple.kpi.dsep` als Abhängigkeit angeben.

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

Auf modernen macOS-Versionen werden Apples Sicherheitsrichtlinien normalerweise nicht am besten als lose eigenständige `.kext`-Bundles betrachtet. Seit **macOS 11** werden Kernel-Erweiterungen in **kernel collections** eingebunden; auf **Apple Silicon** gibt es kein separates **SystemKC**, und Drittanbieter-kexts werden erst ladbar, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** eingebaut wurden und ein Neustart erfolgt ist. Für MACF-Recherche bedeutet das, dass integrierte Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** sich normalerweise mit `kmutil` einfacher auflisten lassen als mit veralteten Tools wie `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Auf Apple Silicon: Wenn ein security kext nicht in der BootKC ist, prüfe als Nächstes die AuxKC. Das ist meist nützlicher, als nach einem eigenständigen bundle unter `/System/Library/Extensions` zu suchen.

## MACF Callouts

Es ist üblich, Callouts zu MACF im Code in Form von **`#if CONFIG_MAC`**-Bedingungsblöcken zu finden. Außerdem ist es innerhalb dieser Blöcke möglich, Aufrufe zu `mac_proc_check*` zu finden, die MACF aufrufen, um **Berechtigungen zu prüfen**, bestimmte Aktionen auszuführen. Außerdem ist das Format der MACF Callouts: **`mac_<object>_<opType>_opName`**.

Das object ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise check, was verwendet wird, um die Aktion zu erlauben oder zu verweigern. Es ist jedoch auch möglich, `notify` zu finden, was es dem kext erlaubt, auf die gegebene Aktion zu reagieren.

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
Welcher den `MAC_CHECK`-Makro aufruft, dessen Code in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) zu finden ist
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
Die alle registrierten MAC-Policies durchlaufen, ihre Funktionen aufrufen und die Ausgabe in der Variable `error` speichern, die nur durch `mac_error_select` mittels Success-Codes überschrieben werden kann; wenn also irgendeine Prüfung fehlschlägt, schlägt die gesamte Prüfung fehl und die Aktion wird nicht erlaubt.

> [!TIP]
> Allerdings gilt: Nicht alle MACF-Callouts werden nur verwendet, um Aktionen zu verweigern. Zum Beispiel ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das die angeforderte Privilege gewährt, wenn irgendeine Policy mit `0` antwortet:
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

Diese Callas sollen die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten (Dutzende von) **Privileges** prüfen und bereitstellen.\
Einige Kernel-Teile würden `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth-Credentials des Prozesses und einem der Privilege-Codes aufrufen; das ruft `mac_priv_check` auf, um zu sehen, ob eine Policy die Gewährung des Privileges **verweigert**, und danach `mac_priv_grant`, um zu sehen, ob eine Policy das `privilege` gewährt.

### proc_check_syscall_unix

Dieser Hook ermöglicht es, alle Systemaufrufe abzufangen. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die diesen Code enthält:
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
Welches im aufrufenden Prozess-**Bitmask** prüft, ob der aktuelle syscall `mac_proc_check_syscall_unix` aufrufen sollte. Das liegt daran, dass syscalls so häufig aufgerufen werden, dass es interessant ist, zu vermeiden, `mac_proc_check_syscall_unix` jedes Mal aufzurufen.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, welche die Bitmask-Syscalls in einem Prozess setzt, von Sandbox aufgerufen wird, um Masken auf sandboxed Prozessen zu setzen.

## Exposed MACF syscalls

Es ist möglich, über einige syscalls zu interagieren, die in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definiert sind:
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
Für offensives Reversing ist **`__mac_syscall`** immer noch einer der besten Userland-Chokepoints. Er führt einen **Policy-Namen** mit (zum Beispiel `"Sandbox"` oder `"AMFI"`), einen **policy-spezifischen Selector/Code** und einen Pointer auf den **opaken Argument-Blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn man nicht dokumentierte Operationen zuerst aus Userland heraus analysiert und erst später in die Kernel-Implementierung pivotiert. Sandbox erreicht ihn typischerweise über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld-Policy-Entscheidungen.

## Praktische offensive Research-Notizen

Aktuelle macOS-Bugs "brechen MACF" selten direkt. Stattdessen missbrauchen sie meist eine **Desynchronisation zwischen einer MACF / Sandbox / TCC-Entscheidung und der privilegierten Aktion, die später ausgeführt wird**.

### Broker-Path-Checks vs. echte privilegierte Aktion

Ein wiederkehrendes Muster ist, dass ein privilegierter Daemon einen **Userland-Pre-Check** (zum Beispiel `sandbox_check_by_audit_token()`) auf einer Version eines Pfads durchführt und später den eigentlichen privilegierten Sink mit einem **anderen oder nicht-kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Aktuelle `diskarbitrationd` / `storagekitd`-Research ist ein gutes Beispiel: **Directory Traversal** plus **Symlink-Swaps** erlauben es dem Angreifer, die Sandbox-Validierung des Daemons zu bestehen und dann über sensible Orte wie `~/Library/Application Support/com.apple.TCC` zu mounten, wodurch der Bug je nach gewähltem Mount-Point zu einem **Sandbox Escape**, einer **lokalen Privilege Escalation** oder einem **TCC-Bypass** wird.

Wenn du Root-Broker prüfst, die aus der Sandbox erreichbar sind, suche zuerst nach:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Path-Kanonisierungs-Helpern
- privilegierten Sinks wie `mount`, `rename`, `copyfile`, Helper-Tool-XPC-Methoden oder allem, was später von Root aus vom Angreifer kontrollierte Pfade anfasst

### Vertrauenswürdige Deputies mit privaten Entitlements

Ein weiteres praktisches Muster ist, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** zu missbrauchen, der bereits die Rechte besitzt, die Grenze zu überschreiten. Aktuelle Safari/TCC-Research ist ein gutes Beispiel: Die interessante Primitive war nicht "TCC im Kernel deaktivieren", sondern lokale Policy/Konfiguration so zu verändern, dass ein Apple-signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion in deinem Auftrag ausführt. In der Praxis sind hochinteressante Audit-Ziele Apple-Daemons/-Apps, die Folgendes kombinieren:

- **private Entitlements** oder FDA-ähnliche Reichweite
- eine beschreibbare Config / Datenbank / Mount-Point / Policy-Datei
- eine spätere sensible Operation, vermittelt durch **Sandbox**, **AMFI**, **TCC** oder eine andere MACF-Policy

Für tieferes produkt-spezifisches Reversing schau dir die dedizierten Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md) an.

## Referenzen

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
