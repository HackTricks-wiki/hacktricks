# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**MACF** steht für **Mandatory Access Control Framework** und ist ein in das Betriebssystem integriertes Sicherheitssystem, das zum Schutz deines Computers beiträgt. Es funktioniert, indem **strikte Regeln dafür festgelegt werden, wer oder was auf bestimmte Teile des Systems** wie Dateien, Anwendungen und Systemressourcen zugreifen darf. Durch die automatische Durchsetzung dieser Regeln stellt MACF sicher, dass nur autorisierte Benutzer und Prozesse bestimmte Aktionen ausführen können, wodurch das Risiko eines unbefugten Zugriffs oder bösartiger Aktivitäten reduziert wird.

Beachte, dass MACF selbst eigentlich keine Entscheidungen trifft, da es Aktionen lediglich **abfängt**. Die Entscheidungen überlässt es den **policy modules** (Kernel-Erweiterungen), die es aufruft, wie `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` und `mcxalr.kext`.

- Eine policy kann erzwingend sein (bei einer Operation 0 oder einen Wert ungleich 0 zurückgeben)
- Eine policy kann zur Überwachung dienen (0 zurückgeben, um keinen Einwand zu erheben, aber den Hook zu nutzen, um etwas auszuführen)
- Eine statische MACF policy wird beim Booten installiert und wird NIEMALS entfernt
- Eine dynamische MACF policy wird von einem KEXT (`kextload`) installiert und kann theoretisch per `kextunload` entladen werden
- Unter iOS sind nur statische policies erlaubt, unter macOS statische + dynamische.<sup>[[7]](#references)</sup>

### Ablauf

1. Der Prozess führt einen syscall/Mach trap aus
2. Die relevante Funktion wird innerhalb des Kernels aufgerufen
3. Die Funktion ruft MACF auf
4. MACF überprüft die policy modules, die in ihrer policy das Hooking dieser Funktion angefordert haben
5. MACF ruft die relevanten policies auf
6. Die policies geben an, ob sie die Aktion erlauben oder verweigern

> [!CAUTION]
> Apple ist die einzige Instanz, die das MAC Framework KPI verwenden kann.

Normalerweise rufen die Funktionen, die Berechtigungen mit MACF überprüfen, das Makro `MAC_CHECK` auf. So auch im Fall eines syscalls zum Erstellen eines Sockets, der die Funktion `mac_socket_check_create` aufruft, die wiederum `MAC_CHECK(socket_check_create, cred, domain, type, protocol);` aufruft. Außerdem ist das Makro `MAC_CHECK` in `security/mac_internal.h` definiert als:<sup>[[3]](#references)</sup>
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
Beachte, dass du durch die Umwandlung von `check` in `socket_check_create` und von `args...` in `(cred, domain, type, protocol)` Folgendes erhältst:
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
Das Auflösen der Helper-Makros zeigt den konkreten Kontrollfluss:
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
Mit anderen Worten: `MAC_CHECK(socket_check_create, ...)` durchläuft zuerst die statischen Policies, sperrt und iteriert bedingt über die dynamischen Policies, gibt die DTrace-Probes rund um jeden Hook aus und führt den Rückgabecode jedes Hooks über `mac_error_select()` zum einzelnen Ergebnis `error` zusammen.


### Labels

MACF verwendet **Labels**, die dann von den Policies verwendet werden, um zu prüfen, ob sie einen Zugriff gewähren sollen oder nicht. Der Code für die Deklaration der Label-Struktur ist [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) zu finden. Diese wird anschließend innerhalb von **`struct ucred`** [hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) im Teil **`cr_label`** verwendet. Das Label enthält Flags und eine Anzahl von **Slots**, die von **MACF policies zur Zuweisung von Zeigern** verwendet werden können. Beispielsweise verweist Sandbox auf das Container-Profil.

## MACF Policies

Eine MACF Policy definiert **Regeln und Bedingungen, die bei bestimmten Kernel-Operationen angewendet werden**.

Eine Kernel-Erweiterung könnte eine `mac_policy_conf`-Struktur konfigurieren und sie anschließend durch den Aufruf von `mac_policy_register` registrieren. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Die Kernel-Extensions, die diese Richtlinien konfigurieren, lassen sich leicht identifizieren, indem die Aufrufe von `mac_policy_register` überprüft werden. Außerdem ist es durch die Überprüfung des Disassemblats der Extension möglich, die verwendete `mac_policy_conf`-Struktur zu finden.

Beachte, dass MACF-Richtlinien auch **dynamisch** registriert und deregistriert werden können.

Eines der wichtigsten Felder von `mac_policy_conf` ist **`mpc_ops`**. Dieses Feld legt fest, an welchen Operationen die Richtlinie interessiert ist. Beachte, dass es Hunderte davon gibt. Daher ist es möglich, zunächst alle auf null zu setzen und anschließend nur diejenigen auszuwählen, an denen die Richtlinie interessiert ist. Von [hier](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
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
Fast alle Hooks werden von MACF zurückgerufen, wenn eine dieser Operationen abgefangen wird. Die **`mpo_policy_*`**-Hooks bilden jedoch eine Ausnahme, da **`mpo_hook_policy_init()`** ein Callback ist, der bei der Registrierung aufgerufen wird (also nach **`mac_policy_register()`**), während **`mpo_hook_policy_initbsd()`** während der späten Registrierung aufgerufen wird, sobald das BSD-Subsystem ordnungsgemäß initialisiert wurde.

Außerdem kann der **`mpo_policy_syscall`**-Hook von jedem kext registriert werden, um ein privates **ioctl**-artiges Aufruf-**interface** bereitzustellen. Ein User-Client kann dann **`mac_syscall`** (#381) aufrufen und als Parameter den **policy name** zusammen mit einem Integer-**code** und optionalen **arguments** angeben.\
Zum Beispiel verwendet **`Sandbox.kext`** dies häufig.

Durch die Überprüfung von **`__DATA.__const*`** des kext ist es möglich, die beim Registrieren der Policy verwendete Struktur `mac_policy_ops` zu identifizieren. Sie kann gefunden werden, weil sich ihr Pointer an einem Offset innerhalb von `mpo_policy_conf` befindet und außerdem aufgrund der Anzahl der NULL-Pointer, die in diesem Bereich vorhanden sein werden.

Außerdem ist es möglich, die Liste der kexts abzurufen, die eine Policy konfiguriert haben, indem die Struktur **`_mac_policy_list`** aus dem Speicher gedumpt wird. Diese wird mit jeder registrierten Policy aktualisiert.

Du kannst auch das Tool `xnoop` verwenden, um alle im System registrierten Policies zu dumpen:
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
Und anschließend alle Checks der Check-Policy mit folgendem Befehl ausgeben:
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

- MACF wird sehr früh initialisiert. In `bootstrap_thread` (im XNU-Startcode) ruft XNU nach `ipc_bootstrap` `mac_policy_init()` (in `mac_base.c`) auf.
- `mac_policy_init()` initialisiert die globale `mac_policy_list` (ein Array oder eine Liste von Policy-Slots) und richtet die Infrastruktur für MAC (Mandatory Access Control) innerhalb von XNU ein.
- Später wird `mac_policy_initmach()` aufgerufen, das die kernel-seitige Registrierung von Policies für integrierte oder gebündelte Policies übernimmt.

### `mac_policy_initmach()` und das Laden von „security extensions“

- `mac_policy_initmach()` untersucht vorab geladene Kernel-Erweiterungen (kexts) oder solche in einer „policy injection“-Liste und prüft deren Info.plist auf den Schlüssel `AppleSecurityExtension`.
- Kexts, die `<key>AppleSecurityExtension</key>` (oder `true`) in ihrer Info.plist deklarieren, gelten als „security extensions“ – also als Erweiterungen, die eine MAC policy implementieren oder sich in die MACF-Infrastruktur einklinken.
- Beispiele für Apple-kexts mit diesem Schlüssel sind **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** und weitere (wie bereits aufgelistet).
- Der Kernel stellt sicher, dass diese kexts früh geladen werden, und ruft anschließend deren Registrierungsroutinen (über `mac_policy_register`) während des Bootvorgangs auf, wobei sie in die `mac_policy_list` eingefügt werden.

- Jedes Policy-Modul (kext) stellt eine `mac_policy_conf`-Struktur mit Hooks (`mpc_ops`) für verschiedene MAC-Operationen bereit (vnode-Prüfungen, exec-Prüfungen, Label-Aktualisierungen usw.).
- Die Load-Time-Flags können `MPC_LOADTIME_FLAG_NOTLATE` enthalten, was bedeutet: „muss früh geladen werden“ (spätere Registrierungsversuche werden abgelehnt).
- Nach der Registrierung erhält jedes Modul ein Handle und belegt einen Slot in der `mac_policy_list`.
- Wenn später ein MAC-Hook aufgerufen wird (beispielsweise für vnode-Zugriff, exec usw.), iteriert MACF über alle registrierten Policies, um gemeinsame Entscheidungen zu treffen.

- Insbesondere ist **AMFI** (Apple Mobile File Integrity) eine solche security extension. Seine Info.plist enthält `AppleSecurityExtension`, wodurch es als Security Policy gekennzeichnet wird.
- Im Rahmen des Kernel-Bootvorgangs stellt die Kernel-Ladelogik sicher, dass die „security policy“ (AMFI usw.) bereits aktiv ist, bevor viele Subsysteme von ihr abhängen. Der Kernel „bereitet sich beispielsweise auf bevorstehende Aufgaben vor, indem er … security policy lädt, einschließlich AppleMobileFileIntegrity (AMFI), Sandbox und Quarantine policy.“
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

Wenn Sie ein kext schreiben, das das MAC framework verwendet (d. h. `mac_policy_register()` usw. aufruft), müssen Sie Abhängigkeiten von KPIs (Kernel Programming Interfaces) deklarieren, damit der kext-Linker (kxld) diese Symbole auflösen kann. Um also zu deklarieren, dass ein `kext` von MACF abhängt, müssen Sie dies in der `Info.plist` mit `com.apple.kpi.dsep` angeben (`find . Info.plist | grep AppleSecurityExtension`). Anschließend referenziert das kext Symbole wie `mac_policy_register`, `mac_policy_unregister` und Zeiger auf MAC hook functions. Um diese aufzulösen, müssen Sie `com.apple.kpi.dsep` als Abhängigkeit auflisten.

Beispiel für einen Info.plist-Ausschnitt (innerhalb Ihres .kext):
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
## MACF in modernen macOS-Versionen

Unter modernen macOS-Versionen lassen sich die Apple-Sicherheitsrichtlinien gewöhnlich nicht am besten als lose, eigenständige `.kext`-Bundles betrachten. Seit **macOS 11** werden Kernel-Erweiterungen in **kernel collections** verknüpft; auf **Apple Silicon** gibt es keine separate **SystemKC**, und Drittanbieter-kexts können erst geladen werden, nachdem sie in die **Auxiliary Kernel Collection (AuxKC)** integriert wurden und ein Neustart erfolgt ist. Für die MACF-Forschung bedeutet dies, dass integrierte Richtlinien wie **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** oder **Quarantine** gewöhnlich mit `kmutil` leichter aufgelistet werden können als mit veralteten Tools wie `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> Auf Apple Silicon: Wenn sich ein Security-kext nicht in der BootKC befindet, prüfe als Nächstes die AuxKC. Das ist normalerweise hilfreicher, als nach einem eigenständigen Bundle unter `/System/Library/Extensions` zu suchen.

## MACF Callouts

Es ist üblich, in Code Callouts zu MACF zu finden, die in bedingten Blöcken wie **`#if CONFIG_MAC`** definiert sind. Außerdem können innerhalb dieser Blöcke Aufrufe von `mac_proc_check*` gefunden werden, die MACF aufrufen, um die **Berechtigungen** zur Ausführung bestimmter Aktionen zu prüfen. Das Format der MACF-Callouts lautet: **`mac_<object>_<opType>_opName`**.

Das Objekt ist eines der folgenden: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
Der `opType` ist normalerweise `check`, das verwendet wird, um die Aktion zu erlauben oder abzulehnen. Es ist jedoch auch möglich, `notify` zu finden, wodurch der kext auf die angegebene Aktion reagieren kann.

Ein Beispiel ist unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) zu finden:

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

Anschließend kann der Code von `mac_file_check_mmap` unter [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) gefunden werden.
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
Die das Makro `MAC_CHECK` aufruft, dessen Code in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> zu finden ist.
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
Welche alle registrierten MAC policies durchläuft, ihre Funktionen aufruft und die Ausgabe in der Variable `error` speichert. Diese kann durch `mac_error_select` nur mit Erfolgscodes überschrieben werden. Wenn also eine Prüfung fehlschlägt, schlägt die vollständige Prüfung fehl und die Aktion wird nicht erlaubt.

> [!TIP]
> Denke jedoch daran, dass nicht alle MACF callouts ausschließlich zum Verweigern von Aktionen verwendet werden. Beispielsweise ruft `mac_priv_grant` das Makro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274) auf, das das angeforderte privilege gewährt, wenn eine policy mit 0 antwortet:
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

Diese callouts dienen dazu, die in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) definierten **privileges** zu prüfen und bereitzustellen.\
Bestimmter Kernel-Code ruft `priv_check_cred()` aus [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) mit den KAuth credentials des Prozesses und einem der privilege-Codes auf. Dieser ruft `mac_priv_check` auf, um zu prüfen, ob eine policy die Vergabe des privilege **verweigert**, und anschließend `mac_priv_grant`, um zu prüfen, ob eine policy das `privilege` gewährt.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Dieser hook ermöglicht das Abfangen aller system calls. In `bsd/dev/[i386|arm]/systemcalls.c` ist die deklarierte Funktion [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25) zu sehen, die folgenden Code enthält:
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
Dabei wird im aufrufenden Prozess anhand der **bitmask** geprüft, ob der aktuelle syscall `mac_proc_check_syscall_unix` aufrufen soll. Da syscalls so häufig aufgerufen werden, ist es sinnvoll, den Aufruf von `mac_proc_check_syscall_unix` jedes Mal zu vermeiden.

Beachte, dass die Funktion `proc_set_syscall_filter_mask()`, die die bitmask der syscalls in einem Prozess festlegt, von Sandbox aufgerufen wird, um Masken für sandboxed Prozesse zu setzen.

## Exposed MACF syscalls

Es ist möglich, über einige in [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) definierte syscalls mit MACF zu interagieren:
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
Für offensives Reversing ist **`__mac_syscall`** weiterhin einer der besten Chokepoints im Userland. Es überträgt einen **policy name** (beispielsweise `"Sandbox"` oder `"AMFI"`), einen **policy-specific selector/code** und einen Pointer auf den **opaque argument blob**, der von `mpo_policy_syscall` verarbeitet wird. Das ist sehr nützlich, wenn zunächst undokumentierte Operationen aus dem Userland heraus analysiert werden und erst später in die Kernel-Implementierung gewechselt wird. Sandbox erreicht diese Funktion häufig über `__sandbox_ms`, und AMFI verwendet denselben Mechanismus für dyld-Policy-Entscheidungen.<sup>[[2]](#references)[[5]](#references)</sup>

## Praktische Hinweise für offensive Forschung

Aktuelle macOS-Bugs "brechen MACF" nur selten direkt. Stattdessen missbrauchen sie gewöhnlich eine **Desynchronisierung zwischen einer MACF- / Sandbox- / TCC-Entscheidung und der privilegierten Aktion, die später ausgeführt wird**.

### Broker-Pfadprüfungen vs. tatsächliche privilegierte Aktion

Ein wiederkehrendes Muster besteht darin, dass ein privilegierter Daemon eine **Userland-Vorprüfung** (beispielsweise `sandbox_check_by_audit_token()`) für eine Version eines Pfads durchführt und später den tatsächlichen privilegierten Sink mit einem **anderen oder nicht kanonischen, vom Angreifer kontrollierten Pfad** ausführt. Die aktuelle Forschung zu `diskarbitrationd` / `storagekitd` ist ein gutes Beispiel: **directory traversal** plus **symlink swaps** ermöglichen es dem Angreifer, die Sandbox-Validierung des Daemons zu passieren und anschließend sensible Speicherorte wie `~/Library/Application Support/com.apple.TCC` zu mounten. Dadurch wird der Bug abhängig vom gewählten Mountpoint zu einem **sandbox escape**, einer **local privilege escalation** oder einem **TCC bypass**.<sup>[[6]](#references)</sup>

Beim Auditieren von Root-Brokern, die aus der Sandbox erreichbar sind, sollte zunächst nach Folgendem gesucht werden:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, Hilfsfunktionen zur Pfadkanonisierung
- privilegierte Sinks wie `mount`, `rename`, `copyfile`, XPC-Methoden von Helper-Tools oder alles, was später als Root auf vom Angreifer kontrollierte Pfade zugreift

### Vertrauenswürdige Deputies mit privaten Entitlements

Ein weiteres praktisches Muster besteht darin, MACF-Hooks nicht direkt anzugreifen, sondern stattdessen einen **vertrauenswürdigen Prozess** zu missbrauchen, der bereits über die für das Überschreiten der Grenze erforderlichen Rechte verfügt. Die aktuelle Safari-/TCC-Forschung ist ein gutes Beispiel: Die interessante Primitive bestand nicht darin, "TCC im Kernel zu deaktivieren", sondern die lokale Policy bzw. Konfiguration so zu verändern, dass ein von Apple signierter Prozess mit **`com.apple.private.tcc.allow`** die sensible Aktion stellvertretend für den Angreifer ausführt.<sup>[[8]](#references)</sup> In der Praxis sind Apple-Daemons und -Apps mit den folgenden Eigenschaften besonders lohnende Audit-Ziele:

- **private Entitlements** oder ein FDA-ähnlicher Zugriff
- eine beschreibbare Konfiguration / Datenbank / ein Mountpoint / eine Policy-Datei
- eine spätere sensible Operation, die durch **Sandbox**, **AMFI**, **TCC** oder eine andere MACF-Policy vermittelt wird

Für ein tiefergehendes produktspezifisches Reversing sollten die dedizierten Seiten zu [macOS Sandbox](macos-sandbox/README.md) und [macOS TCC](macos-tcc/README.md) konsultiert werden.

## Referenzen

- [1] [XNU — `security/mac_policy.h` (der vollständige Vektor der MACF-Policy-Operationen)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`-Makros)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (von `priv_check`/`priv_grant` verwendete Privileg-Codes)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Aufdeckung von Apple-Schwachstellen: Audit von diskarbitrationd und storagekitd, Teil 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference-Tool](https://newosxbook.com/xxr/index.php)
- [8] [Neue macOS-Schwachstelle "HM Surf" könnte zu unbefugtem Datenzugriff führen (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)

{{#include ../../../banners/hacktricks-training.md}}
