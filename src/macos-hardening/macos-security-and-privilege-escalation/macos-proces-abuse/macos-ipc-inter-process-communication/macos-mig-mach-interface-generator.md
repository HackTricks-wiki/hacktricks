# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

MIG a été créé pour **simplifier le processus de création de code Mach IPC**. Il **génère le code nécessaire** pour que le serveur et le client communiquent avec une définition donnée. Même si le code généré est moche, un développeur n'aura qu'à l'importer et son code sera beaucoup plus simple qu'auparavant.

La définition est spécifiée en Interface Definition Language (IDL) en utilisant l'extension `.defs`.

Ces définitions ont 5 sections :

- **Déclaration de sous-système** : Le mot-clé sous-système est utilisé pour indiquer le **nom** et l'**id**. Il est également possible de le marquer comme **`KernelServer`** si le serveur doit s'exécuter dans le noyau.
- **Inclusions et imports** : MIG utilise le préprocesseur C, donc il est capable d'utiliser des imports. De plus, il est possible d'utiliser `uimport` et `simport` pour le code généré par l'utilisateur ou le serveur.
- **Déclarations de types** : Il est possible de définir des types de données bien que généralement il importera `mach_types.defs` et `std_types.defs`. Pour des types personnalisés, une certaine syntaxe peut être utilisée :
- \[i`n/out]tran : Fonction qui doit être traduite d'un message entrant ou vers un message sortant
- `c[user/server]type` : Mapping vers un autre type C.
- `destructor` : Appelez cette fonction lorsque le type est libéré.
- **Opérations** : Ce sont les définitions des méthodes RPC. Il existe 5 types différents :
- `routine` : S'attend à une réponse
- `simpleroutine` : Ne s'attend pas à une réponse
- `procedure` : S'attend à une réponse
- `simpleprocedure` : Ne s'attend pas à une réponse
- `function` : S'attend à une réponse

### Exemple

Créez un fichier de définition, dans ce cas avec une fonction très simple :
```cpp:myipc.defs
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
Notez que le premier **argument est le port à lier** et MIG **gérera automatiquement le port de réponse** (à moins d'appeler `mig_get_reply_port()` dans le code client). De plus, l'**ID des opérations** sera **séquentiel** en commençant par l'ID de sous-système indiqué (donc si une opération est obsolète, elle est supprimée et `skip` est utilisé pour continuer à utiliser son ID).

Maintenant, utilisez MIG pour générer le code serveur et client qui pourra communiquer entre eux pour appeler la fonction Subtract :
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Plusieurs nouveaux fichiers seront créés dans le répertoire actuel.

> [!TIP]
> Vous pouvez trouver un exemple plus complexe dans votre système avec : `mdfind mach_port.defs`\
> Et vous pouvez le compiler depuis le même dossier que le fichier avec : `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Dans les fichiers **`myipcServer.c`** et **`myipcServer.h`**, vous pouvez trouver la déclaration et la définition de la structure **`SERVERPREFmyipc_subsystem`**, qui définit essentiellement la fonction à appeler en fonction de l'ID de message reçu (nous avons indiqué un numéro de départ de 500) :

{{#tabs}}
{{#tab name="myipcServer.c"}}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{{#endtab}}

{{#tab name="myipcServer.h"}}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{{#endtab}}
{{#endtabs}}

En fonction de la structure précédente, la fonction **`myipc_server_routine`** obtiendra l'**ID de message** et renverra la fonction appropriée à appeler :
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
Dans cet exemple, nous avons seulement défini 1 fonction dans les définitions, mais si nous avions défini plus de fonctions, elles auraient été à l'intérieur du tableau de **`SERVERPREFmyipc_subsystem`** et la première aurait été assignée à l'ID **500**, la deuxième à l'ID **501**...

Si la fonction devait envoyer une **réponse**, la fonction `mig_internal kern_return_t __MIG_check__Reply__<name>` existerait également.

En fait, il est possible d'identifier cette relation dans la struct **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* dans d'autres fichiers) :
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Enfin, une autre fonction importante pour faire fonctionner le serveur sera **`myipc_server`**, qui est celle qui va réellement **appeler la fonction** liée à l'identifiant reçu :

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Taille minimale : routine() l'actualisera si différente */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Vérifiez les lignes précédemment mises en surbrillance accédant à la fonction à appeler par ID.

Le code suivant crée un **serveur** et un **client** simples où le client peut appeler les fonctions Soustraire du serveur :

{{#tabs}}
{{#tab name="myipc_server.c"}}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{{#endtab}}

{{#tab name="myipc_client.c"}}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{{#endtab}}
{{#endtabs}}

### L'enregistrement NDR

L'enregistrement NDR est exporté par `libsystem_kernel.dylib`, et c'est une structure qui permet à MIG de **transformer les données de manière à ce qu'elles soient indépendantes du système** sur lequel elles sont utilisées, car MIG a été conçu pour être utilisé entre différents systèmes (et pas seulement sur la même machine).

C'est intéressant car si `_NDR_record` est trouvé dans un binaire en tant que dépendance (`jtool2 -S <binary> | grep NDR` ou `nm`), cela signifie que le binaire est un client ou un serveur MIG.

De plus, les **serveurs MIG** ont la table de dispatch dans `__DATA.__const` (ou dans `__CONST.__constdata` dans le noyau macOS et `__DATA_CONST.__const` dans d'autres noyaux \*OS). Cela peut être extrait avec **`jtool2`**.

Et les **clients MIG** utiliseront le `__NDR_record` pour envoyer avec `__mach_msg` aux serveurs.

## Analyse Binaire

### jtool

Comme de nombreux binaires utilisent maintenant MIG pour exposer des ports mach, il est intéressant de savoir comment **identifier que MIG a été utilisé** et les **fonctions que MIG exécute** avec chaque ID de message.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) peut analyser les informations MIG d'un binaire Mach-O en indiquant l'ID de message et en identifiant la fonction à exécuter :
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
De plus, les fonctions MIG ne sont que des wrappers de la fonction réelle qui est appelée, ce qui signifie qu'en obtenant sa désassemblage et en recherchant BL, vous pourriez être en mesure de trouver la fonction réelle qui est appelée :
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Il a été précédemment mentionné que la fonction qui s'occupera de **appeler la fonction correcte en fonction de l'ID de message reçu** était `myipc_server`. Cependant, vous n'aurez généralement pas les symboles du binaire (pas de noms de fonctions), donc il est intéressant de **vérifier à quoi cela ressemble décompilé** car cela sera toujours très similaire (le code de cette fonction est indépendant des fonctions exposées) :

{{#tabs}}
{{#tab name="myipc_server décompilé 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Instructions initiales pour trouver les pointeurs de fonction appropriés
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Appel à sign_extend_64 qui peut aider à identifier cette fonction
// Cela stocke dans rax le pointeur vers l'appel qui doit être appelé
// Vérifiez l'utilisation de l'adresse 0x100004040 (tableau d'adresses de fonctions)
// 0x1f4 = 500 (l'ID de départ)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Si - sinon, le if retourne faux, tandis que le else appelle la fonction correcte et retourne vrai
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Adresse calculée qui appelle la fonction appropriée avec 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>

{{#endtab}}

{{#tab name="myipc_server décompilé 2"}}
C'est la même fonction décompilée dans une version différente de Hopper gratuite :

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Instructions initiales pour trouver les pointeurs de fonction appropriés
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (l'ID de départ)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// Même si - sinon que dans la version précédente
// Vérifiez l'utilisation de l'adresse 0x100004040 (tableau d'adresses de fonctions)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Appel à l'adresse calculée où la fonction devrait être
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

En fait, si vous allez à la fonction **`0x100004000`**, vous trouverez le tableau de **`routine_descriptor`** structs. Le premier élément de la struct est l'**adresse** où la **fonction** est implémentée, et la **struct prend 0x28 octets**, donc chaque 0x28 octets (à partir de l'octet 0) vous pouvez obtenir 8 octets et cela sera l'**adresse de la fonction** qui sera appelée :

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ces données peuvent être extraites [**en utilisant ce script Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Le code généré par MIG appelle également `kernel_debug` pour générer des journaux sur les opérations d'entrée et de sortie. Il est possible de les vérifier en utilisant **`trace`** ou **`kdv`** : `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
