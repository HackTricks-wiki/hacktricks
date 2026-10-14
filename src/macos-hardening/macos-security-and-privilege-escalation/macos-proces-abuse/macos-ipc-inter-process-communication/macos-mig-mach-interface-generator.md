# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

MIG a été créé pour **simplifier la création de code Mach IPC**. Il **génère essentiellement le code nécessaire** pour que le serveur et le client puissent communiquer à partir d’une définition donnée. Même si le code généré est peu lisible, le développeur n’aura qu’à l’importer, et son code sera beaucoup plus simple qu’avant.<sup>[[1]](#references)</sup>

La définition est spécifiée en Interface Definition Language (IDL), avec l’extension `.defs`.

Ces définitions comportent 5 sections :

- **Déclaration du sous-système** : le mot-clé subsystem sert à indiquer le **nom** et l’**id**. Il est également possible de le marquer comme **`KernelServer`** si le serveur doit s’exécuter dans le noyau.<sup>[[4]](#references)</sup>
- **Inclusions et imports** : MIG utilise le préprocesseur C, ce qui lui permet d’utiliser des imports. De plus, il est possible d’utiliser `uimport` et `simport` pour le code généré côté utilisateur ou serveur.
- **Déclarations de types** : il est possible de définir des types de données, bien qu’en général, `mach_types.defs` et `std_types.defs` soient importés. Pour les types personnalisés, certaines syntaxes peuvent être utilisées :
  - \[i`n/out]tran`: fonction qui doit être appliquée à un message entrant ou sortant
  - `c[user/server]type`: correspondance vers un autre type C.
  - `destructor`: appeler cette fonction lorsque le type est libéré.
- **Opérations** : ce sont les définitions des méthodes RPC. Il en existe 5 types :
  - `routine`: attend une réponse
  - `simpleroutine`: n’attend pas de réponse
  - `procedure`: attend une réponse
  - `simpleprocedure`: n’attend pas de réponse
  - `function`: attend une réponse

### Exemple

Créez un fichier de définition, ici avec une fonction très simple :

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

Notez que le premier **argument est le port auquel se lier** et que MIG **gérera automatiquement le port de réponse** (sauf si `mig_get_reply_port()` est appelé dans le code client). De plus, les **ID des opérations** seront **séquentiels** à partir de l’ID de sous-système indiqué (ainsi, si une opération est dépréciée, elle est supprimée et `skip` est utilisé pour conserver son ID).

Utilisez maintenant MIG pour générer le code serveur et client qui pourra communiquer afin d’appeler la fonction Subtract :

```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```

Plusieurs nouveaux fichiers seront créés dans le répertoire courant.

> [!TIP]
> Vous trouverez un exemple plus complexe sur votre système avec : `mdfind mach_port.defs`\
> Vous pouvez le compiler depuis le même dossier que le fichier avec : `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

Dans les fichiers **`myipcServer.c`** et **`myipcServer.h`**, vous trouverez la déclaration et la définition de la structure **`SERVERPREFmyipc_subsystem`**, qui définit essentiellement la fonction à appeler en fonction de l’ID de message reçu (nous avons indiqué un numéro de départ de 500) :

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

À partir de la struct précédente, la fonction **`myipc_server_routine`** récupérera le **message ID** et renverra la fonction appropriée à appeler :

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

Dans cet exemple, nous n’avons défini qu’une seule fonction dans les définitions, mais si nous en avions défini davantage, elles auraient figuré dans le tableau de **`SERVERPREFmyipc_subsystem`**, la première étant associée à l’ID **500**, la deuxième à l’ID **501**…

Si la fonction devait envoyer une **réponse**, la fonction `mig_internal kern_return_t __MIG_check__Reply__<name>` existerait également.

Il est en fait possible d’identifier cette relation dans la structure **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem*to_name_map*\***` dans d’autres fichiers) :

```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
    { "Subtract", 500 }
#endif
```

Enfin, une autre fonction importante pour faire fonctionner le serveur sera **`myipc_server`**. C’est elle qui va réellement **appeler la fonction** associée à l’identifiant reçu :<sup>[[3]](#references)</sup>

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
	/* Minimal size: routine() will update it if different */
	OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
	OutHeadP->msgh_local_port = MACH_PORT_NULL;
	OutHeadP->msgh_id = InHeadP->msgh_id + 100;
	OutHeadP->msgh_reserved = 0;

	if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
		((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
		return FALSE;
	}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Examinez les lignes mises en évidence précédemment, qui accèdent à la fonction à appeler selon l’identifiant.

Voici le code permettant de créer un **serveur** et un **client** simples, dans lequel le client peut appeler les fonctions Subtract du serveur :

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

### Le NDR_record

Le NDR_record est exporté par `libsystem_kernel.dylib`, et c’est une struct qui permet à MIG de **transformer les données afin qu’elles soient indépendantes du système** utilisé, car MIG était conçu pour être utilisé entre différents systèmes (et pas uniquement sur la même machine).

C’est intéressant, car si `_NDR_record` apparaît comme dépendance dans un binaire (`jtool2 -S <binary> | grep NDR` ou `nm`), cela signifie que le binaire est un client ou un serveur MIG.

De plus, **les serveurs MIG** ont leur table de dispatch dans `__DATA.__const` (ou dans `__CONST.__constdata` dans le kernel de macOS et `__DATA_CONST.__const` dans les autres kernels \*OS). Celle-ci peut être extraite avec **`jtool2`**.

Et **les clients MIG** utilisent `__NDR_record` pour envoyer des messages aux serveurs avec `__mach_msg`.

## Analyse de binaires

### jtool

Comme de nombreux binaires utilisent maintenant MIG pour exposer des mach ports, il est intéressant de savoir **comment identifier l’utilisation de MIG** et **quelles fonctions MIG exécute** pour chaque ID de message.

[**jtool2 / disarm**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#disarm-old-jtool2) peut analyser les informations MIG d’un binaire Mach-O, indiquer l’ID du message et identifier la fonction à exécuter :

```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```

De plus, les fonctions MIG sont des wrappers autour de la fonction réellement appelée. Par conséquent, en obtenant le désassemblage et en recherchant `BL`, vous pourrez peut-être trouver la fonction réellement appelée :

```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```

### Assembleur

Il a été indiqué précédemment que la fonction chargée **d’appeler la fonction appropriée en fonction de l’ID du message reçu** était `myipc_server`. Cependant, vous n’aurez généralement pas les symboles du binaire (pas de noms de fonctions). Il est donc intéressant de **voir à quoi elle ressemble après décompilation**, car elle sera toujours très similaire (le code de cette fonction est indépendant des fonctions exposées) :

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
            rax = *(int32_t *)(var_10 + 0x14);
            // Call to sign_extend_64 that can help to identifyf this function
            // This stores in rax the pointer to the call that needs to be called
            // Check the used of the address 0x100004040 (functions addresses array)
            // 0x1f4 = 500 (the starting ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
            // If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
                    *(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
                    var_4 = 0x0;
            }
            else {
                    // Calculated address that calls the proper function with 2 arguments
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

{{#tab name="myipc_server decompiled 2"}}
Voici la même fonction décompilée avec une autre version gratuite de Hopper :

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
    r31 = r31 - 0x40;
    saved_fp = r29;
    stack[-8] = r30;
    var_10 = arg0;
    var_18 = arg1;
    // Initial instructions to find the proper function ponters
    *(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
    *(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
    *(int32_t *)(var_18 + 0x4) = 0x24;
    *(int32_t *)(var_18 + 0xc) = 0x0;
    *(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
    *(int32_t *)(var_18 + 0x10) = 0x0;
    r8 = *(int32_t *)(var_10 + 0x14);
    r8 = r8 - 0x1f4;
    if (r8 > 0x0) {
            if (CPU_FLAGS & G) {
                    r8 = 0x1;
            }
    }
    if ((r8 & 0x1) == 0x0) {
            r8 = *(int32_t *)(var_10 + 0x14);
            r8 = r8 - 0x1f4;
            if (r8 < 0x0) {
                    if (CPU_FLAGS & L) {
                            r8 = 0x1;
                    }
            }
            if ((r8 & 0x1) == 0x0) {
                    r8 = *(int32_t *)(var_10 + 0x14);
                    // 0x1f4 = 500 (the starting ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
                    r8 = *(r8 + 0x8);
                    var_20 = r8;
                    r8 = r8 - 0x0;
                    if (r8 != 0x0) {
                            if (CPU_FLAGS & NE) {
                                    r8 = 0x1;
                            }
                    }
                    // Same if else as in the previous version
                    // Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
                            var_4 = 0x0;
                    }
                    else {
                            // Call to the calculated address where the function should be
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

En fait, si vous consultez la fonction **`0x100004000`**, vous trouverez le tableau de structs **`routine_descriptor`**. Le premier élément de la struct est l’**adresse** à laquelle la **fonction** est implémentée, et la **struct occupe 0x28 octets**. Ainsi, tous les 0x28 octets (à partir de l’octet 0), vous pouvez récupérer 8 octets, qui correspondent à l’**adresse de la fonction** qui sera appelée :

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ces données peuvent être extraites [**à l’aide de ce script Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

Pour un workflow qui initialise un état et fuzz des séquences de messages MIG avec état, consultez [le fuzzing avec état de Mach IPC](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#stateful-mach-ipc-fuzzing).

### Débogage

Le code généré par MIG appelle également `kernel_debug` pour enregistrer les opérations à l’entrée et à la sortie. Il est possible de les inspecter à l’aide de **`trace`** ou de **`kdv`** : `kdv all | grep MIG`



## References

- [1] [bootstrap_cmds — `migcom.tproj` (le compilateur MIG lui-même)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (exemple de définition de sous-système MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (structure de l’en-tête d’un message Mach)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (définition MIG du sous-système task)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
