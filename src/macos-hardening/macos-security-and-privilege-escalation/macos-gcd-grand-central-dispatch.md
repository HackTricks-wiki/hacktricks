# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

**Grand Central Dispatch (GCD),** également connu sous le nom de **libdispatch** (`libdispatch.dyld`), est disponible à la fois sur macOS et iOS. Il s'agit d'une technologie développée par Apple pour optimiser la prise en charge par les applications de l'exécution concurrente (multithread) sur du matériel multicœur.

**GCD** fournit et gère des **files FIFO** auxquelles votre application peut **soumettre des tâches** sous forme d'**objets block**. Les blocks soumis aux files de dispatch sont **exécutés sur un pool de threads** entièrement géré par le système. GCD crée automatiquement des threads pour exécuter les tâches des files de dispatch et planifie l'exécution de ces tâches sur les cœurs disponibles.

> [!TIP]
> En résumé, pour exécuter du code en **parallèle**, les processus peuvent envoyer des **blocks de code à GCD**, qui se chargera de leur exécution. Les processus ne créent donc pas de nouveaux threads ; **GCD exécute le code fourni avec son propre pool de threads** (qui peut augmenter ou diminuer selon les besoins).

Cela est très utile pour gérer efficacement l'exécution parallèle, en réduisant considérablement le nombre de threads créés par les processus et en optimisant l'exécution parallèle. C'est idéal pour les tâches nécessitant **un haut niveau de parallélisme** (brute-forcing ?) ou pour les tâches qui ne doivent pas bloquer le thread principal : par exemple, sur iOS, le thread principal gère les interactions avec l'interface utilisateur. Toute autre fonctionnalité susceptible de faire se bloquer l'application (recherche, accès au web, lecture d'un fichier...) est donc gérée de cette manière.

### Blocks

Un block est une **section de code autonome** (comme une fonction avec des arguments renvoyant une valeur) et peut également spécifier des variables liées.\
Cependant, au niveau du compilateur, les blocks n'existent pas : ce sont des `os_object`s. Chacun de ces objets est constitué de deux structures :

- **block literal** :
- Il commence par le champ **`isa`**, qui pointe vers la classe du block :
- `NSConcreteGlobalBlock` (blocks provenant de `__DATA.__const`)
- `NSConcreteMallocBlock` (blocks situés dans le heap)
- `NSConcreateStackBlock` (blocks situés dans la stack)
- Il contient des **`flags`** (indiquant les champs présents dans le descripteur du block) ainsi que quelques octets réservés
- Le pointeur de fonction à appeler
- Un pointeur vers le descripteur du block
- Les variables importées par le block (le cas échéant)
- **block descriptor** : sa taille dépend des données présentes (comme indiqué par les flags précédents)
- Il contient quelques octets réservés
- Sa taille
- Il contient généralement un pointeur vers une signature de style Objective-C permettant de déterminer l'espace nécessaire pour les paramètres (flag `BLOCK_HAS_SIGNATURE`)
- Si des variables sont référencées, ce block contient également des pointeurs vers un helper de copie (qui copie la valeur au début) et un helper de libération (qui la libère).

### Files

Une file de dispatch est un objet nommé qui fournit un ordre FIFO pour l'exécution des blocks.

Les blocks sont placés dans des files pour être exécutés, lesquelles prennent en charge 2 modes : `DISPATCH_QUEUE_SERIAL` et `DISPATCH_QUEUE_CONCURRENT`. Bien sûr, la file **serial** **ne présente pas de problèmes de race condition**, car un block ne sera pas exécuté tant que le précédent ne sera pas terminé. En revanche, **l'autre type de file peut en présenter**.

Files par défaut :

- `.main-thread` : provient de `dispatch_get_main_queue()`
- `.libdispatch-manager` : gestionnaire de files de GCD
- `.root.libdispatch-manager` : gestionnaire de files de GCD
- `.root.maintenance-qos` : tâches de priorité la plus faible
- `.root.maintenance-qos.overcommit`
- `.root.background-qos` : disponible sous le nom de `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos` : disponible sous le nom de `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos` : disponible sous le nom de `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos` : disponible sous le nom de `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos` : priorité la plus élevée
- `.root.background-qos.overcommit`

Notez que c'est le système qui décide **quels threads gèrent quelles files à chaque instant** (plusieurs threads peuvent travailler sur la même file, ou un même thread peut travailler sur différentes files à un moment donné).

#### Attributs

Lors de la création d'une file avec **`dispatch_queue_create`**, le troisième argument est un `dispatch_queue_attr_t`, qui est généralement soit `DISPATCH_QUEUE_SERIAL` (qui est en réalité NULL), soit `DISPATCH_QUEUE_CONCURRENT`, qui est un pointeur vers une structure `dispatch_queue_attr_t` permettant de contrôler certains paramètres de la file.

### Objets Dispatch

Libdispatch utilise plusieurs objets, dont les files et les blocks ne sont que 2 exemples. Il est possible de créer ces objets avec `dispatch_object_create` :

- `block`
- `data` : blocs de données
- `group` : groupe de blocks
- `io` : requêtes d'I/O asynchrones
- `mach` : ports Mach
- `mach_msg` : messages Mach
- `pthread_root_queue` : une file avec un pool de threads pthread et sans workqueues
- `queue`
- `semaphore`
- `source` : source d'événements

## Objective-C

En Objective-C, différentes fonctions permettent d'envoyer un block pour qu'il soit exécuté en parallèle :

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async) : soumet un block pour une exécution asynchrone sur une file de dispatch et retourne immédiatement.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync) : soumet un objet block pour exécution et retourne une fois que ce block a terminé son exécution.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once) : exécute un objet block une seule fois pendant toute la durée de vie d'une application.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait) : soumet un work item pour exécution et retourne uniquement une fois son exécution terminée. Contrairement à [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), cette fonction respecte tous les attributs de la file lors de l'exécution du block.

Ces fonctions attendent les paramètres suivants : [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Voici la **struct d'un Block** :
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Et voici un exemple d'utilisation du **parallelism** avec **`dispatch_async`** :
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** est une bibliothèque qui fournit des **bindings Swift** au framework Grand Central Dispatch (GCD), écrit à l'origine en C.\
La bibliothèque **`libswiftDispatch`** encapsule les API GCD en C dans une interface mieux adaptée à Swift, ce qui permet aux développeurs Swift d'utiliser GCD plus facilement et intuitivement.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Exemple de code**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Le script Frida suivant peut être utilisé pour **hooker plusieurs fonctions `dispatch`** et extraire le nom de la queue, la backtrace et le block : [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js).
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Actuellement, Ghidra ne comprend ni la structure ObjectiveC **`dispatch_block_t`**, ni la structure **`swift_dispatch_block`**.

Donc, si vous voulez qu’il les comprenne, vous pouvez simplement les **déclarer** :

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Ensuite, trouvez un endroit dans le code où elles sont **utilisées** :

> [!TIP]
> Notez toutes les références faites à "block" afin de comprendre comment déterminer que la structure est utilisée.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Faites un clic droit sur la variable -> Retype Variable et sélectionnez dans ce cas **`swift_dispatch_block`** :

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra réécrira automatiquement le tout :

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Références

- [1] [libdispatch — `src/queue.c` (implémentation de queue/thread-pool)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/queue.c)
- [2] [libdispatch — `src/source.c` (sources dispatch)](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/source.c)
- [3] [libdispatch — `dispatch/queue.h` (API publique des queues)](https://github.com/apple-oss-distributions/libdispatch/blob/main/dispatch/queue.h)
- [4] [Apple Developer — Dispatch](https://developer.apple.com/documentation/dispatch)

{{#include ../../banners/hacktricks-training.md}}
