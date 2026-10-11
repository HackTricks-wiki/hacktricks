# Débogage du noyau Windows avec KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt est un débogueur Windows x64 destiné aux laboratoires de reverse engineering contrôlés. Une interface WPF côté hôte ou `KfConsole.exe` envoie des commandes à `KfRelay.exe` dans une VM Windows configurée pour accepter les pilotes de test. Le relay les convertit en requêtes `DeviceIoControl` destinées à `KernelFlirt.sys`, qui fournit des opérations sur la mémoire, les registres, les points d’arrêt, le contrôle de l’exécution et les modules du noyau. Le pilote modifie également le chemin de débogage du noyau au moyen d’un hook inline `KdpStub`/`KdTrap` : utilisez-le uniquement dans une VM jetable.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Le relais constitue une frontière de débogage privilégiée, et non un service distant classique. Gardez TCP `31337` sur un réseau isolé de type host-only et n’exposez jamais le pilote signé pour les tests ni le relais à un réseau non fiable.<sup>[[1]](#references)</sup>

Techniques d’exploitation Windows connexes :

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Configuration du lab et premier arrêt

La compilation nécessite Windows 10/11 x64, Visual Studio 2022 avec C++, WDK 10.0.26100.0 ou ultérieur et .NET 9. Chargez le pilote et le relais dans la VM, puis connectez-vous depuis l’hôte. L’interface utilisateur peut ouvrir un EXE ou SYS distant, et la vue **Kernel Modules** permet de placer des points d’arrêt dans les pilotes déjà chargés.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Utilisez `KfLoader.exe unload` lorsque le lab est terminé. La console prend en charge un REPL non connecté, l’accès direct aux périphériques locaux et l’accès par relais ; seul le mode relais implémente le workflow déterministe `open` décrit ci-dessous.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Un flux de travail minimal dans la console est :<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Les adresses sont des expressions. Les nombres seuls sont en hexadécimal, et les expressions peuvent utiliser des registres, des opérations arithmétiques, des déréférencements tels que `[rsp]` et des symboles tels que `ntdll!NtCreateFile`. Les breakpoints sur symboles ne doivent être ajoutés qu’après que `open` ou `attach` a énuméré les modules et chargé leurs PDB.<sup>[[2]](#references)</sup>

## Piégeage déterministe du point d’entrée avec `EB FE`

Côté relay, `open` crée le processus cible suspendu, sauvegarde les premiers octets de son point d’entrée, écrit `EB FE`, reprend le thread d’entrée et vérifie en boucle que son pointeur d’instruction atteint cette adresse. `EB FE` est un saut court de deux octets vers lui-même ; il piège donc l’exécution sans dépendre de la livraison d’une exception de débogage en mode utilisateur. Le relay restaure ensuite les octets d’origine et laisse la cible arrêtée à son point d’entrée.<sup>[[2]](#references)</sup>

Cette méthode est également utile pour observer un chemin précoce du loader avant la fin de la configuration normale du débogueur.<sup>[[2]](#references)</sup>

1. Créez le processus en état suspendu et résolvez son véritable point d’entrée après le mappage de l’image.
2. Sauvegardez les octets d’origine du point d’entrée et remplacez-les par la boucle sur elle-même de deux octets.
3. Reprenez le thread d’entrée et vérifiez en boucle son pointeur d’instruction jusqu’à ce qu’il atteigne l’adresse modifiée.
4. Suspendez la cible et restaurez exactement les octets d’origine avant de poursuivre l’analyse.

Cette technique est volontairement intrusive. Si le débogueur ou le relay se ferme avant la restauration, la cible peut rester bloquée dans une boucle. Le mode local de KernelFlirt ne fournit pas la modification du point d’entrée côté relay ; démarrez le processus manuellement, puis utilisez `attach <pid>`.<sup>[[2]](#references)</sup>

## Choisir le mécanisme de breakpoint

KernelFlirt propose plusieurs mécanismes de breakpoint aux effets différents. Les commandes suivantes permettent à l’analyste de changer de mécanisme lorsque le code packé se réécrit, que les pages exécutables sont en lecture seule ou que les octets des breakpoints logiciels sont vérifiés par contrôle d’intégrité.<sup>[[1]](#references)[[2]](#references)</sup>

| Mécanisme | Commande | Fonctionnement et utilisation |
| --- | --- | --- |
| Logiciel | `bp <expr>` | `INT3` adossé à un MDL ; permet d’instrumenter les pages RX `.text` |
| Logiciel conditionnel | `bp <expr> if <condition>` | Évalue la condition à chaque déclenchement et reprend silencieusement si elle est fausse |
| Exécution matérielle | `ba e1 <expr>` | Utilise l’un des registres DR0-DR3 sans modifier les octets du code |
| Données matérielles | `ba w4 <expr>` / `ba r8 <expr>` | Surveille les écritures ou les lectures/écritures de 1, 2, 4 ou 8 octets |
| Page de garde | `bm <expr> [size]` | Utilise `PAGE_GUARD` pour un breakpoint sur une plage mémoire |
| Temporaire | `g <expr>`, `p` ou `o` | Breakpoint auxiliaire pour l’exécution jusqu’à une adresse, le pas par-dessus et le pas de sortie |

Utilisez `bl` pour distinguer les entrées logicielles, matérielles, mémoire et temporaires, et `bc <address|handle|all>` pour les supprimer. Les emplacements matériels sont rares et reposent sur l’état des registres de débogage ; les pages de garde couvrent une plage plus grande, mais se déclenchent aussi lors d’accès sans rapport sur la même page.

## Pas à pas natif x64 et WoW64

En x64 natif, le pas à pas active le drapeau de trap du processeur via `IOCTL_KF_SINGLE_STEP`. Step Over décode l’instruction actuelle et place des breakpoints temporaires aux adresses suivantes possibles. Step Out lit l’adresse de retour au sommet de la pile actuelle. Au prologue d’une fonction, cette hypothèse sur la pile peut être erronée ; préférez donc un breakpoint interne dont l’adresse est connue.<sup>[[2]](#references)</sup>

Le hook `KdTrap` n’intercepte pas les exceptions 32 bits de la même manière. Pour les cibles WoW64, le débogueur décode l’instruction avec Iced, écrit `EB FE` à l’adresse `EIP` suivante calculée et vérifie en boucle les pointeurs d’instruction des threads. Par conséquent, `g <address>` n’est pas disponible pour WoW64, et un simple `g` bloque la console jusqu’à ce qu’un breakpoint soit atteint. Définissez d’abord un breakpoint qui sera atteint et évitez une exécution indéfinie, car `Ctrl+C` ferme la console au lieu d’annuler la vérification en boucle.<sup>[[2]](#references)</sup>

## Analyse assistée par la mémoire, les registres et les symboles

La console permet de combiner un arrêt sur symbole avec l’inspection de la mémoire et une modification contrôlée. Les appels de recherche acceptent les jokers d’octets, l’ASCII ou l’UTF-16 et sont limités à 4 MB, avec au plus 256 correspondances signalées. Les commandes d’allocation et de protection correspondent aux IOCTL d’allocation, de libération et de protection du pilote.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

Le chargement des PDB lit le répertoire de débogage PE de chaque module distant, extrait son identifiant RSDS, trouve la PDB correspondante via DbgHelp/SymSrv et vérifie qu’elle a bien été chargée en tant que PDB. Placez les PDB privées à côté de la cible sur la machine relais ou ajoutez leur répertoire à `_NT_SYMBOL_PATH` sur l’hôte.<sup>[[2]](#references)</sup>

## Modifications de l’état anti-debug prises en charge par le kernel

L’accès au kernel permet au débogueur de supprimer des indicateurs qu’un débogueur en user-mode ne peut pas masquer de manière fiable. Appliquez une seule modification à la fois, vérifiez le contrôle de la cible et rétablissez le hook correspondant avant de terminer la session.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` efface `EPROCESS.DebugPort`.
- `clr_thread_hide` supprime `HideFromDebugger` des threads cibles.
- `ntqsi on` usurpe la classe `0x23` (`SystemKernelDebuggerInformation`) de `NtQuerySystemInformation`.
- `spoof on` fait en sorte que les lectures en user-mode de `KUSER_SHARED_DATA.KdDebuggerEnabled` renvoient false, tout en conservant l’état du kernel nécessaire au mécanisme de trap.
- `stats` vérifie les compteurs des hooks ainsi que l’état enregistré de `KiDebugRoutine`, `KdpStub` et `KdTrap`.

Ces opérations modifient l’état des processus et du kernel. Un crash, un inline hook obsolète, un offset de structure incorrect ou une restauration inachevée d’un patch peut déstabiliser la VM. C’est pourquoi les snapshots et un environnement isolé avec test-signing sont obligatoires.<sup>[[1]](#references)</sup>

## References

- [1] [Dépôt KernelFlirt et documentation principale](https://github.com/AkaTorich/KernelFlirt)
- [2] [Référence de la console KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
