# Injection de processus Windows via Thread Name-Calling et Waiting Thread Hijacking

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) transfère des octets dans un processus en cours d’exécution sans `WriteProcessMemory` ; Waiting Thread Hijacking (WTH) les exécute sur un thread existant sans `SetThreadContext` ni création d’un thread distant.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Il s’agit de **primitives d’injection de processus, et non de vulnérabilités d’élévation de privilèges** : l’injecteur doit toujours avoir accès au processus et au thread cible. Les API de description des threads nécessitent Windows 10 version 1607 ou ultérieure.<sup>[[1]](#references)[[3]](#references)</sup> Consultez [Antivirus (AV) Bypass](av-bypass.md) pour découvrir d’autres approches d’injection et d’évasion.

## Thread Name-Calling : copie de la charge utile côté cible

`NtSetInformationThread(ThreadNameInformation)` copie une `UNICODE_STRING` fournie dans le stockage du nom du thread. L’appel à `GetThreadDescription` **dans le processus cible** crée ensuite une copie de ce nom dans le heap en mode utilisateur. Le transfert de la charge utile est ainsi séparé de la copie finale en mémoire : l’injecteur peut lire le **pointeur** renvoyé par le heap, tandis qu’un APC exécutant `RtlMoveMemory` dans le processus cible copie les octets vers leur destination.<sup>[[1]](#references)</sup> La technique d’origine prend également en charge les APC utilisateur spéciaux ; l’implémentation WhisperHijack utilise plutôt `NtQueueApcThread` ordinaire sur un thread en attente.<sup>[[1]](#references)[[3]](#references)</sup>

Pour chaque bloc d’au plus `0xFFFE` octets, le PoC suit cet ordre. Un événement auto-reset dupliqué signale la fin uniquement après que la cible a rempli l’emplacement temporaire ; l’injecteur attend ce signal avant de lire le pointeur. L’événement confirme l’exécution de l’APC qui récupère le pointeur du heap, pas celle de l’APC de copie qui suit. Le PoC signale le même thread après avoir mis en file l’APC de copie et s’appuie sur l’ordre des APC plutôt que sur un second signal de fin.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

L’adresse scratch doit être accessible en écriture dans le processus cible et connue de l’injecteur sans qu’il ait besoin de l’écrire au préalable. Le PoC original utilise `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack propose également `PEB.PostProcessInitRoutine` et utilise par défaut `TEB.TlsSlots[63]` (localisé avec `NtQueryInformationThread(ThreadBasicInformation)`). Il n’est **pas garanti** que le slot TLS soit inutilisé dans toutes les cibles ; écraser un slot actif peut perturber le thread. Activez exactement une option dans `Main.c`. Les vérifications à la compilation rejettent les sélections PEB/TEB manquantes ou conflictuelles.<sup>[[4]](#references)</sup>

Un appel normal à `RtlInitUnicodeString` s’arrêterait à un null large intégré. Pour transporter des données binaires, initialisez la longueur de `UNICODE_STRING` à l’aide d’un tampon de remplissage non nul de même taille, remplacez les octets de son `Buffer` par le bloc réel, puis transmettez-le à `NtSetInformationThread`. Ce transfert fondé sur la longueur est différent du passage direct du shellcode à `SetThreadDescription` sous forme de chaîne terminée.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking : retour après une attente sur une file

Énumérez les threads avec `NtQuerySystemInformation(SystemProcessInformation)` et recherchez ceux dont `ThreadState == Waiting` et `WaitReason == WrQueue`. Un thread bloqué dans un wrapper d’appel système tel que `NtWaitForWorkViaWorkerFactory` possède une adresse de retour de l’appelant sauvegardée à `[Rsp]`. Remplacer ce slot de pile redirige le `ret` du wrapper vers un stub sans modifier `Rip` via `SetThreadContext`. Le stub doit sauvegarder les indicateurs et les registres, **appeler** un payload qui se termine par un retour, restaurer l’état, puis sauter vers l’adresse de retour originale sauvegardée.<sup>[[2]](#references)[[3]](#references)</sup>

Dans le PoC x64, le stub comporte un slot de retour sauvegardé de 8 octets à `+0x00`, des instructions à `+0x08` et le payload à `+0x45`. Le slot de pile reçoit `allocation_base + 0x08`, et non l’adresse du slot de données. `WrQueue` à lui seul ne **prouve pas** qu’il s’agit d’une attente de worker factory : la recherche originale identifie également `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` comme chemin d’attente sur une file. Vérifiez la pile d’attente/d’appels réelle et assurez-vous que `[Rsp]` est bien le slot de retour visé avant de vous fier à cette disposition.<sup>[[2]](#references)[[3]](#references)</sup>

## Combiner TNC et WTH sans écritures interprocessus

WhisperHijack illustre le workflow combiné contre un processus natif x64 existant. Son Writer sélectionne un processus/thread candidat, tandis qu’un processus enfant Flipper hérite des handles nécessaires au transfert final. Le handle du processus demande `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **mais pas** `PROCESS_VM_WRITE` ; le PoC actuel ouvre néanmoins le thread avec `THREAD_ALL_ACCESS`. Les contrôles d’accès et les mitigations du processus s’appliquent toujours.<sup>[[3]](#references)[[4]](#references)</sup>

Le PoC combiné suit cette séquence ; les APC de copie mémoire s’exécutent dans la cible plutôt que par l’intermédiaire d’un handle disposant de droits d’écriture à distance.<sup>[[4]](#references)</sup>

1. Réservez des blocs libres alignés sur 64 Ko dans la cible, puis validez leurs pages de 4 Ko avec `PAGE_READWRITE`. Le PoC sonde des adresses candidates fixes avec `NtQueryVirtualMemory` ; ces adresses sont des choix d’implémentation, pas une exigence de TNC ou WTH.
2. Assemblez `[stub WTH de 0x45 octets][payload x64 avec retour][pointeur d’entrée du stub de 8 octets]`, où le pointeur final vaut `allocation_base + 0x08`. Transférez ce tampon avec la boucle de blocs TNC.
3. Dans le Flipper, récupérez le `Rsp` du thread en attente avec `NtGetContextThread(CONTEXT_CONTROL)`. Mettez en file un APC `RtlMoveMemory` dans la cible pour copier la valeur originale de 8 octets à `[Rsp]` vers le slot de données du stub.
4. Rendez la région préparée exécutable avec `NtProtectVirtualMemory`. Ce PoC choisit `PAGE_EXECUTE_READWRITE`, car son payload polymorphe se décode lui-même ; WTH n’exige pas en soi un payload qui se modifie lui-même.
5. Mettez en file un autre APC `RtlMoveMemory` dans la cible pour copier le **pointeur de fin prépositionné** dans `[Rsp]`, puis appelez `NtAlertThread`. L’ordre FIFO des APC sauvegarde le retour original avant de le remplacer ; le retour du wrapper entre dans le stub et, une fois le payload terminé, reprend l’exécution de l’appelant d’origine.

L’absence de `NtWriteVirtualMemory` ne signifie **pas** qu’il n’y a aucune écriture dans la cible : `GetThreadDescription` et `RtlMoveMemory` les effectuent à l’intérieur de celle-ci.<sup>[[1]](#references)[[3]](#references)</sup> La remise d’un APC utilisateur ordinaire dépend également du traitement de sa file d’APC par le thread sélectionné ; un instantané `WrQueue` et une alerte ne garantissent pas une exécution immédiate dans tous les cas.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> L’exemple évite la création d’un thread distant, la suspension et le remplacement direct du contexte, mais reste observable par ses APC et sa transition de protection.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Appel du nom de thread](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Détournement d’un thread en attente](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – PoC WhisperHijack et README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Implémentation WhisperHijack dans Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
