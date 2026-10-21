# Flux de contrôle piloté par les exceptions sous Windows et anti-débogage

{{#include ../banners/hacktricks-training.md}}

Un programme Windows protégé peut utiliser une exception intentionnelle comme branche : l’instruction qui provoque l’exception ne sert que de point d’entrée vers un gestionnaire qui choisit l’adresse suivante du code utilisateur. Cela masque des arêtes lors d’un désassemblage linéaire et déplace l’étape suivante vers la distribution des exceptions.<sup>[[1]](#references)</sup>

## L’importance de la distribution

Un débogueur attaché au processus reçoit une exception de **première chance** avant les gestionnaires de l’application. S’il transmet l’événement comme non géré, Windows recherche les gestionnaires du processus ; si aucun gestionnaire ne traite l’exception, elle revient au débogueur comme exception de **dernière chance**. Un débogueur qui intercepte un événement de point d’arrêt ou d’exécution pas à pas peut donc modifier le comportement du gestionnaire du programme.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` enregistre un VEH à l’avant de la liste des gestionnaires vectoriels du processus. Il s’exécute avant le SEH basé sur les frames, mais une inscription ultérieure avec la priorité maximale peut placer un autre gestionnaire avant lui. Le retour de `EXCEPTION_CONTINUE_SEARCH` transmet l’exception aux autres gestionnaires ; celui de `EXCEPTION_CONTINUE_EXECUTION` reprend l’exécution à partir du `CONTEXT` sauvegardé, y compris les modifications de registres apportées par le gestionnaire.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Le SEH classique sur x86 utilise des inscriptions chaînées sur la pile, que `!exchain` peut examiner. Le x64 natif utilise des entrées `RUNTIME_FUNCTION` dans `.pdata`, avec des données de déroulement dans `.xdata`, et non cette chaîne x86. N’appliquez pas le [workflow de dépassement SEH x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) à un processus x64 natif.<sup>[[5]](#references)[[6]](#references)</sup>

## Transformer une exception en arête de flux de contrôle

Par exemple, un diviseur nul peut intentionnellement déclencher `EXCEPTION_INT_DIVIDE_BY_ZERO` au lieu de représenter un bogue. Le gestionnaire doit reconnaître l’exception et l’adresse fautive, puis définir `ContextRecord->Rip` (ou `Eip` sur x86) sur une continuation valide avant de renvoyer `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Le cœur du gestionnaire ci-dessous suppose que `fault_site` et `continuation` sont des adresses connues dans le même contexte de flux de contrôle. Une implémentation réelle doit préserver la pile et les registres attendus, et ne doit pas reprendre à la même instruction fautive, sans quoi elle provoquera une nouvelle exception.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

Le même mécanisme peut intercepter un `INT3`/`__debugbreak()` intentionnel (`EXCEPTION_BREAKPOINT`) et rediriger l’exécution. **N’incrémentez pas aveuglément `Rip` pour « ignorer le breakpoint »** : l’adresse sauvegardée et l’ajustement requis dépendent du trap, de l’encodage de l’instruction et du comportement du debugger. Comparez `ExceptionRecord->ExceptionAddress` au pointeur d’instruction sauvegardé et désassemblez les octets avant de choisir la continuation.<sup>[[8]](#references)</sup> Le [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) est un exemple distinct de hardware breakpoint qui modifie l’état de retour d’un syscall du loader.

## Le Trap Flag comme mécanisme de contrôle dépendant du debugger

Le bit `0x100` dans `EFLAGS`/`RFLAGS` est le Trap Flag (TF). Le définir provoque une exception `STATUS_SINGLE_STEP` (`0x80000004`) à la prochaine limite d’instruction. Une branche VEH ou SEH peut distinguer un événement single-step transmis à l’application d’un événement intercepté par un debugger, mais il s’agit d’une **heuristique contrôlée par la politique d’exception du debugger**, et non d’une preuve fiable de la présence d’un debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Si le gestionnaire ne veut qu’une seule étape, effacez `0x100` dans le champ `EFlags` du contexte repris avant de continuer. Distinguez également les étapes déclenchées par TF des événements de points d’arrêt matériels en vérifiant l’adresse de déclenchement et l’état de débogage ; les deux peuvent apparaître sous la forme `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Pour les paramètres de première et de seconde chance `sxe`, `sxd` et `sxi` de WinDbg, consultez [l’automatisation des exceptions de WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug : exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Gestion des exceptions du débogueur](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Gestion des exceptions vectorielles](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Gestion des exceptions x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Utilisation d’un gestionnaire d’exceptions vectorielles](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug : instructions d’assemblage](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architecture x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
