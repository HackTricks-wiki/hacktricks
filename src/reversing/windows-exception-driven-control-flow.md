# Flux de contrôle piloté par les exceptions sous Windows et anti-debugging

{{#include ../banners/hacktricks-training.md}}

Un programme Windows protégé peut utiliser une exception intentionnelle comme branche : l’instruction qui provoque la faute ne sert que de point d’entrée vers un gestionnaire qui choisit la prochaine adresse du code utilisateur. Cela masque des arêtes dans le désassemblage linéaire et déplace l’étape suivante vers la distribution des exceptions.<sup>[[1]](#references)</sup>

## La distribution des exceptions est importante

Un débogueur attaché au processus reçoit une exception de **première chance** avant les gestionnaires de l’application. S’il transmet l’événement comme non géré, Windows parcourt les gestionnaires du processus ; une exception sans gestionnaire revient au débogueur en tant qu’exception de **dernière chance**. Un débogueur qui intercepte un événement de breakpoint ou de pas à pas peut donc modifier le déclenchement du gestionnaire du programme.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` enregistre un VEH à l’avant de la liste des gestionnaires vectoriels du processus. Il s’exécute avant les gestionnaires SEH liés aux frames, mais une inscription ultérieure avec la priorité la plus élevée peut placer un autre gestionnaire devant lui. Le retour de `EXCEPTION_CONTINUE_SEARCH` laisse l’exception aux autres gestionnaires ; `EXCEPTION_CONTINUE_EXECUTION` reprend l’exécution à partir du `CONTEXT` sauvegardé, y compris les éventuelles modifications de registres effectuées par le gestionnaire.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Le SEH classique x86 utilise des inscriptions chaînées sur la pile, que `!exchain` peut inspecter. Le x64 natif utilise des entrées `RUNTIME_FUNCTION` dans `.pdata`, avec des données de déroulement dans `.xdata`, et non cette chaîne x86. N’appliquez pas le [workflow d’écrasement du SEH x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) à un processus x64 natif.<sup>[[5]](#references)[[6]](#references)</sup>

## Transformer une faute en arête de flux de contrôle

Par exemple, un diviseur nul peut déclencher volontairement `EXCEPTION_INT_DIVIDE_BY_ZERO` au lieu de signaler un bug. Le gestionnaire doit reconnaître l’exception et l’adresse de la faute, puis définir `ContextRecord->Rip` (ou `Eip` sur x86) sur une adresse de continuation valide avant de renvoyer `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Le cœur du gestionnaire ci-dessous suppose que `fault_site` et `continuation` sont des adresses connues dans le même contexte de flux de contrôle. Une implémentation réelle doit préserver la pile et les registres attendus, et ne doit pas reprendre à la même instruction fautive, sinon elle déclenchera à nouveau une exception.<sup>[[7]](#references)</sup>

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

Le même mécanisme peut intercepter un `INT3`/`__debugbreak()` intentionnel (`EXCEPTION_BREAKPOINT`) et rediriger l'exécution. Ne faites **pas** avancer `Rip` aveuglément pour « ignorer le breakpoint » : l'adresse enregistrée et l'ajustement requis dépendent du trap, de l'encodage de l'instruction et du comportement du debugger. Comparez `ExceptionRecord->ExceptionAddress` au pointeur d'instruction enregistré et désassemblez les octets avant de choisir la continuation.<sup>[[8]](#references)</sup> Le [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) est un exemple distinct de hardware-breakpoint qui modifie l'état de retour d'un syscall du loader.

## Matérialisation des pages déclenchée par une faute

Un VEH peut transformer un page fault en **lazy loader**, et pas seulement en saut. Réservez une plage d'image privée avec des pages laissées non validées, ou des pages mappées avec une protection guard, si cette option est prise en charge. Avant d'exécuter l'image, indexez les emplacements de relocation et les thunks IAT en fonction de leur page de destination. En cas de faute dans cette plage, le handler valide la page touchée ou la rend accessible en écriture, copie les octets de sa section, applique les relocations et les imports de cette page, définit sa protection finale, puis renvoie `EXCEPTION_CONTINUE_EXECUTION`. L'instruction d'origine est réessayée ; ne faites **pas** avancer `Rip`, contrairement à un handler qui ignore la faute. Les pages jamais touchées n'ont pas besoin de contenir le payload en mémoire.<sup>[[11]](#references)</sup>

Dans le cas d'une access violation, `ExceptionRecord->ExceptionAddress` identifie l'**instruction** qui a provoqué la faute, tandis que `ExceptionInformation[1]` identifie l'adresse accédée.<sup>[[10]](#references)</sup> Vérifiez le code d'exception, le nombre de paramètres et la plage de l'adresse accédée avant de matérialiser une page ; sinon, une faute sans rapport risque d'être prise pour une requête du loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` déclenche `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) au premier accès, et Windows efface automatiquement le bit guard ; le réarmer est donc une étape distincte, pas un hook permanent.<sup>[[12]](#references)</sup> Assurez-vous que le VEH et toutes les métadonnées dont il a besoin restent accessibles pendant le dispatch.<sup>[[11]](#references)</sup> Sur x64, les données unwind peuvent devoir être disponibles avant la première faute ; le loader cité matérialise les pages à l'avance avant d'appeler `DllMain` afin d'éviter les races d'initialisation.<sup>[[11]](#references)</sup> Videz le cache d'instructions après avoir écrit le code et avant de l'exécuter.<sup>[[13]](#references)</sup>

Pour retrouver ce flux lors du reversing, arrêtez-vous sur les violations de page guard et les access violations de première chance, examinez l'enregistrement d'exception, puis transmettez l'événement au handler de l'application avec `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Utilisez `!vprot` sur l'adresse accédée pour examiner la protection actuelle de sa page.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Après que le gestionnaire a matérialisé la page, extrayez ses octets et comparez-les à l’image du fichier.<sup>[[11]](#references)</sup> Un `!vprot` exécuté après l’exception ne peut pas prouver que la page était protégée auparavant, car la protection guard est à usage unique.<sup>[[11]](#references)[[12]](#references)</sup> Une fois la plage d’image concernée connue, affinez les filtres d’exception ou les points d’arrêt du gestionnaire afin d’éviter les exceptions sans rapport.<sup>[[16]](#references)</sup> Consultez [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) pour configurer les filtres.<sup>[[16]](#references)</sup>

## Trap Flag comme mécanisme de contrôle dépendant du débogueur

Le bit `0x100` dans `EFLAGS`/`RFLAGS` est le Trap Flag (TF). Son activation provoque une exception `STATUS_SINGLE_STEP` (`0x80000004`) à la frontière de l’instruction suivante. Une branche VEH ou SEH peut distinguer un événement single-step transmis à l’application d’un événement consommé par un débogueur, mais il s’agit d’une **heuristique régie par la politique de gestion des exceptions du débogueur**, et non d’une preuve fiable de la présence d’un débogueur.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Si le gestionnaire ne veut qu'une seule étape, effacez `0x100` dans `EFlags` du contexte repris avant de continuer. Distinguez également les étapes déclenchées par TF des événements de points d'arrêt matériels en vérifiant l'adresse déclenchante et l'état du débogage ; les deux peuvent apparaître comme `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Pour les paramètres de première et seconde chance `sxe`, `sxd` et `sxi` de WinDbg, consultez [Automatisation des exceptions WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug : exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Gestion des exceptions par le débogueur](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Gestion des exceptions vectorielles](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Gestion des exceptions x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Utilisation d'un gestionnaire d'exceptions vectorielles](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug : instructions d'assemblage](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Architecture x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Chargement d'image déclenché par une erreur](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Création de pages de garde](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (afficher l'enregistrement d'exception)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Filtres d'exception sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (continuer avec une exception non gérée)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
