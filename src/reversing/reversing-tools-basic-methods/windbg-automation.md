# Automatisation de WinDbg pour l’instrumentation ciblée

{{#include ../../banners/hacktricks-training.md}}

WinDbg et WinDbgX peuvent exécuter des commandes de débogueur au démarrage, lors d’exceptions et lorsque des points d’arrêt se déclenchent. Ainsi, une session de fuzzing ou de reversing peut collecter l’état uniquement autour d’un chemin déclenché par une entrée, au lieu de s’arrêter manuellement à chaque événement.<sup>[[1]](#references)</sup>

## Démarrer sur une exception utile

`-c` exécute des commandes au premier arrêt du débogueur. Ajoutez `;g` pour reprendre après la configuration. Pour une session WinDbg Classic sans intervention, `-logo` écrit la fenêtre de commandes dans un journal, `-Q` désactive l’enregistrement automatique de l’espace de travail et `-G` ignore le point d’arrêt final afin que la session se termine lorsque la cible quitte. WinDbgX accepte également `-c` ; ses commandes de démarrage configurées s’exécutent ensuite.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Pour les violations d’accès, **`sxe av` interrompt l’exécution à la première chance**, **`sxd av` ignore la première chance mais interrompt l’exécution si l’exception n’est pas gérée à la deuxième chance**, et **`sxi av` ignore les deux chances**. Les descriptions de `sxi`/`sxd` dans l’article sont inversées : Microsoft indique que `sxd` est le filtre de deuxième chance et que `sxi` ignore l’exception. Utilisez `-c` pour une commande de première chance et `-c2` pour une commande de deuxième chance ; un gestionnaire `-c` de première chance ne devient pas un gestionnaire de deuxième chance simplement parce que le filtre est `sxd`. Vérifiez les filtres actifs avec `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

La première commande collecte les registres, une stack trace et une analyse de l’exception uniquement en cas de violation d’accès non gérée. La deuxième exécute `lm` lorsqu’un module est chargé. Les événements de breakpoint (`bp`), de chargement de module (`ld`) et de violation d’accès (`av`) ont des cycles de vie différents : n’ignorez donc pas globalement `bp` si vous utilisez des breakpoints du debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Déclencher les breakpoints coûteux à l’aide d’un déclencheur contrôlé

Choisissez une fonction visible par le script ou contrôlée par les entrées, qui peut être appelée juste avant le chemin à examiner. Installez des **action breakpoints** sur les appels à l’allocator, au parser ou à l’API à inspecter. Désactivez-les par ID avec `bd`. Installez un **trigger breakpoint** dont la commande associée active ces IDs avec `be`, puis reprend l’exécution avec `g` ; un deuxième trigger contrôlé peut les désactiver. Vérifiez les IDs avec `bl` avant de configurer le trigger, car ils dépendent de l’ordre de création des breakpoints. Cette approche sépare les points de contrôle peu coûteux du tracing coûteux et limite les changements apportés au timing et à la disposition du heap de la cible.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Après avoir résolu les deux symboles, utilisez le modèle de commande ci-dessous. Remplacez les symboles entre crochets et l’ID de l’action breakpoint renvoyé par `bl` ; ne supposez pas qu’il s’agit de zéro.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Les commandes de point d’arrêt d’action peuvent afficher `@$ip` et `%y` (adresse symbolisée), vider les arguments sélectionnés ou la mémoire, puis poursuivre l’exécution. Si un point d’arrêt conditionnel ne journalise que les pointeurs situés dans une plage donnée, vérifiez d’abord que cette plage couvre bien l’entrée de test ; une condition incorrecte fait perdre des éléments de preuve sans avertissement.<sup>[[1]](#references)</sup>

### Trouver un déclencheur avec les symboles

Recherchez dans tous les modules chargés si le module d’implémentation est inconnu. `bm` définit des points d’arrêt sur chaque symbole correspondant ; invoquez la fonction accessible au script et vérifiez quel point d’arrêt se déclenche. Par exemple, le code source exécute `Math.cos(0)` dans le renderer en cours de débogage, et pas simplement dans un navigateur quelconque.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Une fois qu’un hit identifie la fonction exacte, utilisez `lm a <symbol>` pour résoudre l’image qui la contient et `? <symbol> - <module>` pour calculer un offset relatif au module. WinDbg peut afficher le même nom de module abrégé pour un exécutable et une DLL ; vérifiez donc le chemin de l’image avant d’utiliser l’offset dans un autre processus. Limitez les breakpoints génériques au symbole vérifié pour éviter toute surcharge.<sup>[[1]](#references)</sup>

### Trouver une candidate sans symboles

Le script `corelan_trigscan.py` de Corelan, basé sur Frida, analyse un module de processus sélectionné à la recherche de motifs d’instructions en virgule flottante, SSE, AVX et trigonométriques. Il génère des commandes de breakpoint WinDbg dans `corelan_trigscan.bps` ainsi que des fichiers `.bps` numérotés plus petits. Exécutez-le avec Python et `frida-tools` sur la cible **sans qu’un autre débogueur y soit attaché** ; attachez ensuite WinDbg au même processus/module et chargez un lot de breakpoints de taille raisonnable.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Pour un décalage relatif au module connu, vérifiez qu’il passe les seuils avant d’importer tous les points d’arrêt générés :<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` correspond à la densité d’instructions pertinentes, `--min-relevant` et `--min-total` définissent des seuils minimaux de nombre d’instructions, et `--min-trig` exige des signaux de type trig forts. Si une fonction connue n’est pas détectée, passez son offset **relatif au module** à `--check-offset` pour examiner son prologue, sa densité, ses nombres d’instructions et ses appels indirects. Un wrapper léger peut avoir une faible densité et ne contenir aucune instruction trig. Abaissez les seuils et, si vous recherchez des wrappers, utilisez l’option `--min-icall 1` réellement prise en charge par le script (et non `--min-ical`) ; les fonctions appelées directement sont analysées, mais les cibles indirectes ne peuvent pas être suivies de manière fiable. Des lots `--splitsize` plus petits peuvent aider lorsque de nombreux breakpoints générés ralentissent WinDbg. Un candidat n’est pas validé tant que l’entrée prévue ne déclenche pas son breakpoint.<sup>[[1]](#references)[[6]](#references)</sup>

## Petits programmes de débogueur et PyKD

Utilisez `.if` lorsqu’une condition est fiable, `.foreach` pour parcourir une sortie délimitée par des espaces, et `.for` avec des pseudo-registres pour parcourir la mémoire ou des structures. `.foreach` ne préserve **pas** les colonnes : une sortie `lm` de largeur variable, par exemple, est une mauvaise entrée, tandis que `lm 1m` produit un nom de module par jeton. Consignez d’abord les données non filtrées si une condition supposée pourrait masquer le chemin qui échoue.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Les alias créés avec `as name value` sont des substitutions textuelles, pas des variables typées. `al` les liste, `ad name` en supprime un, et `${name}` force une expansion sans ambiguïté. Évitez les noms tels que `bp`, `x` ou `r`, car un alias peut masquer une commande intégrée. Les expressions MASM conviennent à l’arithmétique des pointeurs, par exemple `poi(@$t0)` ; `@@c++(...)` permet d’accéder aux champs typés lorsque les symboles sont disponibles, ce qui évite les décalages de structure codés en dur.<sup>[[1]](#references)</sup>

Placez les séquences de commandes plus longues dans un fichier de commandes. `$$><filename` joint les lignes en un seul bloc de commandes et permet d’ajouter une commande du débogueur séparée par un point-virgule. Les structures de contrôle multilignes peuvent rester fragiles ; gardez chaque instruction `.if` ou `.for` sur une seule ligne. Le même fichier peut être exécuté au démarrage avec `-c`.<sup>[[1]](#references)[[8]](#references)</sup>

Pour les opérations difficiles à exprimer dans le langage de commandes, PyKD expose à Python les structures typées, les registres, la mémoire et la sortie du débogueur. Par exemple, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` permet d’accéder aux champs du PEB, `pykd.loadBytes(address, size)` lit la mémoire et `pykd.dbgCommand("lm")` renvoie la sortie du débogueur pour analyse. Préférez `loadChars`/`loadWChars` avec une limite plutôt que des lectures de chaînes sans limite pour les données qui pourraient ne pas être terminées. `disasm(address).asm(instruction)` de PyKD **écrit les octets assemblés à cette adresse** ; si vous l’utilisez pour obtenir des opcodes dans un processus en cours d’exécution, sauvegardez puis restaurez la mémoire d’origine.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan : Débogage - Automatisation et scripting de WinDBG(X) - Partie 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft : sx, sxd, sxe, sxi, sxn, sxr, sx- (Définir les exceptions)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft : be (Activer un point d’arrêt)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft : bd (Désactiver un point d’arrêt)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft : bp, bu, bm (Définir un point d’arrêt)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Source de trigscan de Corelan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft : Options de ligne de commande de WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft : Exécuter un fichier de script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
