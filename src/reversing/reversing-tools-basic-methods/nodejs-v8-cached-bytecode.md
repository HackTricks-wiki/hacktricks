# Désobfuscation statique du bytecode mis en cache de Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Les données mises en cache de V8 sont une **représentation dépendante de la version et avec pertes**, et non du code source JavaScript ni un exécutable natif conventionnel. Un workflow statique efficace consiste donc à supprimer tout empaquetage externe, à désassembler le cache avec le build V8 correspondant, à le convertir en un modèle de pseudocode intermédiaire, puis à appliquer des transformations tenant compte des dépendances sans exécuter l'échantillon. [View8](https://github.com/suleram/View8) et [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implémentent cette approche pour les payloads Node.js protégés par `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquérir et désassembler le cache

Commencez par examiner le preload/launcher plutôt que de supposer que tous les fichiers `.jsc` utilisent le même wrapper. Par exemple, un launcher tel que `node.exe -r preflight.js app.jsc` exécute `preflight.js` avant le module principal ; dans la famille analysée, le preload supprimait une couche Brotli. Après le dépaquetage, identifiez la génération exacte de Node.js/V8 à partir du runtime fourni. Un cache produit par une version de V8 peut être rejeté ou décodé incorrectement par une autre version ; compilez donc ou obtenez un `v8dasm` correspondant précisément à ce tag V8, puis appliquez les patches requis pour View8 et l'affichage des chaînes.<sup>[[1]](#references)[[2]](#references)</sup>

Le workflow sans exécution du toolkit est le suivant :<sup>[[2]](#references)</sup>
```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
--inp app.jsc.disasm.txt --normalize \
--out decompiled/app.dec.txt \
--export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
--out deobfuscated/app.deobf.txt \
--export_format decompiled serialized
```
`--normalize` fournit aux fonctions générées des identifiants stables d'une exécution à l'autre. La sortie texte sert à l'inspection ; le graphe d'objets sérialisé permet à des passes indépendantes de préserver les relations entre fonctions, déclarants, scopes et métadonnées. Il ne s'agit **pas de JavaScript reconstruit ou exécutable**.<sup>[[1]](#references)[[2]](#references)</sup>

### Lire le pseudocode View8 comme un IR

Les noms typiques sont `func_<name>_0x<address>`, les arguments sont `a0...aN`, les registres virtuels sont `r0...rN`, et `ACCU` est l'accumulateur de V8. `start` est le déclarant racine, tandis que `Scope[...]`, les globals et les dictionnaires représentent les valeurs capturées ou partagées par les fonctions imbriquées. N'analysez pas chaque expression comme de la syntaxe JavaScript : par exemple, `!r6 === "0"` dans View8 représente la négation de la comparaison complète (`r6 !== "0"`), ce qui est important lors de la reconstruction des branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Désobfuscation tenant compte des dépendances

Appliquez les transformations dans un ordre qui expose les entrées requises par la passe suivante, et répétez la propagation jusqu'à stabilisation de la sortie. Un ordre pratique est le suivant :<sup>[[1]](#references)[[2]](#references)</sup>

1. Parcourez la hiérarchie des déclarants et propagez les valeurs provenant des globals, des registres, des dictionnaires et des références `Scope[...]`.
2. Récupérez les arguments des décodeurs de chaînes et remplacez les appels chiffrés par leur texte en clair.
3. Fusionnez les fragments de chaînes adjacents ; les noms de propriétés et les chaînes indiquant l'ordre du dispatcher ainsi obtenus débloquent les passes suivantes.
4. Dépliez le control flow, inlinez les proxies d'appel et les wrappers d'opérations atomiques, puis résolvez les références de fonctions stockées dans les dictionnaires.
5. Effectuez une nouvelle propagation, car chaque chaîne, clé ou proxy résolu peut exposer un autre niveau d'indirection.
6. Réduisez les thunks d'initialisation one-shot reconnus et supprimez les helpers morts uniquement après la résolution de leurs sites d'appel.

### Récupérer les tableaux de chaînes RC4 décalés comme une boîte noire

Une structure courante de `javascript-obfuscator` stocke des fragments RC4 encodés en Base64 dans un tableau. Les wrappers de décodeur fournissent un offset numérique et une clé courte, parfois dans l'ordre inverse des arguments, puis ajoutent ou soustraient des constantes capturées dans des scopes de fermeture. Lorsque le décodeur racine est trop fortement obfusqué, récupérez empiriquement le décalage inconnu de l'index du tableau au lieu de reconstruire toute la fonction.<sup>[[1]](#references)</sup>

Pour un tableau de `N` fragments et plusieurs appels au même décodeur :<sup>[[1]](#references)</sup>
```text
for each observed (numeric_argument, rc4_key):
candidates = {}
for shift in 0 .. N-1:
index = apply_observed_sign(numeric_argument, shift)
plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
if plaintext passes encoding/printability checks:
candidates.add(shift)
root_shift = intersection(candidate_sets)
```
N'acceptez pas un shift à partir d'un seul déchiffrement printable : le mauvais ciphertext peut sembler printable par hasard. Utilisez au moins trois observations distinctes et n'acceptez qu'un shift unique produisant un texte plausible pour chacune d'elles. Parcourez ensuite le graphe wrapper/declarer, en cumulant chaque addition ou soustraction et en enregistrant si l'argument numérique apparaît en premier. Mettez ces métadonnées en cache pour chaque sample, remplacez les appels au decoder, concaténez les chunks de plaintext adjacents et exportez les strings séparément pour le triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Préserver la sémantique lors de la désimbrication

Pour les boucles de dispatcher pilotées par des strings telles que `3|2|1|0|4`, décodez la string d'ordre, associez chaque comparaison d'état à son bloc, tenez compte de la notation de condition négative de View8, puis émettez les blocs dans l'ordre du dispatcher. Un `continue` imbriqué peut représenter un saut anticipé vers le dispatcher plutôt qu'un simple fall-through. Lors de la suppression de la boucle, supprimez ce `continue` et déplacez les instructions qui suivaient initialement son `if` englobant dans une branche `else` générée ; supprimer simplement le dispatcher modifie le comportement.<sup>[[1]](#references)</sup>

### Inliner les proxies, les opérations et les lazy thunks

Normalisez les helpers de forwarding tels que `return a0(a1, a2)` avant de remplacer leurs call sites par des appels directs. Traitez de la même manière les wrappers pour la soustraction, la division, la comparaison, les membership tests ou l'invocation. Comme la référence du helper peut elle-même être stockée derrière une clé de dictionnaire déchiffrée ou une valeur de closure, exécutez la propagation des strings et des structures avant et après l'inlining.<sup>[[1]](#references)</sup>

Reconnaissez également les closures qui invoquent une fonction stockée une seule fois, effacent sa référence, mettent le résultat en cache et renvoient ce cache lors des appels suivants. Réduire un tel thunk sur un site d'initialisation expose le dispatcher ou la capability function sous-jacente, mais indiquez que l'exécution originale était **one-shot and cached**, plutôt que de modéliser chaque appel comme une nouvelle invocation.<sup>[[1]](#references)</sup>

## Notes de sécurité et de validation

- Le chargement de `pickle` Python peut exécuter du code. Chargez uniquement les fichiers `.pkl` générés localement par l'exécution View8 de confiance ; ne traitez jamais un pickle fourni par le sample comme des données.<sup>[[2]](#references)</sup>
- Les passes pilotées par des patterns ne constituent pas un décompilateur JavaScript général. Préservez les expressions non résolues et inspectez manuellement les variantes ambiguës de dispatcher plutôt que de forcer une réécriture.<sup>[[1]](#references)[[2]](#references)</sup>
- Les noms de fonctions suggérés par un LLM sont des indications de navigation, pas des preuves. Traitez les dépendances en partant des feuilles si vous les utilisez, mais vérifiez chaque label par rapport au corps, aux arguments, aux strings, au data flow, aux APIs et aux effets de bord.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Briser le sceau : déobfuscation statique du bytecode V8 compilé de JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
