# Désobfuscation statique du bytecode mis en cache de Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Les données mises en cache de V8 constituent une **représentation avec perte et dépendante de la version**, et non du code source JavaScript ni un exécutable natif classique. Un flux de travail statique utile consiste donc à supprimer tout packing externe, à désassembler le cache avec la build V8 correspondante, à le convertir en un modèle de pseudocode intermédiaire, puis à appliquer des transformations tenant compte des dépendances sans exécuter l’échantillon. [View8](https://github.com/suleram/View8) et [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) mettent en œuvre cette approche pour les payloads Node.js protégés par `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Acquérir et désassembler le cache

Commencez par examiner le preload/launcher plutôt que de supposer que tous les fichiers `.jsc` utilisent le même wrapper. Par exemple, un launcher tel que `node.exe -r preflight.js app.jsc` exécute `preflight.js` avant le module principal ; dans la famille analysée, le preload supprimait une couche Brotli. Après le décompactage, identifiez précisément la génération de Node.js/V8 à partir du runtime fourni. Un cache produit par une version de V8 peut être rejeté ou décodé de manière incorrecte par une autre. Créez ou obtenez donc un `v8dasm` correspondant exactement à ce tag V8 et appliquez les correctifs nécessaires pour View8 et l’affichage des chaînes.<sup>[[1]](#references)[[2]](#references)</sup>

Le flux de travail non exécutant de la boîte à outils est le suivant :<sup>[[2]](#references)</sup>

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

`--normalize` attribue des identifiants stables aux fonctions générées d’une exécution à l’autre. La sortie texte sert à l’inspection ; le graphe d’objets sérialisé permet à des passes indépendantes de préserver les relations entre fonctions, déclarants, portées et métadonnées. Il ne s’agit **pas de JavaScript reconstruit ou exécutable**.<sup>[[1]](#references)[[2]](#references)</sup>

### Analyser un cache sans compiler V8

Pour un cache brut ou enveloppé dans Brotli, `jscd` peut identifier l’en-tête et énumérer les constantes et les fonctions sans charger l’échantillon dans Node.js. Commencez par vérifier si ses tables de versions prennent en charge le fichier, puis donnez la priorité aux fonctions avant d’appliquer les passes de deobfuscation View8 plus spécialisées.<sup>[[4]](#references)</sup>

Le hash de version est un indice d’identification, et non la preuve qu’un désassembleur autonome utilise les mêmes flags ou le même snapshot en lecture seule que le producteur.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` génère un listing compatible avec View8 ; la commande View8 ci-dessus peut donc utiliser cette sortie à la place de `v8dasm` lorsque le cache est pris en charge. Examinez les chaînes en parallèle de l’arborescence des fonctions pour repérer les appels au décodeur et les points d’entrée probables ; ne considérez pas le code JavaScript approximatif de `jscd` comme le code source d’origine. Si l’outil rejette la version ou laisse des espaces réservés pour le tas en lecture seule, utilisez une build V8 correspondante ou fournissez une table de noms issue de cette même build, plutôt que de deviner les noms des propriétés.<sup>[[4]](#references)</sup>

Pour un cache dans une application Electron, commencez par [extraire l’ASAR et inspecter les points d’entrée principaux et preload](../../desktop-application-security/electron-desktop-apps/). La disposition des snapshots et de la compression des pointeurs peut différer entre les caches Electron et Node, même lorsque leurs chaînes de version V8 correspondent.<sup>[[4]](#references)</sup>

### Lire le pseudo-code View8 comme un IR

Les noms courants sont `func_<name>_0x<address>`, les arguments sont `a0...aN`, les registres virtuels sont `r0...rN`, et `ACCU` est l’accumulateur de V8. `start` est le déclarateur racine, tandis que `Scope[...]`, les variables globales et les dictionnaires modélisent les valeurs capturées ou partagées par les fonctions imbriquées. N’analysez pas chaque expression comme de la syntaxe JavaScript : par exemple, `!r6 === "0"` représente la négation de la comparaison complète (`r6 !== "0"`), ce qui compte lors de la reconstruction des branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Désobfuscation tenant compte des dépendances

Appliquez les transformations dans un ordre qui expose les entrées requises par l’étape suivante, puis répétez la propagation jusqu’à ce que la sortie se stabilise. Voici un ordre pratique :<sup>[[1]](#references)[[2]](#references)</sup>

1. Parcourez la hiérarchie des déclarateurs et propagez les valeurs provenant des variables globales, des registres, des dictionnaires et des références `Scope[...]`.
2. Retrouvez les arguments du décodeur de chaînes et remplacez les appels chiffrés par du texte en clair.
3. Regroupez les fragments de chaînes adjacents ; les noms de propriétés et les chaînes définissant l’ordre du dispatcher ainsi obtenus débloquent les étapes suivantes.
4. Aplatissez le flux de contrôle, intégrez les proxies d’appel et les wrappers d’opérations atomiques, et résolvez les références de fonctions contenues dans les dictionnaires.
5. Relancez la propagation, car chaque chaîne, clé ou proxy résolu peut révéler une autre couche d’indirection.
6. Réduisez les thunks d’initialisation ponctuels reconnus et supprimez les helpers morts uniquement après avoir résolu leurs sites d’appel.

### Récupérer des tableaux de chaînes RC4 décalés comme une boîte noire

Une disposition courante de `javascript-obfuscator` stocke des fragments RC4 encodés en Base64 dans un seul tableau. Les wrappers du décodeur fournissent un décalage numérique et une courte clé, parfois dans l’ordre inverse des arguments, puis ajoutent ou soustraient des constantes capturées dans des portées de fermeture. Lorsque le décodeur racine est trop fortement obfusqué, retrouvez empiriquement le décalage inconnu des indices du tableau au lieu de reconstruire toute la fonction.<sup>[[1]](#references)</sup>

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

Ne validez pas un décalage à partir d’un seul déchiffrement imprimable : le mauvais ciphertext peut sembler imprimable par hasard. Utilisez au moins trois observations distinctes et n’acceptez qu’un décalage unique qui produit un texte plausible pour chacune d’elles. Parcourez ensuite le graphe des wrappers et des déclarateurs, cumulez chaque addition ou soustraction et notez si l’argument numérique vient en premier. Mettez ces métadonnées en cache pour chaque échantillon, remplacez les appels au décodeur, concaténez les segments de texte clair adjacents et exportez les chaînes séparément pour le triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Préserver la sémantique lors du dépliage

Pour les boucles de dispatch pilotées par des chaînes telles que `3|2|1|0|4`, décodez la chaîne d’ordre, associez chaque comparaison d’état à son bloc, tenez compte de la notation à condition négative de View8, puis émettez les blocs dans l’ordre du dispatcher. Un `continue` imbriqué peut représenter un saut anticipé vers le dispatcher plutôt qu’un simple passage à l’instruction suivante. Lors de la suppression de la boucle, supprimez ce `continue` et déplacez les instructions qui suivaient initialement son `if` englobant dans une branche `else` générée ; supprimer simplement le dispatcher modifie le comportement.<sup>[[1]](#references)</sup>

### Intégrer les proxies, les opérations et les thunks paresseux

Normalisez les helpers de transfert tels que `return a0(a1, a2)` avant de remplacer leurs sites d’appel par des appels directs. Traitez de la même façon les wrappers pour la soustraction, la division, la comparaison, les tests d’appartenance ou l’invocation. Comme la référence du helper peut elle-même être stockée derrière une clé de dictionnaire déchiffrée ou une valeur de fermeture, propagez les chaînes et les structures avant et après l’intégration.<sup>[[1]](#references)</sup>

Repérez également les fermetures qui invoquent une fois une fonction stockée, effacent sa référence, mettent le résultat en cache et renvoient ce cache lors des appels suivants. Réduire un tel thunk à son site d’initialisation révèle le dispatcher ou la fonction de capacité sous-jacente, mais indiquez que l’exécution d’origine était **à usage unique et mise en cache**, plutôt que de modéliser chaque appel comme une nouvelle invocation.<sup>[[1]](#references)</sup>

## Notes de sécurité et de validation

- Le chargement de fichiers Python `pickle` peut exécuter du code. Ne chargez que les fichiers `.pkl` générés localement par l’exécution de View8 de confiance ; ne traitez jamais un pickle fourni avec l’échantillon comme des données.<sup>[[2]](#references)</sup>
- L’absence du corps d’une fonction ne prouve pas que le code source ne contenait pas cette fonction : V8 peut sérialiser une fonction paresseuse sous forme de métadonnées jusqu’à sa compilation lors du premier appel. Lors du triage statique, gardez ces fonctions marquées comme non résolues.<sup>[[6]](#references)</sup>
- Les passes guidées par des motifs ne constituent pas un décompilateur JavaScript général. Conservez les expressions non résolues et inspectez manuellement les variantes ambiguës du dispatcher au lieu de forcer une réécriture.<sup>[[1]](#references)[[2]](#references)</sup>
- Les noms de fonctions suggérés par un LLM sont des indications de navigation, pas des preuves. Traitez les dépendances feuille en premier si vous les utilisez, mais vérifiez chaque étiquette à partir du corps, des arguments, des chaînes, du flux de données, des API et des effets de bord.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Briser le sceau : déobfuscation statique du bytecode V8 compilé de JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [En-tête V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache de code vm.Script de Node.js](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
