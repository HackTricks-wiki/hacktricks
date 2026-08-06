# Exploitation des race conditions du kernel via les Slow Paths de l’Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi l’élargissement de la fenêtre de race est important

De nombreux LPE du kernel Windows suivent le schéma classique `check_state(); NtOpenX("name"); privileged_action();`. Sur le hardware moderne, un `NtOpenEvent`/`NtOpenSection` froid résout un nom court en environ 2 µs, laissant très peu de temps pour modifier l’état vérifié avant l’exécution de l’action privilégiée. En forçant délibérément la recherche dans l’Object Manager Namespace (OMNS) de l’étape 2 à durer plusieurs dizaines de microsecondes, l’attaquant dispose de suffisamment de temps pour remporter de manière fiable des races autrement instables, sans avoir besoin de milliers de tentatives.<sup>[[1]](#references)</sup>

## Les mécanismes internes de la recherche de l’Object Manager en bref

* **Structure de l’OMNS** – Les noms tels que `\BaseNamedObjects\Foo` sont résolus répertoire par répertoire. Chaque composant oblige le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des liens symboliques (par exemple, des lettres de lecteur) peuvent être parcourus en chemin.
* **Limite de `UNICODE_STRING`** – Les chemins OM sont contenus dans une `UNICODE_STRING` dont la valeur `Length` est codée sur 16 bits. La limite absolue est de 65 535 octets (32 767 points de code UTF-16). Avec des préfixes tels que `\BaseNamedObjects\`, l’attaquant contrôle encore environ 32 000 caractères.
* **Prérequis côté attaquant** – Tout utilisateur peut créer des objets sous des répertoires accessibles en écriture tels que `\BaseNamedObjects`. Lorsque le code vulnérable utilise un nom situé à cet emplacement ou suit un lien symbolique qui y aboutit, l’attaquant contrôle les performances de la recherche sans privilèges particuliers.<sup>[[1]](#references)</sup>

## Primitive de ralentissement n°1 – Composant unique maximal

Le coût de résolution d’un composant est approximativement linéaire par rapport à sa longueur, car le kernel doit effectuer une comparaison Unicode avec chaque entrée du répertoire parent. La création d’un event portant un nom de 32 ko augmente immédiatement la latence de `NtOpenEvent`, qui passe d’environ 2 µs à environ 35 µs sous Windows 11 24H2 (environnement de test Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notes pratiques*

- Vous pouvez atteindre la limite de longueur avec n’importe quel objet kernel nommé (events, sections, semaphores…).
- Des liens symboliques ou des points de reparse peuvent faire pointer un nom de « victim » court vers ce composant géant, afin que le ralentissement soit appliqué de manière transparente.
- Comme tout réside dans des namespaces accessibles en écriture par l’utilisateur, le payload fonctionne depuis un niveau d’intégrité utilisateur standard.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Répertoires récursifs profonds

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque étape déclenche la logique de résolution des répertoires (vérifications ACL, recherches dans les hash tables, comptage des références), si bien que la latence par niveau est supérieure à celle d’une simple comparaison de chaîne. Avec environ 16 000 niveaux (limités par la même taille de `UNICODE_STRING`), les mesures empiriques dépassent le seuil de 35 µs atteint avec de longs composants uniques.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Conseils :

* Alternez le caractère à chaque niveau (`A/B/C/...`) si le répertoire parent commence à rejeter les doublons.
* Conservez un tableau de handles afin de pouvoir supprimer proprement la chaîne après l’exploitation et éviter de polluer le namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes au lieu de microsecondes)

Les répertoires d’objets prennent en charge les **shadow directories** (recherches avec fallback) et les tables de hachage organisées en buckets pour les entrées. Exploitez les deux, ainsi que la limite de reparse de 64 composants des liens symboliques, afin de multiplier le ralentissement sans dépasser la longueur de `UNICODE_STRING` :

1. Créez deux répertoires sous `\BaseNamedObjects`, par exemple `A` (shadow) et `A\A` (cible). Créez le second en utilisant le premier comme shadow directory (`NtCreateDirectoryObjectEx`), afin que les recherches infructueuses dans `A` se poursuivent dans `A\A`.
2. Remplissez chaque répertoire de milliers de **noms en collision** qui aboutissent dans le même bucket de hachage (par exemple, en faisant varier les chiffres finaux tout en conservant la même valeur `RtlHashUnicodeString`). Les recherches se dégradent alors en scans linéaires en O(n) à l’intérieur d’un seul répertoire.
3. Construisez une chaîne d’environ 63 **object manager symbolic links** qui effectuent à plusieurs reprises un reparse vers le long suffixe `A\A\…`, consommant ainsi le budget de reparse. Chaque reparse relance l’analyse depuis le début, multipliant le coût des collisions.
4. La recherche du composant final (`...\\0`) prend alors **plusieurs minutes** sous Windows 11 lorsque 16 000 collisions sont présentes par répertoire, ce qui offre une victoire pratiquement garantie dans une race pour des kernel LPEs en one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important* : Un ralentissement de plusieurs minutes transforme les LPEs basées sur une race en exploits déterministes.<sup>[[1]](#references)</sup>

### Notes du retest de 2025 et tooling prêt à l'emploi

- James Forshaw a republié la technique avec des timings mis à jour sur Windows 11 24H2 (ARM64). Les ouvertures de base restent à environ 2 µs ; un composant de 32 kB augmente cette valeur à environ 35 µs, et les chaînes shadow-dir + collision + 63-reparse atteignent toujours environ 3 minutes, ce qui confirme que les primitives fonctionnent encore sur les builds actuels. Le code source et le harness de performance se trouvent dans le post Project Zero mis à jour.<sup>[[1]](#references)</sup>
- Vous pouvez scripter la configuration à l'aide du bundle public `symboliclink-testing-tools` : `CreateObjectDirectory.exe` pour créer la paire shadow/target et `NativeSymlink.exe` dans une boucle pour générer la chaîne de 63 sauts. Cela évite d'écrire manuellement des wrappers `NtCreate*` et garantit la cohérence des ACLs.<sup>[[2]](#references)</sup>

## Mesurer votre fenêtre de race

Intégrez un harness rapide à votre exploit afin de mesurer la taille de la fenêtre sur le hardware de la victime. Le snippet ci-dessous ouvre l'objet target `iterations` fois et renvoie le coût moyen par ouverture à l'aide de `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Les résultats alimentent directement votre stratégie d’orchestration de la race (par ex. le nombre de threads worker nécessaires, les intervalles de sleep et le moment auquel vous devez modifier l’état partagé).

## Workflow d’exploitation

1. **Localiser l’ouverture vulnérable** – Suivez le chemin du kernel (via les symboles, ETW, le traçage par hyperviseur ou le reverse engineering) jusqu’à trouver un appel `NtOpen*`/`ObOpenObjectByName` qui parcourt un nom contrôlé par l’attaquant ou un lien symbolique dans un répertoire accessible en écriture par l’utilisateur.
2. **Remplacer ce nom par un slow path**
- Créez le composant long ou la chaîne de répertoires sous `\BaseNamedObjects` (ou une autre racine OM accessible en écriture).
- Créez un lien symbolique afin que le nom attendu par le kernel soit désormais résolu vers le slow path. Vous pouvez rediriger la recherche de répertoire du driver vulnérable vers votre structure sans toucher à la cible d’origine.
3. **Déclencher la race**
- Le thread A (victime) exécute le code vulnérable et se bloque pendant la recherche lente.
- Le thread B (attaquant) modifie l’état protégé (par ex. échange un handle de fichier, réécrit un lien symbolique ou modifie la sécurité d’un objet) pendant que le thread A est occupé.
- Lorsque le thread A reprend et effectue l’action privilégiée, il observe un état obsolète et réalise l’opération contrôlée par l’attaquant.
4. **Nettoyer** – Supprimez la chaîne de répertoires et les liens symboliques afin d’éviter de laisser des artefacts suspects ou de perturber les utilisateurs légitimes de l’IPC.<sup>[[1]](#references)</sup>

## Considérations opérationnelles

- **Combiner les primitives** – Vous pouvez utiliser un nom long *par niveau* dans une chaîne de répertoires afin d’obtenir une latence encore plus élevée, jusqu’à épuiser la taille de `UNICODE_STRING`.
- **Bugs one-shot** – La fenêtre élargie (de dizaines de microsecondes à plusieurs minutes) rend les bugs « single trigger » réalistes lorsqu’ils sont associés à l’épinglage de l’affinité CPU ou à la préemption assistée par hyperviseur.
- **Effets secondaires** – Le slowdown n’affecte que le chemin malveillant, de sorte que les performances globales du système restent inchangées ; les défenseurs le remarqueront rarement, sauf s’ils surveillent la croissance de l’espace de noms.
- **Nettoyage** – Conservez des handles vers chaque répertoire/objet créé afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Des chaînes de répertoires non bornées peuvent sinon persister après les redémarrages.
- **Races du système de fichiers** – Si le chemin vulnérable est finalement résolu via NTFS, vous pouvez placer un Oplock (par ex. `SetOpLock.exe` du même toolkit) sur le fichier sous-jacent pendant l’exécution du slowdown de l’OM, ce qui bloque le consumer pendant plusieurs millisecondes supplémentaires sans modifier le graphe de l’OM.<sup>[[2]](#references)</sup>

## Notes défensives

- Le code du kernel qui s’appuie sur des objets nommés doit revalider l’état sensible à la sécurité *après* l’ouverture, ou prendre une référence avant la vérification (afin de fermer la fenêtre TOCTOU).
- Imposer des limites supérieures à la profondeur/longueur des chemins de l’OM avant de déréférencer les noms contrôlés par l’utilisateur. Rejeter les noms trop longs force les attaquants à revenir à la fenêtre de microsecondes.
- Instrumenter la croissance de l’espace de noms de l’Object Manager (ETW `Microsoft-Windows-Kernel-Object`) afin de détecter les chaînes suspectes comportant des milliers de composants sous `\BaseNamedObjects`.

## Références

- [1] [Project Zero – Techniques d’exploitation de Windows : gagner les races avec les recherches de chemins](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
