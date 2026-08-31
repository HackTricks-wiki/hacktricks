# Exploitation d’une race condition du kernel via les chemins lents de l’Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi élargir la fenêtre de la race est important

De nombreux LPE du kernel Windows suivent le schéma classique `check_state(); NtOpenX("name"); privileged_action();`. Sur le matériel moderne, un `NtOpenEvent`/`NtOpenSection` cold résout un nom court en ~2 µs, laissant presque aucun temps pour modifier l’état vérifié avant l’exécution de l’action sécurisée. En forçant délibérément la recherche dans l’Object Manager Namespace (OMNS) de l’étape 2 à durer plusieurs dizaines de microsecondes, l’attaquant dispose de suffisamment de temps pour remporter systématiquement des races autrement instables, sans avoir besoin de milliers de tentatives.<sup>[[1]](#references)</sup>

## Internals de la recherche de l’Object Manager en bref

* **Structure de l’OMNS** – Les noms tels que `\BaseNamedObjects\Foo` sont résolus répertoire par répertoire. Chaque composant oblige le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des liens symboliques (par exemple, les lettres de lecteur) peuvent être parcourus en chemin.
* **Limite de `UNICODE_STRING`** – Les chemins OM sont transportés dans une `UNICODE_STRING` dont `Length` est une valeur de 16 bits. La limite absolue est de 65 535 octets (32 767 codepoints UTF-16). Avec des préfixes comme `\BaseNamedObjects\`, un attaquant contrôle encore environ 32 000 caractères.
* **Prérequis côté attaquant** – Tout utilisateur peut créer des objets dans des répertoires accessibles en écriture tels que `\BaseNamedObjects`. Lorsque le code vulnérable utilise un nom situé à l’intérieur de celui-ci, ou suit un lien symbolique qui y aboutit, l’attaquant contrôle les performances de la recherche sans privilèges spéciaux.<sup>[[1]](#references)</sup>

## Primitive de ralentissement n°1 – Composant unique maximal

Le coût de la résolution d’un composant est approximativement linéaire par rapport à sa longueur, car le kernel doit effectuer une comparaison Unicode avec chaque entrée du répertoire parent. La création d’un event portant un nom de 32 kB augmente immédiatement la latence de `NtOpenEvent`, qui passe d’environ ~2 µs à ~35 µs sur Windows 11 24H2 (banc de test Snapdragon X Elite).
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
- Les liens symboliques ou les reparse points peuvent faire pointer un nom court de « victime » vers ce composant géant, de sorte que le ralentissement soit appliqué de manière transparente.
- Comme tout réside dans des namespaces accessibles en écriture par l’utilisateur, le payload fonctionne depuis un niveau d’intégrité utilisateur standard.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Répertoires profondément récursifs

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque niveau déclenche la logique de résolution des répertoires (vérifications ACL, recherches dans les hash tables, comptage des références), de sorte que la latence par niveau est supérieure à celle d’une simple comparaison de chaînes. Avec environ 16 000 niveaux (limités par la même taille de `UNICODE_STRING`), les mesures empiriques dépassent la barrière des 35 µs obtenue avec de longs composants uniques.
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

* Alternez le caractère pour chaque niveau (`A/B/C/...`) si le répertoire parent commence à rejeter les doublons.
* Conservez un tableau de handles afin de pouvoir supprimer proprement la chaîne après l’exploitation et éviter de polluer le namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Répertoires shadow, collisions de hash et reparses de symlinks (minutes au lieu de microsecondes)

Les répertoires d’objets prennent en charge les **répertoires shadow** (recherches de secours) et les tables de hachage organisées en buckets pour les entrées. Exploitez ces deux mécanismes ainsi que la limite de reparse de 64 composants des liens symboliques afin de multiplier le ralentissement sans dépasser la longueur de `UNICODE_STRING` :

1. Créez deux répertoires sous `\BaseNamedObjects`, par exemple `A` (shadow) et `A\A` (cible). Créez le second en utilisant le premier comme répertoire shadow (`NtCreateDirectoryObjectEx`), afin que les recherches infructueuses dans `A` soient redirigées vers `A\A`.
2. Remplissez chaque répertoire de milliers de **noms entrant en collision** et placés dans le même bucket de hachage (par exemple, en faisant varier les chiffres finaux tout en conservant la même valeur `RtlHashUnicodeString`). Les recherches se dégradent alors en parcours linéaires O(n) au sein d’un seul répertoire.
3. Construisez une chaîne d’environ 63 **liens symboliques de l’object manager** qui reparsent de manière répétée vers le long suffixe `A\A\…`, consommant ainsi le budget de reparse. Chaque reparse recommence l’analyse depuis le début, multipliant le coût des collisions.
4. La recherche du composant final (`...\\0`) prend alors **plusieurs minutes** sous Windows 11 lorsque 16 000 collisions sont présentes par répertoire, ce qui fournit une victoire de race pratiquement garantie pour les kernel LPE en un seul tir.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important* : Un ralentissement de plusieurs minutes transforme les LPE basées sur une race, exécutables une seule fois, en exploits déterministes.<sup>[[1]](#references)</sup>

### Notes du retest de 2025 et tooling prêt à l'emploi

- James Forshaw a republié la technique avec des timings mis à jour sur Windows 11 24H2 (ARM64). Les ouvertures de référence restent à environ 2 µs ; un composant de 32 kB augmente cette durée à environ 35 µs, et les chaînes shadow-dir + collision + 63-reparse atteignent toujours environ 3 minutes, confirmant que les primitives fonctionnent encore sur les builds actuels. Le code source et le perf harness se trouvent dans le post Project Zero mis à jour.<sup>[[1]](#references)</sup>
- Vous pouvez scripter la configuration à l'aide du bundle public `symboliclink-testing-tools` : `CreateObjectDirectory.exe` pour créer la paire shadow/target et `NativeSymlink.exe` en boucle pour générer la chaîne de 63 hops. Cela évite d'écrire manuellement des wrappers `NtCreate*` et garantit la cohérence des ACL.<sup>[[2]](#references)</sup>

## Mesurer votre fenêtre de race

Intégrez un quick harness à votre exploit afin de mesurer la taille de la fenêtre sur le hardware de la victime. Le snippet ci-dessous ouvre l'objet target `iterations` fois et renvoie le coût moyen par ouverture à l'aide de `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Les résultats alimentent directement votre stratégie d’orchestration de la race (par exemple, le nombre de threads workers nécessaires, les intervalles de mise en veille et le moment auquel vous devez modifier l’état partagé).

## Workflow d’exploitation

1. **Localiser l’ouverture vulnérable** – Suivez le chemin du kernel (via les symboles, le traçage ETW, un hyperviseur ou le reverse engineering) jusqu’à trouver un appel `NtOpen*`/`ObOpenObjectByName` qui parcourt un nom contrôlé par l’attaquant ou un lien symbolique dans un répertoire accessible en écriture à l’utilisateur.
2. **Remplacer ce nom par un chemin lent**
- Créez le composant long ou la chaîne de répertoires sous `\BaseNamedObjects` (ou une autre racine OM accessible en écriture).
- Créez un lien symbolique afin que le nom attendu par le kernel soit désormais résolu vers le chemin lent. Vous pouvez rediriger la recherche de répertoire du driver vulnérable vers votre structure sans toucher à la cible d’origine.
3. **Déclencher la race**
- Le thread A (victime) exécute le code vulnérable et se bloque pendant la recherche lente.
- Le thread B (attaquant) modifie l’état protégé (par exemple, échange un handle de fichier, réécrit un lien symbolique ou bascule la sécurité de l’objet) pendant que le thread A est occupé.
- Lorsque le thread A reprend et effectue l’action privilégiée, il observe un état obsolète et réalise l’opération contrôlée par l’attaquant.
4. **Nettoyer** – Supprimez la chaîne de répertoires et les liens symboliques afin d’éviter de laisser des artefacts suspects ou de perturber les utilisateurs légitimes de l’IPC.<sup>[[1]](#references)</sup>

## Chaîne appliquée : placeholders Cloud Files mutables + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publié comme bypass pour RoguePlanet (CVE-2026-50656), démontre un schéma d’exploitation plus large : faire en sorte qu’un scanner privilégié classe une représentation d’un fichier logique, puis modifier à la fois ses octets et la résolution de son namespace avant que la remédiation ne l’utilise. Le PoC combine un TOCTOU d’hydratation Cloud Files, un shadow-directory fallback de l’Object Manager, la capture de noms générés par CLFS et un lien vers un partage administratif local afin de transformer le nettoyage de Defender en écriture d’une DLL protégée.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substituer le contenu via l’hydratation Cloud Files

Enregistrez un répertoire accessible en écriture à l’attaquant comme Cloud Files sync root, connectez un callback `CF_CALLBACK_TYPE_FETCH_DATA` et créez un placeholder dont la taille annoncée correspond à un trigger de détection déterministe tel que l’EICAR ZIP. Le premier fetch renvoie le trigger et modifie l’état du callback ; les fetch suivants renvoient le payload. Une fois que le scanner a classé la première représentation, obtenez la transfer key et redémarrez l’hydratation avec des métadonnées de la taille du payload, puis forcez l’hydratation jusqu’à EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
La security boundary échoue si le scan, le verdict et la remediation se réfèrent uniquement à un pathname ou à une identité placeholder : aucun des deux ne garantit qu’une hydration ultérieure renverra les octets qui ont été inspectés.<sup>[[4]](#references)</sup>

### 2. Basculer un invariant path via un shadow-directory fallback

Créez un répertoire Object Manager cible et un second répertoire avec `NtCreateDirectoryObjectEx`, en transmettant le handle cible comme répertoire shadow/fallback. Placez une entrée `WD_SCAN` portant le même nom dans les deux couches de résolution : l’entrée visible pointe vers le working directory normal, tandis que l’entrée fallback pointe vers `\CLFS\??\<working-directory>`. Fournissez à Defender uniquement l’invariant path ci-dessous ; la suppression du lien visible pendant que l’opération est active fait passer la même chaîne vers l’entrée adossée à CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Cette technique se distingue de l’utilisation de shadow directories uniquement pour ralentir la recherche : l’attaquant modifie la **signification** d’un chemin précédemment accepté sans modifier sa chaîne de caractères.<sup>[[4]](#references)</sup>

### 3. Capturer le nom généré et installer un lien spécifique au nom de fichier

Surveillez le répertoire de travail avec `ReadDirectoryChangesW`. Lors du premier `FILE_ACTION_ADDED`, supprimez le lien visible `WD_SCAN` pour activer la recherche de secours. Capturez le deuxième nom de fichier généré, ouvrez ce fichier lié à CLFS et verrouillez la plage `0..MAXLONGLONG` avec `LockFileEx`. Pendant que l’opération privilégiée est bloquée, remplacez `WD_SCAN` dans le répertoire visible par un véritable répertoire Object Manager et créez un lien symbolique enfant nommé d’après le nom de fichier observé (le PoC supprime ses quatre derniers caractères). Faites-le pointer vers la destination protégée via SMB local :<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Le processus non privilégié ne peut pas écrire lui-même à cette destination, mais le contexte SYSTEM de Defender peut parcourir le partage administratif loopback. La combinaison de l’observation des noms générés avec un lien Object Manager spécifique au nom de fichier évite de devoir prédire à l’avance l’artefact de remédiation.<sup>[[4]](#references)</sup>

### 4. Stabiliser la race de nettoyage et déclencher un loader privilégié

Avant l’analyse, le PoC stocke un PE valide (`ntdll.dll`) dans le flux de données alternatif NTFS `:stream` du placeholder. Après que la redirection a créé le fichier de base protégé, il ouvre `phoneinfo.dll:stream` avec un accès d’exécution et maintient un mapping `PAGE_EXECUTE_READ | SEC_IMAGE` actif pendant la reprise du nettoyage ; les objets fichier/section actifs limitent la suppression ou le remplacement pendant la race finale. La nouvelle hydration renvoie alors la payload DLL plutôt qu’EICAR, de sorte que le fichier de base protégé contient du code contrôlé par l’attaquant.<sup>[[4]](#references)</sup>

Une écriture protégée est ensuite convertie en exécution SYSTEM en plaçant un `Report.wer` spécialement conçu sous `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` et en invoquant `\Microsoft\Windows\Windows Error Reporting\QueueReporting` via l’API COM de Task Scheduler. Dans cette chaîne, le traitement WER privilégié charge le fichier `C:\Windows\System32\phoneinfo.dll` implanté ; une connexion named pipe est utilisée comme signal d’exécution de la payload.<sup>[[4]](#references)</sup>

### Pivots de détection

Les corrélations utiles sont plus spécifiques que n’importe quel nom de fichier temporaire unique et couvrent toutes les transitions d’espace de noms de la chaîne :<sup>[[4]](#references)</sup>

- Un fournisseur Cloud Files nouvellement enregistré, suivi d’une détection EICAR et de `CF_OPERATION_TYPE_RESTART_HYDRATION` sur le même placeholder.
- Des chemins Object Manager contenant `WD_TARGET_*`, `WD_SHADOW_*` ou `WD_SCAN`, en particulier un chemin d’analyse sous `\\.\globalroot\BaseNamedObjects\Restricted\`.
- La création d’un fichier CLFS suivie d’un verrou exclusif sur l’ensemble du fichier et d’un accès loopback à `\\127.0.0.1\C$\Windows\System32\*.dll` depuis un processus de sécurité privilégié.
- La création d’une DLL System32 avec un NTFS ADS, suivie d’un mapping `SEC_IMAGE` du flux.
- Une entrée de file d’attente WER créée par l’attaquant, suivie de l’exécution manuelle inhabituelle de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` et du chargement de l’image de la DLL implantée.

## Considérations opérationnelles

- **Combiner les primitives** – Vous pouvez utiliser un nom long *par niveau* dans une chaîne de répertoires afin d’augmenter encore la latence jusqu’à épuiser la taille de `UNICODE_STRING`.
- **Bugs à déclenchement unique** – La fenêtre élargie (de dizaines de microsecondes à plusieurs minutes) rend réalistes les bugs « single trigger » lorsqu’ils sont associés à un CPU affinity pinning ou à une preemption assistée par hyperviseur.
- **Effets secondaires** – Le ralentissement n’affecte que le chemin malveillant ; les performances globales du système restent donc inchangées. Les defenders le remarqueront rarement, sauf s’ils surveillent la croissance de l’espace de noms.
- **Nettoyage** – Conservez des handles vers chaque répertoire/objet créé afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Des chaînes de répertoires non bornées peuvent sinon persister après les redémarrages.
- **Races du système de fichiers** – Si le chemin vulnérable est finalement résolu via NTFS, vous pouvez placer un Oplock (par exemple `SetOpLock.exe` du même toolkit) sur le fichier sous-jacent pendant l’exécution du ralentissement OM, ce qui bloque le consumer pendant quelques millisecondes supplémentaires sans modifier le graphe OM.<sup>[[2]](#references)</sup>

## Notes défensives

- Le code kernel qui s’appuie sur des objets nommés doit revalider l’état sensible à la sécurité *après* l’ouverture, ou prendre une référence avant la vérification (pour fermer la fenêtre TOCTOU).
- Appliquez des limites supérieures à la profondeur/longueur des chemins OM avant de déréférencer les noms contrôlés par l’utilisateur. Le rejet des noms trop longs force les attaquants à revenir à la fenêtre de microsecondes.
- Instrumentez la croissance de l’espace de noms de l’Object Manager (ETW `Microsoft-Windows-Kernel-Object`) afin de détecter les chaînes suspectes comportant des milliers de composants sous `\BaseNamedObjects`.

## References

- [1] [Project Zero – Techniques d’exploitation de Windows : gagner les race conditions avec les recherches de chemins](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/outils de test des liens symboliques](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
