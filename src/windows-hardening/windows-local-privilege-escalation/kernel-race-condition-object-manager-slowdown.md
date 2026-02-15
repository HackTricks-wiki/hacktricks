# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Les noms tels que `\BaseNamedObjects\Foo` sont résolus composant par composant. Chaque composant amène le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des liens symboliques (par ex., des lettres de lecteur) peuvent être traversés en chemin.
* **UNICODE_STRING limit** – Les chemins OM sont transportés dans un `UNICODE_STRING` dont le champ `Length` est une valeur 16 bits. La limite absolue est de 65 535 octets (32 767 points de code UTF-16). Avec des préfixes comme `\BaseNamedObjects\`, un attaquant contrôle encore ≈32 000 caractères.
* **Attacker prerequisites** – Tout utilisateur peut créer des objets sous des répertoires inscriptibles tels que `\BaseNamedObjects`. Quand le code vulnérable utilise un nom à l'intérieur, ou suit un lien symbolique qui pointe là, l'attaquant contrôle la performance de la résolution sans privilèges spéciaux.

## Slowdown primitive #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notes pratiques*

- Vous pouvez atteindre la limite de longueur en utilisant n'importe quel objet noyau nommé (events, sections, semaphores…).
- Symbolic links or reparse points peuvent pointer un nom court “victim” vers ce composant géant afin que le ralentissement soit appliqué de façon transparente.
- Parce que tout vit dans des espaces de noms modifiables par l'utilisateur, le payload fonctionne depuis un niveau d'intégrité utilisateur standard.

## Primitive de ralentissement #2 – Répertoires récursifs profonds

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque saut déclenche la logique de résolution des répertoires (ACL checks, hash lookups, reference counting), donc la latence par niveau est supérieure à celle d'une simple comparaison de chaînes. Avec ~16 000 niveaux (limités par la même taille `UNICODE_STRING`), les mesures empiriques dépassent la barrière des 35 µs atteinte par de longs composants simples.
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
Tips:

* Alternez le caractère par niveau (`A/B/C/...`) si le répertoire parent commence à refuser les doublons.
* Gardez un handle array afin de pouvoir supprimer proprement la chaîne après l'exploitation pour éviter de polluer l'espace de noms.

## Primitive de ralentissement #3 – Shadow directories, hash collisions & symlink reparses (minutes au lieu de microsecondes)

Les object directories prennent en charge les **shadow directories** (recherches de secours) et des tables de hachage bucketed pour les entrées. Exploitez les deux ainsi que la limite de 64 composants pour les symbolic-link reparses afin de multiplier le ralentissement sans dépasser la longueur de `UNICODE_STRING` :

1. Créez deux répertoires sous `\BaseNamedObjects`, par ex. `A` (shadow) et `A\A` (target). Créez le second en utilisant le premier comme shadow directory (`NtCreateDirectoryObjectEx`), ainsi les recherches manquantes dans `A` retombent sur `A\A`.
2. Remplissez chaque répertoire avec des milliers de **colliding names** qui tombent dans le même hash bucket (par ex., en variant les chiffres de fin tout en gardant la même valeur `RtlHashUnicodeString`). Les lookups se dégradent alors en scans linéaires O(n) à l'intérieur d'un seul répertoire.
3. Construisez une chaîne d'environ 63 **object manager symbolic links** qui reparsent de manière répétée vers le long suffixe `A\A\…`, consommant le budget de reparse. Chaque reparse redémarre l'analyse depuis le début, multipliant le coût des collisions.
4. La lookup du composant final (`...\\0`) prend maintenant **des minutes** sur Windows 11 lorsque 16 000 collisions sont présentes par répertoire, offrant une victoire de race pratiquement garantie pour des kernel LPEs one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important* : Un ralentissement de plusieurs minutes transforme des LPE one-shot basés sur des race conditions en exploits déterministes.

### Notes de retest 2025 et outils prêts à l'emploi

- James Forshaw a republié la technique avec des timings mis à jour sur Windows 11 24H2 (ARM64). Les opens de base restent ~2 µs ; un composant de 32 kB porte cela à ~35 µs, et les shadow-dir + collision + 63-reparse chains atteignent encore ~3 minutes, confirmant que les primitives survivent aux builds actuels. Le code source et le perf harness sont dans le post Project Zero actualisé.
- Vous pouvez automatiser la configuration en utilisant le bundle public `symboliclink-testing-tools` : `CreateObjectDirectory.exe` pour engendrer la paire shadow/target et `NativeSymlink.exe` en boucle pour émettre la chaîne de 63 sauts. Cela évite les wrappers `NtCreate*` écrits à la main et garde les ACLs cohérentes.

## Mesurer votre fenêtre de race

Intégrez un petit harness dans votre exploit pour mesurer l'ampleur de la fenêtre sur le hardware de la victime. L'extrait ci-dessous ouvre l'objet cible `iterations` fois et renvoie le coût moyen par open en utilisant `QueryPerformanceCounter`.
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
Les résultats alimentent directement votre stratégie d'orchestration de race (par ex., nombre de worker threads nécessaires, sleep intervals, how early you need to flip the shared state).

## Exploitation workflow

1. **Localiser l'open vulnérable** – Tracez le kernel path (via symbols, ETW, hypervisor tracing, or reversing) jusqu'à trouver un appel `NtOpen*`/`ObOpenObjectByName` qui parcourt un nom contrôlé par l'attaquant ou un symbolic link dans un répertoire user-writable.
2. **Remplacer ce nom par un slow path**
- Créez le long component ou la chaîne de répertoires sous `\BaseNamedObjects` (ou un autre writable OM root).
- Créez un symbolic link pour que le nom attendu par le kernel résolve désormais vers le slow path. Vous pouvez pointer la directory lookup du driver vulnérable vers votre structure sans toucher la cible originale.
3. **Déclencher la race**
- Thread A (victim) exécute le code vulnérable et se bloque dans le slow lookup.
- Thread B (attacker) flips the guarded state (e.g., swaps a file handle, rewrites a symbolic link, toggles object security) pendant que Thread A est occupé.
- Quand Thread A reprend et effectue l'action privilégiée, il observe un état stale et réalise l'opération contrôlée par l'attaquant.
4. **Nettoyage** – Supprimez la chaîne de répertoires et les symbolic links pour éviter de laisser des artefacts suspects ou de casser des utilisateurs IPC légitimes.

## Considérations opérationnelles

- **Combiner des primitives** – Vous pouvez utiliser un long nom *per level* dans une chaîne de répertoires pour augmenter encore la latence jusqu'à épuiser la taille `UNICODE_STRING`.
- **Bugs one-shot** – La fenêtre élargie (dizaines de microsecondes à minutes) rend les bugs “single trigger” réalistes lorsqu'ils sont associés à CPU affinity pinning ou hypervisor-assisted preemption.
- **Effets secondaires** – Le slowdown n'affecte que le malicious path, donc les performances système globales restent inchangées ; les défenseurs remarqueront rarement à moins de monitorer la croissance du namespace.
- **Nettoyage** – Conservez des handles pour chaque directory/object que vous créez afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Sans cela, des chaînes de répertoires non bornées peuvent persister après un reboot.
- **File-system races** – Si le path vulnérable se résout finalement via NTFS, vous pouvez empiler un Oplock (e.g., `SetOpLock.exe` from the same toolkit) sur le fichier backing pendant que le OM slowdown tourne, gelant le consumer pour des millisecondes supplémentaires sans altérer le OM graph.

## Notes défensives

- Le code kernel qui s'appuie sur des named objects devrait re-valider l'état sensible pour la sécurité *après* l'open, ou prendre une référence avant la vérification (fermer la fenêtre TOCTOU).
- Appliquez des bornes supérieures sur la profondeur/longueur des OM path avant de déréférencer des noms contrôlés par l'utilisateur. Rejeter les noms excessivement longs force les attaquants à revenir dans la fenêtre de microsecondes.
- Instrumentez la croissance du namespace de l'object manager (ETW `Microsoft-Windows-Kernel-Object`) pour détecter des chaînes suspectes de milliers de composants sous `\BaseNamedObjects`.

## Références

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
