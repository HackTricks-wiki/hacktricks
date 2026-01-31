# Exploitation de race conditions du kernel via les Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

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
*Remarques pratiques*

- Vous pouvez atteindre la limite de longueur en utilisant n'importe quel objet noyau nommé (events, sections, semaphores…).
- Les liens symboliques ou reparse points peuvent pointer un court nom “victim” vers ce composant géant afin que le slowdown soit appliqué de façon transparente.
- Parce que tout réside dans des espaces de noms modifiables par l'utilisateur, le payload fonctionne depuis un niveau d'intégrité utilisateur standard.

## Slowdown primitive #2 – Deep recursive directories

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque saut déclenche la logique de résolution de répertoire (ACL checks, hash lookups, reference counting), donc la latence par niveau est plus élevée qu'une simple comparaison de chaîne. Avec ~16 000 niveaux (limitée par la même taille `UNICODE_STRING`), les mesures empiriques dépassent la barrière des 35 µs atteinte par de longs composants simples.
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
* Conservez un handle array afin de pouvoir supprimer proprement la chaîne après exploitation pour éviter de polluer le namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories support **shadow directories** (recherches de secours) et des tables de hachage bucketisées pour les entrées. Abusez des deux plus la limite de 64 composants pour le symbolic-link reparse afin de multiplier le ralentissement sans dépasser la longueur de `UNICODE_STRING`:

1. Créez deux répertoires sous `\BaseNamedObjects`, p.ex. `A` (shadow) et `A\A` (target). Créez le second en utilisant le premier comme shadow directory (`NtCreateDirectoryObjectEx`), de sorte que les recherches manquantes dans `A` retombent sur `A\A`.
2. Remplissez chaque répertoire avec des milliers de **colliding names** qui tombent dans le même hash bucket (p.ex. en variant des chiffres de fin tout en gardant la même valeur `RtlHashUnicodeString`). Les lookups se dégradent maintenant en scans linéaires O(n) à l'intérieur d'un seul répertoire.
3. Construisez une chaîne d'environ 63 **object manager symbolic links** qui reparse de manière répétée vers le long suffixe `A\A\…`, consommant le budget de reparse. Chaque reparse redémarre l'analyse depuis le début, multipliant le coût des collisions.
4. La lookup du composant final (`...\\0`) prend maintenant **minutes** sur Windows 11 lorsqu'il y a 16 000 collisions par répertoire, fournissant une victoire de race pratiquement garantie pour des kernel LPEs one-shot.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important*: Un ralentissement de plusieurs minutes transforme les one-shot race-based LPEs en exploits déterministes.

## Mesurer votre fenêtre de race

Intégrez un harness rapide dans votre exploit pour mesurer la taille de la fenêtre sur le matériel de la victime. L'extrait ci-dessous ouvre l'objet cible `iterations` fois et renvoie le coût moyen par ouverture en utilisant `QueryPerformanceCounter`.
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
Les résultats alimentent directement votre race orchestration strategy (par ex., nombre de worker threads nécessaires, sleep intervals, à quel moment il faut flip le shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Créez le composant long ou la chaîne de répertoires sous `\BaseNamedObjects` (ou un autre OM root inscriptible).
- Créez un lien symbolique de sorte que le nom attendu par le kernel résolve maintenant vers le slow path. Vous pouvez diriger la recherche de répertoire du driver vulnérable vers votre structure sans toucher la cible originale.
3. **Trigger the race**
- Thread A (victim) exécute le code vulnérable et se bloque pendant la lookup lente.
- Thread B (attacker) modifie l'état protégé (par ex., échange un file handle, réécrit un lien symbolique, bascule la sécurité de l'objet) pendant que Thread A est occupé.
- Quand Thread A reprend et effectue l'action privilégiée, il observe un état obsolète et réalise l'opération contrôlée par l'attaquant.
4. **Clean up** – Supprimez la chaîne de répertoires et les liens symboliques pour éviter de laisser des artefacts suspects ou de casser des utilisateurs IPC légitimes.

## Operational considerations

- **Combine primitives** – Vous pouvez utiliser un nom long *par niveau* dans une chaîne de répertoires pour obtenir une latence encore plus élevée jusqu'à épuiser la taille de `UNICODE_STRING`.
- **One-shot bugs** – La fenêtre élargie (de dizaines de microsecondes à des minutes) rend les bugs “single trigger” réalistes lorsqu'ils sont associés au CPU affinity pinning ou à la préemption assistée par hyperviseur.
- **Side effects** – Le slowdown n'affecte que le chemin malveillant, donc les performances globales du système restent inchangées ; les défenseurs le remarqueront rarement sauf s'ils surveillent la croissance du namespace.
- **Cleanup** – Conservez des handles sur chaque répertoire/objet que vous créez afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Sinon, des chaînes de répertoires non bornées peuvent persister après un reboot.

## Defensive notes

- Kernel code that relies on named objects should re-validate security-sensitive state *after* the open, or take a reference before the check (closing the TOCTOU gap).
- Imposer des limites supérieures sur la profondeur/longueur des chemins OM avant de déréférencer des noms contrôlés par l'utilisateur. Refuser les noms excessivement longs force les attaquants à revenir dans la fenêtre microseconde.
- Instrumentez la croissance du namespace de l'Object Manager (ETW `Microsoft-Windows-Kernel-Object`) pour détecter des chaînes suspectes de milliers de composants sous `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
