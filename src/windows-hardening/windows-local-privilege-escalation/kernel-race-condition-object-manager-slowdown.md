# Exploitation de conditions de course du kernel via les chemins lents de l'Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi allonger la fenêtre de race est important

De nombreux LPE kernel Windows suivent le schéma classique `check_state(); NtOpenX("name"); privileged_action();`. Sur du matériel moderne, un `NtOpenEvent`/`NtOpenSection` à froid résout un nom court en ~2 µs, laissant presque aucun temps pour modifier l'état vérifié avant que l'action sécurisée ne se produise. En forçant délibérément la recherche dans l'Object Manager Namespace (OMNS) à prendre des dizaines de microsecondes, l'attaquant gagne suffisamment de temps pour l'emporter de manière constante sur des races autrement instables sans avoir besoin de milliers de tentatives.

## Aperçu des internes de la résolution de l'Object Manager

* **Structure OMNS** – Les noms tels que `\BaseNamedObjects\Foo` sont résolus composant par composant (directory-by-directory). Chaque composant amène le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des liens symboliques (par exemple, des lettres de lecteur) peuvent être suivis en chemin.
* **Limite UNICODE_STRING** – Les chemins OM sont transportés dans un `UNICODE_STRING` dont le `Length` est une valeur 16 bits. La limite absolue est de 65 535 octets (32 767 points de code UTF-16). Avec des préfixes comme `\BaseNamedObjects\`, un attaquant contrôle encore ≈32 000 caractères.
* **Prérequis pour l'attaquant** – Tout utilisateur peut créer des objets sous des répertoires inscriptibles tels que `\BaseNamedObjects`. Quand le code vulnérable utilise un nom à l'intérieur, ou suit un lien symbolique qui y aboutit, l'attaquant contrôle les performances de la lookup sans privilèges spéciaux.

## Slowdown primitive #1 – Single maximal component

Le coût de résolution d'un composant est à peu près linéaire avec sa longueur parce que le kernel doit effectuer une comparaison Unicode contre chaque entrée du répertoire parent. La création d'un événement avec un nom long de 32 kB augmente immédiatement la latence de `NtOpenEvent` d'environ ~2 µs à ~35 µs sur Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notes pratiques*

- Vous pouvez atteindre la limite de longueur en utilisant n'importe quel named kernel object (events, sections, semaphores…).
- Les symbolic links ou reparse points peuvent pointer un court “victim” name vers ce composant géant afin que le slowdown soit appliqué de manière transparente.
- Parce que tout se trouve dans des user-writable namespaces, le payload fonctionne à partir d'un standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque saut déclenche la directory resolution logic (ACL checks, hash lookups, reference counting), de sorte que la latence par niveau est supérieure à une simple comparaison de chaînes. Avec ~16 000 niveaux (limités par la même taille `UNICODE_STRING`), les mesures empiriques dépassent la barrière des 35 µs atteinte par de longs composants uniques.
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

* Alternez le caractère par niveau (`A/B/C/...`) si le répertoire parent commence à rejeter les doublons.
* Conservez un tableau de handles pour pouvoir supprimer proprement la chaîne après l'exploitation afin d'éviter de polluer l'espace de noms.

## Mesurer votre race window

Intégrez un petit module de mesure dans votre exploit pour estimer la taille de la race window sur le matériel de la victime. L'extrait ci‑dessous ouvre l'objet cible `iterations` fois et renvoie le coût moyen par ouverture en utilisant `QueryPerformanceCounter`.
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
Les résultats alimentent directement votre race orchestration strategy (p. ex., nombre de worker threads nécessaires, sleep intervals, à quel moment vous devez flip le shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – Tracez le chemin kernel (via symbols, ETW, hypervisor tracing, or reversing) jusqu'à trouver un appel `NtOpen*`/`ObOpenObjectByName` qui parcourt un nom contrôlé par l'attaquant ou un symbolic link dans un répertoire inscriptible par l'utilisateur.
2. **Replace that name with a slow path**
- Créez le composant long ou la chaîne de répertoires sous `\BaseNamedObjects` (ou une autre writable OM root).
- Créez un symbolic link de sorte que le nom attendu par le kernel résolve maintenant vers le slow path. Vous pouvez pointer la directory lookup du driver vulnérable vers votre structure sans toucher la cible originale.
3. **Trigger the race**
- Thread A (victim) exécute le code vulnérable et se bloque dans le slow lookup.
- Thread B (attacker) flip le guarded state (p. ex., swaps un file handle, réécrit un symbolic link, toggles object security) pendant que Thread A est occupé.
- Quand Thread A reprend et effectue l'action privilégiée, il observe un état stale et exécute l'opération contrôlée par l'attaquant.
4. **Clean up** – Supprimez la chaîne de répertoires et les symbolic links pour éviter de laisser des artefacts suspects ou de casser des utilisateurs légitimes d'IPC.

## Operational considerations

- **Combine primitives** – Vous pouvez utiliser un long nom *per level* dans une chaîne de répertoires pour augmenter encore la latence jusqu'à épuiser la taille de `UNICODE_STRING`.
- **One-shot bugs** – La fenêtre élargie (dizaines de microsecondes) rend les “single trigger” bugs réalistes lorsqu'ils sont associés à CPU affinity pinning ou à la préemption assistée par hyperviseur.
- **Side effects** – Le slowdown n'affecte que le chemin malveillant, donc les performances globales du système restent inchangées ; les défenseurs le remarqueront rarement sauf s'ils surveillent la croissance du namespace.
- **Cleanup** – Gardez des handles pour chaque répertoire/objet que vous créez afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Sans cela, des chaînes de répertoires non bornées peuvent persister après reboot.

## Defensive notes

- Le code kernel qui dépend des named objects devrait revalider l'état sensible pour la sécurité *après* l'open, ou prendre une référence avant la vérification (fermer la faille TOCTOU).
- Appliquez des limites supérieures sur la profondeur/longueur des chemins OM avant de déréférencer des noms contrôlés par l'utilisateur. Rejeter les noms trop longs force les attaquants à revenir dans la fenêtre des microsecondes.
- Instrumentez la croissance du namespace de l'object manager (ETW `Microsoft-Windows-Kernel-Object`) pour détecter des chaînes suspectes de milliers de composants sous `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
