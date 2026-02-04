# Exploitation de conditions de course du kernel via les slow paths de l'Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi élargir la fenêtre de race est important

Beaucoup de LPE kernel sous Windows suivent le schéma classique `check_state(); NtOpenX("name"); privileged_action();`. Sur du matériel moderne, un `NtOpenEvent`/`NtOpenSection` froid résout un nom court en ~2 µs, laissant presque aucun temps pour inverser l'état vérifié avant que l'action protégée ait lieu. En forçant délibérément la lookup de l'Object Manager Namespace (OMNS) à l'étape 2 à durer des dizaines de microsecondes, l'attaquant gagne suffisamment de temps pour remporter de façon constante des races autrement instables sans avoir besoin de milliers de tentatives.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Les noms comme `\BaseNamedObjects\Foo` sont résolus répertoire-par-répertoire. Chaque composant force le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des symbolic links (par ex. des lettres de lecteur) peuvent être traversés en chemin.
* **UNICODE_STRING limit** – Les chemins OM sont transportés à l'intérieur d'un `UNICODE_STRING` dont le `Length` est une valeur 16 bits. La limite absolue est de 65 535 bytes (32 767 codepoints UTF-16). Avec des préfixes comme `\BaseNamedObjects\`, un attaquant contrôle encore ≈32 000 caractères.
* **Attacker prerequisites** – N'importe quel utilisateur peut créer des objects sous des répertoires inscriptibles tels que `\BaseNamedObjects`. Quand le code vulnérable utilise un nom à l'intérieur, ou suit un symbolic link qui y mène, l'attaquant contrôle les performances de la lookup sans privilèges spéciaux.

## Primitive de ralentissement #1 – Composant maximal unique

Le coût de résolution d'un composant est à peu près linéaire avec sa longueur parce que le kernel doit effectuer une comparaison Unicode contre chaque entrée dans le répertoire parent. Créer un event avec un nom de 32 kB augmente immédiatement la latence de `NtOpenEvent` d'environ ~2 µs à ~35 µs sur Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Remarques pratiques*

- Vous pouvez atteindre la limite de longueur en utilisant n'importe quel objet kernel nommé (events, sections, semaphores…).
- Symbolic links or reparse points can point a short “victim” name to this giant component so the slowdown is applied transparently.
- Because everything lives in user-writable namespaces, the payload works from a standard user integrity level.

## Primitive de ralentissement #2 – Répertoires récursifs profonds

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
Conseils :

* Alternez le caractère par niveau (`A/B/C/...`) si le répertoire parent commence à refuser les doublons.
* Conservez un handle array pour pouvoir supprimer proprement la chaîne après l'exploitation afin d'éviter de polluer l'espace de noms.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes au lieu de microsecondes)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **minutes** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important* : Un ralentissement de plusieurs minutes transforme des one-shot race-based LPEs en exploits déterministes.

## Mesurer votre fenêtre de race

Intégrez un petit banc de test dans votre exploit pour mesurer l'ampleur de la fenêtre sur le matériel de la victime. L'extrait ci-dessous ouvre l'objet cible `iterations` fois et renvoie le coût moyen par ouverture en utilisant `QueryPerformanceCounter`.
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
Les résultats alimentent directement votre stratégie d'orchestration de race (p. ex., nombre de threads de travail nécessaires, intervalles de pause, à quel moment vous devez basculer l'état partagé).

## Flux d'exploitation

1. **Locate the vulnerable open** – Tracez le chemin dans le kernel (via symbols, ETW, hypervisor tracing, or reversing) jusqu'à trouver un appel NtOpen*/ObOpenObjectByName qui parcourt un nom contrôlé par l'attaquant ou un lien symbolique dans un répertoire écrivable par l'utilisateur.
2. **Replace that name with a slow path**
- Créez le composant long ou la chaîne de répertoires sous \BaseNamedObjects (ou une autre racine OM écrivable).
- Créez un lien symbolique afin que le nom attendu par le kernel résolve désormais vers le chemin lent. Vous pouvez diriger la recherche de répertoire du pilote vulnérable vers votre structure sans toucher la cible originale.
3. **Trigger the race**
- Thread A (victim) exécute le code vulnérable et se bloque pendant la recherche lente.
- Thread B (attacker) bascule l'état protégé (p. ex., échange un handle de fichier, réécrit un lien symbolique, bascule la sécurité d'un objet) pendant que Thread A est occupé.
- Quand Thread A reprend et exécute l'action privilégiée, il observe un état obsolète et effectue l'opération contrôlée par l'attaquant.
4. **Clean up** – Supprimez la chaîne de répertoires et les liens symboliques pour éviter de laisser des artefacts suspects ou de casser des utilisateurs IPC légitimes.

## Considérations opérationnelles

- **Combine primitives** – Combinez des primitives : vous pouvez utiliser un nom long par niveau dans une chaîne de répertoires pour augmenter encore la latence jusqu'à épuisement de la taille de UNICODE_STRING.
- **One-shot bugs** – La fenêtre élargie (de dizaines de microsecondes à minutes) rend les bugs « single trigger » réalistes lorsqu'ils sont combinés avec le pinning d'affinité CPU ou la préemption assistée par hyperviseur.
- **Side effects** – Le ralentissement n'affecte que le chemin malveillant, donc les performances globales du système restent inchangées ; les défenseurs le remarqueront rarement sauf s'ils surveillent la croissance de l'espace de noms.
- **Cleanup** – Conservez des handles pour chaque répertoire/objet que vous créez afin de pouvoir appeler NtMakeTemporaryObject/NtClose ensuite. Sinon, des chaînes de répertoires non bornées peuvent persister après un reboot.

## Notes défensives

- Le code kernel qui se base sur des objets nommés devrait ré-valider l'état sensible à la sécurité *après* l'open, ou prendre une référence avant la vérification (comblant la faille TOCTOU).
- Imposer des bornes supérieures sur la profondeur/longueur des chemins OM avant de déréférencer des noms contrôlés par l'utilisateur. Rejeter les noms trop longs renvoie les attaquants dans la fenêtre de microsecondes.
- Instrumentez la croissance de l'espace de noms de l'object manager (ETW `Microsoft-Windows-Kernel-Object`) pour détecter des chaînes suspectes de milliers de composants sous \BaseNamedObjects.

## Références

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
