# Exploitation d’une race condition du kernel via les chemins lents de l’Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Pourquoi élargir la fenêtre de race est important

De nombreux LPE du kernel Windows suivent le schéma classique `check_state(); NtOpenX("name"); privileged_action();`. Sur le matériel moderne, un `NtOpenEvent`/`NtOpenSection` à froid résout un nom court en ~2 µs, ne laissant presque aucun temps pour modifier l’état vérifié avant l’exécution de l’action sécurisée. En forçant délibérément la recherche dans l’Object Manager Namespace (OMNS) de l’étape 2 à durer plusieurs dizaines de microsecondes, l’attaquant dispose de suffisamment de temps pour remporter de manière constante des races autrement instables, sans avoir besoin de milliers de tentatives.<sup>[[1]](#references)</sup>

## Les composants internes de la recherche de l’Object Manager en bref

* **Structure de l’OMNS** – Les noms tels que `\BaseNamedObjects\Foo` sont résolus répertoire par répertoire. Chaque composant oblige le kernel à trouver/ouvrir un *Object Directory* et à comparer des chaînes Unicode. Des liens symboliques (par exemple, les lettres de lecteur) peuvent être traversés en chemin.
* **Limite de `UNICODE_STRING`** – Les chemins OM sont transportés dans une `UNICODE_STRING` dont `Length` est une valeur de 16 bits. La limite absolue est de 65 535 octets (32 767 points de code UTF-16). Avec des préfixes tels que `\BaseNamedObjects\`, l’attaquant contrôle encore ≈32 000 caractères.
* **Prérequis côté attaquant** – Tout utilisateur peut créer des objets dans des répertoires accessibles en écriture tels que `\BaseNamedObjects`. Lorsque le code vulnérable utilise un nom situé à cet emplacement ou suit un lien symbolique qui y aboutit, l’attaquant contrôle les performances de la recherche sans privilèges particuliers.<sup>[[1]](#references)</sup>

## Primitive de ralentissement n°1 – Composant unique maximal

Le coût de résolution d’un composant est approximativement linéaire par rapport à sa longueur, car le kernel doit effectuer une comparaison Unicode avec chaque entrée du répertoire parent. La création d’un event portant un nom de 32 kB augmente immédiatement la latence de `NtOpenEvent`, qui passe d’environ ~2 µs à ~35 µs sous Windows 11 24H2 (plateforme de test Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Notes pratiques*

- Vous pouvez atteindre la limite de longueur avec n’importe quel objet noyau nommé (events, sections, semaphores…).
- Des liens symboliques ou des points de reparse peuvent faire pointer un nom court de « victim » vers ce composant gigantesque, afin que le ralentissement soit appliqué de manière transparente.
- Comme tout réside dans des namespaces accessibles en écriture par l’utilisateur, le payload fonctionne depuis un niveau d’intégrité utilisateur standard.<sup>[[1]](#references)</sup>

## Primitive de ralentissement n°2 – Répertoires profondément récursifs

Une variante plus agressive alloue une chaîne de milliers de répertoires (`\BaseNamedObjects\A\A\...\X`). Chaque niveau déclenche la logique de résolution des répertoires (vérifications ACL, recherches dans la table de hachage, comptage des références), de sorte que la latence par niveau est supérieure à celle d’une simple comparaison de chaînes. Avec environ 16 000 niveaux (limités par la même taille de `UNICODE_STRING`), les mesures empiriques dépassent la barrière des 35 µs obtenue avec de longs composants uniques.
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

* Alternez le caractère par niveau (`A/B/C/...`) si le répertoire parent commence à rejeter les doublons.
* Conservez un tableau de handles afin de pouvoir supprimer proprement la chaîne après l’exploitation et éviter de polluer le namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes au lieu de microsecondes)

Les répertoires d’objets prennent en charge les **shadow directories** (recherches de repli) et les tables de hachage réparties en buckets pour les entrées. Exploitez ces deux mécanismes ainsi que la limite de reparse de 64 composants des liens symboliques afin de multiplier le ralentissement sans dépasser la longueur de `UNICODE_STRING` :

1. Créez deux répertoires sous `\BaseNamedObjects`, par exemple `A` (shadow) et `A\A` (target). Créez le second en utilisant le premier comme shadow directory (`NtCreateDirectoryObjectEx`), afin que les recherches manquantes dans `A` soient redirigées vers `A\A`.
2. Remplissez chaque répertoire de milliers de **noms entrant en collision** dans le même bucket de hachage (par exemple, en faisant varier les chiffres finaux tout en conservant la même valeur `RtlHashUnicodeString`). Les recherches se dégradent alors en scans linéaires O(n) à l’intérieur d’un seul répertoire.
3. Construisez une chaîne d’environ 63 **liens symboliques de l’Object Manager** qui effectuent à répétition une reparse vers le long suffixe `A\A\…`, consommant le budget de reparse. Chaque reparse recommence l’analyse depuis le début, multipliant le coût des collisions.
4. La recherche du composant final (`...\\0`) prend alors **plusieurs minutes** sous Windows 11 lorsque 16 000 collisions sont présentes par répertoire, offrant une victoire pratiquement garantie dans une race pour des kernel LPEs exécutées en une seule tentative.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Pourquoi c'est important* : Un ralentissement de plusieurs minutes transforme les LPE basées sur une race en exploits déterministes.<sup>[[1]](#references)</sup>

### Notes de retest de 2025 et tooling prêt à l'emploi

- James Forshaw a republié la technique avec des timings mis à jour sur Windows 11 24H2 (ARM64). Les ouvertures de référence restent à environ 2 µs ; un composant de 32 kB porte cette valeur à environ 35 µs, et les chaînes shadow-dir + collision + 63 reparse atteignent toujours environ 3 minutes, confirmant que les primitives fonctionnent encore sur les builds actuels. Le code source et le harness de performance se trouvent dans le post actualisé de Project Zero.<sup>[[1]](#references)</sup>
- Vous pouvez scripter la configuration à l'aide du bundle public `symboliclink-testing-tools` : `CreateObjectDirectory.exe` pour créer la paire shadow/target et `NativeSymlink.exe` dans une boucle pour générer la chaîne de 63 hops. Cela évite d'écrire manuellement des wrappers `NtCreate*` et garantit la cohérence des ACL.<sup>[[2]](#references)</sup>

## Mesurer votre fenêtre de race

Intégrez un harness rapide à votre exploit afin de mesurer la taille de la fenêtre sur le hardware de la victime. Le snippet ci-dessous ouvre l'objet cible `iterations` fois et renvoie le coût moyen par ouverture à l'aide de `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Les résultats alimentent directement votre stratégie d’orchestration de la race (par exemple, le nombre de threads workers nécessaires, les intervalles de veille et le délai avant lequel vous devez basculer l’état partagé).

## Flux d’exploitation

1. **Localiser l’ouverture vulnérable** – Suivez le chemin du kernel (via les symboles, le traçage ETW, l’hyperviseur ou le reverse engineering) jusqu’à trouver un appel `NtOpen*`/`ObOpenObjectByName` qui parcourt un nom contrôlé par l’attaquant ou un lien symbolique dans un répertoire accessible en écriture par l’utilisateur.
2. **Remplacer ce nom par un chemin lent**
- Créez le composant long ou la chaîne de répertoires sous `\BaseNamedObjects` (ou une autre racine OM accessible en écriture).
- Créez un lien symbolique afin que le nom attendu par le kernel résolve désormais vers le chemin lent. Vous pouvez rediriger la recherche de répertoire du driver vulnérable vers votre structure sans toucher à la cible originale.
3. **Déclencher la race**
- Le thread A (victime) exécute le code vulnérable et se bloque pendant la recherche lente.
- Le thread B (attaquant) bascule l’état protégé (par exemple, remplace un handle de fichier, réécrit un lien symbolique ou modifie la sécurité de l’objet) pendant que le thread A est occupé.
- Lorsque le thread A reprend et effectue l’action privilégiée, il observe un état obsolète et exécute l’opération contrôlée par l’attaquant.
4. **Nettoyer** – Supprimez la chaîne de répertoires et les liens symboliques afin d’éviter de laisser des artefacts suspects ou de perturber les utilisateurs légitimes de l’IPC.<sup>[[1]](#references)</sup>

## Chaîne appliquée : placeholders Cloud Files mutables + changement de chemin Object Manager

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), publié comme bypass pour RoguePlanet (CVE-2026-50656), démontre un modèle d’exploitation plus large : faire en sorte qu’un scanner privilégié classe une représentation d’un fichier logique, puis modifier à la fois ses octets et la résolution de son namespace avant que la remédiation ne l’utilise. Le PoC combine un TOCTOU d’hydratation Cloud Files, un fallback vers un shadow-directory de l’Object Manager, la capture d’un nom généré par CLFS et un lien vers un partage administratif local afin de transformer le nettoyage de Defender en écriture d’une DLL protégée.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substituer le contenu via l’hydratation Cloud Files

Enregistrez un répertoire accessible en écriture par l’attaquant comme sync root Cloud Files, connectez un callback `CF_CALLBACK_TYPE_FETCH_DATA` et créez un placeholder dont la taille annoncée correspond à un déclencheur de détection déterministe tel que le ZIP EICAR. Le premier fetch renvoie le déclencheur et bascule l’état du callback ; les fetch suivants renvoient le payload. Après que le scanner a classé la première représentation, obtenez la transfer key et redémarrez l’hydratation avec des métadonnées correspondant à la taille du payload, puis forcez l’hydratation jusqu’à EOF.<sup>[[4]](#references)</sup>
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
La frontière de sécurité échoue si l’analyse, le verdict et la remédiation se réfèrent uniquement à un chemin ou à une identité placeholder : rien ne garantit qu’une hydratation ultérieure renverra les octets qui ont été inspectés.<sup>[[4]](#references)</sup>

### 2. Faire passer un chemin invariant par un fallback de répertoire shadow

Créez un répertoire Object Manager cible et un second répertoire avec `NtCreateDirectoryObjectEx`, en transmettant le handle de la cible comme répertoire shadow/fallback. Placez une entrée `WD_SCAN` portant le même nom dans les deux couches de résolution : l’entrée visible pointe vers le répertoire de travail normal, tandis que l’entrée fallback pointe vers `\CLFS\??\<working-directory>`. Fournissez uniquement le chemin invariant ci-dessous à Defender ; supprimer le lien visible pendant que l’opération est active fait passer la même chaîne vers l’entrée adossée à CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Cette méthode se distingue de l'utilisation de shadow directories uniquement pour ralentir la recherche : l'attaquant modifie la **signification** d'un chemin précédemment accepté sans modifier sa chaîne de caractères.<sup>[[4]](#references)</sup>

### 3. Capturer le nom généré et installer un lien spécifique au nom de fichier

Surveillez le répertoire de travail avec `ReadDirectoryChangesW`. Lors du premier `FILE_ACTION_ADDED`, supprimez le lien `WD_SCAN` visible afin d'activer la recherche de secours. Capturez le deuxième nom de fichier généré, ouvrez ce fichier lié à CLFS et verrouillez la plage `0..MAXLONGLONG` avec `LockFileEx`. Pendant que l'opération privilégiée est bloquée, remplacez `WD_SCAN` dans le répertoire visible par un véritable répertoire Object Manager et créez un lien symbolique enfant nommé d'après le nom de fichier observé (la PoC supprime ses quatre derniers caractères). Faites-le pointer vers la destination protégée via SMB local :<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Le processus non privilégié ne peut pas écrire lui-même à cette destination, mais le contexte SYSTEM de Defender peut parcourir le partage administratif loopback. La combinaison de l'observation des noms générés avec un lien Object Manager spécifique au nom de fichier évite de devoir prédire à l'avance l'artefact de remédiation.<sup>[[4]](#references)</sup>

### 4. Stabiliser la race de nettoyage et déclencher un loader privilégié

Avant l'analyse, le PoC stocke un PE valide (`ntdll.dll`) dans le flux de données alternatif NTFS `:stream` du placeholder. Après que la redirection a créé le fichier de base protégé, il ouvre `phoneinfo.dll:stream` avec un accès d'exécution et conserve une mapping `PAGE_EXECUTE_READ | SEC_IMAGE` active pendant la reprise du nettoyage ; les objets fichier/section actifs limitent la suppression ou le remplacement pendant la race finale. La réhydratation redémarrée renvoie alors la payload DLL plutôt qu'EICAR, de sorte que le fichier de base protégé contient du code contrôlé par l'attaquant.<sup>[[4]](#references)</sup>

Une écriture protégée est ensuite convertie en exécution SYSTEM en plaçant un `Report.wer` spécialement conçu sous `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` et en invoquant `\Microsoft\Windows\Windows Error Reporting\QueueReporting` via l'API COM du Task Scheduler. Dans cette chaîne, le traitement WER privilégié charge le `C:\Windows\System32\phoneinfo.dll` placé par l'attaquant ; une connexion à un named pipe sert de signal d'exécution de la payload.<sup>[[4]](#references)</sup>

### Pivots de détection

Les corrélations utiles sont plus spécifiques qu'un simple nom de fichier temporaire et couvrent toutes les transitions d'espace de noms de la chaîne :<sup>[[4]](#references)</sup>

- Un fournisseur Cloud Files nouvellement enregistré, suivi d'une détection EICAR et de `CF_OPERATION_TYPE_RESTART_HYDRATION` sur le même placeholder.
- Des chemins Object Manager contenant `WD_TARGET_*`, `WD_SHADOW_*` ou `WD_SCAN`, en particulier un chemin d'analyse sous `\\.\globalroot\BaseNamedObjects\Restricted\`.
- La création d'un fichier CLFS suivie d'un verrou exclusif sur l'ensemble du fichier et d'un accès loopback à `\\127.0.0.1\C$\Windows\System32\*.dll` depuis un processus de sécurité privilégié.
- La création d'une DLL System32 accompagnée d'un NTFS ADS, suivie d'une mapping `SEC_IMAGE` du flux.
- Une entrée de file WER créée par l'attaquant, suivie d'une exécution manuelle inhabituelle de `\Microsoft\Windows\Windows Error Reporting\QueueReporting` et du chargement de la DLL placée par l'attaquant.

## Chaîne appliquée : switch de mount point contrôlé par oplock contre une remédiation privilégiée

Un pattern LPE réutilisable apparaît lorsqu'un scanner privilégié vérifie un fichier contrôlé par l'attaquant, puis le traite en le rouvrant via le **pathname** au lieu de continuer avec des handles validés. FalconFlank est un exemple public ciblant le workflow de suppression des macros Office de CrowdStrike Falcon ; le repository affirme avoir effectué des tests sur Windows 11 25H2 et Windows Server 2025 avec la policy concernée activée, mais ne publie aucun CVE, aucune plage de builds affectés, aucun avis du fournisseur ni statut de patch. La revendication spécifique au produit doit donc être considérée comme non vérifiée et dépendante du build.<sup>[[5]](#references)[[6]](#references)</sup>

### Disposition de la race

1. Construire un tree accessible en écriture dont le nom relatif final est utile à la destination visée. L'exemple utilise `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, mais écrit initialement un document de macro OLE — et non une PE DLL — dans `bcrypt.dll`. La détection fondée sur le contenu déclenche la remédiation tout en conservant le basename contrôlé par l'attaquant pour le side-load ultérieur.<sup>[[5]](#references)</sup>
2. Ouvrir les directories avec un partage étendu et `FILE_OPEN_REPARSE_POINT`, puis demander un oplock RH asynchrone sur le trigger avec `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` et `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Attendre l'overlapped event et utiliser sa complétion comme signal de switch du path. Une notification de rupture d'oplock RH est indicative et ne prouve pas que chaque opération conflictuelle est bloquée ; l'exploitabilité dépend donc toujours de la séquence exacte d'ouverture/remédiation de la victime.<sup>[[5]](#references)[[7]](#references)</sup>
3. Après la rupture, supprimer le leaf directory avec `FileDispositionInformationEx` (information class 64) en utilisant les flags de suppression et de sémantique POSIX, fermer son handle, puis appliquer un `IO_REPARSE_TAG_MOUNT_POINT` au parent désormais vide avec `FSCTL_SET_REPARSE_POINT_EX`. Le mount point redirige le suffixe inchangé vers un tree protégé tel que `\\SystemRoot\\System32\\WindowsPowerShell` ; la configuration d'un reparse point échoue si le directory n'est pas vide, ce qui explique l'étape de suppression précédente.<sup>[[5]](#references)[[8]](#references)</sup>
4. Reprendre le workflow privilégié. S'il résout à nouveau la string sans prouver que la chaîne de directories et l'objet final sont ceux qui ont été inspectés précédemment, le même pathname logique atteint désormais le directory protégé choisi par l'attaquant. Dans l'exemple, la réussite est testée en rouvrant `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` en lecture/écriture depuis le processus d'origine ; cela distingue la primitive d'écriture confused-deputy de l'étape ultérieure d'exécution de code.<sup>[[5]](#references)</sup>
5. Remplacer le fichier obtenu par la véritable DLL et activer un loader privilégié. Le PoC utilise `CreateTransaction` + `CreateFileTransacted`, tronque le fichier, mappe le remplacement de la taille de la DLL, copie le PE, puis commit ; TxF associe le file handle et les opérations ultérieures fondées sur des handles à la transaction, mais constitue un mécanisme de remplacement post-race plutôt que la source de l'échec de la boundary de privilèges.<sup>[[5]](#references)[[9]](#references)</sup>
6. Enfin, exécuter une scheduled task privilégiée existante dont l'exécutable recherche le nom adjacent placé par l'attaquant. FalconFlank invoque `\\Microsoft\\Windows\\Application Experience\\MareBackup`, attend que la DLL se connecte à `\\??\\pipe\\FALCONFLANK`, puis supprime le fichier placé. Ne pas déduire un token particulier du seul nom de la task : vérifier le processus lancé, le chemin du module, le niveau d'intégrité et le token sur le build testé.<sup>[[5]](#references)</sup>

La question centrale de l'audit n'est donc pas « le service valide-t-il le path d'entrée d'origine ? », mais « chaque mutation privilégiée reste-t-elle liée aux mêmes objets fichier et directory ouverts qui ont été validés ? ». Conserver les handles entre la vérification et l'utilisation, ouvrir les objets enfants relativement à un handle de directory de confiance, refuser les tags reparse inattendus et revalider l'identité du fichier avant la mutation permettent de fermer cette classe de bug de substitution de pathname.<sup>[[1]](#references)[[8]](#references)</sup>

### Détection et triage du PoC

Une détection à fort signal corrèle la transition d'espace de noms avec le consommateur privilégié : un header OLE sous un basename de DLL dans un tree temporaire nommé par GUID, une rupture d'oplock, la suppression de type POSIX du leaf directory, la création d'un mount point ciblant un directory Windows protégé, puis la création ou la modification du même basename sous cette destination. Pour l'exemple public, ajouter `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, l'exécution manuelle de `MareBackup` et le named pipe `FALCONFLANK` comme pivots plus précis ; aucun n'est suffisant seul.<sup>[[5]](#references)</sup>

Lors de la reproduction du PoC, tenir compte de trois défauts de fiabilité du source publié : il appelle `FlushFileBuffers` avec le pointeur du byte-array intégré au lieu du file handle, teste un `HRESULT` obsolète après `GetFolder`, `GetTask` et `Run`, et utilise des boucles de retry/wait sans limite pour la suppression du directory, la création du reparse, l'event d'oplock et la connexion au pipe.<sup>[[5]](#references)</sup>

## Considérations opérationnelles

- **Combiner les primitives** – Il est possible d'utiliser un nom long *par niveau* dans une chaîne de directories pour augmenter encore la latence jusqu'à épuiser la taille de `UNICODE_STRING`.
- **Bugs one-shot** – La fenêtre élargie (de dizaines de microsecondes à plusieurs minutes) rend réalistes les bugs à « trigger unique » lorsqu'ils sont associés à l'épinglage de l'affinité CPU ou à la préemption assistée par hypervisor.
- **Effets secondaires** – Le ralentissement n'affecte que le path malveillant ; les performances globales du système restent donc inchangées. Les defenders le remarqueront rarement s'ils ne surveillent pas la croissance de l'espace de noms.
- **Nettoyage** – Conserver les handles de chaque directory/objet créé afin de pouvoir appeler `NtMakeTemporaryObject`/`NtClose` ensuite. Les chaînes de directories sans limite peuvent sinon persister après les reboots.
- **Races du file system** – Si le path vulnérable est finalement résolu via NTFS, il est possible de placer un Oplock (par exemple `SetOpLock.exe` du même toolkit) sur le fichier sous-jacent pendant l'exécution du ralentissement OM, afin de figer le consumer pendant quelques millisecondes supplémentaires sans modifier le graphe OM.<sup>[[2]](#references)</sup>

## Notes défensives

- Le code kernel qui s'appuie sur des objets nommés doit revalider l'état sensible à la sécurité *après* l'ouverture, ou prendre une référence avant la vérification (pour fermer la fenêtre TOCTOU).
- Imposer des limites supérieures à la profondeur/longueur des paths OM avant de déréférencer les noms contrôlés par l'utilisateur. Le rejet des noms excessivement longs force les attaquants à revenir à la fenêtre de quelques microsecondes.
- Instrumenter la croissance de l'espace de noms de l'Object Manager (ETW `Microsoft-Windows-Kernel-Object`) afin de détecter les chaînes suspectes comportant des milliers de composants sous `\BaseNamedObjects`.

## References

- [1] [Project Zero – Techniques d'exploitation Windows : gagner les race conditions avec les recherches de paths](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Comment utiliser Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
