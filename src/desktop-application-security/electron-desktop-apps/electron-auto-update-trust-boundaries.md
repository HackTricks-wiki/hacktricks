# Frontières de confiance des mises à jour automatiques d’Electron

{{#include ../../banners/hacktricks-training.md}}

## Surface d’attaque des mises à jour automatiques d’Electron

Considérez un updater comme une frontière d’exécution de code à distance : il récupère du contenu exécutable, détermine si ce contenu est plus récent et digne de confiance, le prépare localement, puis le transmet à un programme d’installation. Examinez l’ensemble du graphe de confiance — index des versions, métadonnées par version, artefact, signatures détachées, clé de vérification intégrée, cache, chemin temporaire et programme d’installation — et pas seulement la signature du `.app` final.<sup>[[1]](#references)[[2]](#references)</sup>

### Tests à forte valeur

- **Rollback/rejeu :** rejouez un manifeste précédemment valide ainsi que son artefact toujours signé. Une signature authentifie son contenu, mais ne garantit pas son actualité ; le client doit rejeter les versions inférieures à un seuil monotone persistant, sauf si une politique de récupération authentifiée autorise explicitement le rollback.<sup>[[2]](#references)</sup>
- **Substitution de métadonnées/d’artefact :** modifiez séparément la version, l’URL, le hash attendu, l’artefact et la signature détachée. Essayez également de combiner une paire artefact/signature valide issue d’une version avec les métadonnées d’une autre. Si les métadonnées de version ne sont pas signées, TLS ou la signature de l’exécutable final n’empêchent pas un CDN ou une origine compromis de modifier la logique de sélection.<sup>[[1]](#references)[[2]](#references)</sup>
- **Confusion entre canaux signés :** diffusez une version alpha, beta, de développement ou de débogage légitimement signée par le canal de production. Réutiliser la même clé et la même politique pour tous les environnements permet à l’artefact de passer une vérification limitée au signataire ; l’identité et le canal de production doivent faire partie de la politique authentifiée, ou utiliser une racine de confiance distincte.<sup>[[2]](#references)</sup>
- **TOCTOU sur le fichier temporaire :** déterminez si la vérification ouvre un chemin d’accès et si l’installation ouvre ensuite à nouveau ce même chemin. Si un attaquant local peut renommer, remplacer ou rediriger l’objet préparé entre ces opérations, le programme d’installation peut consommer des octets qui n’ont jamais été vérifiés. Un répertoire de préparation en mode `0700` limite l’accès, mais ne rend pas les deux opérations atomiques.<sup>[[2]](#references)</sup>

Le triage statique et à l’exécution permet de repérer rapidement ces frontières.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Lors d’un test autorisé, interceptez la vérification des mises à jour, archivez chaque réponse et modifiez un seul champ à la fois. Inspectez ensuite le propriétaire et le mode du répertoire de staging, puis tracez les ouvertures de fichiers du téléchargement à l’installation. Sur macOS, poursuivez avec les [tests des limites de confiance de l’installateur](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) si le flux atteint un helper privilégié, et examinez les [faiblesses de la signature de code](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) au lieu de considérer « signé » comme une vérification complète de l’identité.<sup>[[2]](#references)</sup>

### Liaison et politique attendues

Une conception défendable authentifie à la fois les métadonnées de sélection et les octets de l’artefact. La conception de référence SafeUpdater montre l’utilisation d’une clé publique Ed25519 intégrée, de manifestes et d’artefacts signés, d’un message signé dérivé de `SHA-256(file)` et de la version, ainsi que d’un condensat d’artefact SHA-512 stocké dans des métadonnées signées ; il s’agit explicitement d’une référence de recherche et non d’un paquet prêt pour la production.<sup>[[1]](#references)[[2]](#references)</sup>

Vérifiez que la cible fournit également les propriétés suivantes.<sup>[[1]](#references)[[2]](#references)</sup>

- utilise une représentation signée non ambiguë qui lie le condensat de l’artefact à sa version canonique et à son environnement de publication ;
- désactive la rétrogradation par défaut et impose une version minimale acceptée pour les retours arrière autorisés ;
- sépare la production de la non-production au moyen de clés/canaux distincts ou de données de politique de publication authentifiées ; et
- installe le fichier ouvert déjà vérifié (ou un handle/objet immuable équivalent) au lieu de résoudre à nouveau le même chemin d’accès.

## References

- [1] [Implémentation de référence Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater : concevoir un mécanisme sécurisé de mise à jour automatique pour Electron](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
