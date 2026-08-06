# Forensics du cache Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Cette page résume comment effectuer le triage des artefacts du cache de Discord Desktop afin de récupérer des fichiers exfiltrés, des endpoints de webhook et des chronologies d'activité. Discord Desktop est une application Electron/Chromium et utilise Chromium Simple Cache sur le disque.

## Où chercher (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Principales structures sur disque dans Cache_Data:<sup>[[1]](#references)</sup>
- index: base de données d'index Simple Cache
- data_#: fichiers de blocs binaires du cache pouvant contenir plusieurs objets mis en cache
- f_######: entrées individuelles du cache stockées dans des fichiers autonomes (souvent des corps plus volumineux)

Remarque: la suppression de messages/canaux/serveurs dans Discord ne purge pas ce cache local. Les éléments mis en cache restent souvent présents et leurs timestamps de fichiers correspondent à l'activité de l'utilisateur, ce qui permet de reconstruire une chronologie.<sup>[[1]](#references)</sup>

## Éléments pouvant être récupérés

- Pièces jointes exfiltrées et miniatures récupérées via cdn.discordapp.com/media.discordapp.net
- Images, GIFs, vidéos (par ex., .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Appels à l'API Discord (https://discord.com/api/vX/…)
- Utile pour corréler le beaconing/l'activité d'exfiltration et hacher les médias afin de les comparer à des renseignements<sup>[[1]](#references)</sup>

## Triage rapide (manuel)

- Rechercher dans le cache les artefacts à forte valeur indicative:
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de pièces jointes/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Appels à l'API Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Trier les entrées mises en cache par date de modification afin de construire rapidement une chronologie (mtime reflète le moment où l'objet a été mis en cache):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Analyse des entrées f_* (HTTP body + headers)

Les fichiers commençant par f_ contiennent les en-têtes de réponse HTTP suivis du body. Le bloc d'en-têtes se termine généralement par \r\n\r\n. Les en-têtes de réponse utiles comprennent:
- Content-Type: pour déduire le type de média
- Content-Location ou X-Original-URL: URL distante d'origine pour l'aperçu/la corrélation
- Content-Encoding: peut être gzip/deflate/br (Brotli)

Les médias peuvent être extraits en séparant les en-têtes du body et, éventuellement, en les décompressant selon Content-Encoding. L'identification par magic bytes est utile lorsque Content-Type est absent.

## DFIR automatisé: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Fonction: analyse récursivement le dossier de cache de Discord, trouve les URLs de webhook/API/pièces jointes, analyse les bodies f_*, peut éventuellement extraire les médias et produit des rapports de chronologie HTML + CSV avec des hashes SHA‑256.<sup>[[2]](#references)</sup>

Exemple d'utilisation CLI:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
Options principales :
- --cache: Chemin vers Cache_Data
- --format html|csv|both
- --timeline: Génère une timeline CSV ordonnée (par date de modification)
- --extra: Analyse également Code Cache et GPUCache voisins
- --carve: Extrait les médias des octets bruts à proximité des correspondances regex (images/vidéos)
- Sortie : rapport HTML, rapport CSV, timeline CSV et dossier de médias contenant les fichiers extraits

## Conseils pour l'analyse

- Corrélez la date de modification (mtime) des fichiers f_* et data_* avec les périodes d'activité de l'utilisateur/de l'attaquant afin de reconstituer une timeline.
- Hash les médias récupérés (SHA-256) et comparez-les à des jeux de données connus comme malveillants ou exfiltrés.
- Les URLs de webhook extraites peuvent être testées pour vérifier leur disponibilité ou être renouvelées ; envisagez de les ajouter aux blocklists et d'effectuer une chasse rétrospective sur les proxies.
- Le cache persiste après un « effacement » côté serveur. Si l'acquisition est possible, collectez l'intégralité du répertoire Cache ainsi que les caches voisins associés (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Références

- [1] [Discord comme C2 et les preuves mises en cache laissées derrière](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
