# Extraction de configuration et TTPs d’AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire open source de post-exploitation/C2, avec des beacons Windows x86/x64 (EXE/DLL/service EXE/shellcode brut) et la prise en charge des BOF.<sup>[[1]](#references)</sup> Cette page décrit :
- Comment sa configuration empaquetée avec RC4 est intégrée et comment l’extraire des beacons
- Les indicateurs réseau/profil des listeners HTTP/SMB/TCP
- Les TTPs courantes de loader et de persistance observées sur le terrain, avec des liens vers les pages consacrées aux techniques Windows correspondantes

Les versions récentes en amont incluent également des listeners beacon DNS/DoH et la famille distincte d’agents/listeners Gopher ; les infrastructures Adaptix modernes peuvent donc exposer plus que les surfaces HTTP/SMB/TCP d’origine, même lorsqu’un échantillon donné utilise encore l’agent beacon classique.<sup>[[2]](#references)</sup>

## Profils et champs des beacons

AdaptixC2 prend en charge trois types principaux de beacon :<sup>[[1]](#references)</sup>
- BEACON_HTTP : C2 web avec serveurs/ports/SSL configurables, méthode, URI, en-têtes, user-agent et nom de paramètre personnalisé
- BEACON_SMB : C2 pair-à-pair par named pipe (intranet)
- BEACON_TCP : sockets directes, avec éventuellement un marqueur préfixé pour masquer le début du protocole

Il s’agit des structures de beacon documentées publiquement dans les premières analyses d’Adaptix, et elles restent le point de départ le plus courant pour l’extraction côté échantillon.<sup>[[1]](#references)</sup> Toutefois, les versions actuelles en amont incluent aussi `BeaconDNS` et les extensions Gopher côté serveur ; ne partez donc pas du principe que chaque déploiement Adaptix actif expose uniquement une infrastructure HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Champs typiques des profils observés dans les configurations de beacon HTTP (après déchiffrement) :<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (chaînes préfixées par leur longueur)
- ans_pre_size (u32), ans_size (u32) – utilisés pour analyser les tailles des réponses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Les versions récentes de BeaconHTTP prennent également en charge la rotation, choisie par l’opérateur, entre plusieurs URI, user-agents, en-têtes Host et serveurs, avec une sélection séquentielle ou aléatoire.<sup>[[2]](#references)</sup> Pour la détection, cela signifie qu’un seul hôte infecté peut répartir ses connexions de rappel entre plusieurs chemins et combinaisons d’en-têtes, tout en restant dans la famille classique des beacons empaquetés avec RC4.

Exemple de profil HTTP par défaut (issu d’une compilation de beacon) :<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["172.16.196.1"],
  "ports": [4443],
  "http_method": "POST",
  "uri": "/uri.php",
  "parameter": "X-Beacon-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 2,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

Profil HTTP malveillant observé (attaque réelle) :<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["tech-system[.]online"],
  "ports": [443],
  "http_method": "POST",
  "uri": "/endpoint/api",
  "parameter": "X-App-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 4,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

## Empaquetage de la configuration chiffrée et chemin de chargement

Lorsque l’opérateur clique sur Create dans le builder, AdaptixC2 intègre le profil chiffré sous forme de blob de fin dans le beacon. Le format est le suivant :<sup>[[1]](#references)</sup>
- 4 octets : taille de la configuration (uint32, little-endian)
- N octets : données de configuration chiffrées avec RC4
- 16 octets : clé RC4

Le chargeur du beacon copie la clé de 16 octets depuis la fin, puis déchiffre avec RC4 le bloc de N octets sur place :<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implications pratiques :<sup>[[1]](#references)</sup>
- La structure entière se trouve souvent dans la section PE .rdata.
- L’extraction est déterministe : lire la taille, lire le texte chiffré de cette taille, lire la clé de 16 octets placée juste après, puis déchiffrer avec RC4.

## Flux de travail d’extraction de la configuration (défenseurs)

Écrivez un extracteur qui reproduit la logique du beacon :<sup>[[1]](#references)</sup>
1) Localisez le blob dans le PE (généralement dans .rdata). Une approche pragmatique consiste à parcourir .rdata à la recherche d’une disposition [taille|texte chiffré|clé de 16 octets] plausible et à tenter un déchiffrement RC4.
2) Lisez les 4 premiers octets → taille (uint32 LE).
3) Lisez les N octets suivants, où N=size → texte chiffré.
4) Lisez les 16 derniers octets → clé RC4.
5) Déchiffrez le texte chiffré avec RC4. Analysez ensuite le profil en clair comme suit :
   - scalaires u32/bool, comme indiqué ci-dessus
   - chaînes préfixées par leur longueur (longueur u32 suivie des octets ; un NUL final peut être présent)
   - tableaux : servers_count suivi d’autant de paires [chaîne, port u32]

Preuve de concept minimale en Python (autonome, sans dépendances externes) fonctionnant avec un blob préalablement extrait :

```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

class P:
    def __init__(self, buf: bytes):
        self.b = buf; self.o = 0
    def u32(self) -> int:
        v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def u8(self) -> int:
        v = self.b[self.o]; self.o += 1; return v
    def s(self) -> str:
        L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
        return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    cfg = {}
    cfg['agent_type']    = p.u32()
    cfg['use_ssl']       = bool(p.u8())
    n                    = p.u32()
    cfg['servers']       = []
    cfg['ports']         = []
    for _ in range(n):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method']   = p.s()
    cfg['uri']           = p.s()
    cfg['parameter']     = p.s()
    cfg['user_agent']    = p.s()
    cfg['http_headers']  = p.s()
    cfg['ans_pre_size']  = p.u32()
    cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
    cfg['kill_date']     = p.u32()
    cfg['working_time']  = p.u32()
    cfg['sleep_delay']   = p.u32()
    cfg['jitter_delay']  = p.u32()
    cfg['listener_type'] = 0
    cfg['download_chunk_size'] = 0x19000
    return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```

Conseils :
- Lors de l’automatisation, utilisez un parseur PE pour lire .rdata, puis appliquez une fenêtre glissante : pour chaque offset o, essayez size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = les 16 octets suivants ; déchiffrez avec RC4 et vérifiez que les champs de chaîne se décodent en UTF-8 et que les longueurs sont plausibles.
- Parsez les profils SMB/TCP en suivant les mêmes conventions de préfixage des longueurs.

## Profils de listener personnalisés : ne vous limitez pas au schéma HTTP classique

Le format d’empaquetage externe (`u32 size | RC4 ciphertext | 16-byte key`) est réutilisable : les listeners personnalisés par les acteurs peuvent donc conserver le même workflow d’extraction tout en modifiant complètement la disposition des champs déchiffrés.

Un bon exemple récent est la campagne Tropic Trooper de mars 2026, où le beacon Adaptix extrait ne contenait pas de profil HTTP/TCP standard. À la place, le blob déchiffré stockait des paramètres de transport GitHub tels que :<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (par exemple `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Stratégie pratique de parsing :
- Détectez d’abord le blob RC4 externe comme d’habitude.
- Après le déchiffrement, orientez le parsing selon les chaînes sentinelles et la plausibilité des champs, plutôt que d’imposer immédiatement le parseur HTTP.
- Parmi les bonnes chaînes sentinelles : `api.github.com`, `/issues?state=open`, les verbes/URI HTTP, les chaînes de type named pipe ou les tableaux de serveurs/ports manifestement valides.
- Si le parseur HTTP échoue, mais que le texte en clair contient des chaînes UTF-8 cohérentes préfixées par leur longueur, conservez l’échantillon et essayez d’autres schémas au lieu de l’écarter comme faux positif.

Dans cette campagne, le listener personnalisé utilisait les issues GitHub comme transport C2, et le beacon interrogeait `ipinfo.io` pour connaître son IP externe, car l’API GitHub ne révèle pas directement à l’opérateur l’adresse source de la victime.<sup>[[5]](#references)</sup>

## Empreintes réseau et chasse aux menaces

HTTP :<sup>[[1]](#references)</sup>
- Courant : POST vers des URI choisies par l’opérateur (par exemple /uri.php, /endpoint/api)
- Paramètre d’en-tête personnalisé utilisé pour l’ID du beacon (par exemple X‑Beacon‑Id, X‑App‑Id)
- User-agents imitant Firefox 20 ou des versions contemporaines de Chrome
- Périodicité des requêtes visible via sleep_delay/jitter_delay
- Les versions plus récentes peuvent faire tourner les URI, user-agents, en-têtes Host et serveurs d’un callback à l’autre ; regroupez donc les échantillons selon les noms d’en-tête inhabituels, les tailles de réponse, la réutilisation TLS et le timing, plutôt que de supposer une seule paire chemin/UA.<sup>[[2]](#references)</sup>

SMB/TCP :<sup>[[1]](#references)</sup>
- Listeners SMB named pipe pour le C2 sur intranet lorsque les sorties web sont limitées
- Les beacons TCP peuvent ajouter quelques octets avant le trafic pour masquer le début du protocole

Valeurs par défaut actuelles de teamserver en amont
- `profile.yaml` fournit actuellement teamserver `0.0.0.0:4321`, le endpoint `/endpoint`, les noms de fichiers de certificat/clé `server.rsa.crt` et `server.rsa.key`, ainsi que des extenders pour HTTP, SMB, TCP, DNS, l’agent Beacon et Gopher.<sup>[[2]](#references)</sup>
- Pour les routes non correspondantes, le gestionnaire d’erreurs par défaut renvoie `Server: AdaptixC2` et `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Le corps 404 standard contient `AdaptixC2 404` et `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Les scans à l’échelle d’Internet menés en 2026 ont découvert de nombreux teamservers exposés sur `4321` et de nombreux listeners beacon sur `43211` ; ces deux ports sont donc de bons points de départ pour pivoter, mais ne doivent pas être considérés comme exhaustifs.<sup>[[4]](#references)</sup>

Empreintes des listeners DNS/DoH :<sup>[[4]](#references)</sup>
- L’extender BeaconDNS actuel répond de manière autoritative (`AA=true`)
- Les requêtes qui ne correspondent pas à la forme attendue du protocole beacon — notamment les noms ayant moins de 5 labels avant le domaine configuré — reçoivent souvent la réponse `TXT "OK"`
- Si le TTL de base configuré est laissé à zéro, le listener utilise une valeur de base de 10 secondes et ajoute jusqu’à 59 secondes de jitter
- Les sondes actives à labels courts sont donc utiles lorsqu’aucun listener HTTP n’est exposé

## TTP de loader et de persistance observés lors d’incidents

Loaders PowerShell en mémoire :<sup>[[1]](#references)</sup>
- Téléchargement de payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allocation de mémoire non managée, copie du shellcode, passage de la protection à 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Exécution via invocation dynamique .NET : Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Logiciels signés trojanisés / loaders de shellcode en plusieurs étapes :<sup>[[5]](#references)</sup>
- Une chaîne d’attaque Tropic Trooper de 2026 utilisait un exécutable SumatraPDF trojanisé (loader TOSHIS) qui redirigeait `_security_init_cookie` vers du code malveillant au lieu de modifier le point d’entrée PE
- Le loader résolvait les API via le hachage Adler-32, téléchargeait un PDF leurre, récupérait le shellcode de deuxième étape, le déchiffrait avec AES-128-CBC via WinCrypt (`CryptDeriveKey` à partir d’une seed codée en dur), puis exécutait par réflexion un beacon Adaptix en mémoire
- La persistance a ensuite été assurée par des tâches planifiées aux noms d’apparence anodine, comme `\MSDNSvc` ou `\MicrosoftUDN`, configurées pour relancer l’agent environ toutes les deux heures

Consultez ces pages pour l’exécution en mémoire et les considérations liées à AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistance observés :<sup>[[1]](#references)</sup>
- Raccourci (.lnk) dans le dossier Startup pour relancer un loader à l’ouverture de session
- Clés Run du registre (HKCU/HKLM ...\CurrentVersion\Run), souvent avec des noms d’apparence anodine comme "Updater" pour lancer loader.ps1.<sup>[[10]](#references)</sup>
- Détournement de l’ordre de recherche des DLL en déposant msimg32.dll dans %APPDATA%\Microsoft\Windows\Templates pour les processus vulnérables

Analyses approfondies et vérifications des techniques :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pistes de chasse aux menaces
- PowerShell effectuant des transitions RW→RX : VirtualProtect vers PAGE_EXECUTE_READWRITE dans powershell.exe.<sup>[[8]](#references)</sup>
- Schémas d’invocation dynamique (GetDelegateForFunctionPointer)
- Réponses 404 HTTPS à des requêtes sans route correspondante contenant `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Réponses DNS avec `AA=true` et `TXT "OK"` à des requêtes courtes sous des domaines suspects.<sup>[[4]](#references)</sup>
- Trafic vers l’API GitHub sur `/repos/<owner>/<repo>/issues`, suivi de requêtes vers `ipinfo.io` provenant de la même chaîne loader/beacon.<sup>[[5]](#references)</sup>
- Fichier .lnk de démarrage dans les dossiers Startup de l’utilisateur ou communs.<sup>[[1]](#references)</sup>
- Clés Run suspectes (par exemple "Updater") et noms de loader comme update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Échantillons PE trojanisés qui redirigent `_security_init_cookie` vers du code de téléchargement avant d’afficher un document leurre.<sup>[[5]](#references)</sup>
- Chemins de DLL accessibles en écriture par l’utilisateur sous %APPDATA%\Microsoft\Windows\Templates contenant msimg32.dll.<sup>[[1]](#references)</sup>

## Notes sur les champs OpSec

- KillDate : horodatage après lequel l’agent s’autodétruit.<sup>[[1]](#references)</sup>
- WorkingTime : heures pendant lesquelles l’agent doit être actif pour se fondre dans l’activité professionnelle.<sup>[[1]](#references)</sup>

Ces champs peuvent servir au regroupement et à expliquer les périodes d’inactivité observées.

## YARA et indicateurs statiques

Unit 42 a publié des règles YARA de base pour les beacons (C/C++ et Go) et les constantes de hachage d’API des loaders.<sup>[[1]](#references)</sup> Envisagez de les compléter par des règles recherchant la disposition [size|ciphertext|16-byte-key] près de la fin de PE .rdata, les chaînes du profil HTTP par défaut et des indicateurs plus récents de serveur/listener tels que `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` et `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2 : un nouveau framework open source exploité dans des attaques réelles (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentation d’Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2 : empreinte à grande échelle d’un framework C2 open source (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper se tourne vers AdaptixC2 et un listener beacon personnalisé (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Documentation Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Documentation Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de protection mémoire – Documentation Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Clés Run du registre / dossier Startup](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
