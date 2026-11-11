# Extraction de configuration et TTPs d’AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire open source de post-exploitation/C2, avec des beacons Windows x86/x64 (EXE/DLL/service EXE/shellcode brut) et la prise en charge de BOF.<sup>[[1]](#references)</sup> Cette page documente :
- Comment sa configuration empaquetée avec RC4 est intégrée et comment l’extraire des beacons
- Les indicateurs réseau/profil des listeners HTTP/SMB/TCP
- Les TTPs courants de loader et de persistence observés dans la nature, avec des liens vers les pages pertinentes sur les techniques Windows

Les versions récentes en amont incluent également des listeners beacon DNS/DoH et la famille distincte d’agents/listeners Gopher ; une infrastructure Adaptix moderne peut donc exposer davantage que les surfaces HTTP/SMB/TCP d’origine, même si un échantillon précis utilise encore l’agent beacon classique.<sup>[[2]](#references)</sup>

## Profils et champs de beacon

AdaptixC2 prend en charge trois types principaux de beacon :<sup>[[1]](#references)</sup>
- BEACON_HTTP : C2 web avec serveurs/ports/SSL configurables, méthode, URI, en-têtes, user-agent et nom de paramètre personnalisé
- BEACON_SMB : C2 pair-à-pair par named pipe (intranet)
- BEACON_TCP : sockets directes, avec éventuellement un marqueur préfixé pour masquer le début du protocole

Ce sont les layouts de beacon documentés publiquement dans les premières analyses d’Adaptix, et ils restent le point de départ le plus courant pour l’extraction côté échantillon.<sup>[[1]](#references)</sup> Cependant, les builds actuels en amont incluent également les extensions `BeaconDNS` et Gopher côté serveur ; ne supposez donc pas que chaque déploiement Adaptix actif expose uniquement une infrastructure HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Le résumé des champs et les exemples JSON suivants décrivent le format HTTP analysé en 2025 ; ils ne constituent pas une spécification de parser pour les builds plus récents en amont. Champs typiques dans ces échantillons (après déchiffrement) :<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (tableau de chaînes), ports (tableau de u32)
- http_method, uri, parameter, user_agent, http_headers (chaînes préfixées par leur longueur)
- ans_pre_size (u32), ans_size (u32) – utilisés pour analyser les tailles des réponses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Les builds BeaconHTTP récents prennent également en charge la rotation, sélectionnée par l’opérateur, entre plusieurs URI, user-agents, en-têtes Host et serveurs, avec une sélection séquentielle ou aléatoire.<sup>[[2]](#references)</sup> Du point de vue de la détection, cela signifie qu’un même hôte infecté peut répartir ses connexions sur plusieurs chemins de callback et combinaisons d’en-têtes sans abandonner la famille classique de beacons empaquetés avec RC4.

Exemple de profil HTTP par défaut (issu d’un build de beacon) :<sup>[[1]](#references)</sup>

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

Lorsque l’opérateur clique sur Create dans le builder, AdaptixC2 compile le profil chiffré dans le beacon. Ne partez pas du principe qu’il se trouve à la fin du PE ou du shellcode : localisez les octets du profil en parcourant les sections ou en suivant `getProfile()` dans l’échantillon. Le format empaqueté est le suivant :<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 octets : taille de la configuration (uint32, little-endian)
- N octets : données de configuration chiffrées avec RC4
- 16 octets : clé RC4

Le loader du beacon copie la clé de 16 octets depuis la fin et déchiffre avec RC4 le bloc de N octets sur place :<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implications pratiques :<sup>[[1]](#references)</sup>
- Toute la structure se trouve souvent dans la section PE .rdata.
- L’extraction est déterministe : lire la taille, lire le ciphertext de cette taille, lire la clé de 16 octets placée juste après, puis déchiffrer avec RC4.

## Workflow d’extraction de la configuration (défenseurs)

Pour le triage général d’un échantillon avant d’extraire le beacon, voir [Malware Analysis](malware-analysis.md).

Écrire un extractor qui reproduit la logique du beacon :<sup>[[1]](#references)</sup>
1) Localiser le blob dans le PE (généralement .rdata). Une approche pragmatique consiste à parcourir .rdata à la recherche d’une disposition plausible [taille|ciphertext|clé de 16 octets] et à tenter un déchiffrement RC4.
2) Lire les 4 premiers octets → taille (uint32 LE).
3) Lire les N octets suivants (N=taille) → ciphertext.
4) Lire les 16 derniers octets → clé RC4.
5) Déchiffrer le ciphertext avec RC4. Analyser ensuite le profil en clair comme suit :
   - scalaires u32/boolean comme indiqué ci-dessus
   - chaînes préfixées par leur longueur (longueur u32 suivie des octets ; un NUL final peut être présent)
   - tableaux : servers_count suivi d’autant de paires [chaîne, port u32]

Proof of concept Python pour HTTP historique (autonome, sans dépendances externes) pour un blob préalablement extrait selon l’ordre des champs de 2025. Utiliser l’analyseur du schéma actuel ci-dessous pour les builds stock récents :<sup>[[1]](#references)[[11]](#references)</sup>

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

### Analyser les profils HTTP et DNS stock actuels

La version upstream sérialise d’abord six valeurs `u32` little-endian : le watermark/type de l’agent, la date d’expiration, la durée de fonctionnement, le délai de veille, le jitter et le watermark/type du listener. Les données spécifiques à HTTP commencent ensuite par un indicateur SSL d’un octet. Contrairement à l’exemple legacy, elles comportent des listes URI, user-agent et d’en-têtes Host précédées de leur nombre d’éléments, puis le mode de rotation et les paramètres du proxy. Le parser legacy commence donc à lire l’indicateur SSL dans le champ de la date d’expiration et produit des résultats erronés avec ces versions. Les longueurs des chaînes et les valeurs entières de ce profil sont encodées en little-endian ; les chaînes empaquetées se terminent par un NUL lorsqu’elles ne sont pas vides.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

À l’aide des helpers `P` et `rc4` ci-dessus, utilisez ce parser sur un plaintext **HTTP stock** déchiffré. Ne divulguez pas la clé RC4 dans les rapports publics : le profil HTTP peut contenir un nom d’utilisateur et un mot de passe de proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Analyser un profil plaintext HTTP stock actuel</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Pour un beacon DNS standard, lisez les six mêmes champs `u32` courants, puis les chaînes `domain`, `resolvers`, `doh_resolvers` et `qtype`, précédées de leur longueur. Lisez `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` et `dns_mode` en tant que `u32`, puis la chaîne d’user-agent DoH précédée de sa longueur. `dns_mode` distingue UDP, DoH et les deux sens de fallback. Il s’agit d’un format distinct : ne faites pas passer le texte brut DNS par le parseur HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Conseils :
- Pour automatiser, utilisez un parseur PE pour lire .rdata, puis appliquez une fenêtre glissante : pour chaque offset o, essayez size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = les 16 octets suivants ; déchiffrez avec RC4 et vérifiez que les champs chaîne se décodent en UTF-8 et que les longueurs sont plausibles.
- Parsez les profils SMB/TCP en suivant les mêmes conventions de préfixe de longueur.

## Profils de listener personnalisés : ne codez pas en dur uniquement le schéma HTTP classique

Le format d’empaquetage externe (`u32 size | RC4 ciphertext | 16-byte key`) est réutilisable. Les listeners personnalisés par l’acteur peuvent donc suivre le même processus d’extraction tout en modifiant complètement la structure des champs déchiffrés.

Un exemple récent est la campagne Tropic Trooper de mars 2026, dans laquelle le beacon Adaptix extrait ne contenait pas de profil HTTP/TCP standard. À la place, le blob déchiffré stockait des paramètres de transport GitHub tels que :<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (par exemple `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Stratégie pratique de parsing :
- Détectez d’abord le blob RC4 externe comme d’habitude.
- Après le déchiffrement, orientez le parsing selon les chaînes sentinelles et la plausibilité des champs, plutôt que d’imposer immédiatement le parseur HTTP.
- Parmi les bonnes sentinelles : `api.github.com`, `/issues?state=open`, les verbes/URI HTTP, les chaînes de type named pipe ou les tableaux manifestement valides de serveurs/ports.
- Si le parseur HTTP échoue, mais que le texte brut contient des chaînes UTF-8 cohérentes précédées de leur longueur, conservez l’échantillon et essayez d’autres schémas au lieu de le rejeter comme faux positif.

Dans cette campagne, le listener personnalisé utilisait les issues GitHub comme transport C2, et le beacon interrogeait `ipinfo.io` pour connaître son IP externe, car l’API GitHub ne révèle pas directement à l’opérateur l’adresse source de la victime.<sup>[[5]](#references)</sup>

## Fingerprinting réseau et hunting

HTTP :<sup>[[1]](#references)</sup>
- Courant : POST vers des URI choisies par l’opérateur (par exemple, /uri.php, /endpoint/api)
- Paramètre d’en-tête personnalisé utilisé pour l’ID du beacon (par exemple, X‑Beacon‑Id, X‑App‑Id)
- User-agents imitant Firefox 20 ou des versions contemporaines de Chrome
- Cadence de polling visible via sleep_delay/jitter_delay
- Les versions récentes peuvent faire tourner les URI, user-agents, en-têtes Host et serveurs entre les callbacks. Regroupez donc les échantillons selon les noms d’en-tête inhabituels, les profils de taille des réponses, la réutilisation TLS et le timing, plutôt que de supposer une seule paire chemin/UA.<sup>[[2]](#references)</sup>

SMB/TCP :<sup>[[1]](#references)</sup>
- Listeners SMB à named pipe pour le C2 intranet lorsque la sortie web est limitée
- Les beacons TCP peuvent ajouter quelques octets avant le trafic afin d’obscurcir le début du protocole

Valeurs par défaut actuelles de teamserver en amont
- `profile.yaml` est actuellement fourni avec le teamserver `0.0.0.0:4321`, l’endpoint `/endpoint`, les noms de fichiers de certificat/clé `server.rsa.crt` et `server.rsa.key`, ainsi que des extenders pour HTTP, SMB, TCP, DNS, l’agent Beacon et Gopher.<sup>[[2]](#references)</sup>
- Pour les routes non correspondantes, le gestionnaire d’erreurs par défaut renvoie `Server: AdaptixC2` et `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Le corps 404 standard contient `AdaptixC2 404` et `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Des scans à l’échelle d’Internet en 2026 ont trouvé de nombreux teamservers exposés sur le port `4321` et de nombreux listeners beacon sur le port `43211`. Ces deux ports sont donc de bons points de départ pour pivoter, mais ne doivent pas être considérés comme exhaustifs.<sup>[[4]](#references)</sup>

Empreintes des listeners DNS/DoH :<sup>[[4]](#references)</sup>
- L’extender BeaconDNS actuel répond de manière autoritaire (`AA=true`)
- Les requêtes qui ne correspondent pas au format du protocole beacon — notamment les noms comportant moins de 5 labels avant le domaine configuré — reçoivent généralement la réponse `TXT "OK"`
- Si le TTL de base configuré reste à zéro, le listener utilise une base de 10 secondes et ajoute jusqu’à 59 secondes de jitter
- Des sondes actives à labels courts sont donc utiles lorsqu’aucun listener HTTP n’est exposé

## TTP de loader et de persistance observées lors d’incidents

Loaders PowerShell en mémoire :<sup>[[1]](#references)</sup>
- Téléchargement de payloads Base64/XOR (`Invoke‑RestMethod` / WebClient).<sup>[[9]](#references)</sup>
- Allocation de mémoire non gérée, copie du shellcode, passage de la protection à 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Exécution via invocation dynamique .NET : Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Loaders de shellcode par étapes / logiciels signés trojanisés :<sup>[[5]](#references)</sup>
- Une chaîne Tropic Trooper de 2026 utilisait un exécutable SumatraPDF trojanisé (loader TOSHIS) qui redirigeait `_security_init_cookie` vers du code malveillant au lieu de modifier le point d’entrée PE
- Le loader résolvait les API par hachage Adler-32, téléchargeait un PDF leurre, récupérait le shellcode de deuxième étape, le déchiffrait avec AES-128-CBC via WinCrypt (`CryptDeriveKey` à partir d’une seed codée en dur), puis exécutait par réflexion un beacon Adaptix en mémoire
- La persistance a ensuite été transférée vers des tâches planifiées portant des noms anodins tels que `\MSDNSvc` ou `\MicrosoftUDN`, configurées pour relancer l’agent environ toutes les deux heures

Consultez ces pages sur l’exécution en mémoire et les considérations AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistance observés :<sup>[[1]](#references)</sup>
- Raccourci (.lnk) dans le dossier Startup pour relancer un loader à l’ouverture de session
- Clés Run du registre (HKCU/HKLM ...\CurrentVersion\Run), souvent avec des noms anodins comme « Updater » pour lancer loader.ps1.<sup>[[10]](#references)</sup>
- Détournement de l’ordre de recherche des DLL en déposant msimg32.dll dans %APPDATA%\Microsoft\Windows\Templates pour les processus vulnérables

Analyses détaillées des techniques et vérifications :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Pistes de hunting
- PowerShell provoquant des transitions RW→RX : VirtualProtect vers PAGE_EXECUTE_READWRITE dans powershell.exe.<sup>[[8]](#references)</sup>
- Schémas d’invocation dynamique (GetDelegateForFunctionPointer)
- Réponses 404 HTTPS sans correspondance contenant `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Réponses DNS avec `AA=true` et `TXT "OK"` à des requêtes courtes sous des domaines suspects.<sup>[[4]](#references)</sup>
- Trafic vers l’API GitHub à `/repos/<owner>/<repo>/issues`, suivi de requêtes vers `ipinfo.io` provenant de la même chaîne de loader/beacon.<sup>[[5]](#references)</sup>
- Fichier .lnk dans les dossiers Startup de l’utilisateur ou communs.<sup>[[1]](#references)</sup>
- Clés Run suspectes (par exemple, « Updater ») et noms de loader tels que update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Échantillons PE trojanisés redirigeant `_security_init_cookie` vers du code de téléchargement avant d’afficher un document leurre.<sup>[[5]](#references)</sup>
- Chemins de DLL accessibles en écriture par l’utilisateur sous %APPDATA%\Microsoft\Windows\Templates contenant msimg32.dll.<sup>[[1]](#references)</sup>

## Notes sur les champs OpSec

- KillDate : horodatage après lequel l’agent s’autodétruit.<sup>[[1]](#references)</sup>
- WorkingTime : heures pendant lesquelles l’agent doit être actif afin de se fondre dans l’activité professionnelle.<sup>[[1]](#references)</sup>

Ces champs peuvent servir au regroupement et à expliquer les périodes d’inactivité observées.

## YARA et indicateurs statiques

Unit 42 a publié des règles YARA de base pour les beacons (C/C++ et Go) et les constantes de hachage d’API des loaders.<sup>[[1]](#references)</sup> Envisagez de compléter ces règles par des signatures recherchant le format [size|ciphertext|16-byte-key] près de la fin de .rdata dans les PE, les chaînes du profil HTTP par défaut et des marqueurs plus récents de serveur/listener tels que `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` et `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2 : un nouveau framework open source exploité dans des attaques réelles (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentation du framework Adaptix](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2 : fingerprinting à grande échelle d’un framework C2 open source (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper se tourne vers AdaptixC2 et un listener beacon personnalisé (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de protection de la mémoire – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Clés Run du registre/dossier Startup](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Génération de profil AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parseur de profil beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Génération de profil DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Empaquetage de profil AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
