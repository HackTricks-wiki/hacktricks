# Extraction de configuration et TTPs d'AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire et open source de post-exploitation/C2 avec des beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) et la prise en charge de BOF.<sup>[[1]](#references)</sup> Cette page documente :
- La manière dont sa configuration empaquetée avec RC4 est intégrée et comment l'extraire des beacons
- Les indicateurs réseau/profil pour les listeners HTTP/SMB/TCP
- Les TTPs courants de loaders et de persistence observés dans la nature, avec des liens vers les pages consacrées aux techniques Windows pertinentes

Les versions récentes en amont incluent également des listeners de beacon DNS/DoH ainsi que la famille distincte d'agents/listeners Gopher. L'infrastructure Adaptix moderne peut donc exposer davantage que les surfaces HTTP/SMB/TCP d'origine, même lorsqu'un échantillon spécifique utilise encore l'agent beacon classique.<sup>[[2]](#references)[[3]](#references)</sup>

## Profils et champs des beacons

AdaptixC2 prend en charge trois types principaux de beacons :<sup>[[1]](#references)</sup>
- BEACON_HTTP : C2 web avec serveurs/ports/SSL configurables, méthode, URI, headers, user-agent et nom de paramètre personnalisé
- BEACON_SMB : C2 peer-to-peer via named pipe (intranet)
- BEACON_TCP : sockets directs, éventuellement précédés d'un marker pour obfusquer le début du protocole

Il s'agit des structures de beacon documentées publiquement dans les premières analyses d'Adaptix, et elles restent le point de départ le plus courant pour l'extraction côté échantillon.<sup>[[1]](#references)</sup> Toutefois, les builds upstream actuels incluent également les extenders `BeaconDNS` et Gopher côté serveur. Il ne faut donc pas supposer que chaque déploiement Adaptix actif n'expose que l'infrastructure HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Champs de profil généralement observés dans les configurations de beacon HTTP (après déchiffrement) :<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – utilisés pour analyser les tailles des réponses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Les builds récents de BeaconHTTP prennent également en charge la rotation, sélectionnée par l'opérateur, entre plusieurs URI, user-agents, headers Host et serveurs, avec une sélection séquentielle ou aléatoire.<sup>[[2]](#references)</sup> Du point de vue du hunting, cela signifie qu'un seul hôte infecté peut se connecter à plusieurs chemins de callback et combinaisons de headers sans sortir de la famille classique des beacons empaquetés avec RC4.

Exemple de profil HTTP par défaut (provenant d'un build de beacon) :<sup>[[1]](#references)</sup>
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
Profil HTTP malveillant observé (attaque réelle):<sup>[[1]](#references)</sup>
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

Lorsque l’opérateur clique sur Create dans le builder, AdaptixC2 intègre le profil chiffré sous forme de blob en fin de beacon. Le format est le suivant :<sup>[[1]](#references)</sup>
- 4 octets : taille de la configuration (uint32, little-endian)
- N octets : données de configuration chiffrées avec RC4
- 16 octets : clé RC4

Le loader du beacon copie la clé de 16 octets depuis la fin, puis déchiffre avec RC4 le bloc de N octets en place :<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implications pratiques :<sup>[[1]](#references)</sup>
- L’ensemble de la structure se trouve souvent dans la section PE .rdata.
- L’extraction est déterministe : lire la taille, lire le ciphertext de cette taille, lire la clé de 16 octets placée immédiatement après, puis effectuer le déchiffrement RC4.

## Workflow d’extraction de la configuration (defenders)

Écrire un extracteur qui reproduit la logique du beacon :<sup>[[1]](#references)</sup>
1) Localiser le blob dans le PE (généralement .rdata). Une approche pragmatique consiste à parcourir .rdata à la recherche d’une structure plausible [size|ciphertext|16-byte key] et à tenter RC4.
2) Lire les 4 premiers octets → taille (uint32 LE).
3) Lire les N octets suivants, où N=size → ciphertext.
4) Lire les 16 derniers octets → clé RC4.
5) Déchiffrer le ciphertext avec RC4. Analyser ensuite le profil en clair comme suit :
- scalaires u32/boolean, comme indiqué ci-dessus
- chaînes préfixées par leur longueur (longueur u32 suivie des octets ; un NUL final peut être présent)
- tableaux : servers_count suivi du nombre correspondant de paires [string, u32 port]

Proof-of-concept minimal en Python (autonome, sans dépendance externe) fonctionnant avec un blob préalablement extrait :
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
- Lors de l’automatisation, utilisez un parseur PE pour lire `.rdata`, puis appliquez une fenêtre glissante : pour chaque offset o, essayez `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, puis utilisez les 16 octets suivants comme clé candidate ; déchiffrez avec RC4 et vérifiez que les champs de chaînes se décodent en UTF-8 et que leurs longueurs sont cohérentes.
- Analysez les profiles SMB/TCP en suivant les mêmes conventions préfixées par la longueur.

## Custom listener profiles : ne codez pas en dur uniquement le schéma HTTP classique

Le format d’encapsulation externe (`u32 size | RC4 ciphertext | 16-byte key`) est réutilisable. Les listeners personnalisés par l’acteur peuvent donc conserver le même workflow d’extraction tout en modifiant complètement la disposition des champs déchiffrés.

Un bon exemple récent est la campagne de Tropic Trooper d’avril 2026, au cours de laquelle le beacon Adaptix extrait ne contenait pas de profile HTTP/TCP standard. À la place, le blob déchiffré stockait des paramètres de transport GitHub tels que :<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (par exemple `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Stratégie pratique d’analyse :
- Détectez d’abord le blob RC4 externe exactement comme d’habitude.
- Après le déchiffrement, choisissez la branche en fonction de chaînes sentinelles et de la cohérence des champs, plutôt que de forcer immédiatement l’analyse HTTP.
- Les bonnes sentinelles incluent `api.github.com`, `/issues?state=open`, des verbes/URI HTTP, des chaînes de type named pipe ou des tableaux de serveurs/ports manifestement valides.
- Si l’analyse HTTP échoue mais que le texte en clair contient des chaînes UTF-8 cohérentes, préfixées par leur longueur, conservez l’échantillon et essayez d’autres schémas au lieu de le considérer comme un faux positif.

Dans cette campagne, le listener personnalisé utilisait les GitHub issues comme transport C2, et le beacon interrogeait `ipinfo.io` pour connaître son IP externe, car l’API GitHub ne révèle pas directement à l’opérateur l’adresse source de la victime.<sup>[[5]](#references)</sup>

## Fingerprinting réseau et hunting

HTTP<sup>[[1]](#references)</sup>
- Courant : POST vers des URI sélectionnées par l’opérateur (par exemple `/uri.php`, `/endpoint/api`)
- Paramètre d’en-tête personnalisé utilisé pour l’identifiant du beacon (par exemple `X‑Beacon‑Id`, `X‑App‑Id`)
- User-agents imitant Firefox 20 ou des builds Chrome contemporains
- Cadence de polling visible via `sleep_delay`/`jitter_delay`
- Les builds plus récents peuvent faire tourner les URI, user-agents, en-têtes Host et serveurs entre les callbacks. Regroupez donc les événements selon les noms d’en-têtes peu communs, les modèles de taille des réponses, la réutilisation TLS et le timing, plutôt que de supposer une seule paire chemin/UA<sup>[[2]](#references)</sup>

SMB/TCP<sup>[[1]](#references)</sup>
- Listeners SMB utilisant des named pipes pour le C2 intranet lorsque la sortie web est limitée
- Les beacons TCP peuvent préfixer le trafic de quelques octets afin d’obscurcir le début du protocole

Valeurs par défaut actuelles du teamserver upstream
- `profile.yaml` fournit actuellement un teamserver `0.0.0.0:4321`, un endpoint `/endpoint`, les noms de fichiers de certificat/clé `server.rsa.crt` et `server.rsa.key`, ainsi que des extenders pour HTTP, SMB, TCP, DNS, Beacon agent et Gopher<sup>[[2]](#references)</sup>
- Pour les routes ne correspondant à aucune route, le gestionnaire d’erreur par défaut renvoie `Server: AdaptixC2` et `Adaptix-Version: v1.2`<sup>[[4]](#references)</sup>
- Le corps 404 standard contient `AdaptixC2 404` et `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- Les scans à l’échelle d’Internet menés en 2026 ont découvert de nombreux teamservers exposés sur `4321` et de nombreux beacon listeners sur `43211`. Ces deux ports sont donc de bons pivots initiaux, mais ne doivent pas être considérés comme exhaustifs<sup>[[4]](#references)</sup>

Empreintes des listeners DNS/DoH<sup>[[4]](#references)</sup>
- L’extender BeaconDNS actuel répond de manière autoritative (`AA=true`)
- Les requêtes qui ne correspondent pas à la structure du protocole beacon — notamment les noms comportant moins de 5 labels avant le domaine configuré — reçoivent généralement une réponse `TXT "OK"`
- Si le TTL de base configuré reste à zéro, le listener utilise une base de 10 secondes et ajoute jusqu’à 59 secondes de jitter
- Cela rend les sondes actives à labels courts utiles lorsqu’aucun listener HTTP n’est exposé

## TTP de loader et de persistence observées lors d’incidents

Loaders PowerShell en mémoire<sup>[[1]](#references)</sup>
- Téléchargement de payloads Base64/XOR (`Invoke‑RestMethod` / WebClient)<sup>[[9]](#references)</sup>
- Allocation de mémoire non gérée, copie du shellcode et modification de la protection en `0x40` (`PAGE_EXECUTE_READWRITE`) via VirtualProtect<sup>[[7]](#references)</sup>
- Exécution via invocation dynamique .NET : Marshal.GetDelegateForFunctionPointer + delegate.Invoke()<sup>[[6]](#references)</sup>

Logiciels signés trojanisés / loaders de shellcode staged<sup>[[5]](#references)</sup>
- Une chaîne Tropic Trooper de 2026 utilisait un exécutable SumatraPDF trojanisé (loader TOSHIS) qui redirigeait `_security_init_cookie` vers du code malveillant au lieu de modifier le point d’entrée PE
- Le loader résolvait les API via du hashing Adler-32, téléchargeait un PDF leurre, récupérait un shellcode de deuxième étape, le déchiffrait avec AES-128-CBC via WinCrypt (`CryptDeriveKey` à partir d’une seed codée en dur), puis exécutait de manière reflective un beacon Adaptix en mémoire
- La persistence a ensuite été déplacée vers des scheduled tasks portant des noms d’apparence légitime tels que `\MSDNSvc` ou `\MicrosoftUDN`, configurées pour relancer l’agent environ toutes les deux heures

Consultez ces pages concernant l’exécution en mémoire et les considérations AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistence observés<sup>[[1]](#references)</sup>
- Raccourci (.lnk) dans le dossier Startup pour relancer un loader à l’ouverture de session
- Clés Registry Run (`HKCU/HKLM ...\CurrentVersion\Run`), souvent avec des noms d’apparence légitime comme `"Updater"` pour lancer `loader.ps1`<sup>[[10]](#references)</sup>
- DLL search-order hijack en déposant `msimg32.dll` sous `%APPDATA%\Microsoft\Windows\Templates` pour les processus vulnérables

Analyses approfondies et vérifications des techniques :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idées de hunting
- Transitions RW→RX générées par PowerShell : VirtualProtect vers PAGE_EXECUTE_READWRITE à l’intérieur de powershell.exe<sup>[[8]](#references)</sup>
- Patterns d’invocation dynamique (GetDelegateForFunctionPointer)
- Réponses HTTPS 404 sans correspondance contenant `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- Réponses DNS avec `AA=true` et `TXT "OK"` pour des requêtes courtes sous des domaines suspects<sup>[[4]](#references)</sup>
- Trafic de l’API GitHub vers `/repos/<owner>/<repo>/issues`, suivi de requêtes vers `ipinfo.io` provenant de la même chaîne loader/beacon<sup>[[5]](#references)</sup>
- Fichiers `.lnk` dans les dossiers Startup de l’utilisateur ou les dossiers Startup communs<sup>[[1]](#references)</sup>
- Clés Run suspectes (par exemple `"Updater"`) et noms de loaders tels que `update.ps1`/`loader.ps1`<sup>[[1]](#references)</sup>
- Échantillons PE trojanisés qui redirigent `_security_init_cookie` vers du code de téléchargement avant d’afficher un document leurre<sup>[[5]](#references)</sup>
- Chemins DLL accessibles en écriture par l’utilisateur sous `%APPDATA%\Microsoft\Windows\Templates`, contenant `msimg32.dll`<sup>[[1]](#references)</sup>

## Notes sur les champs OpSec

- KillDate : timestamp après lequel l’agent expire automatiquement<sup>[[1]](#references)</sup>
- WorkingTime : heures pendant lesquelles l’agent doit être actif afin de se fondre dans l’activité professionnelle<sup>[[1]](#references)</sup>

Ces champs peuvent être utilisés pour le clustering et pour expliquer les périodes d’inactivité observées.

## YARA et indices statiques

Unit 42 a publié des règles YARA de base pour les beacons (C/C++ et Go) ainsi que des constantes de hashing d’API utilisées par les loaders.<sup>[[1]](#references)</sup> Envisagez de les compléter avec des règles recherchant la disposition [size|ciphertext|16-byte-key] près de la fin de la section `.rdata` d’un PE, les chaînes du profile HTTP par défaut et les marqueurs plus récents de serveur/listener tels que `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` et `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## Références

- [1] [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
