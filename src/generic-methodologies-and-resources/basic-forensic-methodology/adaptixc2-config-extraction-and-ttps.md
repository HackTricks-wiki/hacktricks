# Extraction de configuration et TTPs d’AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire et open source de post-exploitation/C2 avec des beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) et une prise en charge de BOF. Cette page documente :
- La manière dont sa configuration packée avec RC4 est intégrée et comment l’extraire des beacons
- Les indicateurs réseau/profil pour les listeners HTTP/SMB/TCP
- Les TTPs couramment observés dans la nature concernant les loaders et la persistence, avec des liens vers les pages consacrées aux techniques Windows pertinentes

Les versions upstream récentes proposent également des listeners de beacon DNS/DoH ainsi que la famille distincte d’agents/listeners Gopher. Ainsi, une infrastructure Adaptix moderne peut exposer davantage que les surfaces HTTP/SMB/TCP d’origine, même lorsqu’un échantillon spécifique utilise encore l’agent beacon classique.

## Profils et champs des beacons

AdaptixC2 prend en charge trois types principaux de beacons :
- BEACON_HTTP : C2 web avec serveurs/ports/SSL configurables, méthode, URI, headers, user-agent et nom de paramètre personnalisé
- BEACON_SMB : C2 peer-to-peer via named pipe (intranet)
- BEACON_TCP : sockets directs, avec éventuellement un marker ajouté au début pour obfusquer le début du protocole

Il s’agit des layouts de beacon documentés publiquement dans les premières analyses d’Adaptix, et ils restent le point de départ le plus courant pour l’extraction côté échantillon. Cependant, les builds upstream actuels incluent également les extenders `BeaconDNS` et Gopher côté serveur. Il ne faut donc pas supposer que chaque déploiement Adaptix actif n’expose que l’infrastructure HTTP/SMB/TCP.

Champs de profil typiquement observés dans les configurations des beacons HTTP (après déchiffrement) :
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – utilisés pour analyser les tailles des réponses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Les builds récents de BeaconHTTP prennent également en charge la rotation sélectionnée par l’opérateur entre plusieurs URIs, user-agents, headers Host et serveurs, avec une sélection séquentielle ou aléatoire. Du point de vue du hunting, cela signifie qu’un seul hôte infecté peut se répartir sur plusieurs chemins de callback et combinaisons de headers, sans abandonner la famille classique de beacons packés avec RC4.

Exemple de profil HTTP par défaut (provenant d’un build de beacon) :
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
Profil HTTP malveillant observé (attaque réelle) :
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

Lorsque l’opérateur clique sur Create dans le builder, AdaptixC2 intègre le profil chiffré sous forme de bloc final dans le beacon. Le format est le suivant :
- 4 octets : taille de la configuration (uint32, little-endian)
- N octets : données de configuration chiffrées avec RC4
- 16 octets : clé RC4

Le loader du beacon copie la clé de 16 octets depuis la fin et déchiffre avec RC4 le bloc de N octets sur place :
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implications pratiques :
- Toute la structure se trouve souvent dans la section PE .rdata.
- L’extraction est déterministe : lire la taille, lire le ciphertext de cette taille, lire la clé de 16 octets placée immédiatement après, puis effectuer le déchiffrement RC4.

## Workflow d’extraction de la configuration (défenseurs)

Écrivez un extracteur qui reproduit la logique du beacon :
1) Localiser le blob dans le PE (généralement dans .rdata). Une approche pragmatique consiste à analyser .rdata à la recherche d’une structure plausible [size|ciphertext|clé de 16 octets] et à tenter un déchiffrement RC4.
2) Lire les 4 premiers octets → size (uint32 LE).
3) Lire les N octets suivants → ciphertext.
4) Lire les 16 derniers octets → clé RC4.
5) Déchiffrer le ciphertext avec RC4. Analyser ensuite le profil en clair comme suit :
- scalaires u32/boolean comme indiqué ci-dessus
- chaînes préfixées par leur longueur (longueur u32 suivie des octets ; un NUL final peut être présent)
- tableaux : servers_count suivi du nombre correspondant de paires [string, port u32]

Proof of concept Python minimal (autonome, sans dépendances externes) fonctionnant avec un blob préalablement extrait :
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
- Lors de l’automatisation, utilisez un parseur PE pour lire `.rdata`, puis appliquez une fenêtre glissante : pour chaque offset o, essayez `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, la clé candidate étant les 16 octets suivants ; déchiffrez avec RC4 et vérifiez que les champs de type chaîne sont décodés en UTF-8 et que leurs longueurs sont cohérentes.
- Parsez les profils SMB/TCP en suivant les mêmes conventions préfixées par la longueur.

## Profils de listeners personnalisés : ne codez pas en dur uniquement le schéma HTTP classique

Le format d’empaquetage externe (`u32 size | RC4 ciphertext | 16-byte key`) est réutilisable. Des listeners personnalisés par l’acteur peuvent donc conserver le même workflow d’extraction tout en modifiant complètement la disposition des champs déchiffrés.

Un bon exemple récent est la campagne Tropic Trooper d’avril 2026, dans laquelle le beacon Adaptix extrait ne contenait pas de profil HTTP/TCP standard. À la place, le blob déchiffré stockait des paramètres de transport GitHub tels que :
- `repo_owner`
- `repo_name`
- `api_host` (par exemple `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Stratégie pratique de parsing :
- Détectez d’abord le blob RC4 externe exactement comme d’habitude.
- Après le déchiffrement, choisissez la branche selon les chaînes sentinelles et la cohérence des champs, plutôt que de forcer immédiatement le parseur HTTP.
- De bonnes sentinelles incluent `api.github.com`, `/issues?state=open`, les verbes/URI HTTP, les chaînes de type named pipe ou des tableaux de serveurs/ports manifestement valides.
- Si le parseur HTTP échoue mais que le texte en clair contient des chaînes UTF-8 cohérentes préfixées par leur longueur, conservez l’échantillon et essayez d’autres schémas au lieu de le rejeter comme faux positif.

Dans cette campagne, le listener personnalisé utilisait les issues GitHub comme transport C2, et le beacon interrogeait `ipinfo.io` pour connaître son IP externe, car l’API GitHub ne révèle pas directement à l’opérateur l’adresse source de la victime.

## Fingerprinting réseau et hunting

HTTP
- Courant : POST vers des URI choisies par l’opérateur (par exemple `/uri.php`, `/endpoint/api`)
- Paramètre d’en-tête personnalisé utilisé pour l’ID du beacon (par exemple `X‑Beacon‑Id`, `X‑App‑Id`)
- User-agents imitant Firefox 20 ou des builds Chrome contemporains
- Cadence de polling visible via `sleep_delay`/`jitter_delay`
- Les builds plus récents peuvent faire tourner les URI, les user-agents, les en-têtes Host et les serveurs entre les callbacks. Regroupez donc les événements selon les noms d’en-tête rares, les motifs de taille des réponses, la réutilisation TLS et la temporisation, plutôt que de supposer une paire chemin/UA unique.

SMB/TCP
- Listeners SMB utilisant des named pipes pour le C2 intranet lorsque l’egress web est limité
- Les beacons TCP peuvent préfixer le trafic de quelques octets afin d’obfusquer le début du protocole

Valeurs par défaut actuelles de l’upstream teamserver
- `profile.yaml` fournit actuellement un teamserver sur `0.0.0.0:4321`, un endpoint `/endpoint`, les noms de fichiers de certificat/clé `server.rsa.crt` et `server.rsa.key`, ainsi que des extenders pour HTTP, SMB, TCP, DNS, Beacon agent et Gopher
- Pour les routes non correspondantes, le gestionnaire d’erreur par défaut renvoie `Server: AdaptixC2` et `Adaptix-Version: v1.2`
- Le corps 404 standard contient `AdaptixC2 404` et `You need to enter the correct connection details.`
- Les scans à l’échelle d’Internet réalisés en 2026 ont trouvé de nombreux teamservers exposés sur `4321` et de nombreux beacon listeners sur `43211`. Ces deux ports sont donc de bons pivots initiaux, mais ne doivent pas être considérés comme exhaustifs

Empreintes des listeners DNS/DoH
- L’extender BeaconDNS actuel répond de manière autoritative (`AA=true`)
- Les requêtes qui ne correspondent pas à la forme du protocole beacon — notamment les noms comportant moins de 5 labels avant le domaine configuré — reçoivent généralement une réponse `TXT "OK"`
- Si le TTL de base configuré est laissé à zéro, le listener utilise une base de 10 secondes et ajoute jusqu’à 59 secondes de jitter
- Les sondes actives à labels courts sont donc utiles lorsqu’aucun listener HTTP n’est exposé

## TTP de loader et de persistence observées lors d’incidents

Loaders PowerShell en mémoire
- Téléchargement de payloads Base64/XOR (`Invoke‑RestMethod` / WebClient)
- Allocation de mémoire non gérée, copie du shellcode, puis changement de protection vers `0x40` (`PAGE_EXECUTE_READWRITE`) via VirtualProtect
- Exécution via invocation dynamique .NET : `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`

Loaders de shellcode signés et trojanisés / staged
- Une chaîne Tropic Trooper de 2026 utilisait un exécutable SumatraPDF trojanisé (loader TOSHIS) qui redirigeait `_security_init_cookie` vers du code malveillant au lieu de modifier le point d’entrée PE
- Le loader résolvait les API via le hashing Adler-32, téléchargeait un PDF leurre, récupérait un shellcode de deuxième étape, le déchiffrait avec AES-128-CBC via WinCrypt (`CryptDeriveKey` à partir d’une seed codée en dur), puis exécutait de manière reflective un beacon Adaptix en mémoire
- La persistence a ensuite été déplacée vers des scheduled tasks aux noms d’apparence légitime tels que `\MSDNSvc` ou `\MicrosoftUDN`, configurées pour relancer l’agent environ toutes les deux heures

Consultez ces pages pour l’exécution en mémoire et les considérations AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistence observés
- Raccourci (.lnk) dans le dossier Startup pour relancer un loader à l’ouverture de session
- Clés Registry Run (`HKCU/HKLM ...\CurrentVersion\Run`), souvent avec des noms d’apparence légitime tels que « Updater » pour démarrer `loader.ps1`
- DLL search-order hijacking en déposant `msimg32.dll` sous `%APPDATA%\Microsoft\Windows\Templates` pour les processus vulnérables

Analyses approfondies et vérifications des techniques :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idées de hunting
- PowerShell générant des transitions RW→RX : VirtualProtect vers PAGE_EXECUTE_READWRITE dans `powershell.exe`
- Schémas d’invocation dynamique (`GetDelegateForFunctionPointer`)
- Erreurs HTTPS 404 non correspondantes avec `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details.`
- Réponses DNS avec `AA=true` et `TXT "OK"` pour les requêtes courtes sous des domaines suspects
- Trafic API GitHub vers `/repos/<owner>/<repo>/issues` suivi de requêtes vers `ipinfo.io` provenant de la même chaîne loader/beacon
- Fichiers `.lnk` dans les dossiers Startup utilisateur ou communs
- Clés Run suspectes (par exemple « Updater ») et noms de loader tels que `update.ps1`/`loader.ps1`
- Échantillons PE trojanisés qui redirigent `_security_init_cookie` vers du code de téléchargement avant d’afficher un document leurre
- Chemins de DLL accessibles en écriture par l’utilisateur sous `%APPDATA%\Microsoft\Windows\Templates` et contenant `msimg32.dll`

## Remarques sur les champs OpSec

- KillDate : horodatage après lequel l’agent expire automatiquement
- WorkingTime : heures durant lesquelles l’agent doit être actif afin de se fondre dans l’activité professionnelle

Ces champs peuvent être utilisés pour le clustering et pour expliquer les périodes d’inactivité observées.

## YARA et pistes statiques

Unit 42 a publié des règles YARA de base pour les beacons (C/C++ et Go) ainsi que des constantes de hashing d’API de loader. Envisagez de les compléter avec des règles recherchant la disposition [size|ciphertext|16-byte-key] près de la fin de `.rdata` d’un PE, les chaînes du profil HTTP par défaut et les nouveaux marqueurs de serveur/listener tels que `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` et `ipinfo.io`.

## Références

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
