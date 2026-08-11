# Extraction de configuration et TTPs d’AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire open source de post-exploitation/C2 avec des beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) et la prise en charge de BOF.<sup>[[1]](#references)</sup> Cette page documente :
- La manière dont sa configuration compactée avec RC4 est intégrée et peut être extraite des beacons
- Les indicateurs réseau/profil pour les listeners HTTP/SMB/TCP
- Les TTPs couramment observés dans les loaders et la persistance, avec des liens vers les pages consacrées aux techniques Windows pertinentes

Les versions upstream récentes incluent également des listeners de beacon DNS/DoH ainsi que la famille distincte d’agents/listeners Gopher. Ainsi, une infrastructure Adaptix moderne peut exposer davantage que les surfaces HTTP/SMB/TCP d’origine, même lorsqu’un échantillon spécifique utilise encore l’agent beacon classique.<sup>[[2]](#references)</sup>

## Profils et champs des beacons

AdaptixC2 prend en charge trois types principaux de beacons :<sup>[[1]](#references)</sup>
- BEACON_HTTP : C2 web avec serveurs/ports/SSL, méthode, URI, headers, user-agent et nom de paramètre personnalisé configurables
- BEACON_SMB : C2 peer-to-peer via named pipe (intranet)
- BEACON_TCP : sockets directes, avec éventuellement un marker préfixé pour obfusquer le début du protocole

Il s’agit des layouts de beacon documentés publiquement dans les premières analyses d’Adaptix, et ils restent le point de départ le plus courant pour l’extraction côté échantillon.<sup>[[1]](#references)</sup> Toutefois, les builds upstream actuels incluent également les extenders `BeaconDNS` et Gopher côté serveur. Il ne faut donc pas supposer que chaque déploiement Adaptix actif n’expose qu’une infrastructure HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Champs de profil typiquement observés dans les configurations de beacon HTTP (après déchiffrement) :<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array de strings), ports (array de u32)
- http_method, uri, parameter, user_agent, http_headers (strings préfixées par leur longueur)
- ans_pre_size (u32), ans_size (u32) – utilisés pour parser les tailles des réponses
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Les builds récents de BeaconHTTP prennent également en charge la rotation sélectionnée par l’opérateur entre plusieurs URI, user-agents, headers Host et serveurs, avec une sélection séquentielle ou aléatoire.<sup>[[2]](#references)</sup> Du point de vue du hunting, cela signifie qu’un hôte infecté peut effectuer des callbacks vers plusieurs chemins et combinaisons de headers sans abandonner la famille classique de beacons compactés avec RC4.

Exemple de profil HTTP par défaut (provenant d’un build de beacon) :<sup>[[1]](#references)</sup>
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

Lorsque l’opérateur clique sur Create dans le builder, AdaptixC2 intègre le profile chiffré sous forme de bloc de données final dans le beacon. Le format est le suivant :<sup>[[1]](#references)</sup>
- 4 octets : taille de la configuration (uint32, little-endian)
- N octets : données de configuration chiffrées avec RC4
- 16 octets : clé RC4

Le loader du beacon copie la clé de 16 octets depuis la fin, puis déchiffre avec RC4 le bloc de N octets sur place :<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implications pratiques :<sup>[[1]](#references)</sup>
- L’ensemble de la structure se trouve souvent dans la section .rdata du PE.
- L’extraction est déterministe : lire la taille, lire le ciphertext de cette taille, lire la clé de 16 octets placée immédiatement après, puis effectuer le déchiffrement RC4.

## Workflow d’extraction de la configuration (défenseurs)

Écrivez un extracteur qui reproduit la logique du beacon :<sup>[[1]](#references)</sup>
1) Localiser le blob dans le PE (généralement dans .rdata). Une approche pragmatique consiste à analyser .rdata à la recherche d’une disposition plausible [size|ciphertext|16‑byte key] et à tenter RC4.
2) Lire les 4 premiers octets → size (uint32 LE).
3) Lire les N=size octets suivants → ciphertext.
4) Lire les 16 derniers octets → clé RC4.
5) Déchiffrer le ciphertext avec RC4. Analyser ensuite le profil en clair comme suit :
- scalaires u32/boolean comme indiqué ci-dessus
- chaînes préfixées par leur longueur (longueur u32 suivie des octets ; un NUL final peut être présent)
- tableaux : servers_count suivi du nombre correspondant de paires [string, u32 port]

Proof of concept Python minimal (autonome, sans dépendances externes) fonctionnant avec un blob préextrait :
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
- Lors de l'automatisation, utilisez un parseur PE pour lire `.rdata`, puis appliquez une fenêtre glissante : pour chaque offset o, essayez `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, clé candidate = 16 octets suivants ; déchiffrez avec RC4 et vérifiez que les champs de type chaîne se décodent en UTF-8 et que les longueurs sont cohérentes.
- Parsez les profils SMB/TCP en suivant les mêmes conventions préfixées par la longueur.

## Profils de listener personnalisés : ne codez pas en dur uniquement le schéma HTTP classique

Le format d'encapsulation externe (`u32 size | RC4 ciphertext | 16-byte key`) est réutilisable, de sorte que les listeners personnalisés par l'acteur peuvent conserver le même workflow d'extraction tout en modifiant complètement la disposition des champs déchiffrés.

Un bon exemple récent est la campagne Tropic Trooper de mars 2026, dans laquelle le beacon Adaptix extrait ne contenait pas de profil HTTP/TCP standard. À la place, le blob déchiffré stockait des paramètres de transport GitHub tels que :<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (par exemple `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Stratégie pratique de parsing :
- Détectez d'abord le blob RC4 externe exactement comme d'habitude.
- Après le déchiffrement, basez le choix sur les chaînes sentinelles et la cohérence des champs plutôt que d'imposer immédiatement le parseur HTTP.
- Les bonnes sentinelles incluent `api.github.com`, `/issues?state=open`, les verbes/URI HTTP, les chaînes de type named pipe ou des tableaux serveur/port manifestement valides.
- Si le parseur HTTP échoue mais que le plaintext contient des chaînes UTF-8 cohérentes préfixées par leur longueur, conservez l'échantillon et essayez d'autres schémas au lieu de le supprimer comme faux positif.

Dans cette campagne, le listener personnalisé utilisait les issues GitHub comme transport C2, et le beacon interrogeait `ipinfo.io` pour connaître son IP externe, car l'API GitHub ne révèle pas directement à l'opérateur l'adresse source de la victime.<sup>[[5]](#references)</sup>

## Fingerprinting réseau et hunting

HTTP :<sup>[[1]](#references)</sup>
- Courant : POST vers des URI sélectionnées par l'opérateur (par ex. /uri.php, /endpoint/api)
- Paramètre d'en-tête personnalisé utilisé pour l'identifiant du beacon (par ex. X‑Beacon‑Id, X‑App‑Id)
- User-agents imitant Firefox 20 ou des builds Chrome contemporains
- Cadence de polling visible via sleep_delay/jitter_delay
- Les builds plus récents peuvent faire tourner les URI, user-agents, en-têtes Host et serveurs entre les callbacks ; regroupez donc les événements selon les noms d'en-têtes inhabituels, les modèles de taille des réponses, la réutilisation TLS et le timing au lieu de supposer une seule paire chemin/UA.<sup>[[2]](#references)</sup>

SMB/TCP :<sup>[[1]](#references)</sup>
- Listeners SMB utilisant des named pipes pour le C2 intranet lorsque l'egress web est limité
- Les beacons TCP peuvent préfixer le trafic de quelques octets afin d'obfusquer le début du protocole

Valeurs par défaut actuelles du teamserver upstream
- `profile.yaml` fournit actuellement le teamserver `0.0.0.0:4321`, l'endpoint `/endpoint`, les noms de fichiers de certificat/clé `server.rsa.crt` et `server.rsa.key`, ainsi que des extenders pour HTTP, SMB, TCP, DNS, l'agent Beacon et Gopher.<sup>[[2]](#references)</sup>
- Pour les routes non correspondantes, le gestionnaire d'erreur par défaut renvoie `Server: AdaptixC2` et `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Le corps 404 standard contient `AdaptixC2 404` et `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Les scans à l'échelle d'Internet effectués en 2026 ont trouvé de nombreux teamservers exposés sur `4321` et de nombreux beacon listeners sur `43211` ; les deux ports sont donc de bons pivots initiaux, mais ne doivent pas être considérés comme exhaustifs.<sup>[[4]](#references)</sup>

Empreintes des listeners DNS/DoH :<sup>[[4]](#references)</sup>
- L'extender BeaconDNS actuel répond de manière autoritative (`AA=true`)
- Les requêtes qui ne correspondent pas à la forme du protocole beacon — notamment les noms comportant moins de 5 labels avant le domaine configuré — reçoivent couramment la réponse `TXT "OK"`
- Si le TTL de base configuré est laissé à zéro, le listener utilise une base de 10 secondes et ajoute jusqu'à 59 secondes de jitter
- Cela rend les probes actives à labels courts utiles lorsqu'aucun listener HTTP n'est exposé

## TTPs de loader et de persistence observées lors d'incidents

Loaders PowerShell en mémoire :<sup>[[1]](#references)</sup>
- Téléchargent des payloads Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allouent de la mémoire unmanaged, copient le shellcode et modifient la protection en 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Exécutent via une invocation dynamique .NET : Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Loaders de shellcode signés trojanisés / en plusieurs étapes :<sup>[[5]](#references)</sup>
- Une chaîne Tropic Trooper de 2026 utilisait un exécutable SumatraPDF trojanisé (loader TOSHIS) qui redirigeait `_security_init_cookie` vers du code malveillant au lieu de modifier le point d'entrée PE
- Le loader résolvait les APIs via le hashing Adler-32, téléchargeait un PDF leurre, récupérait le shellcode de deuxième étape, le déchiffrait avec AES-128-CBC via WinCrypt (`CryptDeriveKey` à partir d'une seed codée en dur), puis exécutait de manière reflective un beacon Adaptix en mémoire
- La persistence a ensuite été déplacée vers des tâches planifiées aux noms d'apparence légitime tels que `\MSDNSvc` ou `\MicrosoftUDN`, configurées pour relancer l'agent environ toutes les deux heures

Consultez ces pages pour l'exécution en mémoire et les considérations AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistence observés :<sup>[[1]](#references)</sup>
- Raccourci du dossier Startup (.lnk) pour relancer un loader à l'ouverture de session
- Clés Registry Run (HKCU/HKLM ...\CurrentVersion\Run), souvent avec des noms d'apparence légitime comme "Updater" pour démarrer loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijacking en déposant msimg32.dll sous %APPDATA%\Microsoft\Windows\Templates pour les processus vulnérables

Approfondissements et vérifications des techniques :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idées de hunting
- PowerShell déclenchant des transitions RW→RX : VirtualProtect vers PAGE_EXECUTE_READWRITE dans powershell.exe.<sup>[[8]](#references)</sup>
- Patterns d'invocation dynamique (GetDelegateForFunctionPointer)
- Réponses HTTPS 404 non correspondantes avec `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ou `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Réponses DNS avec `AA=true` et `TXT "OK"` pour des requêtes courtes sous des domaines suspects.<sup>[[4]](#references)</sup>
- Trafic API GitHub vers `/repos/<owner>/<repo>/issues` suivi de requêtes vers `ipinfo.io` depuis la même chaîne loader/beacon.<sup>[[5]](#references)</sup>
- Fichiers .lnk Startup sous les dossiers Startup de l'utilisateur ou communs.<sup>[[1]](#references)</sup>
- Clés Run suspectes (par ex. "Updater") et noms de loader tels que update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Échantillons PE trojanisés qui redirigent `_security_init_cookie` vers du code downloader avant d'afficher un document leurre.<sup>[[5]](#references)</sup>
- Chemins DLL accessibles en écriture par l'utilisateur sous %APPDATA%\Microsoft\Windows\Templates contenant msimg32.dll.<sup>[[1]](#references)</sup>

## Notes sur les champs OpSec

- KillDate : timestamp après lequel l'agent expire automatiquement.<sup>[[1]](#references)</sup>
- WorkingTime : heures durant lesquelles l'agent doit être actif afin de se fondre dans l'activité professionnelle.<sup>[[1]](#references)</sup>

Ces champs peuvent être utilisés pour le clustering et pour expliquer les périodes d'inactivité observées.

## Indices YARA et statiques

Unit 42 a publié des règles YARA de base pour les beacons (C/C++ et Go) ainsi que des constantes de hashing d'API de loader.<sup>[[1]](#references)</sup> Envisagez de les compléter par des règles recherchant la disposition [size|ciphertext|16-byte-key] près de la fin de la section PE `.rdata`, les chaînes du profil HTTP par défaut et des marqueurs plus récents de serveur/listener tels que `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` et `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2 : Un nouveau framework open source exploité dans des attaques réelles (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentation Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2 : Fingerprinting d'un framework C2 open source à grande échelle (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper pivote vers AdaptixC2 et un Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Documentation Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Documentation Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constantes de protection de la mémoire – Documentation Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Clés Registry Run/Dossier Startup](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
