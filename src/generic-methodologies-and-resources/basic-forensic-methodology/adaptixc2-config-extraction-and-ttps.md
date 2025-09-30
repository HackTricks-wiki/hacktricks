# AdaptixC2 Extraction de configuration et TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 est un framework modulaire et open‑source de post‑exploitation/C2 avec des beacons Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) et prise en charge de BOF. Cette page documente :
- Comment sa configuration chiffrée RC4 est intégrée et comment l'extraire des beacons
- Indicateurs réseau/profil pour les listeners HTTP/SMB/TCP
- TTPs courants de loader et de persistence observés dans la nature, avec des liens vers des pages de techniques Windows pertinentes

## Profils et champs des beacons

AdaptixC2 prend en charge trois types principaux de beacons :
- BEACON_HTTP: C2 web avec serveurs/ports/SSL configurables, méthode, URI, headers, user‑agent, et un nom de paramètre personnalisé
- BEACON_SMB: C2 peer‑to‑peer via named‑pipe (intranet)
- BEACON_TCP: sockets directs, éventuellement avec un marqueur préfixé pour obfusquer le démarrage du protocole

Champs de profil typiques observés dans les configs HTTP des beacons (après déchiffrement) :
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
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

Lorsque l'opérateur clique sur Create dans le builder, AdaptixC2 intègre le profil chiffré en tant que tail blob dans le beacon. Le format est :
- 4 bytes: taille de la configuration (uint32, little‑endian)
- N bytes: données de configuration chiffrées par RC4
- 16 bytes: RC4 key

Le beacon loader copie la key de 16 bytes depuis la fin et RC4‑decrypts le bloc de N bytes en place:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implications pratiques :
- L'ensemble de la structure se trouve souvent dans la section .rdata du PE.
- L'extraction est déterministe : lire la taille, lire le ciphertext de cette taille, lire la clé de 16 octets placée immédiatement après, puis déchiffrer avec RC4.

## Flux de travail d'extraction de configuration (défenseurs)

Écrire un extracteur qui imite la logique du beacon :
1) Localisez le blob dans le PE (généralement .rdata). Une approche pragmatique consiste à scanner .rdata à la recherche d'une mise en page plausible [size|ciphertext|16‑byte key] et tenter RC4.
2) Lire les 4 premiers octets → size (uint32 LE).
3) Lire les N=size octets suivants → ciphertext.
4) Lire les 16 derniers octets → clé RC4.
5) Déchiffrer le ciphertext avec RC4. Puis analyser le profil en clair comme suit :
- scalaires u32/boolean comme indiqué ci‑dessus
- chaînes préfixées par la longueur (u32 length suivi des octets ; un NUL terminal peut être présent)
- tableaux : servers_count suivi de autant de paires [string, u32 port]

Preuve de concept Python minimale (autonome, sans dépendances externes) fonctionnant avec un blob pré‑extrait :
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
Tips:
- Lors de l'automatisation, utilisez un parseur PE pour lire .rdata puis appliquez une fenêtre glissante : pour chaque offset o, essayez size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt et vérifiez que les champs string se décodent en UTF‑8 et que les longueurs sont cohérentes.
- Analysez les profils SMB/TCP en suivant les mêmes conventions préfixant la longueur.

## Empreintes réseau et chasse

HTTP
- Fréquent : POST vers des URI choisies par l'opérateur (par ex., /uri.php, /endpoint/api)
- Paramètre d'en‑tête personnalisé utilisé pour l'ID du beacon (par ex., X‑Beacon‑Id, X‑App‑Id)
- User‑agents imitant Firefox 20 ou des builds Chrome contemporains
- Cadence de sondage visible via sleep_delay/jitter_delay

SMB/TCP
- Listeners de named‑pipe SMB pour C2 intranet lorsque la sortie web est limitée
- Les beacons TCP peuvent préfixer quelques octets avant le trafic pour obscurcir le début du protocole

## TTPs de loader et de persistance observés dans des incidents

Chargeurs PowerShell en mémoire
- Téléchargent des payloads Base64/XOR (Invoke‑RestMethod / WebClient)
- Allouent de la mémoire non gérée, copient le shellcode, changent la protection en 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Exécutent via invocation dynamique .NET : Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Consultez ces pages pour l'exécution en mémoire et les considérations AMSI/ETW :

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mécanismes de persistance observés
- Raccourci dans le dossier Startup (.lnk) pour relancer un loader au logon
- Clés Run du registre (HKCU/HKLM ...\CurrentVersion\Run), souvent avec des noms à consonance bénigne comme "Updater" pour démarrer loader.ps1
- DLL search‑order hijack en déposant msimg32.dll sous %APPDATA%\Microsoft\Windows\Templates pour des processus susceptibles

Approfondissements et vérifications techniques :

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idées de chasse
- Transitions RW→RX initiées par PowerShell : VirtualProtect vers PAGE_EXECUTE_READWRITE dans powershell.exe
- Schémas d'invocation dynamique (GetDelegateForFunctionPointer)
- .lnk dans les dossiers Startup utilisateur ou communs
- Clés Run suspectes (ex., "Updater"), et noms de loader comme update.ps1/loader.ps1
- Chemins DLL inscriptibles par l'utilisateur sous %APPDATA%\Microsoft\Windows\Templates contenant msimg32.dll

## Notes sur les champs OpSec

- KillDate : horodatage après lequel l'agent s'auto‑expire
- WorkingTime : heures pendant lesquelles l'agent doit être actif pour se fondre dans l'activité professionnelle

Ces champs peuvent être utilisés pour le clustering et pour expliquer des périodes d'inactivité observées.

## YARA et pistes statiques

Unit 42 a publié des YARA basiques pour les beacons (C/C++ et Go) et des constantes de hachage d'API du loader. Envisagez de compléter avec des règles cherchant la mise en page [size|ciphertext|16‑byte‑key] près de la fin de .rdata du PE et les chaînes du profil HTTP par défaut.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
