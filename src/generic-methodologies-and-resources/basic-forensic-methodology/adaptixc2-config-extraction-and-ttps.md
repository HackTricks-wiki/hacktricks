# Estrazione della configurazione e TTP di AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 è un framework modulare e open-source di post-exploitation/C2 con beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e supporto BOF. Questa pagina documenta:
- Come la sua configurazione packed con RC4 è incorporata e come estrarla dai beacon
- Indicatori di rete/profilo per listener HTTP/SMB/TCP
- TTP comuni di loader e persistence osservate in natura, con link alle pagine sulle tecniche Windows pertinenti

Le release upstream recenti includono anche listener beacon DNS/DoH e la famiglia separata di agent/listener Gopher; pertanto, l'infrastruttura Adaptix moderna può esporre più superfici rispetto a quelle HTTP/SMB/TCP originali, anche quando uno specifico sample utilizza ancora il classic beacon agent.

## Profili e campi dei beacon

AdaptixC2 supporta tre tipi principali di beacon:
- BEACON_HTTP: web C2 con server/porte/SSL configurabili, metodo, URI, headers, user-agent e un nome di parametro personalizzato
- BEACON_SMB: C2 peer-to-peer tramite named pipe (intranet)
- BEACON_TCP: socket diretti, con la possibilità di anteporre un marker per offuscare l'inizio del protocollo

Questi sono i layout dei beacon documentati pubblicamente nelle prime analisi di Adaptix e rappresentano ancora il punto di partenza più comune per l'estrazione lato sample. Tuttavia, le build upstream attuali includono anche gli extender `BeaconDNS` e Gopher sul lato server; non bisogna quindi presumere che ogni deployment Adaptix attivo esponga soltanto un'infrastruttura HTTP/SMB/TCP.

Campi tipici dei profili osservati nelle configurazioni dei beacon HTTP (dopo la decryption):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – utilizzati per analizzare le response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Le build recenti di BeaconHTTP supportano anche la rotation selezionata dall'operatore tra più URI, user-agent, Host headers e server, con selezione sequenziale o casuale. Dal punto di vista dell'hunting, ciò significa che un singolo host infetto può distribuire il traffico su diversi callback path e combinazioni di header senza abbandonare la classic beacon family packed con RC4.

Esempio di profilo HTTP predefinito (da una beacon build):
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
Profilo HTTP malevolo osservato (attacco reale):
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
## Packaging e percorso di caricamento della configurazione cifrata

Quando l'operatore fa clic su Create nel builder, AdaptixC2 incorpora il profilo cifrato come tail blob nel beacon. Il formato è:
- 4 byte: dimensione della configurazione (uint32, little-endian)
- N byte: dati di configurazione cifrati con RC4
- 16 byte: chiave RC4

Il loader del beacon copia la chiave di 16 byte dalla fine e decifra con RC4 il blocco di N byte in place:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Implicazioni pratiche:
- L'intera struttura si trova spesso nella sezione PE .rdata.
- L'estrazione è deterministica: leggere size, leggere il ciphertext di quella dimensione, leggere la chiave di 16 byte posizionata immediatamente dopo, quindi eseguire RC4-decrypt.

## Workflow di estrazione della configurazione (difensori)

Scrivere un extractor che riproduca la logica del beacon:
1) Individuare il blob all'interno del PE (comunemente in .rdata). Un approccio pratico consiste nell'analizzare .rdata alla ricerca di un layout plausibile [size|ciphertext|16-byte key] e tentare RC4.
2) Leggere i primi 4 byte → size (uint32 LE).
3) Leggere i successivi N=size byte → ciphertext.
4) Leggere gli ultimi 16 byte → RC4 key.
5) Eseguire RC4-decrypt del ciphertext. Quindi analizzare il profilo in chiaro come segue:
- scalari u32/boolean come indicato sopra
- stringhe con prefisso di lunghezza (lunghezza u32 seguita dai byte; può essere presente un NUL finale)
- array: servers_count seguito dal numero corrispondente di coppie [string, u32 port]

Proof-of-concept Python minimale (standalone, senza dipendenze esterne) che funziona con un blob pre-estratto:
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
Suggerimenti:
- Quando automatizzi, usa un PE parser per leggere `.rdata`, quindi applica una sliding window: per ogni offset o, prova size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; esegui la decrittazione RC4 e verifica che i campi stringa vengano decodificati come UTF-8 e che le lunghezze siano plausibili.
- Analizza i profili SMB/TCP seguendo le stesse convenzioni con lunghezza prefissata.

## Custom listener profiles: non usare hard-code solo per lo schema HTTP classico

Il formato di packing esterno (`u32 size | RC4 ciphertext | 16-byte key`) è riutilizzabile, quindi i listener personalizzati dagli attori possono mantenere lo stesso workflow di estrazione modificando completamente il layout dei campi decrittati.

Un buon esempio recente è la campagna Tropic Trooper dell'aprile 2026, nella quale l'Adaptix beacon estratto non conteneva un profilo HTTP/TCP standard. Al contrario, il blob decrittato memorizzava parametri di trasporto GitHub come:
- `repo_owner`
- `repo_name`
- `api_host` (ad esempio `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Strategia pratica per il parser:
- Rileva prima il blob RC4 esterno esattamente come al solito.
- Dopo la decrittazione, scegli il ramo in base a sentinel string e alla validità dei campi, invece di forzare immediatamente l'HTTP parser.
- Buoni sentinel includono `api.github.com`, `/issues?state=open`, verbi/URI HTTP, stringhe in stile named pipe o array di server/porte evidentemente validi.
- Se l'HTTP parser fallisce ma il plaintext contiene stringhe UTF-8 coerenti con lunghezza prefissata, conserva il sample e prova schemi alternativi invece di scartarlo come falso positivo.

In quella campagna il custom listener usava le GitHub issues come trasporto C2, mentre il beacon interrogava `ipinfo.io` per conoscere il proprio IP esterno, perché la GitHub API non rivela direttamente all'operatore l'indirizzo sorgente della vittima.

## Network fingerprinting e hunting

HTTP
- Comune: POST verso URI scelti dall'operatore (ad es. `/uri.php`, `/endpoint/api`)
- Parametro di custom header usato per il beacon ID (ad es. `X‑Beacon‑Id`, `X‑App‑Id`)
- User-agent che imitano Firefox 20 o build contemporanee di Chrome
- Cadenza del polling visibile tramite sleep_delay/jitter_delay
- Le build più recenti possono ruotare URI, user-agent, header Host e server tra i callback; esegui quindi il clustering su nomi di header non comuni, pattern delle dimensioni delle risposte, riutilizzo TLS e tempistiche, invece di presumere una singola coppia path/UA

SMB/TCP
- Listener SMB named pipe per C2 intranet quando l'uscita web è limitata
- I TCP beacon possono anteporre alcuni byte al traffico per offuscare l'inizio del protocollo

Current upstream teamserver defaults
- `profile.yaml` attualmente include `0.0.0.0:4321` per il teamserver, l'endpoint `/endpoint`, i nomi dei file certificato/chiave `server.rsa.crt` e `server.rsa.key`, oltre agli extenders per HTTP, SMB, TCP, DNS, Beacon agent e Gopher
- Per le route non corrispondenti, l'error handler predefinito restituisce `Server: AdaptixC2` e `Adaptix-Version: v1.2`
- Il body 404 predefinito contiene `AdaptixC2 404` e `You need to enter the correct connection details.`
- Le scansioni Internet-wide del 2026 hanno rilevato molti teamserver esposti sulla porta `4321` e molti beacon listener sulla porta `43211`; entrambe le porte sono quindi seed pivot utili, ma non devono essere considerate esaustive

DNS/DoH listener fingerprints
- L'extender BeaconDNS attuale risponde in modo autorevole (`AA=true`)
- Le query che non corrispondono alla forma del protocollo beacon — in particolare i nomi con meno di 5 label prima del dominio configurato — ricevono comunemente la risposta `TXT "OK"`
- Se il base TTL configurato viene lasciato a zero, il listener usa un valore base di 10 secondi e aggiunge fino a 59 secondi di jitter
- Questo rende utili le active probe con label brevi quando non è esposto alcun HTTP listener

## Loader e TTP di persistence osservati negli incidenti

In‑memory PowerShell loaders
- Scaricano payload Base64/XOR (`Invoke‑RestMethod` / WebClient)
- Allocano memoria unmanaged, copiano shellcode e modificano la protection a 0x40 (`PAGE_EXECUTE_READWRITE`) tramite VirtualProtect
- Eseguono tramite dynamic invocation .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- Una catena Tropic Trooper del 2026 utilizzava un eseguibile SumatraPDF trojanized (TOSHIS loader) che reindirizzava `_security_init_cookie` verso codice malevolo invece di applicare patch al PE entry point
- Il loader risolveva le API tramite hashing Adler-32, scaricava un PDF esca, recuperava shellcode di secondo stadio, lo decrittava con AES-128-CBC tramite WinCrypt (`CryptDeriveKey` da un seed hardcoded) ed eseguiva reflectively un Adaptix beacon in memoria
- La persistence è stata successivamente spostata su scheduled task con nomi dall'aspetto benigno come `\MSDNSvc` o `\MicrosoftUDN`, configurati per rilanciare l'agent circa ogni due ore

Consulta queste pagine per l'esecuzione in memoria e le considerazioni su AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Meccanismi di persistence osservati
- Shortcut (.lnk) nella Startup folder per rilanciare un loader al logon
- Registry Run key (HKCU/HKLM ...\CurrentVersion\Run), spesso con nomi dall'aspetto benigno come "Updater" per avviare loader.ps1
- DLL search-order hijack depositando msimg32.dll in `%APPDATA%\Microsoft\Windows\Templates` per i processi vulnerabili

Approfondimenti e verifiche sulle technique:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idee per l'hunting
- Processi PowerShell che generano transizioni RW→RX: VirtualProtect verso PAGE_EXECUTE_READWRITE all'interno di powershell.exe
- Pattern di dynamic invocation (GetDelegateForFunctionPointer)
- 404 HTTPS non corrispondenti con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details.`
- Risposte DNS con `AA=true` e `TXT "OK"` per query brevi nei domini sospetti
- Traffico GitHub API verso `/repos/<owner>/<repo>/issues` seguito da lookup a `ipinfo.io` dalla stessa catena loader/beacon
- File .lnk nella Startup folder dell'utente o comune
- Run key sospette (ad es. "Updater") e nomi di loader come update.ps1/loader.ps1
- Sample PE trojanized che reindirizzano `_security_init_cookie` verso codice downloader prima di mostrare un documento esca
- Percorsi DLL scrivibili dall'utente sotto `%APPDATA%\Microsoft\Windows\Templates` contenenti msimg32.dll

## Note sui campi OpSec

- KillDate: timestamp dopo il quale l'agent scade automaticamente
- WorkingTime: ore durante le quali l'agent deve essere attivo per mimetizzarsi con l'attività lavorativa

Questi campi possono essere utilizzati per il clustering e per spiegare i periodi di inattività osservati.

## YARA e indicatori statici

Unit 42 ha pubblicato regole YARA di base per i beacon (C/C++ e Go) e per le costanti di API-hashing dei loader. Valuta di integrarle con regole che cerchino il layout [size|ciphertext|16-byte-key] vicino alla fine della sezione PE `.rdata`, le stringhe del profilo HTTP predefinito e marker più recenti di server/listener come `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.

## Riferimenti

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
