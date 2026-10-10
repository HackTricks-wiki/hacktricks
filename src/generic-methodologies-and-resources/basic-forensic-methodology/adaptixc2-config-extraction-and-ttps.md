# Estrazione della configurazione e TTP di AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 è un framework modulare e open-source per post-exploitation/C2, con beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e supporto BOF.<sup>[[1]](#references)</sup> Questa pagina documenta:
- Come viene incorporata la configurazione impacchettata con RC4 e come estrarla dai beacon
- Indicatori di rete/profilo per i listener HTTP/SMB/TCP
- TTP comuni di loader e persistenza osservati in natura, con link alle relative pagine sulle tecniche Windows

Le versioni upstream recenti includono anche listener beacon DNS/DoH e la famiglia separata di agent/listener Gopher, quindi le infrastrutture Adaptix moderne possono esporre più delle superfici HTTP/SMB/TCP originali, anche quando un campione specifico usa ancora il classico agent beacon.<sup>[[2]](#references)</sup>

## Profili beacon e campi

AdaptixC2 supporta tre tipi principali di beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web con server/porte/SSL configurabili, metodo, URI, header, user-agent e un nome di parametro personalizzato
- BEACON_SMB: C2 peer-to-peer tramite named pipe (intranet)
- BEACON_TCP: socket diretti, con possibilità di anteporre un marker per offuscare l'inizio del protocollo

Questi sono i layout dei beacon documentati pubblicamente nelle prime analisi di Adaptix e restano il punto di partenza più comune per l'estrazione dal campione.<sup>[[1]](#references)</sup> Tuttavia, le build upstream attuali includono anche gli extender `BeaconDNS` e Gopher lato server, quindi non presumere che ogni deployment Adaptix attivo esponga solo infrastrutture HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Campi tipici dei profili osservati nelle configurazioni dei beacon HTTP (dopo la decrittazione):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (stringhe con prefisso di lunghezza)
- ans_pre_size (u32), ans_size (u32) – usati per analizzare le dimensioni delle risposte
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Le build recenti di BeaconHTTP supportano anche la rotazione selezionata dall'operatore tra più URI, user-agent, header Host e server, con selezione sequenziale o casuale.<sup>[[2]](#references)</sup> Dal punto di vista dell'hunting, ciò significa che un singolo host infetto può distribuire le callback su diversi percorsi e combinazioni di header senza abbandonare la classica famiglia di beacon impacchettati con RC4.

Esempio di profilo HTTP predefinito (da una build beacon):<sup>[[1]](#references)</sup>

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

Profilo HTTP malevolo osservato (attacco reale):<sup>[[1]](#references)</sup>

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

## Confezionamento della configurazione cifrata e percorso di caricamento

Quando l'operatore fa clic su Create nel builder, AdaptixC2 inserisce il profilo cifrato nel beacon come blob in coda. Il formato è:<sup>[[1]](#references)</sup>
- 4 byte: dimensione della configurazione (uint32, little-endian)
- N byte: dati di configurazione cifrati con RC4
- 16 byte: chiave RC4

Il loader del beacon copia la chiave di 16 byte dalla fine e decifra con RC4 il blocco di N byte in-place:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implicazioni pratiche:<sup>[[1]](#references)</sup>
- L'intera struttura si trova spesso nella sezione .rdata del PE.
- L'estrazione è deterministica: leggi la dimensione, leggi il ciphertext di quella dimensione, leggi la chiave RC4 da 16 byte collocata subito dopo, quindi decifra con RC4.

## Workflow di estrazione della configurazione (difensori)

Scrivi un estrattore che imiti la logica del beacon:<sup>[[1]](#references)</sup>
1) Individua il blob nel PE (comunemente in .rdata). Un approccio pragmatico consiste nello scansionare .rdata alla ricerca di un layout plausibile [size|ciphertext|16-byte key] e tentare RC4.
2) Leggi i primi 4 byte → size (uint32 LE).
3) Leggi i successivi N=size byte → ciphertext.
4) Leggi gli ultimi 16 byte → chiave RC4.
5) Decifra il ciphertext con RC4. Poi analizza il profilo in chiaro come segue:
   - scalari u32/boolean come indicato sopra
   - stringhe precedute dalla lunghezza (lunghezza u32 seguita dai byte; può essere presente un NUL finale)
   - array: servers_count seguito da altrettante coppie [string, u32 port]

Proof-of-concept Python minimale (standalone, senza dipendenze esterne) che funziona con un blob già estratto:

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
- Quando automatizzi, usa un parser PE per leggere `.rdata`, quindi applica una finestra mobile: per ogni offset `o`, prova `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, la chiave candidata = i 16 byte successivi; decifra con RC4 e verifica che i campi stringa siano decodificati come UTF-8 e che le lunghezze siano ragionevoli.
- Analizza i profili SMB/TCP seguendo le stesse convenzioni con lunghezze prefissate.

## Profili listener personalizzati: non codificare rigidamente solo lo schema HTTP classico

Il formato di packing esterno (`u32 size | RC4 ciphertext | 16-byte key`) è riutilizzabile, quindi i listener personalizzati dagli attori possono mantenere lo stesso flusso di estrazione modificando completamente il layout dei campi decrittati.

Un buon esempio recente è la campagna Tropic Trooper del marzo 2026, in cui il beacon Adaptix estratto non conteneva un profilo HTTP/TCP standard. Il blob decrittato conteneva invece parametri di trasporto GitHub, come:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (ad esempio `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Strategia pratica per il parser:
- Per prima cosa, rileva il blob RC4 esterno esattamente come di consueto.
- Dopo la decrittazione, scegli il parser in base a stringhe sentinella e alla coerenza dei campi, invece di imporre subito il parser HTTP.
- Tra le buone stringhe sentinella ci sono `api.github.com`, `/issues?state=open`, verbi/URI HTTP, stringhe in stile named pipe o array di server/porte chiaramente validi.
- Se il parser HTTP fallisce ma il testo in chiaro contiene stringhe UTF-8 coerenti con lunghezze prefissate, conserva il sample e prova schemi alternativi invece di scartarlo come falso positivo.

In quella campagna, il listener personalizzato usava le issue GitHub come trasporto C2 e il beacon interrogava `ipinfo.io` per ottenere il proprio IP esterno, poiché l’API GitHub non rivela direttamente all’operatore l’indirizzo sorgente della vittima.<sup>[[5]](#references)</sup>

## Fingerprinting e ricerca in rete

HTTP:<sup>[[1]](#references)</sup>
- Comune: POST verso URI scelti dall’operatore (ad es., /uri.php, /endpoint/api)
- Parametro di header personalizzato usato per il beacon ID (ad es., X‑Beacon‑Id, X‑App‑Id)
- User-agent che imitano Firefox 20 o versioni recenti di Chrome
- Cadenza di polling visibile tramite sleep_delay/jitter_delay
- Le versioni più recenti possono ruotare URI, user-agent, header Host e server tra i callback; quindi, raggruppa i risultati in base a nomi di header insoliti, pattern delle dimensioni delle risposte, riutilizzo TLS e tempistiche, invece di presumere una singola coppia percorso/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener SMB named pipe per C2 intranet dove l’uscita web è limitata
- I beacon TCP possono anteporre alcuni byte al traffico per offuscare l’inizio del protocollo

Valori predefiniti attuali del teamserver upstream
- Attualmente `profile.yaml` include il teamserver `0.0.0.0:4321`, l’endpoint `/endpoint`, i nomi dei file certificato/chiave `server.rsa.crt` e `server.rsa.key`, ed extender per HTTP, SMB, TCP, DNS, l’agente Beacon e Gopher.<sup>[[2]](#references)</sup>
- Per le route senza corrispondenza, il gestore di errori predefinito restituisce `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Il corpo 404 standard contiene `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Le scansioni su scala globale di Internet nel 2026 hanno rilevato molti teamserver esposti sulla porta `4321` e molti listener beacon sulla porta `43211`; entrambe le porte sono quindi utili come punti di partenza, ma non vanno considerate esaustive.<sup>[[4]](#references)</sup>

Fingerprint dei listener DNS/DoH:<sup>[[4]](#references)</sup>
- L’extender BeaconDNS attuale risponde in modo autorevole (`AA=true`)
- Le query che non corrispondono alla struttura prevista dal protocollo beacon, in particolare i nomi con meno di 5 label prima del dominio configurato, ricevono spesso la risposta `TXT "OK"`
- Se il TTL di base configurato resta a zero, il listener usa un valore di base di 10 secondi e aggiunge fino a 59 secondi di jitter
- Per questo, le sonde attive con label brevi sono utili quando non è esposto alcun listener HTTP

## TTP di loader e persistenza osservate negli incidenti

Loader PowerShell in-memory:<sup>[[1]](#references)</sup>
- Scaricano payload Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allocano memoria unmanaged, copiano la shellcode e impostano la protezione su 0x40 (PAGE_EXECUTE_READWRITE) tramite VirtualProtect.<sup>[[7]](#references)</sup>
- Eseguono tramite invocazione dinamica .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software firmato trojanizzato / loader di shellcode a stadi:<sup>[[5]](#references)</sup>
- Una catena Tropic Trooper del 2026 ha usato un eseguibile SumatraPDF trojanizzato (loader TOSHIS) che reindirizzava `_security_init_cookie` verso codice malevolo, invece di modificare l’entry point PE
- Il loader risolveva le API tramite hashing Adler-32, scaricava un PDF esca, recuperava la shellcode del secondo stadio, la decrittava con AES-128-CBC tramite WinCrypt (`CryptDeriveKey` da un seed hardcoded) ed eseguiva in memoria, tramite esecuzione riflessiva, un beacon Adaptix
- In seguito, la persistenza è passata ad attività pianificate con nomi dall’aspetto innocuo, come `\MSDNSvc` o `\MicrosoftUDN`, configurate per riavviare l’agente all’incirca ogni due ore

Consulta queste pagine per informazioni sull’esecuzione in-memory e sulle considerazioni relative ad AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Meccanismi di persistenza osservati:<sup>[[1]](#references)</sup>
- Collegamento (.lnk) nella cartella Startup per riavviare un loader all’accesso
- Chiavi Run del registro (HKCU/HKLM ...\CurrentVersion\Run), spesso con nomi dall’aspetto innocuo come "Updater" per avviare loader.ps1.<sup>[[10]](#references)</sup>
- Hijack dell’ordine di ricerca delle DLL, copiando msimg32.dll in %APPDATA%\Microsoft\Windows\Templates per i processi vulnerabili

Approfondimenti tecnici e verifiche:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Idee per la ricerca
- PowerShell che avvia transizioni RW→RX: VirtualProtect per PAGE_EXECUTE_READWRITE all’interno di powershell.exe.<sup>[[8]](#references)</sup>
- Pattern di invocazione dinamica (GetDelegateForFunctionPointer)
- Risposte HTTPS 404 senza corrispondenza con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Risposte DNS con `AA=true` e `TXT "OK"` a query brevi sotto domini sospetti.<sup>[[4]](#references)</sup>
- Traffico verso l’API GitHub a `/repos/<owner>/<repo>/issues` seguito da interrogazioni a `ipinfo.io` dalla stessa catena di loader/beacon.<sup>[[5]](#references)</sup>
- File .lnk in Startup dell’utente o nelle cartelle Startup comuni.<sup>[[1]](#references)</sup>
- Chiavi Run sospette (ad es., "Updater") e nomi di loader come update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Sample PE trojanizzati che reindirizzano `_security_init_cookie` verso codice downloader prima di mostrare un documento esca.<sup>[[5]](#references)</sup>
- Percorsi DLL scrivibili dall’utente sotto %APPDATA%\Microsoft\Windows\Templates contenenti msimg32.dll.<sup>[[1]](#references)</sup>

## Note sui campi OpSec

- KillDate: timestamp dopo il quale l’agente si autodisattiva.<sup>[[1]](#references)</sup>
- WorkingTime: ore durante le quali l’agente deve essere attivo per confondersi con l’attività aziendale.<sup>[[1]](#references)</sup>

Questi campi possono essere usati per il clustering e per spiegare i periodi di inattività osservati.

## YARA e indicatori statici

Unit 42 ha pubblicato regole YARA di base per i beacon (C/C++ e Go) e per le costanti di hashing delle API dei loader.<sup>[[1]](#references)</sup> Valuta di affiancarle a regole che rilevino il layout [size|ciphertext|16-byte-key] vicino alla fine di PE .rdata, le stringhe del profilo HTTP predefinito e indicatori più recenti di server/listener, come `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: un nuovo framework open source usato in attacchi reali (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentazione Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: fingerprinting su larga scala di un framework C2 open source (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper adotta AdaptixC2 e un listener beacon personalizzato (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Costanti di protezione della memoria – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Chiavi Run del registro/Cartella Startup](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
