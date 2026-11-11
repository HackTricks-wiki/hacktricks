# Estrazione della configurazione di AdaptixC2 e TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 è un framework modulare, open source, di post-exploitation/C2, con beacon Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) e supporto BOF.<sup>[[1]](#references)</sup> Questa pagina descrive:
- Come viene incorporata la configurazione impacchettata con RC4 e come estrarla dai beacon
- Gli indicatori di rete/profilo per i listener HTTP/SMB/TCP
- Le TTP comuni di loader e persistenza osservate in natura, con link alle pagine sulle tecniche Windows pertinenti

Le versioni upstream recenti includono anche listener beacon DNS/DoH e la famiglia separata di agent/listener Gopher; pertanto, l'infrastruttura Adaptix moderna può esporre più delle superfici HTTP/SMB/TCP originali, anche quando un campione specifico usa ancora il classico agent beacon.<sup>[[2]](#references)</sup>

## Profili e campi dei beacon

AdaptixC2 supporta tre tipi principali di beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: C2 web con server/porte/SSL configurabili, metodo, URI, header, user-agent e un nome di parametro personalizzato
- BEACON_SMB: C2 peer-to-peer tramite named pipe (intranet)
- BEACON_TCP: socket diretti, con possibilità di anteporre un marker per offuscare l'inizio del protocollo

Questi sono i layout dei beacon documentati pubblicamente nelle prime analisi di Adaptix e rappresentano ancora il punto di partenza più comune per l'estrazione dal campione.<sup>[[1]](#references)</sup> Tuttavia, le build upstream attuali includono anche gli extender `BeaconDNS` e Gopher lato server, quindi non dare per scontato che ogni deployment Adaptix attivo esponga solo infrastruttura HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Il seguente riepilogo dei campi e i campioni JSON descrivono il formato HTTP analizzato nel 2025; non costituiscono una specifica del parser per le build upstream più recenti. Campi tipici in quei campioni (dopo la decrittazione):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array di stringhe), ports (array di u32)
- http_method, uri, parameter, user_agent, http_headers (stringhe con prefisso di lunghezza)
- ans_pre_size (u32), ans_size (u32) – usati per analizzare le dimensioni delle risposte
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Le build recenti di BeaconHTTP supportano anche la rotazione, selezionata dall'operatore, tra più URI, user-agent, header Host e server, con selezione sequenziale o casuale.<sup>[[2]](#references)</sup> Dal punto di vista dell'hunting, questo significa che un singolo host infetto può distribuire le callback su più percorsi e combinazioni di header senza abbandonare la classica famiglia di beacon impacchettati con RC4.

Esempio di profilo HTTP predefinito (da una build di beacon):<sup>[[1]](#references)</sup>

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

## Impacchettamento della configurazione crittografata e percorso di caricamento

Quando l'operatore fa clic su Create nel builder, AdaptixC2 compila il profilo crittografato nel beacon. Non presumere che si trovi alla fine del PE o dello shellcode: individua i byte del profilo tramite scansione delle sezioni o seguendo `getProfile()` nell'esempio. Il formato impacchettato è:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 byte: dimensione della configurazione (uint32, little-endian)
- N byte: dati di configurazione crittografati con RC4
- 16 byte: chiave RC4

Il loader del beacon copia la chiave di 16 byte dalla fine e decrittografa con RC4 il blocco di N byte in-place:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Implicazioni pratiche:<sup>[[1]](#references)</sup>
- L'intera struttura si trova spesso nella sezione PE .rdata.
- L'estrazione è deterministica: leggere la dimensione, leggere il ciphertext di quella dimensione, leggere la chiave da 16 byte posizionata subito dopo, quindi decrittare con RC4.

## Flusso di lavoro per l'estrazione della configurazione (difensori)

Per il triage generale dei sample prima di estrarre il beacon, vedere [Analisi del malware](malware-analysis.md).

Scrivere un extractor che imiti la logica del beacon:<sup>[[1]](#references)</sup>
1) Individuare il blob all'interno del PE (comunemente in .rdata). Un approccio pratico consiste nello scansionare .rdata alla ricerca di una struttura plausibile [dimensione|ciphertext|chiave da 16 byte] e tentare RC4.
2) Leggere i primi 4 byte → dimensione (uint32 LE).
3) Leggere i successivi N=size byte → ciphertext.
4) Leggere gli ultimi 16 byte → chiave RC4.
5) Decrittare il ciphertext con RC4. Quindi analizzare il profilo in chiaro come segue:
   - scalari u32/booleani come indicato sopra
   - stringhe con prefisso di lunghezza (lunghezza u32 seguita dai byte; può essere presente un NUL finale)
   - array: servers_count seguito da altrettante coppie [stringa, porta u32]

Proof-of-concept Python per HTTP, legacy e autonomo (senza dipendenze esterne), per un blob estratto in precedenza secondo l'ordine dei campi del 2025. Per le build stock recenti, usare il parser dello schema corrente riportato sotto:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Analizza i profili HTTP e DNS stock attuali

Le build upstream attuali inseriscono per primi sei valori `u32` little-endian: watermark/tipo dell’agent, data di kill, tempo di attività, sleep, jitter e watermark/tipo del listener. I dati specifici di HTTP iniziano quindi con un flag SSL di un byte. A differenza dell’esempio legacy, includono liste con conteggio di URI, user-agent e intestazioni Host, seguite dalla modalità di rotazione e dalle impostazioni del proxy. Di conseguenza, il parser legacy inizia a leggere il flag SSL dal campo della data di kill e restituisce risultati errati su queste build. Le lunghezze delle stringhe e i valori interi di questo profilo usano la codifica little-endian; le stringhe impacchettate includono un NUL finale se non sono vuote.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Con gli helper `P` e `rc4` indicati sopra, usa questo parser sul plaintext **stock HTTP** decrittato. Non includere la chiave RC4 nei report pubblici: il profilo HTTP può contenere un nome utente e una password del proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Analizza un profilo plaintext HTTP stock attuale</summary>

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

Per un beacon DNS standard, leggi gli stessi sei campi `u32`, poi le stringhe `domain`, `resolvers`, `doh_resolvers` e `qtype` precedute dalla lunghezza. Leggi `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` e `dns_mode` come `u32`, poi la stringa user-agent DoH preceduta dalla lunghezza. `dns_mode` distingue UDP, DoH e le due direzioni di fallback. Si tratta di un layout separato: non forzare il plaintext DNS attraverso il parser HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Suggerimenti:
- Per automatizzare, usa un parser PE per leggere .rdata, poi applica una sliding window: per ogni offset o, prova size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = i 16 byte successivi; esegui la decrittazione RC4 e verifica che i campi stringa siano decodificabili come UTF-8 e che le lunghezze siano plausibili.
- Analizza i profili SMB/TCP seguendo le stesse convenzioni con lunghezza prefissata.

## Profili listener personalizzati: non codificare in modo rigido solo lo schema HTTP classico

Il formato di packing esterno (`u32 size | RC4 ciphertext | 16-byte key`) è riutilizzabile, quindi i listener personalizzati dagli attori possono mantenere lo stesso workflow di estrazione cambiando completamente il layout dei campi decrittati.

Un buon esempio recente è la campagna Tropic Trooper del marzo 2026, in cui il beacon Adaptix estratto non conteneva un profilo HTTP/TCP standard. Il blob decrittato conteneva invece parametri di trasporto GitHub, come:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (ad esempio `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Strategia pratica per il parser:
- Per prima cosa, rileva il blob RC4 esterno esattamente come al solito.
- Dopo la decrittazione, scegli il parser in base a stringhe sentinella e alla plausibilità dei campi, invece di applicare subito il parser HTTP.
- Tra le buone sentinelle ci sono `api.github.com`, `/issues?state=open`, verbi/URI HTTP, stringhe in stile named pipe o array di server/porte chiaramente validi.
- Se il parser HTTP fallisce ma il plaintext contiene stringhe UTF-8 coerenti precedute dalla lunghezza, conserva il campione e prova schemi alternativi invece di scartarlo come falso positivo.

In quella campagna, il listener personalizzato usava GitHub issues come trasporto C2 e il beacon interrogava `ipinfo.io` per ottenere l’IP esterno, perché la GitHub API non rivela direttamente all’operatore l’indirizzo sorgente della vittima.<sup>[[5]](#references)</sup>

## Fingerprinting di rete e hunting

HTTP:<sup>[[1]](#references)</sup>
- Comune: POST verso URI scelti dall’operatore (ad es. /uri.php, /endpoint/api)
- Parametro header personalizzato usato per il beacon ID (ad es. X‑Beacon‑Id, X‑App‑Id)
- User-agent che imitano Firefox 20 o versioni contemporanee di Chrome
- Cadenza di polling visibile tramite sleep_delay/jitter_delay
- Le build più recenti possono ruotare URI, user-agent, header Host e server tra i callback; quindi, per il clustering, basati su nomi di header insoliti, pattern delle dimensioni delle risposte, riutilizzo TLS e tempistiche, anziché presumere una singola coppia path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener SMB named pipe per C2 intranet, quando l’uscita web è limitata
- I beacon TCP possono anteporre alcuni byte al traffico per offuscare l’inizio del protocollo

Impostazioni predefinite attuali del teamserver upstream
- Attualmente `profile.yaml` include teamserver `0.0.0.0:4321`, endpoint `/endpoint`, nomi dei file certificato/chiave `server.rsa.crt` e `server.rsa.key`, ed extender per HTTP, SMB, TCP, DNS, Beacon agent e Gopher.<sup>[[2]](#references)</sup>
- Per le route non corrispondenti, il gestore di errore predefinito restituisce `Server: AdaptixC2` e `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Il body 404 standard contiene `AdaptixC2 404` e `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Le scansioni su scala Internet del 2026 hanno rilevato molti teamserver esposti sulla porta `4321` e molti listener beacon sulla porta `43211`; entrambe le porte sono quindi utili come punti di partenza, ma non vanno considerate esaustive.<sup>[[4]](#references)</sup>

Fingerprint dei listener DNS/DoH:<sup>[[4]](#references)</sup>
- L’attuale extender BeaconDNS risponde in modo autorevole (`AA=true`)
- Le query che non corrispondono alla struttura prevista dal protocollo beacon — in particolare i nomi con meno di 5 label prima del dominio configurato — ricevono spesso una risposta `TXT "OK"`
- Se il TTL di base configurato è zero, il listener usa un valore di base di 10 secondi e aggiunge fino a 59 secondi di jitter
- Questo rende utili le probe attive con label brevi quando non è esposto alcun listener HTTP

## TTP di loader e persistenza osservate negli incidenti

Loader PowerShell in memoria:<sup>[[1]](#references)</sup>
- Scaricano payload Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allocano memoria unmanaged, copiano la shellcode e impostano la protezione su 0x40 (PAGE_EXECUTE_READWRITE) tramite VirtualProtect.<sup>[[7]](#references)</sup>
- Eseguono tramite invocazione dinamica .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software firmato trojanizzato / loader di shellcode a fasi:<sup>[[5]](#references)</sup>
- Una catena Tropic Trooper del 2026 ha usato un eseguibile SumatraPDF trojanizzato (loader TOSHIS) che reindirizzava `_security_init_cookie` verso codice malevolo anziché modificare l’entry point PE
- Il loader risolveva le API tramite hashing Adler-32, scaricava un PDF esca, recuperava la shellcode del secondo stadio, la decrittava con AES-128-CBC tramite WinCrypt (`CryptDeriveKey` a partire da un seed hardcoded) ed eseguiva in memoria, tramite reflective loading, un beacon Adaptix
- In seguito, la persistenza è stata affidata a task pianificati con nomi dall’aspetto innocuo, come `\MSDNSvc` o `\MicrosoftUDN`, configurati per riavviare l’agent all’incirca ogni due ore

Consulta queste pagine per informazioni sull’esecuzione in memoria e sulle considerazioni relative ad AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Meccanismi di persistenza osservati:<sup>[[1]](#references)</sup>
- Collegamento (.lnk) nella cartella Startup per riavviare un loader all’accesso
- Chiavi Run del registro (HKCU/HKLM ...\CurrentVersion\Run), spesso con nomi dall’aspetto innocuo come "Updater" per avviare loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack tramite rilascio di msimg32.dll in %APPDATA%\Microsoft\Windows\Templates per i processi vulnerabili

Approfondimenti tecnici e verifiche:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Spunti per l’hunting
- Transizioni RW→RX avviate da PowerShell: VirtualProtect su PAGE_EXECUTE_READWRITE all’interno di powershell.exe.<sup>[[8]](#references)</sup>
- Pattern di invocazione dinamica (GetDelegateForFunctionPointer)
- Risposte 404 HTTPS a route non corrispondenti con `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` o `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Risposte DNS con `AA=true` e `TXT "OK"` a query brevi sotto domini sospetti.<sup>[[4]](#references)</sup>
- Traffico GitHub API verso `/repos/<owner>/<repo>/issues` seguito da lookup a `ipinfo.io` nella stessa catena loader/beacon.<sup>[[5]](#references)</sup>
- File .lnk in Startup, nella cartella utente o in quella comune.<sup>[[1]](#references)</sup>
- Chiavi Run sospette (ad es. "Updater") e nomi di loader come update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Campioni PE trojanizzati che reindirizzano `_security_init_cookie` verso codice downloader prima di mostrare un documento esca.<sup>[[5]](#references)</sup>
- Percorsi DLL scrivibili dall’utente sotto %APPDATA%\Microsoft\Windows\Templates contenenti msimg32.dll.<sup>[[1]](#references)</sup>

## Note sui campi OpSec

- KillDate: timestamp dopo il quale l’agent si disattiva automaticamente.<sup>[[1]](#references)</sup>
- WorkingTime: orari in cui l’agent dovrebbe essere attivo per confondersi con l’attività aziendale.<sup>[[1]](#references)</sup>

Questi campi possono essere usati per il clustering e per spiegare i periodi di inattività osservati.

## YARA e indicatori statici

Unit 42 ha pubblicato regole YARA di base per beacon (C/C++ e Go) e costanti per l’API hashing dei loader.<sup>[[1]](#references)</sup> Valuta di affiancarle a regole che cercano il layout [size|ciphertext|16-byte-key] vicino alla fine della sezione PE .rdata, le stringhe del profilo HTTP predefinito e indicatori più recenti di server/listener, come `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` e `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: un nuovo framework open source utilizzato in attacchi reali (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Documentazione di Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: fingerprinting su larga scala di un framework C2 open source (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper passa ad AdaptixC2 e a un listener Beacon personalizzato (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Documentazione Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Documentazione Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Costanti di protezione della memoria – Documentazione Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Chiavi Run del registro/cartella Startup](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Generazione dei profili AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser del profilo beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Generazione del profilo DNS AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Packing del profilo AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
