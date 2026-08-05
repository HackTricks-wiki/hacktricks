# Servizi e protocolli di rete di macOS

{{#include ../../banners/hacktricks-training.md}}

## Servizi di accesso remoto

Questi sono i servizi comuni di macOS per accedervi da remoto.\
Puoi abilitare/disabilitare questi servizi in `Impostazioni di Sistema` --> `Condivisione`

- **VNC**, noto come “Screen Sharing” (tcp:5900)
- **SSH**, chiamato “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), o “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, noto come “Remote Apple Event” (tcp:3031)

Verifica se qualcuno è abilitato eseguendo:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerare la configurazione della condivisione localmente

Quando hai già l'esecuzione di codice locale su un Mac, **controlla lo stato configurato**, non solo i socket in ascolto. `systemsetup` e `launchctl` generalmente indicano se il servizio è abilitato amministrativamente, mentre `kickstart` e `system_profiler` aiutano a confermare la configurazione effettiva di ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) è una versione avanzata di [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adattata a macOS, che offre funzionalità aggiuntive. Una vulnerabilità rilevante di ARD riguarda il metodo di autenticazione per la password della schermata di controllo, che utilizza solo i primi 8 caratteri della password, rendendolo vulnerabile a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con strumenti come Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), poiché non esistono rate limits predefiniti.<sup>[[3]](#references)</sup>

Le istanze vulnerabili possono essere identificate utilizzando lo script `vnc-info` di **nmap**. I servizi che supportano `VNC Authentication (2)` sono particolarmente suscettibili agli attacchi brute force a causa del troncamento della password a 8 caratteri.

Per abilitare ARD per varie attività amministrative, come privilege escalation, accesso alla GUI o monitoraggio degli utenti, utilizza il comando seguente:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD offre livelli di controllo versatili, tra cui osservazione, controllo condiviso e controllo completo, con sessioni che persistono anche dopo la modifica della password dell'utente. Consente di inviare direttamente comandi Unix ed eseguirli come root per gli utenti amministrativi. La pianificazione delle attività e la ricerca Remote Spotlight sono funzionalità degne di nota, poiché facilitano ricerche remote e a basso impatto di file sensibili su più macchine.

Dal punto di vista dell'operatore, **Monterey 12.1+ ha modificato i workflow di abilitazione remota** nelle flotte gestite. Se controlli già l'MDM della vittima, il comando `EnableRemoteDesktop` di Apple è spesso il modo più pulito per attivare la funzionalità di desktop remoto sui sistemi più recenti. Se disponi già di un foothold sull'host, `kickstart` è ancora utile per ispezionare o riconfigurare i privilegi ARD dalla command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Recenti ricerche su `screensharingd` hanno mostrato che Apple Screen Sharing non utilizza sempre la classica autenticazione VNC: le build più recenti parlano **RFB `003.889`** e pubblicizzano **security type `36`**, in cui **SRP** esegue prima l'autenticazione e **ChaCha20-Poly1305** viene installato solo dopo il successo di `ccsrp_server_verify_session`. Il write-up pubblico riporta che il bug è stato corretto in **macOS Tahoe 26.6** (**27 luglio 2026**).<sup>[[8]](#references)[[9]](#references)</sup>

Un pattern utile da ricordare è il **bypass dello stale-status parser**: dopo una lettura della lunghezza di 4 byte eseguita correttamente, ogni branch di errore o di dimensione eccessiva deve restituire un errore nuovo. Nelle build interessate, una lunghezza del frame SRP in big-endian **`>= 32768`** fa sì che il percorso di rifiuto riutilizzi il precedente successo di `NetBufferRead` (`0`), quindi il chiamante imposta la sessione come autenticata anche se non è stata eseguita alcuna password proof e non è stata installata alcuna crittografia di trasporto. Poiché i byte non letti rimangono nel buffer socket condiviso, un attacker può **inviare tramite pipeline dati SRP malformati e messaggi RFB post-auth nello stesso burst TCP** e farli analizzare come **traffico autenticato in chiaro**.<sup>[[8]](#references)</sup>

Dopo il bypass, il messaggio proprietario di Apple per il **file-copy**, **`0x22`**, diventa una **primitiva di lettura/scrittura di file come root** perché `screensharingd` viene eseguito come root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: lettura arbitraria di file
- `kind=2` / `StartFileReceive`: scrittura arbitraria di file
- Valori `sid` differenti consentono di mettere in pipeline diverse transazioni in una singola connessione
- In `kind=101` (`NewItem`), imposta il byte `14` / `arg[0]` su `0x01` per un file normale, l'offset del payload `+42` su una dimensione del file big-endian **non zero**, e l'offset del payload `+0x5a` sulla modalità Unix desiderata (`0600` se si prende di mira un crontab)

Interessanti pivot post-write sui path scrivibili includono **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** e **`/var/root/.ssh/authorized_keys`**. **SIP non blocca l'auth bypass né la lettura dei file come root**, ma blocca alcuni target di scrittura come **`/var/at`**, quindi l'esecuzione basata su cron funziona solo con SIP disabilitato. Sugli host predefiniti con SIP abilitato, è meglio ragionare in termini di **"scrittura di file come root in file privilegiati consumati automaticamente"** piuttosto che di esecuzione immediata del codice.<sup>[[8]](#references)</sup>

Un'altra insidia SRP emersa dalla stessa ricerca: i server devono validare **`A mod N != 0`** (secondo RFC 5054), non solo **`A > 0`**. Accettare **`A = N`** può forzare il segreto condiviso a zero e compromettere la verifica della password.<sup>[[8]](#references)[[10]](#references)</sup>

**Idee per il rilevamento**

- Sessioni di tipo Security `36` in cui la lunghezza del primo frame SRP è **`>= 32768`**
- Sessioni che iniziano a elaborare traffico di file-copy in testo in chiaro **`0x22`** prima di qualsiasi prova SRP riuscita / installazione del cipher
- Retry ripetuti e di breve durata verso **TCP/5900**, insieme a più valori `sid` di file-copy in un singolo burst
- Creazione imprevista di **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** o **`/var/root/.ssh/authorized_keys`** dopo l'esposizione di Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple chiama questa funzionalità **Remote Application Scripting** nelle moderne Impostazioni di Sistema. Sotto il cofano, espone remotamente l'**Apple Event Manager** tramite **EPPC** sulla **TCP/3031**, attraverso il servizio `com.apple.AEServer`. Palo Alto Unit 42 l'ha nuovamente evidenziata come una primitiva pratica di **macOS lateral movement**, poiché credenziali valide e un servizio RAE abilitato consentono a un operatore di controllare applicazioni scriptabili su un Mac remoto.<sup>[[6]](#references)</sup>

Controlli utili:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Se disponi già di privilegi admin/root sul target e vuoi abilitarlo:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Test di connettività di base da un altro Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In pratica, il caso di abuso non è limitato a Finder. Qualsiasi **scriptable application** che accetti gli Apple events richiesti diventa una superficie d'attacco remota, rendendo RAE particolarmente interessante dopo il furto di credenziali sulle reti macOS interne.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Un rendering errato della sessione poteva causare la trasmissione del desktop o della finestra *sbagliati*, con conseguente leak di informazioni sensibili|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un utente con accesso alla condivisione dello schermo poteva riuscire a visualizzare **lo schermo di un altro utente** a causa di un problema nella gestione dello stato|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Suggerimenti per l'hardening**

* Disabilitare *Screen Sharing*/*Remote Management* quando non sono strettamente necessari.
* Mantenere macOS completamente aggiornato (in genere Apple distribuisce security fix per le ultime tre major release).
* Utilizzare una **Strong Password** e, quando possibile, mantenere disabilitata l'opzione *“VNC viewers may control screen with password”*.
* Posizionare il servizio dietro una VPN invece di esporre TCP 5900/3283 su Internet.
* Aggiungere una regola di Application Firewall per limitare `ARDAgent` alla subnet locale:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Protocollo Bonjour

Bonjour, una tecnologia progettata da Apple, consente ai **dispositivi sulla stessa rete di rilevare i servizi offerti dagli altri dispositivi**. Conosciuto anche come Rendezvous, **Zero Configuration** o Zeroconf, consente a un dispositivo di unirsi a una rete TCP/IP, **scegliere automaticamente un indirizzo IP** e trasmettere i propri servizi agli altri dispositivi di rete.

Il Zero Configuration Networking, fornito da Bonjour, garantisce che i dispositivi possano:

- **Ottenere automaticamente un indirizzo IP** anche in assenza di un server DHCP.
- Eseguire la **traduzione da nome a indirizzo** senza richiedere un server DNS.
- **Rilevare i servizi** disponibili sulla rete.

I dispositivi che utilizzano Bonjour si assegneranno un **indirizzo IP nell'intervallo 169.254/16** e ne verificheranno l'univocità sulla rete. I Mac mantengono una voce nella tabella di routing per questa subnet, verificabile tramite `netstat -rn | grep 169`.

Per il DNS, Bonjour utilizza il **protocollo Multicast DNS (mDNS)**. mDNS opera sulla **porta 5353/UDP**, utilizzando **query DNS standard** ma indirizzandole all'**indirizzo multicast 224.0.0.251**. Questo approccio garantisce che tutti i dispositivi in ascolto sulla rete possano ricevere e rispondere alle query, facilitando l'aggiornamento dei relativi record.

Quando entra nella rete, ogni dispositivo seleziona autonomamente un nome, che in genere termina con **.local** e può essere derivato dall'hostname o generato casualmente.

La discovery dei servizi all'interno della rete è facilitata da **DNS Service Discovery (DNS-SD)**. Sfruttando il formato dei record DNS SRV, DNS-SD utilizza i **record DNS PTR** per consentire l'elencazione di più servizi. Un client che cerca un servizio specifico richiederà un record PTR per `<Service>.<Domain>` e riceverà in risposta un elenco di record PTR formattati come `<Instance>.<Service>.<Domain>` se il servizio è disponibile su più host.

L'utility `dns-sd` può essere utilizzata per **rilevare e pubblicizzare servizi di rete**. Di seguito sono riportati alcuni esempi del suo utilizzo:

### Ricerca di SSH Services

Per cercare SSH Services sulla rete, si utilizza il seguente comando:
```bash
dns-sd -B _ssh._tcp
```
Questo comando avvia la ricerca di servizi \_ssh.\_tcp e restituisce dettagli come timestamp, flag, interfaccia, dominio, tipo di servizio e nome dell'istanza.

### Pubblicizzare un servizio HTTP

Per pubblicizzare un servizio HTTP, puoi usare:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Questo comando registra un servizio HTTP denominato "Index" sulla porta 80 con un percorso `/index.html`.

Per cercare quindi i servizi HTTP sulla rete:
```bash
dns-sd -B _http._tcp
```
Quando un servizio si avvia, annuncia la propria disponibilità a tutti i dispositivi della sottorete trasmettendo in multicast la propria presenza. I dispositivi interessati a questi servizi non devono inviare richieste, ma semplicemente ascoltare questi annunci.

Per un'interfaccia più intuitiva, l'app **Discovery - DNS-SD Browser**, disponibile sull'Apple App Store, può visualizzare i servizi offerti sulla rete locale.

In alternativa, è possibile scrivere script personalizzati per sfogliare e individuare i servizi utilizzando la libreria `python-zeroconf`. Lo script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) mostra come creare un service browser per i servizi `_http._tcp.local.`, stampando i servizi aggiunti o rimossi:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Ricerca di Bonjour specifica per macOS

Nelle reti macOS, Bonjour è spesso il modo più semplice per trovare **superfici di amministrazione remota** senza interagire direttamente con il target. Apple Remote Desktop può individuare i client tramite Bonjour, quindi gli stessi dati di discovery sono utili a un attacker.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Per tecniche più ampie di **mDNS spoofing, impersonation e discovery tra subnet**, consulta la pagina dedicata:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerazione di Bonjour sulla rete

* **Nmap NSE** – individua i servizi pubblicizzati da un singolo host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Lo script `dns-service-discovery` invia una query `_services._dns-sd._udp.local` e quindi enumera ogni tipo di servizio pubblicizzato.

* **mdns_recon** – tool Python che analizza interi intervalli alla ricerca di responder mDNS *misconfigured* che rispondono a query unicast (utile per trovare dispositivi raggiungibili tra subnet/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Questo comando restituisce gli host che espongono SSH tramite Bonjour al di fuori del link locale.

### Considerazioni sulla sicurezza e vulnerabilità recenti (2024-2025)

| Anno | CVE | Gravità | Problema | Patch disponibile in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Media|Un errore logico in *mDNSResponder* consentiva a un pacchetto appositamente creato di causare un **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (settembre 2024) |
|2025|CVE-2025-31222|Alta|Un problema di correttezza in *mDNSResponder* poteva essere sfruttato per una **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (maggio 2025) |

**Indicazioni per la mitigazione**

1. Limita UDP 5353 all'ambito *link-local* – bloccalo o applica un rate limit su controller wireless, router e firewall basati sull'host.
2. Disabilita completamente Bonjour sui sistemi che non richiedono la service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Negli ambienti in cui Bonjour è richiesto internamente, ma non deve mai oltrepassare i confini della rete, utilizza le restrizioni del profilo *AirPlay Receiver* (MDM) o un proxy mDNS.
4. Abilita **System Integrity Protection (SIP)** e mantieni macOS aggiornato – entrambe le vulnerabilità sopra indicate sono state corrette rapidamente, ma per una protezione completa richiedevano che SIP fosse abilitato.

### Disabilitare Bonjour

Se sussistono problemi di sicurezza o altri motivi per disabilitare Bonjour, è possibile disattivarlo utilizzando il seguente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Riferimenti

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analisi - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Movimento laterale su macOS: tecniche uniche e popolari ed esempi reali](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Informazioni sul contenuto di sicurezza di macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Informazioni sul contenuto di sicurezza di macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Utilizzo del protocollo Secure Remote Password (SRP) per l'autenticazione TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
