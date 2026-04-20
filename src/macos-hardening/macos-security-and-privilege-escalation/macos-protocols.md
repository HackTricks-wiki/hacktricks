# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Questi sono i comuni servizi macOS per accedervi da remoto.\
Puoi abilitare/disabilitare questi servizi in `System Settings` --> `Sharing`

- **VNC**, noto come “Screen Sharing” (tcp:5900)
- **SSH**, chiamato “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), oppure “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, noto come “Remote Apple Event” (tcp:3031)

Controlla se qualcuno è abilitato eseguendo:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Enumerare la configurazione di condivisione localmente

Quando hai già esecuzione di codice locale su un Mac, **controlla lo stato configurato**, non solo i socket in ascolto. `systemsetup` e `launchctl` di solito ti dicono se il servizio è abilitato a livello amministrativo, mentre `kickstart` e `system_profiler` aiutano a confermare la configurazione ARD/Sharing effettiva:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) è una versione migliorata di [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adattata per macOS, che offre funzionalità aggiuntive. Una vulnerabilità notevole in ARD è il suo metodo di autenticazione per la password di controllo schermo, che usa solo i primi 8 caratteri della password, rendendolo vulnerabile ad attacchi di [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con strumenti come Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), poiché non ci sono limiti di rate predefiniti.

Le istanze vulnerabili possono essere identificate usando lo script `vnc-info` di **nmap**. I servizi che supportano `VNC Authentication (2)` sono particolarmente suscettibili ad attacchi di brute force a causa della troncatura della password a 8 caratteri.

Per abilitare ARD per varie attività amministrative come privilege escalation, accesso GUI o monitoraggio utente, usa il seguente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornisce livelli di controllo versatili, tra cui observation, shared control e full control, con sessioni che persistono anche dopo i cambi di password dell'utente. Consente di inviare direttamente comandi Unix, eseguirli come root per gli utenti amministrativi. La pianificazione dei task e Remote Spotlight search sono funzionalità notevoli, che facilitano ricerche remote a basso impatto di file sensibili su più macchine.

Dal punto di vista dell'operatore, **Monterey 12.1+ changed remote-enablement workflows** nelle fleet gestite. Se controlli già l'MDM della vittima, il comando `EnableRemoteDesktop` di Apple è spesso il modo più pulito per attivare la funzionalità di remote desktop sui sistemi più recenti. Se hai già un foothold sull'host, `kickstart` è ancora utile per ispezionare o riconfigurare i privilegi ARD dalla command line.

### Pentesting Remote Apple Events (RAE / EPPC)

Apple chiama questa funzionalità **Remote Application Scripting** nelle System Settings moderne. Sotto il cofano espone il **Apple Event Manager** in remoto tramite **EPPC** su **TCP/3031** attraverso il servizio `com.apple.AEServer`. Palo Alto Unit 42 lo ha evidenziato di nuovo come una pratica primitive di **macOS lateral movement** perché credenziali valide più un servizio RAE abilitato consentono a un operatore di controllare applicazioni scriptabili su un Mac remoto.

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Se hai già admin/root sul target e vuoi abilitarlo:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Test di connettività di base da un altro Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
In pratica, il caso di abuso non è limitato a Finder. Qualsiasi **scriptable application** che accetta i richiesti Apple events diventa una superficie di attacco remota, il che rende RAE particolarmente interessante dopo il furto di credenziali nelle reti macOS interne.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Il rendering errato della sessione poteva causare la trasmissione del desktop o della finestra *sbagliata*, con conseguente leak di informazioni sensibili|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Un utente con accesso allo screen sharing potrebbe riuscire a visualizzare lo **schermo di un altro utente** a causa di un problema di state-management|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disabilita *Screen Sharing*/*Remote Management* quando non è strettamente necessario.
* Mantieni macOS completamente aggiornato (Apple in genere distribuisce fix di sicurezza per le ultime tre release major).
* Usa una **Strong Password** *e* applica, quando possibile, l’opzione *“VNC viewers may control screen with password”* **disabilitata**.
* Metti il servizio dietro una VPN invece di esporre TCP 5900/3283 a Internet.
* Aggiungi una regola di Application Firewall per limitare `ARDAgent` alla subnet locale:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour, una tecnologia progettata da Apple, consente ai **devices sulla stessa network di rilevare i servizi offerti dagli altri**. Conosciuta anche come Rendezvous, **Zero Configuration**, o Zeroconf, permette a un device di unirsi a una rete TCP/IP, **scegliere automaticamente un indirizzo IP**, e trasmettere i propri servizi agli altri network devices.

Zero Configuration Networking, fornito da Bonjour, garantisce che i devices possano:

- **Ottenere automaticamente un IP Address** anche in assenza di un server DHCP.
- Eseguire la **traduzione da nome a indirizzo** senza richiedere un server DNS.
- **Scoprire i servizi** disponibili sulla network.

I devices che usano Bonjour si assegnano un **indirizzo IP dall'intervallo 169.254/16** e ne verificano l'unicità sulla network. I Mac mantengono una voce nella routing table per questa subnet, verificabile con `netstat -rn | grep 169`.

Per DNS, Bonjour utilizza il **Multicast DNS (mDNS) protocol**. mDNS opera sulla **porta 5353/UDP**, usando **standard DNS queries** ma indirizzandole all'**indirizzo multicast 224.0.0.251**. Questo approccio garantisce che tutti i devices in ascolto sulla network possano ricevere e rispondere alle query, facilitando l'aggiornamento dei loro records.

Una volta entrato nella network, ogni device seleziona autonomamente un nome, in genere terminante con **.local**, che può derivare dall'hostname o essere generato casualmente.

Il service discovery all'interno della network è facilitato da **DNS Service Discovery (DNS-SD)**. Sfruttando il formato dei DNS SRV records, DNS-SD usa **DNS PTR records** per consentire l'elenco di più servizi. Un client che cerca un servizio specifico richiederà un PTR record per `<Service>.<Domain>`, ricevendo in risposta un elenco di PTR records formattati come `<Instance>.<Service>.<Domain>` se il servizio è disponibile su più host.

L'utility `dns-sd` può essere usata per **discovering and advertising network services**. Ecco alcuni esempi del suo utilizzo:

### Searching for SSH Services

Per cercare servizi SSH sulla network, si usa il seguente comando:
```bash
dns-sd -B _ssh._tcp
```
Questo comando avvia la ricerca di servizi \_ssh.\_tcp e produce dettagli come timestamp, flags, interface, domain, service type e instance name.

### Advertising an HTTP Service

Per pubblicizzare un servizio HTTP, puoi usare:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Questo comando registra un servizio HTTP chiamato "Index" sulla porta 80 con un percorso di `/index.html`.

Per poi cercare servizi HTTP sulla rete:
```bash
dns-sd -B _http._tcp
```
Quando un servizio si avvia, annuncia la propria disponibilità a tutti i dispositivi sulla subnet multicasting la propria presenza. I dispositivi interessati a questi servizi non devono inviare richieste ma semplicemente ascoltare questi annunci.

Per un'interfaccia più user-friendly, l'app **Discovery - DNS-SD Browser** disponibile su Apple App Store può visualizzare i servizi offerti sulla tua rete locale.

In alternativa, si possono scrivere script personalizzati per esplorare e scoprire servizi usando la libreria `python-zeroconf`. Lo script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) dimostra come creare un service browser per servizi `_http._tcp.local.`, stampando i servizi aggiunti o rimossi:
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
### Hunting Bonjour specifico per macOS

Sulle reti macOS, Bonjour è spesso il modo più semplice per trovare **surface di amministrazione remota** senza toccare direttamente il target. Apple Remote Desktop stesso può scoprire i client tramite Bonjour, quindi gli stessi dati di discovery sono utili per un attacker.
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
Per tecniche più ampie di **mDNS spoofing, impersonation e cross-subnet discovery**, consulta la pagina dedicata:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerare Bonjour sulla rete

* **Nmap NSE** – scopri i servizi annunciati da un singolo host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Lo script `dns-service-discovery` invia una query `_services._dns-sd._udp.local` e poi enumera ogni tipo di servizio annunciato.

* **mdns_recon** – tool Python che analizza interi range cercando responder mDNS *misconfigured* che rispondono a query unicast (utile per trovare dispositivi raggiungibili attraverso subnet/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Questo restituirà gli host che espongono SSH tramite Bonjour fuori dal link locale.

### Considerazioni di sicurezza e vulnerabilità recenti (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Un errore logico in *mDNSResponder* permetteva a un pacchetto costruito ad arte di attivare un **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Un problema di correttezza in *mDNSResponder* poteva essere abusato per **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Linee guida di mitigazione**

1. Limita UDP 5353 allo scope *link-local* – bloccandolo o applicando rate-limit su controller wireless, router e firewall host-based.
2. Disabilita completamente Bonjour sui sistemi che non richiedono service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Per gli ambienti in cui Bonjour è necessario internamente ma non deve mai attraversare i confini di rete, usa restrizioni del profilo *AirPlay Receiver* (MDM) oppure un proxy mDNS.
4. Abilita **System Integrity Protection (SIP)** e mantieni macOS aggiornato – entrambe le vulnerabilità sopra sono state patchate rapidamente, ma per una protezione completa facevano affidamento sul fatto che SIP fosse abilitato.

### Disabilitare Bonjour

Se ci sono preoccupazioni di sicurezza o altri motivi per disabilitare Bonjour, può essere disattivato usando il seguente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
