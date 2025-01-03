# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Questi sono i servizi macOS comuni per accedervi da remoto.\
Puoi abilitare/disabilitare questi servizi in `System Settings` --> `Sharing`

- **VNC**, conosciuto come “Screen Sharing” (tcp:5900)
- **SSH**, chiamato “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), o “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, conosciuto come “Remote Apple Event” (tcp:3031)

Controlla se qualcuno è abilitato eseguendo:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) è una versione avanzata di [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) progettata per macOS, che offre funzionalità aggiuntive. Una vulnerabilità notevole in ARD è il suo metodo di autenticazione per la password dello schermo di controllo, che utilizza solo i primi 8 caratteri della password, rendendola soggetta a [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con strumenti come Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), poiché non ci sono limiti di velocità predefiniti.

Le istanze vulnerabili possono essere identificate utilizzando lo script `vnc-info` di **nmap**. I servizi che supportano `VNC Authentication (2)` sono particolarmente suscettibili agli attacchi di forza bruta a causa della troncatura della password a 8 caratteri.

Per abilitare ARD per vari compiti amministrativi come l'escalation dei privilegi, l'accesso GUI o il monitoraggio degli utenti, utilizzare il seguente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornisce livelli di controllo versatili, inclusi osservazione, controllo condiviso e controllo completo, con sessioni che persistono anche dopo le modifiche della password dell'utente. Consente di inviare comandi Unix direttamente, eseguendoli come root per gli utenti amministrativi. La pianificazione dei compiti e la ricerca remota di Spotlight sono caratteristiche notevoli, che facilitano ricerche remote a basso impatto per file sensibili su più macchine.

## Protocollo Bonjour

Bonjour, una tecnologia progettata da Apple, consente **ai dispositivi sulla stessa rete di rilevare i servizi offerti l'uno dall'altro**. Conosciuto anche come Rendezvous, **Zero Configuration** o Zeroconf, consente a un dispositivo di unirsi a una rete TCP/IP, **scegliere automaticamente un indirizzo IP** e trasmettere i propri servizi ad altri dispositivi di rete.

La Rete Zero Configuration, fornita da Bonjour, garantisce che i dispositivi possano:

- **Ottenere automaticamente un indirizzo IP** anche in assenza di un server DHCP.
- Eseguire **la traduzione nome-indirizzo** senza richiedere un server DNS.
- **Scoprire i servizi** disponibili sulla rete.

I dispositivi che utilizzano Bonjour si assegneranno un **indirizzo IP dall'intervallo 169.254/16** e verificheranno la sua unicità sulla rete. I Mac mantengono un'entrata nella tabella di routing per questa subnet, verificabile tramite `netstat -rn | grep 169`.

Per DNS, Bonjour utilizza il **protocollo Multicast DNS (mDNS)**. mDNS opera su **porta 5353/UDP**, impiegando **query DNS standard** ma mirate all'**indirizzo multicast 224.0.0.251**. Questo approccio garantisce che tutti i dispositivi in ascolto sulla rete possano ricevere e rispondere alle query, facilitando l'aggiornamento dei loro record.

All'unirsi alla rete, ogni dispositivo seleziona autonomamente un nome, che di solito termina in **.local**, il quale può derivare dal nome host o essere generato casualmente.

La scoperta dei servizi all'interno della rete è facilitata da **DNS Service Discovery (DNS-SD)**. Sfruttando il formato dei record DNS SRV, DNS-SD utilizza **record DNS PTR** per abilitare l'elenco di più servizi. Un client che cerca un servizio specifico richiederà un record PTR per `<Service>.<Domain>`, ricevendo in cambio un elenco di record PTR formattati come `<Instance>.<Service>.<Domain>` se il servizio è disponibile da più host.

L'utilità `dns-sd` può essere impiegata per **scoprire e pubblicizzare i servizi di rete**. Ecco alcuni esempi del suo utilizzo:

### Ricerca di Servizi SSH

Per cercare servizi SSH sulla rete, viene utilizzato il seguente comando:
```bash
dns-sd -B _ssh._tcp
```
Questo comando avvia la ricerca dei servizi \_ssh.\_tcp e restituisce dettagli come timestamp, flag, interfaccia, dominio, tipo di servizio e nome dell'istanza.

### Pubblicizzare un Servizio HTTP

Per pubblicizzare un servizio HTTP, puoi usare:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Questo comando registra un servizio HTTP chiamato "Index" sulla porta 80 con un percorso di `/index.html`.

Per cercare i servizi HTTP sulla rete:
```bash
dns-sd -B _http._tcp
```
Quando un servizio si avvia, annuncia la sua disponibilità a tutti i dispositivi sulla subnet multicasting la sua presenza. I dispositivi interessati a questi servizi non devono inviare richieste, ma semplicemente ascoltare questi annunci.

Per un'interfaccia più user-friendly, l'app **Discovery - DNS-SD Browser** disponibile su Apple App Store può visualizzare i servizi offerti sulla tua rete locale.

In alternativa, possono essere scritti script personalizzati per navigare e scoprire servizi utilizzando la libreria `python-zeroconf`. Lo script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) dimostra come creare un browser di servizi per i servizi `_http._tcp.local.`, stampando i servizi aggiunti o rimossi:
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
### Disabilitare Bonjour

Se ci sono preoccupazioni riguardo alla sicurezza o altre ragioni per disabilitare Bonjour, può essere disattivato utilizzando il seguente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Riferimenti

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
