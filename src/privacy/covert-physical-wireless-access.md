# Accesso fisico e wireless covert

{{#include ../banners/hacktricks-training.md}}

Per un'implementazione dettagliata e approvata dal proprietario, che includa rendezvous in uscita, ripristino dell'alimentazione/uplink, segreti minimi conservati sul dispositivo, test di cattura e monitoraggio per una possibile scoperta, vedere [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

La modifica del percorso di rete può cambiare anche l'origine fisica apparente. Un attore sofisticato può utilizzare un sistema compromesso nelle vicinanze, un dispositivo nascosto, un accesso pubblico, un backhaul cellulare o un ricevitore satellitare, in modo che i log del target indichino un'origine diversa da quella dell'operatore. Nessuna di queste opzioni elimina le prove fisiche, radio o del provider; sposta l'attribuzione in dataset differenti.

## Matrice delle tecniche

| Tecnica | Origine apparente | Condizione necessaria | Prove di grande valore |
|---|---|---|---|
| Nearby wireless pivot | un'azienda/abitazione accanto al target | host dual-homed compromesso e accesso al Wi-Fi del target | log dell'endpoint dell'host vicino, associazione RF e RADIUS/DHCP del target |
| Public/guest network | NAT del luogo o uscita del tunnel | accesso legittimo o bypass del controllo degli accessi | captive portal, DHCP, associazione all'AP, CCTV e dati di pagamento/localizzazione |
| Covert drop device | indirizzo cablato, Wi-Fi o cellulare del target/vicino | posizionamento fisico o consegna | switchport/USB, RF, inventario, alimentazione e telemetria del tunnel in uscita |
| Cellular router/eSIM | NAT dell'operatore o APN dedicato | modem/SIM/abbonamento | IMEI/IMSI/eSIM, settore cellulare, account dell'operatore e temporizzazione del traffico |
| Satellite-link abuse | indirizzo dell'abbonato nell'area di copertura | debolezza specifica del protocollo e del servizio | localizzazione RF, flusso uplink, RTT/routing impossibili e registri del provider |

## Nearest-neighbor attack

Volexity ha documentato un'operazione APT28/GRU del 2022 in cui l'attore si trovava lontano dal target finale. Eseguì un password spraying contro il servizio pubblico del target per ottenere credenziali valide, ma l'MFA impediva il login diretto da Internet. Il Wi-Fi aziendale del target accettava quelle credenziali senza MFA. L'attore comprometteva organizzazioni fisicamente vicine al target, individuava un sistema dual-homed con portata wireless e utilizzava quel sistema per autenticarsi al Wi-Fi del target. Volexity ha denominato questa tecnica **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
La novità sta nella combinazione. Nessun operatore raggiunge il target e l’MFA del servizio esposto su Internet continua a funzionare. Il vicino compromesso fornisce la prossimità fisica; la credenziale del target sottratta fornisce l’accesso logico; il Wi-Fi del target diventa il percorso per attraversare il confine.

### Prerequisiti e visibilità

- Un sistema nelle vicinanze deve essere controllabile da remoto e disporre di una radio compatibile o dell’accesso a un altro pivot nelle vicinanze.
- L’SSID del target deve raggiungere quel sistema e l’ammissione al Wi-Fi deve accettare una credenziale, un certificato o uno stato del dispositivo riutilizzabile.
- Il pivot spesso necessita di due percorsi simultanei: uno verso l’operatore e uno verso la WLAN del target.
- Il target può rilevare un nuovo MAC della station e uno username legittimo, ma nessun certificato del dispositivo gestito, stato di sicurezza, cronologia o ingresso previsto nell’edificio corrispondente.
- I log dell’endpoint del vicino possono mostrare scansioni wireless, nuovi profili, modifiche alle interfacce, tunneling e attività di controllo remoto.

### Rilevamento e prevenzione

1. Richiedere EAP-TLS basato su certificati e lo stato di sicurezza del dispositivo gestito per il Wi-Fi aziendale; non considerare sufficiente una password che ha superato l’MFA su Internet solo perché arriva via radio.
2. Correlare l’autenticazione RADIUS con l’identità MDM/NAC, il binding storico station/dispositivo, la posizione dell’AP, gli eventi di accesso fisico e le sessioni simultanee.
3. Generare un alert quando un account si associa per la prima volta, da un bordo AP insolito, senza un certificato gestito o mentre la stessa identità è attiva altrove.
4. Monitorare gli endpoint in grado di fare bridging delle interfacce. Su Windows, Linux e network appliance, analizzare profili WLAN inattesi, configurazioni di forwarding/NAT, adattatori virtuali e tunnel persistenti.
5. Ridurre la dispersione non necessaria del segnale con un posizionamento sensato degli AP e una pianificazione della potenza. Si tratta di un controllo di supporto, non di autenticazione.
6. Coordinare l’incident response con gli occupanti degli edifici vicini: la fonte radio finale potrebbe essere essa stessa una vittima.

Il [laboratorio controllato tra due organizzazioni](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) riproduce questi indicatori senza attaccare un vicino.

## Luoghi pubblici e Wi-Fi di terze parti

Usare il Wi-Fi di un bar, hotel, aeroporto o ente municipale modifica l’IP mostrato a una destinazione. Non crea anonimato. Il gestore del luogo o il suo provider possono conservare l’associazione all’AP, il MAC del dispositivo, il lease DHCP, l’account del captive portal, la convalida tramite SMS/email e i log dei flussi. L’ingresso fisico, le telecamere CCTV, gli acquisti, la posizione del telefono e i dati di viaggio possono collegare l’evento digitale a una persona.

Un attore può tentare di ridurre un singolo elemento identificativo usando indirizzi MAC randomizzati, un dispositivo separato, contanti o un tunnel. La correlazione tra livelli rimane possibile tramite l’orario di arrivo, il pattern di frequentazione del luogo, le impronte radio, il comportamento del portal, la temporizzazione del traffico, le riprese delle telecamere e il provider del tunnel. Una VPN sposta inoltre la destinazione dai log del luogo ai log della VPN; non elimina la consapevolezza del luogo che il dispositivo era presente.

I responsabili degli accessi pubblici dovrebbero isolare i client, bloccare il traffico laterale, usare WPA2/3-Enterprise o chiavi per dispositivo ove possibile, conservare log proporzionati DHCP/RADIUS/security, proteggere i captive portal e pubblicare una procedura per gli abusi. I Red team dovrebbero usare un luogo di questo tipo solo quando i suoi termini e l’engagement lo consentono; aggirare un portal, rubare l’accesso o prendere di mira altri ospiti non è una scorciatoia autorizzata per il testing.

## Dispositivi drop occultati e warshipping

Un drop è un piccolo sistema collocato o consegnato all’interno di un sito, poi controllato tramite Ethernet, Wi-Fi o rete cellulare in uscita. Il “warshipping” confeziona il dispositivo in modo che una normale consegna lo porti all’interno del perimetro radio. L’hardware possibile va da un single-board computer a un caricatore modificato, una periferica USB, un network appliance o un modem alimentato a batteria.

Architettura operativa:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Il dispositivo può fornire un foothold remoto, eseguire misurazioni wireless, emulare una periferica autorizzata per un’esercitazione o inoltrare il traffico. La sua origine apparente è locale, ma crea artefatti fisici: numeri di serie, imballaggi, impronte digitali, telecamere, log degli accessi, consumo energetico, descrittori USB, negoziazione della switchport, fingerprint DHCP, comportamento dell’OUI/randomizzazione del MAC, emissioni RF e connessioni ricorrenti di rendezvous.

### Controlli difensivi

- Mantenere procedure per il locale di ricezione e l’inventario degli asset; ispezionare componenti elettronici e pacchi inattesi indirizzati a dipendenti inesistenti.
- Usare 802.1X/NAC per l’accesso cablato e wireless, disabilitare le porte inutilizzate e collocare i dispositivi sconosciuti in una VLAN di remediation limitata.
- Generare alert per nuovi fingerprint DHCP, MAC amministrati localmente che persistono, nuovi dispositivi USB di rete/HID, Wi-Fi Direct/Bluetooth non autorizzati e tunnel outbound di lunga durata.
- Creare una baseline del comportamento di switchport, power-over-Ethernet, DNS e TLS. Un host di piccole dimensioni senza un record nell’inventario che effettua connessioni crittografate periodiche è un segnale più significativo del solo “Raspberry Pi OUI”.
- Durante un’esercitazione, inventariare, etichettare, definire lo scope, crittografare, fornire un kill remoto, impostare una scadenza per il recupero e assicurarsi che lo smarrimento non possa esporre credenziali riutilizzabili.

## Cellular eSIM backhaul

Un modem cellulare evita il gateway Internet del target e può mantenere un drop raggiungibile dietro il carrier NAT tramite un rendezvous outbound. Gli indirizzi mobili possono ruotare o essere condivisi; l’operatore cellulare dispone comunque di solide evidenze sull’abbonato e sulla rete: identità della SIM/eSIM, IMSI, indirizzi/porte assegnati, tempistiche della cella/settore, dati dell’account e dei pagamenti e record di roaming.

Dal punto di vista dell’azienda, rilevare modem imprevisti e hotspot personali tramite survey wireless/RF, inventario USB/PCI degli endpoint, restrizioni MDM, monitoraggio degli SSID rogue e ispezioni fisiche. Un drop che usa la rete cellulare per il controllo può comunque essere rilevato dal suo comportamento Ethernet/Wi-Fi locale e dalle sue emissioni radio.

Per le esercitazioni autorizzate, l’organizzazione dovrebbe essere proprietaria dell’abbonamento e del modem, registrare gli identificativi presso il controller e verificare che i termini del carrier/provider consentano il traffico. Un’etichetta prepagata o un acquisto in cryptocurrency non cancellano i record delle torri cellulari, del dispositivo o del punto vendita.

## MAC randomization e device fingerprinting

I sistemi moderni possono usare un MAC randomizzato amministrato localmente per ogni rete. Ciò riduce il tracciamento passivo a lungo termine tramite un MAC di fabbrica stabile; non nasconde:

- la tempistica di probe/associazione e l’insieme delle funzionalità di rete richieste;
- gli information element 802.11, i rate supportati e il comportamento specifico del vendor;
- le opzioni/hostname DHCP, gli identificatori IPv6 e il fingerprint del captive portal/browser;
- l’identità 802.1X autenticata o il certificato;
- l’account di livello superiore, il tunnel e il pattern del traffico; oppure
- l’osservazione fisica.

I difensori non dovrebbero usare allowlist MAC come autenticazione. Collegare l’identità radio al certificato e alla postura del dispositivo e considerare normali i MAC variabili, salvo che altro contesto risulti anomalo.

## Satellite-link hijacking

Kaspersky ha documentato l’uso da parte di Turla di vulnerabilità presenti nei vecchi servizi Internet satellitari DVB-S unidirezionali. Nel modello riportato, un abbonato remoto legittimo inviava le richieste outbound tramite un collegamento terrestre, ma riceveva i dati downstream attraverso una trasmissione satellitare wide-area non crittografata. Un attore all’interno dell’area coperta dal satellite poteva osservare il downlink, scegliere l’IP di un abbonato attivo e fare in modo che le risposte C2 fossero indirizzate a quell’IP. Sia l’abbonato legittimo sia l’attore ricevevano la trasmissione; l’attore estraeva il traffico destinato alla porta selezionata, mentre l’abbonato legittimo scartava i pacchetti non richiesti. L’operatore C2 sembrava quindi utilizzare un indirizzo del provider satellitare situato in un’altra area geografica.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Questo era specifico del protocollo/servizio, vincolato dalla larghezza di banda e non equivalente alla compromissione di un moderno terminale satellitare bidirezionale crittografato. Inoltre, non nascondeva il percorso delle richieste in uscita dell'attore a un osservatore sufficientemente capace. Le opportunità di rilevamento includono routing asimmetrico/impossibile, traffico verso un subscriber che non aveva avviato il flusso, porte di destinazione insolite, telemetria del provider, analisi della posizione del ricevitore/RF e configurazione del malware. Usa questo caso per mettere in discussione l'assunzione secondo cui geolocalizzare un IP C2 significhi geolocalizzare il suo controller, non come ricetta per la realizzazione.

## Foglio di lavoro per la correlazione fisico-digitale

Quando una source apparentemente locale è sospetta, crea una singola timeline:

1. normalizza gli orologi di AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controllo degli accessi fisici;
2. identifica la prima associazione radio o il primo link-up, non soltanto il primo alert;
3. associa la station al certificato, al device posture, al fingerprint DHCP e alla posizione dello switch/AP;
4. cerca attività simultanee di remote-control/tunnel sui sistemi nelle vicinanze;
5. esamina consegne, visitatori, anomalie dell'inventario, telecamere e risultati RF in conformità con la policy/legge applicabile;
6. metti in sicurezza il device sospetto e lo stato volatile della rete; non spegnerlo forzatamente senza criterio;
7. determina se la source apparente è un'infrastruttura controllata dall'attore o un'altra vittima.

## References

- [1] [Volexity — L'attacco Nearest Neighbor: come un APT russo ha weaponized le reti Wi-Fi vicine](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla satellitare: command and control di un APT nel cielo](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Aggiunte hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Linee guida per la protezione delle reti locali wireless](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
