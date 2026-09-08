# Accesso fisico e wireless covert

Per un'implementazione dettagliata e approvata dal proprietario, che includa rendezvous outbound, recupero dell'alimentazione/uplink, segreti minimi conservati sul dispositivo, capture testing e monitoraggio di possibili scoperte, vedere [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Cambiare il percorso di rete può anche modificare l'origine fisica apparente. Un actor sofisticato può utilizzare un sistema compromesso nelle vicinanze, un dispositivo nascosto, un accesso pubblico, un backhaul cellulare o un ricevitore satellitare, in modo che i log del target indichino un'origine diversa da quella dell'operator. Nessuna di queste opzioni elimina le evidenze fisiche, radio o del provider; sposta l'attribuzione in dataset differenti.

## Matrice delle tecniche

| Tecnica | Origine apparente | Condizione necessaria | Evidenza di alto valore |
|---|---|---|---|
| Pivot wireless nelle vicinanze | un'azienda o un'abitazione accanto al target | host dual-homed compromesso e accesso al Wi-Fi del target | log endpoint dell'host vicino, associazione RF e RADIUS/DHCP del target |
| Rete pubblica/guest | NAT del locale o tunnel exit | accesso legittimo o bypass del controllo degli accessi | captive portal, DHCP, associazione AP, CCTV e record di pagamento/localizzazione |
| Dispositivo covert drop | indirizzo cablato, Wi-Fi o cellulare del target o nelle vicinanze | posizionamento fisico o consegna | switchport/USB, RF, inventario, alimentazione e telemetria del tunnel outbound |
| Router cellulare/eSIM | NAT dell'operatore o APN dedicato | modem/SIM/abbonamento | IMEI/IMSI/eSIM, settore cellulare, account dell'operatore e tempistiche del traffico |
| Abuso del satellite link | indirizzo dell'abbonato nell'area di copertura del beam | debolezza specifica del protocollo e del servizio | localizzazione RF, flusso uplink, RTT/routing impossibili e record del provider |

## Nearest-neighbor attack

Volexity ha documentato un'operazione APT28/GRU del 2022 in cui l'actor era remoto rispetto al target finale. Ha eseguito password spraying sul public service del target per ottenere credenziali valide, ma l'MFA impediva il login diretto da Internet. Il Wi-Fi aziendale del target accettava quelle credenziali senza MFA. L'actor ha compromesso organizzazioni fisicamente vicine al target, ha trovato un sistema dual-homed con portata wireless e ha utilizzato quel sistema per autenticarsi al Wi-Fi del target. Volexity ha denominato questa tecnica **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
La novità sta nella composizione. Nessun operatore si reca presso il target e l'MFA del servizio esposto su Internet continua a funzionare. Il vicino compromesso fornisce la prossimità fisica; la credenziale del target sottratta fornisce l'accesso logico; il Wi-Fi del target diventa il percorso per attraversare il confine.

### Prerequisiti e visibilità

- Un sistema nelle vicinanze deve poter essere controllato da remoto e disporre di una radio compatibile o dell'accesso a un altro pivot nelle vicinanze.
- L'SSID del target deve raggiungere quel sistema e l'ammissione al Wi-Fi deve accettare una credenziale/certificato/stato del dispositivo riutilizzabile.
- Il pivot spesso necessita di due percorsi simultanei: uno verso l'operatore e uno verso la WLAN del target.
- Il target potrebbe rilevare un nuovo MAC della station e un nome utente legittimo, ma nessun certificato di managed device, dato relativo al posture, cronologia o accesso previsto all'edificio corrispondente.
- I log dell'endpoint del vicino potrebbero mostrare scansioni wireless, nuovi profili, modifiche alle interfacce, tunneling e attività di remote control.

### Rilevamento e prevenzione

1. Richiedere EAP-TLS basato su certificati e posture del managed device per il Wi-Fi aziendale; non considerare sufficiente una password che ha fallito l'MFA su Internet solo perché arriva via radio.
2. Correlare l'autenticazione RADIUS con l'identità MDM/NAC, il precedente binding station/device, la posizione dell'AP, gli eventi di accesso fisico e le sessioni simultanee.
3. Generare un alert quando un account si associa per la prima volta, da un bordo AP insolito, senza un certificato gestito o mentre la stessa identità è attiva altrove.
4. Monitorare gli endpoint in grado di fare bridging delle interfacce. Su Windows, Linux e network appliance, analizzare profili WLAN imprevisti, configurazioni di forwarding/NAT, adattatori virtuali e tunnel persistenti.
5. Ridurre la dispersione non necessaria del segnale con un posizionamento sensato degli AP e una pianificazione della potenza. Questo è un controllo di supporto, non un sistema di autenticazione.
6. Coordinare la risposta agli incidenti con i tenant vicini: la sorgente radio finale potrebbe essere essa stessa una vittima.

Il [lab con due organizzazioni di proprietà](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) riproduce questi elementi osservabili senza attaccare un vicino.

## Locali pubblici e Wi-Fi di terze parti

L'utilizzo del Wi-Fi di un bar, hotel, aeroporto o ente municipale modifica l'IP mostrato a una destinazione. Non crea anonimato. Il locale o il suo provider potrebbero conservare l'associazione all'AP, il MAC del dispositivo, il lease DHCP, l'account del captive portal, la validazione tramite SMS/email e i flow log. L'ingresso fisico, le CCTV, gli acquisti, la posizione del dispositivo mobile e i dati di viaggio possono collegare l'evento digitale a una persona.

Un attore potrebbe tentare di ridurre un elemento identificativo utilizzando MAC randomizzati, un dispositivo separato, contanti o un tunnel. La correlazione tra livelli rimane possibile tramite l'orario di arrivo, gli schemi ripetuti di presenza nel locale, le impronte radio, il comportamento del portal, la tempistica del traffico, le riprese delle telecamere e il provider del tunnel. Una VPN sposta inoltre la destinazione dai log del locale ai log della VPN; non elimina la consapevolezza del locale che il dispositivo era presente.

I difensori degli accessi pubblici dovrebbero isolare i client, bloccare il traffico laterale, utilizzare WPA2/3-Enterprise o chiavi per-device ove possibile, conservare log DHCP/RADIUS/security proporzionati, proteggere i captive portal e pubblicare una procedura per gli abusi. I red team dovrebbero utilizzare un simile locale solo quando i suoi termini e l'engagement lo consentono; aggirare un portal, sottrarre l'accesso o prendere di mira altri ospiti non è una scorciatoia autorizzata per i test.

## Dispositivi drop covert e warshipping

Un drop è un piccolo sistema collocato o introdotto in un sito, quindi controllato tramite Ethernet, Wi-Fi o rete cellulare in uscita. Il “warshipping” confeziona il dispositivo in modo che una normale consegna lo porti all'interno del perimetro radio. L'hardware possibile va da un single-board computer a un caricatore modificato, una periferica USB, un network appliance o un modem alimentato a batteria.

Architettura operativa:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Il dispositivo può fornire un foothold remoto, eseguire misurazioni wireless, emulare una periferica autorizzata per un’esercitazione oppure inoltrare il traffico. La sua origine apparente è locale, ma crea tracce fisiche: numeri di serie, imballaggi, impronte digitali, telecamere, log di accesso, consumo energetico, descrittori USB, negoziazione della switchport, fingerprint DHCP, comportamento dell’OUI/randomizzazione MAC, emissioni RF e connessioni ricorrenti di rendezvous.

### Controlli difensivi

- Mantenere procedure per il locale di ricezione e l’inventario degli asset; ispezionare dispositivi elettronici e pacchi inattesi indirizzati a dipendenti inesistenti.
- Usare 802.1X/NAC per l’accesso cablato e wireless, disabilitare le porte inutilizzate e collocare i dispositivi sconosciuti in una VLAN di remediation con restrizioni.
- Generare alert per nuovi fingerprint DHCP, MAC amministrati localmente che persistono, nuovi dispositivi USB di rete/HID, Wi-Fi Direct/Bluetooth non autorizzati e tunnel in uscita di lunga durata.
- Creare una baseline del comportamento della switchport, del power-over-Ethernet, del DNS e del TLS. Un host minuscolo senza una voce nell’inventario che effettua connessioni cifrate periodiche è un segnale più rilevante del solo “Raspberry Pi OUI”.
- Durante un’esercitazione, inventariare, etichettare, definire lo scope, cifrare, fornire un remote kill, stabilire una scadenza per il recupero e garantire che lo smarrimento non possa esporre credenziali riutilizzabili.

## Backhaul cellulare ed eSIM

Un modem cellulare evita il gateway Internet del target e può mantenere un drop raggiungibile dietro il NAT dell’operatore tramite un rendezvous in uscita. Gli indirizzi mobili possono ruotare o essere condivisi; tuttavia, l’operatore cellulare dispone di solide evidenze relative all’abbonato e alla rete: identità della SIM/eSIM, IMSI, IMEI del dispositivo, indirizzi/porte assegnati, temporizzazione della cella/settore, dati dell’account e dei pagamenti e record di roaming.

Dal punto di vista dell’azienda, rilevare modem inattesi e hotspot personali tramite survey wireless/RF, inventario USB/PCI degli endpoint, restrizioni MDM, monitoraggio degli SSID rogue e ispezione fisica. Un drop che utilizza la rete cellulare per il controllo può comunque essere individuato dal suo comportamento Ethernet/Wi-Fi locale e dalle sue emissioni radio.

Per le esercitazioni autorizzate, l’organizzazione dovrebbe essere proprietaria dell’abbonamento e del modem, registrare gli identificatori presso il controller e verificare che i termini dell’operatore/provider consentano il traffico. Un’etichetta prepaid o un acquisto in cryptocurrency non cancellano i record delle torri cellulari, dei dispositivi o dei rivenditori.

## Randomizzazione MAC e device fingerprinting

I sistemi moderni possono usare un MAC randomizzato e amministrato localmente per ogni rete. Ciò riduce il tracking passivo a lungo termine tramite un MAC di fabbrica stabile; non nasconde:

- la temporizzazione di probe/associazione e l’insieme delle funzionalità di rete richieste;
- gli information element 802.11, le velocità supportate e il comportamento specifico del vendor;
- le opzioni/hostname DHCP, gli identificatori IPv6 e il fingerprint del captive portal/browser;
- l’identità o il certificato autenticati tramite 802.1X;
- l’account a un livello superiore, il tunnel e il pattern del traffico; oppure
- l’osservazione fisica.

I difensori non dovrebbero usare allowlist MAC come autenticazione. Collegare l’identità radio al certificato e alla postura del dispositivo e considerare normali i MAC variabili, salvo che altro contesto risulti anomalo.

## Hijacking del collegamento satellitare

Kaspersky ha documentato l’uso, da parte di Turla, delle debolezze presenti nei sistemi meno recenti di Internet satellitare DVB-S unidirezionale. Nel modello riportato, un abbonato remoto legittimo inviava le richieste in uscita tramite un collegamento terrestre, ma riceveva i dati downstream tramite una trasmissione satellitare wide-area non cifrata. Un attore all’interno dell’area coperta dal satellite poteva osservare il downlink, scegliere l’IP di un abbonato attivo e fare in modo che le risposte C2 fossero indirizzate a quell’IP. Sia l’abbonato legittimo sia l’attore ricevevano la trasmissione; l’attore estraeva il traffico destinato alla porta selezionata, mentre l’abbonato legittimo scartava i pacchetti non sollecitati. L’operatore C2 sembrava quindi utilizzare un indirizzo del provider satellitare in un’altra area geografica.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Questo era specifico del protocollo/servizio, soggetto a limitazioni di banda e non equivalente alla compromissione di un moderno terminale satellitare bidirezionale cifrato. Inoltre, non nascondeva il percorso delle richieste in uscita dell'attore a un osservatore sufficientemente capace. Le opportunità di rilevamento includono routing asimmetrico/impossibile, traffico verso un subscriber che non aveva avviato il flusso, porte di destinazione insolite, telemetria del provider, indagini sulla posizione del ricevitore/RF e configurazione del malware. Usa questo caso per mettere in discussione l'assunto che geolocalizzare un IP C2 significhi geolocalizzare il suo controller, non come ricetta per la realizzazione.

## Scheda di correlazione da fisico a digitale

Quando una sorgente apparentemente locale è sospetta, crea una singola timeline:

1. normalizza gli orologi di AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controllo degli accessi fisici;
2. identifica la prima associazione radio o il primo link-up, non solo il primo alert;
3. associa la station al certificato, al device posture, al fingerprint DHCP e alla posizione dello switch/AP;
4. cerca attività simultanee di remote-control/tunnel sui sistemi vicini;
5. esamina consegne, visitatori, eccezioni nell'inventario, telecamere e rilevamenti RF secondo le policy/leggi applicabili;
6. conserva il device sospetto e lo stato volatile della rete; non spegnerlo forzatamente alla cieca;
7. determina se la sorgente apparente è un'infrastruttura controllata dall'attore o un'altra vittima.

## References

- [1] [Volexity — L'attacco Nearest Neighbor: come un gruppo APT russo ha arm weaponized le reti Wi-Fi vicine](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla satellitare: command and control APT nel cielo](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Aggiunte hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Linee guida per la protezione delle reti locali wireless](https://csrc.nist.gov/pubs/sp/800/153/final)
