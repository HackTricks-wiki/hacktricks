# Accesso fisico e wireless occulto

{{#include ../banners/hacktricks-training.md}}

Per un'implementazione dettagliata e autorizzata dal proprietario, che copra rendezvous in uscita, ripristino di alimentazione/uplink, segreti minimi conservati sul dispositivo, test di acquisizione e monitoraggio per individuare eventuali tentativi di scoperta, consulta [Nodi sul campo autorizzati resilienti all'acquisizione](capture-resilient-authorized-field-nodes.md).

Cambiare il percorso di rete può anche modificare l'origine fisica apparente. Un attore sofisticato può usare un sistema compromesso nelle vicinanze, un dispositivo nascosto, l'accesso pubblico, una connessione cellulare di backhaul o un ricevitore satellitare, facendo sì che i log del bersaglio indichino un luogo diverso da quello dell'operatore. Nessuna di queste opzioni elimina le prove fisiche, radio o del provider: sposta l'attribuzione in dataset differenti.

## Matrice delle tecniche

| Tecnica | Origine apparente | Condizione necessaria | Prove di alto valore |
|---|---|---|---|
| Pivot wireless nelle vicinanze | un'attività o un'abitazione accanto al bersaglio | host dual-homed compromesso e accesso al Wi-Fi del bersaglio | log endpoint dell'host vicino, associazione RF e RADIUS/DHCP del bersaglio |
| Rete pubblica/guest | NAT del locale o uscita del tunnel | accesso legittimo o aggiramento del controllo degli accessi | captive portal, DHCP, associazione all'AP, CCTV e dati di pagamento/localizzazione |
| Dispositivo di drop occulto | indirizzo cablato, Wi-Fi o cellulare del bersaglio o nelle vicinanze | installazione fisica o consegna | porta dello switch/USB, RF, inventario, alimentazione e telemetria del tunnel in uscita |
| Router cellulare/eSIM | NAT dell'operatore o APN dedicato | modem/SIM/abbonamento | IMEI/IMSI/eSIM, settore cellulare, account dell'operatore e tempistiche del traffico |
| Abuso del collegamento satellitare | indirizzo dell'abbonato nell'area di copertura | debolezza specifica del protocollo e del servizio | localizzazione RF, flusso uplink, RTT/routing impossibili e registri del provider |

## Attacco Nearest Neighbor

Volexity ha documentato un'operazione APT28/GRU del 2022 in cui l'attore si trovava a distanza dal bersaglio finale. Ha effettuato password spraying contro il servizio pubblico del bersaglio per ottenere credenziali valide, ma l'MFA ha impedito l'accesso diretto da Internet. Il Wi-Fi aziendale del bersaglio accettava quelle credenziali senza MFA. L'attore ha compromesso organizzazioni fisicamente vicine al bersaglio, ha individuato un sistema dual-homed con copertura wireless e lo ha usato per autenticarsi al Wi-Fi del bersaglio. Volexity ha chiamato questa tecnica **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

La novità sta nella combinazione. Nessun operatore si reca presso il target e l’MFA del servizio esposto a Internet continua a funzionare. Il vicino compromesso fornisce la prossimità fisica; la credenziale rubata del target fornisce l’accesso logico; il Wi-Fi del target diventa il percorso per oltrepassare il confine.

### Prerequisiti e visibilità

- Un sistema nelle vicinanze deve poter essere controllato da remoto e avere una radio compatibile oppure accesso a un altro pivot vicino.
- L’SSID del target deve raggiungere quel sistema e l’accesso Wi-Fi deve accettare credenziali, certificati o stati del dispositivo riutilizzabili.
- Spesso il pivot necessita di due percorsi simultanei: uno verso l’operatore e uno verso la WLAN del target.
- Il target potrebbe rilevare un nuovo MAC della station e un nome utente legittimo, ma nessun certificato di dispositivo gestito, stato di conformità, cronologia o ingresso previsto nell’edificio corrispondente.
- I log degli endpoint del vicino potrebbero mostrare scansioni wireless, nuovi profili, modifiche alle interfacce, tunneling e attività di controllo remoto.

### Rilevamento e prevenzione

1. Richiedere EAP-TLS basato su certificati e lo stato di conformità dei dispositivi gestiti per il Wi-Fi aziendale; non considerare sufficiente una password che non ha superato l’MFA su Internet solo perché viene presentata via radio.
2. Correlare l’autenticazione RADIUS con identità MDM/NAC, associazioni storiche tra station e dispositivo, posizione dell’AP, eventi di accesso fisico e sessioni simultanee.
3. Generare un alert quando un account si associa per la prima volta, da un’area insolita dell’AP, senza un certificato gestito o mentre la stessa identità è attiva altrove.
4. Monitorare gli endpoint in grado di collegare le interfacce. Su Windows, Linux e appliance di rete, verificare la presenza di profili WLAN imprevisti, configurazioni di forwarding/NAT, adattatori virtuali e tunnel persistenti.
5. Ridurre la dispersione non necessaria del segnale con un posizionamento degli AP e una pianificazione della potenza adeguati. È una misura di supporto, non un metodo di autenticazione.
6. Coordinare la risposta agli incidenti con i tenant confinanti: la sorgente radio finale potrebbe essere a sua volta una vittima.

Il [lab controllato a due organizzazioni](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) riproduce questi elementi osservabili senza attaccare un vicino.

### Convalidare un percorso di pivot Windows

Un host Windows connesso a due reti non collega automaticamente le interfacce. Per prima cosa, inventariare gli adattatori, le route e lo stato WLAN, quindi associarsi solo tramite un profilo approvato. L’argomento `name` di `netsh wlan connect` identifica un profilo installato, non un SSID e una password qualsiasi. Confrontare la tabella di routing prima e dopo l’associazione, in modo che una nuova route predefinita non interrompa il percorso di controllo né invalidi il risultato. Proseguire con i [controlli successivi all’associazione](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) solo dopo aver confermato l’interfaccia e la route previste.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

L’artefatto dell’incidente pubblicato da Volexity mostra un’altra distinzione utile. Il codice C# incorporato apre la WLAN API, enumera le interfacce, legge da disco un XML EAP e chiama `WlanSetProfileEapXmlUserData` per un profilo denominato sulla prima interfaccia wireless. L’API imposta le credenziali utente EAP su un profilo 802.1X esistente, ma il componente pubblicato non contiene né `WlanConnect` né la logica di discovery descritta nel report. Consideralo come provisioning del profilo, non come un connettore completo, e ispeziona il profilo risultante nell’ambito della [valutazione di client e supplicant](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Luoghi pubblici e Wi-Fi di terze parti

Usare il Wi-Fi di un bar, hotel, aeroporto o comune cambia l’indirizzo IP mostrato al destinatario. Non garantisce l’anonimato. Il luogo o il suo provider potrebbero conservare i log delle associazioni all’AP, degli indirizzi MAC dei dispositivi, delle lease DHCP, degli account del captive portal, delle verifiche via SMS/email e dei flussi. I registri degli ingressi, le telecamere CCTV, gli acquisti, la localizzazione mobile e i viaggi possono collegare l’evento digitale a una persona.

Un attore potrebbe cercare di ridurre un elemento identificativo usando indirizzi MAC randomizzati, un dispositivo separato, contanti o un tunnel. La correlazione tra livelli resta possibile tramite orario di arrivo, schemi ricorrenti di frequentazione del luogo, fingerprint radio, comportamento sul portale, tempistiche del traffico, riprese delle telecamere e provider del tunnel. Anche una VPN sposta i log relativi alla destinazione dal luogo al provider VPN; non elimina la consapevolezza del luogo che il dispositivo fosse presente.

Chi gestisce l’accesso pubblico dovrebbe isolare i client, bloccare il traffico laterale, usare WPA2/3-Enterprise o chiavi per dispositivo ove possibile, conservare log proporzionati di DHCP/RADIUS/sicurezza, proteggere i captive portal e pubblicare una procedura per le segnalazioni di abuso. I red team dovrebbero usare un luogo simile solo se i suoi termini e l’ingaggio lo consentono; aggirare un portale, rubare l’accesso o prendere di mira altri ospiti non è una scorciatoia autorizzata per i test.

## Dispositivi drop covert e warshipping

Un drop è un piccolo sistema collocato o introdotto in un sito, quindi controllato tramite Ethernet in uscita, Wi-Fi o rete cellulare. Il “warshipping” confeziona il dispositivo in modo che una normale consegna lo porti all’interno del perimetro radio. L’hardware possibile va da un single-board computer a un caricatore modificato, una periferica USB, un apparato di rete o un modem alimentato a batteria.

Architettura operativa:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Il dispositivo può fornire un punto d’appoggio remoto, effettuare misurazioni wireless, emulare una periferica autorizzata per un’esercitazione o inoltrare traffico. La sua origine apparente è locale, ma crea tracce fisiche: numeri di serie, imballaggi, impronte digitali, telecamere, registri degli accessi, consumo energetico, descrittori USB, negoziazione della porta dello switch, fingerprint DHCP, comportamento dell’OUI MAC e della randomizzazione, emissioni RF e connessioni di rendezvous ricorrenti.

### Controlli difensivi

- Mantieni procedure per la ricezione dei pacchi e l’inventario degli asset; ispeziona dispositivi elettronici inattesi e pacchi indirizzati a dipendenti inesistenti.
- Usa 802.1X/NAC per gli accessi cablati e wireless, disabilita le porte inutilizzate e colloca i dispositivi sconosciuti in una VLAN di remediation con accesso limitato.
- Genera avvisi per nuovi fingerprint DHCP, MAC amministrati localmente che persistono, nuovi dispositivi USB di rete/HID, Wi-Fi Direct/Bluetooth non autorizzati e tunnel in uscita di lunga durata.
- Stabilisci una baseline per il comportamento delle porte dello switch, dell’alimentazione PoE, del DNS e di TLS. Un host di piccole dimensioni, privo di registrazione nell’inventario e che effettua connessioni cifrate periodiche, è un indicatore più significativo del solo «OUI Raspberry Pi».
- Durante un’esercitazione, fai l’inventario, etichetta, definisci l’ambito, cifra, predisponi un kill switch remoto, fissa una scadenza per il recupero e assicurati che un’eventuale perdita non esponga credenziali riutilizzabili.

## Backhaul cellulare ed eSIM

Un modem cellulare evita il gateway Internet del bersaglio e può mantenere un drop raggiungibile dietro il NAT dell’operatore tramite un rendezvous in uscita. Gli indirizzi mobili possono cambiare o essere condivisi; l’operatore cellulare conserva comunque prove dettagliate sull’abbonato e sulla rete: identità SIM/eSIM, IMSI, IMEI del dispositivo, indirizzi/porte assegnati, orari delle celle/settori, dati dell’account e di pagamento e registri di roaming.

Dal punto di vista dell’azienda, rileva modem e hotspot personali inattesi mediante rilevamenti wireless/RF, inventario USB/PCI degli endpoint, restrizioni MDM, monitoraggio degli SSID rogue e ispezioni fisiche. Un drop che usa la rete cellulare per il controllo può comunque essere individuato tramite il suo comportamento Ethernet/Wi-Fi locale e le sue emissioni radio.

Per le esercitazioni autorizzate, l’organizzazione dovrebbe possedere l’abbonamento e il modem, registrare gli identificatori insieme al controller e verificare che i termini dell’operatore/provider consentano il traffico. Un’etichetta prepagata o un acquisto in criptovaluta non cancellano i registri delle torri cellulari, dei dispositivi o dei rivenditori.

## Randomizzazione MAC e fingerprinting dei dispositivi

I sistemi moderni possono usare un MAC casuale amministrato localmente per ogni rete. Ciò riduce il tracciamento passivo a lungo termine tramite un MAC di fabbrica stabile; non nasconde:

- i tempi di probe/associazione e l’insieme delle funzionalità di rete richieste;
- gli elementi informativi 802.11, le velocità supportate e il comportamento specifico del vendor;
- le opzioni DHCP/il nome host, gli identificatori IPv6 e il fingerprint del browser/portale captive;
- l’identità o il certificato 802.1X autenticati;
- gli account di livello superiore, il tunnel e il pattern del traffico; oppure
- l’osservazione fisica.

I difensori non dovrebbero usare allowlist MAC come metodo di autenticazione. Associa l’identità radio al certificato e alla postura del dispositivo; considera normali i MAC variabili, salvo anomalie in altri elementi di contesto.

## Dirottamento del collegamento satellitare

Kaspersky ha documentato l’uso da parte di Turla di vulnerabilità presenti nei vecchi servizi Internet satellitari DVB-S unidirezionali. Nel modello descritto, un abbonato remoto legittimo inviava richieste in uscita tramite un collegamento terrestre, ma riceveva i dati in downstream attraverso una trasmissione satellitare non cifrata su vasta area. Un attore che si trovava nell’area coperta dal satellite poteva osservare il downlink, scegliere l’IP di un abbonato attivo e fare in modo che le risposte C2 fossero indirizzate a quell’IP. Sia l’abbonato legittimo sia l’attore ricevevano la trasmissione; l’attore estraeva il traffico destinato alla porta selezionata, mentre l’abbonato legittimo scartava i pacchetti non richiesti. L’operatore C2 sembrava così usare un indirizzo del provider satellitare situato in un’altra area geografica.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Questo era specifico del protocollo/servizio, limitato dalla larghezza di banda e non equivalente alla compromissione di un moderno terminale satellitare bidirezionale cifrato. Inoltre, non nascondeva il percorso delle richieste in uscita dell'attore a un osservatore sufficientemente capace. Le opportunità di rilevamento includono routing asimmetrico/impossibile, traffico verso un abbonato che non ha avviato la comunicazione, porte di destinazione insolite, telemetria del provider, indagini sulla posizione del ricevitore/RF e configurazione del malware. Usa questo caso per mettere in discussione l'assunto che la geolocalizzazione di un IP C2 individui geograficamente chi lo controlla, non come ricetta per realizzarlo.

## Scheda di correlazione tra fisico e digitale

Quando una sorgente apparentemente locale desta sospetti, crea un'unica timeline:

1. sincronizza gli orari di AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controllo degli accessi fisici;
2. identifica la prima associazione radio o attivazione del collegamento, non solo il primo alert;
3. associa la stazione a certificato, stato del dispositivo, fingerprint DHCP e posizione dello switch/AP;
4. cerca attività simultanee di controllo remoto/tunneling sui sistemi vicini;
5. esamina consegne, visitatori, anomalie di inventario, telecamere e rilevamenti RF nel rispetto delle normative e delle policy applicabili;
6. preserva il dispositivo sospetto e lo stato volatile della rete; non riavviare alla cieca;
7. determina se la sorgente apparente è un'infrastruttura controllata dall'attore o un'altra vittima.

## References

- [1] [Volexity — L'attacco del vicino più prossimo: come un APT russo ha armato le reti Wi-Fi vicine per ottenere accesso occulto](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: comando e controllo APT nel cielo](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Aggiunte hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Linee guida per la protezione delle reti locali wireless](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Codice WLAN PowerShell/C# oscurato](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — Funzione WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
