# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipi di payload di Intruder

Burp Intruder include i seguenti generatori e trasformazioni di payload integrati:<sup>[[1]](#references)</sup>

- **Simple list:** Usa un elenco configurato di stringhe come payload.
- **Runtime file:** Legge un payload per riga durante l'esecuzione. È utile per gli elenchi di grandi dimensioni, perché Burp non carica l'intero file in memoria.
- **Case modification:** Genera il valore invariato, le forme minuscole e maiuscole, `Propername` (prima lettera maiuscola e il resto minuscolo) oppure `ProperName` (prima lettera maiuscola e i caratteri rimanenti invariati). Burp elimina i risultati duplicati.
- **Numbers:** Genera numeri sequenziali o casuali all'interno di un intervallo configurato.
- **Brute forcer:** Genera tutte le permutazioni per un set di caratteri e una lunghezza minima/massima scelti.

## Estensioni e strumenti complementari

- **Collabfiltrator** genera payload che eseguono comandi ed esfiltrano l'output tramite query DNS verso Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** esporta i risultati di Burp per usarli in altri flussi di lavoro di reporting.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converte le richieste HTTP in script in diversi linguaggi.<sup>[[4]](#references)</sup>

## Test di autorizzazione multi-sessione con Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) è un'estensione Java per Burp Suite `2025.5+` che archivia cookie e header insoliti in profili di credenziali con nome. Selezionando un profilo in un editor di richieste modificabile, incluso Repeater o una richiesta Proxy intercettata, i dati di autenticazione della richiesta vengono sostituiti. È uno strumento per ripetere le richieste, **non un authorization bypass**: usalo per inviare la stessa richiesta con account diversi quando verifichi l'accesso orizzontale, i limiti dei ruoli verticali, l'isolamento dei tenant e [IDOR/BOLA](../pentesting-web/idor.md) nell'ambito della [metodologia di test web](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Flusso di lavoro ripetibile per il confronto delle identità

Il flusso di lavoro seguente mantiene la risorsa/azione e l'identità dell'utente come variabili di test separate, riducendo i falsi risultati dovuti a token scaduti o alla sessione browser errata.<sup>[[5]](#references)[[8]](#references)</sup>

1. Autentica gli account di test che rappresentano ciascun utente, ruolo e tenant rilevante in profili browser o container separati.
2. Apri una richiesta contenente i cookie e gli header di una delle identità, seleziona **Sessions > New** e assegna al profilo un nome univoco, come `tenant-a-user` o `tenant-b-admin`. Ripeti l'operazione per ogni identità di test.
3. Invia una richiesta candidata a Repeater e ripetila senza modificare metodo, endpoint, parametri o identificativo dell'oggetto, cambiando solo la sessione selezionata. Confronta i dati della risposta e le modifiche di stato osservabili, non solo i codici di stato.
4. Per i controlli a livello di oggetto, ripeti una richiesta per un oggetto che appartiene sicuramente all'account A selezionando il profilo dell'account B. Per i controlli a livello di funzione, ripeti la stessa azione privilegiata con profili dotati di privilegi inferiori.
5. Dopo una nuova autenticazione o la rotazione dei token, usa **Update** su una richiesta browser corrente oppure configura una regola Auto Update prima di ripetere il confronto.

### Semantica di acquisizione e inserimento

Esamina le modalità di aggiornamento/inserimento prima dei test: una richiesta ibrida contenente credenziali di due identità può invalidare il confronto. Le impostazioni predefinite correnti copiano tutti i cookie della richiesta in un profilo, aggiornano solo gli header insoliti già archiviati, copiano i cookie del profilo selezionato nella richiesta di destinazione (rimuovendone i cookie esistenti) e aggiungono gli header del profilo. Il selettore può essere limitato a un sottodominio esatto, al dominio dell'applicazione di primo livello (impostazione predefinita) oppure a tutti i profili salvati.<sup>[[7]](#references)</sup>

- **Mirror** è utile quando l'intero set di cookie definisce un'identità e occorre rimuovere i cookie di destinazione scaduti.
- **Update existing** segue i valori che ruotano senza acquisire cookie o header non correlati dal traffico del browser.
- **Add all** mantiene i valori aggiuntivi già archiviati nel profilo o nella richiesta; verifica che non rimangano dati associati all'identità della sessione precedente.
- **Do nothing** esclude cookie o header dagli aggiornamenti del profilo quando quella classe di credenziali non è rilevante.

### Sincronizzazione delle sessioni tramite Proxy

Le regole Auto Update associano il traffico Proxy a un profilo salvato e ne aggiornano cookie/header. Preferisci un criterio stabile, come un header di richiesta dedicato, un contrassegno `User-Agent` specifico del profilo, un cookie identificativo, `X-PwnFox-Color` o un claim JWT; combinalo con condizioni di ambito/dominio/percorso per impedire alle applicazioni non correlate di aggiornare il profilo. Tutte le condizioni in una regola vengono valutate in ordine con un `AND` logico, quindi inserisci prima i controlli più restrittivi; implementa `OR` creando più regole associate allo stesso profilo. È supportata anche la corrispondenza negativa.<sup>[[6]](#references)</sup>

Per ogni regola corrispondente, scegli **Mirror request**, **Add all**, **Update existing** o **Do nothing** separatamente per cookie e header. Le regole basate solo sulle richieste vengono eseguite quando Proxy riceve la richiesta; aggiungendo una condizione relativa allo stato, a un header o al corpo della risposta, la valutazione viene posticipata fino all'arrivo della risposta. È possibile assegnare un colore di evidenziazione al traffico corrispondente, utile per verificare che ogni identità browser aggiorni solo il profilo previsto.<sup>[[6]](#references)</sup>

I profili salvati risiedono nel progetto Burp e le esportazioni dei dati di progetto in JSON includono le sessioni, e quindi i relativi cookie e header. Considera entrambi i file come credenziali attive, limita l'accesso e cancella i dati dell'estensione salvati al termine dell'incarico.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Documentazione PortSwigger - Tipi di payload di Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Codice sorgente di Session Switcher e documentazione d'uso](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Regole Auto Update di Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Impostazioni di Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: semplificare i test di autorizzazione multi-sessione in Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
