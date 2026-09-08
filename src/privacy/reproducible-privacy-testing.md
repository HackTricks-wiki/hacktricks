# Test di privacy riproducibili

Una configurazione della privacy non è completata quando si connette. È completata quando il suo confine dichiarato è stato testato durante l’uso normale, i malfunzionamenti, il ripristino e lo smantellamento. Esegui i test su infrastrutture di tua proprietà o che sei autorizzato a ispezionare; i siti pubblici di “leak test” diventano un altro osservatore.

## Crea un piccolo ambiente di test autorizzato

Usa tre ruoli, idealmente su provider/reti separati:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Registrare prima di ogni test:

- ID del test, inizio/fine in UTC, operatore e autorizzazione;
- versioni e configurazione di endpoint/OS/client, nonché l'hash della configurazione;
- osservazioni previste su IPv4, IPv6, DNS, TLS, account, pagamenti e aspetti fisici;
- quali log verranno esaminati e i relativi orologi/fusi orari;
- criterio di superamento/fallimento e orario di teardown.

Non testare mai per prima un'identità sensibile. Utilizzare un account sintetico e valori canary univoci e innocui di proprietà del tester.

## Test del percorso di rete

### 1. Acquisire la baseline

Prima di abilitare il percorso di privacy, registrare le route locali e i resolver:
```bash
ip route
ip -6 route
resolvectl status
```
Su macOS usa `route -n get default`, `netstat -rn -f inet6` e `scutil --dns`. Salva l'output solo nell'archivio controllato delle evidenze; può contenere identificatori locali.

### 2. Connettersi e ispezionare il routing

Abilita il namespace VPN/Tor/workload, quindi verifica la route selezionata per gli indirizzi pubblici controllati:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Sostituisci gli indirizzi della documentazione con gli indirizzi del server di test. Conferma che l'interfaccia/la tabella selezionata corrisponda al design.

### 3. Osserva da entrambe le estremità

Imposta l'URL dell'endpoint sotto il tuo controllo, quindi richiedi un percorso benigno univoco:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Usa un dominio reale controllato dal tester, TLS autenticato e un token non sensibile nel path. Controlla il log del server per verificare:

- indirizzo sorgente/ASN ed egress previsto;
- IPv4 rispetto a IPv6;
- comportamento di Host/SNI visibile all'endpoint;
- user agent e header dell'applicazione;
- ora esatta e riutilizzo della richiesta.

Non aggiungere `X-Forwarded-For`, header di debug univoci o cookie contenenti l'identità a una richiesta che dovrebbe essere separata.

### 4. Testa il DNS con un canary di proprietà

Configura una zona di test autorevole di cui controlli i log delle query. Esegui una query per un'etichetta casuale univoca attraverso il compartimento:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Ispeziona il log autorevole. Normalmente vede il recursive resolver, non necessariamente il client. Confronta quel resolver con il design DNS previsto per VPN/Tor/applicazione. Non è richiesto un random public DNS leak site.

### 5. Testare il comportamento fail-closed

Mantieni un loop di richieste benigno rivolto all'endpoint di proprietà, quindi interrompi il percorso privacy. Il workload deve fallire invece di passare a un'interfaccia fisica. Controlla entrambe le famiglie di indirizzi e il DNS:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Ripetere durante:

- arresto anomalo del processo tunnel;
- passaggio da Wi-Fi a Ethernet o all'hotspot;
- sospensione/riattivazione;
- rinnovo DHCP;
- stato del captive portal;
- riconnessione del provider/scadenza della chiave.

Per un namespace/container Linux, arrestare il relativo tunnel e verificare che non disponga di altre route predefinite o resolver:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
Nomi e comandi variano a seconda del deployment. Non incollarli in un host di produzione remoto senza possibilità di recupero tramite console.

### 6. Ispezionare socket e pacchetti locali

Con autorizzazione, verifica quale processo/interfaccia comunica effettivamente:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
Sostituisci `TEST_SERVER_IP` con l'indirizzo esplicito di tua proprietà; evita di acquisire indiscriminatamente dati di utenti non pertinenti. L'interfaccia fisica dovrebbe vedere il peer del tunnel/bridge, mentre il traffico con destinazione in chiaro dovrebbe esistere solo al livello previsto.

## Test di Tor e onion-service

1. In Tor Browser, visita il controllo della connessione del Tor Project e conferma l'uso di Tor. Non considerarlo una prova dell'identità.<sup>[[1]](#references)</sup>
2. Visita l'endpoint HTTPS di tua proprietà con un canary univoco e conferma che rilevi un'uscita Tor, nessun cookie identificativo e il contesto standard del browser.
3. Seleziona **New Identity**, visita nuovamente l'endpoint con un canary diverso e verifica che lo stato locale sia stato cancellato come previsto. Il cambio dell'IP di uscita non è garantito né rappresenta lo scopo di New Identity.
4. Per un onion service, accedervi esclusivamente tramite Tor Browser. Conferma che l'host del servizio non abbia listener pubblici con una scansione esterna autorizzata e che le risposte dell'applicazione non contengano hostname/IP pubblici.
5. Ispeziona DNS/HTTP outbound dell'origine, template, pagine di errore, email/webhook e asset di terze parti. Qualsiasi fetch diretto può divulgare l'origine o l'account dell'operatore.
6. Se è abilitata l'autorizzazione del client, conferma che un Tor Browser pulito e senza credenziali non possa connettersi e che uno con credenziali possa farlo.
7. Ruota una chiave di autorizzazione di test e conferma che il client revocato perda l'accesso senza modificare l'identità onion.

## Test del compartimento del browser

Crea una pagina controllata che registri solo i campi necessari per il test, con un breve periodo di conservazione. Confronta i compartimenti personali e quelli dedicati alla privacy per:

- cookie/local storage/service worker e cache;
- stato di sincronizzazione/accesso del browser;
- lingua, fuso orario, dimensioni dello schermo/finestra e font;
- candidati WebRTC/rete;
- permessi e modifiche visibili alle estensioni;
- dati user-agent TLS/HTTP lato server.

Non cercare di rendere Tor Browser “più casuale”. La condizione di superamento è la somiglianza con il suo anonymity set standard e l'assenza di stato personale, non la massima differenza rispetto al browser personale.

Testa copia/incolla, trascinamento, apertura dei file scaricati, suggerimenti del password manager e pulsanti dell'identity provider. Questi sono frequenti ponti tra i compartimenti.

## Test di isolamento del sistema operativo

### Tails

1. Inizia con un file/canary benigno in una sessione senza Persistent Storage.
2. Arresta completamente il sistema, riavvia e conferma che sia scomparso.
3. Abilita una sola categoria di persistenza necessaria, ripeti il test e conferma che lo stato non correlato del browser/dell'applicazione non venga conservato.
4. Verifica che Unsafe Browser non possa essere utilizzato dopo il login al portale per attività sensibili e che le applicazioni Tor si riconnettano normalmente.

### Whonix/Qubes

1. Arresta il qube Gateway/net e dimostra che il qube Workstation/app non possa raggiungere IPv4, IPv6 o DNS.
2. Tenta esclusivamente il percorso clipboard/file inter-qube configurato esplicitamente e conferma che gli altri percorsi di cartelle/dispositivi condivisi siano assenti.
3. Apri un documento di test benigno in un qube disposable, chiudilo e conferma che il suo stato scompaia.
4. Verifica che il qube vault non abbia un NetVM e non possa acquisirne uno tramite una modifica del template/default.
5. Esegui lo snapshot/restore di una VM di test e verifica se lo stato associato all'identità ritorna inaspettatamente.

## Test dei metadati delle comunicazioni

Per ogni messenger selezionato:

1. Crea partecipanti esclusivamente di test su dispositivi controllati.
2. Registra ciò che è richiesto per la registrazione: telefono, account dell'app store, IP, push service, username o invito.
3. Invia un solo messaggio benigno mentre ispezioni anteprime delle notifiche, desktop collegati, dispositivi wearable e backup.
4. Verifica i codici di sicurezza tramite un percorso indipendente.
5. Disabilita ricevute/push oppure abilita Tor/trasporti locali uno alla volta e osserva i cambiamenti in affidabilità/metadati.
6. Esporta o ripristina un backup di test e documenta esattamente quali profilo, contatti e cronologia contiene.
7. Perdi/revoca un dispositivo di test e conferma che i partecipanti rimanenti vedano il cambiamento previsto della chiave/del dispositivo.

Non eseguire il test contattando persone non coinvolte o generando traffico abusivo.

## Test di sanitizzazione dei file

1. Calcola l'hash e conserva l'originale in uno storage di evidenze cifrato:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. Crea una copia ripulita utilizzando il processo specifico per il formato descritto in [Comunicazioni e condivisione con tutela della privacy](privacy-preserving-communications-and-sharing.md).
3. Confronta gli inventari dei metadati:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Esegui/apri la copia in un contesto usa e getta. Controlla contenuti nascosti, allegati, link, moduli, livelli, miniature e identificatori visivi.
5. Cerca solo nella copia preparata stringhe note di canary relative ad autore/email/percorso.
6. Calcola l'hash dell'output finale e fai verificare a una seconda persona il file esatto che verrà pubblicato.

L'assenza nell'output di ExifTool non dimostra l'anonimato; gli interni del formato, i pixel, la prosa e i record di distribuzione rimangono.

## Test della privacy dei pagamenti

Usa l'importo minimo consentito o una rete di test/sandbox ufficiale:

1. Scrivi la visualizzazione prevista per pagatore, beneficiario/esercente, emittente/exchange, rete/nodo, ledger pubblico e contabile/responsabile del controllo.
2. Crea una fattura/contesto esercente di test univoco senza identità falsa.
3. Paga una volta, quindi raccogli la tua ricevuta, estratto conto, dashboard dell'esercente, log del wallet/nodo e visualizzazione della blockchain pubblica, ove applicabile.
4. Verifica se importo, timestamp, indirizzo/token, account, IP/dispositivo, consegna e percorso del rimborso corrispondono alla tabella degli osservatori.
5. Per Bitcoin, controlla il riutilizzo degli indirizzi, gli input selezionati, il resto e i successivi consolidamenti nella visualizzazione coin-control del wallet.
6. Per i protocolli shielded, verifica l'effettivo pool/percorso e ciò che rivela una viewing key; non dedurre la privacy dal branding del wallet.
7. Per e-cash/Taler, testa backup/ripristino, rimborso e riscatto con un valore ridotto; documenta i record dei confini di mint/exchange/federation.
8. Revoca una carta virtuale/credenziale di test e conferma che l'autorizzazione successiva fallisca, mantenendo al contempo chiara la gestione dei rimborsi legittimi.
9. Riconcilia e conserva criptate le evidenze fiscali/di autorizzazione richieste.

Non creare mai trasferimenti circolari, suddivisioni per soglia, acquisti falsi o rimborsi sospetti come “test della privacy”.

## Esercitazione di responsabilizzazione autorizzata del red-team

Prima dell'esercitazione, svolgi un tabletop e un drill tecnico:

1. Un operatore avvia un canary benigno da ciascun percorso sorgente approvato.
2. Il SOC target registra ciò che rileva senza ricevere l'identità dell'operatore, se è previsto un blind testing.
3. Il controller dell'esercitazione risolve la relazione sorgente → engagement → operatore dalla mappa depositata in escrow e dal job record firmato.
4. Il controller invia lo stop di emergenza; l'operatore e il proprietario dell'infrastruttura dimostrano lo spegnimento entro il tempo previsto dalle ROE.
5. Il provider abuse riceve il contatto corretto 24/7 e il riferimento all'autorizzazione.
6. Le evidenze mostrano target, orario, strumento/job e operatore senza conservare contenuti di payload non necessari.
7. Un secondo operatore verifica la revoca delle credenziali e il teardown delle risorse.

Boccia la revisione della readiness se il SOC può vedere trivialmente infrastrutture personali/domestiche **oppure** se il controller non può attribuire e arrestare rapidamente la sorgente.

## Modello del record di test
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Verifica della connessione](https://check.torproject.org/)
- [2] [WireGuard — Routing e Network Namespaces](https://www.wireguard.com/netns/)
- [3] [ExifTool — FAQ e indicazioni sui metadati](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Guida tecnica al testing e alla valutazione della sicurezza delle informazioni](https://csrc.nist.gov/pubs/sp/800/115/final)
