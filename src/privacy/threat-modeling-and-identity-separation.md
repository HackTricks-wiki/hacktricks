# Threat Modeling e separazione delle identità

Il fallimento più comune dell'anonimato non è la crittografia compromessa. È il **linkage**: un identificatore, un pattern temporale, un dispositivo, un account, un pagamento, un file o un'abitudine umana collega due contesti che avrebbero dovuto rimanere separati.

## Costruisci un threat model per la privacy

Il piano di sicurezza in sei domande dell'EFF è una base solida: cosa deve essere protetto, da chi, l'impatto e la probabilità di un fallimento, lo sforzo disponibile e gli alleati che possono aiutare.<sup>[[1]](#references)</sup> Rendilo operativo con una piccola tabella:

| Asset/azione | Osservatore | Dati osservabili | Percorso di correlazione | Controllo | Rischio residuo |
|---|---|---|---|---|---|
| Ricerca su un cliente | ISP | Metadati di destinazione/temporali | Record dell'abbonato domestico | Tor Browser | Uso di Tor visibile; correlazione end-to-end |
| Account pseudonimo | Piattaforma | IP, browser, dati di recupero | Numero di telefono/email/foto riutilizzati | Contesto e alias dedicati | Correlazione con stile di scrittura/grafo sociale |
| Acquisto online | Commerciante | Account, consegna, carta tokenizzata | Indirizzo e cronologia dell'account | Guest checkout, campi minimi, carta virtuale | L'emittente e il corriere conservano i record |
| Traffico di red team | Target/cliente | IP sorgente e comportamento | Record del provider/incarico | Egress dedicato e autorizzato | Deliberatamente attribuibile in caso di escalation |

Rivedi la tabella ogni volta che cambiano la posizione, il provider, il dispositivo, la controparte o le conseguenze.

## Disegna il grafo della linkability

Tratta ogni identità come un nodo separato. Aggiungi un edge per ogni attributo condiviso:

- email o indirizzo di recupero;
- numero di telefono o caricamento della rubrica;
- username, avatar, foto, bio o stile di scrittura/codice;
- password, account di passkey-sync o domanda di recupero;
- dispositivo, advertising ID, profilo del browser, cookie, font o estensioni;
- indirizzo IP, fuso orario, lingua, pianificazione o stato online simultaneo;
- carta bancaria, account di exchange, cluster di wallet, indirizzo di spedizione o programma fedeltà;
- campi dell'autore del documento, posizione EXIF, contrassegni della stampante o proprietario della condivisione cloud;
- collega, appartenenza a gruppi e grafo sociale.

Un edge non è automaticamente fatale, ma indica quale osservatore può effettuare il collegamento. L'EFF avverte specificamente che numeri di telefono, indirizzi email e fotografie riutilizzate possono collegare i profili.<sup>[[2]](#references)</sup>

## Crea un compartimento passo dopo passo

1. **Nomina il contesto e i collegamenti vietati.** Esempio: `client-red-2026`, vietato all'email personale, ai profili del browser di casa, ai metodi di pagamento personali e ai clienti non correlati.
2. **Scegli il confine di isolamento.** In ordine di robustezza crescente: profilo separato del browser → account OS separato → VM/qube separata → dispositivo dedicato. Una scheda separata o una finestra privata non costituisce un confine di sicurezza.
3. **Crea identificatori nuovi all'interno di quel confine.** Usa un'email/alias specifico per il contesto, username, password-manager vault o collection e chiavi di autenticazione. Non aggiungere un canale di recupero personale se l'unlinkability dal provider è importante.
4. **Scegli una policy di rete.** Decidi se il contesto utilizzerà sempre una VPN del cliente, una VPS per l'incarico, una VPN affidabile o Tor. Applica il routing fail-closed dove possibile.
5. **Scegli una policy di pagamento.** Il metodo di pagamento deve corrispondere al modello dell'osservatore; una carta virtuale può nascondere il PAN al commerciante, ma identifica comunque il cliente presso l'emittente.
6. **Definisci le regole di trasferimento dei dati.** Preferisci trasferimenti mirati e deliberati. Considera clipboard, cartelle condivise, dispositivi USB, cloud sync, stampanti e screenshot come possibili ponti.
7. **Registra le date di creazione e dismissione.** Definisci quali evidenze devono essere conservate per contratti/tasse/compliance e quali dati transitori devono scadere.
8. **Verifica i collegamenti prima dell'uso.** Controlla le impostazioni dell'account, i campi di recupero, il profilo pubblico, IP/DNS, lo stato del browser, i metadati dei file e le dashboard del provider.

{% hint style="warning" %}
Non inventare informazioni sull'identità quando un servizio o la legge richiedono un'identificazione accurata. Un compartimento per la privacy riguarda la minimizzazione e la separazione dei dati, non la frode d'identità o l'elusione della customer due diligence.
{% endhint %}

## Baseline di endpoint e account

- Usa hardware supportato e installa tempestivamente gli aggiornamenti di OS, browser, wallet e firmware.
- Abilita la crittografia del dispositivo e usa un passcode del dispositivo robusto. La crittografia at rest è utile quando un dispositivo spento viene perso o sequestrato, ma non quando malware o una sessione sbloccata possono leggere i dati.<sup>[[3]](#references)</sup>
- Usa password uniche e generate casualmente in un password manager.
- Preferisci autenticazione resistente al phishing, come WebAuthn/passkeys o security key hardware, quando il threat model consente il relativo modello di recupero/sync. NIST osserva che gli OTP inseriti manualmente non sono resistenti al phishing, perché un impostore può inoltrarli.<sup>[[4]](#references)</sup>
- Conserva i codici di recupero offline e separati dall'endpoint. Verifica se un account di passkey sincronizzato unisce identità che dovrebbero rimanere separate.
- Disabilita i permessi non necessari relativi a posizione, contatti, microfono, fotocamera, Bluetooth, advertising ID e attività in background.
- Non integrare cloud sync personale, browser sync, account di password manager o app store in un contesto ad alta separazione.

## Privacy del browser

Il browser fingerprinting usa configurazione, dispositivo, ambiente e comportamento osservabili per identificare o correlare un utente. Cancellare i cookie o cambiare gli indirizzi IP non lo neutralizza in modo affidabile e il W3C considera implausibile la completa eliminazione tecnica tramite mezzi ampiamente distribuiti.<sup>[[5]](#references)</sup>

Per la privacy ordinaria:

1. Usa un browser supportato con modalità HTTPS-only e una solida protezione dal tracking.
2. Blocca il tracking di terze parti e separa lo stato dove supportato.
3. Usa profili separati del browser per contesti realmente separati.
4. Disabilita i permessi non necessari e cancella i dati dei siti secondo una pianificazione definita.
5. Evita di accedere ad account ricchi di identità mentre svolgi ricerche sensibili non correlate.

Per l'anonimato web, usa **Tor Browser nella sua configurazione standard**. Non usare un proxy per instradare un browser normale tramite Tor: Tor Project avverte che i browser ordinari possono fare leak tramite DNS/WebRTC, stato persistente, font, plugin e differenze di fingerprint.<sup>[[6]](#references)</sup> Evita estensioni aggiuntive, dimensioni insolite delle finestre, font personalizzati e preferenze che rendono il browser riconoscibile.<sup>[[7]](#references)</sup>

## Comunicazioni e metadati

I metadati includono mittente, destinatario, ora, posizione e altro contesto anche quando il contenuto del messaggio è crittografato end-to-end.<sup>[[8]](#references)</sup>

- Preferisci strumenti con crittografia end-to-end, metadati lato server ridotti e protocolli/client open ove pratico.
- Verifica i contatti sensibili usando un canale indipendente o di persona. I safety number di Signal sono progettati per questo controllo.<sup>[[9]](#references)</sup>
- Gli username di Signal possono avviare un contatto senza condividere un numero di telefono, ma per registrarsi è comunque necessario un numero; configura deliberatamente la visibilità/individuabilità del numero di telefono.<sup>[[9]](#references)</sup>
- I messaggi a scomparsa riducono le copie conservate; i destinatari possono comunque fotografare, copiare, inoltrare o archiviare i contenuti.
- L'email espone normalmente i metadati di routing. Anche i provider orientati alla privacy non possono rendere un messaggio crittografato end-to-end quando l'altra parte usa l'email ordinaria, a meno che entrambe le parti utilizzino un metodo E2EE compatibile. Proton, per esempio, documenta che la posta ordinaria verso altri provider usa TLS e rimane leggibile dal provider ricevente.<sup>[[10]](#references)</sup>
- Separa le rubriche e non caricare contatti personali su un account pseudonimo.

## File, foto e paternità

Tails avverte che le fotografie possono contenere dati della fotocamera e sulla posizione e che i documenti Office possono contenere campi relativi all'autore e all'ora di creazione.<sup>[[11]](#references)</sup>

Prima della condivisione:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Quindi riapri la copia ripulita in un visualizzatore isolato e verifica:

- proprietà del documento, commenti, modifiche rilevate, fogli/diapositive nascosti, miniature e allegati;
- EXIF/XMP/IPTC, GPS, timestamp, nomi di dispositivi/software e ID univoci;
- riflessi visibili, punti di riferimento, contenuti degli schermi, voci, volti e suoni di sottofondo;
- nome del file, percorsi degli archivi, proprietario della condivisione cloud, certificato di firma e cronologia delle revisioni.

La sanitizzazione può danneggiare le prove o l'autenticità. Conserva un originale crittografato quando la catena di custodia o una verifica successiva sono importanti. Anche la stilometria e lo stile di programmazione possono collegare un autore; la rimozione dei metadata non modifica lo stile umano.

## Common failure patterns

- Accedere a un account personale tramite una connessione “anonima”.
- Riutilizzare un telefono di recupero, avatar, username, chiave pubblica, wallet o indirizzo per donazioni.
- Utilizzare due identità contemporaneamente da contesti correlabili.
- Copiare testo/file tramite una clipboard cloud personale o una cartella condivisa.
- Installare estensioni distintive di Tor Browser o modificare molte impostazioni predefinite.
- Fidarsi di una dichiarazione “no logs” senza capire cosa viene registrato, per quanto tempo e da quali subappaltatori.
- Presumere che un telefono secondario sia anonimo mentre viaggia insieme a un telefono personale. EFF osserva che la posizione cellulare e gli spostamenti congiunti possono correlare i dispositivi.<sup>[[3]](#references)</sup>
- Considerare la crittografia come una cancellazione; gli endpoint e i destinatari possono conservare il testo in chiaro.

## Verification checklist

- [ ] Il contesto non contiene un indirizzo personale di recupero, un numero di telefono, un account di sincronizzazione o media riutilizzati, salvo accettazione intenzionale.
- [ ] Il percorso di rete previsto è attivo e chiude in caso di errore.
- [ ] Fuso orario, impostazioni locali, estensioni e autorizzazioni del browser/dispositivo corrispondono al piano.
- [ ] Nel compartimento non sono aperti account personali.
- [ ] I file sono stati ispezionati e sottoposti a sanitizzazione; gli originali sono gestiti separatamente.
- [ ] I contatti sono autenticati tramite un secondo canale.
- [ ] I metadata visibili al provider e il periodo di conservazione sono noti.
- [ ] Le procedure di teardown, conservazione delle prove e recupero degli account sono documentate.

## References

- [1] [EFF Surveillance Self-Defense — Il tuo piano di sicurezza](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Proteggersi sui social network](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Partecipare a una protesta](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Gestione dell'autenticazione e degli autenticatori](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Mitigazione del browser fingerprinting nelle specifiche web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Usare Tor con altri browser](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugin e add-on in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Perché i metadata delle comunicazioni sono importanti](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privacy del numero di telefono e username: approfondimento](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Cosa è crittografato in Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Avvertenze: Tails è sicuro, ma non è magico](https://tails.net/doc/about/warnings/index.en.html)
