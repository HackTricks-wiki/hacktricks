# Playbook di privacy operativa

{{#include ../banners/hacktricks-training.md}}

Questi playbook combinano i controlli del resto di questa sezione. Sono punti di partenza, non garanzie: aggiorna il threat model ogni volta che un nuovo osservatore, account, dispositivo, luogo, pagamento, file o controparte entra nel workflow.

## Preflight universale

1. Scrivi l'obiettivo legittimo e ciò che deve rimanere privato **e rispetto a chi**.
2. Registra le identità, i dispositivi, le reti, gli account, i metodi di pagamento, le controparti, i luoghi fisici e i dati che l'attività coinvolgerà.
3. Identifica l'osservatore plausibile più forte e la conseguenza di un errore.
4. Conferma l'autorizzazione, la legge applicabile, i termini del provider e la policy organizzativa.
5. Decidi cosa deve rimanere attribuibile internamente per sicurezza, risposta agli incidenti, contabilità e audit.
6. Scegli il compartimento funzionante più piccolo; stabilisci i relativi percorsi di ripristino e arresto prima dell'uso.
7. Testa il compartimento con un servizio controllato, includendo IP/DNS/IPv6, identità del browser, metadati dei documenti, estratto del pagamento e leakage delle notifiche.

Usa il modello dettagliato in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Baseline di privacy quotidiana

Obiettivo: ridurre il tracking commerciale, il takeover degli account e l'esposizione non necessaria senza cercare di diventare anonimi.

- Usa un OS mantenuto con cifratura completa del disco, aggiornamenti automatici, blocco dello schermo e secure boot quando disponibile.
- Configura prima il password manager, l'email di recupero e la MFA/security key resistente al phishing.
- Esamina i permessi delle app, la cronologia delle posizioni, gli identificatori pubblicitari, la sincronizzazione cloud e le connessioni degli account di terze parti.
- Usa un browser mainstream con poche estensioni, protezione dal tracking, HTTPS e profili separati per la navigazione lavorativa/personale/ad alto rischio.
- Usa alias di private relay o indirizzi email distinti in base alla relazione; non usare un numero di telefono personale quando è semplicemente opzionale.
- Preferisci la messaggistica cifrata end-to-end per i contenuti, ricordando però che partecipanti, tempistiche, gruppi ed endpoint rimangono metadati.
- Rimuovi deliberatamente i metadati dai file e controlla la copia esportata, non l'originale, prima della pubblicazione.
- Usa token di carte virtuali o wallet per compartimentare le credenziali di pagamento; non considerarli anonimi.
- Esegui il backup del materiale di recupero cifrato e verifica il ripristino.

## Pubblicazione pseudonima

Obiettivo: impedire ai lettori occasionali e alle piattaforme di collegare banalmente una pubblicazione a un'identità civile. Questo non contrasta un'indagine mirata condotta da un avversario capace.

1. Definisci se la piattaforma, il provider di hosting, i lettori, i contatti, la rete locale, il provider di pagamento o un procedimento legale rientrano nel threat model.
2. Crea un endpoint/contesto account dedicato partendo da una baseline pulita. Disabilita la sincronizzazione personale del browser, i documenti cloud, il caricamento dei contatti e le anteprime delle notifiche.
3. Crea l'account pseudonimo tramite il compartimento di rete scelto. Non riutilizzare username, avatar, canali di recupero, boilerplate di scrittura o login personale dell'identity provider.
4. Usa Tor Browser quando l'unlinkability della destinazione è più importante della velocità; non aggiungere estensioni, non ridimensionarlo/personalizzarlo eccessivamente e non aprire documenti scaricati mentre sei online in una sessione desktop ordinaria.
5. Redigi usando un processo che non incorpori nomi di template personali, autori delle revisioni, percorsi delle stampanti, GPS/EXIF, miniature o livelli nascosti. Esporta una copia e controllala con strumenti per metadati appropriati.
6. Controlla il contenuto alla ricerca di fatti autoidentificanti: date uniche, dettagli sul luogo di lavoro, meteo/fuso orario locale, riflessi, audio di sottofondo, abitudini linguistiche e riutilizzo di testi pubblicati in precedenza.
7. Usa un canale di risposta separato. Considera ogni contatto diretto, allegato e link come un potenziale tentativo di correlazione o phishing.
8. Se è coinvolto del denaro, usa il metodo legittimo che espone solo i dati necessari. Presumi che la piattaforma e l'intermediario regolamentato possano conoscere il beneficiario anche se i lettori non lo conoscono.
9. Pubblica, quindi controlla il risultato pubblico da un contesto pulito differente. Registra ciò che la piattaforma ha aggiunto o trasformato.
10. Mantieni una cadenza pianificata solo se non crea un'impronta comportamentale stabile; dismetti il compartimento invece di riconvertirlo silenziosamente.

Per giornalismo serio, attivismo, violenza domestica o rischio a livello statale, richiedi assistenza personalizzata a un'organizzazione esperta di sicurezza digitale; una checklist statica non può modellare la legge locale o un avversario reale.

## Authorized red-team engagement

Obiettivo: mantenere le identità personali e le reti domestiche degli operatori fuori dalla telemetria del target, preservando al contempo autorizzazione, controllo e risposta agli incidenti.

### Prima della finestra di avvio

- Finalizza l'annesso infrastrutturale ROE, target/esclusioni, intervalli di origine, date, arresto di emergenza e autorizzazioni di terze parti/provider.
- Assegna un profilo operatore o una VM dedicata, i segreti dell'engagement, l'archivio delle evidenze, il progetto cloud, i domini e il budget.
- Preferisci un'uscita fornita dal cliente o un bastion fisso controllato dall'organizzazione. Testa il comportamento full-tunnel IPv4/IPv6/DNS e la policy fail-closed.
- Conserva la mappatura tra operatore e infrastruttura pubblica presso il controller dell'esercitazione o il contatto escrow concordato.
- Stabilisci rate limit, allowlist delle destinazioni e un'approvazione separata per azioni distruttive, wireless, fisiche, di phishing o di raccolta delle credenziali.
- Usa un metodo di pagamento controllato dall'organizzazione e registra internamente le approvazioni.

### Durante l'engagement

- Parti dall'endpoint e dal tunnel approvati; verifica l'egress osservato prima del traffico di assessment.
- Mantieni account personali, dispositivi, numeri di telefono, repository, chiavi SSH/GPG e sincronizzazione cloud fuori dal compartimento.
- Registra operatore/job, avvio/arresto, origine, destinazione nell'ambito e modifica della configurazione senza raccogliere contenuti del cliente non necessari.
- Arresta l'attività in caso di ambiguità sull'ambito, sistemi di terze parti inattesi, notifica di abuso del provider, impatto sulla sicurezza, apparecchiatura persa o perdita di contatto con il controller.
- Non improvvisare mai usando il Wi-Fi di un vicino, credenziali rubate, una SIM/account non approvati o hardware nascosto in una sede.

### Fine dell'engagement

- Arresta i job e il C2; recupera i drop device approvati; revoca token, credenziali e certificati.
- Riconcilia infrastruttura, domini, indirizzi sorgente, spese, dati e casi del provider con l'inventario.
- Restituisci/elimina/conserva i dati del cliente secondo il contratto, preserva le evidenze di audit minime necessarie e fai verificare l'arresto da un secondo operatore.

Consulta [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) per la guida completa a build e teardown.

## Acquisto o donazione privata legittima

Obiettivo: minimizzare la divulgazione al merchant o al pubblico rispettando gli obblighi dell'emittente, contabili, fiscali e relativi alle sanzioni.

1. Elenca chi non deve sapere cosa: pubblico, merchant, intermediario di pagamento, datore di lavoro/delegato dell'account familiare, servizio di consegna o osservatore della blockchain.
2. Verifica le norme locali, il destinatario/la controparte, i termini del provider, i limiti sul contante e le esigenze di conservazione dei registri.
3. Scegli il metodo:
- contanti per pagamenti locali legittimi accettati senza una registrazione della rete di pagamento;
- una carta virtuale regolamentata/specifica per il merchant per separare le credenziali online;
- cryptocurrency solo dopo aver analizzato acquisizione, ledger, wallet backend, rete, controparte e collegamenti alle spese successive.
4. Usa i dati obbligatori veritieri e ometti solo le informazioni opzionali su loyalty/marketing. Non usare l'identità/indirizzo di un'altra persona e non suddividere una transazione per aggirare una soglia.
5. Separa il contesto del browser/account del merchant ed evita login social, loyalty o canali personali di recupero non correlati.
6. Verifica cosa compare negli estratti, nelle ricevute, nelle notifiche, nelle spedizioni e negli elenchi pubblici dei donatori.
7. Conserva cifrate le evidenze obbligatorie di ricevute/fisco/autorizzazione; revoca le credenziali di pagamento usa e getta dopo il periodo per i rimborsi.

Consulta [Private Digital Payments](private-digital-payments.md) e [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viaggi e reti non affidabili

Obiettivo: proteggere dati e account sulle reti non amministrate dall'utente, non nascondere attività non autorizzate.

- Aggiorna i dispositivi e scarica credenziali/mappe necessarie prima del viaggio.
- Riduci al minimo i dati memorizzati; usa cifratura completa del disco, sblocco sicuro, pianificazione del recupero remoto e procedure a dispositivo spento per il confine/rischio fisico appropriate alla consulenza legale.
- Verifica l'SSID del luogo e il captive portal. Quando appropriato, preferisci un personal hotspot, ricordando però i registri dell'abbonato cellulare e della posizione.
- Usa una VPN approvata full/forced-tunnel per i dati dell'organizzazione; verifica che i dispositivi tethered la condividano e testa il comportamento IPv6/DNS.
- Usa un travel router per l'isolamento dei client e una policy ripetibile, non come garanzia di anonimato.
- Considera la ricarica USB pubblica, i computer presi in prestito, le stampanti pubbliche e i sistemi condivisi delle sale riunioni come minacce separate.
- Presumi che presenza fisica, identificatori radio, login al portal, telecamere e registri di pagamento/posizione possano correlare la visita.

I dettagli di confronto e configurazione sono in [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Risposta a errori ed esposizioni

Quando un compartimento subisce un leak o potrebbe essere collegato:

1. Arresta l'attività se proseguirla aumenta il danno; usa l'arresto di emergenza dell'engagement quando applicabile.
2. Preserva le evidenze necessarie senza diffondere dati sensibili. Registra l'ora esatta, l'indicatore osservato e gli asset interessati.
3. Notifica il proprietario/controller/contatto di sicurezza appropriato. Non nascondere un incidente per preservare una narrativa di privacy.
4. Revoca sessioni, token, credenziali di pagamento e accesso all'infrastruttura; ruota i segreti da un endpoint noto come pulito.
5. Determina quali collegamenti hanno permesso la correlazione: endpoint, account di recupero, rete, pagamento, metadati, contenuto, comportamento, controparte o presenza fisica.
6. Considera compromesso l'intero compartimento interessato. Non limitarti a cambiarne lo username o l'IP di uscita.
7. Rispetta gli obblighi di notifica relativi a breach, provider, cliente, aspetti finanziari e legge.
8. Ricostruisci solo dopo aver modificato il processo che ha causato il collegamento; documenta il controllo e testalo.

## Audit periodico

- [ ] Threat model e ipotesi legali/provider riesaminati secondo una pianificazione datata.
- [ ] Dispositivi, account, alias, domini, percorsi di rete e credenziali di pagamento inventariati.
- [ ] I percorsi di recupero non attraversano inaspettatamente i compartimenti.
- [ ] Comportamento full-tunnel, DNS, IPv6 e fail-closed testato.
- [ ] File e profili pubblici controllati per metadati/riutilizzo dei contenuti.
- [ ] Ipotesi su wallet node/backend e protocolli crypto ancora aggiornate.
- [ ] Log e ricevute ridotti al minimo, cifrati, soggetti a controllo degli accessi e conservati entro i limiti previsti.
- [ ] I vecchi compartimenti e l'infrastruttura dell'engagement sono stati completamente dismessi.
{{#include ../banners/hacktricks-training.md}}
