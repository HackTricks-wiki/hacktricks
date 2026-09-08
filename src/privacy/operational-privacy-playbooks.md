# Playbook di privacy operativa

Questi playbook combinano i controlli del resto di questa sezione. Sono punti di partenza, non garanzie: aggiorna il threat model ogni volta che nel workflow entra un nuovo osservatore, account, dispositivo, luogo, pagamento, file o controparte.

## Preflight universale

1. Scrivi l'obiettivo legittimo e ciò che deve rimanere privato **da chi**.
2. Registra le identità, i dispositivi, le reti, gli account, i circuiti di pagamento, le controparti, i luoghi fisici e i dati che l'attività toccherà.
3. Identifica l'osservatore probabile più capace e la conseguenza di un fallimento.
4. Conferma l'autorizzazione, la legge applicabile, i termini del provider e la policy organizzativa.
5. Decidi cosa deve rimanere attribuibile internamente per sicurezza, risposta agli incidenti, contabilità e audit.
6. Scegli il compartment più piccolo praticabile; stabilisci i relativi percorsi di recovery e shutdown prima dell'utilizzo.
7. Testa il compartment con un servizio controllato, includendo IP/DNS/IPv6, identità del browser, metadati dei documenti, estratto conto del pagamento e leakage delle notifiche.

Usa il modello dettagliato in [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Baseline quotidiana di privacy

Obiettivo: ridurre il tracking commerciale, il takeover degli account e l'esposizione non necessaria senza cercare di diventare anonimi.

- Usa un OS mantenuto con cifratura completa del disco, aggiornamenti automatici, blocco dello schermo e secure boot, quando disponibili.
- Configura prima password manager, email di recovery e MFA/security keys resistenti al phishing.
- Esamina i permessi delle app, la cronologia delle posizioni, gli identificatori pubblicitari, la sincronizzazione cloud e le connessioni ad account di terze parti.
- Usa un browser mainstream con poche estensioni, protezione dal tracking, HTTPS e profili separati per la navigazione lavorativa/personale/ad alto rischio.
- Usa alias di private relay o indirizzi email distinti in base alla relazione; non usare un numero di telefono personale quando è semplicemente opzionale.
- Preferisci la messaggistica cifrata end-to-end per i contenuti, ricordando però che partecipanti, tempistiche, gruppi ed endpoint restano metadati.
- Rimuovi deliberatamente i metadati dai file e ispeziona la copia esportata, non l'originale, prima della pubblicazione.
- Usa virtual card o token del wallet per separare le credenziali di pagamento; non definirli anonimi.
- Esegui il backup del materiale di recovery cifrato e testa il ripristino.

## Pubblicazione pseudonima

Obiettivo: impedire a lettori e piattaforme casuali di collegare banalmente una pubblicazione a un'identità civile. Questo non sconfigge un'indagine mirata condotta da un avversario capace.

1. Definisci se rientrano nel threat model la piattaforma, il provider di hosting, i lettori, i contatti, la rete locale, il provider di pagamento o un procedimento legale.
2. Crea un endpoint/contesto account dedicato partendo da una baseline pulita. Disabilita la sincronizzazione personale del browser, i documenti cloud, il caricamento dei contatti e le anteprime delle notifiche.
3. Crea l'account pseudonimo attraverso il compartment di rete scelto. Non riutilizzare username, avatar, canali di recovery, boilerplate di scrittura o login personali dell'identity provider.
4. Usa Tor Browser quando l'unlinkability verso la destinazione è più importante della velocità; non aggiungere estensioni, non ridimensionarlo/personalizzarlo eccessivamente e non aprire documenti scaricati mentre sei online in una normale sessione desktop.
5. Redigi i contenuti con un processo che non incorpori nomi di template personali, autori delle revisioni, percorsi delle stampanti, GPS/EXIF, miniature o livelli nascosti. Esporta una copia e ispezionala con strumenti di metadati appropriati.
6. Controlla i contenuti per individuare fatti auto-identificativi: date uniche, dettagli sul luogo di lavoro, condizioni meteo/fuso orario locale, riflessi, audio ambientale, abitudini linguistiche e riutilizzo di testi già pubblicati.
7. Usa un canale di risposta separato. Considera ogni contatto diretto, allegato e link come un potenziale tentativo di correlazione o phishing.
8. Se sono coinvolti soldi, usa il metodo legittimo che espone solo i dati necessari. Presumi che la piattaforma e l'intermediario regolamentato possano conoscere il beneficiario anche se i lettori non lo conoscono.
9. Pubblica, quindi ispeziona il risultato pubblico da un contesto pulito diverso. Registra ciò che la piattaforma ha aggiunto o trasformato.
10. Mantieni una cadenza pianificata solo se non crea un'impronta comportamentale stabile; dismetti il compartment invece di riutilizzarlo silenziosamente.

Per giornalismo serio, attivismo, violenza domestica o rischio a livello statale, chiedi assistenza personalizzata a un'organizzazione esperta di sicurezza digitale; una checklist statica non può modellare la legge locale o un avversario attivo.

## Engagement autorizzato di red team

Obiettivo: tenere le identità personali degli operatori e le reti domestiche fuori dalla telemetria del target, preservando al contempo autorizzazione, controllo e risposta agli incidenti.

### Prima della finestra di avvio

- Finalizza l'annesso infrastrutturale del ROE, i target/esclusioni, gli intervalli di origine, le date, l'emergency stop e i permessi di terze parti/provider.
- Assegna un profilo operatore o una VM dedicati, i secret dell'engagement, l'archivio delle evidenze, il progetto cloud, i domini e il budget.
- Preferisci l'egress fornito dal cliente o un bastion fisso controllato dall'organizzazione. Testa il comportamento full-tunnel IPv4/IPv6/DNS e la policy fail-closed.
- Conserva la corrispondenza tra operatore e infrastruttura pubblica presso il controller dell'esercitazione o il contatto escrow concordato.
- Stabilisci rate limit, allowlist delle destinazioni e un'approvazione separata per azioni distruttive, wireless, fisiche, di phishing o di raccolta delle credenziali.
- Usa un circuito di pagamento controllato dall'organizzazione e registra internamente le approvazioni.

### Durante l'engagement

- Parti dall'endpoint e dal tunnel approvati; verifica l'egress osservato prima del traffico di assessment.
- Tieni fuori dal compartment gli account personali, i dispositivi, i numeri di telefono, i repository, le chiavi SSH/GPG e la sincronizzazione cloud.
- Registra operatore/job, avvio/arresto, origine, destinazione nell'ambito e modifica della configurazione senza raccogliere contenuti del cliente non necessari.
- Interrompi in caso di ambiguità dello scope, sistemi inattesi di terze parti, notifica di abuso del provider, impatto sulla sicurezza, perdita dell'attrezzatura o perdita dei contatti con il controller.
- Non improvvisare mai usando il Wi-Fi del vicino, credenziali rubate, una SIM/account non approvati o hardware nascosto in una sede.

### Fine dell'engagement

- Arresta i job e il C2; recupera i drop device approvati; revoca token, credenziali e certificati.
- Riconcilia infrastruttura, domini, indirizzi sorgente, spese, dati e casi dei provider con l'inventario.
- Restituisci/elimina/conserva i dati del cliente secondo il contratto, preserva le evidenze di audit minime necessarie e fai verificare lo shutdown da un secondo operatore.

Consulta [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) per la guida completa alla configurazione e al teardown.

## Acquisto o donazione privata legittima

Obiettivo: ridurre al minimo la divulgazione al merchant o al pubblico rispettando gli obblighi dell'emittente, contabili, fiscali e relativi alle sanzioni.

1. Elenca chi non deve sapere cosa: pubblico, merchant, intermediario di pagamento, datore di lavoro/delegato dell'account familiare, servizio di consegna o osservatore della blockchain.
2. Verifica le norme locali, il destinatario/la controparte, i termini del provider, i limiti sul contante e le esigenze di conservazione dei documenti.
3. Scegli il circuito:
- contanti per pagamenti locali legittimi accettati senza una registrazione della rete di pagamento;
- una virtual card regolamentata/specifica per il merchant per la separazione delle credenziali online;
- cryptocurrency solo dopo aver analizzato acquisizione, ledger, backend del wallet, rete, controparte e collegamenti alle spese successive.
4. Usa i dati obbligatori veritieri e ometti solo le informazioni opzionali di loyalty/marketing. Non usare l'identità/indirizzo di un'altra persona e non dividere una transazione per aggirare una soglia.
5. Separa il contesto browser/account del merchant ed evita login social, loyalty o canali personali di recovery non correlati.
6. Conferma cosa compare su estratti conto, ricevute, notifiche, spedizioni ed elenchi pubblici dei donatori.
7. Conserva cifrati i documenti richiesti relativi a ricevute/fisco/autorizzazioni; revoca le credenziali di pagamento usa-e-getta dopo il periodo per i rimborsi.

Consulta [Private Digital Payments](private-digital-payments.md) e [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Viaggi e reti non attendibili

Obiettivo: proteggere dati e account sulle reti non amministrate dall'utente, non occultare attività non autorizzate.

- Aggiorna i dispositivi e scarica le credenziali/mappe necessarie prima del viaggio.
- Riduci al minimo i dati memorizzati; usa cifratura completa del disco, sblocco forte, pianificazione del recovery remoto e procedure a dispositivo spento per frontiere/rischi fisici appropriate al parere legale.
- Verifica l'SSID del luogo e il captive portal. Preferisci un hotspot personale quando appropriato, ricordando però i record dell'abbonato cellulare e della posizione.
- Usa una VPN approvata full/forced per i dati dell'organizzazione; verifica che i dispositivi tethered la condividano e testa il comportamento IPv6/DNS.
- Usa un travel router per l'isolamento dei client e una policy ripetibile, non come garanzia di anonimato.
- Considera la ricarica USB pubblica, i computer presi in prestito, le stampanti pubbliche e i sistemi condivisi delle sale riunioni come minacce separate.
- Presumi che presenza fisica, identificatori radio, login al portal, telecamere e registri di pagamento/posizione possano correlare la visita.

I dettagli di confronto e configurazione sono in [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Risposta a failure ed esposizione

Quando un compartment subisce un leak o può essere collegato:

1. Interrompi l'attività se proseguirla aumenta il danno; usa l'emergency stop dell'engagement quando applicabile.
2. Conserva le evidenze necessarie senza diffondere dati sensibili. Registra l'ora esatta, l'indicatore osservato e gli asset coinvolti.
3. Informa il responsabile/controller/security contact appropriato. Non occultare un incidente per preservare una narrativa di privacy.
4. Revoca sessioni, token, credenziali di pagamento e accesso all'infrastruttura; ruota i secret da un endpoint noto come pulito.
5. Determina quali edge hanno creato il collegamento: endpoint, recovery dell'account, rete, pagamento, metadati, contenuto, comportamento, controparte o presenza fisica.
6. Considera completamente bruciato l'intero compartment coinvolto. Non limitarti a cambiarne username o exit IP.
7. Rispetta gli obblighi di notifica relativi a breach, provider, cliente, finanze e legge.
8. Ricostruisci solo dopo aver modificato il processo che ha causato il collegamento; documenta il controllo e testalo.

## Audit periodico

- [ ] Threat model e assunzioni legali/provider revisionati secondo una cadenza datata.
- [ ] Dispositivi, account, alias, domini, percorsi di rete e credenziali di pagamento inventariati.
- [ ] I percorsi di recovery non attraversano inaspettatamente i compartment.
- [ ] Comportamento full-tunnel, DNS, IPv6 e fail-closed testato.
- [ ] File e profili pubblici controllati per metadati/riutilizzo dei contenuti.
- [ ] I nodi/backend dei wallet e le assunzioni sui protocolli crypto restano aggiornati.
- [ ] Log e ricevute sono minimi, cifrati, soggetti a controllo degli accessi e conservati entro i limiti previsti.
- [ ] I vecchi compartment e l'infrastruttura degli engagement sono stati completamente dismessi.
