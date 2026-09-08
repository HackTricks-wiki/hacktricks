# Infrastruttura autorizzata per il red team

{{#include ../banners/hacktricks-training.md}}

Per i dispositivi on-site durevoli, utilizzare il design [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) e la procedura operativa per la gestione delle potenziali scoperte.

Per un red team professionale, l'obiettivo è l'**attribuzione controllata**, non l'immunità dalla responsabilità. Il target non dovrebbe poter vedere facilmente l'IP domestico o gli account personali di un operatore, mentre il responsabile dell'engagement deve poter identificare la fonte, interrompere l'operazione, gestire le segnalazioni di abuso, preservare le prove e dimostrare l'autorizzazione.

Questa pagina costituisce la baseline di deployment per un engagement legittimo. Per le tecniche avversarie che intende emulare, inclusi ORB compromessi, relay residenziali, fronting, dead drop e pivot wireless nelle vicinanze, iniziare da [Infrastruttura offensiva ed elusione dell'attribuzione](offensive-infrastructure-and-attribution-evasion.md) e [Casi di studio governativi e APT](government-and-apt-case-studies.md), quindi riprodurre la telemetria necessaria negli [authorized labs](authorized-adversary-emulation-labs.md).

NIST definisce le rules of engagement (ROE) come vincoli prestabiliti che conferiscono l'autorità per attività di testing definite.<sup>[[1]](#references)</sup> L'architettura della privacy non può ampliare tale autorità.

## Scegliere un pattern di egress

| Pattern | Uso ideale | Cosa vede il target | Cosa vede il provider/osservatore locale | Accountability |
|---|---|---|---|---|
| VPN/jump host fornito dal client | La maggior parte degli assessment | Range di indirizzi del client | Identità del client e accesso dell'operatore | Massima |
| Bastion dell'organizzazione di red team | Egress controllato e ripetibile | Range dell'organizzazione | Hosting provider e organizzazione | Elevata |
| VPS specifico per l'engagement | Isolare client/campagne | Indirizzo del VPS | Account dell'host, billing, log del control plane e degli accessi | Elevata se documentata |
| VPN commerciale approvata | Ricerca/scanning consentiti dal provider e dalle ROE | Egress VPN condiviso/dedicato | Account VPN e connessione sorgente | Media |
| Tor Browser | Ricerca web che richiede l'assenza di collegamento con la destinazione | Exit Tor | La rete locale vede Tor/bridge; la destinazione vede Tor | Poco adatto all'attribuzione della sorgente tramite allowlist |
| Drop on-site approvato dal client | Simulazione interna | Dispositivo/indirizzo on-site | Rete del sito e provider del tunnel remoto | Elevata se inventariato |
| Guest Wi-Fi legittimo | Uso amministrativo/di ricerca a basso rischio | IP pubblico della sede o egress del tunnel | Sede, ISP, VPN/Tor | Debole e fisicamente osservabile |

Per la maggior parte delle attività, un egress fisso fornito dal client o controllato dall'organizzazione è più sicuro e rapido dei servizi di anonimato consumer. Consente inoltre ai defender di inserire in allowlist, monitorare o deliberatamente **non** inserire in allowlist i range di sorgente noti, in base al design dell'esercitazione.

## Allegato dell'infrastruttura ROE

Registrare prima del deployment:

- entità legali che concedono e ricevono l'autorizzazione;
- target esatti ed esclusioni esplicite;
- orari di inizio/fine, fuso orario e tecniche consentite;
- IP sorgente, nomi dell'autonomous system/provider, domini, redirector, infrastruttura mail e identificativi dei dispositivi on-site;
- se sono consentiti phishing, C2, credential capture, wireless testing, accesso fisico, denial-of-service, persistence o servizi di terze parti;
- approvazioni del client e del provider, incluso qualsiasi riferimento alla pre-notifica;
- frase per l'arresto d'emergenza, contatti abuse del client e del provider disponibili 24/7 e tempo massimo di risposta;
- classi di dati che possono essere raccolte, cifratura, accesso, conservazione ed eliminazione;
- requisiti relativi a prove e logging, incluso chi conserva la mappatura dall'infrastruttura pubblica all'operatore;
- teardown, scadenza dei domini, revoca dei certificati, rotazione delle credenziali, recupero dei dispositivi e attestazione finale.

Verificare che gli IP pubblici e i domini siano effettivamente controllati dalla parte autorizzante o siano esplicitamente inclusi nello scope. NIST SP 800-115 raccomanda di confermare che gli indirizzi pubblici dei target rientrino nella competenza dell'organizzazione prima del testing.<sup>[[2]](#references)</sup>

## Egress rapido specifico per l'engagement

### Workflow di build

1. **Creare un account/progetto per l'engagement** all'interno dell'organizzazione di red team, utilizzando dati accurati di billing e ownership. Separare ruoli, API key, budget e audit log da quelli degli altri client.
2. **Verificare ogni policy del provider.** I provider cloud, VPS, CDN, domini, email e VPN applicano regole diverse. AWS, ad esempio, consente assessment specifici, ma richiede un'approvazione preventiva per C2 ospitati/covert simulation e vieta le attività elencate.<sup>[[3]](#references)</sup>
3. **Assegnare indirizzi di egress fissi** e inserirli nell'allegato ROE. Evitare il cycling rapido di IP/risorse; complica l'incident response e potrebbe violare la policy del provider.
4. **Rendere sicura la gestione:** SSH con sole key o management plane identity-aware, MFA resistente al phishing, rete admin separata, least privilege, immagini aggiornate, nessuna porta admin pubblica e storage cifrato dei secret.
5. **Creare un percorso full-tunnel** dall'endpoint dell'operatore al bastion. Instradare DNS e IPv6 in modo deliberato e applicare un firewall deny quando il tunnel è inattivo.
6. **Limitare le destinazioni e le porte in uscita** allo scope autorizzato quando possibile. Applicare rate limit agli scanner e sottoporre le tecniche irreversibili/distruttive a un gate di approvazione separato.
7. **Eseguire il logging per l'accountability, non per la sorveglianza:** autenticazione dell'operatore, modifiche alla configurazione, avvio/arresto, indirizzo sorgente, destinazione nello scope e identificativi di tool/job. Evitare la cattura di payload/credenziali, salvo quando richiesta dall'esercitazione e protetta dal data plan.
8. **Validare tramite un endpoint controllato** di proprietà dell'organizzazione: IPv4/IPv6 osservati, percorso DNS, reverse DNS, clock, comportamento della source port, failure/reconnect e contatto abuse del provider.
9. **Condividere la mappa di attribuzione in modo sicuro** con l'exercise controller o con un contatto escrow concordato. Non pubblicarla al team del target se il blind detection fa parte del test.

### Architettura
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Un VPS è pseudonimo solo rispetto alla destinazione. L'host può conservare record di contatto, fatturazione, identità, IP sorgente, API, dispositivo, posizione e utilizzo; la sola cronologia AWS CloudTrail visibile al cliente può esporre l'attività di gestione.<sup>[[4]](#references)</sup> Pagare l'hosting con criptovaluta non cancella questi record.

## Domini e certificati

- Usa un account del registrar specifico per l'engagement, di proprietà dell'organizzazione.
- Abilita il registrar lock, DNSSEC ove supportato, MFA/security key e il rinnovo automatico solo per il periodo approvato.
- Usa la privacy della registrazione per ridurre l'esposizione pubblica, non per rappresentare falsamente le informazioni del registrant. La policy ICANN impone ai registrar di raccogliere i dati di registrazione anche quando la loro visualizzazione pubblica è oscurata o sottoposta a proxy.<sup>[[5]](#references)</sup>
- Evita nomi che impersonino illegalmente parti non correlate. I domini typosquatting/lookalike richiedono l'approvazione esplicita del cliente e del provider.
- Inventaria DNS, certificati, configurazione CDN/redirector e analytics di terze parti che potrebbero esporre gli operatori o i clienti.
- Durante il teardown, rimuovi i record, revoca certificati/token, conserva le evidenze concordate e decidi se il dominio debba essere mantenuto a scopo difensivo.

## Nodi drop on-site autorizzati

Un Raspberry Pi o un dispositivo simile è accettabile solo quando il proprietario della struttura/rete e il cliente ne autorizzano esplicitamente l'esatta posizione e il comportamento. Un piano sicuro:

1. Registra il seriale del dispositivo, il MAC/la policy per il MAC privato, una foto, il proprietario, la posizione esatta approvata, la fonte di alimentazione, la scadenza per il recupero e il contatto per eventuali manomissioni.
2. Usa un'immagine firmata minimale, secret crittografati, storage in sola lettura o recuperabile, host firewall, aggiornamenti di sicurezza automatici ove pratico e nessuna credenziale predefinita.
3. Configura comunicazioni esclusivamente in uscita verso un endpoint di engagement nominato. Non esporre un listener non autenticato.
4. Inserisci in allowlist destinazioni e funzionalità. Packet capture, raccolta di credenziali, impersonificazione wireless e movimento laterale devono essere autorizzati esplicitamente ciascuno.
5. Usa autenticazione reciproca, chiavi a breve durata, kill remoto, health reporting e limiti di banda.
6. Assicurati che perdita o furto non rivelino credenziali riutilizzabili o dati del cliente.
7. Inserisci in calendario il recupero e il wipe sicuro/decommissioning; ottieni un verbale di recupero firmato.

Non nascondere hardware in un bar, hotel, ufficio condiviso, proprietà del vicino o luogo pubblico senza il permesso scritto del proprietario/gestore.

## Reti guest e travel router

Se uno scenario autorizzato richiede l'accesso guest:

- verifica l'SSID e la policy di utilizzo accettabile con la struttura/il cliente;
- usa un travel router di proprietà dell'organizzazione o un bridge device a bassa fiducia per isolare la workstation privilegiata;
- completa i captive portal al di fuori della workstation privilegiata;
- avvia il tunnel approvato prima del traffico di assessment;
- conferma che i dispositivi tethered utilizzino effettivamente quel tunnel;
- presumi che la struttura possa correlare associazione radio, portale, presenza fisica e record delle telecamere/dei pagamenti;
- non eludere mai il controllo degli accessi, clonare un altro dispositivo, attaccare il Wi-Fi o lasciare apparecchiature sul posto.

## Separazione operativa

- Un client/engagement per ogni compartimento dell'endpoint, progetto cloud, set di secrets, gruppo di domini, set di redirector e archivio delle evidenze.
- Nessuna email personale, sincronizzazione del browser, numero di telefono, cloud drive, chiave SSH/GPG, identità di code-signing o rimborso di pagamenti al di fuori dei sistemi organizzativi approvati.
- Non riutilizzare configurazioni distintive dei payload, percorsi di callback, certificati o repository pubblici tra clienti, a meno che il design dell'esercizio accetti il fingerprinting.
- Assegna all'infrastruttura una data di disattivazione e un alert di budget. I sistemi abbandonati diventano un rischio sia per il cliente sia per Internet.
- Conserva un'attribuzione interna sufficiente per investigare gli incidenti. “Nessun log” è generalmente incompatibile con le esigenze professionali di raccolta delle evidenze e di sicurezza.

## Invisibile ai defender, attribuibile al controller

Quando l'obiettivo dell'esercizio è misurare il rilevamento anziché testare una allowlist, il SOC target può rimanere all'oscuro senza rendere l'operazione non responsabile:

1. Il controller dell'esercizio approva ogni source pubblica, dominio, certificato e dispositivo on-site, ma ne tiene l'elenco nascosto al SOC.
2. Il controller conserva la mappa source-to-engagement/operator in un vault crittografato separato, con accesso di emergenza a due persone.
3. Ogni job dell'operatore riceve un manifest firmato contenente scope, finestra temporale, compartimento della source e identificatore irreversibile del job. Il target non deve visualizzare il manifest durante il normale funzionamento.
4. Gli eventi di audit del bastion vengono concatenati o inviati in modalità append-only allo storage del controller, così che un operatore non possa riscrivere silenziosamente l'attribuzione dopo un incidente.
5. Un contatto 24/7 per gli abusi presso il provider conserva una frase/riferimento di verifica che conferma l'autorizzazione senza divulgare pubblicamente il cliente.
6. Ogni percorso implementa un canale di arresto out-of-band che non dipende dal C2 dell'assessment, dalla rete target o dall'account di un singolo operatore.
7. Prima del live testing, invia canary benigni da ogni source. Conferma che il controller possa individuarli e arrestarli entro il tempo di risposta previsto dal ROE.
8. Dopo l'esercizio, confronta la telemetria del SOC con il ledger del controller, divulga l'elenco delle source e spiega i rilevamenti mancati/errati.

Non aggiungere anti-forensics, distruzione dei log, relay compromessi o false identità degli abbonati. Questi elementi compromettono i test responsabili anziché migliorarli.

## Checklist di teardown

- [ ] Il controller dell'esercizio conferma l'arresto.
- [ ] C2, tunnel, redirector, posta, VPN e job pianificati sono disabilitati.
- [ ] I dispositivi on-site sono recuperati fisicamente e riconciliati.
- [ ] Token, chiavi API, chiavi SSH, certificati e credenziali raccolte sono revocati/ruotati.
- [ ] DNS e risorse cloud sono rimossi o trasferiti per la conservazione difensiva.
- [ ] I dati del cliente sono restituiti, conservati o distrutti secondo il contratto.
- [ ] I record finanziari, di audit e di autorizzazione richiesti rimangono crittografati e con accesso controllato.
- [ ] I casi di abuso presso i provider sono chiusi e il cliente riceve gli indicatori finali delle source.
- [ ] Un secondo operatore verifica che non rimanga attiva alcuna infrastruttura.

## References

- [1] [NIST CSRC — Regole di ingaggio](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Guida tecnica al test e alla valutazione della sicurezza delle informazioni](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Policy di supporto ai clienti per il Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Informativa sulla privacy](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Policy sui dati di registrazione](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
