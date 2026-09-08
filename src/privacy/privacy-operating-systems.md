# Sistemi operativi per la privacy

{{#include ../banners/hacktricks-training.md}}

I sistemi operativi focalizzati sulla privacy riducono gli errori di routing e persistenza, ma nessuno può compensare comportamenti identificativi o hardware compromesso.

## Scegliere il modello di isolamento

| Sistema | Ideale per | Persistenza | Applicazione del network enforcement | Principale compromesso |
|---|---|---|---|---|
| **Tor Browser su un OS mantenuto aggiornato** | Navigazione web anonima occasionale | Lo stato del browser normalmente è limitato alla sessione | Solo il traffico del browser | Le altre applicazioni e l'host restano fuori da Tor |
| **Tails** | Sessioni portatili, amnesiche e a scopo singolo | Persistent Storage crittografato opzionale | Il traffico Internet è forzato attraverso Tor | Riavvii e attriti nel workflow; affidabilità di firmware/hardware |
| **Whonix** | Applicazioni persistenti che necessitano di routing Tor forzato | VM persistenti | Separazione tra Gateway e Workstation | L'host/l'hypervisor e la combinazione delle identità restano fattori di rischio |
| **Qubes-Whonix** | Forte separazione dei compartimenti per utenti avanzati | Per-qube | Qube di rete dedicati e Whonix | Requisiti hardware e complessità operativa |

## Tails

Tails si avvia in modo indipendente da un supporto rimovibile, instrada il traffico Internet attraverso Tor ed è progettato per lasciare uno stato locale minimo. I suoi stessi avvisi sottolineano che non può proteggere da BIOS/firmware/hardware compromessi, divulgazioni identificative, metadati dei file o da un osservatore potente in grado di correlare entrambe le estremità.<sup>[[1]](#references)</sup>

### Workflow Tails a scopo singolo

1. Scarica Tails dal sito ufficiale su un computer affidabile e aggiornato, quindi segui la procedura ufficiale di verifica/installazione.
2. Usa un'unità USB supportata solo per avviare Tails; non usarla anche come unità generica per il trasferimento dei file.
3. Avvia il sistema su hardware che controlli fisicamente. Un OS live non può neutralizzare un keylogger hardware o un firmware malevolo.
4. Lascia Persistent Storage disabilitato, a meno che il workflow non ne abbia realmente bisogno. Se lo abiliti, rendi persistenti solo le categorie necessarie e usa una passphrase robusta.
5. Connettiti a una rete lecita. Se un captive portal è inevitabile, usa Unsafe Browser di Tails solo per il portale, non divulgare informazioni identificative non necessarie, chiudilo immediatamente e connettiti a Tor prima di qualsiasi attività sensibile.<sup>[[2]](#references)</sup>
6. Configura un bridge Tor se la visibilità diretta di Tor o il suo blocco costituiscono un problema.
7. Esegui **una sola identità/finalità contestuale per sessione**. Tails consiglia di riavviare tra attività che non dovrebbero essere collegate.<sup>[[1]](#references)</sup>
8. Esamina e ripulisci i file prima di pubblicarli. Non aprire documenti attivi scaricati in un'applicazione che potrebbe aggirare il contesto previsto.
9. Arresta completamente il sistema al termine e mantieni l'USB fisicamente al sicuro.

## Whonix

Whonix separa un **Gateway** che instrada Tor da una **Workstation** le cui applicazioni non possono conoscere direttamente l'IP esterno. Ciò riduce in modo significativo gli errori relativi a proxy/DNS, ma l'host, l'hypervisor, il comportamento e i documenti possono comunque rivelare l'identità. Whonix avverte esplicitamente di non usare una workstation per più identità e di non combinare attività anonime e non anonime.<sup>[[3]](#references)</sup>

### Workflow a compartimenti

1. Verifica l'immagine Whonix e la piattaforma di virtualizzazione utilizzando fonti ufficiali.
2. Applica le patch all'host, all'hypervisor, al Gateway e alla Workstation prima dell'uso.
3. Clona una Workstation nuova per ogni identità o incarico; non clonare mai una VM dopo che vi è stato introdotto uno stato associato a un'identità.
4. Mantieni fuori dalla Workstation gli account personali, le cartelle condivise dell'host, la sincronizzazione degli appunti, i dispositivi USB e i dati relativi a ora/posizione.
5. Usa gli snapshot per il ripristino, non come sostituto dei backup o della separazione delle identità.
6. Verifica che la Workstation non possa raggiungere Internet quando il Gateway è arrestato.
7. Per i file particolarmente rischiosi, usa una VM/qube disposable ed esporta solo un risultato ripulito.

## Qubes OS e Qubes-Whonix

Qubes implementa la sicurezza tramite la compartimentazione con qube basate su Xen. Il suo design limita la possibilità che una compromissione in un dominio raggiunga automaticamente gli altri, ma le applicazioni all'interno dello **stesso** qube non sono isolate tra loro.<sup>[[4]](#references)</sup> Le disposable qube forniscono uno stato nuovo per siti, file e dispositivi non affidabili.<sup>[[5]](#references)</sup>

Una disposizione pratica:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Regole:

- Assegna a ogni qube un livello di attendibilità e uno scopo di identità.
- Conserva i segreti in un vault qube offline e usa operazioni esplicite di copia tra qube e trasferimento di file.
- Apri file e link non richiesti in disposables.
- Instrada attraverso Whonix o un qube VPN dedicato solo i qube previsti.
- Contrassegna chiaramente le finestre e arresta i qube non correlati durante le attività sensibili.
- Non presumere che due qube impediscano la correlazione se condividono account, contenuti, orari o pagamenti.

## Verifica e manutenzione

- Verifica le firme e i checksum degli installer seguendo le istruzioni ufficiali.
- Applica prima le patch ai template, quindi riavvia i qube/VM dipendenti.
- Verifica il comportamento di negazione della rete, DNS, IPv6, orologio, clipboard, directory condivise e assegnazione USB.
- Controlla Persistent Storage e gli snapshot delle VM per individuare vecchi dati associati all'identità.
- Conserva backup offline crittografati di seed/chiavi e prova il ripristino in un ambiente isolato.
- Ricrea un compartimento dopo una sospetta compromissione; cambiare l'IP di uscita non è sufficiente.

## References

- [1] [Tails — Avvertenze: Tails è sicuro, ma non è magico](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Accesso a una rete tramite captive portal](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Limitazioni di Whonix e Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Obiettivi di progettazione della sicurezza](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Come usare i disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
