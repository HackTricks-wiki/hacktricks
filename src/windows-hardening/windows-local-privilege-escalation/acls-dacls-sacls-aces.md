# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Un'Access Control List (ACL) consiste in un insieme ordinato di Access Control Entries (ACEs) che determinano le protezioni per un oggetto e le sue proprietà. In sostanza, un'ACL definisce quali azioni da parte di quali principi di sicurezza (utenti o gruppi) sono permesse o negate su un dato oggetto.

Ci sono due tipi di ACL:

- **Discretionary Access Control List (DACL):** Specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
- **System Access Control List (SACL):** Regola l'audit dei tentativi di accesso a un oggetto.

Il processo di accesso a un file comporta che il sistema controlli il descrittore di sicurezza dell'oggetto rispetto al token di accesso dell'utente per determinare se l'accesso debba essere concesso e l'estensione di tale accesso, basato sulle ACEs.

### **Key Components**

- **DACL:** Contiene ACEs che concedono o negano permessi di accesso a utenti e gruppi per un oggetto. È essenzialmente l'ACL principale che determina i diritti di accesso.
- **SACL:** Utilizzato per l'audit degli accessi agli oggetti, dove le ACEs definiscono i tipi di accesso da registrare nel Security Event Log. Questo può essere prezioso per rilevare tentativi di accesso non autorizzati o per risolvere problemi di accesso.

### **System Interaction with ACLs**

Ogni sessione utente è associata a un token di accesso che contiene informazioni di sicurezza rilevanti per quella sessione, inclusi identità utente, di gruppo e privilegi. Questo token include anche un SID di accesso che identifica univocamente la sessione.

L'Autorità di Sicurezza Locale (LSASS) elabora le richieste di accesso agli oggetti esaminando il DACL per le ACEs che corrispondono al principio di sicurezza che tenta di accedere. L'accesso è immediatamente concesso se non vengono trovate ACEs rilevanti. Altrimenti, LSASS confronta le ACEs con il SID del principio di sicurezza nel token di accesso per determinare l'idoneità all'accesso.

### **Summarized Process**

- **ACLs:** Definiscono i permessi di accesso tramite DACLs e le regole di audit tramite SACLs.
- **Access Token:** Contiene informazioni su utenti, gruppi e privilegi per una sessione.
- **Access Decision:** Presa confrontando le ACEs del DACL con il token di accesso; le SACLs sono utilizzate per l'audit.

### ACEs

Ci sono **tre principali tipi di Access Control Entries (ACEs)**:

- **Access Denied ACE**: Questa ACE nega esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
- **Access Allowed ACE**: Questa ACE concede esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in un DACL).
- **System Audit ACE**: Posizionata all'interno di un System Access Control List (SACL), questa ACE è responsabile della generazione di log di audit in caso di tentativi di accesso a un oggetto da parte di utenti o gruppi. Documenta se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti critiche**:

1. Il **Security Identifier (SID)** dell'utente o del gruppo (o il loro nome principale in una rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o audit di sistema).
3. **Flags di eredità** che determinano se gli oggetti figli possono ereditare l'ACE dal loro genitore.
4. Un [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valore a 32 bit che specifica i diritti concessi all'oggetto.

La determinazione dell'accesso viene condotta esaminando sequenzialmente ogni ACE fino a:

- Un **Access-Denied ACE** nega esplicitamente i diritti richiesti a un fiduciario identificato nel token di accesso.
- **Access-Allowed ACE(s)** concedono esplicitamente tutti i diritti richiesti a un fiduciario nel token di accesso.
- Dopo aver controllato tutte le ACEs, se qualche diritto richiesto **non è stato esplicitamente consentito**, l'accesso è implicitamente **negato**.

### Order of ACEs

Il modo in cui le **ACEs** (regole che dicono chi può o non può accedere a qualcosa) sono messe in una lista chiamata **DACL** è molto importante. Questo perché una volta che il sistema concede o nega l'accesso in base a queste regole, smette di guardare il resto.

C'è un modo migliore per organizzare queste ACEs, e si chiama **"ordine canonico."** Questo metodo aiuta a garantire che tutto funzioni senza intoppi e in modo equo. Ecco come funziona per sistemi come **Windows 2000** e **Windows Server 2003**:

- Prima, metti tutte le regole fatte **specificamente per questo elemento** prima di quelle che provengono da altrove, come una cartella genitore.
- In quelle regole specifiche, metti quelle che dicono **"no" (nega)** prima di quelle che dicono **"sì" (consenti)**.
- Per le regole che provengono da altrove, inizia con quelle della **fonte più vicina**, come il genitore, e poi torna indietro da lì. Ancora una volta, metti **"no"** prima di **"sì."**

Questa configurazione aiuta in due modi principali:

- Garantisce che se c'è un **"no"** specifico, venga rispettato, indipendentemente da quali altre regole **"sì"** ci siano.
- Permette al proprietario di un elemento di avere l'**ultima parola** su chi può entrare, prima che entrino in gioco eventuali regole da cartelle genitore o più lontane.

Facendo le cose in questo modo, il proprietario di un file o di una cartella può essere molto preciso su chi ottiene accesso, assicurandosi che le persone giuste possano entrare e quelle sbagliate no.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Quindi, questo **"ordine canonico"** riguarda tutto il garantire che le regole di accesso siano chiare e funzionino bene, mettendo prima le regole specifiche e organizzando tutto in modo intelligente.

### GUI Example

[**Esempio da qui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Questa è la scheda di sicurezza classica di una cartella che mostra l'ACL, DACL e ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Se clicchiamo sul **pulsante Avanzate**, otterremo più opzioni come l'eredità:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

E se aggiungi o modifichi un Principale di Sicurezza:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

E infine abbiamo il SACL nella scheda di Audit:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Quando gestiamo l'accesso alle risorse, come una cartella, utilizziamo liste e regole note come Access Control Lists (ACLs) e Access Control Entries (ACEs). Queste definiscono chi può o non può accedere a determinati dati.

#### Denying Access to a Specific Group

Immagina di avere una cartella chiamata Cost, e vuoi che tutti possano accedervi tranne un team di marketing. Impostando correttamente le regole, possiamo assicurarci che al team di marketing venga esplicitamente negato l'accesso prima di consentire a tutti gli altri. Questo viene fatto posizionando la regola per negare l'accesso al team di marketing prima della regola che consente l'accesso a tutti.

#### Allowing Access to a Specific Member of a Denied Group

Diciamo che Bob, il direttore marketing, ha bisogno di accesso alla cartella Cost, anche se il team di marketing in generale non dovrebbe avere accesso. Possiamo aggiungere una regola specifica (ACE) per Bob che gli concede accesso, e posizionarla prima della regola che nega l'accesso al team di marketing. In questo modo, Bob ottiene accesso nonostante la restrizione generale sul suo team.

#### Understanding Access Control Entries

Le ACEs sono le singole regole in un'ACL. Identificano utenti o gruppi, specificano quali accessi sono consentiti o negati e determinano come queste regole si applicano agli elementi secondari (ereditarietà). Ci sono due principali tipi di ACEs:

- **Generic ACEs**: Queste si applicano in modo ampio, influenzando tutti i tipi di oggetti o distinguendo solo tra contenitori (come cartelle) e non contenitori (come file). Ad esempio, una regola che consente agli utenti di vedere il contenuto di una cartella ma non di accedere ai file al suo interno.
- **Object-Specific ACEs**: Queste forniscono un controllo più preciso, consentendo di impostare regole per tipi specifici di oggetti o persino per singole proprietà all'interno di un oggetto. Ad esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono ma non le proprie ore di accesso.

Ogni ACE contiene informazioni importanti come a chi si applica la regola (utilizzando un Security Identifier o SID), cosa consente o nega la regola (utilizzando un access mask) e come viene ereditata da altri oggetti.

#### Key Differences Between ACE Types

- **Generic ACEs** sono adatte per scenari di controllo accessi semplici, dove la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti all'interno di un contenitore.
- **Object-Specific ACEs** sono utilizzate per scenari più complessi, specialmente in ambienti come Active Directory, dove potrebbe essere necessario controllare l'accesso a proprietà specifiche di un oggetto in modo diverso.

In sintesi, ACLs e ACEs aiutano a definire controlli di accesso precisi, assicurando che solo gli individui o i gruppi giusti abbiano accesso a informazioni o risorse sensibili, con la possibilità di personalizzare i diritti di accesso fino al livello delle singole proprietà o tipi di oggetti.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: Tre tipi di ACE generici che sono attaccati a tutti gli oggetti sicuri. Tre tipi di ACE specifici per oggetti che possono verificarsi per oggetti di Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Insieme di flag bit che controllano l'ereditarietà e l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valore a 32 bit i cui bit corrispondono ai diritti di accesso per l'oggetto. I bit possono essere impostati sia su che giù, ma il significato dell'impostazione dipende dal tipo di ACE. Ad esempio, se il bit che corrisponde al diritto di leggere i permessi è attivato, e il tipo di ACE è Nega, l'ACE nega il diritto di leggere i permessi dell'oggetto. Se lo stesso bit è attivato ma il tipo di ACE è Consenti, l'ACE concede il diritto di leggere i permessi dell'oggetto. Maggiori dettagli sull'Access mask appaiono nella tabella successiva. |
| SID         | Identifica un utente o un gruppo il cui accesso è controllato o monitorato da questo ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Diritti di Accesso Specifici per Oggetto      | Leggi dati, Esegui, Aggiungi dati           |
| 16 - 22     | Diritti di Accesso Standard             | Elimina, Scrivi ACL, Scrivi Proprietario            |
| 23          | Può accedere alla sicurezza ACL            |                                           |
| 24 - 27     | Riservato                           |                                           |
| 28          | Generico TUTTI (Leggi, Scrivi, Esegui) | Tutto sotto                          |
| 29          | Generico Esegui                    | Tutte le cose necessarie per eseguire un programma |
| 30          | Generico Scrivi                      | Tutte le cose necessarie per scrivere in un file   |
| 31          | Generico Leggi                       | Tutte le cose necessarie per leggere un file       |

## References

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}
