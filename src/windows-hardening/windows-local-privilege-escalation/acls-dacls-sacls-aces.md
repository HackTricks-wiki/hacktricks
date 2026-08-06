# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Una Access Control List (ACL) è costituita da un insieme ordinato di Access Control Entries (ACEs) che definiscono le protezioni per un oggetto e le sue proprietà. In sostanza, una ACL definisce quali azioni eseguite da quali security principal (utenti o gruppi) sono consentite o negate su un determinato oggetto.

Esistono due tipi di ACL:

- **Discretionary Access Control List (DACL):** specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
- **System Access Control List (SACL):** governa l'auditing dei tentativi di accesso a un oggetto.

Il processo di accesso a un file prevede che il sistema controlli il security descriptor dell'oggetto rispetto all'access token dell'utente, per determinare se l'accesso debba essere concesso e in quale misura, sulla base delle ACE.<sup>[[1]](#references)</sup>

### **Componenti principali**

- **DACL:** contiene ACE che concedono o negano autorizzazioni di accesso a utenti e gruppi per un oggetto. È essenzialmente la ACL principale che determina i diritti di accesso.
- **SACL:** viene utilizzata per l'auditing dell'accesso agli oggetti, dove le ACE definiscono i tipi di accesso da registrare nel Security Event Log. Può essere preziosa per rilevare tentativi di accesso non autorizzati o per risolvere problemi di accesso.<sup>[[1]](#references)</sup>

### **Interazione del sistema con le ACL**

Ogni sessione utente è associata a un access token che contiene informazioni di sicurezza rilevanti per quella sessione, incluse le identità dell'utente e dei gruppi e i privilegi. Questo token include anche un logon SID che identifica univocamente la sessione.

La Local Security Authority (LSASS) elabora le richieste di accesso agli oggetti esaminando la DACL alla ricerca di ACE che corrispondano al security principal che sta tentando l'accesso. L'accesso viene concesso immediatamente se non vengono trovate ACE rilevanti. In caso contrario, LSASS confronta le ACE con il SID del security principal nell'access token per determinare se l'accesso è consentito.<sup>[[1]](#references)</sup>

### **Processo riassunto**

- **ACL:** definiscono le autorizzazioni di accesso tramite le DACL e le regole di auditing tramite le SACL.
- **Access Token:** contiene informazioni sull'utente, sui gruppi e sui privilegi per una sessione.
- **Decisione di accesso:** viene presa confrontando le ACE della DACL con l'access token; le SACL vengono utilizzate per l'auditing.<sup>[[1]](#references)</sup>

### ACE

Esistono **tre tipi principali di Access Control Entries (ACE)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: questa ACE nega esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in una DACL).
- **Access Allowed ACE**: questa ACE concede esplicitamente l'accesso a un oggetto per utenti o gruppi specificati (in una DACL).
- **System Audit ACE**: posizionata all'interno di una System Access Control List (SACL), questa ACE è responsabile della generazione dei log di auditing quando utenti o gruppi tentano di accedere a un oggetto. Documenta se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti fondamentali**:<sup>[[1]](#references)</sup>

1. Il **Security Identifier (SID)** dell'utente o del gruppo (oppure il nome del principal nella rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o system audit).
3. **Inheritance flags** che determinano se gli oggetti figlio possono ereditare l'ACE dal loro oggetto padre.
4. Una [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valore a 32 bit che specifica i diritti concessi sull'oggetto.

La determinazione dell'accesso viene eseguita esaminando sequenzialmente ogni ACE fino a quando:<sup>[[1]](#references)</sup>

- Una **Access-Denied ACE** nega esplicitamente i diritti richiesti a un trustee identificato nell'access token.
- Una o più **Access-Allowed ACE** concedono esplicitamente tutti i diritti richiesti a un trustee presente nell'access token.
- Dopo aver controllato tutte le ACE, se un diritto richiesto **non è stato esplicitamente consentito**, l'accesso viene **negato** implicitamente.

### Ordine delle ACE

Il modo in cui le **ACE** (regole che stabiliscono chi può o non può accedere a qualcosa) vengono inserite in un elenco chiamato **DACL** è molto importante. Questo perché, una volta concesso o negato l'accesso sulla base di queste regole, il sistema smette di esaminare le regole rimanenti.<sup>[[1]](#references)</sup>

Esiste un modo ottimale per organizzare queste ACE, chiamato **"ordine canonico"**. Questo metodo contribuisce a garantire che tutto funzioni in modo regolare e coerente. Ecco come viene applicato in sistemi come **Windows 2000** e **Windows Server 2003**:

- Per prima cosa, inserire tutte le regole create **specificamente per questo elemento** prima di quelle provenienti da un'altra posizione, come una cartella padre.
- Tra queste regole specifiche, inserire prima quelle che dicono **"no" (nega)** e poi quelle che dicono **"sì" (consenti)**.
- Per le regole provenienti da un'altra posizione, iniziare da quelle della **fonte più vicina**, come la cartella padre, e procedere a ritroso. Anche in questo caso, inserire **"no"** prima di **"sì"**.

Questa configurazione offre due vantaggi importanti:

- Garantisce che un **"no"** specifico venga rispettato, indipendentemente dalle altre regole **"sì"** presenti.
- Permette al proprietario di un elemento di avere l'**ultima parola** su chi può accedere, prima che entrino in gioco le regole delle cartelle padre o di altri livelli superiori.

Organizzando le regole in questo modo, il proprietario di un file o di una cartella può definire con precisione chi può accedere, assicurandosi che le persone autorizzate possano entrare e quelle non autorizzate no.

![Diagramma dell'ordinamento delle Access Control Entry NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Pertanto, questo **"ordine canonico"** serve a garantire che le regole di accesso siano chiare e funzionino correttamente, inserendo prima le regole specifiche e organizzando tutto in modo logico.

### Esempio GUI

[**Esempio tratto da qui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Questa è la classica scheda di sicurezza di una cartella che mostra la ACL, la DACL e le ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Facendo clic sul **pulsante Advanced** saranno disponibili ulteriori opzioni, come l'ereditarietà:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

E se si aggiunge o modifica un Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Infine, abbiamo la SACL nella scheda Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Spiegazione semplificata dell'access control

Quando si gestisce l'accesso alle risorse, come una cartella, si utilizzano elenchi e regole noti come Access Control Lists (ACL) e Access Control Entries (ACE). Questi definiscono chi può o non può accedere a determinati dati.<sup>[[1]](#references)</sup>

#### Negare l'accesso a un gruppo specifico

Immagina di avere una cartella chiamata Cost e di voler consentire l'accesso a tutti tranne che a un team di marketing. Configurando correttamente le regole, possiamo assicurarci che al team di marketing venga negato esplicitamente l'accesso prima di consentirlo a tutti gli altri. Questo risultato si ottiene posizionando la regola che nega l'accesso al team di marketing prima della regola che consente l'accesso a tutti.

#### Consentire l'accesso a un membro specifico di un gruppo a cui è stato negato l'accesso

Supponiamo che Bob, il direttore del marketing, abbia bisogno di accedere alla cartella Cost, anche se in generale il team di marketing non dovrebbe averne accesso. Possiamo aggiungere una regola specifica (ACE) per Bob che gli conceda l'accesso e posizionarla prima della regola che nega l'accesso al team di marketing. In questo modo, Bob ottiene l'accesso nonostante la restrizione generale applicata al suo team.

#### Comprendere le Access Control Entries

Le ACE sono le singole regole presenti in una ACL. Identificano utenti o gruppi, specificano quale accesso è consentito o negato e determinano come queste regole si applicano agli elementi subordinati (ereditarietà). Esistono due tipi principali di ACE:

- **Generic ACEs**: si applicano in modo ampio, interessando tutti i tipi di oggetti oppure distinguendo solo tra container (come le cartelle) e oggetti non-container (come i file). Ad esempio, una regola che consente agli utenti di visualizzare il contenuto di una cartella, ma non di accedere ai file al suo interno.
- **Object-Specific ACEs**: forniscono un controllo più preciso, consentendo di impostare regole per tipi specifici di oggetti o persino per singole proprietà all'interno di un oggetto. Ad esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono, ma non i propri orari di accesso.

Ogni ACE contiene informazioni importanti, come il soggetto a cui si applica la regola (utilizzando un Security Identifier o SID), ciò che la regola consente o nega (utilizzando un access mask) e il modo in cui viene ereditata da altri oggetti.

#### Differenze principali tra i tipi di ACE

- Le **Generic ACEs** sono adatte a scenari semplici di access control, in cui la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti all'interno di un container.
- Le **Object-Specific ACEs** vengono utilizzate in scenari più complessi, soprattutto in ambienti come Active Directory, dove potrebbe essere necessario controllare in modo diverso l'accesso a proprietà specifiche di un oggetto.

In sintesi, ACL e ACE contribuiscono a definire controlli di accesso precisi, garantendo che solo le persone o i gruppi autorizzati possano accedere a informazioni o risorse sensibili, con la possibilità di personalizzare i diritti di accesso fino al livello delle singole proprietà o dei tipi di oggetto.

### Struttura di una Access Control Entry

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: tre tipi di ACE generiche associate a tutti gli oggetti che supportano la sicurezza e tre tipi di ACE specifiche per oggetto che possono essere presenti per gli oggetti Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Insieme di flag di bit che controllano l'ereditarietà e l'auditing.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valore a 32 bit i cui bit corrispondono ai diritti di accesso per l'oggetto. I bit possono essere attivati o disattivati, ma il significato dell'impostazione dipende dal tipo di ACE. Ad esempio, se il bit corrispondente al diritto di leggere le autorizzazioni è attivato e il tipo di ACE è Deny, l'ACE nega il diritto di leggere le autorizzazioni dell'oggetto. Se lo stesso bit è attivato ma il tipo di ACE è Allow, l'ACE concede il diritto di leggere le autorizzazioni dell'oggetto. Ulteriori dettagli sull'access mask sono riportati nella tabella successiva. |
| SID         | Identifica un utente o un gruppo il cui accesso è controllato o monitorato da questa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Struttura dell'access mask

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Diritti di accesso specifici dell'oggetto      | Lettura dei dati, esecuzione, aggiunta di dati           |
| 16 - 22     | Diritti di accesso standard             | Eliminazione, scrittura della ACL, scrittura del proprietario            |
| 23          | Può accedere alla security ACL            |                                           |
| 24 - 27     | Riservato                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Tutto ciò che segue                          |
| 29          | Generic Execute                    | Tutto ciò che è necessario per eseguire un programma |
| 30          | Generic Write                      | Tutto ciò che è necessario per scrivere su un file   |
| 31          | Generic Read                       | Tutto ciò che è necessario per leggere un file       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
