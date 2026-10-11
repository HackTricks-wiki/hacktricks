# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Una Access Control List (ACL) è composta da un insieme ordinato di Access Control Entry (ACE) che definiscono le protezioni applicate a un oggetto e alle sue proprietà. In sostanza, una ACL specifica quali azioni sono consentite o negate a determinati principal di sicurezza (utenti o gruppi) su un dato oggetto.

Esistono due tipi di ACL:

- **Discretionary Access Control List (DACL):** Specifica quali utenti e gruppi hanno o non hanno accesso a un oggetto.
- **System Access Control List (SACL):** Regola la verifica dei tentativi di accesso a un oggetto.

Durante l'accesso a un file, il sistema confronta il descrittore di sicurezza dell'oggetto con il token di accesso dell'utente per determinare se concedere l'accesso e in quale misura, in base alle ACE.<sup>[[1]](#references)</sup>

Se una directory padre concede Full Control ma un file figlio nega la lettura, controlla separatamente la DACL effettiva, il proprietario e l'ereditarietà del **file figlio**. Per modificare la DACL del file è necessario disporre di `WRITE_DAC` sul file oppure del diritto di proprietario applicabile; [Microsoft definisce `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) e [documenta l'accesso implicito del proprietario](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Le autorizzazioni della directory padre, da sole, non garantiscono che sia possibile leggere il file figlio o modificarne la DACL.

### **Componenti principali**

- **DACL:** Contiene ACE che concedono o negano agli utenti e ai gruppi le autorizzazioni di accesso a un oggetto. È essenzialmente la ACL principale che definisce i diritti di accesso.
- **SACL:** Usata per verificare gli accessi agli oggetti; le ACE definiscono i tipi di accesso da registrare nel Security Event Log. Può essere preziosa per rilevare tentativi di accesso non autorizzato o per risolvere problemi di accesso.<sup>[[1]](#references)</sup>

### **Interazione del sistema con le ACL**

A ogni sessione utente è associato un token di accesso che contiene informazioni di sicurezza pertinenti alla sessione, incluse identità dell'utente e dei gruppi e privilegi. Il token include anche un logon SID che identifica in modo univoco la sessione.

La Local Security Authority (LSASS) elabora le richieste di accesso agli oggetti esaminando la DACL alla ricerca di ACE corrispondenti al principal di sicurezza che sta tentando l'accesso. Se non vengono trovate ACE pertinenti, l'accesso viene concesso immediatamente. In caso contrario, LSASS confronta le ACE con il SID del principal di sicurezza presente nel token di accesso per determinare se l'accesso è consentito.<sup>[[1]](#references)</sup>

### **Riepilogo del processo**

- **ACL:** Definiscono le autorizzazioni di accesso tramite le DACL e le regole di audit tramite le SACL.
- **Token di accesso:** Contiene le informazioni su utente, gruppi e privilegi di una sessione.
- **Decisione di accesso:** Viene presa confrontando le ACE della DACL con il token di accesso; le SACL sono usate per l'audit.<sup>[[1]](#references)</sup>

### ACE

Esistono **tre tipi principali di Access Control Entry (ACE)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Questa ACE nega esplicitamente l'accesso a un oggetto a utenti o gruppi specificati (in una DACL).
- **Access Allowed ACE**: Questa ACE concede esplicitamente l'accesso a un oggetto a utenti o gruppi specificati (in una DACL).
- **System Audit ACE**: Inserita in una System Access Control List (SACL), questa ACE genera log di audit quando utenti o gruppi tentano di accedere a un oggetto. Registra se l'accesso è stato consentito o negato e la natura dell'accesso.

Ogni ACE ha **quattro componenti fondamentali**:<sup>[[1]](#references)</sup>

1. Il **Security Identifier (SID)** dell'utente o del gruppo (oppure il nome del principal nella rappresentazione grafica).
2. Un **flag** che identifica il tipo di ACE (accesso negato, consentito o audit di sistema).
3. **Flag di ereditarietà** che determinano se gli oggetti figlio possono ereditare l'ACE dal padre.
4. Una [**maschera di accesso**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valore a 32 bit che specifica i diritti concessi sull'oggetto.

La determinazione dell'accesso avviene esaminando in sequenza ogni ACE finché:<sup>[[1]](#references)</sup>

- Una **Access-Denied ACE** nega esplicitamente i diritti richiesti a un trustee identificato nel token di accesso.
- Una o più **Access-Allowed ACE** concedono esplicitamente tutti i diritti richiesti a un trustee presente nel token di accesso.
- Dopo aver esaminato tutte le ACE, se un diritto richiesto **non è stato esplicitamente consentito**, l'accesso viene **negato** implicitamente.

### Ordine delle ACE

Il modo in cui le **ACE** (regole che stabiliscono chi può o non può accedere a qualcosa) sono disposte nella lista chiamata **DACL** è molto importante. Infatti, una volta che il sistema concede o nega l'accesso in base a queste regole, smette di esaminare le altre.<sup>[[1]](#references)</sup>

Esiste un modo consigliato per organizzare queste ACE, detto **"canonical order"**. Questo metodo aiuta a far funzionare tutto in modo corretto ed equo. Ecco come si applica a sistemi come **Windows 2000** e **Windows Server 2003**:

- Prima, inserisci tutte le regole create **specificamente per questo elemento**, prima di quelle ereditate da altre posizioni, ad esempio da una cartella padre.
- Tra queste regole specifiche, inserisci prima quelle che dicono **"no" (deny)** e poi quelle che dicono **"sì" (allow)**.
- Per le regole ereditate da altre posizioni, comincia da quelle provenienti dalla **fonte più vicina**, ad esempio la cartella padre, e poi procedi risalendo la gerarchia. Anche in questo caso, inserisci prima **"no"** e poi **"sì."**

Questa impostazione offre due vantaggi importanti:

- Fa sì che un **"no"** specifico venga rispettato, indipendentemente dalle altre regole **"sì"**.
- Permette al proprietario di un elemento di avere **l'ultima parola** su chi può accedervi, prima che entrino in gioco le regole delle cartelle padre o di altre posizioni più lontane.

Organizzando le regole in questo modo, il proprietario di un file o di una cartella può definire con precisione chi può accedervi, assicurandosi che le persone autorizzate possano farlo e quelle non autorizzate no.

![Diagramma dell'ordine delle voci di controllo degli accessi NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Questo **"canonical order"** serve quindi a rendere chiare ed efficaci le regole di accesso, mettendo al primo posto quelle specifiche e organizzando tutto in modo razionale.

### Esempio di GUI

[**Esempio disponibile qui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Questa è la classica scheda di sicurezza di una cartella, che mostra ACL, DACL e ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Se facciamo clic sul **pulsante Advanced**, vedremo altre opzioni, come l'ereditarietà:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

E se aggiungiamo o modifichiamo un Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Infine, nella scheda Auditing troviamo la SACL:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Spiegazione semplificata del controllo degli accessi

Per gestire l'accesso alle risorse, come una cartella, usiamo liste e regole chiamate Access Control List (ACL) e Access Control Entry (ACE). Queste definiscono chi può o non può accedere a determinati dati.<sup>[[1]](#references)</sup>

#### Negare l'accesso a un gruppo specifico

Immagina di avere una cartella chiamata Cost e di voler consentire l'accesso a tutti tranne che al team marketing. Configurando correttamente le regole, possiamo negare esplicitamente l'accesso al team marketing prima di consentirlo a tutti gli altri. Per farlo, si posiziona la regola che nega l'accesso al team marketing prima di quella che lo consente a tutti.

#### Consentire l'accesso a un membro specifico di un gruppo a cui è stato negato l'accesso

Supponiamo che Bob, il direttore marketing, debba accedere alla cartella Cost, anche se in generale il team marketing non dovrebbe potervi accedere. Possiamo aggiungere una regola specifica (ACE) che concede l'accesso a Bob e posizionarla prima della regola che nega l'accesso al team marketing. In questo modo, Bob ottiene l'accesso nonostante la restrizione generale applicata al suo team.

#### Comprendere le Access Control Entry

Le ACE sono le singole regole di una ACL. Identificano utenti o gruppi, specificano quali accessi sono consentiti o negati e determinano come le regole si applicano agli elementi secondari (ereditarietà). Esistono due tipi principali di ACE:

- **ACE generiche**: Si applicano in modo ampio, interessando tutti i tipi di oggetti oppure distinguendo solo tra contenitori (come le cartelle) e oggetti non contenitore (come i file). Per esempio, una regola che consente agli utenti di visualizzare il contenuto di una cartella, ma non di accedere ai file al suo interno.
- **ACE specifiche per oggetto**: Consentono un controllo più preciso, permettendo di impostare regole per tipi specifici di oggetti o persino per singole proprietà di un oggetto. Per esempio, in una directory di utenti, una regola potrebbe consentire a un utente di aggiornare il proprio numero di telefono, ma non i propri orari di accesso.

Ogni ACE contiene informazioni importanti, come a chi si applica la regola (tramite un Security Identifier o SID), cosa consente o nega (tramite una maschera di accesso) e come viene ereditata da altri oggetti.

#### Differenze principali tra i tipi di ACE

- Le **ACE generiche** sono adatte a scenari di controllo degli accessi semplici, in cui la stessa regola si applica a tutti gli aspetti di un oggetto o a tutti gli oggetti contenuti in un contenitore.
- Le **ACE specifiche per oggetto** si usano in scenari più complessi, soprattutto in ambienti come Active Directory, dove potrebbe essere necessario controllare in modo diverso l'accesso a proprietà specifiche di un oggetto.

In sintesi, ACL e ACE consentono di definire controlli di accesso precisi, assicurando che solo le persone o i gruppi autorizzati possano accedere a informazioni o risorse sensibili e permettendo di adattare i diritti di accesso fino al livello delle singole proprietà o dei tipi di oggetto.

### Struttura di una Access Control Entry

| Campo ACE   | Descrizione                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Flag che indica il tipo di ACE. Windows 2000 e Windows Server 2003 supportano sei tipi di ACE: tre tipi generici, applicabili a tutti gli oggetti a protezione avanzata, e tre tipi specifici per oggetto, che possono essere presenti negli oggetti di Active Directory.                                                                                                                                                                                                                                                            |
| Flag        | Insieme di flag di bit che controllano l'ereditarietà e l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Dimensione  | Numero di byte di memoria allocati per l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Maschera di accesso | Valore a 32 bit i cui bit corrispondono ai diritti di accesso sull'oggetto. I bit possono essere attivati o disattivati, ma il significato dell'impostazione dipende dal tipo di ACE. Per esempio, se il bit corrispondente al diritto di leggere le autorizzazioni è attivato e il tipo di ACE è Deny, l'ACE nega il diritto di leggere le autorizzazioni dell'oggetto. Se lo stesso bit è attivato e il tipo di ACE è Allow, l'ACE concede il diritto di leggere le autorizzazioni dell'oggetto. La tabella successiva fornisce ulteriori dettagli sulla maschera di accesso. |
| SID         | Identifica un utente o un gruppo il cui accesso è controllato o monitorato da questa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Struttura della maschera di accesso

| Bit (intervallo) | Significato                       | Descrizione/esempio                     |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Diritti di accesso specifici per oggetto | Lettura dei dati, esecuzione, aggiunta di dati |
| 16 - 22     | Diritti di accesso standard        | Eliminazione, scrittura ACL, scrittura proprietario |
| 23          | Può accedere alla security ACL     |                                           |
| 24 - 27     | Riservato                          |                                           |
| 28          | Generic ALL (lettura, scrittura, esecuzione) | Tutto quanto indicato sotto               |
| 29          | Generic Execute                   | Tutto ciò che serve per eseguire un programma |
| 30          | Generic Write                     | Tutto ciò che serve per scrivere in un file |
| 31          | Generic Read                      | Tutto ciò che serve per leggere un file |

## References

- [1] [Come usa il sistema le ACL - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL e ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
