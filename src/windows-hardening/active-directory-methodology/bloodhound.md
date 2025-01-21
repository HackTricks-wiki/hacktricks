# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) è parte della Sysinternal Suite:

> Un visualizzatore e editor avanzato di Active Directory (AD). Puoi utilizzare AD Explorer per navigare facilmente in un database AD, definire posizioni preferite, visualizzare proprietà e attributi degli oggetti senza aprire finestre di dialogo, modificare permessi, visualizzare uno schema di oggetto ed eseguire ricerche sofisticate che puoi salvare e rieseguire.

### Snapshots

AD Explorer può creare snapshot di un AD in modo da poterlo controllare offline.\
Può essere utilizzato per scoprire vulnerabilità offline o per confrontare diversi stati del database AD nel tempo.

Ti verranno richiesti il nome utente, la password e la direzione per connetterti (è richiesto un qualsiasi utente AD).

Per prendere uno snapshot di AD, vai su `File` --> `Create Snapshot` e inserisci un nome per lo snapshot.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) è uno strumento che estrae e combina vari artefatti da un ambiente AD. Le informazioni possono essere presentate in un **report** Microsoft Excel **formattato in modo speciale** che include viste riassuntive con metriche per facilitare l'analisi e fornire un quadro olistico dello stato attuale dell'ambiente AD target.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound è un'applicazione web Javascript a pagina singola, costruita su [Linkurious](http://linkurio.us/), compilata con [Electron](http://electron.atom.io/), con un database [Neo4j](https://neo4j.com/) alimentato da un raccoglitore di dati C#.

BloodHound utilizza la teoria dei grafi per rivelare le relazioni nascoste e spesso non intenzionali all'interno di un ambiente Active Directory o Azure. Gli attaccanti possono utilizzare BloodHound per identificare facilmente percorsi di attacco altamente complessi che altrimenti sarebbero impossibili da identificare rapidamente. I difensori possono utilizzare BloodHound per identificare ed eliminare quegli stessi percorsi di attacco. Sia i team blue che red possono utilizzare BloodHound per ottenere facilmente una comprensione più profonda delle relazioni di privilegio in un ambiente Active Directory o Azure.

Quindi, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) è uno strumento straordinario che può enumerare automaticamente un dominio, salvare tutte le informazioni, trovare possibili percorsi di escalation dei privilegi e mostrare tutte le informazioni utilizzando grafici.

BloodHound è composto da 2 parti principali: **ingestors** e **l'applicazione di visualizzazione**.

Gli **ingestors** vengono utilizzati per **enumerare il dominio ed estrarre tutte le informazioni** in un formato che l'applicazione di visualizzazione comprenderà.

L'**applicazione di visualizzazione utilizza neo4j** per mostrare come tutte le informazioni siano correlate e per mostrare diversi modi per escalare i privilegi nel dominio.

### Installazione

Dopo la creazione di BloodHound CE, l'intero progetto è stato aggiornato per facilitare l'uso con Docker. Il modo più semplice per iniziare è utilizzare la sua configurazione Docker Compose preconfigurata.

1. Installa Docker Compose. Questo dovrebbe essere incluso con l'installazione di [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Esegui:
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Trova la password generata casualmente nell'output del terminale di Docker Compose.  
4. In un browser, vai su http://localhost:8080/ui/login. Accedi con il nome utente **`admin`** e una **`password generata casualmente`** che puoi trovare nei log di docker compose.

Dopo questo, dovrai cambiare la password generata casualmente e avrai l'interfaccia nuova pronta, da cui puoi scaricare direttamente gli ingestors.

### SharpHound

Hanno diverse opzioni, ma se vuoi eseguire SharpHound da un PC unito al dominio, utilizzando il tuo utente attuale e estrarre tutte le informazioni, puoi fare:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Puoi leggere di più su **CollectionMethod** e sulla sessione loop [qui](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Se desideri eseguire SharpHound utilizzando credenziali diverse, puoi creare una sessione CMD netonly ed eseguire SharpHound da lì:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Scopri di più su Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) è uno strumento per trovare **vulnerabilità** in Active Directory associate a **Group Policy**. \
È necessario **eseguire group3r** da un host all'interno del dominio utilizzando **qualsiasi utente del dominio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **valuta la postura di sicurezza di un ambiente AD** e fornisce un bel **report** con grafici.

Per eseguirlo, puoi eseguire il file binario `PingCastle.exe` e inizierà una **sessione interattiva** presentando un menu di opzioni. L'opzione predefinita da utilizzare è **`healthcheck`** che stabilirà una **panoramica** di base del **dominio**, e troverà **misconfigurazioni** e **vulnerabilità**.

{{#include ../../banners/hacktricks-training.md}}
