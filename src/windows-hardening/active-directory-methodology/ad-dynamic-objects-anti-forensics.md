# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meccanismi e nozioni di base sul rilevamento

- Qualsiasi oggetto creato con la classe ausiliaria **`dynamicObject`** acquisisce **`entryTTL`** (conto alla rovescia in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando **`entryTTL`** raggiunge 0, il **Garbage Collector** lo elimina senza tombstone/recycle-bin, cancellando il creatore e i timestamp e impedendone il recupero.
- **`entryTTL` è un attributo operativo/constructed**: richiederlo esplicitamente nelle query LDAP. Il TTL può essere rinnovato aggiornando **`entryTTL`** prima della scadenza oppure tramite l'OID LDAP di refresh del TTL **`1.3.6.1.4.1.1466.101.119.1`**.
- I valori minimi/predefiniti del TTL sono applicati in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** come TTL predefinito e **900s** come TTL minimo valido predefinito; entrambi supportano valori da **1s a 1y**. Gli oggetti dinamici non sono supportati nelle partizioni Configuration/Schema.
- Non esiste alcuna conversione da statico a dinamico e, dopo la scadenza, non viene attraversata alcuna fase di tombstone. I team IR non possono fare affidamento sui controlli degli oggetti eliminati o sul Recycle Bin; devono acquisire l'oggetto live e i relativi metadati prima che il GC lo rimuova.
- Il refresh è **sensibile alla replica**: se il TTL viene rinnovato troppo vicino alla scadenza, un'altra replica writable o il GC possono comunque eliminare localmente l'oggetto prima che il refresh venga replicato. TTL molto brevi funzionano quindi meglio quando l'attacker sa quale DC gestirà l'abuso, mentre i defender dovrebbero interrogare **tutti i naming contexts / tutte le repliche** durante il triage.
- L'eliminazione può subire un ritardo di alcuni minuti sui DC con uptime breve (<24h), lasciando una stretta finestra di risposta per interrogare/effettuare il backup degli attributi. Rilevare il fenomeno generando **alert sui nuovi oggetti che contengono `entryTTL`/`msDS-Entry-Time-To-Die`** e correlando tali eventi con SID orfani/link interrotti.<sup>[[1]](#references)</sup>

## Enumerazione rapida / Live Triage

- Interrogare **tutti i `namingContexts` da RootDSE**, non solo il domain NC. L'abuso di oggetti dinamici può trovarsi in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o nelle application partitions.
- Quando l'oggetto è ancora attivo, eseguire immediatamente il dump dei **replication metadata** e di tutti gli attributi collegati/ACL. Dopo la scadenza, potrebbero rimanere solo **valori `gPLink` interrotti, SID orfani o risposte DNS memorizzate nella cache**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion con computer auto-eliminanti

- Il valore predefinito **`ms-DS-MachineAccountQuota` = 10** consente a qualsiasi utente autenticato di creare computer. Aggiungendo `dynamicObject` durante la creazione, il computer può auto-eliminarsi e **liberare lo slot della quota**, cancellando al contempo le prove.
- Modifica di Powermad all'interno di `New-MachineAccount` (elenco objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se il TTL richiesto è **inferiore a `DynamicObjectMinTTL`**, è previsto un adeguamento o un rifiuto lato server, a seconda del percorso di creazione; in molti domini il limite effettivo è **900s** e il valore di fallback/predefinito resta **86400s**. ADUC potrebbe nascondere `entryTTL`, ma le query LDP/LDAP lo rivelano.
- Finché l'oggetto esiste, i defender possono comunque risalire al creatore non privilegiato tramite **`msDS-CreatorSID`** sull'oggetto computer. Una volta scaduto il computer dinamico, tale attribuzione scompare insieme all'oggetto.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Creare un **dynamic security group**, quindi impostare il **`primaryGroupID`** di un utente sul RID di quel gruppo per ottenere una membership effettiva che **non appare in `memberOf`**, ma viene rispettata da Kerberos e dagli access token.<sup>[[1]](#references)</sup>
- La scadenza del TTL **elimina il gruppo nonostante la protezione contro l'eliminazione del gruppo primario**, lasciando l'utente con un **`primaryGroupID`** corrotto che punta a un RID inesistente e senza un tombstone che permetta di investigare come sia stato concesso il privilegio.
- La reportistica dipende dallo strumento: **`Get-ADGroupMember` / `net group`** generalmente risolvono la membership derivata dal gruppo primario, mentre **`memberOf`** e **`Get-ADGroup -Properties member`** non lo fanno. Per ulteriori tecniche relative a **`primaryGroupID`**, consulta [questa pagina su DCShadow e l'abuso di PGID](dcshadow.md).
- Per gli obiettivi **non protetti da AdminSDHolder**, gli attaccanti possono combinare il trucco del dynamic group con un **DACL deny sulla lettura di `primaryGroupID`** (o dell'attributo `member` del gruppo) per nascondere il collegamento a molti workflow LDAP/PowerShell anche prima della scadenza del gruppo.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Aggiungere ACE per un **dynamic user/group di breve durata** a **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL, il SID diventa **irrisolvibile (“Unknown SID”)** nell'ACL del template e **SDProp (~60 min)** propaga tale SID orfano a tutti gli oggetti Tier-0 protetti.
- Le analisi forensi perdono l'attribuzione perché il principal non esiste più (nessun DN dell'oggetto eliminato). Monitorare la presenza di **nuovi principal dinamici + improvvisi SID orfani negli ACL di AdminSDHolder/degli oggetti privilegiati**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution con prove auto-distruttive

- Creare un oggetto **`groupPolicyContainer` dinamico** con un **`gPCFileSysPath`** malevolo (ad esempio una SMB share à la GPODDITY) e collegarlo tramite **`gPLink`** a una OU target.
- I client elaborano la policy e scaricano il contenuto dalla SMB dell'attaccante. Quando il TTL scade, l'oggetto GPO (e **`gPCFileSysPath`**) scompare; rimane soltanto un **GUID `gPLink` non valido**, rimuovendo dalle directory LDAP le prove del payload eseguito.
- Questo è operativamente più pulito della pulizia classica in stile **GPODDITY**: invece di ripristinare manualmente il `gPCFileSysPath` originale, AD rimuove automaticamente il GPC malevolo allo scadere del timer.<sup>[[1]](#references)</sup>

## Reindirizzamento DNS AD-Integrated effimero

- I record DNS AD sono oggetti **`dnsNode`** nelle partizioni **DomainDnsZones/ForestDnsZones**. Crearli come **dynamic objects** consente un reindirizzamento temporaneo degli host (credential capture/MITM). I client memorizzano nella cache la risposta A/AAAA malevola; in seguito il record si auto-elimina, lasciando la zone pulita (potrebbe essere necessario ricaricare la zone in DNS Manager per aggiornare la visualizzazione).
- Rilevamento: generare un alert per **qualsiasi record DNS contenente `dynamicObject`/`entryTTL`** tramite log di replica/eventi; i record transitori compaiono raramente nei log DNS standard.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Nota)

- La delta sync di Entra Connect si basa sui **tombstone** per rilevare le eliminazioni. Un **utente on-prem dinamico** può essere sincronizzato con Entra ID, scadere ed essere eliminato senza tombstone: la delta sync non rimuoverà l'account cloud, lasciando un **utente Entra attivo orfano** finché non viene eseguita una **initial/full sync** o non viene forzata una pulizia manuale nel cloud.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
