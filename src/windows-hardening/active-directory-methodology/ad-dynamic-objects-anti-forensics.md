# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meccanismi e nozioni di base sul rilevamento

- Qualsiasi oggetto creato con la classe ausiliaria **`dynamicObject`** acquisisce **`entryTTL`** (conto alla rovescia in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando `entryTTL` raggiunge 0 **e l'oggetto non ha discendenti**, il Garbage Collector lo elimina senza tombstone/recycle-bin, cancellando il creatore e i timestamp e impedendone il recupero.<sup>[[4]](#references)</sup>
- **`entryTTL` è un attributo operational/constructed**: richiederlo esplicitamente nelle query LDAP. Il TTL può essere rinnovato aggiornando `entryTTL` prima della scadenza oppure tramite l'OID LDAP per il refresh del TTL **`1.3.6.1.4.1.1466.101.119.1`**.
- Il TTL minimo/predefinito sono AVA a livello di forest in **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` e `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft documenta **86400s** come TTL predefinito e **900s** come TTL minimo valido predefinito; l'intervallo dello schema di `entryTTL` è **1–31557600s** (un secondo fino a un anno).<sup>[[3]](#references)</sup> Gli oggetti dinamici sono **unsupported nelle partizioni Configuration/Schema**.
- Non esiste alcuna conversione da statico a dinamico e, dopo la scadenza, non esiste alcuna fase di tombstone. I team IR non possono fare affidamento sui controlli degli oggetti eliminati o sul Recycle Bin; devono acquisire l'oggetto live e i relativi metadati prima che il GC lo rimuova.
- Il refresh è **sensibile alla replica**: se il TTL viene rinnovato troppo vicino alla scadenza, un'altra replica writable o il GC potrebbero comunque eliminare localmente l'oggetto prima che il refresh venga replicato. TTL molto brevi funzionano quindi meglio quando l'attacker sa quale DC gestirà l'abuso, mentre i defender dovrebbero interrogare **tutti i naming contexts / tutte le repliche** durante il triage.
- L'eliminazione può ritardare di alcuni minuti sui DC con uptime ridotto (<24h), lasciando una stretta finestra di risposta per interrogare/effettuare il backup degli attributi. Rilevare il fenomeno generando **alert sui nuovi oggetti che contengono `entryTTL`/`msDS-Entry-Time-To-Die`** e correlando questi eventi con SID orfani/link interrotti.<sup>[[1]](#references)</sup>

### Grafo delle scadenze e casi limite della pulizia dei riferimenti

- Ogni discendente al di sotto di un oggetto dinamico deve essere a sua volta dinamico. Un parent dinamico scaduto viene sottoposto a garbage collection solo dopo essere diventato una leaf; se un discendente ha un `msDS-Entry-Time-To-Die` successivo, il DC posticipa la scadenza del parent oltre la scadenza massima dei discendenti. Di conseguenza, un subtree dinamico writable può **mantenere/estendere un parent che sembra prossimo a scomparire**: enumerare l'intero subtree e non usare l'`entryTTL` osservato del parent come deadline per la pulizia.<sup>[[4]](#references)</sup>
- La pulizia alla scadenza è **consapevole dei schema-link**. Le repliche rimuovono i valori degli attributi linked che fanno riferimento all'oggetto dinamico eliminato, ma conservano i valori non linked. È previsto che i normali riferimenti di membership forward/back-link vengano ripuliti, mentre i riferimenti integer/SID/stringa, come `primaryGroupID`, i SID incorporati in `nTSecurityDescriptor` o il testo di `gPLink`, possano sopravvivere come residui forensi.<sup>[[4]](#references)</sup>

## Enumerazione rapida / Live Triage

- Interrogare **tutti i `namingContexts` da RootDSE**, non solo il domain NC. L'abuso di oggetti dinamici può trovarsi in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o nelle application partitions.
- Finché l'oggetto è ancora live, eseguire immediatamente il dump dei **replication metadata** e di tutti gli attributi linked/ACL. Dopo la scadenza potrebbero rimanere soltanto **valori `gPLink` interrotti, SID orfani o risposte DNS in cache**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion con Computer Self-Deleting

- Il valore predefinito di **`ms-DS-MachineAccountQuota` = 10** consente a qualsiasi utente autenticato di creare computer. Aggiungere `dynamicObject` durante la creazione fa sì che il computer si elimini automaticamente e **liberi lo slot della quota**, cancellando al contempo le tracce.
- Modifica di Powermad all’interno di `New-MachineAccount` (elenco objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se il TTL richiesto è **inferiore a `DynamicObjectMinTTL`**, aspettarsi un adattamento o un rifiuto lato server, a seconda del percorso di creazione; in molti domini il limite effettivo è di **900s** e il fallback/valore predefinito resta **86400s**. ADUC potrebbe nascondere `entryTTL`, ma le query LDP/LDAP lo rivelano.
- Finché l’oggetto esiste, i defender possono ancora recuperare il creatore non privilegiato da **`msDS-CreatorSID`** sull’oggetto computer. Una volta scaduto il computer dinamico, tale attribuzione scompare insieme all’oggetto.<sup>[[1]](#references)</sup>

## Appartenenza Stealth al Primary Group

- Creare un **dynamic security group**, quindi impostare il **`primaryGroupID`** di un utente sul RID di quel gruppo per ottenere un’appartenenza effettiva che **non compare in `memberOf`**, ma viene rispettata da Kerberos e dagli access token.<sup>[[1]](#references)</sup>
- La scadenza del TTL **elimina il gruppo nonostante la protezione dall’eliminazione del primary group**, lasciando l’utente con un **`primaryGroupID`** corrotto che punta a un RID inesistente e senza tombstone per investigare come sia stato concesso il privilegio.
- La generazione dei report dipende dallo strumento: **`Get-ADGroupMember` / `net group`** normalmente risolvono l’appartenenza derivata dal primary group, mentre **`memberOf`** e **`Get-ADGroup -Properties member`** no. Per ulteriori tecniche relative a **`primaryGroupID`**, vedere [questa pagina su DCShadow e l’abuso di PGID](dcshadow.md).
- Per i target **non protetti da AdminSDHolder**, gli attacker possono combinare la tecnica del dynamic group con un **DACL deny sulla lettura di `primaryGroupID`** (o dell’attributo `member` del gruppo) per nascondere il collegamento a molti workflow LDAP/PowerShell anche prima della scadenza del gruppo.<sup>[[2]](#references)</sup>

## Inquinamento degli Orphan-SID di AdminSDHolder

- Aggiungere ACE per un **dynamic user/group** di breve durata a **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL, il SID diventa **irrisolvibile (“Unknown SID”)** nella ACL del template e **SDProp (~60 min)** propaga tale SID orfano su tutti gli oggetti Tier-0 protetti.
- Le attività forensi perdono l’attribuzione perché il principal non esiste più (nessun DN dell’oggetto eliminato). Monitorare la presenza di **nuovi principal dinamici + SID orfani improvvisi su AdminSDHolder/ACL privilegiate**.<sup>[[1]](#references)</sup>

## Esecuzione di GPO dinamiche con Evidence Self-Destructing

- Creare un oggetto **`groupPolicyContainer` dinamico** con un **`gPCFileSysPath`** malevolo (ad esempio una SMB share à la GPODDITY) e collegarlo tramite **`gPLink`** a una OU target.
- I client elaborano la policy e recuperano il contenuto dalla SMB dell’attacker. Quando il TTL scade, l’oggetto GPO (e **`gPCFileSysPath`**) scompare; rimane solo un GUID **`gPLink`** non valido, rimuovendo da LDAP le prove del payload eseguito.
- Questo è operativamente più pulito della pulizia classica in stile **GPODDITY**: invece di ripristinare manualmente il **`gPCFileSysPath`** originale, AD rimuove automaticamente il GPC malevolo allo scadere del timer.<sup>[[1]](#references)</sup> Vedere [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) per i dettagli sul protocollo e sugli strumenti, anziché duplicarli qui.

## Reindirizzamento DNS AD-Integrated Effimero

- I record DNS AD sono oggetti **`dnsNode`** in **DomainDnsZones/ForestDnsZones**. Crearli come **dynamic objects** consente un reindirizzamento temporaneo degli host (credential capture/MITM). I client memorizzano nella cache la risposta A/AAAA malevola; in seguito il record si elimina automaticamente, lasciando la zone pulita (potrebbe essere necessario ricaricare la zone in DNS Manager per aggiornare la visualizzazione).
- Rilevamento: generare un alert per **qualsiasi record DNS che contenga `dynamicObject`/`entryTTL`** tramite i replication/event logs; i record transitori raramente compaiono nei log DNS standard.<sup>[[1]](#references)</sup>

## Lacuna del Delta-Sync Ibrido di Entra ID (Nota)

- La delta sync di Entra Connect si basa sui **tombstone** per rilevare le eliminazioni. Un **utente on-prem dinamico** può essere sincronizzato con Entra ID, scadere ed essere eliminato senza tombstone: la delta sync non rimuoverà l’account cloud, lasciando un **utente Entra attivo orfano** finché non viene eseguita una **initial/full sync** o forzata una pulizia manuale nel cloud.<sup>[[1]](#references)</sup>



## References

- [1] [Oggetti dinamici in Active Directory: la minaccia stealth](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Avventure nel comportamento, nella reportistica e nello sfruttamento dei Primary Group](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configurazione dei limiti TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Requisiti di DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
