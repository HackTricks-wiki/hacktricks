# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meccaniche & Basi di Detection

- Qualsiasi oggetto creato con la classe ausiliaria **`dynamicObject`** ottiene **`entryTTL`** (conto alla rovescia in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando `entryTTL` raggiunge 0 il **Garbage Collector lo elimina senza tombstone/recycle-bin**, cancellando creatore/timestamp e bloccando il recovery.
- **`entryTTL` è un attributo operazionale/constructed**: richiedilo esplicitamente nelle query LDAP. Il TTL può essere rinnovato sia aggiornando `entryTTL` prima della scadenza, sia tramite l'OID LDAP TTL refresh **`1.3.6.1.4.1.1466.101.119.1`**.
- Il TTL min/default è applicato in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** come TTL default e **900s** come TTL minimo valido default; entrambi supportano **1s–1y**. Gli oggetti dinamici sono **non supportati nelle partizioni Configuration/Schema**.
- Non esiste conversione **static→dynamic** e non c'è una fase tombstone dopo la scadenza. I team IR non possono fare affidamento sui controlli per oggetti eliminati o sul Recycle Bin; devono acquisire l'oggetto/metadata live prima che il GC lo rimuova.
- Il refresh è **sensibile alle replica**: se il TTL viene rinnovato troppo vicino alla scadenza, un'altra replica scrivibile o il GC può comunque eliminare l'oggetto localmente prima che il refresh si replichi. TTL molto brevi quindi funzionano meglio quando l'attaccante sa quale DC gestirà l'abuso, mentre i defender dovrebbero interrogare **tutti i naming contexts / replicas** durante il triage.
- La cancellazione può ritardare di alcuni minuti sui DC con uptime breve (<24h), lasciando una finestra ristretta di risposta per interrogare/backup degli attributi. Rileva con **alert su nuovi oggetti che contengono `entryTTL`/`msDS-Entry-Time-To-Die`** e correlazione con SID orfani/broken links.

## Fast Enumeration / Live Triage

- Interroga **tutti i `namingContexts` da RootDSE**, non solo il domain NC. L'abuso dinamico può vivere in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o in application partitions.
- Mentre l'oggetto è ancora vivo, esegui subito il dump dei **replication metadata** e di eventuali attributi linkati/ACLs. Dopo la scadenza potresti ritrovarti solo con **broken `gPLink` values, orphan SIDs, o cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Evasione MAQ con Computer Auto-Eliminanti

- Il valore predefinito **`ms-DS-MachineAccountQuota` = 10** permette a qualsiasi utente autenticato di creare computer. Aggiungi `dynamicObject` durante la creazione per far sì che il computer si auto-elimini e **liberi lo slot di quota** mentre cancella le evidenze.
- Modifica Powermad dentro `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se il TTL richiesto è **inferiore a `DynamicObjectMinTTL`**, aspettati un aggiustamento lato server o un rifiuto a seconda del percorso di creazione; in molti domini il limite effettivo è **900s** e il fallback/predefinito resta **86400s**. ADUC può nascondere `entryTTL`, ma le query LDP/LDAP lo rivelano.
- Finché l'oggetto esiste, i defender possono comunque recuperare il creatore non privilegiato da **`msDS-CreatorSID`** sull'oggetto computer. Una volta scaduto il computer dinamico, quell'attribuzione scompare con l'oggetto.

## Membership del Primary Group Stealth

- Crea un **dynamic security group**, poi imposta **`primaryGroupID`** di un utente sul RID di quel gruppo per ottenere una membership effettiva che **non appare in `memberOf`** ma viene rispettata in Kerberos/access tokens.
- La scadenza del TTL **elimina il gruppo nonostante la protezione di cancellazione del primary group**, lasciando l'utente con un `primaryGroupID` corrotto che punta a un RID inesistente e senza tombstone da analizzare per capire come è stato concesso il privilegio.
- Il reporting dipende dallo strumento: **`Get-ADGroupMember` / `net group`** di solito risolvono la membership derivata dal primary group, mentre **`memberOf`** e **`Get-ADGroup -Properties member`** no. Per un uso più ampio di `primaryGroupID`, vedi [this other page about DCShadow and PGID abuse](dcshadow.md).
- Per target **non protetti da AdminSDHolder**, gli attacker possono combinare il trucco del dynamic-group con un **DACL deny sulla lettura di `primaryGroupID`** (o dell'attributo `member` del gruppo) per nascondere il collegamento da molti flussi LDAP/PowerShell anche prima che il gruppo scada.

## Inquinamento Orfano-SID di AdminSDHolder

- Aggiungi ACE per un **short-lived dynamic user/group** a **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL il SID diventa **non risolvibile (“Unknown SID”)** nell'ACL del template, e **SDProp (~60 min)** propaga quel SID orfano su tutti gli oggetti protetti Tier-0.
- La forensics perde l'attribuzione perché il principal non esiste più (nessun DN di oggetto eliminato). Monitora **nuovi principal dinamici + SID orfani improvvisi su AdminSDHolder/ACL privilegiate**.

## Esecuzione di GPO Dinamiche con Evidenze Auto-Distruttive

- Crea un oggetto **dynamic `groupPolicyContainer`** con un **`gPCFileSysPath`** malevolo (es. share SMB come in GPODDITY) e **collegalo tramite `gPLink`** a una OU target.
- I client elaborano la policy e prelevano il contenuto da SMB dell'attacker. Quando il TTL scade, l'oggetto GPO (e `gPCFileSysPath`) scompare; resta solo un **`gPLink`** GUID rotto, rimuovendo l'evidenza LDAP del payload eseguito.
- Operativamente è più pulito della classica pulizia in stile **GPODDITY**: invece di ripristinare da solo il `gPCFileSysPath` originale, AD rimuove automaticamente il GPC malevolo una volta scaduto il timer.

## Redirezione Ephemeral di DNS Integrato in AD

- I record DNS di AD sono oggetti **`dnsNode`** in **DomainDnsZones/ForestDnsZones**. Creandoli come **dynamic objects** si consente una redirezione temporanea dell'host (credential capture/MITM). I client memorizzano in cache la risposta A/AAAA malevola; il record poi si auto-elimina così la zona sembra pulita (DNS Manager potrebbe richiedere un reload della zona per aggiornare la vista).
- Detection: allerta su **qualsiasi record DNS che contenga `dynamicObject`/`entryTTL`** tramite log di replication/eventi; i record transitori compaiono raramente nei log DNS standard.

## Gap di Delta-Sync Ibrido Entra ID (Nota)

- Entra Connect delta sync si basa su **tombstones** per rilevare le delete. Un **dynamic on-prem user** può sincronizzarsi su Entra ID, scadere ed essere eliminato senza tombstone: il delta sync non rimuoverà l'account cloud, lasciando un **orphaned active Entra user** fino a quando non viene forzato un **initial/full sync** o una pulizia manuale nel cloud.

## Riferimenti

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
