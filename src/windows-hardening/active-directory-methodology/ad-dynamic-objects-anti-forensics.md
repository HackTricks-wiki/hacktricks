# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meccaniche & Basi di Detection

- Qualsiasi oggetto creato con la classe ausiliaria **`dynamicObject`** ottiene **`entryTTL`** (conteggio alla rovescia in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando `entryTTL` raggiunge 0, il **Garbage Collector lo elimina senza tombstone/recycle-bin**, cancellando creatore/timestamp e bloccando il recupero.
- **`entryTTL` è un attributo operativo/constructed**: richiedilo esplicitamente nelle query LDAP. Il TTL può essere rinnovato aggiornando `entryTTL` prima della scadenza oppure tramite LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- I limiti min/default del TTL sono applicati in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documenta **86400s** come TTL predefinito e **900s** come TTL minimo valido predefinito; entrambi supportano **1s–1y**. Gli oggetti dinamici sono **non supportati nelle partizioni Configuration/Schema**.
- Non esiste conversione static→dynamic e non c’è una fase tombstone dopo la scadenza. I team IR non possono fare affidamento sui controlli per oggetti eliminati o su Recycle Bin; devono catturare l’oggetto vivo/metadata prima che il GC lo rimuova.
- Il refresh è **sensibile alla replica**: se il TTL viene rinnovato troppo vicino alla scadenza, un’altra replica scrivibile o il GC può comunque eliminare l’oggetto localmente prima che il refresh si replichi. TTL molto brevi funzionano quindi meglio quando l’attaccante sa quale DC gestirà l’abuso, mentre i difensori dovrebbero interrogare **tutti i naming contexts / repliche** durante il triage.
- La cancellazione può ritardare di qualche minuto sui DC con uptime breve (<24h), lasciando una finestra stretta per risposta/query/backup degli attributi. Rileva **allertando su nuovi oggetti che portano `entryTTL`/`msDS-Entry-Time-To-Die`** e correlando con orphan SIDs/link interrotti.

## Fast Enumeration / Live Triage

- Interroga **tutti i `namingContexts` da RootDSE**, non solo il domain NC. L’abuso dinamico può vivere in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) o in application partitions.
- Mentre l’oggetto è ancora vivo, dumpa immediatamente i **metadati di replica** e qualsiasi attributo collegato/ACL. Dopo la scadenza potresti ritrovarti solo con **valori `gPLink` interrotti, orphan SIDs, o risposte DNS in cache**.
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

- Il valore predefinito di **`ms-DS-MachineAccountQuota` = 10** permette a qualsiasi utente autenticato di creare computer. Aggiungi `dynamicObject` durante la creazione per far sì che il computer si auto-elimini e **liberi lo slot di quota** cancellando anche le evidenze.
- Modifica Powermad in `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Se il TTL richiesto è **inferiore a `DynamicObjectMinTTL`**, aspettati un aggiustamento lato server o un rifiuto a seconda del percorso di creazione; in molti domini il minimo effettivo è **900s** e il fallback/predefinito resta **86400s**. ADUC può nascondere `entryTTL`, ma le query LDP/LDAP lo rivelano.
- Mentre l'oggetto esiste, i difensori possono comunque recuperare il creatore non privilegiato da **`msDS-CreatorSID`** sull'oggetto computer. Una volta che il computer dinamico scade, quell'attribuzione scompare insieme all'oggetto.

## Membership del Primary Group Stealth

- Crea un **dynamic security group**, poi imposta il **`primaryGroupID`** di un utente sul RID di quel gruppo per ottenere una membership effettiva che **non appare in `memberOf`** ma viene riconosciuta in Kerberos/access token.
- La scadenza del TTL **elimina il gruppo nonostante la protezione di cancellazione del primary group**, lasciando l'utente con un `primaryGroupID` corrotto che punta a un RID inesistente e senza tombstone da analizzare per capire come è stato concesso il privilegio.
- La reportistica dipende dallo strumento: **`Get-ADGroupMember` / `net group`** di solito risolvono la membership derivata dal primary group, mentre **`memberOf`** e **`Get-ADGroup -Properties member`** no. Per un uso più ampio di `primaryGroupID`, vedi [this other page about DCShadow and PGID abuse](dcshadow.md).
- Per target **non protetti da AdminSDHolder**, gli attacker possono combinare il trucco del dynamic-group con un **DACL deny sulla lettura di `primaryGroupID`** (o dell'attributo `member` del gruppo) per nascondere il collegamento da molti flussi LDAP/PowerShell anche prima della scadenza del gruppo.

## Inquinamento Orphan-SID di AdminSDHolder

- Aggiungi ACE per un **dynamic user/group** di breve durata a **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL, il SID diventa **non risolvibile (“Unknown SID”)** nell'ACL del template, e **SDProp (~60 min)** propaga quel SID orfano su tutti gli oggetti protetti Tier-0.
- Le forensics perdono l'attribuzione perché il principal non esiste più (nessun DN di oggetto eliminato). Monitora **nuovi principal dinamici + SID orfani improvvisi su AdminSDHolder/ACL privilegiate**.

## Esecuzione GPO Dinamica con Evidenze Auto-Distruttive

- Crea un oggetto **dynamic `groupPolicyContainer`** con un **`gPCFileSysPath`** malevolo (es. share SMB à la GPODDITY) e **collegalo tramite `gPLink`** a una OU target.
- I client elaborano la policy e scaricano il contenuto dall'SMB dell'attacker. Quando il TTL scade, l'oggetto GPO (e `gPCFileSysPath`) scompare; rimane solo un **`gPLink`** GUID interrotto, rimuovendo le evidenze LDAP del payload eseguito.
- Operativamente è più pulito del cleanup classico in stile **GPODDITY**: invece di ripristinare tu stesso `gPCFileSysPath`, AD rimuove automaticamente il GPC malevolo quando il timer scade.

## Redirezione DNS Integrata in AD Effimera

- I record DNS di AD sono oggetti **`dnsNode`** in **DomainDnsZones/ForestDnsZones**. Creandoli come **dynamic objects** si ottiene una redirezione temporanea dell'host (credential capture/MITM). I client mettono in cache la risposta A/AAAA malevola; il record poi si auto-elimina così la zona appare pulita (DNS Manager potrebbe richiedere un reload della zona per aggiornare la vista).
- Detection: segnala **qualsiasi record DNS che contenga `dynamicObject`/`entryTTL`** tramite log di replica/eventi; i record transitori compaiono raramente nei normali log DNS.

## Gap di Delta-Sync Ibrido Entra ID (Nota)

- Entra Connect delta sync si basa sui **tombstones** per rilevare le eliminazioni. Un **dynamic on-prem user** può sincronizzarsi su Entra ID, scadere ed eliminarsi senza tombstone: il delta sync non rimuoverà l'account cloud, lasciando un **utente Entra attivo orfano** fino a quando non viene forzata una **initial/full sync** o una pulizia manuale nel cloud.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
