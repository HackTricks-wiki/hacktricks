# AD Dynamic Objects (dynamicObject) Anti-forense

{{#include ../../banners/hacktricks-training.md}}

## Meccanica e nozioni di base per il rilevamento

- Qualsiasi oggetto creato con la auxiliary class **`dynamicObject`** ottiene **`entryTTL`** (conteggio in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando `entryTTL` raggiunge 0 il **Garbage Collector lo elimina senza tombstone/recycle-bin**, cancellando creator/timestamp e impedendo il recupero.
- Il TTL può essere rinfrescato aggiornando `entryTTL`; min/default sono imposti in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (supporta 1s–1y ma comunemente defaulta a 86,400s/24h). Gli oggetti dinamici **non sono supportati nelle partizioni Configuration/Schema**.
- La cancellazione può subire ritardi di pochi minuti su DC con uptime breve (<24h), lasciando una finestra ristretta per interrogare/backup degli attributi. Rilevare segnalando **nuovi oggetti che riportano `entryTTL`/`msDS-Entry-Time-To-Die`** e correlando con SID orfani/link interrotti.

## MAQ Evasion with Self-Deleting Computers

- Il valore di default **`ms-DS-MachineAccountQuota` = 10** permette a qualsiasi utente autenticato di creare computer. Aggiungere `dynamicObject` durante la creazione fa sì che il computer si autoelimini e **liberi lo slot di quota** mentre cancella le prove.
- Tweak Powermad dentro `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- TTL breve (es. 60s) spesso fallisce per utenti standard; AD ricade su **`DynamicObjectDefaultTTL`** (esempio: 86,400s). ADUC può nascondere `entryTTL`, ma LDP/LDAP query lo rivelano.

## Stealth Primary Group Membership

- Creare un **security group dinamico**, poi impostare il `primaryGroupID` di un utente al RID di quel gruppo per ottenere membership effettiva che **non compare in `memberOf`** ma viene rispettata nei token Kerberos/access.
- Alla scadenza del TTL **il gruppo viene eliminato nonostante la protezione da cancellazione primary-group**, lasciando l'utente con un `primaryGroupID` corrotto che punta a un RID inesistente e senza tombstone per indagare come sia stato concesso il privilegio.

## AdminSDHolder Orphan-SID Pollution

- Aggiungere ACEs per un **utente/gruppo dinamico a vita breve** in **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL lo SID diventa **non risolvibile (“Unknown SID”)** nel template ACL, e **SDProp (~60 min)** propaga quello SID orfano su tutti gli oggetti protetti Tier-0.
- La forense perde l'attribuzione perché il principale non esiste più (nessun DN di deleted-object). Monitorare per **nuovi principal dinamici + improvvisi SID orfani su AdminSDHolder/ACL privilegiati**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Creare un oggetto **`groupPolicyContainer` dinamico** con un `gPCFileSysPath` malevolo (es., SMB share in stile GPODDITY) e **linkarlo tramite `gPLink`** a un OU target.
- I client processano la policy e scaricano contenuto dallo SMB dell'attaccante. Quando il TTL scade, l'oggetto GPO (e `gPCFileSysPath`) scompaiono; rimane solo un **`gPLink`** GUID rotto, cancellando le evidenze LDAP della payload eseguita.

## Ephemeral AD-Integrated DNS Redirection

- I record AD DNS sono oggetti **`dnsNode`** in **DomainDnsZones/ForestDnsZones**. Crearli come **dynamic objects** permette redirezioni host temporanee (credential capture/MITM). I client cachano la risposta A/AAAA malevola; il record poi si autoelimina lasciando la zone apparentemente pulita (DNS Manager può richiedere il reload della zona per aggiornare la vista).
- Rilevamento: segnalare **qualsiasi record DNS che riporti `dynamicObject`/`entryTTL`** via replication/event logs; i record transitori raramente compaiono nei log DNS standard.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync si basa sui **tombstone** per rilevare le cancellazioni. Un **utente on-prem dinamico** può syncare su Entra ID, scadere e cancellarsi senza tombstone—delta sync non rimuoverà l'account cloud, lasciando un **utente Entra attivo orfano** fino a quando non viene forzata una **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
