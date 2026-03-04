# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meccanica e rilevamento di base

- Qualsiasi oggetto creato con la classe ausiliaria **`dynamicObject`** ottiene **`entryTTL`** (conteggio in secondi) e **`msDS-Entry-Time-To-Die`** (scadenza assoluta). Quando `entryTTL` raggiunge 0 il **Garbage Collector lo elimina senza tombstone/recycle-bin**, cancellando creatore/timestamp e impedendo il recupero.
- Il TTL può essere rinfrescato aggiornando `entryTTL`; valori min/default sono imposti in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (supporta 1s–1y ma comunemente è impostato su 86,400s/24h). Gli oggetti dynamic non sono supportati nelle partizioni Configuration/Schema.
- La cancellazione può subire un ritardo di alcuni minuti sui DC con uptime ridotto (<24h), lasciando una finestra di risposta stretta per interrogare/fare il backup degli attributi. Rilevare generando **alert su nuovi oggetti che riportano `entryTTL`/`msDS-Entry-Time-To-Die`** e correlando con SID orfani/link interrotti.

## MAQ Evasion with Self-Deleting Computers

- Il valore predefinito **`ms-DS-MachineAccountQuota` = 10** permette a qualsiasi utente autenticato di creare computer. Aggiungi `dynamicObject` durante la creazione per far sì che il computer si auto-elimini e **liberi lo slot della quota** cancellando le prove.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Un TTL breve (es., 60s) spesso fallisce per utenti standard; AD ricade su **`DynamicObjectDefaultTTL`** (esempio: 86,400s). ADUC può nascondere `entryTTL`, ma LDP/LDAP query lo rivelano.

## Stealth Primary Group Membership

- Crea un **dynamic security group**, poi imposta il **`primaryGroupID`** di un utente al RID di quel gruppo per ottenere una membership effettiva che **non compare in `memberOf`** ma viene rispettata nei token Kerberos/access.
- La scadenza del TTL **elimina il gruppo nonostante la protezione da delete del primary-group**, lasciando l'utente con un `primaryGroupID` corrotto che punta a un RID inesistente e senza tombstone per investigare come il privilegio sia stato concesso.

## AdminSDHolder Orphan-SID Pollution

- Aggiungi ACE per un **utente/gruppo dynamic a breve vita** in **`CN=AdminSDHolder,CN=System,...`**. Dopo la scadenza del TTL il SID diventa **irrisolvibile (“Unknown SID”)** nell'ACL template, e **SDProp (~60 min)** propaga quel SID orfano su tutti gli oggetti Tier-0 protetti.
- La forensic perde l'attribuzione perché il principal non esiste più (nessun deleted-object DN). Monitorare per **nuovi principal dynamic + improvvisi SID orfani su AdminSDHolder/ACL privilegiate**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Crea un oggetto **dynamic `groupPolicyContainer`** con un `gPCFileSysPath` malevolo (es., condivisione SMB alla GPODDITY) e **linkalo via `gPLink`** a un OU di destinazione.
- I client elaborano la policy e scaricano il contenuto dall'SMB dell'attaccante. Quando il TTL scade, l'oggetto GPO (e il `gPCFileSysPath`) svaniscono; rimane solo un GUID **`gPLink` rotto**, rimuovendo l'evidenza LDAP della payload eseguita.

## Ephemeral AD-Integrated DNS Redirection

- I record DNS AD sono oggetti **`dnsNode`** in **DomainDnsZones/ForestDnsZones**. Crearli come **dynamic objects** permette un reindirizzamento temporaneo degli host (credential capture/MITM). I client memorizzano nella cache la risposta A/AAAA malevola; il record dopo si auto-elimina così la zona sembra pulita (DNS Manager può richiedere un reload della zona per aggiornare la vista).
- Rilevamento: generare alert su **qualsiasi record DNS che riporti `dynamicObject`/`entryTTL`** tramite replicazione/log eventi; i record transitori raramente compaiono nei log DNS standard.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Il delta sync di Entra Connect si basa sui **tombstones** per rilevare le cancellazioni. Un **dynamic on-prem user** può sincronizzarsi con Entra ID, scadere e cancellarsi senza tombstone—il delta sync non rimuoverà l'account cloud, lasciando un **utente Entra orfano attivo** fino a quando non viene forzato un **full sync** manuale.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
