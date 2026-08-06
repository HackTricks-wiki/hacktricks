# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Controlla il post originale per [tutte le informazioni su questa tecnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

In **sintesi**: se puoi scrivere nella proprietà **msDS-KeyCredentialLink** di un user/computer, puoi recuperare l'**NT hash di quell'oggetto**.<sup>[[1]](#references)</sup>

Nel post viene descritto un metodo per configurare **credenziali di autenticazione basate su chiave pubblica-privata** e acquisire un **Service Ticket** univoco che include l'hash NTLM del target. Questo processo utilizza l'NTLM_SUPPLEMENTAL_CREDENTIAL crittografato all'interno del Privilege Attribute Certificate (PAC), che può essere decrittografato.<sup>[[1]](#references)</sup>

### Requisiti

Per applicare questa tecnica, devono essere soddisfatte determinate condizioni:<sup>[[1]](#references)</sup>

- È necessario almeno un Domain Controller Windows Server 2016.
- Sul Domain Controller deve essere installato un certificato digitale per l'autenticazione del server.
- Active Directory deve essere al Windows Server 2016 Functional Level.
- È necessario un account con diritti delegati per modificare l'attributo msDS-KeyCredentialLink dell'oggetto target.

## Abuse

L'abuse di Key Trust per gli oggetti computer comprende passaggi aggiuntivi oltre all'ottenimento di un Ticket Granting Ticket (TGT) e dell'hash NTLM. Le opzioni includono:<sup>[[1]](#references)</sup>

1. Creare un **RC4 silver ticket** per agire come utenti privilegiati sull'host previsto.
2. Utilizzare il TGT con **S4U2Self** per l'impersonation di **utenti privilegiati**, rendendo necessarie modifiche al Service Ticket per aggiungere una service class al service name.

Un vantaggio significativo dell'abuse di Key Trust è che si limita alla private key generata dall'attacker, evitando la delega ad account potenzialmente vulnerabili e senza richiedere la creazione di un computer account, che potrebbe essere difficile da rimuovere.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

È basato su DSInternals e fornisce un'interfaccia C# per questo attack. Whisker e la sua controparte Python, **pyWhisker**, consentono di manipolare l'attributo `msDS-KeyCredentialLink` per ottenere il controllo degli account Active Directory. Questi tools supportano diverse operazioni, come l'aggiunta, l'elenco, la rimozione e la cancellazione delle key credentials dall'oggetto target.

Le funzioni di **Whisker** includono:

- **Add**: genera una coppia di chiavi e aggiunge una key credential.
- **List**: visualizza tutte le voci delle key credential.
- **Remove**: elimina una key credential specificata.
- **Clear**: cancella tutte le key credential, interrompendo potenzialmente l'uso legittimo di WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Estende le funzionalità di Whisker ai **sistemi basati su UNIX**, sfruttando Impacket e PyDSInternals per capacità di exploitation complete, tra cui l'elenco, l'aggiunta e la rimozione di KeyCredentials, nonché la loro importazione ed esportazione in formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray mira a **sfruttare i permessi GenericWrite/GenericAll che ampi gruppi di utenti possono avere sugli oggetti del dominio** per applicare ampiamente le Shadow Credentials. Questo comporta l'accesso al dominio, la verifica del functional level del dominio, l'enumerazione degli oggetti del dominio e il tentativo di aggiungere KeyCredentials per ottenere TGT e rivelare gli hash NT. Le opzioni di cleanup e le tecniche di exploitation ricorsiva ne aumentano l'utilità.

## Riferimenti

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
