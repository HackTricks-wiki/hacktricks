# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#3f17" id="3f17"></a>

**Consulta il post originale per [tutte le informazioni su questa tecnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

In sintesi, il controllo dell'attributo **`msDS-KeyCredentialLink`** di un utente o computer può consentire a un attacker di aggiungere una key credential, autenticarsi come quell'oggetto con PKINIT e, quando il KDC e l'account supportano i flussi necessari, utilizzare il ticket risultante con `S4U2Self`/user-to-user per recuperare l'hash NT dell'oggetto.<sup>[[1]](#references)</sup>

Nel post viene descritto un metodo per configurare **credenziali di autenticazione basate su una coppia di chiavi pubblica-privata** e acquisire un **Service Ticket** univoco che include l'hash NTLM del target. Questo processo coinvolge il valore NTLM_SUPPLEMENTAL_CREDENTIAL cifrato all'interno del Privilege Attribute Certificate (PAC), che può essere decrittografato.<sup>[[1]](#references)</sup>

### Requisiti

Per applicare questa tecnica, devono essere soddisfatte determinate condizioni:<sup>[[1]](#references)</sup>

- È necessario almeno un Domain Controller Windows Server 2016.
- Il Domain Controller deve avere installato un certificato digitale per l'autenticazione del server.
- Lo schema della directory deve contenere `msDS-KeyCredentialLink`; i requisiti pratici della piattaforma descritti dalla ricerca sono un DC Windows Server 2016 o successivo e un certificato compatibile con PKINIT sul KDC. Verifica la combinazione di schema e DC del dominio invece di presumere che sia sufficiente l'etichetta del functional level del dominio per determinare l'exploitability.
- È necessario un account con diritti delegati per modificare l'attributo msDS-KeyCredentialLink dell'oggetto target.

## Abuso

L'abuso di Key Trust per gli oggetti computer comprende passaggi ulteriori rispetto all'ottenimento di un Ticket Granting Ticket (TGT) e dell'hash NTLM. Le opzioni includono:<sup>[[1]](#references)</sup>

1. Creare un **RC4 silver ticket** per agire come utenti privilegiati sull'host previsto.
2. Utilizzare il TGT con **S4U2Self** per impersonare **utenti privilegiati**, rendendo necessarie modifiche al Service Ticket per aggiungere una service class al service name.

Un vantaggio significativo dell'abuso di Key Trust è che è limitato alla private key generata dall'attacker, evitando la delega ad account potenzialmente vulnerabili e senza richiedere la creazione di un computer account, che potrebbe essere difficile da rimuovere.<sup>[[1]](#references)</sup>

## Strumenti

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker utilizza DSInternals per manipolare `msDS-KeyCredentialLink` da C#. Whisker e la sua controparte Python **pyWhisker** supportano l'aggiunta, l'elenco, la rimozione e la cancellazione delle key credential.<sup>[[2]](#references)[[4]](#references)</sup>

Le funzioni di **Whisker** includono:

- **Add**: Genera una coppia di chiavi e aggiunge una key credential.
- **List**: Visualizza tutte le voci delle key credential.
- **Remove**: Elimina una key credential specificata.
- **Clear**: Cancella tutte le key credential, interrompendo potenzialmente l'utilizzo legittimo di WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker porta il workflow sui **sistemi UNIX-like** con Impacket e PyDSInternals, includendo operazioni di list/add/remove e import/export JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera gli oggetti del dominio sui quali l'operatore dispone di diritti come `GenericWrite`/`GenericAll`, tenta di aggiungere ampie quantità di key credentials e include modalità di cleanup/recursive. Lo spraying esteso è dannoso e facilmente individuabile; usa target espliciti e conserva ogni DeviceID aggiunto per una rimozione precisa.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: abusare del mapping degli account tramite Key Trust per ottenere il takeover dell'account](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool per ottenere il controllo degli account AD manipolando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool per effettuare lo spraying di Shadow Credentials in un dominio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versione Python del tool Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
