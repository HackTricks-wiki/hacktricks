# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Controlla il post originale per [tutte le informazioni su questa tecnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

In **sintesi**: se puoi scrivere nella proprietà **msDS-KeyCredentialLink** di un utente/computer, puoi recuperare l'**hash NT di quell'oggetto**.

Nel post, viene delineato un metodo per impostare **credenziali di autenticazione a chiave pubblica-privata** per acquisire un **Service Ticket** unico che include l'hash NTLM del target. Questo processo coinvolge l'NTLM_SUPPLEMENTAL_CREDENTIAL crittografato all'interno del Privilege Attribute Certificate (PAC), che può essere decrittografato.

### Requisiti

Per applicare questa tecnica, devono essere soddisfatte determinate condizioni:

- È necessario un minimo di un Domain Controller Windows Server 2016.
- Il Domain Controller deve avere installato un certificato digitale di autenticazione del server.
- Active Directory deve essere al livello funzionale di Windows Server 2016.
- È richiesto un account con diritti delegati per modificare l'attributo msDS-KeyCredentialLink dell'oggetto target.

## Abuso

L'abuso di Key Trust per oggetti computer comprende passaggi oltre all'ottenimento di un Ticket Granting Ticket (TGT) e dell'hash NTLM. Le opzioni includono:

1. Creare un **RC4 silver ticket** per agire come utenti privilegiati sull'host previsto.
2. Utilizzare il TGT con **S4U2Self** per impersonare **utenti privilegiati**, necessitando modifiche al Service Ticket per aggiungere una classe di servizio al nome del servizio.

Un vantaggio significativo dell'abuso di Key Trust è la sua limitazione alla chiave privata generata dall'attaccante, evitando la delega a account potenzialmente vulnerabili e non richiedendo la creazione di un account computer, che potrebbe essere difficile da rimuovere.

## Strumenti

### [**Whisker**](https://github.com/eladshamir/Whisker)

Si basa su DSInternals fornendo un'interfaccia C# per questo attacco. Whisker e il suo equivalente Python, **pyWhisker**, consentono la manipolazione dell'attributo `msDS-KeyCredentialLink` per ottenere il controllo sugli account Active Directory. Questi strumenti supportano varie operazioni come aggiungere, elencare, rimuovere e cancellare le credenziali di chiave dall'oggetto target.

Le funzioni di **Whisker** includono:

- **Add**: Genera una coppia di chiavi e aggiunge una credenziale di chiave.
- **List**: Mostra tutte le voci delle credenziali di chiave.
- **Remove**: Elimina una credenziale di chiave specificata.
- **Clear**: Cancella tutte le credenziali di chiave, potenzialmente interrompendo l'uso legittimo di WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Estende la funzionalità di Whisker a **sistemi basati su UNIX**, sfruttando Impacket e PyDSInternals per capacità di sfruttamento complete, inclusi l'elenco, l'aggiunta e la rimozione di KeyCredentials, oltre all'importazione e all'esportazione in formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray mira a **sfruttare i permessi GenericWrite/GenericAll che ampi gruppi di utenti possono avere sugli oggetti di dominio** per applicare ShadowCredentials in modo ampio. Comporta il login nel dominio, la verifica del livello funzionale del dominio, l'enumerazione degli oggetti di dominio e il tentativo di aggiungere KeyCredentials per l'acquisizione del TGT e la rivelazione dell'hash NT. Le opzioni di pulizia e le tattiche di sfruttamento ricorsivo ne aumentano l'utilità.

## Riferimenti

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
