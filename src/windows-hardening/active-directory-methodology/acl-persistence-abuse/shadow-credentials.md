# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione <a href="#3f17" id="3f17"></a>

**Consulta il post originale per [tutte le informazioni su questa tecnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

In sintesi, il controllo di **`msDS-KeyCredentialLink`** di un utente o di un computer può consentire a un attaccante di aggiungere una key credential, autenticarsi come quell'oggetto con PKINIT e, quando il KDC e l'account supportano i flussi necessari, usare il ticket ottenuto con `S4U2Self`/user-to-user per recuperare l'hash NT dell'oggetto.<sup>[[1]](#references)</sup>

Nel post viene descritto un metodo per configurare **credenziali di autenticazione a chiave pubblica e privata** e ottenere un **Service Ticket** univoco che include l'hash NTLM del target. Questo processo utilizza NTLM_SUPPLEMENTAL_CREDENTIAL cifrato all'interno del Privilege Attribute Certificate (PAC), che può essere decifrato.<sup>[[1]](#references)</sup>

### Requisiti

Per applicare questa tecnica, devono essere soddisfatte alcune condizioni:<sup>[[1]](#references)</sup>

- È necessario almeno un Domain Controller Windows Server 2016.
- Il Domain Controller deve avere installato un certificato digitale per l'autenticazione del server.
- Lo schema della directory deve contenere `msDS-KeyCredentialLink`; secondo la ricerca, i requisiti pratici della piattaforma sono un DC Windows Server 2016 o successivo e un certificato compatibile con PKINIT sul KDC. Verifica la combinazione di schema e DC del dominio, anziché presumere che la sola etichetta del livello funzionale del dominio determini la sfruttabilità.
- È necessario un account con diritti delegati per modificare l'attributo msDS-KeyCredentialLink dell'oggetto target.

## Abuso

L'abuso di Key Trust per gli oggetti computer comprende passaggi che vanno oltre l'ottenimento di un Ticket Granting Ticket (TGT) e dell'hash NTLM. Le opzioni includono:<sup>[[1]](#references)</sup>

1. Creare un **RC4 silver ticket** per agire come utenti privilegiati sull'host previsto.
2. Usare il TGT con **S4U2Self** per impersonare **utenti privilegiati**; è necessario modificare il Service Ticket per aggiungere una service class al nome del servizio.

Un vantaggio significativo dell'abuso di Key Trust è che si limita alla chiave privata generata dall'attaccante, evitando la delega ad account potenzialmente vulnerabili e senza richiedere la creazione di un account computer, che potrebbe essere difficile da rimuovere.<sup>[[1]](#references)</sup>

## Strumenti

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker usa DSInternals per manipolare `msDS-KeyCredentialLink` da C#. Whisker e la sua controparte Python **pyWhisker** supportano l'aggiunta, l'elenco e la rimozione delle key credential, nonché la loro eliminazione completa.<sup>[[2]](#references)[[4]](#references)</sup>

Le funzioni di **Whisker** includono:

- **Add**: genera una coppia di chiavi e aggiunge una key credential.
- **List**: mostra tutte le voci delle key credential.
- **Remove**: elimina una key credential specificata.
- **Clear**: elimina tutte le key credential, interrompendo potenzialmente l'uso legittimo di WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker porta questo workflow sui **sistemi UNIX-like** con Impacket e PyDSInternals, includendo operazioni di elenco, aggiunta e rimozione, nonché di importazione/esportazione JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumera gli oggetti di dominio su cui l’operatore dispone di diritti come `GenericWrite`/`GenericAll`, tenta di aggiungere key credential su larga scala e include modalità di cleanup/ricorsive. Lo spraying su larga scala è invasivo e vistoso; usa target espliciti e conserva ogni DeviceID aggiunto per poterlo rimuovere con precisione.<sup>[[3]](#references)</sup>

ADWS può trasportare la scrittura delle key credential quando LDAP diretto è filtrato. Vedi il [workflow SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: abuso del mapping degli account Key Trust per la compromissione dell’account](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Strumento per compromettere account AD manipolando msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Strumento per distribuire Shadow Credentials in un dominio](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Versione Python dello strumento Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
