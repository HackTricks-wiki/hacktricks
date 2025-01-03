{{#include ../../banners/hacktricks-training.md}}

Ci sono diversi blog su Internet che **mettono in evidenza i pericoli di lasciare le stampanti configurate con LDAP con credenziali di accesso predefinite/deboli**.\
Questo perché un attaccante potrebbe **ingannare la stampante a autenticarsi contro un server LDAP malevolo** (tipicamente un `nc -vv -l -p 444` è sufficiente) e catturare le **credenziali della stampante in chiaro**.

Inoltre, diverse stampanti conterranno **log con nomi utente** o potrebbero persino essere in grado di **scaricare tutti i nomi utente** dal Domain Controller.

Tutte queste **informazioni sensibili** e la comune **mancanza di sicurezza** rendono le stampanti molto interessanti per gli attaccanti.

Alcuni blog sull'argomento:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configurazione della Stampante

- **Posizione**: L'elenco dei server LDAP si trova in: `Network > LDAP Setting > Setting Up LDAP`.
- **Comportamento**: L'interfaccia consente modifiche al server LDAP senza reinserire le credenziali, mirando alla comodità dell'utente ma ponendo rischi per la sicurezza.
- **Sfruttamento**: Lo sfruttamento comporta il reindirizzamento dell'indirizzo del server LDAP a una macchina controllata e l'utilizzo della funzione "Test Connection" per catturare le credenziali.

## Cattura delle Credenziali

**Per passaggi più dettagliati, fare riferimento alla [fonte](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metodo 1: Netcat Listener

Un semplice listener netcat potrebbe essere sufficiente:
```bash
sudo nc -k -v -l -p 386
```
Tuttavia, il successo di questo metodo varia.

### Metodo 2: Server LDAP Completo con Slapd

Un approccio più affidabile prevede l'impostazione di un server LDAP completo perché la stampante esegue un bind nullo seguito da una query prima di tentare il binding delle credenziali.

1. **Impostazione del Server LDAP**: La guida segue i passaggi da [questa fonte](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Passaggi Chiave**:
- Installare OpenLDAP.
- Configurare la password di amministrazione.
- Importare schemi di base.
- Impostare il nome di dominio nel DB LDAP.
- Configurare LDAP TLS.
3. **Esecuzione del Servizio LDAP**: Una volta impostato, il servizio LDAP può essere eseguito utilizzando:
```bash
slapd -d 2
```
## Riferimenti

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
