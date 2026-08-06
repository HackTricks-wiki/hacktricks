# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Recent Windows build では、**SMB client が代替 TCP port をサポート**するようになりました。この機能を悪用すると、攻撃者が以下を実行できる場合、**local NTLM authentication** を **SYSTEM local privilege escalation** に変えることができます。<sup>[[1]](#references)</sup>

1. 攻撃者が制御する listener に **non-445 port** で SMB connection を開く
2. その TCP connection を維持する
3. **privileged local client** に**同じ SMB share path**へのアクセスを強制する
4. 結果として発生した **local NTLM authentication** を、マシンの実際の SMB service に relay する

これは **CVE-2026-24294** の基盤となる primitive であり、**March 2026** に patch が適用されました。<sup>[[1]](#references)[[4]](#references)</sup>

## なぜ機能するのか

古い CMTI / serialized-SPN reflection trick については、こちらで説明しています。

{{#ref}}
../ntlm/README.md
{{#endref}}

この新しい variant では、marshalled hostname は必要ありません。代わりに、2 つの SMB client の挙動を悪用します。<sup>[[1]](#references)</sup>

- **Windows 11 24H2** および **Windows Server 2025** における **alternative port support**。ユーザーは `net use \\host\share /tcpport:<port>` で利用できます
- **SMB connection reuse / multiplexing**。複数の authenticated session が同じ TCP connection を利用できます

つまり、low-privileged user はまず SMB client から high port 上の攻撃者 SMB server へ TCP connection を作成し、その後、privileged service に**完全に同じ UNC path**へのアクセスを強制できます。Windows が既存の TCP connection の再利用を決定すると、privileged NTLM exchange は攻撃者が制御する transport 上で送信され、local SMB server に relay できます。<sup>[[1]](#references)</sup>

## 前提条件

- Target が SMB alternative ports をサポートしていること:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** 以降
- 攻撃者が、選択した high port 上で local または remote SMB server を実行できること
- 攻撃者が privileged service に UNC path へのアクセスを強制できること
- privileged authentication が **NTLM local authentication** であること
- Target が relay 可能であること:<sup>[[1]](#references)</sup>
- Synacktiv は、**Windows Server 2025** ではデフォルトで機能したと報告しています
- ただし、**Windows 11 24H2** では outbound SMB signing がデフォルトで強制されるため、彼らの chain は機能しませんでした

## Userland と internals

コマンドラインから見ると、この機能は単純です:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
プログラムからは、client は未 documented な `lpUseOptions` data を指定して `WNetAddConnection4W` を使用します。関連する option は `TraP`（transport parameters）で、最終的に FSCTL 経由で kernel の SMB client に到達し、`mrxsmb` によって parse されます。<sup>[[1]](#references)[[3]](#references)</sup>

重要な実用上の注意点:<sup>[[1]](#references)</sup>

- **UNC syntax には依然として port field がない**
- **`net use` は logon session 単位**
- **TCP connection と SMB session は別々の object であるため、bypass は引き続き機能する**
- exploit が SMB client による既存の TCP connection の reuse に依存する場合、**同じ share path を再利用することが必須**

## Exploitation flow

### 1. Attacker-controlled SMB transport を作成する

high port で SMB server を実行し、Windows から接続させます:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
サーバーは、例えば `user:user` のように、あなたが管理している任意の認証情報ペアを受け入れられます。この手順の目的は、まだ privilege escalation を行うことではなく、Windows SMB client に listener への再利用可能な TCP connection を開かせ、維持させることだけです。<sup>[[1]](#references)</sup>

### 2. privileged service を同じ UNC path に強制する

**PetitPotam** などの coercion primitive を、**同じ** `\\192.168.56.3\share` path に対して使用します。coerced client が privileged で、target name が local（`localhost` または local IP/host）の場合、Windows は **NTLM local authentication** を実行します。

TCP connection が再利用されるため、その privileged NTLM exchange は実際の local SMB server に直接送られるのではなく、attacker SMB service に送られます。<sup>[[1]](#references)</sup>

### 3. privileged authentication を local SMB に relay する

attacker-controlled SMB service は privileged NTLM exchange を `ntlmrelayx.py` に転送し、これをマシンの実際の SMB listener に relay して、`NT AUTHORITY\SYSTEM` として session を取得します。<sup>[[1]](#references)</sup>

公開された writeup で使用されている代表的な tooling：<sup>[[1]](#references)</sup>

- 再利用された TCP connection 経由で privileged auth を受信するため、custom port 上で `smbserver.py` を使用
- 取得した NTLM を local SMB に relay するため、`ntlmrelayx.py` を使用
- privileged authentication を強制するため、`PetitPotam.exe` または別の coercion primitive を使用

## Operator notes

- これは **local privilege escalation** technique であり、一般的な remote relay trick ではありません<sup>[[1]](#references)</sup>
- attacker-controlled SMB service は、share mount に最初に使用された **同じ TCP connection** 上で privileged authentication を処理する必要があります<sup>[[1]](#references)</sup>
- coerced access が **異なる share path** に到達すると、Windows は別の connection を確立する可能性があり、chain は失敗します<sup>[[1]](#references)</sup>
- arbitrary-port step が機能しても、SMB signing requirements によって relay が阻止される可能性があります<sup>[[1]](#references)</sup>
- Kerberos material しか持っていない場合、または local NTLM を強制できない場合、この exact variant だけでは不十分です<sup>[[1]](#references)</sup>

## Detection and hardening

- **March 2026 Patch Tuesday** の **CVE-2026-24294** に対する patch を適用する<sup>[[4]](#references)</sup>
- **non-default SMB ports** を使用する `net use` または `New-SmbMapping` を監視する<sup>[[1]](#references)</sup>
- workstation または server から **high TCP ports** への通常と異なる outbound SMB に alert を出す<sup>[[1]](#references)</sup>
- **EFSRPC / PetitPotam-style** triggers などの coercion opportunities を確認する<sup>[[1]](#references)</sup>
- 可能な場合は SMB signing を強制する。Synacktiv は、これにより Windows 11 24H2 上での relay が阻止されたと具体的に記載しています<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
