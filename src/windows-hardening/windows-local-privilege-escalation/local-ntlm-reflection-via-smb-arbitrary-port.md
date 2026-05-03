# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

最近の Windows ビルドでは、**SMB client support for alternative TCP ports** が導入されました。この機能は、攻撃者が以下を行える場合に、**local NTLM authentication** を **SYSTEM local privilege escalation** に変えるために悪用できます。

1. 攻撃者が制御する listener に対して、**445以外のポート**で SMB 接続を開く
2. その TCP 接続を生かしたままにする
3. **特権のある local client** に **同じ SMB share path** へアクセスさせる
4. 発生した **local NTLM authentication** を machine の実際の SMB service に relay する

これが **CVE-2026-24294** の基本原理で、**2026年3月**に修正されました。

## Why it works

古い CMTI / serialized-SPN reflection の手法はこちらで説明されています:

{{#ref}}
../ntlm/README.md
{{#endref}}

この新しい変種では、**marshalled hostname** は不要です。代わりに、2つの SMB client の挙動を悪用します。

- **Windows 11 24H2** と **Windows Server 2025** にある **alternative port support**。`net use \\host\share /tcpport:<port>` でユーザーに公開されている
- **SMB connection reuse / multiplexing**。複数の authenticated sessions が同じ TCP connection を共有できる

つまり、権限の低いユーザーがまず SMB client から攻撃者の SMB server へ高番ポートで TCP connection を作成し、その後、特権サービスに **まったく同じ UNC path** へアクセスさせます。Windows が既存の TCP connection を再利用すると判断した場合、特権の NTLM exchange は攻撃者が制御する transport 上で送信され、ローカル SMB server へ relay できます。

## Preconditions

- Target が SMB alternative ports をサポートしている:
- **Windows 11 24H2** 以降
- **Windows Server 2025** 以降
- 攻撃者が選択した高番ポートで local または remote の SMB server を実行できる
- 攻撃者が特権サービスに UNC path へアクセスさせられる
- 特権認証が **NTLM local authentication** であること
- Target が relayable であること:
- Synacktiv は **Windows Server 2025** ではデフォルトで動作すると報告した
- 彼らの chain は **Windows 11 24H2** では動作しなかった。これは outbound SMB signing がデフォルトで強制されるため

## Userland and internals

コマンドラインから見ると、この機能はシンプルに見えます:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
プログラム的には、クライアントは未公開の `lpUseOptions` データ付きで `WNetAddConnection4W` を使用します。関連するオプションは `TraP` (transport parameters) で、これは最終的に FSCTL 経由で kernel SMB client に到達し、`mrxsmb` によって解析されます。

重要な実用上の注意:

- **UNC syntax には依然として port field がない**
- **`net use` は per-logon-session**
- この bypass が今でも機能するのは、**TCP connection と SMB session が別々の object** だから
- exploit が SMB client に以前作成された TCP connection の再利用を依存する場合、**同じ share path** を再利用することが必須

## Exploitation flow

### 1. attacker-controlled SMB transport を作成する

高い port で SMB server を実行し、Windows にそこへ connect させる:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
サーバーは、たとえば `user:user` のように、あなたが制御する任意の credential pair を受け入れられます。この手順の目的はまだ privilege escalation ではなく、Windows SMB client に対して、再利用可能な TCP connection をあなたの listener に open させ、そのまま維持させることです。

### 2. 特権サービスを同じ UNC path に強制する

**PetitPotam** のような coercion primitive を使って、**同じ** `\\192.168.56.3\share` path に対して誘導します。強制された client が privileged で、target name が local (`localhost` または local IP/host) の場合、Windows は **NTLM local authentication** を行います。

TCP connection が再利用されるため、その privileged な NTLM exchange は、直接 real local SMB server に行くのではなく、attacker の SMB service に届きます。

### 3. 特権認証を local SMB へ relay する

attacker-controlled の SMB service は、受け取った privileged NTLM exchange を `ntlmrelayx.py` に転送し、それが machine の real SMB listener に relay されて `NT AUTHORITY\SYSTEM` としての session を取得します。

public writeup での典型的な tooling:

- 再利用された TCP connection 経由で privileged auth を受け取るための custom port 上の `smbserver.py`
- 捕捉した NTLM を local SMB に relay するための `ntlmrelayx.py`
- privileged authentication を強制するための `PetitPotam.exe` などの coercion primitive

## Operator notes

- これは **local privilege escalation** technique であり、汎用的な remote relay trick ではありません
- attacker-controlled の SMB service は、最初に share mount に使われたのと**同じ TCP connection** 上で privileged authentication を処理しなければなりません
- 強制された access が**別の share path** に当たると、Windows は別の connection を確立し、chain は壊れます
- SMB signing requirements は、arbitrary-port step が成功しても relay を失敗させることがあります
- Kerberos material しか持っていない場合、または local NTLM を強制できない場合、この exact variant だけでは不十分です

## Detection and hardening

- **March 2026 Patch Tuesday** の **CVE-2026-24294** を patch する
- **non-default SMB ports** を使った `net use` や `New-SmbMapping` を監視する
- workstation や server から **high TCP ports** への異常な outbound SMB を alert する
- **EFSRPC / PetitPotam-style** の trigger などの coercion opportunities を確認する
- 可能な限り SMB signing を強制する; Synacktiv はこれが Windows 11 24H2 での relay を block したと特記しています

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
