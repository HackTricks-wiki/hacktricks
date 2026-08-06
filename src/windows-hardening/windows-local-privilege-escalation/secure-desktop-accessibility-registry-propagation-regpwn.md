# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows の Accessibility 機能は、ユーザー設定を HKCU 配下に保持し、セッションごとの HKLM ロケーションへ伝播させます。**Secure Desktop** への遷移（ロック画面または UAC プロンプト）の際、**SYSTEM** コンポーネントがこれらの値を再コピーします。**セッションごとの HKLM キーがユーザーによって書き込み可能**な場合、これは特権書き込みの集中点となり、**registry symbolic links** によってリダイレクトできます。その結果、**arbitrary SYSTEM registry write** が可能になります。<sup>[[1]](#references)</sup>

RegPwn technique は、この伝播チェーンを悪用します。`osk.exe` が使用するファイルに対する **opportunistic lock (oplock)** によって、小さな race window を安定化させます。<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Example feature: **On-Screen Keyboard** (`osk`)。関連するロケーションは次のとおりです。

- **システム全体の feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure Desktop への遷移中の propagation（簡略化）:

1. **User `atbroker.exe`** が `HKCU\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` にコピーします。
2. **SYSTEM `atbroker.exe`** が `HKLM\...\Session<session id>\ATConfig\osk` を `HKU\.DEFAULT\...\ATConfig\osk` にコピーします。
3. **SYSTEM `osk.exe`** が `HKU\.DEFAULT\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` にコピーし戻します。

セッションの HKLM subtree がユーザーによって書き込み可能な場合、step 2/3 により、ユーザーが置き換え可能なロケーションを介した SYSTEM write が実現します。<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

user-writable な per-session key を、攻撃者が選択した destination を指す **registry symbolic link** に置き換えます。SYSTEM copy が発生すると、その link に従い、攻撃者が制御する values が arbitrary target key に書き込まれます。

Key idea:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker replaces that key with a **registry link** to any other key.
- SYSTEM performs the copy and writes into the attacker-chosen key with SYSTEM permissions.

これにより、**arbitrary SYSTEM registry write** primitive が得られます。<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`** の起動から per-session key への書き込みまでの間には、短い timing window があります。これを reliable にするため、exploit は次の対象に **oplock** を設定します:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
oplock がトリガーされると、攻撃者はセッションごとの HKLM キーを registry link に置き換え、SYSTEM による書き込みを実行させた後、link を削除します。<sup>[[1]](#references)</sup>

## Exploitation Flow の例（概要）

1. access token から現在の **session ID** を取得します。
2. 非表示の `osk.exe` インスタンスを起動し、短時間 sleep します（oplock が確実にトリガーされるようにします）。
3. 攻撃者が制御する値を次に書き込みます。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。
5. **Secure Desktop** (`LockWorkstation()`) をトリガーし、SYSTEM の `atbroker.exe` / `osk.exe` を起動させます。
6. oplock のトリガー時に、`HKLM\...\Session<session id>\ATConfig\osk` を任意の target への **registry link** に置き換えます。
7. SYSTEM による copy が完了するまで短時間待機し、その後 link を削除します。<sup>[[1]](#references)</sup>

## Primitive を SYSTEM Execution に変換する

単純な chain の 1 つは、**service configuration** の値（例: `ImagePath`）を上書きしてから service を起動する方法です。RegPwn PoC は **`msiserver`** の `ImagePath` を上書きし、**MSI COM object** を instantiating してトリガーすることで、**SYSTEM** code execution を実現します。<sup>[[1]](#references)[[2]](#references)</sup>

## Related

その他の Secure Desktop / UIAccess の挙動については、次を参照してください。

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
