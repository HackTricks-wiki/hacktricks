# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows の Accessibility 機能は、ユーザー設定を HKCU に保存し、セッションごとの HKLM ロケーションへ伝播させます。**Secure Desktop** への遷移（ロック画面または UAC プロンプト）の際、**SYSTEM** コンポーネントがこれらの値を再コピーします。**セッションごとの HKLM キーがユーザーによって書き込み可能**な場合、これは特権書き込みのチョークポイントとなり、**registry symbolic links** によってリダイレクトできるため、**任意の SYSTEM registry write** が可能になります。<sup>[[1]](#references)</sup>

RegPwn technique は、この伝播チェーンを、`osk.exe` が使用するファイルに対する **opportunistic lock (oplock)** によって安定化した小さな race window と組み合わせて悪用します。<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

機能の例: **On-Screen Keyboard** (`osk`)。関連するロケーションは次のとおりです。

- **システム全体の feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **ユーザーごとの configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **セッションごとの HKLM config (`winlogon.exe` によって作成、user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

secure desktop への遷移中の propagation（簡略化）:

1. **User `atbroker.exe`** が `HKCU\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` にコピーする。
2. **SYSTEM `atbroker.exe`** が `HKLM\...\Session<session id>\ATConfig\osk` を `HKU\.DEFAULT\...\ATConfig\osk` にコピーする。
3. **SYSTEM `osk.exe`** が `HKU\.DEFAULT\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` にコピーし戻す。

セッションの HKLM subtree がユーザーによって書き込み可能な場合、step 2/3 により、ユーザーが置き換え可能なロケーションを介した SYSTEM write が可能になります。<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

ユーザーによって書き込み可能なセッションごとの key を、攻撃者が選択した destination を指す **registry symbolic link** に置き換えます。SYSTEM copy が実行されると、link をたどり、攻撃者が制御する values を arbitrary target key に書き込みます。

Key idea:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker がその key を、別の任意の key への **registry link** に置き換える。
- SYSTEM が copy を実行し、SYSTEM permissions で攻撃者が選択した key に書き込む。

これにより、**arbitrary SYSTEM registry write** primitive が得られます。<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

**SYSTEM `osk.exe`** の起動からセッションごとの key への書き込みまでの間には、短い timing window があります。これを reliable にするため、exploit は次の対象に **oplock** を設定します】【。
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
oplockがtriggerされると、攻撃者はsessionごとのHKLM keyをregistry linkに置き換え、SYSTEMによるwriteを実行させた後、linkを削除します。<sup>[[1]](#references)</sup>

## Exploitation Flowの例（概要）

1. access tokenから現在の**session ID**を取得します。
2. 非表示の`osk.exe`インスタンスを起動し、短時間sleepします（oplockがtriggerされるようにします）。
3. 攻撃者が制御する値を以下にwriteします。
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`に**oplock**を設定します。
5. **Secure Desktop**（`LockWorkstation()`）をtriggerし、SYSTEMの`atbroker.exe` / `osk.exe`を起動させます。
6. oplockのtrigger時に、`HKLM\...\Session<session id>\ATConfig\osk`を任意のtargetへの**registry link**に置き換えます。
7. SYSTEMによるcopyが完了するまで短時間待機し、その後linkを削除します。<sup>[[1]](#references)</sup>

## PrimitiveをSYSTEM Executionに変換する

単純なchainの1つは、**service configuration**の値（例：`ImagePath`）をoverwriteしてからserviceをstartする方法です。RegPwn PoCは**`msiserver`**の`ImagePath`をoverwriteし、**MSI COM object**をinstantiateしてtriggerすることで、**SYSTEM** code executionを実現します。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Related

その他のSecure Desktop / UIAccessの動作については、以下を参照してください。

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
