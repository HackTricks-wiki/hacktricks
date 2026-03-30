# セキュアデスクトップ アクセシビリティ レジストリ伝播 LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows の Accessibility 機能はユーザー設定を HKCU 下に保持し、それをセッションごとの HKLM の場所へ伝播します。**Secure Desktop** の遷移（ロック画面や UAC プロンプト）の間、**SYSTEM** コンポーネントがこれらの値を再コピーします。もし **per-session HKLM キーがユーザーによって書き込み可能**であれば、それは特権書き込みのチョークポイントとなり、**レジストリ シンボリックリンク**でリダイレクトすることができ、結果として **任意の SYSTEM レジストリ書き込み** を得られます。

RegPwn 技術はその伝播チェーンを悪用し、`osk.exe` が使用するファイルに対して **opportunistic lock (oplock)** を置くことで短いレース窓を安定化させます。

## Registry Propagation Chain (Accessibility -> Secure Desktop)

例の機能: **On-Screen Keyboard** (`osk`)。関連する場所は次のとおり：

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Secure Desktop 遷移中の伝播（簡略化）:

1. **ユーザーコンテキストの `atbroker.exe`** が `HKCU\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` へコピーする。
2. **SYSTEM コンテキストの `atbroker.exe`** が `HKLM\...\Session<session id>\ATConfig\osk` を `HKU\.DEFAULT\...\ATConfig\osk` へコピーする。
3. **SYSTEM の `osk.exe`** が `HKU\.DEFAULT\...\ATConfig\osk` を `HKLM\...\Session<session id>\ATConfig\osk` へコピーする。

もしセッションの HKLM サブツリーがユーザーによって書き込み可能であれば、ステップ 2／3 はユーザーが置き換え可能な場所を通じて SYSTEM による書き込みを提供します。

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

ユーザーが書き込み可能な per-session キーを、攻撃者が選んだ宛先を指す **レジストリ シンボリックリンク** に置き換えます。SYSTEM がコピーを行うとき、リンクをたどって任意のターゲットキーに攻撃者制御の値を書き込みます。

重要な点:

- 被害者の書き込み先（ユーザー書き込み可能）:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- 攻撃者はそのキーを任意の他のキーを指す **レジストリリンク** に置き換える。
- SYSTEM がコピーを行うと、SYSTEM 権限で攻撃者が選んだキーに書き込む。

これにより **任意の SYSTEM レジストリ書き込み** プリミティブが得られます。

## Winning the Race Window with Oplocks

`SYSTEM` の `osk.exe` が起動して per-session キーに書き込むまでの間に短いタイミング窓があります。信頼性を上げるために、エクスプロイトは次のファイルに対して **oplock** を置きます：
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
When the oplock triggers, the attacker swaps the per-session HKLM key for a registry link, lets the SYSTEM write land, then removes the link.

## 例：エクスプロイトフロー（高レベル）

1. アクセストークンから現在の **session ID** を取得します。
2. 非表示の `osk.exe` インスタンスを起動し、短時間待機します（oplock がトリガーされることを確実にするため）。
3. 攻撃者が制御する値を次に書き込みます:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` に **oplock** を設定します。
5. **Secure Desktop**（`LockWorkstation()`）をトリガーし、SYSTEM の `atbroker.exe` / `osk.exe` が起動するようにします。
6. oplock がトリガーされたら、`HKLM\...\Session<session id>\ATConfig\osk` を任意のターゲットへの **registry link** に置き換えます。
7. SYSTEM によるコピーが完了するまで短時間待ち、リンクを削除します。

## プリミティブを SYSTEM 実行に変換する

一つの単純なチェーンは、**service configuration** 値（例: `ImagePath`）を上書きしてからサービスを開始することです。RegPwn PoC は **`msiserver`** の `ImagePath` を上書きし、**MSI COM object** をインスタンス化することでこれをトリガーし、**SYSTEM** のコード実行を達成します。

## Related

For other Secure Desktop / UIAccess behaviors, see:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
