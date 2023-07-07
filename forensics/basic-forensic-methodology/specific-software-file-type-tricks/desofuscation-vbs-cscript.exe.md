<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


悪意のあるVBSファイルをデバッグ/復号化するのに役立ついくつかのこと:

## echo
```bash
Wscript.Echo "Like this?"
```
## コメント

このセクションでは、VBSスクリプトの逆コンパイルと復号化について説明します。これは、CScript.exeを使用して実行されるVBSスクリプトの解析に役立ちます。

### VBSスクリプトの逆コンパイル

VBSスクリプトを逆コンパイルするためには、CScript.exeを使用します。以下のコマンドを使用して、スクリプトを逆コンパイルします。

```plaintext
cscript.exe /E:vbscript script.vbe > script.vbs
```

このコマンドは、VBE形式のスクリプトをVBS形式に変換します。変換されたスクリプトは、`script.vbs`という名前のファイルに保存されます。

### VBSスクリプトの復号化

VBSスクリプトが暗号化されている場合、以下の手順を使用して復号化できます。

1. スクリプトを逆コンパイルします（前のセクションで説明した方法を使用）。
2. 復号化関数を特定します。これは、スクリプト内の暗号化された部分を復号化するための関数です。
3. 復号化関数の実装を調査し、暗号化アルゴリズムや鍵の情報を取得します。
4. 取得した情報を使用して、暗号化された部分を復号化します。

以上がVBSスクリプトの逆コンパイルと復号化の基本的な手法です。これらの手法を使用することで、暗号化されたVBSスクリプトの解析が可能になります。
```text
' this is a comment
```
## テスト
```text
cscript.exe file.vbs
```
## ファイルにデータを書き込む

To write data to a file in Python, you can use the `write()` method of a file object. Here is an example:

```python
# Open the file in write mode
file = open("filename.txt", "w")

# Write data to the file
file.write("Hello, World!")

# Close the file
file.close()
```

In this example, we first open the file `"filename.txt"` in write mode using the `open()` function. The `"w"` argument specifies that we want to open the file for writing. If the file doesn't exist, it will be created. If it already exists, its contents will be overwritten.

Next, we use the `write()` method of the file object to write the string `"Hello, World!"` to the file.

Finally, we close the file using the `close()` method to ensure that any changes are saved and resources are freed.

Remember to handle exceptions when working with files, and always close the file after you are done writing to it.
```aspnet
Function writeBinary(strBinary, strPath)

Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

' below lines purpose: checks that write access is possible!
Dim oTxtStream

On Error Resume Next
Set oTxtStream = oFSO.createTextFile(strPath)

If Err.number <> 0 Then MsgBox(Err.message) : Exit Function
On Error GoTo 0

Set oTxtStream = Nothing
' end check of write access

With oFSO.createTextFile(strPath)
.Write(strBinary)
.Close
End With

End Function
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
