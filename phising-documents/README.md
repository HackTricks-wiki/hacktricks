# Phising Documents

Microsoft Word performs file data validation prior to opening a file. Data validation is performed in the form of data structure identification, against the OfficeOpenXML standard. If any error occurs during the data structure identification, the file being analysed will not be opened.

Usually Word files containing macros uses the `.docm` extension. However, it's possible to rename the file changing the file extension and still keep their macro executing capabilities.  
For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution.  
The same internals and mechanisms apply to all software of the Microsoft Office Suite \(Excel, PowerPoint etc.\).

You can use the following command to check with extensions are going to be executed by some Office programs:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template \(File –Options –Add-ins –Manage: Templates –Go\) that includes macros can “execute” macros as well.

### Word with external image

Go to: _Insert --&gt; Quick Parts --&gt; Field_  
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**: http://&lt;ip&gt;/whatever_

![](../.gitbook/assets/image%20%28347%29.png)

### Macros Code

```bash
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

## Autoload functions

The more common they are, the more probable the AV will detect it.

* AutoOpen\(\)
* Document\_Open\(\)

## Methodology

1. Recon the victim
   1. Select the victim domain.
   2. Preform some basic web enumeration searching for login portals used by the victim and decide which one you will impersonate.
   3. Use some OSINT to find emails of the domain



## Generate similar domain names

### Domain Name Variation Techniques

* **Keyword**: The domain name **contains** an important **keyword** of the original domain \(e.g., zelster.com-management.com\).
* **hypened subdomain**: Change the **dot for a hyphen** of a subdomain \(e.g., www-zelster.com\).
* **New TLD**: Same domain using a **new TLD** \(e.g., zelster.org\)
* **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** \(e.g., zelfser.com\).
* **Transposition:** It **swaps two letters** within the domain name \(e.g., zelster.com\).
* **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name \(e.g., zeltsers.com\).
* **Omission**: It **removes one** of the letters from the domain name \(e.g., zelser.com\).
* **Repetition:** It **repeats one** of the letters in the domain name \(e.g., zeltsser.com\).
* **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard \(e.g, zektser.com\).
* **Subdomained**: Introduce a **dot** inside the domain name \(e.g., ze.lster.com\).
* **Insertion**: It **inserts a letter** into the domain name \(e.g., zerltser.com\).
* **Bitsquatting:** It anticipates a small portion of systems encountering hardware errors, resulting in the mutation of the resolved domain name by 1 bit. \(e.g., xeltser.com\).
* **Missing dot**: Append the TLD to the domain name. \(e.g., zelstercom.com\)

### Automatic Tools

* \*\*\*\*[**dnstwist**](https://github.com/elceef/dnstwist)\*\*\*\*
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)\*\*\*\*

### **Websites**

* [https://dnstwist.it/](https://dnstwist.it/)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

## GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute  `/opt/gophish/gophish`  
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local: 

```bash
ssh -L 333:127.0.0.1:3333 <user>@<ip>
```

### Configuration

#### TLS certificate configuration

Before this step you should have **already bought the domain** you are going to use and it must be **pointing** to the **IP of the VPS** where you are configuring **gophish**.

```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```

#### Mail configuration

Start installing:  `apt-get install postfix`

Then add the domain to the following files:

* **/etc/postfix/virtual\_domains** 
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>  
mydestination = $myhostname, <domain>, localhost.com, localhost`

Finally modify the files **`/etc/hostname`** and **`/etc/mailname`** to your domain name and **restart your VPS.**

Now, create a **DNS A record** of `mail.<domain>` pointing to the **ip address** of the VPS and a **DNS MX** record pointing to `mail.<domain>` 

Now lets test to send an email:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

#### Gophish configuration

Stop the execution of gophish and lets configure it.  
Modify `/opt/gophish/config.json` to the following \(note the use of https\):

```bash
{
        "admin_server": {
                "listen_url": "127.0.0.1:3333",
                "use_tls": true,
                "cert_path": "gophish_admin.crt",
                "key_path": "gophish_admin.key"
        },
        "phish_server": {
                "listen_url": "0.0.0.0:443",
                "use_tls": true,
                "cert_path": "/opt/gophish/ssl_keys/key.crt",
                "key_path": "/opt/gophish/ssl_keys/key.pem"
        },
        "db_name": "sqlite3",
        "db_path": "gophish.db",
        "migrations_prefix": "db/db_",
        "contact_address": "",
        "logging": {
                "filename": "",
                "level": ""
        }
}
```

#### Configure gophish service

In order to create the gophish service so it can be started automatically and managed a service you can create the file `/etc/init.d/gophish` with the following content:

```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}

stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/bin/pidof ${process})
    kill ${pid}
    sleep 1 
}

status() {
    pid=$(/bin/pidof ${process})
    if [["$pid" != ""| "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}

case $1 in
    start|stop|status) "$1" ;;
esac
```

Finish configuring the service and checking it doing:

```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```

## SPAM filters bypass

### Wait

The older a domain is the less probable it's going to be caught as spam. Then you should wait as much time as possible \(at least 1week\) before the phishing assessment.  
Note that even if you have to wait a week you can finish configuring everything now. 

### Configure Reverse DNS \(rDNS\) record

Set a rDNS \(PTR\) record that resolves the IP address of the VPS to the domain name.

### Sender Policy Framework \(SPF\) Record

You must **configure a SPF record for the new domain**. If you don't know what is a SPF record read the following page:

{% page-ref page="../pentesting/pentesting-smtp/" %}

You can use [https://www.spfwizard.net/](https://www.spfwizard.net/) to generate your SPF policy \(use the IP of the VPS machine\)

![](../.gitbook/assets/image%20%28398%29.png)

This is the content that must be set inside a TXT record inside the domain:

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance \(DMARC\) Record

You must **configure a DMARC record for the new domain**. If you don't know what is a DMARC record read the following page:

{% page-ref page="../pentesting/pentesting-smtp/" %}

You have to create a new DNS TXT record pointing the hostname `_dmarc.<domain>` with the following content:

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail \(DKIM\)

You must **configure a DKIM for the new domain**. If you don't know what is a DMARC record read the following page:

{% page-ref page="../pentesting/pentesting-smtp/" %}

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)  
Just access the page and send an email to the address they give you:

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

### ​Removing from Spamhouse Blacklist

The page www.mail-tester.com can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com/).

## References

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)

