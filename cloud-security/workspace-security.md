# Workspace Security

## Workspace Phishing

### Generic Phishing Methodology

{% content-ref url="../phishing-methodology/" %}
[phishing-methodology](../phishing-methodology/)
{% endcontent-ref %}

### Google Groups Phishing

Apparently by default in workspace members [**can create groups**](https://groups.google.com/all-groups) **and invite people to them**. You can then modify the email that will be sent to the user **adding some links.** The **email will come from a google address**, so it will looks **legit** and people might click on the link.

### Hangout Phishing

You might be able either to directly talk with a person just having his email address or sending an invitation to talk. Either way, modify an email account maybe naming it "Google Security" and adding some Google logos, and the people will think they are talking to google: [https://www.youtube.com/watch?v=KTVHLolz6cE\&t=904s](https://www.youtube.com/watch?v=KTVHLolz6cE\&t=904s)

Just the **same technique** can be used with **Google Chat**.

### Google Doc Phishing

You can create an **apparently legitimate document** and the in a comment **mention some email (like +user@gmail.com)**. Google will **send an email to that email address** notifying that he was mentioned in the document. You can **put a link in that document** to try to make the persona access it.

### Google Calendar Phishing

You can **create a calendar event** and add as many email address of the company you are attacking as you have. Schedule this calendar event in **5 or 15 min** from the current time. Make the event looks legit and **put a comment indicating that they need to read something** (with the **phishing link**).\
To make it looks less suspicious:

* Set that the **receivers cannot see the other invited people**
* Do **NOT send emails notifying about the event**. Then, the people will only see their warning about a meeting in 5mins and that they need to read that link.
* Apparently using the API you can set to **True** that **people** has **accepted** the event and even create **comments on their behalf**.

### OAuth Phishing

Any of the previous techniques might be used to make the user access a **Google OAuth application** that will **request** the user some **access**. If the user **trust** the **source** he might **trust** the **application** (even if it's asking for high privileged permissions).

Note that Google presents an ugly prompt asking warning that the application is untrusted in several cases and from Workspace admins can even prevent people to accept OAuth applications. More on this in the OAuth section.

## Password Spraying

In order to test passwords with all the emails you found (or you have generated based in a email name pattern you might have discover) you can use a tool like [**https://github.com/ustayready/CredKing**](https://github.com/ustayready/CredKing) who will use AWS lambdas to change IP address.

## Oauth Apps

**Google** allows to create applications that can **interact on behalf users** with several **Google services**: Gmail, Drive, GCP...

When creating an application to **act on behalf other users**, the developer needs to create an **OAuth app inside GCP** and indicate the scopes (permissions) the app needs to access the users data.\
When a **user** wants to **use** that **application**, he will be **prompted** to **accept** that the application will access to his data specified in the scopes.

This is a very juicy way to **phish** non-technical users into using **applications that access sensitive information** because they might not understand the consequences. Therefore, in organizations accounts, there are ways to prevent this from happening.

### Unverified App prompt

As it was mentioned, google will always present a **prompt to the user to accept** the permissions he is giving the application on his behalf. However, if the application is considered **dangerous**, google will show **first** a **prompt** indicating that it's **dangerous** and **making more difficult** to the user to grant the permissions to the app.

This prompt appears in apps that:

* Uses any scope that can access to private data (Gmail, Drive, GCP, BigQuery...)
* Apps with less than 100 users (apps > 100 a review process is needed also to not show the unverified prompt)

### Interesting Scopes

You can [**find here**](https://developers.google.com/identity/protocols/oauth2/scopes) a list of all the Google OAuth scopes.

* **cloud-platform**: View and manage your data across **Google Cloud Platform** services. You can impersonate the user in GCP.
* **directory.readonly**: See and download your organization's GSuite directory. Get names, phones, calendar URLs of all the users.

## App Scripts

Developers can create App Scripts and set them as a standalone project or bound them to Google Docs/Sheets/Slides/Forms. App Scripts is code that will be triggered when a user with editor permission access the doc (and after accepting the OAuth prompt)

However, even if the app isn't verified there are a couple of ways to not show that prompt:

* If the publisher of the app is in the same Workspace as the user accessing it
* If the script is in a drive of the user

### Copy Document Unverified Prompt Bypass

When you create a link to share a document a link similar to this one is created: `https://docs.google.com/spreadsheets/d/1i5[...]aIUD/edit`\
If you **change** the ending **"/edit"** for **"/copy"**, instead of accessing it google will ask you if you want to **generate a copy of the document.**

{% hint style="warning" %}
If someone creates a **copy** of that **document** that **contained the App Script**, he will also be **copying the App Script**, therefore when he **opens** the copied **spreadsheet**, the **regular OAuth prompt** will appear **bypassing the unverified prompt**, because **the user is now the author of the App Script of the copied file**.
{% endhint %}

This method will be able to bypass also the Workspace admin restriction:

![](<../.gitbook/assets/image (662) (1) (1).png>)

But can be prevented with:

![](<../.gitbook/assets/image (632).png>)

### Shared Document Unverified Prompt Bypass

Moreover, if someone **shared** with you a document with **editor access**, you can generate **App Scripts inside the document** and the **OWNER (creator) of the document will be the owner of the App Script**.

{% hint style="warning" %}
This means, that the **creator of the document will appear as creator of any App Script** anyone with editor access creates inside of it.

This also means that the **App Script will be trusted by the Workspace environment** of the creator of the document.
{% endhint %}

{% hint style="danger" %}
This also means that if an **App Script already existed** and people has **granted access**, anyone with **Editor** permission to the doc can **modify it and abuse that access.**\
To abuse this you also need people to trigger the App Script. And one neat trick if to **publish the script as a web app**. When the **people** that already granted **access** to the App Script access the web page, they will **trigger the App Script** (this also works using `<img>` tags.
{% endhint %}

## Post-Exploitation

### Google Groups Privesc

By default in workspace a **group** can be **freely accessed** by any member of the organization.\
Workspace also allow to **grant permission to groups** (even GCP permissions), so if groups can be joined and they have extra permissions, an attacker may **abuse that path to escalate privileges**.

You potentially need access to the console to join groups that allow to be joined by anyone in the org. Check groups information in [**https://groups.google.com/all-groups**](https://groups.google.com/all-groups).

### Privesc to GCP Summary

* Abusing the **google groups privesc** you might be able to escalate to a group with some kind of privileged access to GCP
* Abusing **OAuth applications** you might be able to impersonate users and access to GCP on their behalf

### Access Groups Mail info

If you managed to **compromise a google user session**, from [**https://groups.google.com/all-groups**](https://groups.google.com/all-groups)  you can see the history of mails sent to the mail groups the user is member of, and you might find **credentials** or other **sensitive data**.

### Takeout - Download Everything Google Knows about an account

If you have a **session inside victims google account** you can download everything Google saves about that account from [**https://takeout.google.com**](https://takeout.google.com/u/1/?pageId=none)

### Vault - Download all the Workspace data of users

If an organization has **Google Vault enabled**, you might be able to access [**https://vault.google.com**](https://vault.google.com/u/1/)  and **download** all the **information**.

### Contacts download

From [**https://contacts.google.com**](https://contacts.google.com/u/1/?hl=es\&tab=mC) you can download all the **contacts** of the user.

### Cloudsearch

In [**https://cloudsearch.google.com/**](https://cloudsearch.google.com) you can just search **through all the Workspace content** (email, drive, sites...) a user has access to. Ideal to **find quickly sensitive information**.

### Currents

In [**https://currents.google.com/**](https://currents.google.com) you can access a Google **Chat**, so you might find sensitive information in there.

### Google Drive Mining

When **sharing** a document yo can **specify** the **people** that can access it one by one, **share** it with your **entire company** (**or** with some specific **groups**) by **generating a link**.

When sharing a document, in the advance setting you can also **allow people to search** for this file (by **default** this is **disabled**). However, it's important to note that once users views a document, it's searchable by them.

For sake of simplicity, most of the people will generate and share a link instead of adding the people that can access the document one by one.

Some proposed ways to find all the documents:

* Search in internal chat, forums...
* **Spider** known **documents** searching for **references** to other documents. You can do this within an App Script with[ **PaperChaser**](https://github.com/mandatoryprogrammer/PaperChaser)

### **Keep Notes**

In [**https://keep.google.com/**](https://keep.google.com) you can access the notes of the user, **sensitive** **information** might be saved in here.

### Persistence inside a Google account

If you managed to **compromise a google user session** and the user had **2FA**, you can **generate** an [**app password**](https://support.google.com/accounts/answer/185833?hl=en) and **regenerate the 2FA backup codes** to know that even if the user change the password you **will be able to access his account**. Another option **instead** of **regenerating** the codes is to **enrol your own authenticator** app in the 2FA.

### Persistence via OAuth Apps

If you have **compromised the account of a user,** you can just **accept** to grant all the possible permissions to an **OAuth App**. The only problem is that Workspace can configure to **disallow external and/or internal OAuth apps** without being reviewed.\
It is pretty common to not trust by default external OAuth apps but trust internal ones, so if you have **enough permissions to generate a new OAuth application** inside the organization and external apps are disallowed, generate it and **use that new internal OAuth app to maintain persistence**.

### Persistence via delegation

You can just **delegate the account** to a different account controlled by the attacker.

### Persistence via Android App

If you have a **session inside victims google account** you can browse to the **Play Store** and **install** a **malware** you have already uploaded it directly **in the phone** to maintain persistence and access the victims phone.

### **Persistence via Gmail**

* You can create **filters to hide** security notifications from Google
  * from: (no-reply@accounts.google.com) "Security Alert"
  * Hide password reset emails
* Create **forwarding address to forward sensitive information** (or everything) - You need manual access.
  * Create a forwarding address to send emails that contains the word "password" for example
* Add **recovery email/phone under attackers control**

### **Persistence via** App Scripts

You can create **time-based triggers** in App Scripts, so if the App Script is accepted by the user, it will be **triggered** even **without the user accessing it**.

The docs mention that to use `ScriptApp.newTrigger("funcion")` you need the **scope** `script.scriptapp`, but **apparently thats not necessary** as long as you have declare some other scope.

### **Administrate Workspace**

In [**https://admin.google.com**/](https://admin.google.com), if you have enough permissions you might be able to modify settings in the Workspace of the whole organization.

You can also search emails through all the users invoices in [**https://admin.google.com/ac/emaillogsearch**](https://admin.google.com/ac/emaillogsearch)

## Account Compromised Recovery

* Log out of all sessions
* Change user password
* Generate new 2FA backup codes
* Remove App passwords
* Remove OAuth apps
* Remove 2FA devices
* Remove email forwarders
* Remove emails filters
* Remove recovery email/phones
* Remove bad Android Apps
* Remove bad account delegations

## References

* [https://www.youtube-nocookie.com/embed/6AsVUS79gLw](https://www.youtube-nocookie.com/embed/6AsVUS79gLw) - Matthew Bryant - Hacking G Suite: The Power of Dark Apps Script Magic
* [https://www.youtube.com/watch?v=KTVHLolz6cE](https://www.youtube.com/watch?v=KTVHLolz6cE) - Mike Felch and Beau Bullock - OK Google, How do I Red Team GSuite?
