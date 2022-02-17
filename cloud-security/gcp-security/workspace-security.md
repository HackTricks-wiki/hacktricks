# Workspace Security

## Google Groups Privesc

By default in workspace a **group** can be **freely accessed** by any member of the organization.\
Workspace also allow to **grant permission to groups** (even GCP permissions), so if groups can be joined and they have extra permissions, an attacker may **abuse that path to escalate privileges**.

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

![](<../../.gitbook/assets/image (662).png>)

But can be prevented with:

![](<../../.gitbook/assets/image (632).png>)

### Shared Document Unverified Prompt Bypass

Moreover, if someone **shared** with you a document with **editor access**, you can generate **App Scripts inside the document** and the **OWNER (creator) of the document will be the owner of the App Script**.

{% hint style="warning" %}
This means, that the **creator of the document will appear as creator of any App Script** anyone with editor access creates inside of it.

This also means that the **App Script will be trusted by the Workspace environment** of the creator of the document.
{% endhint %}

{% hint style="danger" %}
This also means that if an **App Script already existed** and people has **granted access**, anyone with **Editor** permission to the doc can **modify it and abuse that access.**\
****To abuse this you also need people to trigger the App Script. And one neat trick if to **publish the script as a web app**. When the **people** that already granted **access** to the App Script access the web page, they will **trigger the App Script** (this also works using `<img>` tags.
{% endhint %}

## Post-Exploitation

### Google Drive

When **sharing** a document yo can **specify** the **people** that can access it one by one, **share** it with your **entire company** (**or** with some specific **groups**) by **generating a link**.

When sharing a document, in the advance setting you can also **allow people to search** for this file (by **default** this is **disabled**). However, it's important to note that once users views a document, it's searchable by them.

For sake of simplicity, most of the people will generate and share a link instead of adding the people that can access the document one by one.

Some proposed ways to find all the documents:

* Search in internal chat, forums...
* **Spider** known **documents** searching for **references** to other documents. You can do this within an App Script with[ **PaperChaser**](https://github.com/mandatoryprogrammer/PaperChaser)****

### **Gmail**

* You can create **filters to hide** security notifications from Google
  * from: (no-reply@accounts.google.com) "Security Alert"
  * Hide password reset emails
* Create **forwarding address to send sensitive information** (You need manual access)
  * Create a forwarding address to send emails that contains the word "password" for example

### App Scripts

* Create **time-based triggers** to main **persistance**
  * The docs mention that to use `ScriptApp.newTrigger("funcion")` you need the **scope** `script.scriptapp`, but **apparently thats not necessary** as long as you have declare some other scope..

## References

* [https://www.youtube-nocookie.com/embed/6AsVUS79gLw](https://www.youtube-nocookie.com/embed/6AsVUS79gLw) - Matthew Bryant - Hacking G Suite: The Power of Dark Apps Script Magic
