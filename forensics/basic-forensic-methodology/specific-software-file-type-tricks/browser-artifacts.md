# Browser Artifacts

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Browsers Artifacts <a href="#3def" id="3def"></a>

When we talk about browser artifacts we talk about, navigation history, bookmarks, list of downloaded files, cache data, etc.

These artifacts are files stored inside specific folders in the operating system.

Each browser stores its files in a different place than other browsers and they all have different names, but they all store (most of the time) the same type of data (artifacts).

Let us take a look at the most common artifacts stored by browsers.

* **Navigation History:** Contains data about the navigation history of the user. Can be used to track down if the user has visited some malicious sites for example
* **Autocomplete Data:** This is the data that the browser suggests based on what you search for the most. Can be used in tandem with the navigation history to get more insight.
* **Bookmarks:** Self Explanatory.
* **Extensions and Add ons:** Self Explanatory.
* **Cache:** When navigating websites, the browser creates all sorts of cache data (images, javascript files…etc) for many reasons. For example to speed the loading time of websites. These cache files can be a great source of data during a forensic investigation.
* **Logins:** Self Explanatory.
* **Favicons:** They are the little icons found in tabs, urls, bookmarks and the such. They can be used as another source to get more information about the website or places the user visited.
* **Browser Sessions:** Self Explanatory.
* **Downloads**: Self Explanatory.
* **Form Data:** Anything typed inside forms is oftentimes stored by the browser, so the next time the user enters something inside of a form the browser can suggest previously entered data.
* **Thumbnails:** Self Explanatory.
* **Custom Dictionary.txt**: Words added to the dictionary by the user.

## Firefox

Firefox create the profiles folder in \~/_**.mozilla/firefox/**_ (Linux), in **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Inside this folder, the file _**profiles.ini**_ should appear with the name(s) of the user profile(s).\
Each profile has a "**Path**" variable with the name of the folder where its data is going to be stored. The folder should be **present in the same directory where the \_profiles.ini**\_\*\* exist\*\*. If it isn't, then, probably it was deleted.

Inside the folder **of each profile** (_\~/.mozilla/firefox/\<ProfileName>/_) path you should be able to find the following interesting files:

* _**places.sqlite**_ : History (moz\_\_places), bookmarks (moz\_bookmarks), and downloads (moz\_\_annos). In Windows the tool [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) can be used to read the history inside _**places.sqlite**_.
  * Query to dump history: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
    * Note that a link type is a number that indicates:
      * 1: User followed a link
      * 2: User wrote the URL
      * 3: User used a favorite
      * 4: Loaded from Iframe
      * 5: Accessed via HTTP redirect 301
      * 6: Accessed via HTTP redirect 302
      * 7: Downloaded file
      * 8: User followed a link inside an Iframe
  * Query to dump downloads: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
  *
* _**bookmarkbackups/**_ : Bookmarks backups
* _**formhistory.sqlite**_ : **Web form data** (like emails)
* _**handlers.json**_ : Protocol handlers (like, which app is going to handle _mailto://_ protocol)
* _**persdict.dat**_ : Words added to the dictionary
* _**addons.json**_ and \_**extensions.sqlite** \_ : Installed addons and extensions
* _**cookies.sqlite**_ : Contains **cookies.** [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) can be used in Windows to inspect this file.
*   _**cache2/entries**_ or _**startupCache**_ : Cache data (\~350MB). Tricks like **data carving** can also be used to obtain the files saved in the cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) can be used to see the **files saved in the cache**.

    Information that can be obtained:

    * URL, fetch Count, Filename, Content type, File size, Last modified time, Last fetched time, Server Last Modified, Server Response
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Settings and Preferences
* _**downloads.sqlite**_ : Old downloads database (now it's inside places.sqlite)
* _**thumbnails/**_ : Thumbnails
* _**logins.json**_ : Encrypted usernames and passwords
* **Browser’s built-in anti-phishing:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
  * Will return “safebrowsing.malware.enabled” and “phishing.enabled” as false if the safe search settings have been disabled
* _**key4.db**_ or _**key3.db**_ : Master key?

To try to decrypt the master password, you can use [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
With the following script and call you can specify a password file to brute force:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome creates the profile inside the home of the user _**\~/.config/google-chrome/**_ (Linux), in _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), or in \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
Most of the information will be saved inside the _**Default/**_ or _**ChromeDefaultData/**_ folders inside the paths indicated before. Here you can find the following interesting files:

* _**History**_: URLs, downloads and even searched keywords. In Windows, you can use the tool [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) to read the history. The "Transition Type" column means:
  * Link: User clicked on a link
  * Typed: The url was written
  * Auto Bookmark
  * Auto Subframe: Add
  * Start page: Home page
  * Form Submit: A form was filled and sent
  * Reloaded
* _**Cookies**_: Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) can be used to inspect the cookies.
* _**Cache**_: Cache. In Windows, you can use the tool [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) to inspect the ca
* _**Bookmarks**_: Bookmarks
* _**Web Data**_: Form History
* _**Favicons**_: Favicons
* _**Login Data**_: Login information (usernames, passwords...)
* _**Current Session**_ and _**Current Tabs**_: Current session data and current tabs
* _**Last Session**_ and _**Last Tabs**_: These files hold sites that were active in the browser when Chrome was last closed.
* _**Extensions**_: Extensions and addons folder
* **Thumbnails** : Thumbnails
* **Preferences**: This file contains a plethora of good information such as plugins, extensions, sites using geolocation, popups, notifications, DNS prefetching, certificate exceptions, and much more. If you’re trying to research whether or not a specific Chrome setting was enabled, you will likely find that setting in here.
* **Browser’s built-in anti-phishing:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
  * You can simply grep for “**safebrowsing**” and look for `{"enabled: true,"}` in the result to indicate anti-phishing and malware protection is on.

## **SQLite DB Data Recovery**

As you can observe in the previous sections, both Chrome and Firefox use **SQLite** databases to store the data. It's possible to **recover deleted entries using the tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **or** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer stores **data** and **metadata** in different locations. The metadata will allow finding the data.

The **metadata** can be found in the folder `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` where VX can be V01, V16, or V24.\
In the previous folder, you can also find the file V01.log. In case the **modified time** of this file and the WebcacheVX.data file **are different** you may need to run the command `esentutl /r V01 /d` to **fix** possible **incompatibilities**.

Once **recovered** this artifact (It's an ESE database, photorec can recover it with the options Exchange Database or EDB) you can use the program [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) to open it. Once **opened**, go to the table named "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Inside this table, you can find in which other tables or containers each part of the stored information is saved. Following that, you can find the **locations of the data** stored by the browsers and the **metadata** that is inside.

**Note that this table indicates metadata of the cache for other Microsoft tools also (e.g. skype)**

### Cache

You can use the tool [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) to inspect the cache. You need to indicate the folder where you have extracted the cache date.

#### Metadata

The metadata information about the cache stores:

* Filename in the disc
* SecureDIrectory: Location of the file inside the cache directories
* AccessCount: Number of times it was saved in the cache
* URL: The url origin
* CreationTime: First time it was cached
* AccessedTime: Time when the cache was used
* ModifiedTime: Last webpage version
* ExpiryTime: Time when the cache will expire

#### Files

The cache information can be found in _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ and _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

The information inside these folders is a **snapshot of what the user was seeing**. The caches have a size of **250 MB** and the timestamps indicate when the page was visited (first time, creation date of the NTFS, last time, modification time of the NTFS).

### Cookies

You can use the tool [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) to inspect the cookies. You need to indicate the folder where you have extracted the cookies.

#### **Metadata**

The metadata information about the cookies stored:

* Cookie name in the filesystem
* URL
* AccessCount: Number of times the cookies have been sent to the server
* CreationTime: First time the cookie was created
* ModifiedTime: Last time the cookie was modified
* AccessedTime: Last time the cookie was accessed
* ExpiryTime: Time of expiration of the cookie

#### Files

The cookies data can be found in _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ and _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Session cookies will reside in memory and persistent cookie in the disk.

### Downloads

#### **Metadata**

Checking the tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) you can find the container with the metadata of the downloads:

![](<../../../.gitbook/assets/image (445).png>)

Getting the information of the column "ResponseHeaders" you can transform from hex that information and obtain the URL, the file type and the location of the downloaded file.

#### Files

Look in the path _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **History**

The tool [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) can be used to read the history. But first, you need to indicate the browser in advanced options and the location of the extracted history files.

#### **Metadata**

* ModifiedTime: First time a URL is found
* AccessedTime: Last time
* AccessCount: Number of times accessed

#### **Files**

Search in _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ and _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **Typed URLs**

This information can be found inside the registry NTDUSER.DAT in the path:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
  * Stores the last 50 URLs typed by the user
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
  * last time the URL was typed

## Microsoft Edge

For analyzing Microsoft Edge artifacts all the **explanations about cache and locations from the previous section (IE 11) remain valid** with the only difference that the base locating, in this case, is _**%userprofile%\Appdata\Local\Packages**_ (as can be observed in the following paths):

* Profile Path: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* History, Cookies and Downloads: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Settings, Bookmarks, and Reading List: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Last active sessions: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

The databases can be found in `/Users/$User/Library/Safari`

* **History.db**: The tables `history_visits` _and_ `history_items` contains information about the history and timestamps.
  * `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: Contains the info about the downloaded files.
* **Book-marks.plis**t: URLs bookmarked.
* **TopSites.plist**: List of the most visited websites that the user browses to.
* **Extensions.plist**: To retrieve an old-style list of Safari browser extensions.
  * `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
  * `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: Domains that are allowed to push notifications.
  * `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Tabs that were opened the last time the user exited Safari.
  * `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Browser’s built-in anti-phishing:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
  * The reply should be 1 to indicate the setting is active

## Opera

The databases can be found in `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

Opera **stores browser history and download data in the exact same format as Google Chrome**. This applies to the file names as well as the table names.

* **Browser’s built-in anti-phishing:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
  * **fraud\_protection\_enabled** should be **true**

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
