# Browser Artifacts

## Browsers Artefacts <a id="3def"></a>

When we talk about browser artefacts we talk about, navigation history, bookmarks, list of downloaded files, cache data…etc.

These artefacts are files stored inside of specific folders in the operating system.

Each browser stores its files in a different place than other browsers and they all have different names, but they all store \(most of the time\) the same type of data \(artefacts\).

Let us take a look at the most common artefacts stored by browsers.

* **Navigation History :** Contains data about the navigation history of the user. Can be used to track down if the user has visited some malicious sites for example
* **Autocomplete Data :** This is the data that the browser suggest based on what you search the most. Can be used in tandem with the navigation history to get more insight.
* **Bookmarks :** Self Explanatory.
* **Extensions and Addons :** Self Explanatory.
* **Cache :** When navigating websites, the browser creates all sorts of cache data \(images, javascript files…etc\) for many reasons. For example to speed loading time of websites. These cache files can be a great source of data during a forensic investigation.
* **Logins :** Self Explanatory.
* **Favicons :** They are the little icons found in tabs, urls, bookmarks and the such. They can be used as another source to get more information about the website or places the user visited.
* **Browser Sessions :** Self Explanatory.
* **Downloads :**Self Explanatory.
* **Form Data :** Anything typed inside forms is often times stored by the browser, so the next time the user enters something inside of a form the browser can suggest previously entered data.
* **Thumbnails :** Self Explanatory.

## Firefox

Firefox use to create the profiles folder in ~/_**.mozilla/firefox/**_ \(Linux\) ****or in _**C:\Users\XXX\AppData\Roaming\Mozilla\Firefox\Profiles\**_ \(Windows\)_**.**_  
Inside this folder, the file _**profiles.ini**_ should appear with the name\(s\) of the used profile\(s\).  
Each profile has a "**Path**" variable with the name of the folder where it's data is going to be stored. The folder should be **present in the same directory where the** _**profiles.ini**_ **exist**. If it isn't, then, probably it was deleted.

Inside the folder **of each profile** \(_~/.mozilla/firefox/&lt;ProfileName&gt;/_\) path you should be able to find the following interesting files:

* _**places.sqlite**_ : History \(_moz\_places_\) and bookmarks \(_moz\_bookmarks_\)
* _**bookmarkbackups/**_ : Bookmarks backups
* _**formhistory.sqlite**_ : **Web form data** \(like emails\)
* _**handlers.json**_ : Protocol handlers \(like, which app is going to handle _mailto://_ protocol\)
* _**persdict.dat**_ : Words added to the dictionary
* _**addons.json**_ and _**extensions.sqlite**_ : Installed addons and extensions
* _**cookies.sqlite**_ : Contains **cookies**
* _**cache2/entries**_ or _**startupCache**_ : Cache data
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Settings and Preferences
* _**downloads.sqlite**_ : Downloads
* _**thumbnails/**_ : Thumbnails
* _**logins.json**_ : Encrypted usernames and passwords
* _**key4.db**_ or _**key3.db**_ : Master key ?

In order to try to decrypt the master password you can use [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox_decrypt)  
With the following script and call you can specify a password file to bruteforce:

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

![](../../.gitbook/assets/image%20%2873%29.png)

## Google Chrome

Google Chrome creates the profile inside the home of the user _**~/.config/google-chrome/**_ \(Linux\) or in _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\**_ \(Windows\).  
Most of the information will be saved inside the _**Default/**_ or _**ChromeDefaultData/**_ folders inside the paths indicated before. Inside here you can find the following interesting files:

* _**History**_ : URLs, downloads and even searched keywords
* _**Cookies**_ : Cookies
* _**Cache**_ : Cache
* _**Bookmarks**_ : **** Bookmarks 
* _**Web Data**_ : Form History
* _**Favicons**_ : Favicons
* _**Login Data**_ : Login information \(usernames, passwords...\)
* _**Current Session**_ and _**Current Tabs**_ : Current session data and current tabs
* _**Last Session**_ and _**Last Tabs**_ : Old session and tabs
* _**Extensions/**_ : Extensions and addons folder
* **Thumbnails** : Thumbnails

## Microsoft Edge

* Profile Path: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* History, Cookies and Downloads: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Settings, Bookmarks, and Reading List: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\#!XXX\MicrosoftEdge\Cache**_
* Last active sessions: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

