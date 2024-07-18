# Browser Artifacts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts include various types of data stored by web browsers, such as navigation history, bookmarks, and cache data. These artifacts are kept in specific folders within the operating system, differing in location and name across browsers, yet generally storing similar data types.

Here's a summary of the most common browser artifacts:

* **Navigation History**: Tracks user visits to websites, useful for identifying visits to malicious sites.
* **Autocomplete Data**: Suggestions based on frequent searches, offering insights when combined with navigation history.
* **Bookmarks**: Sites saved by the user for quick access.
* **Extensions and Add-ons**: Browser extensions or add-ons installed by the user.
* **Cache**: Stores web content (e.g., images, JavaScript files) to improve website loading times, valuable for forensic analysis.
* **Logins**: Stored login credentials.
* **Favicons**: Icons associated with websites, appearing in tabs and bookmarks, useful for additional information on user visits.
* **Browser Sessions**: Data related to open browser sessions.
* **Downloads**: Records of files downloaded through the browser.
* **Form Data**: Information entered in web forms, saved for future autofill suggestions.
* **Thumbnails**: Preview images of websites.
* **Custom Dictionary.txt**: Words added by the user to the browser's dictionary.

## Firefox

Firefox organizes user data within profiles, stored in specific locations based on the operating system:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

A `profiles.ini` file within these directories lists the user profiles. Each profile's data is stored in a folder named in the `Path` variable within `profiles.ini`, located in the same directory as `profiles.ini` itself. If a profile's folder is missing, it may have been deleted.

Within each profile folder, you can find several important files:

* **places.sqlite**: Stores history, bookmarks, and downloads. Tools like [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) on Windows can access the history data.
  * Use specific SQL queries to extract history and downloads information.
* **bookmarkbackups**: Contains backups of bookmarks.
* **formhistory.sqlite**: Stores web form data.
* **handlers.json**: Manages protocol handlers.
* **persdict.dat**: Custom dictionary words.
* **addons.json** and **extensions.sqlite**: Information on installed add-ons and extensions.
* **cookies.sqlite**: Cookie storage, with [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) available for inspection on Windows.
* **cache2/entries** or **startupCache**: Cache data, accessible through tools like [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Stores favicons.
* **prefs.js**: User settings and preferences.
* **downloads.sqlite**: Older downloads database, now integrated into places.sqlite.
* **thumbnails**: Website thumbnails.
* **logins.json**: Encrypted login information.
* **key4.db** or **key3.db**: Stores encryption keys for securing sensitive information.

Additionally, checking the browser’s anti-phishing settings can be done by searching for `browser.safebrowsing` entries in `prefs.js`, indicating whether safe browsing features are enabled or disabled.

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

Google Chrome stores user profiles in specific locations based on the operating system:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Within these directories, most user data can be found in the **Default/** or **ChromeDefaultData/** folders. The following files hold significant data:

* **History**: Contains URLs, downloads, and search keywords. On Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) can be used to read the history. The "Transition Type" column has various meanings, including user clicks on links, typed URLs, form submissions, and page reloads.
* **Cookies**: Stores cookies. For inspection, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) is available.
* **Cache**: Holds cached data. To inspect, Windows users can utilize [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
* **Bookmarks**: User bookmarks.
* **Web Data**: Contains form history.
* **Favicons**: Stores website favicons.
* **Login Data**: Includes login credentials like usernames and passwords.
* **Current Session**/**Current Tabs**: Data about the current browsing session and open tabs.
* **Last Session**/**Last Tabs**: Information about the sites active during the last session before Chrome was closed.
* **Extensions**: Directories for browser extensions and addons.
* **Thumbnails**: Stores website thumbnails.
* **Preferences**: A file rich in information, including settings for plugins, extensions, pop-ups, notifications, and more.
* **Browser’s built-in anti-phishing**: To check if anti-phishing and malware protection are enabled, run `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Look for `{"enabled: true,"}` in the output.

## **SQLite DB Data Recovery**

As you can observe in the previous sections, both Chrome and Firefox use **SQLite** databases to store the data. It's possible to **recover deleted entries using the tool** [**sqlparse**](https://github.com/padfoot999/sqlparse) **or** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 manages its data and metadata across various locations, aiding in separating stored information and its corresponding details for easy access and management.

### Metadata Storage

Metadata for Internet Explorer is stored in `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (with VX being V01, V16, or V24). Accompanying this, the `V01.log` file might show modification time discrepancies with `WebcacheVX.data`, indicating a need for repair using `esentutl /r V01 /d`. This metadata, housed in an ESE database, can be recovered and inspected using tools like photorec and [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), respectively. Within the **Containers** table, one can discern the specific tables or containers where each data segment is stored, including cache details for other Microsoft tools such as Skype.

### Cache Inspection

The [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) tool allows for cache inspection, requiring the cache data extraction folder location. Metadata for cache includes filename, directory, access count, URL origin, and timestamps indicating cache creation, access, modification, and expiry times.

### Cookies Management

Cookies can be explored using [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), with metadata encompassing names, URLs, access counts, and various time-related details. Persistent cookies are stored in `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, with session cookies residing in memory.

### Download Details

Downloads metadata is accessible via [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), with specific containers holding data like URL, file type, and download location. Physical files can be found under `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

To review browsing history, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) can be used, requiring the location of extracted history files and configuration for Internet Explorer. Metadata here includes modification and access times, along with access counts. History files are located in `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Typed URLs and their usage timings are stored within the registry under `NTUSER.DAT` at `Software\Microsoft\InternetExplorer\TypedURLs` and `Software\Microsoft\InternetExplorer\TypedURLsTime`, tracking the last 50 URLs entered by the user and their last input times.

## Microsoft Edge

Microsoft Edge stores user data in `%userprofile%\Appdata\Local\Packages`. The paths for various data types are:

* **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data is stored at `/Users/$User/Library/Safari`. Key files include:

* **History.db**: Contains `history_visits` and `history_items` tables with URLs and visit timestamps. Use `sqlite3` to query.
* **Downloads.plist**: Information about downloaded files.
* **Bookmarks.plist**: Stores bookmarked URLs.
* **TopSites.plist**: Most frequently visited sites.
* **Extensions.plist**: List of Safari browser extensions. Use `plutil` or `pluginkit` to retrieve.
* **UserNotificationPermissions.plist**: Domains permitted to push notifications. Use `plutil` to parse.
* **LastSession.plist**: Tabs from the last session. Use `plutil` to parse.
* **Browser’s built-in anti-phishing**: Check using `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. A response of 1 indicates the feature is active.

## Opera

Opera's data resides in `/Users/$USER/Library/Application Support/com.operasoftware.Opera` and shares Chrome's format for history and downloads.

* **Browser’s built-in anti-phishing**: Verify by checking if `fraud_protection_enabled` in the Preferences file is set to `true` using `grep`.

These paths and commands are crucial for accessing and understanding the browsing data stored by different web browsers.

## References

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
