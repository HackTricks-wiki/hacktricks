# Android APK Checklist

### [Learn Android fundamentals](android-app-pentesting/#2-android-application-fundamentals)

* [ ] [Basics](android-app-pentesting/#fundamentals-review)
* [ ] [Dalvik & Smali](android-app-pentesting/#dalvik--smali)
* [ ] [Entry points](android-app-pentesting/#application-entry-points)
  * [ ] [Activities](android-app-pentesting/#launcher-activity)
  * [ ] [URL Schemes](android-app-pentesting/#url-schemes)
  * [ ] [Content Providers](android-app-pentesting/#services)
  * [ ] [Services](android-app-pentesting/#services-1)
  * [ ] [Broadcast Receivers](android-app-pentesting/#broadcast-receivers)
  * [ ] [Intents](android-app-pentesting/#intents)
  * [ ] [Intent Filter](android-app-pentesting/#intent-filter)
* [ ] [Other components](android-app-pentesting/#other-app-components)
* [ ] [How to use ADB](android-app-pentesting/#adb-android-debug-bridge)
* [ ] [How to modify Smali](android-app-pentesting/#smali)

### [Static Analysis](android-app-pentesting/#static-analysis)

* [ ] Check for the use of [obfuscation](android-checklist.md#some-obfuscation-deobfuscation-information), checks for noting if the mobile was rooted, if an emulator is being used and anti-tampering checks. [Read this for more info](android-app-pentesting/#other-checks).
* [ ] Sensitive applications \(like bank apps\) should check if the mobile is rooted and should actuate in consequence.
* [ ] Search for [interesting strings](android-app-pentesting/#looking-for-interesting-info) \(passwords, URLs, API, encryption, backdoors, tokens, Bluetooth uuids...\).
  * [ ] Special attention to [firebase ](android-app-pentesting/#firebase)APIs.
* [ ] [Read the manifest:](android-app-pentesting/#basic-understanding-of-the-application-manifest-xml)
  * [ ] Check if the application is in debug mode and try to "exploit" it
  * [ ] Check if the APK allows backups
  * [ ] Exported Activities
  * [ ] Content Providers
  * [ ] Exposed services
  * [ ] Broadcast Receivers
  * [ ] URL Schemes
* [ ] Is the application s[aving data insecurely internally or externally](android-app-pentesting/#insecure-data-storage)?
* [ ] Is there any [password hard coded or saved in disk](android-app-pentesting/#poorkeymanagementprocesses)? Is the app [using insecurely crypto algorithms](android-app-pentesting/#useofinsecureandordeprecatedalgorithms)?
* [ ] All the libraries compiled using the PIE flag?
* [ ] Don't forget that there is a bunch of[ static Android Analyzers](android-app-pentesting/#automatic-analysis) that can help you a lot during this phase.

### [Dynamic Analysis](android-app-pentesting/#dynamic-analysis)

* [ ] Prepare the environment \([online](android-app-pentesting/#online-dynamic-analysis), [local VM or physical](android-app-pentesting/#local-dynamic-analysis)\)
* [ ] Is there any [unintended data leakage](android-app-pentesting/#unintended-data-leakage) \(logging, copy/paste, crash logs\)?
* [ ] [Confidential information being saved in SQLite dbs](android-app-pentesting/#sqlite-dbs)?
* [ ] [Exploitable exposed Activities](android-app-pentesting/#exploiting-exported-activities-authorisation-bypass)?
* [ ] [Exploitable Content Providers](android-app-pentesting/#exploiting-content-providers-accessing-and-manipulating-sensitive-information)?
* [ ] [Exploitable exposed Services](android-app-pentesting/#exploiting-services)?
* [ ] [Exploitable Broadcast Receivers](android-app-pentesting/#exploiting-broadcast-receivers)?
* [ ] Is the application [transmitting information in clear text/using weak algorithms](android-app-pentesting/#insufficient-transport-layer-protection)? is a MitM possible?
* [ ] [Inspect HTTP/HTTPS traffic](android-app-pentesting/#inspecting-http-traffic)
  * [ ] This one is really important, because if you can capture the HTTP traffic you can search for common Web vulnerabilities \(Hacktricks has a lot of information about Web vulns\).
* [ ] Check for possible [Android Client Side Injections](android-app-pentesting/#android-client-side-injections-and-others) \(probably some static code analysis will help here\)
* [ ] [Frida](android-app-pentesting/#frida): Just Frida, use it to obtain interesting dynamic data from the application \(maybe some passwords...\)

### Some obfuscation/Deobfuscation information

* [ ] [Read here](android-app-pentesting/#obfuscating-deobfuscating-code)



If you want to **know** about my **latest modifications**/**additions** or you have **any suggestion for HackTricks or PEASS**, ****join the [💬](https://emojipedia.org/speech-balloon/) ****[**PEASS & HackTricks telegram group here**](https://t.me/peass), or **follow me on Twitter** [🐦](https://emojipedia.org/bird/)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to ****[**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) ****that will be reflected in this book.  
Don't forget to **give ⭐ on the github** to motivate me to continue developing this book.

![](../.gitbook/assets/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67%20%286%29%20%284%29.png)

​[**Buy me a coffee here**](https://www.buymeacoffee.com/carlospolop)\*\*\*\*

