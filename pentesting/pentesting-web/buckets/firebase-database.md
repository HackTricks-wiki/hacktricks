# Firebase Database

## What is Firebase

Firebase is a Backend-as-a-Services mainly for mobile application. It is focused on removing the charge of programming the back-end providing a nice SDK as well as many other interesting things that facilitates the interaction between the application and the back-end.

### Pentest Methodology

Therefore, some **Firebase endpoints** could be found in **mobile applications**. It is possible that the Firebase endpoint used is **configured badly grating everyone privileges to read \(and write\)** on it.

This is the common methodology to search and exploit poorly configured Firebase databases:

1. **Get the APK** of app you can use any of the tool to get the APK from the device for this POC. You can use “APK Extractor” [https://play.google.com/store/apps/details?id=com.ext.ui&hl=e](https://hackerone.com/redirect?signature=3774f35d1b5ea8a4fd209d80084daa9f5887b105&url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dcom.ext.ui%26hl%3Den)
2. **Decompile** the APK using **apktool**, follow the below command to extract the source code from the APK.
3. Go to the _**res/values/strings.xml**_ and look for this and **search** for “**firebase**” keyword
4. You may find something like this URL “_**https://xyz.firebaseio.com/**_”
5. Next, go to the browser and **navigate to the found URL**: _https://xyz.firebaseio.com/.json_
6. 2 type of responses can appear:
   1. “**Permission Denied**”: This means that you cannot access it, so it's well configured
   2. “**null**” response or a bunch of **JSON data**: This means that the database is public and you at least have read access.
      1. In this case, you could **check for writing privileges**, an exploit to test writing privileges can be found here: [https://github.com/MuhammadKhizerJaved/Insecure-Firebase-Exploit](https://github.com/MuhammadKhizerJaved/Insecure-Firebase-Exploit)

**Interesting note**: When analysing a mobile application with **MobSF**, if it finds a firebase database it will check if this is **publicly available** and will notify it.

## References

* [https://blog.securitybreached.org/2020/02/04/exploiting-insecure-firebase-database-bugbounty/](https://blog.securitybreached.org/2020/02/04/exploiting-insecure-firebase-database-bugbounty/)
*  [https://medium.com/@danangtriatmaja/firebase-database-takover-b7929bbb62e1](https://medium.com/@danangtriatmaja/firebase-database-takover-b7929bbb62e1)

