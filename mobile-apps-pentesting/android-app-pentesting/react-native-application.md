# React Native Application

**Information copied from** [**https://medium.com/bugbountywriteup/lets-know-how-i-have-explored-the-buried-secrets-in-react-native-application-6236728198f7**](https://medium.com/bugbountywriteup/lets-know-how-i-have-explored-the-buried-secrets-in-react-native-application-6236728198f7)\*\*\*\*

React Native is a **mobile application framework** that is most commonly used to develop applications for **Android** and **iOS** by enabling the use of React and native platform capabilities. These days, it’s become increasingly popular to use React across platforms.  
But most of the time, the core logic of the application lies in the React Native **JavaScript that can be obtained** without needing to use dex2jar.

#### **Step-1**: Let’s confirm whether the application was built on React Native framework.

To check this, rename the APK with zip extension and then extract the APK to a new folder using the following command

```text
cp com.example.apk example-apk.zip
unzip -qq example-apk.zip -d ReactNative
```

Browse to the newly created `ReactNative` folder, and find the `assets` folder. Inside this folder, it should contain `index.android.bundle`. This file will contain all of the React JavaScript in a **minified format.**React Native Reverse Engineering

![Image for post](https://miro.medium.com/max/1559/1*enjF2H7PclRAIcNCxDIOJw.png)

#### **Step-2**: Creating a file named `index.html` in the same directory with the following code in it.

```text
<script src="index.android.bundle"></script>
```

React Native Reverse Engineering

![Image for post](https://miro.medium.com/max/1526/1*Qrg2jrXF8UxwbbRJJVWmRw.png)

Open the **index.html** file in **Google Chrome**. Open up the Developer Toolbar \(**Command+Option+J for OS X or Control+Shift+J for Windows**\), and click on “Sources”. You should see a JavaScript file, split up into folders and files that make up the main bundle.

> If you are able to find a file called `index.android.bundle.map`, you will be able to analyze the source code in an unminified format. `map` files contain the source mapping that allows you to map minified identifiers.

#### **Step-3**: search for sensitive credentials and endpoints

In this phase, you have to identify the **sensitive keywords** to analyze the **Javascript** code. A pattern that is popular with React Native applications, is the use of a third party services like such as Firebase, AWS s3 service endpoints, private keys etc.,

During my initial **recon process**, I have observed the application using the Dialogflow service. So based on this, I have searched a pattern related to its configuration. Fortunately, I was able to find **sensitive hard-coded credentials** in the Javascript code.

![Image for post](https://miro.medium.com/max/2086/1*RAToFnqpp9ndM0lBeMlz6g.png)

