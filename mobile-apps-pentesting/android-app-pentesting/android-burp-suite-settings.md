# Burp Suite Configuration for Android

**This tutorial was taken from:** [**https://medium.com/@ehsahil/basic-android-security-testing-lab-part-1-a2b87e667533**](https://medium.com/@ehsahil/basic-android-security-testing-lab-part-1-a2b87e667533)\*\*\*\*

## Add a proxy in Burp Suite to listen.

Address: **192.168.56.1** & Port: **1337**

Choose _**All Interfaces**_ option.

![](https://miro.medium.com/max/700/1*0Bn7HvqI775Nr5fXGcqoJA.png)

## **Adding listener in Android device.**

Setting → Wifi →WiredSSID \(Long press\)

Choose Modify network → Check Advance options.

Select Proxy to the manual

![](https://miro.medium.com/max/700/1*gkDuYqWMldFuYguQuID7sw.png)

Testing connection over http and https using devices browser.

1. http:// \(working\) tested — [http://ehsahil.com](http://ehsahil.com/)

![](https://miro.medium.com/max/700/1*LJ2uhK2JqKYY_wYkH3jwbw.png)

2. https:// certificate error — https://google.com

![](https://miro.medium.com/max/700/1*M-AoG6Yqo21D9qgQHLCSzQ.png)

## **Installing burp certificate in android device.**

Download burp certificate. — Use your desktop machine to download the certificate.

[https://burp](http://burp/)

![](https://miro.medium.com/max/700/1*f4LjnkNs7oA1f4XokEeiTw.png)

Click on **CA certificate download the certificate.**

The downloaded certificate is in cacert.der extension and Android 5.\* does not recognise it as certificate file.

You can download the cacert file using your desktop machine and rename it from cacert.der to cacert.crt and drop it on Android device and certificate will be automatically added into **file:///sd\_card/downloads.**

**Installing the downloaded certificate.**

Settings →Security →Install certificate from SD cards

Now, goto: sdcard →Downloads → Select cacert.crt

Now, Name it as anything “portswigger”

![](https://miro.medium.com/max/700/1*lDtlQ1FfcHEytrSZNvs2Mw.png)

You also need to setup the PIN before adding certificate. Verifying the installed certificate using trusted certificates.

Trusted certificates →Users

![](https://miro.medium.com/max/700/1*dvEffIIS0-dPE6q3ycFx3Q.png)

After installing Certificate SSL endpoints also working fine tested using → [https://google.com](https://google.com/)

![](https://miro.medium.com/max/700/1*lt0ZvZH60HI0ud1eE9jAnA.png)

{% hint style="info" %}
After installing the certificate this way Firefox for Android won't use it \(based on my tests\), so use a different browser.
{% endhint %}

