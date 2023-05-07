Burpsuite is a **Man in the middle (MITM) web application proxy**. At a base level, Burp can be used to intercept and modify traffic sent by a web browser. Burpsuite can also be used for:
- Bypass client side input validation.
- Capture and log all HTTP requests made by the browser.
- Passively build a sitemap as you walk the application.
- Modify and replay previous requests.
- Decode/encode text
- Add/remove/modify Headers and parameters.
- Change request method
- Automate a sequence of requests (think authentication)
- Manage cookies and user sessions. 
- Perform a plethora of web based attacks.
- Prevent out of scope requests (this can and will save your ass at some point)
- **\[PRO]** Automatic Vulnerability scanner and validation
- **\[PRO]** Automatically spider website and build site map (similar to gobuster or dirb)
- **\[PRO]** Session persistence and saved projects. 

> The professional version has some automagic features, but this is still a *very* manual tool. You will still need to know how to find and exploit common vulnerabilities to take full advantage of this tool. 

# Download, install, and setup
Burpsuite Community (the version that doesn't cost half a grand) can be downloaded for free at [https://portswigger.net/burp/releases/community/latest](https://portswigger.net/burp/releases/community/latest)

Download the latest version for your platform, Java is required to run this software.

Once you are done installing, run the application and select
> Temporary Project > Next > Use Burp Defaults > Start Burp

Unless you have the professional version, you can just press next until your up and running.

# Learning Resources
There are a metric fuck-ton of resources and training videos you can take advantage of to learn how to use this tool. 

### Try Hack Me
Interactive capture the flag style hand on learning.
- [Burp Suite Basics](https://tryhackme.com/room/burpsuitebasics)
- [Burp Suite Repeater](https://tryhackme.com/room/burpsuiterepeater)
- [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop)

### Portswigger
More traditional lectures and included CTF style lab activities. 
- [Free Burpsuite Training](https://portswigger.net/training)

# Proxy
The Burpsuite `proxy` can be used to intercept and modify incoming requests. The burp proxy can be configured to proxy traffic from any browser that supports proxies, but for simplicity we will use the included chromium based browser.

Navigate to the `Proxy` tab, and click Open Browser. All traffic into and out of this browser will be captured by Burp.

## Modifying requests
To modify requests, Press the gray `intercept is off` button. The text should change to say `intercept is on` with a blue background. Next, navigate to [example.com](https://example.com). You should then see the following request queued in burpsuite:

![Burp Proxy view for example.com](/Images/BurpProxyExample.png)

In the main view, we can modify the request my editing the text. We are also greeted with an `inspector` navigation bar on the right. We can use this to modify the request in a tabled format. Selecting an existing parameter or header will give us the option change how the information is displayed. For example, we are given the option to base64 or url decode parameters. 

From here we have a few options for interacting with the request: **Forward, Drop, and Action.**
- **Forward:** Sends the request to the server
- **Drop:** Drops the request
- **Action:** opens the `right click` context menu
