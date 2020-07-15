# Spoofing SSDP and UPnP Devices with EvilSSDP

**This post was copied from** [**https://www.hackingarticles.in/evil-ssdp-spoofing-the-ssdp-and-upnp-devices/**](https://www.hackingarticles.in/evil-ssdp-spoofing-the-ssdp-and-upnp-devices/)\*\*\*\*

## **Introduction**

### **What is SSDP?**

SSDP or Simple Service Discovery Protocol is a network protocol designed for advertisement and discovery of network services. It can work without any DHCP or DNS Configuration. It was designed to be used in residential or small office environments. It uses UDP as the underlying transport protocol on port 1900. It uses the HTTP method NOTIFY to announce the establishment or withdrawal of services to a multicast group. It is the basis of the discovery protocol UPnP.

### **What are UPnP devices?**

UPnP or Universal Plug and Play is a set of networking protocols that allows networked devices, such as personal computers, printers, Internet gateways, Wi-Fi access points, and mobile devices to discover each other’s availability on the network and establish network services for communications, data sharing, and entertainment. The UPnP architecture supports zero-configuration networking. A UPnP compatible device from any vendor can dynamically join a network, obtain an IP address, announce its name, advertise or convey its capabilities upon request, and learn about the presence and capabilities of other devices.

Now that we understood the basic functions of SSDP or UPnP, let’s use it to manipulate the target user in order to steal their credentials.

### **Installation**

The Evil SSDP too was developed by [initstring](https://twitter.com/init_string). This tool is hosted on the GitHub. We will be using the git clone command to clone all the contents of the git onto our attacker machine. The git clone command will create a directory with the same name as on GitHub. Since the tool is developed in Python version 3, we will have to use the python3 followed by the name of the .py file in order to run the program. Here we can see a basic help screen of the tool.

```bash
git clone https://github.com/initstring/evil-ssdp.git
cd evil-ssdp/ls
python3 evil-ssdp.py --help
```

![](https://i0.wp.com/1.bp.blogspot.com/-O6lddDvxqts/Xkq5PHqeE_I/AAAAAAAAisQ/FKOCxVwT9cMy54lLy0SsYcKoM5Q95K5mQCLcBGAsYHQ/s1600/1.png?w=687&ssl=1)

In the cloned directory, we will find a directory named templates. It contains all the pre complied templates that can be used to phish the target user.

## **Spoofing Scanner SSDP**

Now, that we ran the tool without any issues, let’s use it to gain some sweet credentials. In this first Practical, we will be spoofing a Scanner as a reliable UPnP device. To begin, we will have to configure the template.

### **Template Configuration**

To use the tool, we will have to provide the network interface. Here, on our attacker machine, we have the “eth0” as our interface, you can find your interface using the “ifconfig” command.

After providing the interface, we will use the “–template” parameter to pass a template that we found earlier in the templates directory. To spoof a scanner, we will be running the following command. As we can see that the tool has done its job and hosted multiple template files on our attacker machine at port 8888. We also have the SMB pointer hosted as well.

```bash
ls temlates/
python3 evil-ssdp.py eth0 --template scanner
```

![](https://i0.wp.com/1.bp.blogspot.com/-kg05jQ03Fnw/Xkq5Qing_qI/AAAAAAAAisk/GYK8MuCKqKUalqh3DHGWVRoyDlAQaxUrwCLcBGAsYHQ/s1600/2.png?w=687&ssl=1)

### **Manipulating User**

The next logical step is to manipulate the user to click on the application. Being on the same network as the target will show our fake scanner on its explorer. This is where the UPnP is in works. The Evil SSDP tool creates this genuine-looking scanner on the system on the target without any kind of forced interaction with the target.

![](https://i1.wp.com/1.bp.blogspot.com/-_05xXp10Buk/Xkq5Qz4yosI/AAAAAAAAiso/HdHr0qJ59rkR2ur_UYcrHMdf93uqMhXUwCLcBGAsYHQ/s1600/3.png?w=687&ssl=1)

Upon clicking the icon inside the Explorer, we will be redirected to the default Web Browser, opening our hosted link. The templates that we used are in play here. The user is now aware he/she is indeed connected to a genuine scanner or a fake UPnP device that we generated. Unaware target having no clue enters the valid credentials on this template as shown in the image given below.

![](https://i2.wp.com/1.bp.blogspot.com/-lp2DBNRl12A/Xkq5RBtGvgI/AAAAAAAAiss/G9jSOVdBO4wnRKixpXlbj6BJeCTBWz7cACLcBGAsYHQ/s1600/4.png?w=687&ssl=1)

### **Grabbing the Credentials**

As soon as the target user enters the credentials, we check our terminal on the attacker machine to find that we have the credentials entered by the user. As there is no conversation required for each target device, our fake scanner is visible to each and every user in the network. This means the scope of this kind of attack is limitless.

![](https://i1.wp.com/1.bp.blogspot.com/-RAI02igc4F4/Xkq5RSJ3j2I/AAAAAAAAisw/p47jd_jyyAE3RQIpms6nd-TzsPygD4CXQCLcBGAsYHQ/s1600/5.png?w=687&ssl=1)

## **Spoofing Office365 SSDP**

In the previous practical, we spoofed the scanner to the target user. Now, ongoing through the template directory, we found the Office365 template. Let’s use it.

### **Template Configuration**

As we did previously, let’s begin with the configuration of the template as well as the tool. We are going to use the python3 to run the tool followed by the name of the python file. Then providing the network interface which indeed will be followed by the template parameter with the office365.

```bash
python3 evil-ssdp.py eth0 --template office365
```

![](https://i1.wp.com/1.bp.blogspot.com/-8GWxmKPDkIo/Xkq5RmgF8_I/AAAAAAAAis0/bxVTcd4aBCUZBEDuUIg3-G39aMu7l5YCgCLcBGAsYHQ/s1600/6.png?w=687&ssl=1)

As we can see that the tool has done its job and hosted multiple template files on our attacker machine at port 8888.

### **Manipulating User**

As soon as we run the tool, we have a UPnP device named Office365 Backups. This was done by the tool without having to send any file, payload or any other type of interaction to the target user. All that’s left is the user to click on the icon.

![](https://i0.wp.com/1.bp.blogspot.com/-txqBOw02D6w/Xkq5RgolUcI/AAAAAAAAis4/wkQTzYBmtdU_Nbq9X1qI47FlJtdqHvIjQCLcBGAsYHQ/s1600/7.png?w=687&ssl=1)

Upon being clicked by the user, the target user is redirected to our fake template page through their default browser. This is a very genuine looking Microsoft webpage. The clueless user enters their valid credentials onto this page.

![](https://i1.wp.com/1.bp.blogspot.com/-69Tf3PRpvhM/Xkq5RziDXzI/AAAAAAAAis8/vjejKgh0XigRHFC2Ib8QCpPlzx_RAu4eACLcBGAsYHQ/s1600/8.png?w=687&ssl=1)

### **Grabbing the Credentials**

As soon as the user enters the credentials and they get passed as the post request to the server, which is our target machine, we see that on our terminal, we have the credentials.

![](https://i0.wp.com/1.bp.blogspot.com/-3KXN6DKT_E0/Xkq5SEwhKHI/AAAAAAAAitA/a2gTi5UwNE0JsMH-XQEW33MchkxgjPGSwCLcBGAsYHQ/s1600/9.png?w=687&ssl=1)

## **Diverting User to a Password Vault SSDP**

Until now, we successfully spoofed the target user to gain some scanner credentials and some Office365 backup credentials. But now we go for the most important thing that is used as a UPnP, The Password Vault.

### **Template Configuration**

As we did in our previous practices, we will have to set up the template for the password-vault. In no time, the tool hosts the password-vault template onto the port 8888.

```bash
python3 evil-ssdp.py eth0 --template password-vault
```

![](https://i2.wp.com/1.bp.blogspot.com/-YPQirClmWN4/Xkq5O5WFgoI/AAAAAAAAisI/4_i4ogVRWE0C_ez3p6EkL8YdJ0ot48DmwCLcBGAsYHQ/s1600/10.png?w=687&ssl=1)

### **Manipulating User**

Moving onto the target machine, we see that the Password Vault UPnP is visible in the Explorer. Now lies that the user clicks on the device and gets trapped into our attack. Seeing something like Password Vault, the user will be tempted to click on the icon.

![](https://i2.wp.com/1.bp.blogspot.com/-3oMPYaCZ46k/Xkq5PB4zQ_I/AAAAAAAAisM/i5C8qZVB8RYWBwAkiKCZbdptIbsnk4CUwCLcBGAsYHQ/s1600/11.png?w=687&ssl=1)

As the clueless user thinks that he/she has achieved far most important stuff with the fake keys and passwords. This works as a distraction for the user, as this will lead the user to try this exhaustive list of credentials with no success.

![](https://i0.wp.com/1.bp.blogspot.com/-SrCMlWIUxCM/Xkq5Pg_IznI/AAAAAAAAisU/L_ZIvQKfltkyk9iUCrEGyXCojx5b86uFgCLcBGAsYHQ/s1600/12.png?w=687&ssl=1)

## **Spoofing Microsoft Azure SSDP**

While working with Spoofing, one of the most important tasks is to not let the target user know that he/she has been a victim of Spoofing.  This can be achieved by redirecting the user after we grab the credentials or cookies or anything that the attacker wanted to acquire. The evil\_ssdp tool has a parameter \(-u\) which redirects the targeted user to any URL of the attacker’s choice. Let’s take a look at the working of this parameter in action.

To start, we will use the python3 for loading the tool. Followed by we mention the Network Interface that should be used. Now for this practical, we will be using the Microsoft Azure Storage Template. After selecting the template, we put the \(-u\) parameter and then mention any URL where we want to redirect the user. Here we are using the Microsoft official Link. But this can be any malicious site.

```bash
python3 evil-ssdp.py eth0 --template microsoft-azure -u https://malicous-site.com
```

![](https://i2.wp.com/1.bp.blogspot.com/-ReHCqgFazX0/Xkq5QBiQ7jI/AAAAAAAAisY/_DFdnzBpSGY1iDP1YJxeVTHF3iS5PZnqwCLcBGAsYHQ/s1600/13.png?w=687&ssl=1)

### **Manipulating User**

Now that we have started the tool, it will create a UPnP device on the Target Machine as shown in the image given below. For the attack to be successful, the target needs to click on the device.

![](https://i1.wp.com/1.bp.blogspot.com/-rROTfEGP3z8/Xkq5QBn46dI/AAAAAAAAisc/7RDv7fI3BPYt1XmrKVRKOEHurkGY1xeogCLcBGAsYHQ/s1600/14.png?w=687&ssl=1)

After clicking the icon, we see that the user is redirected to the Microsoft Official Page. This can be whatever the attacker wants it to be.

![](https://i2.wp.com/1.bp.blogspot.com/-gU36s2kyIbg/Xkq5QVRh61I/AAAAAAAAisg/hN3uVMTPh-suDiH5ID3-mWcQiNvDVYeJACLcBGAsYHQ/s1600/15.png?w=687&ssl=1)

This concludes our practical of this awesome spoofing tool.

## **Mitigation**

* Disable UPnP devices.
* Educate Users to prevent phishing attacks
* Monitor the network for the password travel in cleartext.

