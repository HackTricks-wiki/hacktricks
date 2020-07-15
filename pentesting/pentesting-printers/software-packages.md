---
description: 'Info from http://hacking-printers.net/wiki/index.php/Software_packages'
---

# Software packages

In the recent years, printer vendors have started to introduce the **possibility to install custom software on their devices**. The format of such ‘printer apps’ is proprietary and SDKs are not available to the public. The feature of writing customized software which runs on printers was intended and is reserved for resellers and contractors, not for end-users. Hereby a printer fleet can be adapted to the special needs and business processes of a company; document solution providers can easily integrate printers into their management software. One popular example is NSi AutoStore [\[1\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-1) which can be installed on many MFPs and automatically uploads scanned or copied documents to predefined locations. Obviously, the feature to run custom code on a printer device is a potential security threat. Furthermore code signing of software packages is potentially harder than it is for [firmware](http://hacking-printers.net/wiki/index.php/Firmware_updates) as software is not only written by the printer manufacturer but by a broader range of developers who need to be in possession of the secret key to sign their software. Therefore it is logical to include the secret key in SDKs which are protected by being exclusively available from developer platforms. This article is an effort to systematically gather information on vendor-specific software platforms/SDKs.

## Vendors

In the following a rough outline on the software platforms provided by major printer vendors to extend functionality of their devices is given.

### HP \(Chai/OXP\)

HP introduced their ‘Chai Appliance Platform’ platform in 1999 to run Java applications on LaserJet printers. While an SDK had been open to the public at first [\[2\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-2), access was later restricted to members of HP's developer network. Chai servlets which come as `.jar` files which originally needed to be certified and signed by HP before they would be accepted by a printer device. [\[3\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-phenoelit2002embedded-3) discovered a flaw in the deployment process: by installing EZloader – an alternative loader software provided by HP which had already been signed – they were able to upload and run their own, unsigned Java packages. As it seems, code signing was completely dropped by HP for later Chai versions: [\[4\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-mueller2016printers-4) were able to write and execute a proof-of-concept printer malware which listens on port 9100 and uploads incoming documents to an FTP server before printing them. Their code is based on [\[5\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-5) who extended the device to support load-balancing and included the required SDK files and proprietary Java libraries in their demonstration. With the libraries, arbitrary Java code can be complied and executed on older HP LaserJets by uploading the `.jar` files to a ‘hidden’ URL: [`http://printer/hp/device/this.loader`](http://printer/hp/device/this.loader). This attack can be carried out if no password has yet been set for the embedded web server. Otherwise, the password must first be retrieved from `/dev/rdsk_jdi_cfg0` with PostScript \(see [file system access](http://hacking-printers.net/wiki/index.php/File_system_access)\) or bypassed by resetting the device to [factory defaults](http://hacking-printers.net/wiki/index.php/Factory_defaults). A web attacker can upload the `.jar` file using [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) if the victim is currently logged into the printer's embedded web server. For newer devices, HP uses the web services based ‘Open Extensibility Platform’ \([OXP](https://developers.hp.com/oxp/)\) instead of Chai for which no SDK is publicly available.

### Canon \(MEAP\)

The ‘Multifunctional Embedded Application Platform’ \([MEAP](http://www.developersupport.canon.com/faq/335#t335n18)\) is a Java-based software platform introduced by Canon in 2003 for their imageRunner series and extended to web services in 2010. Third party developers can obtain the MEAP [SDK](http://developersupport.canon.com/content/meap-sdk-0) for a fee of $5,000 which is certainly out of scope for research purposes.

### Xerox/Dell \(EIP\)

The ‘Extensible Interface Platform’ \([EIP](http://www.office.xerox.com/eip/enus.html)\) [\[6\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-6) was announced in 2006 by Xerox for various MFPs. The architecture – which is also supported by a few rebadged Dell devices – is based on web services technology. The [SDK](http://www.office.xerox.com/eip/enus.html) is freely available for registered developers.

### Brother \(BSI\)

The ‘Brother Solutions Interface’ \([BSI](https://www.brother-usa.com/lp/civ/bsi.aspx)\) is an XML-based web architecture launched in 2012 for scanners, copiers and printers. Access to the [SDK](https://www.brother-usa.com/lp/civ/home.aspx) is available to licensed developers.

### Lexmark \(eSF\)

The ‘Embedded Solution Framework’ \([eSF](http://www.lexmark-emea.com/usa/BSD_solution_catalouge.pdf)\) was launched in 2006 for Lexmark MFPs. The SDK to develop Java applications is reserved for ‘specially qualified partners’. According to [\[7\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-7) ‘these applications must be digitally signed by Lexmark before being adopted’ using 2048-bit RSA signatures.

### Samsung \(XOA\)

The ‘eXtensible Open Architecture’ \([XOA](http://samsungprintingsolutions.com/2015/02/can-samsungs-extensible-open-architecture-xoa/)\) was introduced by Samsung in 2008 and comes in two flavours: the XOA-E Java virtual machine and the web services based XOA-Web. The [SDK](http://xoapartnerportal.com/) is only available to Samsung resellers.

### Ricoh \(ESA\)

The ‘Embedded Software Architecture’ \([ESA](https://www.ricoh.com/esa/)\) [\[8\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-8) was launched by Ricoh in 2004. The Java based [SDK/J](http://www.ricoh-developer.com/content/device-sdk-type-j-sdkj-overview) is available to developers after a registration.

### Kyocera/Utax \(HyPAS\)

The ‘Hybrid Platform for Advanced Solutions’ \([HyPAS](http://usa.kyoceradocumentsolutions.com/americas/jsp/Kyocera/hypas_overview.jsp)\) [\[9\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-9) has been released by Kyocera in 2008. Applications are based either on Java or on web services. The [SDK](https://www.kyoceradocumentsolutions.eu/index/document_solutions/HyPAS/hypas_developer_partner.html) is only available for members of the ‘HyPAS Development Partner Programme’ and applications have to be approved by Kyocera.

### Konica Minolta \(bEST\)

The ‘bizhub Extended Solution Technology’ \([bEST](https://best.kmbs.us/)\) [\[10\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-10) which is based on web services was introduced by Konica Minolta in 2009. Access to the [SDK](https://best.kmbs.us/pages/levels.php) requires ‘platinum membership level’ in the developer program for a fee of $4,000 which is out of scope for independent researchers.

### Toshiba \(e-BRIDGE\)

The ‘e-BRIDGE Open Platform’ \([e-BRIDGE](http://www.estudio.com.sg/solutions_ebridge.aspx)\) was released by Toshiba in 2008 to customize their high-end MFPs based on web services technology. An SDK is not available to the general public.

### Sharp \(OSA\)

The ‘Open Systems Architecture’ \([OSA](http://siica.sharpusa.com/Document-Systems/Sharp-OSA)\) [\[11\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-11) was announced by Sharp in 2004. The [SDK](http://sharp-partners.com/us/PartnerPrograms/DeveloperProgram/tabid/722/Default.aspx) used to develop web services is fee-based and applications need to be validated by Sharp before they can be installed on an MFP.

### Oki \(sXP\)

The ‘smart eXtendable Platform’ \([sXP](http://www.oki.com/en/press/2014/09/z14053e.html)\) [\[12\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-12) which is based on web services was launched by Oki Data in 2013 for their MFP devices. Oki does not publish any information regarding an official developer program or publicly available SDK.

## Results

On older HP laser printers, arbitrary Java bytecode can be executed as demonstrated by [\[3\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-phenoelit2002embedded-3) and [\[4\]](http://hacking-printers.net/wiki/index.php/Software_packages#cite_note-mueller2016printers-4). Security is based on the password of the embedded web server which can be easily retrieved with PostScript or bypassed by restoring factory defaults. It is hard to make a reasoned statement on the security of other software platforms because of lacking access to the SDK and/or proper technical documentation. A comparison of platforms, applied technologies and – where known – software package deployment procedures is given below:

| Vendor | Platform | Embedded Java | Web services | Deployment |
| :--- | :--- | :--- | :--- | :--- |
| HP | Chai/OXP | ✔ | ✔ | web server |
| Xerox/Dell | EIP |  | ✔ | unknown |
| Canon | MEAP | ✔ | ✔ | unknown |
| Brother | BSI |  | ✔ | unknown |
| Lexmark | eSF | ✔ |  | unknown |
| Samsung | XOA | ✔ | ✔ | web server |
| Ricoh | ESA | ✔ |  | unknown |
| Kyocera/Utax | HyPAS | ✔ | ✔ | USB drive |
| Konica Minolta | bEST |  | ✔ | unknown |
| Toshiba | e-Bridge |  | ✔ | unknown |
| Sharp | OSA |  | ✔ | unknown |
| Oki | sXP |  | ✔ | unknown |

### **How to test for this attack?**

Obtain an SDK and write your own proof-of-concept application or find a ‘printer app’ which already does what you want \(for example, automatically upload scanned documents to FTP\). Also check which protection mechanisms exist to install custom software on the device.

### **Who can perform this attack?**

Depended on how software packages are deployed.

