# What are Intents

This post was copied from [https://manifestsecurity.com/android-application-security-part-14/](https://manifestsecurity.com/android-application-security-part-14/)

Your mobile application can accept data from all kinds of sources. In most cases this will be an Inter Process Communication \(IPC\) mechanism. To look in to possible attacks on the same, we first need to have know about Intent. **Sit back tight, this post is going to be long**.

Intent is basically a message that is passed between components \(such as Activities, Services, Broadcast Receivers, and Content Providers\). So, it is almost equivalent to parameters passed to API calls. The fundamental differences between API calls and intents’ way of invoking components are:

* API calls are synchronous while intent-based invocations are asynchronous.
* API calls are compile time binding while intent-based calls are run-time binding.

Of course, Intents can be made to work exactly like API calls by using what are called explicit intents, which will be explained later. But more often than not, implicit intents are the way to go and that is what is explained here.

One component that wants to invoke another has to only express its’ intent to do a job. And any other component that exists and has claimed that it can do such a job through intent-filters, is invoked by the android platform to accomplish the job. This means, both the components are not aware of each other’s existence and can still work together to give the desired result for the end-user.

This invisible connection between components is achieved through the combination of intents, intent-filters and the android platform.

An intent is an abstract description of an operation to be performed. It can be used with startActivity to launch an Activity, broadcastIntent to send it to any interested BroadcastReceiver components, and startService\(Intent\) or bindService\(Intent, ServiceConnection, int\) to communicate with a background Service.

An Intent provides a facility for performing late runtime binding between the code in different applications. Its most significant use is in the launching of activities, where it can be thought of as the glue between activities. It is basically a passive data structure holding an abstract description of an action to be performed. The primary pieces of information in an intent are:

* **action** The general action to be performed, such as ACTION_VIEW, ACTION_EDIT, ACTION\_MAIN, etc.
* **data** The data to operate on, such as a person record in the contacts database, expressed as a Uri.

To be simple Intent can be used for

* To start an Activity, typically opening a user interface for an app
* As broadcasts to inform the system and apps of changes
* To start, stop, and communicate with a background service
* To access data via ContentProviders
* As callbacks to handle events

Improper implementation could result in data leakage, restricted functions being called and program flow being manipulated.

**What is Intent Filters ?**

If an Intents is send to the Android system, it will determine suitable applications for this Intents. If several components have been registered for this type of Intents, Android offers the user the choice to open one of them.

This determination is based on IntentFilters. An IntentFilters specifies the types of Intent that an activity, service, orBroadcast Receiver can respond to. An Intent Filter declares the capabilities of a component. It specifies what anactivity or service can do and what types of broadcasts a Receiver can handle. It allows the corresponding component to receive Intents of the declared type. IntentFilters are typically defined via the AndroidManifest.xml file. For BroadcastReceiver it is also possible to define them in coding. An IntentFilters is defined by its category, action and data filters. It can also contain additional metadata.

If any of the component is public then it can accessed from another application installed on the same device. In Android a activity/services/content provider/broadcast receiver is public when exported is set to true but a component is also public if the **manifest specifies an Intent filter** for it. However,  
developers can explicitly make components private \(regardless of any intent filters\)  
by setting the “exported” attribute to false for each component in the manifest file.  
Developers can also set the “permission” attribute to require a certain permission to access  
each component, thereby restricting access to the component.

In the upcoming posts i will try to attack activity/services/broadcast reciever/content provider from drozer console.

