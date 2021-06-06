# Apple GSA Protocol

This repository includes a simple script for authenticating with Apple's GrandSlam Authentication protocol. Although there is a little documentation on this process online, I could not find any resources on how to set up some of the parameters for GSA authentication, which is why I decided to make this repository.


## What is GrandSlam Authentication (GSA) ?

GSA is based on the [SRP-6a authentication protocol](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) which can verify a user has the correct password to an account without actually transmitting it. GSA is utilized in many of Apple's applications for authentication. Some apps that use GSA endpoints include iCloud and the App Store. 

The endpoint for GSA is https://gsa.apple.com/grandslam/GsService2

## Analyzing traffic

All of Apple's applications utilize SSL pinning which means you must take a couple of extra steps in order to read some of the traffic yourself.

**macOS**: 
The first step in obtaining the web traffic would be to intercept the SSL pinning functions with a tool such as Frida to effectively render pinning useless, but in order to do so you must disable System Integrity Protection (SIP), otherwise, Frida cannot hook to the process properly and will throw an error.

**iOS**: Using a jailbroken device, you may use Frida or [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) to bypass the SSL pinning. 

**Important Note**: Regardless of what application or process you want to analyze, if you're after GSA traffic, you need to hook into Auth Kit Daemon (AKD). This process is entirely responsible for all GSA protocols. The process will be titled `akd`. If you're going to use SSL Kill Switch 2 on iOS, then akd is launched before it can be hooked, which means that you'll need to execute a kill -9 command to kill akd and have it restart so that SSL Kill Switch 2 can properly hook it next time.


## Python Script

The python script in this repository can successfully execute one of the first steps towards proper authentication via the GSA protocol (getting the M1), but it may not provide much help in getting past any further for reasons explained below. Nevertheless, the first step can be considered complete and this provides a nice overview of how some parameters such as the a2k are generated.



## Limitations

I have not been successful in terms of getting an M2 token when trying to recreate the second GSA request. According to some online sources, the `X-Apple-I-MD` parameter is time-sensitive and lasts only about 30 seconds. The first step in getting a full implementation would be to figure out how this is generated. 

Because it is difficult to analyze Apple's binaries to get this information, some people have resorted to hooking into Apple's AFD binaries to call the function that generates the `X-Apple-I-MD` token and extracting it for utilization. In a future update, I will likely incorporate support for this.

## Contributions

Contributions in the form of issues or pull requests are always welcome. It may take a community-led effort to get the whole process completed.
