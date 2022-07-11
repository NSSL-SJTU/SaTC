## Action keyword verification

[Chinese](README_cn.md)

### About NetGear

During our manual verification process, we found that the action keyword of NetGear upnpd is located in an array. When a new UPnP request comes in, UPnP will traverse the action keyword array, find the string that matches the request, and give it to the processing function to deal with. If the action keyword extracted from the front end also exists in this array, we consider this action keyword to be referenced. So the comparison result is 100%

#### Example: NetGear R6400

There is a string array in the `SUB_262D4` function, if have UPnP request comes in, Upnp will traverse the action keyword array, find the string that matches the request, and give it to the processing function to deal with.

![code1](img/1.png)

What is recorded in the `s_Event` array:

![code2](img/2.png)

### About Tenda

It doesn't have action keywords in Tenda's app_data_center. So the verification result is 0%