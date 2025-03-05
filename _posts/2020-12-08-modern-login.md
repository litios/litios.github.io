---
layout: post
title: Modern login
date: 2020-12-08
classes: wide
tags:
  - Userspace
  - Exploitation
--- 
<pre style="font-size: 0.5rem; text-align: center">
                          ,                          *                          
                           **                       **                          
                            ,*     ,*********     ,*                            
                             **********************.                            
                          *****************************                         
                       ,*********************************                       
                     .******    ****************.   *******                     
                    ****************************************                    
                   ,*****************************************                   
                   *******************************************                  
                                                                                
        ,*****,   ,*******************************************    ******.       
       *********  ,*******************************************  ,*********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************  **********      
       *********  ,*******************************************   ********,      
         .***.    ,*******************************************     ,**,         
                  ,*******************************************                  
                  ,*******************************************                  
                  .*******************************************                  
                           **********       *********                           
                           **********       *********                           
                           **********       *********                           
                           **********       *********                           
                           **********       *********                           
                            ********        ,*******,                           
</pre>

---

This was an Android reversing challenge from the DefCamp CTF 2020 rated with 50 points. The description said:

>This should rock your life to the roots of your passwords.
>
>Flag format: CTF{sha256}

---

They give us an apk so my first approach was to execute it to see how it worked. I connected my phone to my PC, enabled USB debugging under the developer options in my phone and installed it.

![](https://lh6.googleusercontent.com/ZiAtp727d2_IfnEEP60Tp3sBDJtzOKJ1mmdbgM-urbVxu7fkIVjobuxMoPNim033-16vj78Y7NOewf1zr09_XGZ7s3zmV0GES7MX8QfBgPyfevTKgeusf364baZfqxBQCFpKazbN)

This is how the app looks:

![](https://lh6.googleusercontent.com/UuHHsUHBqLhmGTK_EX7ARl4jUroNo54uHPwoTblnxvRyzvXKfVxQeP6jP8F8r9uwXEOrjE3f7He9qW_DY_i5LUocUyx5zXN1Z2mbMjTNSvcFz98FYw7wSLRLjkR15LWuVBvwhZ-k)

It shows an input and when we hit Submit, it does nothing. Okay, that doesn’t help us a lot. So let’s get the contents of the apk.

For that, we are going to use [apktool](https://ibotpeaches.github.io/Apktool/) which is used for reversing Android applications. (I’m not covering the installation process because it’s already on the page.)

We run it with `d` to decompress the app into a folder with the same name:

![](https://lh5.googleusercontent.com/jwZbHEiMDthomMLJ8ukAnCnGvEXfWDusHVRz1Pkq-OLwp2uL-flgeR75HKoAji2YnrY7xsAhG0nJcs-kAmpUdQzW8cVvJMm19DDVTkuiqAOuhCmDztg-gf-kDODo5kZXxZnhSMvC)

This is what the program generates:

![](https://lh5.googleusercontent.com/aEYRNDQ9tcaVstmPhw0DRUB-pmL1ftkLu7bLBmOMXrh1ymKN-ggbcwDE1KViz3y8LDweui2_LePTkguQxouEaBGqx6StHoeDTmM6y77caCq7Fmn5NwxoqrEgZYv0r9L7GLgtzRBH)

The original Java/Kotlin files are converted to smali files which are a bit different. We found a lot of packages and classes inside the smali folder:

![](https://lh4.googleusercontent.com/S7J-W6yjxukDZxSG-uhyt8iBfiFpM3cF7wWkviwbfEs3bpiOK9F8odHC8DAPrHM2fZdOOrso66Z_BrrWlKWyXiqFaY1WqOVpbRQWbeh5hy9ZO0Yx5usMpY4qzBBbpT9VAo8G_89d)

When looking for the flag directly inside the classes we don’t get any match. So, let’s take another road. Let’s find out what’s being executed when we access the application. If there is an input field maybe we could get something there.

First, let’s find out what’s the apk package name. Go to the AndroidManifest.xml file and there we can see an xml tag with the package name:

![](https://lh4.googleusercontent.com/6vfR-6qihu0Gnf5elaoStm8NpQoydvWF3lVvqaCKXgfRouYXAsOaeyHtLD2QGaH5DFqa_ga-mxTQuNsb4MOk-msjH53NVTgTZ9BwzYCU8FL1gQpTwrOI-ChYAn5cc95jP01kCkQq)

Let’s go back to the phone and adb. Open the application and get a shell inside the phone using the `shell` command:

![](https://lh5.googleusercontent.com/TG-pzlBX2eaqTqU1uK8Tdup4OmoJW3w5rC-1wjDDYOh_t7BD5W2zxgZNFLn8a2Z792cEg_ynSkOCGwdNQRO2A8624mvUXBaT_bKJKVZoU4vP234YYRXVUN4ulM6fYkcI4xN976LP)

Now, let’s use the command `dumpsys window windows` to get information about the open apps and we can use `grep` to filter by using the package name:

![](https://lh5.googleusercontent.com/KAQcYQJ3zGbR2dW6VPw_CEmd_2goJoRPxA9hhjp6w3WpgPxrCHMTSoBETIEpAx6UvjQ4lxt0dr51ejeLcytPCKsgxzdL-IY60gc7S-Fpmz7R5Nnb4R0ICzPZVW5KlyiMiSEcrwNz)

So we found the Activity name, **org.kivy.android.PythonActivity**. Now we know we have to search inside that package. Back to the code!

---

We start to look inside the kivy folder, searching for something interesting inside the PythonActivity.smali. Inside the **onCreate** function we notice something at the end.

![](https://lh4.googleusercontent.com/0mR-QZZviP2tv2m8D0a5RfB6x9q8X8eFvsvFkDyppnQC1cNLv6jdC1G0-KQk0_-4wfBlb451guO2kJqDhkQU00ROyRJDuJkwnU_OrIt-P8-AUCm7D2biKcURA3V4owxnSSpjhUIU) Maybe the code is hidden somehow and get’s unpacked when the app is started?

Inside the file **PythonActivity$UnpackFilesTask** I found it’s actually delegating the task to **PythonActivityUtil**:

![](https://lh6.googleusercontent.com/9GcogHw42ZcBphkrbrFH_J8MjV3DXq2SP7XeuhjrYDLbyctY4Vu8pjW3flCktg2mT-25bvudfImnbu2CYhYGEcKhhVA5qrYI6i2nIJYQl9Y1RkiNRRP7WKRcwaa9sYHPTkmYH2xp)

Let’s take a look at that function:

![](https://lh3.googleusercontent.com/7HaQbK4MQUWiUsjnalPeBa14VoxZGF1jJ5lVJ_DDqlVohXV6NnL_doN9DFyJX2zhX3LhTvb03NmYgfqrIKnhPxmnLLYgiH4oYkk92bYv2DHwOefOb1N4hShWTjU4sNzSeCmzxUVa)

Looks like it’s actually unpacking something here. It does a lot of things here but looking at the strings used we find something:

![](https://lh4.googleusercontent.com/TmT0hFl4sVHSk3wK92ofbJ9YSQvFF27P0H983vQIIWISzB4EsgVlZw5BpNAnMM-V0JDwdrN73TgEyMlbNy1l2Fw6-OfIiSci1m40CNXVb4jqk0m6MgPgfuqHBCacYhy-IXk6YsvN)

![](https://lh4.googleusercontent.com/3FD6c9skD-Zkkcp7MmYJ9QMuIZM-1KDMf7CXtPcNDf91rggjibkZ_WVH3_Ki_SDTYIZbexr-LLeKBO_Gkyr8Foi7OwTGVMlsPH3T9zisiBZ5C3ZJnrZXuEew3DWaWhbGD_ZxNv4U)

So it’s unpacking something from an **.mp3**? Let’s check that. Apktool also unpacks the assets inside an ‘assets’ folder. There is a **private.mp3** file. That matches what we saw inside that function, right?

Let’s check with `file`:

![](https://lh4.googleusercontent.com/YdX0dG6FwtF6zPkb6acyfLXgcD3bbGvHw1b5Y-EibGj2Di3IjsyCeJIDtj0Z20Dc0NkxQ5grz8XHY8HwDQ6rVH2wSw1qbd6gWTdgxXwAacB4x2smneDhSAUU94lEHMv-FKzJE8zN)

That’s definitely not an mp3 file. Let’s decompress it with `tar`:

![](https://lh4.googleusercontent.com/-IRIooCruOYjCuIBrPYCjbiTgmBiSDC-vUUk_Pa6aiR3DgUKm7vOp3kWSUJTXrJnMlE7QezrZQnT0py93tYzyoICrSBgnyNwSyrFueL7-KEZXgcPJlqZAOuEdU9Mu8Mfk_EIOlX7)

And a bunch of files and folders are created:

![](https://lh6.googleusercontent.com/aONVhL2p3lt_XAe36B-Gi6Frr2ZANR-8mTDlULs0Ye20iRAwYyIrsNW74XA9xbz4LFHP0GJh1XmNR-JDM1E0cjmeigC6XeWdag8eOtaC0Vw0HT2VEIsJ6ejnFpd75VQpnX-T4NiR)

We can start by checking main.py (I mean, it’s the main. Makes sense):

![](https://lh5.googleusercontent.com/PnCvC2kELYKOOAU6mst3oTtoqvCAM7KfaL-DWYMRRvVrPHCnqBOfhNrl0BxSXRsFJ7KQdl6SmOyjSrtR9Cyz1DwzQJeZHzbe-KRdieWYV9TSyN67UGbMRHFC3I5ndtZj0f00KDMS)

We can see an auth function. That looks promising. It looks like it's returning the contents of **U** if it succeeds. Let’s clean that up.

Remove all the parts that are related to Android so we get an executable python file. That means deleting the import from kivy, the self.root accesses, the z.text and then moving the auth function outside the Main class and delete Main.

(As you can see the U it’s only affected by g, which is just a bunch of bytes and the functions used also doesn’t use any of that so we can delete all of that without worrying.)

This is the final file:

![](https://lh4.googleusercontent.com/oYojKi4hm94QgT6OWuauLlLFIIOyROlOCq0DkE1atKsPQGV4eV4TP2GS1glJ1i0jV-dkofXGPEpE8frH_RaQ3NHRz0-CcHADGy_75HcqULFpE1ZvkX0zIlyrCtIt9wIzcha-1AB-)

So let’s add a print to that auth function to check the contents of **U**. Execute it:

![](https://lh4.googleusercontent.com/fBjfV0dQMq4RTrLo41tb9P-KYUlOvgX6skcUWc5RdDy8WgUc39_E-pIUUJDfYFLIWZdXv58UEPEgmMO01l3jorFR9EovbNWa-SPRRpZxrFFfJB_NLsKOhnLUZ6r-36cgciP-graK)

And there is the flag!
