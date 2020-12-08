<pre style="font-size: 0.6rem; text-align: center">
                                                                                                
                           @((%/(%%.#..&@&(****@(****//*,,                                      
                           @((%/(%%.#//((((#(@.@((**%(%@**                                      
                           @((%##((((((((((((((@((%.(((%&(                                      
                     ****#%#((((((((((((((((((((((%%((((%&                                      
                     ....((((((((((((#.    ,,,#((((%(((%%*                                      
                     **(((((((((((((          .,%((((((%%%.......%.%                            
                     *(((((((((((((     #@@     ,((((((%%%%%((#,#%.%                            
                     @(((((((((((((&            /((((((((((%%%@,#%.%                            
                     @(@*,,,*@((((((@          @((((((((((((((%%%@.%                            
                    /,        ,&((((((((@@@@(((((((((((((((((((((%%%%....                       
                    @    @@    ,@(@*,/@%@((((((((((((((((((((((((((%%%...                       
                    *          ,((@% @@@(%((((((((((((((((((((((((((%%%@,                       
                    ..%.      #((((((((((((((((((((((((((((((((((((((%%%/                       
                        \$$&%((((((((((((((((((((((((((((((((((((((((%%%@                       
                           &%.@&*@(((((((((((((((((((((((((((((((((((%%%*                       
                           &%.@&*#/*((((((((((((((((((((((((((((((((%%%@(                       
                           #########((((((((((((((((((((((((((((((#%%%@,,                       
                           *********(((%@((((((((((((((((((((((((((%&....                       
                           .........#*.*,,@((((((((((((((((((%&(((%&(((((                       
                           .........#*.*,,%.&@(((((((((((%%%%@@((%@......                       
                           .........#*.*,,%.&#..@#/@@@@#%@                                      
                                                    @((%@                                       
</pre>

---

This was a reversing challenge from the DefCamp CTF 2020 rated with 293 points. The description said:

> I heard you can't redo what's deleted. Is that true?
>
> Flag: ctf{sha256(original_message)}

---

First, let’s run the binary they give us. ![](https://lh5.googleusercontent.com/hDswveTeczPHKtnda07jMK1mv6AvcAF9Uf7yM6NTbepVFhkPIlGe8roLGXouE9IZ5zGLmhijDvg0V6i5OmdT-G1msMzkQgAuXYlvN0VtUehI1cTF33SKGAkFaHLiRbyRcKM3PuAC)

Well, as the description said, this challenge is about getting the original message. So, let’s check how that message is encoded.

Let’s open the binary inside [Cutter](https://cutter.re]). Looking at the amount of functions and some names like go.runtime.gogo we know this is a Go binary (the name said it too).

Let’s open the main function, which is sym.go.main.main. We are going to analyze it step by step.

![](https://lh4.googleusercontent.com/hIjiEKIIh5XUcFQjcKtcoiyP9bGKJMxl_S2WdvVQNcxC6NboA56OIMP9dJ7UVZScqMtKJRbL_-pEH0W96GzvuTlBETisgtD09AfcBjGLjTQn6UPHEsiwE11XQ5oJP7ur_9UU2J9Y)

First, it’s printing something. After that, another print

![](https://lh5.googleusercontent.com/5p68lRi5s-DJ7YiPZFOpNU8AmRMGO5FRF4yWF4hOrXjt8UpRbt9hKF6tIUZJZ4ev1B-qnWSbcubBhDmigucvq1Yhl4WB4dXDh54NB_2cP9tKAVyjG3wLXu4G9NVLb-KlOuOHh0kV)

Then, it loads some bytes and encrypts them with AES.

![](https://lh3.googleusercontent.com/e6s1gjr7qjAP0hVT4i-GM3AkXI_5FH140ESWFDvmBqE4RNwjHQH_PR99qVb4-URqFiDboKQS_uvYWagWu1aK2VqltFF6w_Bc9AQiaSmFnK81Ari4WGDlkMlwXfEifJdkSlbkxrC9)

Finally, it converts it to string and prints something again.

![](https://lh6.googleusercontent.com/wk_B2KJyrbrXM7Y2FW6ElTnyVrMxwffMoSUQKmPt4E5hxhZ4K800k8U6SQOuc9eusUkhdHUS9NJgsjlfNZEi9-rysvumVm_LZSIPBMjn7lzBR9yOTeKEPsbnmDIwxbsoJNbu6q-N)

It’s time for some dynamic analysis. Let’s put a break on the instruction and run the program. After stepping to the first print, we can see what the first print was all about:

![](https://lh3.googleusercontent.com/70lTgKtLz5oVM_Un1oKbHtgdR1_w_r_nVXgxmdmePHl4zZXFhbJGiauc49rhvsfq4ic8hGZOZzUYj3RYBvgiT0x_25Kf9VkfOQUqCF8U_-5QANDj8i49NPdfDIP6R75gk0QHoSdH)

The second print output also looks familiar:

![](https://lh6.googleusercontent.com/G03JNisNLNaZJ1uC3hbf2_42YQItJVi0-wknrn7xQyVWvNBNDCb1UqPhGAhRFrEJaAaZNjOItACug_M7-PeBzApIylkmtQazHbSibcq-n_v1QI8vjtLN_U_sTQLqu2QK8mgnnfar)

After that, when we first run it, it shows us the encoded message so it looks like all the AES encryption is about the original message.

Then, the stringtoslicebyte is executed. After the call, we can check the rax register to find the result of the function (the address of the contents)

![](https://lh3.googleusercontent.com/gn4tGtzxxLajFvpMtpvUCQdORjKRE5fJoJwCGD_cRvnIKpFBMDYB0M2O2jBxll1mu7m5vYD-soGInD1UZCwdWaLRNwiOvy4m8oHeJRmj-MPaddFzzohnyk5jzT6Qwb1c6T5xMX6d)

According to the chars, that looks like the passphrase for the AES encryption. So the original message must be loaded before the call.

We can see that the address 0x4c0e36 is loaded into rax. Let’s check that.

![](https://lh5.googleusercontent.com/ECjrJc4pyps9CMJjK4-7S8OrpkRau4jb5ZcL54JmXaCymyv-Ehfrim_EapAJupepwz8ZMxnKTZZreUM6qH_s322X1yu3ecCAlgni1R9aIq2qHzd7M_Fek-OtBYPueFM74j3CG1wa)

After that instruction, it’s actually loading the size of the message to encode, which is 0x10 (or 16 bytes). Let’s grab 16 chars from that previous address: g01sn0tf0rsk1d1e.

We have the original message! We can double check that. We can write a Golang program to decrypt it (because we know the passphrase)

![](https://lh6.googleusercontent.com/WDm9_d4C2uLrHHiNSpYcIrwGPdCgRt2GCgZuTcZVH55NDDcrwPwvOhMRXtrYmd6D1LwzqNui_82WdgWtdiHpnslhqK5vMK9JkrqeluGj3JuhJPRpMqYN4e8blpw7jV54mPsDP6Dh)

We run it and:

![](https://lh6.googleusercontent.com/LA58j1lpCm0uZC6A2EW1QN5i2hdemdKKx0i5t7mlIpVsNJW_hHW0Sk765kmc7Md8a8YxN84QDTLnE-HBsYYClGQZgrtldMBSuO33HuVO0YtOOBp5B5RqjwKbsTIljndCa1T_ly3t)

We were right.

Let’s get the sha256 of that string:

![](https://lh6.googleusercontent.com/GtxYHtnhzdkmLw4KvYWI1TWqtuU86tXQkfp_ZqSd0nNGZ5ImNO8ac0O4D8yuQdwQ7Qa-sNDSIT-LfHcsABPBSgwxrAdEg6bHSbdlkav_u5Oee6fc1tU0nFtD7hJZIGMufGra4INt)

Put that uppercase letters to lowercase and we have the flag:

ctf{a4e394ae892144a54c008a3b480a1b22a6b64dd26c4b0c9eba498330f511b51e}