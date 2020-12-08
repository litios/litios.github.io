<pre style="font-size: 0.4rem; text-align: center">
                                           ,,,,,                                
                               ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,                   
                         ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,              
                     ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,          
                 ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,      
              ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,   
            ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,, 
          ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
        ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,  
       ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,     
     ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,           
                                                                                
                                                                                
                                                                                
  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                  
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%               
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%             
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%            
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%            
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%            
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%             
 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%               
  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                  
                                                                                
                                                                                
                                                                                
     /////////////////////////////////////////////////////////////////          
       ////////////////////////////////////////////////////////////////////     
        //////////////////////////////////////////////////////////////////////  
          //////////////////////////////////////////////////////////////////////
            /////////////////////////////////////////////////////////////////// 
              //////////////////////////////////////////////////////////////    
                 /////////////////////////////////////////////////////////      
                     /////////////////////////////////////////////////          
                         /////////////////////////////////////////              
                               /////////////////////////////                    

</pre>

---

This was a challenge from the DefCamp CTF 2020 rated with 193 points (Q1) and 208 points (Q3). It was about investigating an security breach inside some Windows hosts by using logs collected from a ELK (Elasticsearch, Logstash, Kibana) system.     

---

First step was to download the challenge zip, and execute then different commands they provide in the description.

To get the IP of the kibana first we must find out the name of the container with ‘docker container ls’ and we find that it’s elastic\_kibana\_1. Then, we use ‘docker container inspect elastic\_kibana\_1’ to get information about the container and, also, the IP.

![](https://lh6.googleusercontent.com/A3KCH1zK26GrlIaPNpVEbbkpx2vWo4cbbp0mR1p8HOeq7VmuIzCr5a2goOJTKi0-lOPYCEuKz9_ymzK6vZH-Sy6cKig6ngjFINqOgHZSz-MkZIwz3LbhGSly8Ysg2vwnTZ2tS5Rt)

We connect to [http://172.18.0.2:5601/] and a login screen appears. We try the default login credentials (which are elastic:changeme) and we get in.

Then we go to the left panel -> Kibana -> Discover. We set the date range to the one in the description and we get:

![](https://lh5.googleusercontent.com/HWnKffSSvJKfR3y1GvtTUSYmf5EFM2K3ygBCjsbxsETjp0bpE09Exj488RfViLf0mde_zsVt7yJCmztyqyfNVU3E1RHZ7Sqw1rv_8KrZAIG2Z_YTGQ8YLhQOuYfeY3Uv9A17JWht)

There are almost 5000 hits so let’s use the filter to find the solutions.

## Q1

The description talk about some tool to dump passwords. Let’s check what commands were used by filtering with the **cmd.exe** and **powershell.exe** processes.

We are going to filter the fields with the following one so it’s easier to see them:

![](https://lh5.googleusercontent.com/vC9VpeXbXp_eKMRZBuSYuwPncZFBkJOmn4LUYL6vj4ZvvsF7K2j0KN_B-WxKZ0QlmXNCcwWppSMRqOqG-g2uC4RCRVfttlHxnP5gpIHocf4nl2-nnPf4Gum_wsgfQLTRMwzK0O-j)

By inspecting the **cmd.exe** commands we found some weird commands related to the attack but nothing related to the passwords.

Let’s check the **powershell.exe** logs. At Dec 4, 10:37:11 we can see the malware is downloading some software and executing it.

![](https://lh4.googleusercontent.com/3au6lZodEQ8DohHNqxoktLYSQ940G6ZwyUOrDiy0x6fC6xZRMhBBwNL5e2v529SBpgT5RI1CXWH5WW1UjKjOYErre47TDGq6ZSUdMpqbRZN6e4vtzI_VSHaaLrB4JuJ0gvhfPoqt)

By searching that name we get the tool **Mimikatz**, which is used to dump Windows passwords, among other things. The parameter (-DumpCreds) also is an indicator of what it's doing. They ask us about the process name so let’s search around that moment.

![](https://lh4.googleusercontent.com/spuGiopMkeemIMeKl0FE4sId7KdSg3c4HxbHeBXl0PeWvqtogxufeD68V5Ta5wJm6ogW7NtZbJtT4dlH7_7d58_dpMh7pDjO-Pz2qY1rfG4wQxd2JzZhmfS6EsaN__DJWuD7XjWN)

Just a couple moments before, a mim.exe was executed. Let’s filter by that name:

![](https://lh4.googleusercontent.com/y9y6zM1hocZk0XFAXlh-O-YjMALOGV5nMQcjToDqBMxeuQg7t2vzH49_IjYwOJPsKHSJBKXDuf0jUy2Z0Up5xsvZUuHc6NiznUc9azE4WIc_IWVicrZxLJUE2sHqj6EYpiLNrl53)

It looks like this is the program that was dumping the passwords so the flag will be: ctf{mim.exe}

## Q3

They told us about some APT script they used to start the attack so let’s back to the cmd.exe logs. Just a few logs from the beginning we find something promising:

![](https://lh4.googleusercontent.com/YTza3KWArxM0SCxJ6u2YDR_l0X2dU7KGT8ituiay9G7J7OlBrm3Yt2GFrQ-BsrWGl9df53mP3Xr7AIfKEaatG9qYouxe9SIWRdKE7QHpdnVD08tpV49WIAMX8F-GKp9uCUS6Fd-Q)

That name really looks suspicious. We search that on Google and we find (https://github.com/NextronSystems/APTSimulator). This is a tool set to perform APT attacks for simulations.

But, we have to be sure that it was the first one. So let’s filter by date from the first log to Dec 4, 09:32:15.

We perform an investigation by 30 min ranges:

![](https://lh5.googleusercontent.com/-uYI2jD0qj44ZRY_0MrZIvWk3R8S2Kw-W00Uog-YtTeIWgTHQ0DSHAFFpokOKVKjmuxZNx5RkYDYu4Sz5LNqiWxplT7vX52fryTs9-OXnSXevlQdMg1V9DDFVx90cPUyWU4gAgVz)

The only suspicious command is that p.exe but it doesn’t look like it’s the responsible for the APT attacks.

According to the investigation, we determined that the guilty is the **APTSimulator.bat** so the flag will be ctf{APTSimulator.bat}