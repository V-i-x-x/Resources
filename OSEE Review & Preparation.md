**EXP-401 OSEE Review & Preparation**

A lot of students asked me about the training and how did i prepare for it. so here we are.

I attended the live training in QA London and pass the exam on my first attempt in May 2023.

The live training itself was fun, I enjoyed it and it was full of knowledge and magic lol.

***Pre Live Training***

What i did to prepare for the live training and be comfortable about it as much as possible is the following.

Read these 2 articles Part 1 & 2 so you can be familiar a bit with the concepts and the techniques used nowadays to bypass windows mitigations before the live training:

https://www.crowdstrike.com/blog/state-of-exploit-development-part-1/

https://www.crowdstrike.com/blog/state-of-exploit-development-part-2/

Read a little bit about the heap and how it works:

Windows 8 Internal Heap: https://illmatics.com/Windows%208%20Heap%20Internals.pdf

Windows 10 Segment Heap Internals: https://www.youtube.com/watch?v=hetZx78SQ_A

https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf

you don't have to understand every single bit and structure out there.

Just understand how the allocations and free works, how the heap allocate stuff and how does it free them, what does it look for before allocating and freeing? how to trigger lfh (low fragmentation heap)? these kind of stuff.

How Kernel shellcodes works part 1 & 2: 
https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-1

https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-2

And at last, I recommend you Write your own usermode 64-bit shellcode (assembly) to get familiar and comfortable with assembly.

if you already took EXP-301 Course, you already know how to write a 32-bit shellcode from scratch, you can start there and port it to a 64-bit shellcode. (that's what I did)

***Live training***

The pace in the training was pretty fast, my approach was I focused more on understanding the concepts taugh in the classroom specially the one I wasn't familiar with, instead of trying to finish every single exercise in the classroom.

So generally I focused on understanding the concepts, reading the exploits and understanding the poc's the instructors run And ask questions when I am confused.

The most important thing is to understand everything taught in the classroom and ask the instructors if you have any confusion, you will have all the time to go through the exercises and the extra miles after the live training unless again you are comfortable and you want an extra coin :).

The instructors will not go over every single thing in the live training as there is no time for it. but they will go throught most and the toughest parts of it.

***post live training***

After the live training, I started going through the book again line by line, step by step.

Did all the exercises and the extra miles.

Now the big question, is it enough for the exam?

Well that's a tough question to actually reply to, because it depends on the individual experience.

for me, I already had some experience in usermode and kernelmode exploits (not much in kernel but had an idea by trying some old ones locally every now and then)

In the classroom they only teach you 1 or 2 vulnerabilities and how to trigger them, but that doesn't mean the exam will be one of these vulnerabilities taugh in the classroom.

so what I did to refresh my memory and what i recommand as well is the following:

Read the windows 8 Internal Heap: https://illmatics.com/Windows%208%20Heap%20Internals.pdf (you don't have to understand like every bit of what happening just how it works and how the allocation and free happens)

Read the Windows 10 Segment Heap Internals: https://www.youtube.com/watch?v=hetZx78SQ_A

https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf

Read Some Kernel Exploits Case Studies and how it was exploited: https://h0mbre.github.io/ (Read All HEVD Exploits, understand how they works and how they was exploited => even if they are old its about understanding how the vulnerability works and how to approach it)

And of course the instructors as well at the end of the training will share some links for more research for you to do and exploits to make from just a POC. (It is a good practice and specially if you dont have much experience about it).

***The Exam***

You know I can't talk a lot about the Exam xD.

The OSEE exam contains two assignments and points will be rewarded for partial or full complition of the given assignments.

Each of the assigments awards 25 points for partial completion and 50 points for full completion, thus the maximum obtainable amout of points is 100.

To successfully pass the certification exam, 75 points is required.

The Exam is a 71 hours and 45 minutes exam, and 24 hours afterwards for the writing the report.

The Exam was tought and hard honestly but fair.

In the live training and in the book, there is a big amount of reverse engineering happening, but the exam needs to be finished in 3 days, so the amount of reversing you need to do in the exam is not as big as in the materials.

So the reversing that you need to do is fair for the amount of time you have.

During the exam, It took me 1 day to finish the first assignment fully (50 points).

Another 1 day to finish 50% of the second assignment (25 points) -> I struggled a lot on that one.

half a day till i find the route to get the last 25 points.

Even though I found the way to get the other 25 points, but I didn't wanna risk messing up my report, and I chose to start making my report and taking screenshots on the last half of my 3rd day , because it's a big report to make xD.

Make sure to take breaks and sleep and breath specially when you get stuck at some point, trust me taking some fresh air will help.
