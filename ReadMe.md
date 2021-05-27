It can be really difficult to get the AES Key of a game if you do not know what you are doing, I remember when I didnt know how to get it so I decided to make a tool that makes it easier for beginnners

## Tested Games:
Fortnite Season 2-16 (Unreal Engine 4)  
Thrid Person Game (Unreal Engine 5)

### You should manually start games like Fortnite, otherwise this tool could fail to read the process memory (\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe)
#### If this doesn't work for you just make a open a new issue and I will try to add support for your game :)

### Example outputs:
```
Please select from where you want to get the AES Key
0: Memory
1: File
2: Dump File
3. LibUE4.so File
4. APK File
Use: 0
Enter the name or id of the process: MyProject

Found MyProject

Found 1 AES Keys in 720ms
0xD0DE16965D23CC8A46178FFFAB18130651D2C99F7B3D63ECC8FD04D691609572 (0N4Wll0jzIpGF4//qxgTBlHSyZ97PWPsyP0E1pFglXI=) at 140695177160459
```
