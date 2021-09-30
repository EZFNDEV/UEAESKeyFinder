It can be really difficult to get the AES Key of a game if you do not know what you are doing, I remember when I didnt know how to get it so I decided to make a tool that makes it easier for beginnners

#### If this doesn't work for you just a open a new issue, but provide the game name and a memory dump of it, if you already have the AES Key or find it later please provide that too :)
You can use https://github.com/NtQuery/Scylla to get a memory dump of your game

## Android (arm64-v8 only)
For android games you will get two AES Keys, that is because I do not know when the key is + 0x1000 after the offset it should be at. Just try both :)
(If you know why the location is 0x1000 bytes forward please make a pr)

## Android (armeabi-v7a)
If you send me a library + AES Key I can add support for that too

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