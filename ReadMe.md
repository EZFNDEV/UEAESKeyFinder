It can be really difficult to get the AES Key of a game if you do not know what you are doing, I remember when I didnt know how to get it so I decided to make a tool that makes it easier for beginnners

## Tested Games:
Fortnite Season 2.4.2 (Memory) (UE4.19)  
Fortnite Season 3 (Memory) (UE4.20)  
ShooterGame (Memory) (UE4.20.3)  
Fortnite Season 6.3 (Memory) (UE4.23)  
Fortnite Season 9.1 (Memory) (UE4.23)  
VALORANT (Memory) (UE4.24.3)  
Pal7 (File) (UE4.25.1)  
Fortnite Season 13.4 (Memory) (UE4.26)  
Fortnite Season 15.5 (Memory) (UE4.26)  
Fortnite Season 16.2 (Memory) (UE4.26)  
ShooterGame (Memory) (UE4.26.1)  
Fortnite Season 16.3 (Memory) (UE4.26.1)  

### You should manually start games like Fortnite, otherwise this tool could fail to read the process memory (\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe)
#### If this doesn't work for you just make a open a new issue and I will try to add support for your game :)

### Example outputs:
```
Do you want to use a dump file, its recommended (y/n)
n
Enter the name of the process:
FortniteClient-Win64-Shipping

Found FortniteClient-Win64-Shipping

Found 2 AES Keys in 675ms
0x20175EA945CCA944B664B8161979E380E72C9943D785E50D6CDD0712801FCE19 (IBdeqUXMqUS2ZLgWGXnjgOcsmUPXheUNbN0HEoAfzhk=) at 140698487652551
0xCE0D9BEFF8DA86195BC0F95E1612948871ED8DAA0E9199D18272F5C80853156A (zg2b7/jahhlbwPleFhKUiHHtjaoOkZnRgnL1yAhTFWo=) at 140698644835001
------------------------------------------------------------------------------------------------------------------------------------
Do you want to use a dump file, its recommended (y/n)
n
Enter the name of the process:
FortniteClient-Win64-Shipping

Found FortniteClient-Win64-Shipping

Found 1 AES Keys in 505ms
0x67D061EFA8E049F7C62F1C460F14CD5AD7E601C13F3FB66F0FB090B72B721ACC (Z9Bh76jgSffGLxxGDxTNWtfmAcE/P7ZvD7CQtytyGsw=) at 140697872524562
------------------------------------------------------------------------------------------------------------------------------------
Do you want to use a dump file, its recommended (y/n)
n
Enter the name of the process:
FortniteClient-Win64-Shipping

Found FortniteClient-Win64-Shipping

Found 1 AES Keys in 658ms
0xDA62D5DBF537499EF82351FC4751D2AFC82E35CAF19945BDD02E3C6BB9462491 (2mLV2/U3SZ74I1H8R1HSr8guNcrxmUW90C48a7lGJJE=) at 140698023256069
------------------------------------------------------------------------------------------------------------------------------------
Do you want to use a dump file, its recommended (y/n)
n
Enter the name or id of the process:
ShooterGame

Found ShooterGame

Found 1 AES Keys in 615ms
0x4CBD3A09052D50B450C924D5A09E2EA0289AA8B3F851CC9D89E1E36068B68D94 (TL06CQUtULRQySTVoJ4uoCiaqLP4UcydieHjYGi2jZQ=) at 140702566467339
```
