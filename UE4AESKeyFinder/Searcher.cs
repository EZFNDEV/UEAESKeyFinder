using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

public class Searcher
{
    private IntPtr hProcess;
    private Process Process;
    private ulong AllocationBase;
    private byte[] ProcessMemory;

    public Searcher() { }

    public Searcher(Process p)
    {
        Process = p;
        hProcess = p.Handle;
        AllocationBase = (ulong)p.MainModule.BaseAddress;
        ProcessMemory = new byte[p.MainModule.ModuleMemorySize];

        // To best honest idk why some regions are 0 if we read all at once ¯\_(ツ)_/¯
        for (int i = 0; i < ProcessMemory.Length; i += 2048)
        {
            byte[] bytes = new byte[2048];
            Win32.ReadProcessMemory(hProcess, AllocationBase + (ulong)i, bytes, 2048);
            for (int ii = 0; ii < bytes.Length; ii++)
            {
                if (!(i + ii >= ProcessMemory.Length)) ProcessMemory[i + ii] = bytes[ii];
                else break;
            };
        }
    }
    public Searcher(byte[] bytes)
    {
        AllocationBase = 0;
        ProcessMemory = bytes;
    }
    public int FollowJMP(int addr)
    {
        byte[] jmp = this.ProcessMemory[(addr + 1)..(addr + 1 + 4)].Reverse<byte>().ToArray();
        jmp[3] += 5; // JMP instruction length

        addr = (int)addr + (int)Convert.ToInt32(BitConverter.ToString(jmp).Replace("-", ""), 16);
        // Auto follow other jmps
        if ((this.ProcessMemory[addr] == 0x0F && this.ProcessMemory[addr + 4] == 0xE9)) return FollowJMP(addr + 4);

        return addr;
    }
    public Dictionary<ulong, string> FindAllPattern(out long t)
    {
        Stopwatch timer = Stopwatch.StartNew();
        Dictionary<ulong, string> offsets = new Dictionary<ulong, string>();

        // Based on "?Callback@FEncryptionKeyRegistration@@SAXQEAE@Z"
        // https://github.com/EpicGames/UnrealEngine/blob/5df54b7ef1714f28fb5da319c3e83d96f0bedf08/Engine/Source/Runtime/Core/Public/Modules/ModuleManager.h#L841

        // Should work for all newer Fortnite versions
        // C7 45 D0 ? ? ? ? C7 45 D4 ? ? ? ? C7 45 D8 ? ? ? ? C7 45 DC ? ? ? ? ? ? ? ? C7 45 E0 ? ? ? ? C7 45 E4? ? ? ? C7 45 E8 ? ? ? ? C7 45 EC ? ? ? ?

        string aesKey = "";
        int verify_1 = 0xC7;
        for (int i = 0; i < ProcessMemory.Length - 10; i++)
        {
            try
            {
                // Should start with smth like 48 8D 64 24 08 and end with it 
                if (this.ProcessMemory[i - 3] == 0x00 && this.ProcessMemory[i - 2] == 0x00 && this.ProcessMemory[i - 1] == 0x00) continue;
                if (this.ProcessMemory[i] != verify_1 || (this.ProcessMemory[i + 1] != 0x45 && this.ProcessMemory[i + 1] != 0x01)) continue;
                int verify_2 = this.ProcessMemory[i + 1] == 0x01 ? 0x41 : 0x45;
                int verify_3 = this.ProcessMemory[i + 1] == 0x01 ? 0 : 0xD0;
                if (this.ProcessMemory[i + 1] == 0x45 && this.ProcessMemory[i + 2] != verify_3) continue;

                // It should be the first keypart
                if (this.ProcessMemory[i - 7] == verify_1 && this.ProcessMemory[i - 6] == verify_2) continue;

                verify_3 += 0x04;
                // Make sure this address is valid (Not following jumps yet) fuck it, lets also check the jmps
                bool c = false;
                int addr = i + 4 + 2 + (this.ProcessMemory[i + 1] == 0x01 ? 0 : 1);
                aesKey = BitConverter.ToString(this.ProcessMemory[(addr - 4)..addr]).Replace("-", ""); // New valid start, new luck

                while (aesKey.Length != 64)
                // 8 parts, we have to skip the instruction with the size of 2-3 and the key itself with the size of 4
                // older versions have a simple mov rcx, but never have mov rcx+4
                {
                    if (this.ProcessMemory[addr] != verify_1 && this.ProcessMemory[addr] != 0xE9) // Same for all UE4 games
                    {
                        // Sometimes one keypart has 4 useless bytes at the end, just skip it if the 3 bytes after it match the new keypart start
                        // JMP Right after it is possible too
                        if (this.ProcessMemory[addr] == 0x0F && this.ProcessMemory[addr + 4] == 0xE9)
                        {
                            addr += 4; // Skip the useless bytes
                            // jump to the address and check if the bytes are valid
                            addr = FollowJMP(addr);
                            if (this.ProcessMemory[addr] != verify_1 && this.ProcessMemory[addr + 1] != verify_2 && this.ProcessMemory[addr + 2] != verify_3) c = true;
                        }
                        else if (this.ProcessMemory[addr + 4] != verify_1 && this.ProcessMemory[addr + 5] != verify_2 && this.ProcessMemory[addr + 6] != verify_3) c = true;
                        else addr += 4;
                    };

                    if (this.ProcessMemory[addr] == 0xE9) addr = FollowJMP(addr);
                    else
                    {
                        if (this.ProcessMemory[addr + 1] != verify_2) c = true;
                        if ((this.ProcessMemory[addr + 2] != verify_3)) c = true;
                        aesKey = aesKey + BitConverter.ToString(this.ProcessMemory[(addr + 3)..(addr + 7)]).Replace("-", "");
                        addr += 4 + 3; // C7 4x xx
                        verify_3 += 0x04;
                    };

                    if (aesKey.Length == 64)
                    {
                        // This is the last, we should not be able to get another keypart, if so this is not the correct AES Keys.
                        // if (this.ProcessMemory[addr] == verify_1 && this.ProcessMemory[addr + 1] == verify_2) c = true;
                        if (this.ProcessMemory[addr] == 0xE9) addr = FollowJMP(addr);
                        // && this.ProcessMemory[addr + 1] != 0x8D && this.ProcessMemory[addr + 1] != 0x64 && this.ProcessMemory[addr + 1] != 0x24 && this.ProcessMemory[addr + 1] != 0x08
                        if (this.ProcessMemory[addr] != 0x48)
                        {
                            // There might be movups so lets check 50 bytes if we still get 48 8D
                            if (this.ProcessMemory[addr] != 0x0F) c = true;
                            for (int xx = 0; xx < 30; xx++)
                            {
                                addr = addr + xx;
                                if (this.ProcessMemory[addr] == 0x48 && this.ProcessMemory[addr] == 0x8D) break;
                            }
                        };
                        if (this.ProcessMemory[addr] != 0x48 && this.ProcessMemory[addr] == 0x8D) c = true;
                        // I think it always ends with 48 8D 64 24 08, correct me if I am wrong...
                    }
                    if (c) break;
                }
                if (c) continue;

                offsets.Add(AllocationBase + (ulong)i, $"0x{aesKey}");
            }
            catch { }
        }

        t = timer.ElapsedMilliseconds;
        return offsets;
    }

    public static class Win32
    {
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead = 0);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    }
}