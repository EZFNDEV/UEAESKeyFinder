using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;

public class Searcher
{
    private bool useUE4Lib = false;

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
    public Searcher(byte[] bytes, bool useAndroid, bool isAPK = false)
    {
        if (isAPK)
        {
            // Find "APK Sig Block" (Opening the whole file is bad...)
            int libUE4Offset = 0;
            for (int i = bytes.Length - 1; i > 0; i--)
            {
                // Feel free to make a loop here
                if (bytes[i] != 0x41) continue;
                if (bytes[i + 1] != 0x50) continue;
                if (bytes[i + 2] != 0x4B) continue;
                if (bytes[i + 3] != 0x20) continue;
                if (bytes[i + 4] != 0x53) continue;
                if (bytes[i + 5] != 0x69) continue;
                if (bytes[i + 6] != 0x67) continue;
                if (bytes[i + 7] != 0x20) continue;
                if (bytes[i + 8] != 0x42) continue;
                if (bytes[i + 9] != 0x6C) continue;
                if (bytes[i + 10] != 0x6F) continue;
                if (bytes[i + 11] != 0x63) continue;
                if (bytes[i + 12] != 0x6B) continue;

                libUE4Offset = i;
                break;
            }

            byte[] libUE4 = new byte[] { 0x6C, 0x69, 0x62, 0x2F, 0x61, 0x72, 0x6D, 0x36, 0x34, 0x2D, 0x76, 0x38, 0x61, 0x2F, 0x6C, 0x69, 0x62, 0x55, 0x45, 0x34, 0x2E, 0x73, 0x6F };
            for (int i = libUE4Offset; i < bytes.Length - 1 - libUE4.Length - 1; i++)
            {
                if (bytes[i] != libUE4[0]) continue;
                // Now you know why I never didnt do it on the other things lmao
                bool c = false;
                for (int ii = 0; ii < libUE4.Length - 1; ii++)
                {
                    if (bytes[ii + i] != libUE4[ii])
                    {
                        c = true;
                        break;
                    };
                };
                if (c) continue;

                libUE4Offset = BitConverter.ToInt32(bytes[(i - 4)..(i)]);
            }

            // Read compressed/uncompressed size from the header and then skip it
            int compressed = BitConverter.ToInt32(bytes[(libUE4Offset + 18)..(libUE4Offset + 22)]);
            int uncompressed = BitConverter.ToInt32(bytes[(libUE4Offset + 22)..(libUE4Offset + 26)]);
            libUE4Offset = libUE4Offset + 53; // Header size is hardcoded, but why would it ever change?

            MemoryStream uncompressedLibUE4 = new MemoryStream();
            DeflateStream deflated = new DeflateStream(new MemoryStream(bytes[(libUE4Offset)..(libUE4Offset + compressed)]), CompressionMode.Decompress);
            deflated.CopyTo(uncompressedLibUE4);
            if (uncompressedLibUE4.Length != uncompressed) throw new Exception("Failed to read LibUE4.so, decompressed size does not match the decompressed size from the header!");
            ProcessMemory = uncompressedLibUE4.ToArray();
        }
        else
        {
            ProcessMemory = bytes;
        }

        useUE4Lib = useAndroid;
    }
    public int FollowJMP(int addr)
    {
        addr = (BitConverter.ToInt32(this.ProcessMemory[(addr + 1)..(addr + 1 + 4)].ToArray()) + 5) + addr;
        if ((this.ProcessMemory[addr] == 0x0F && this.ProcessMemory[addr + 4] == 0xE9)) return FollowJMP(addr + 4);

        return addr;
    }
    public Dictionary<ulong, string> FindAllPattern(out long t)
    {
        Stopwatch timer = Stopwatch.StartNew();
        Dictionary<ulong, string> offsets = new Dictionary<ulong, string>();

        // Android
        if (useUE4Lib)
        {
            string aesKey = "";
            // We could (should) use a function to match the pattern but idk (lazy)...
            for (int i = 0; i < ProcessMemory.Length - 10; i++)
            {
                // if this gets no results (or too many) for some reason we could also get the addr that calls this...

                // First instruction is the adrp, then add...

                // Second instruction
                if (this.ProcessMemory[i] != 0x01) continue;
                if (this.ProcessMemory[i + 1] != 0x01) continue;
                if (this.ProcessMemory[i + 2] != 0x40) continue;
                if (this.ProcessMemory[i + 3] != 0xAD) continue;

                // Third instruction
                if (this.ProcessMemory[i + 4] != 0x01) continue;
                if (this.ProcessMemory[i + 5] != 0x00) continue;
                if (this.ProcessMemory[i + 6] != 0x00) continue;
                if (this.ProcessMemory[i + 7] != 0xAD) continue;

                // Fourth instruction
                if (this.ProcessMemory[i + 8] != 0xC0) continue;
                if (this.ProcessMemory[i + 9] != 0x03) continue;
                if (this.ProcessMemory[i + 10] != 0x5F) continue;
                if (this.ProcessMemory[i + 11] != 0xD6) continue;

                aesKey = "";
                ulong aesKeyAddr = 0;
                // TODO: Remove capstone and manaully get the label for adrp and add
                // NOTE: doesnt work for older versions (15.4 still works) (they work a bit different but kinda easy to fix (next update))
                // I totally suck with arm64, if you know how to improve this (without capstone would be best) feel free to make a pull request
                uint PAGE_MASK = 0xFFFFF000;
                const Arm64DisassembleMode disassembleMode = Arm64DisassembleMode.Arm;
                using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode))
                {
                    disassembler.EnableInstructionDetails = true;
                    disassembler.DisassembleSyntax = DisassembleSyntax.Intel;

                    Arm64Instruction[] instructions = disassembler.Disassemble(this.ProcessMemory[(i - 8)..i]); // get the first instruction

                    string adrp_s = instructions[0].Operand.Split(", #")[instructions[0].Operand.Split(", #").Length - 1];
                    ulong adrp = ulong.Parse(adrp_s[2..(adrp_s.Length)], System.Globalization.NumberStyles.HexNumber);

                    string add_s = instructions[1].Operand.Split(", #")[instructions[1].Operand.Split(", #").Length - 1];
                    ulong add = ulong.Parse(add_s[2..(add_s.Length)], System.Globalization.NumberStyles.HexNumber);

                    aesKeyAddr = ((ulong)(i & PAGE_MASK) + adrp + add) & 0xFFFFFFFF;
                }

                aesKey += BitConverter.ToString(this.ProcessMemory[(int)aesKeyAddr..(int)(aesKeyAddr + 32)]).ToString().Replace("-", "");
                offsets.Add(AllocationBase + aesKeyAddr, $"0x{aesKey}");
            }
        }
        else
        {
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