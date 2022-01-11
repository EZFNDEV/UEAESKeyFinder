using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public class Searcher
{
    private const int PAGE_SIZE = 4000;

    private bool useUE4Lib = false;

    private IntPtr hProcess;
    private Process Process;
    private ulong AllocationBase;
    private byte[] ProcessMemory;
    private string FilePath;

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
                if (
                    bytes[i] != 0x41 ||
                    bytes[i + 1] != 0x50 ||
                    bytes[i + 1] != 0x50 ||
                    bytes[i + 2] != 0x4B ||
                    bytes[i + 3] != 0x20 ||
                    bytes[i + 4] != 0x53 ||
                    bytes[i + 5] != 0x69 ||
                    bytes[i + 6] != 0x67 ||
                    bytes[i + 7] != 0x20 ||
                    bytes[i + 8] != 0x42 ||
                    bytes[i + 9] != 0x6C ||
                    bytes[i + 10] != 0x6F ||
                    bytes[i + 11] != 0x63 ||
                    bytes[i + 12] != 0x6B
                ) continue;

                libUE4Offset = i;
                break;
            }

            byte[] libUE4 = new byte[] { 0x6C, 0x69, 0x62, 0x2F, 0x61, 0x72, 0x6D, 0x36, 0x34, 0x2D, 0x76, 0x38, 0x61, 0x2F, 0x6C, 0x69, 0x62, 0x55, 0x45, 0x34, 0x2E, 0x73, 0x6F };
            for (int i = libUE4Offset; i < bytes.Length - 1 - libUE4.Length - 1; i++)
            {
                if (bytes[i] != libUE4[0]) continue;
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
            if (libUE4Offset == 0) throw new Exception("Failed to read LibUE4.so, patterns were not found!");

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
    public void SetFilePath(string path) { FilePath = path; }
    public string SearchEngineVersion()
    {
        if (FilePath != null) return FileVersionInfo.GetVersionInfo(FilePath).FileVersion;
        
        // We search backwards because its mostly at the end
        byte[] ProductVersion = new byte[] { 0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00 };
        for (int i = ProcessMemory.Length - 1; i > 0; i--)
        {
            if (this.ProcessMemory[i] != ProductVersion[0]) continue;
            bool c = false;
            for (int ii = 0; ii < ProductVersion.Length - 1; ii++)
            {
                if (this.ProcessMemory[ii + i] != ProductVersion[ii])
                {
                    c = true;
                    break;
                };
            };
            if (c) continue;

            UnicodeEncoding unicodeEncoding = new UnicodeEncoding();
            return new string(unicodeEncoding.GetChars(this.ProcessMemory[(i + ProductVersion.Length - 2)..(i + ProductVersion.Length - 2 + 14)], 2, 12));
        }

        return "";
    }
    public int FollowJMP(int addr)
    {
        addr = (BitConverter.ToInt32(this.ProcessMemory[(addr + 1)..(addr + 1 + 4)].ToArray()) + 5) + addr;
        if ((this.ProcessMemory[addr] == 0x0F && this.ProcessMemory[addr + 4] == 0xE9)) return FollowJMP(addr + 4);

        return addr;
    }
    public UInt64 DecodeADRP(int adrp) // https://chromium.googlesource.com/chromiumos/third_party/binutils/+/refs/heads/stabilize-7374.B/gold/aarch64.cc#150
    {
        const int mask19 = (1 << 19) - 1;
        const int mask2 = 3;

        // 21-bit imm encoded in adrp.
        int imm = ((adrp >> 29) & mask2) | (((adrp >> 5) & mask19) << 2);
        // Retrieve msb of 21-bit-signed imm for sign extension.
        int msbt = (imm >> 20) & 1;
        // Real value is imm multipled by 4k. Value now has 33-bit information.
        int value = imm << 12;
        // Sign extend to 64-bit by repeating msbt 31 (64-33) times and merge it
        // with value.
        return (UInt64)(((((int)(1) << 32) - msbt) << 33) | value);
    }
    public UInt64 DecodeADD(int add)
    {
        var imm12 = (add & 0x3ffc00) >> 10;
        if ((imm12 & 0xc00000) != 0) imm12 <<= 12;
        return (UInt64)imm12;
    }
    public int GetADRLAddress(int ADRPLoc)
    {
        UInt64 ADRP = DecodeADRP(BitConverter.ToInt32(this.ProcessMemory, ADRPLoc));
        UInt64 ADD = DecodeADD(BitConverter.ToInt32(this.ProcessMemory, ADRPLoc + 4));

        return (int)((((UInt64)ADRPLoc & 0xFFFFF000) + ADRP + ADD) & 0xFFFFFFFF);
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

                // 01 01 40 AD 01 00 00 AD C0 03 5F D6

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
                int aesKeyAddr = GetADRLAddress(i - 8);

                aesKey += BitConverter.ToString(this.ProcessMemory[aesKeyAddr..(aesKeyAddr + 32)]).ToString().Replace("-", "");
                offsets.Add(AllocationBase + (ulong)aesKeyAddr, $"0x{aesKey}");

                aesKeyAddr += 0x1000; // Please fix this, idk when its + 0x1000 and when not....
                aesKey = BitConverter.ToString(this.ProcessMemory[aesKeyAddr..(aesKeyAddr + 32)]).ToString().Replace("-", "");
                offsets.Add(AllocationBase + (ulong)aesKeyAddr, $"0x{aesKey}");
            }
        }
        else
        {
            string EngineVersionStr = SearchEngineVersion();
            int EngineVersion = 17;
            if (EngineVersionStr != "") EngineVersion = Convert.ToInt32(EngineVersionStr.Split(".")[1]);
            if (EngineVersion < 18)
            {
                // Let's just try something, not sure if that works for all games
                string aesKey = "";

                for (int i = 0; i < ProcessMemory.Length-10; i++)
                {
                    if (ProcessMemory[i] != 0x00 || ProcessMemory[i + 1] != 0x30 || ProcessMemory[i + 2] != 0x78) continue;

                    // Now we need to find where the first 00 starts and go back to that location
                    int start = i;
                    while (ProcessMemory[start-1] == 0x00) start -= 1;

                    // Key is 64 letters long, lets make sure the first byte before the key is 0x00
                    if (ProcessMemory[start - 65] != 0x00) continue;

                    aesKey = Encoding.Default.GetString(ProcessMemory[(start - 64)..start]);

                    // Lets make sure the key is as valid string
                    if (Regex.IsMatch(aesKey, @"^[a-zA-Z0-9]+$"))
                    {
                        offsets.Add(AllocationBase + (ulong)start-64, aesKey);
                        break;
                    }
                }
            }
            
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
                                if (this.ProcessMemory[addr] != 0xC3 && this.ProcessMemory[addr] != 0x48)
                                {
                                    // There might be movups so lets check 50 bytes if we still get 48 8D
                                    if (this.ProcessMemory[addr] != 0x0F) c = true;
                                    for (int xx = 0; xx < 30; xx++)
                                    {
                                        addr = addr + xx;
                                        if (this.ProcessMemory[addr] == 0x48 && this.ProcessMemory[addr] == 0x8D) break;
                                    }
                                    // We should probably delete this...
                                    if (this.ProcessMemory[addr] != 0x48 && this.ProcessMemory[addr] == 0x8D) c = true;
                                }
                            }
                            if (c) break;
                        }
                        if (c) continue;

                        offsets.Add(AllocationBase + (ulong)i, $"0x{aesKey}");
                    }
                    catch { }
                }
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