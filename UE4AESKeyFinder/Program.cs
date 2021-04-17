using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using static Searcher;

namespace UE4AESKeyFinder
{
    class Program
    {
        public static byte[] GetHex(string hex)
        {
            var r = new byte[hex.Length / 2];
            for (var i = 0; i < r.Length; i++) r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }
        static void Main(string[] args)
        {
            long TimeMs = 0;
            Dictionary<ulong, string> aesKeys = new Dictionary<ulong, string>();

            // Always used to work but now that I want to release it it doesnt -.-
            // Console.WriteLine("Do you want to use a dump file, its recommended (y/n)");
            bool UseDump = false; // Console.ReadLine() == "y";

            if (UseDump)
            {
                Console.WriteLine("Please enter the file path: ");
                string Path = Console.ReadLine().Replace("\"", "");
                if (!File.Exists(Path))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed to find the dump file.");
                    return;
                }

                Searcher searcher = new Searcher(File.ReadAllBytes(Path));
                aesKeys = searcher.FindAllPattern(out long x);
                TimeMs = x;
            }
            else
            {
                Console.WriteLine("Enter the name or id of the process: ");
                string ProcessName = Console.ReadLine();

                bool found = false;
                foreach (Process p in Process.GetProcesses())
                {
                    if (p.ProcessName == ProcessName || p.Id.ToString() == ProcessName)
                    {
                        Console.WriteLine($"\nFound {p.ProcessName}");
                        Searcher searcher = new Searcher(p, Win32.OpenProcess(0x0010, false, p.Id));
                        aesKeys = searcher.FindAllPattern(out long x);
                        TimeMs = x;
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed to find the process.");
                    Console.ReadLine();
                    return;
                }
            }

            if (aesKeys.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nFound {aesKeys.Count} AES Keys in {TimeMs}ms");
                Console.ForegroundColor = ConsoleColor.White;
                foreach (KeyValuePair<ulong, string> o in aesKeys)
                {
                    Console.WriteLine($"{aesKeys[o.Key]} ({System.Convert.ToBase64String(GetHex(aesKeys[o.Key][2..aesKeys[o.Key].Length]))}) at {o.Key}");
                };
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nFailed to find any AES Keys.");
                Console.ReadLine();
            }

            Console.ReadLine();
        }
    }
}
