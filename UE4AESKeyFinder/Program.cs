using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using static Searcher;

namespace UE4AESKeyFinder
{
    class Program
    {
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtSuspendProcess(IntPtr processHandle);
        public static byte[] GetHex(string hex)
        {
            var r = new byte[hex.Length / 2];
            for (var i = 0; i < r.Length; i++) r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }
        static void Main(string[] args)
        {
            Searcher searcher = new Searcher();
            Process game = new Process();

            long TimeMs = 0;
            Dictionary<ulong, string> aesKeys = new Dictionary<ulong, string>();

            Console.Write("Please select from where you want to get the AES Key\n0: Memory\n1: File\n2: Dump File\n\nUse: ");

            char method = (char)Console.Read();
            switch (method)
            {
                case '0':
                    Console.Write("Enter the name or id of the process: ");
                    Console.Read();
                    Console.Read();
                    string ProcessName = Console.ReadLine();

                    bool found = false;
                    foreach (Process p in Process.GetProcesses())
                    {
                        if (p.ProcessName == ProcessName || p.Id.ToString() == ProcessName)
                        {
                            Console.WriteLine($"\nFound {p.ProcessName}");
                            searcher = new Searcher(p);
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
                    break;
                case '1':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    string path2 = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path2))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the dump file.");
                        return;
                    }

                    game = new Process() { StartInfo = { FileName = path2 } };
                    game.Start();
                    Thread.Sleep(1000);
                    // Not required to fully load
                    NtSuspendProcess(game.Handle);

                    searcher = new Searcher(game);
                    break;
                case '2':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    string path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the dump file.");
                        return;
                    }

                    searcher = new Searcher(File.ReadAllBytes(path));
                    break;
            }

            aesKeys = searcher.FindAllPattern(out long x);

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
            }

            if (method == '1') try { game.Kill(); } catch { };

            Console.ReadLine();
        }
    }
}
