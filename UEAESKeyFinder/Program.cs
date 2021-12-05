using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using static Searcher;

namespace UEAesKeyFinder
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

            Console.Write("Please select from where you want to get the AES Key\n0: Memory\n1: File\n2: Dump File\n3. LibUE4.so File\n4. APK File\nUse: ");

            char method = (char)Console.Read();
            string path;
            string EngineVersion = "4.18.0";
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
                    EngineVersion = searcher.SearchEngineVersion();
                    if (EngineVersion != "")
                    {
                        Console.WriteLine($"Engine Version: {EngineVersion}");
                    }
                    break;
                case '1':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the dump file.");
                        return;
                    }

                    game = new Process() { StartInfo = { FileName = path } };
                    game.Start();
                    Thread.Sleep(1000);
                    // Not required to fully load
                    NtSuspendProcess(game.Handle);

                    searcher = new Searcher(game);
                    searcher.SetFilePath(path);
                    EngineVersion = searcher.SearchEngineVersion();
                    if (EngineVersion != "")
                    {
                        Console.WriteLine($"Engine Version: {EngineVersion}");
                    }
                    break;
                case '2':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the dump file.");
                        return;
                    }

                    searcher = new Searcher(File.ReadAllBytes(path));
                    searcher.SetFilePath(path);
                    EngineVersion = searcher.SearchEngineVersion();
                    if (EngineVersion != "")
                    {
                        Console.WriteLine($"Engine Version: {EngineVersion}");
                    }
                    break;
                case '3':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the lib.");
                        return;
                    }

                    searcher = new Searcher(File.ReadAllBytes(path), true);
                    break;
                case '4':
                    Console.Write("Please enter the file path: ");
                    Console.Read();
                    Console.Read();
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to find the apk.");
                        return;
                    }
                    searcher = new Searcher(File.ReadAllBytes(path), true, true);
                    break;
            }

            Dictionary<ulong, string> aesKeys = searcher.FindAllPattern(out long took);

            if (aesKeys.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(aesKeys.Count == 1 ? $"\nFound {aesKeys.Count} AES Key in {took}ms" : $"\nFound {aesKeys.Count} AES Keys in {took}ms");
                Console.ForegroundColor = ConsoleColor.White;
                int EngineVersionI = 17;
                if (EngineVersion != "") EngineVersionI = Convert.ToInt32(EngineVersion.Split(".")[1]);
                if (EngineVersionI < 18)
                {
                    foreach (KeyValuePair<ulong, string> o in aesKeys)
                    {
                        Console.WriteLine($"{aesKeys[o.Key]} at {o.Key}");
                    };
                }
                else
                {
                    foreach (KeyValuePair<ulong, string> o in aesKeys)
                    {
                        Console.WriteLine($"{aesKeys[o.Key]} ({System.Convert.ToBase64String(GetHex(aesKeys[o.Key][2..aesKeys[o.Key].Length]))}) at {o.Key}");
                    };
                }
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