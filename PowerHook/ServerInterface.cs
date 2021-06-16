// RemoteFileMonitor (File: FileMonitorHook\ServerInterface.cs)
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
using System.IO;


namespace PowerHook
{
    /// <summary>
    /// Provides an interface for communicating from the client (target) to the server (injector)
    /// </summary>
    public class ServerInterface : MarshalByRefObject
    {

        public void IsInstalled(int clientPID)
        {
            Console.WriteLine("[+] Hooked into PID: {0}\r\n", clientPID);
        }


        /// <summary>
        /// Output the message to the console as well as a file (depends on the "-f" flag).
        /// </summary>
        public void ReportMessages(string[] messages)
        {
            for (int i = 0; i < messages.Length; i++)
            {
                Console.WriteLine(messages[i]);
                string Temp = Path.GetTempPath();
                string filepath = Temp + "filepath.txt";
                if (File.Exists(filepath))
                {
                    WriteToFile(messages[i]);
                }
            }
        }

        public void WriteToFile(string message)
        {
            string Temp = Path.GetTempPath();
            string filepath = File.ReadAllText(Temp + "filepath.txt");
            File.AppendAllText(filepath, message + "\n\r");
            
        }

        /// <summary>
        /// Report exception
        /// </summary>
        /// <param name="e"></param>
        public void ReportException(Exception e)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + e.ToString());
        }

        int count = 0;
        /// <summary>
        /// Called to confirm that the IPC channel is still open / host application has not closed
        /// </summary>
        public void Ping()
        {
            // Output token animation to visualise Ping
            var oldTop = Console.CursorTop;
            var oldLeft = Console.CursorLeft;
            Console.CursorVisible = false;

        

            Console.SetCursorPosition(oldLeft, oldTop);
            Console.CursorVisible = true;
        }
    }
}
