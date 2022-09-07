using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Newtonsoft.Json;
using static SharpSack.ManagedIPHelper;
using static SharpSack.DataAccess;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security;
using System.Security.Permissions;
using System.Security.AccessControl;
using System.Management;

namespace SharpSack
{
    class Program
    {
        private static readonly List<Module> ActiveModules = new List<Module>() {
            new Module("Print help","help","Example: SharpSack.exe help", false),
            new Module("Service stop & start","service","Example: SharpSack.exe service [service name]", true, "Enter the service name as a parameter"),
            new Module("DNS lookup","dnslookup","Example: SharpSack.exe dnslookup [hostname]", true, "Enter the hostname as a parameter"),
            new Module("Deserialize input string","deserialize","Example: SharpSack.exe deserialize [string]", true, "Enter the string to deserialize as a parameter"),
            new Module("Convert to base64","tobase64","Example: SharpSack.exe tobase64 [string or filename]", true, "Enter the string or filename to encode as a parameter"),
            new Module("Convert from base64","frombase64","Example: SharpSack.exe frombase64 [string or filename] {out file}", true, "Enter the string or filename to decode as a parameter"),
            new Module("Start process as user","processasuser","Example: SharpSack.exe processasuser [username] [password]", true, "Enter the username and password to run the process as"),
            new Module("Get directory file count","filecount","Example: SharpSack.exe filecount [directory]", true, "Enter the directory to count files in"),
            new Module("Convert file to array string","filetoarray","Example: SharpSack.exe filetoarray [filename]", true, "Enter the path of the file you want to convert"),
            new Module("List directory contents","dir","Example: SharpSack.exe dir {path} {\"recurse\"}", false, "Enter the path of the directory (or leave blank for current)"),
            new Module("Get environment info","whoami","Example: SharpSack.exe whoami", false),
            new Module("Get environment info","hostname","Example: SharpSack.exe hostname", false),
            new Module("Create a directory","mkdir","Example: SharpSack.exe mkdir [directory name]", true, "Enter the directory path to create"),
            new Module("Check network connections","netstat","Example: SharpSack.exe netstat", false),
            new Module("Get installed programs","programs","Example: SharpSack.exe programs", false),
            new Module("Get SSL certificate details","ssldetails","Example: SharpSack.exe ssldetails [url]", true, "Enter the URL to inspect SSL details"),
            new Module("*DEV* View remote desktop sessions","rdsessions","Example: SharpSack.exe rdsessions {server}",true,""),
            new Module("View user sessions","sessions","Example: SharpSack.exe sessions", false),
            new Module("Get network information","ipconfig","Example: SharpSack.exe ipconfig", false),
            new Module("Do a reverse DNS lookup","rdns","Example: SharpSack.exe rdns {host1,host2}", true, "Enter a comma separated list of hosts for an rDNS lookup"),
            new Module("Launches a hidden instance of IE via COM","hiddenie","Example: SharpSack.exe hiddenie", false),
            new Module("Checks file permissions","perms","Example: SharpSack.exe perms {file}", true, "Enter file to check permissions on"),
            new Module("Enumerate environment variables","env","Example: SharpSack.exe env", false),
            new Module("Create a process that just hangs out","inception","Example: SharpSack.exe inception [processname] {ppid}", true, "Enter process name of spanwed process and ppid to spoof"),
            new Module("Search processes","searchps","Example: SharpSack.exe searchps [processname]", true, "Enter process name you want to search for"),
            new Module("Fuzzy match folder containing binary","binmatch","Example: SharpSack.exe binmatch [topDirectory] [folderMatch] [binary]", true, "Enter the top level directory to search, intermediate folder to fuzzy match, and the binary to find"),
            new Module("Get mounted drives","drives","Example: SharpSack.exe drives", false),
            new Module("Convert binary file to hex string","bin2hex","Example: SharpSack.exe bin2hex [file]", true,"Enter file to convert to hex string"),
        };

        public static int Main(string[] args)
        {
            try
            {
                if (string.IsNullOrEmpty(args[0]))
                {
                    Console.WriteLine("Pick a module\n");
                    PrintHelp();
                    return 1;
                }
                else
                {
                    Module selectedModule = ActiveModules.Where(m => m.Command.Equals(args[0].ToLower())).FirstOrDefault();

                    if (selectedModule == null)
                    {
                        Console.WriteLine("Module name not found: {0}", args[0]);
                        PrintHelp();
                        return 1;
                    }

                    if (selectedModule.Command.Equals("help"))
                    {
                        PrintHelp();
                        return 0;
                    }

                    List<string> moduleArgs = args.Skip(1).ToList();

                    if ((selectedModule.RequiresArgs && moduleArgs.Count == 0) || (moduleArgs.Where(a => a.ToLower().Equals("help")).FirstOrDefault() == moduleArgs.FirstOrDefault()) && moduleArgs.Exists(a => a.ToLower().Equals("help")))
                    {
                        Console.WriteLine("\n{0,-65} {1}", selectedModule.HelpText, selectedModule.Tip);
                        return 1;
                    }

                    switch (selectedModule.Command.ToLower())
                    {
                        case "service":
                            HandleService(moduleArgs.FirstOrDefault());
                            break;
                        case "dnslookup":
                            DNSLookup(moduleArgs.FirstOrDefault().Split(',').ToList());
                            break;
                        case "deserialize":
                            DeserializeString(moduleArgs.FirstOrDefault());
                            break;
                        case "tobase64":
                            ConvertToBase64(moduleArgs.FirstOrDefault(), moduleArgs.Skip(1).FirstOrDefault().Equals("file"));
                            break;
                        case "frombase64":
                            Console.WriteLine(moduleArgs.Count);
                            ConvertFromBase64(moduleArgs.FirstOrDefault(), moduleArgs.Skip(1).FirstOrDefault());
                            break;
                        case "help":
                            PrintHelp();
                            break;
                        case "processasuser":
                            StartProcessAsUser(moduleArgs.FirstOrDefault(), moduleArgs.Skip(1).FirstOrDefault());
                            break;
                        case "filecount":
                            GetFileCount(moduleArgs.FirstOrDefault());
                            break;
                        case "filetoarray":
                            FileToArray(moduleArgs.FirstOrDefault());
                            break;
                        case "dir":
                            string dir = string.Empty;
                            if (moduleArgs.Count > 0)
                                dir = moduleArgs.FirstOrDefault();
                            ListDirectory(dir, moduleArgs.Any(a => a.ToLower().Equals("recursive")));
                            break;
                        case "whoami":
                        case "hostname":
                            WhoAmI();
                            break;
                        case "mkdir":
                            CreateDirectory(moduleArgs.FirstOrDefault(), moduleArgs.Count > 1 && moduleArgs.Any(a => a.ToLower().Equals("zwsp")));
                            break;
                        case "netstat":
                            Netstat();
                            break;
                        case "programs":
                            GetPrograms();
                            break;
                        case "ssldetails":
                            GetSSLDetails(moduleArgs.FirstOrDefault());
                            break;
                        case "rdsessions":
                            string server = "127.0.0.1";
                            if (moduleArgs.Count > 0)
                                server = moduleArgs.FirstOrDefault();
                            GetRDUserSessions(server);
                            break;
                        case "sessions":
                            GetSessions();
                            break;
                        case "ipconfig":
                            IpConfig();
                            break;
                        case "rdns":
                            ReverseDNS(moduleArgs.FirstOrDefault().Split(',').ToList());
                            break;
                        case "cat":
                            Cat(moduleArgs.FirstOrDefault());
                            break;
                        case "hiddenie":
                            LaunchIE();
                            break;
                        case "perms":
                            CheckPermissions(moduleArgs.FirstOrDefault());
                            break;
                        case "env":
                            GetEnvVars();
                            break;
                        case "inception":
                            int ppid;
                            try
                            {
                                ppid = Convert.ToInt32(moduleArgs.Skip(1).FirstOrDefault());
                            }
                            catch
                            {
                                ppid = -1;
                            }
                            SpoofPPID(moduleArgs.FirstOrDefault(),ppid);
                            break;
                        case "searchps":
                            ProcessSearch(moduleArgs.FirstOrDefault());
                            break;
                        case "binmatch":
                            BinMatch(moduleArgs.FirstOrDefault(), moduleArgs.Skip(1).FirstOrDefault(), moduleArgs.Skip(2).FirstOrDefault());
                            break;
                        case "drives":
                            GetMountedDrives();
                            break;
                        case "bin2hex":
                            Bin2Hex(moduleArgs.FirstOrDefault());
                            break;
                        default:
                            PrintHelp();
                            break;
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("Good job, you broke it. Heres some debugging info, good luck.");

                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }

            return 0;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("");
            ActiveModules.ForEach(mod => Console.WriteLine("{0, -45} {1, -100}", mod.Name, mod.HelpText));
        }

        private static void HandleService(string serviceName)
        {
            try
            {
                ServiceController service = new ServiceController(serviceName);

                if ((service.Status.Equals(ServiceControllerStatus.Stopped)) || (service.Status.Equals(ServiceControllerStatus.StopPending)))
                {
                    Console.WriteLine("{0} is stopped. Starting...", serviceName);
                    service.Start();
                    Console.WriteLine("{0} is running.", serviceName);
                }
                else
                {
                    Console.WriteLine("{0} is running. Stopping...", serviceName);
                    service.Stop();
                    Console.WriteLine("{0} has stopped.", serviceName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void DNSLookup(List<string> hostnames)
        {
            if(hostnames.Count == 1)
            {
                string possibleFile = hostnames.FirstOrDefault();
                if (File.Exists(possibleFile))
                {
                    Console.WriteLine("Reading from {0}\n", possibleFile);
                    hostnames = File.ReadAllLines(possibleFile).ToList();
                }
            }

            try
            {
                foreach (string hostname in hostnames) {
                    IPHostEntry hostEntry = Dns.GetHostEntry(hostname);
                    Console.WriteLine("{0}:", hostname);
                    foreach (IPAddress ip in hostEntry.AddressList)
                    {
                        Console.WriteLine("    {0}",ip.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void DeserializeString(string input)
        {
            try
            {
                JsonTextReader reader = new JsonTextReader(new StringReader(input));
                while (reader.Read())
                {
                    if (reader.Value != null)
                        Console.WriteLine("Token: {0}, Value: {1}", reader.TokenType, reader.Value);
                    else
                        Console.WriteLine("Token: {0}", reader.TokenType);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void ConvertToBase64(string input, bool isFile)
        {
            try
            {
                Regex rx = new Regex(@"^(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                if (isFile || rx.IsMatch(input))
                {
                    Console.WriteLine("Detected input as a filename: {0}", input);
                    byte[] fileBytes = File.ReadAllBytes(input);
                    Console.WriteLine("Base64 Encoded Output: {0}", Convert.ToBase64String(fileBytes));
                }
                else
                {
                    Console.WriteLine("Detected input as a string: {0}", input);
                    byte[] stringBytes = Encoding.ASCII.GetBytes(input);
                    Console.WriteLine("Base64 Encoded Output: {0}", Convert.ToBase64String(stringBytes));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void ConvertFromBase64(string input, string outFile)
        {
            try
            {
                Regex rx = new Regex(@"^(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
                if (rx.IsMatch(input))
                {
                    Console.WriteLine("Detected input as a filename: {0}", input);
                    string fileText = File.ReadAllText(input);
                    byte[] textBytes = Convert.FromBase64String(fileText);
                    if (!string.IsNullOrEmpty(outFile))
                    {
                        File.WriteAllBytes(outFile, textBytes);
                        Console.WriteLine("Bytes written to {0}", outFile);

                    }
                    else
                    {
                        Console.WriteLine("Base64 Decoded Output: {0}", Encoding.ASCII.GetString(textBytes));
                    }

                    
                }
                else
                {
                    Console.WriteLine("Detected input as a string: {0}", input);
                    byte[] stringBytes = Convert.FromBase64String(input);
                    Console.WriteLine("Base64 Decoded Output: {0}", Encoding.ASCII.GetString(stringBytes));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void StartProcessAsUser(string userName, string password)
        {
            Process proc = new Process();
            SecureString ssPwd = new SecureString();
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.CreateNoWindow = true;
            proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            proc.StartInfo.FileName = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
            proc.StartInfo.WorkingDirectory = @"C:\Program Files (x86)\Google\Chrome\Application\";
            proc.StartInfo.LoadUserProfile = true;
            proc.StartInfo.Domain = userName.Split('\\')[0];
            proc.StartInfo.UserName = userName.Split('\\')[1];
            
            for (int x = 0; x < password.Length; x++)
            {
                ssPwd.AppendChar(password[x]);
            }

            proc.StartInfo.Password = ssPwd;
            try
            {
                proc.Start();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static void GetFileCount(string directory)
        {
            try
            {
                Console.WriteLine("File Count: {0}", Directory.GetFiles(directory, "*", SearchOption.TopDirectoryOnly).Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void FileToArray(string fileName)
        {
            try
            {
                byte[] fileBytes = File.ReadAllBytes(fileName);

                //char[] output = BitConverter.ToString(fileBytes, 0);

                string output = "0x" + BitConverter.ToString(fileBytes).Replace("-", ",0x");

                Console.WriteLine(output);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void ListDirectory(string directory, bool recursive)
        {
            try
            {
                int totalDirs = 0;
                int totalFiles = 0;

                string searchDir = string.IsNullOrEmpty(directory) ? Directory.GetCurrentDirectory() : directory;
                Console.WriteLine("\nFiles and Directories in {0}\n", searchDir);


                //TODO: Add a grep to this function
                List<string> entries = Directory.EnumerateFileSystemEntries(searchDir, "*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).ToList();

                foreach (string entry in entries)
                {
                    FileOutput file = new FileOutput(entry, searchDir);

                    if (file.Type.Equals("DIR"))
                        totalDirs += 1;
                    else
                        totalFiles += 1;

                    string fileOwner = File.GetAccessControl(entry).GetOwner(typeof(NTAccount)).ToString();

                    //This line has to be changed if you also change the maxLength in the FileOutput class
                    Console.WriteLine("{0,-60}  {1,-4}  {2,-10}  {3,10}  {4,10}  {5,-10}", file.Name,  file.Type, file.Size, file.LastWriteDate, file.LastWriteTime, fileOwner);
                }

                Console.WriteLine("\n{0} total files", totalFiles);
                Console.WriteLine("{0} total directories", totalDirs);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void WhoAmI()
        {
            Console.WriteLine("{0,-15}  {1}", "Current User:", Environment.UserName);
            Console.WriteLine("{0,-15}  {1}", "Current System:", Environment.MachineName);
            Console.WriteLine("{0,-15}  {1}", "Current Domain:", Environment.UserDomainName);
        }

        private static void CreateDirectory(string dirName, bool zwsp)
        {
            Console.WriteLine("\nCreated {0}", Directory.CreateDirectory(zwsp ? (dirName + '\u200B') : dirName).FullName);
        }

        private static void Netstat()
        {
            Console.WriteLine("Active Connections");
            Console.WriteLine();

            Console.WriteLine(" {0,-7}{1,-23}{2, -23}{3,-14}{4}", "Proto", "Local Address", "Foreign Address", "State", "PID");
            foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
            {
                Process process = Process.GetProcessById(tcpRow.ProcessId);
                if (process.ProcessName != "System")
                {
                    try
                    {
                        Console.WriteLine(" [{0}]", Path.GetFileName(process.MainModule.FileName));
                    }
                    catch(Exception ex)
                    {
                        // Catch the Access Denied exception and move on
                        Console.WriteLine(" [{0}]", "Unavailable");
                    }
                }
                else
                {
                    Console.WriteLine(" [{0}]", "System");
                }
                
                Console.WriteLine(" {0,-7}{1,-23}{2, -23}{3,-14}{4}", "TCP", tcpRow.LocalEndPoint, tcpRow.RemoteEndPoint, tcpRow.State, tcpRow.ProcessId);
            }
        }

        private static void GetPrograms()
        {
            string uninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(uninstallKey))
            {
                foreach (string skName in rk.GetSubKeyNames())
                {
                    using (RegistryKey sk = rk.OpenSubKey(skName))
                    {
                        try
                        {
                            // This length is arbitrary. I looked at what was getting returned and picked a number that looked reliable
                            if (sk.GetValueNames().Length > 3)
                            {
                                Console.WriteLine("{0} {1}", "Name:", sk.GetValue("DisplayName"));
                                Console.WriteLine("{0} {1}", "Version:", sk.GetValue("DisplayVersion"));
                                Console.WriteLine("{0} {1}\n", "Install Date:", sk.GetValue("InstallDate"));
                            }
                        }
                        catch (Exception ex){ }
                    }
                }
            }
        }

        private static void GetSSLDetails(string url)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            response.Close();

            X509Certificate cert = request.ServicePoint.Certificate;

            X509Certificate2 cert2 = new X509Certificate2(cert);


            Console.WriteLine("\n--Certificate Information--");
            Console.WriteLine("Issuer Name: {0}", cert2.GetIssuerName());
            Console.WriteLine("Expiration Date: {0}", cert2.GetExpirationDateString());
            Console.WriteLine("Public Key: {0}", cert2.GetPublicKeyString(), Environment.NewLine);

            X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.Build(cert2);

            Console.WriteLine("\n--Chain Information--");
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }

        }

        private static void GetRDUserSessions(string serverName)
        {
            IntPtr serverHandle = IntPtr.Zero;
            List<String> resultList = new List<string>();
            serverHandle = OpenServer(serverName);
            try
            {
                IntPtr SessionInfoPtr = IntPtr.Zero; IntPtr userPtr = IntPtr.Zero; IntPtr domainPtr = IntPtr.Zero; Int32 sessionCount = 0;
                Int32 retVal = WTSEnumerateSessions(serverHandle, 0, 1, ref SessionInfoPtr, ref sessionCount);
                Int32 dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                Int32 currentSession = (int)((long)SessionInfoPtr); uint bytes = 0;
                if (retVal != 0)
                {
                    for (int i = 0; i < sessionCount; i++)
                    {
                        WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)currentSession, typeof(WTS_SESSION_INFO));
                        currentSession += dataSize;
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSUserName, out userPtr, out bytes);
                        WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSDomainName, out domainPtr, out bytes);
                        Console.WriteLine("Domain and User: " + Marshal.PtrToStringAnsi(domainPtr) + "\\" + Marshal.PtrToStringAuto(userPtr));
                    }
                    WTSFreeMemory(SessionInfoPtr);
                }
                else { Console.WriteLine("No Remote Desktop sessions found"); }
            }
            catch (Exception ex) {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
            finally { CloseServer(serverHandle); }

        }

        private static void GetSessions()
        {
            List<string> foundUsers = new List<string>();
            foreach (Process proc in Process.GetProcesses())
            {
                string user = GetProcessUser(proc);
                if (!foundUsers.Contains(user) && !string.IsNullOrEmpty(user)) 
                {
                    Console.WriteLine("Found session for {0}", user);
                    foundUsers.Add(user);
                }
            }
            if (foundUsers.Count == 0)
                Console.WriteLine("No sessions found, something is wrong");
        }

        private static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                return wi.Name;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                    CloseHandle(processHandle);
            }
        }

        private static void IpConfig()
        {
            try
            {
                foreach (NetworkInterface intf in NetworkInterface.GetAllNetworkInterfaces().ToList())
                {
                    Console.WriteLine("\n{0, -20} {1}", "Interface Name:", intf.Name);
                    Console.WriteLine("{0, -20} {1}", "Interface Type:", intf.NetworkInterfaceType);

                    Console.WriteLine("{0, -20} {1}", "DNS Suffix:", intf.GetIPProperties().DnsSuffix);

                    foreach (UnicastIPAddressInformation ip in intf.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            Console.WriteLine("{0, -20} {1}", "IP Address:", ip.Address.ToString());
                        }
                    }
                }
            }
            catch (Exception ex) 
            {
                Console.WriteLine("Good job, you broke it. Heres some debugging info, good luck.");

                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static void LaunchIE()
        {
            Type loT = Type.GetTypeFromProgID("InternetExplorer.Application");
            var ie = Activator.CreateInstance(loT);
            Console.WriteLine("Donezo.");

        }

        private static void CheckPermissions(string filename)
        {
            Console.WriteLine("File To Check: {0}", filename);
            try
            {
                var controls = File.GetAccessControl(filename.Replace("\"",string.Empty));
                var rules = controls.GetAccessRules(true, true, typeof(NTAccount));
                foreach (AuthorizationRule rule in rules)
                {
                    Console.WriteLine(rule.IdentityReference);
                    FileSystemAccessRule accessRule = rule as FileSystemAccessRule;
                    if (accessRule != null)
                        Console.WriteLine("  ...{0}", accessRule.FileSystemRights);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }

        }

        private static void ReverseDNS(List<string> hostnames)
        {
            Console.WriteLine("           Hostname | IP               ");
            Console.WriteLine("=======================================");
            Console.WriteLine();
            foreach (string host in hostnames)
            {
                List<IPAddress> iPAddresses = new List<IPAddress>();
                try
                {
                    iPAddresses = Dns.GetHostAddresses(host).ToList<IPAddress>();
                }
                catch
                {
                    Console.WriteLine("Lookup failed for: {0}", host);
                }
                foreach (IPAddress ipaddress in iPAddresses)
                {
                    Console.WriteLine(host + " | " + ipaddress.ToString());
                }
            }

        }

        private static void Cat(string filename)
        {
            foreach (string line in File.ReadAllLines(filename).ToList())
            {
                Console.WriteLine(line);
            }
        }

        private static void GetEnvVars()
        {
            foreach(DictionaryEntry envVar in Environment.GetEnvironmentVariables())
            {
                Console.WriteLine("{0} = {1}", envVar.Key, envVar.Value);
            }
        }

        private static void SpoofPPID(string process, int ppid)
        {
            if (ppid == -1)
                ppid = Process.GetProcessesByName("explorer.exe").FirstOrDefault().Id;
            
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            STARTUPINFOEX si = new STARTUPINFOEX();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            si.StartupInfo.cb = Marshal.SizeOf(si);
            IntPtr lpValue = IntPtr.Zero;
            IntPtr lpSize = IntPtr.Zero;

            bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            success = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize);

            Process target = Process.GetProcessById(ppid);
            IntPtr parentHandle = Process.GetProcessById(target.Id).Handle;

            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, parentHandle);


            success = UpdateProcThreadAttribute(
                 si.lpAttributeList,
                 0,
                 (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                 lpValue,
                 (IntPtr)IntPtr.Size,
                 IntPtr.Zero,
                 IntPtr.Zero);

            bool success2 = CreateProcess(process, null,
                IntPtr.Zero, IntPtr.Zero, false,
                ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | ProcessCreationFlags.CREATE_NO_WINDOW,
                IntPtr.Zero, null, ref si, out pi);


            if (si.lpAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(si.lpAttributeList);
                Marshal.FreeHGlobal(si.lpAttributeList);
            }
            Marshal.FreeHGlobal(lpValue);

        }

        private static void ProcessSearch(string searchProc)
        {
            Console.WriteLine("{0,5}  {1,-10}  {2,-12}  {3,-20}  {4,-0}", "PID","Session ID","Process Name", "Process Owner", "Location");
            
            foreach(Process proc in Process.GetProcessesByName(searchProc))
            {
                Console.WriteLine("{0,5}  {1,-10}  {2,-12}  {3,-20}  {4,-0}", proc.Id, proc.SessionId, proc.ProcessName, GetProcessOwner(proc.Id), proc.MainModule.FileName);
            }

        }

        private static void Bin2Hex(string file)
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(file);
                string hex = "0x" + BitConverter.ToString(bytes).Replace("-", ",0x");
                Console.WriteLine(hex);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.InnerException);
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static string GetProcessOwner(int processId)
        {
            //TODO: See if possible to switch out the * to reduce query return size
            string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection processList = searcher.Get();

            foreach (ManagementObject obj in processList)
            {
                string[] argList = new string[] { string.Empty, string.Empty };
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                    return argList[1] + "\\" + argList[0];
            }

            return "NO OWNER";
        }

        private static void BinMatch(string topDir, string folderMatch, string binary)
        {
            foreach (string subDir in Directory.GetDirectories(topDir, "*"+folderMatch+"*", SearchOption.TopDirectoryOnly))
                Console.WriteLine(Directory.GetFiles(subDir, binary).FirstOrDefault());
        }

        private static void GetProtectedProcesses()
        {
            //foreach(Process proc in Process.GetProcesses().Where(a => a.))

        }

        private static void GetMountedDrives()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                Console.WriteLine(drive.Name);
                Console.WriteLine(drive.DriveFormat);
                Console.WriteLine(drive.VolumeLabel);
            }
        }
    }
}
