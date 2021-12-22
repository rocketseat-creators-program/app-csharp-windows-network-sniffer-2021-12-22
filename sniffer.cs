using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetworkSniffer
{
    class App
    {
        static void Main(string[] args)
        {
            try
            {
                Run(args);
            }
            catch (Exception exception)
            {
                Console.WriteLine("Fatal: " + exception.Message);
            }
        }

        static void Run(string[] args) {
            Console.WriteLine("Analisador de Pacote de Rede");
            Console.WriteLine("^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            var ipAddress = SelectIPAddress();
            Console.WriteLine("IP: " + ipAddress);

            var socket = CreateSocket(ipAddress);

            do
            {
                var buffer = new byte[ushort.MaxValue];
                var bufferLength = socket.Receive(buffer);

                Console.WriteLine("## [ {0:yyyy-MM-dd HH:mm:ss.fff} ] ##".PadLeft(80, '#'), DateTime.Now);

                var protocolIPv4 = new ProtocolIPv4(buffer, bufferLength);
                Console.WriteLine(protocolIPv4);
            } while (Console.KeyAvailable == false ||
                     Console.ReadKey().Key != ConsoleKey.Escape);
        }

        static Socket CreateSocket(IPAddress ipAddress)
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                throw new NotImplementedException("SocketType.Raw not works on Linux.");
            }

            var socket = new Socket(
                ipAddress.AddressFamily,
                SocketType.Raw,
                ProtocolType.IP);

            var ipEndPoint = new IPEndPoint(ipAddress, 0);
            socket.Bind(ipEndPoint);

            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                throw new NotImplementedException("SocketOptionName.HeaderIncluded works only for IPv4.");
            }

            socket.SetSocketOption(
                SocketOptionLevel.IP,
                SocketOptionName.HeaderIncluded, // `HeaderIncluded` works only for IPv4.
                true);

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotImplementedException("IOControlCode.ReceiveAll works only on Windows.");
            }

            var optionIn = new byte[] { 1, 0, 0, 0 };
            var optionOut = new byte[4];
            socket.IOControl(
                IOControlCode.ReceiveAll, // `ReceiveAll` works only on Windows.
                optionIn,
                optionOut);

            return socket;
        }

        static IPAddress SelectIPAddress()
        {
            var hostname = Dns.GetHostName();
            Console.WriteLine("Computador: " + hostname);

            var hostnameEntry = Dns.GetHostEntry(hostname);
            var ipAddresses = hostnameEntry.AddressList;

            Console.WriteLine("Endereços IP:");
            for (var i = 0; i < ipAddresses.Length; i++)
            {
                var ipAddress = ipAddresses[i];
                Console.WriteLine("  " + (i + 1) + ") " + ipAddress);
            }

            int selectedIndex;
            do
            {
                Console.Write("Selecione: ");
            } while (int.TryParse(Console.ReadLine(), out selectedIndex) == false ||
                     selectedIndex < 1 ||
                     selectedIndex > ipAddresses.Length);

            return ipAddresses[selectedIndex - 1];
        }
    }

    class ProtocolIPv4
    {
        private int length;
        public ProtocolIPv4(byte[] data, int length) {
            this.length = length;

            var stream = new BinaryReader(new MemoryStream(data));
            
            // Comprimentos dos campos: https://en.wikipedia.org/wiki/IPv4

            int readed;

            readed = stream.ReadByte();
            Version = (byte) (readed >> 4);
            InternetHeaderLength = (byte) ((byte) (readed << 4) >> 4);

            readed = stream.ReadByte();
            DifferentiatedServicesCodePoint =  (byte) (readed >> 2);
            ExplicitCongestionNotification = (byte) ((byte) (readed << 6) >> 6);

            TotalLength = stream.ReadUInt16();
            if (BitConverter.IsLittleEndian)
            {
                // Exemplo didático. Prefira usar `IPAddress.NetworkToHostOrder()` como nas próximas leituras.
                TotalLength = (ushort)((TotalLength >> 8) + (TotalLength << 8));
            }

            Identification = (ushort)IPAddress.NetworkToHostOrder((short)stream.ReadUInt16());

            readed = IPAddress.NetworkToHostOrder((short)stream.ReadUInt16());
            Flags = (byte) (readed >> 13);
            FragmentOffset = (ushort) ((ushort) (readed << 3) >> 3);

            TimeToLive = stream.ReadByte();

            Protocol = (IPProtocolType)stream.ReadByte();

            HeaderChecksum = (ushort) IPAddress.NetworkToHostOrder((short)stream.ReadUInt16());

            SourceIPAddress = (uint) stream.ReadInt32();

            DestinationIPAddress = (uint) stream.ReadInt32();

            var internetHeaderLengthInBytes = InternetHeaderLength * 32 / 8;
            Data = new byte[TotalLength - internetHeaderLengthInBytes];
            Array.Copy(data, internetHeaderLengthInBytes, Data, 0, Data.Length);
        }

        public byte Version { get; private set; }
        public byte InternetHeaderLength { get; private set; }
        public byte DifferentiatedServicesCodePoint { get; private set; }
        public byte ExplicitCongestionNotification { get; private set; }
        public ushort TotalLength { get; private set; }
        public ushort Identification { get; private set; }
        public byte Flags { get; private set; }
        public ushort FragmentOffset { get; private set; }
        public byte TimeToLive { get; private set; }
        public IPProtocolType Protocol { get; private set; }
        public ushort HeaderChecksum { get; private set; }
        public uint SourceIPAddress { get; private set; }
        public uint DestinationIPAddress { get; private set; }
        public byte[] Data { get; private set; }

        public override string ToString()
        {
            var result = new StringBuilder();
            result.AppendLine("IPv4, " + length + " bytes");
            result.AppendLine(Format.Binary("Version", Version, 4));
            result.AppendLine(Format.Binary("InternetHeaderLength", InternetHeaderLength, 4));
            result.AppendLine(Format.Binary("DifferentiatedServicesCodePoint", DifferentiatedServicesCodePoint, 6));
            result.AppendLine(Format.Binary("ExplicitCongestionNotification", ExplicitCongestionNotification, 2));
            result.AppendLine(Format.Binary("TotalLength", TotalLength, 16));
            result.AppendLine(Format.Binary("Identification", Identification, 16));
            result.AppendLine(Format.Binary("Flags", Flags, 3));
            result.AppendLine(Format.Binary("FragmentOffset", FragmentOffset, 13));
            result.AppendLine(Format.Binary("TimeToLive", TimeToLive, 8));
            result.AppendLine(Format.Binary("Protocol", (byte)Protocol, 8) + ", " + Protocol);
            result.AppendLine(Format.Binary("HeaderChecksum", HeaderChecksum, 16));
            result.AppendLine(Format.IPv4("SourceIPAddress", SourceIPAddress));
            result.AppendLine(Format.IPv4("DestinationIPAddress", DestinationIPAddress));
            result.AppendLine(Encoding.Default.GetString(Data));
            return result.ToString();
        }
    }

    static class Format
    {
        public static string Binary(string field, uint value, int binaryLength)
        {
            var padding = 50;
            var binary = Convert.ToString(value, 2).PadLeft(binaryLength, '0').PadLeft(32);
            return (field + ": ").PadLeft(padding) + binary + " = " + value;
        }

        public static string IPv4(string field, uint value)
        {
            var padding = 96;
            var ip = string.Join(".", new IPAddress(value)
                .ToString()
                .Split('.')
                .Select(block => block.PadLeft(3, ' ')).ToArray());
            return Binary(field, value, 32).PadRight(padding) + ip;
        }
    }

    enum IPProtocolType: byte
    {
        HOPOPT = 0,
        ICMP = 1,
        IGMP = 2,
        GGP = 3,
        IP_in_IP = 4,
        ST = 5,
        TCP = 6,
        CBT = 7,
        EGP = 8,
        IGP = 9,
        BBN_RCC_MON = 10,
        NVP_II = 11,
        PUP = 12,
        ARGUS = 13,
        EMCON = 14,
        XNET = 15,
        CHAOS = 16,
        UDP = 17,
        MUX = 18,
        DCN_MEAS = 19,
        HMP = 20,
        PRM = 21,
        XNS_IDP = 22,
        TRUNK_1 = 23,
        TRUNK_2 = 24,
        LEAF_1 = 25,
        LEAF_2 = 26,
        RDP = 27,
        IRTP = 28,
        ISO_TP4 = 29,
        NETBLT = 30,
        MFE_NSP = 31,
        MERIT_INP = 32,
        DCCP = 33,
        _3PC = 34,
        IDPR = 35,
        XTP = 36,
        DDP = 37,
        IDPR_CMTP = 38,
        TP_Plus_Plus = 39,
        IL = 40,
        IPv6 = 41,
        SDRP = 42,
        IPv6_Route = 43,
        IPv6_Frag = 44,
        IDRP = 45,
        RSVP = 46,
        GRE = 47,
        DSR = 48,
        BNA = 49,
        ESP = 50,
        AH = 51,
        I_NLSP = 52,
        SwIPe = 53,
        NARP = 54,
        MOBILE = 55,
        TLSP = 56,
        SKIP = 57,
        IPv6_ICMP = 58,
        IPv6_NoNxt = 59,
        IPv6_Opts = 60,
        Any_Host_Internal_Protocol = 61,
        CFTP = 62,
        Any_Local_Network = 63,
        SAT_EXPAK = 64,
        KRYPTOLAN = 65,
        RVD = 66,
        IPPC = 67,
        Any_Dstributed_File_System = 68,
        SAT_MON = 69,
        VISA = 70,
        IPCU = 71,
        CPNX = 72,
        CPHB = 73,
        WSN = 74,
        PVP = 75,
        BR_SAT_MON = 76,
        SUN_ND = 77,
        WB_MON = 78,
        WB_EXPAK = 79,
        ISO_IP = 80,
        VMTP = 81,
        SECURE_VMTP = 82,
        VINES = 83,
        TTP = 84,
        IPTM = 84,
        NSFNET_IGP = 85,
        DGP = 86,
        TCF = 87,
        EIGRP = 88,
        OSPF = 89,
        Sprite_RPC = 90,
        LARP = 91,
        MTP = 92,
        AX_25 = 93,
        OS = 94,
        MICP = 95,
        SCC_SP = 96,
        ETHERIP = 97,
        ENCAP = 98,
        Any_Private_Scheme = 99,
        GMTP = 100,
        IFMP = 101,
        PNNI = 102,
        PIM = 103,
        ARIS = 104,
        SCPS = 105,
        QNX = 106,
        Active_Networks = 107,
        IPComp = 108,
        SNP = 109,
        Compaq_Peer = 110,
        IPX_in_IP = 111,
        VRRP = 112,
        PGM = 113,
        Any_0_Hop_Protocol = 114,
        L2TP = 115,
        DDX = 116,
        IATP = 117,
        STP = 118,
        SRP = 119,
        UTI = 120,
        SMP = 121,
        SM = 122,
        PTP = 123,
        IS_IS_over_IPv4 = 124,
        FIRE = 125,
        CRTP = 126,
        CRUDP = 127,
        SSCOPMCE = 128,
        IPLT = 129,
        SPS = 130,
        PIPE = 131,
        SCTP = 132,
        FC = 133,
        RSVP_E2E_IGNORE = 134,
        Mobility_Header = 135,
        UDPLite = 136,
        MPLS_in_IP = 137,
        manet = 138,
        HIP = 139,
        Shim6 = 140,
        WESP = 141,
        ROHC = 142,
        Ethernet = 143
    }
}