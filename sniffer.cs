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

            Protocol = stream.ReadByte();

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
        public byte Protocol { get; private set; }
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
            result.AppendLine(Format.Binary("Protocol", Protocol, 8));
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
}