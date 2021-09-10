using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Analisador de pacotes de rede.");
            BeginListen();
            while (true) ;
        }

        static Socket FactorySocket(IPAddress ip)
        {
            var socket = new Socket(
                AddressFamily.InterNetwork,
                SocketType.Raw,
                ProtocolType.IP);
            
            socket.Bind(new IPEndPoint(ip, 0));
            
            socket.SetSocketOption(
                SocketOptionLevel.IP,
                SocketOptionName.HeaderIncluded,
                true);

            var optionIn = new byte[] {1, 0, 0, 0};
            var optionOut = new byte[] {1, 0, 0, 0};

            socket.IOControl(
                IOControlCode.ReceiveAll,
                optionIn,
                optionOut);

            return socket;
        }

        static void BeginListen(IAsyncResult result = null)
        {
            Tuple<Socket, byte[]> state;
            
            Socket socket;
            byte[] buffer;

            if (result == null)
            {
                socket = FactorySocket(SelectIPv4Address());
                buffer = new byte[4096];
                state = new Tuple<Socket, byte[]>(socket, buffer);
            }
            else
            {
                state = (Tuple<Socket, byte[]>) result.AsyncState;
                socket = state.Item1;
                buffer = state.Item2;

                var bufferLength = socket.EndReceive(result);
                var iPv4Packet = new IPv4Packet(buffer, bufferLength);

                //Condição para capturar a senha de autenticação com o IRC
                //if (iPv4Packet.TCPPacket != null && iPv4Packet.TCPPacket.DestinationPort == 6667 && iPv4Packet.TCPPacket.DataAsText.Contains("PASS"))
                //{
                    Console.WriteLine("## [ {0:yyyy-MM-dd HH:mm:ss.fff} ] ##".PadLeft(80, '#'), DateTime.Now);
                    Console.WriteLine(iPv4Packet);
                //}
            }

            socket.BeginReceive(
                buffer,
                0,
                buffer.Length,
                SocketFlags.None,
                BeginListen, state);
        }

        static IPAddress[] GetIPv4Addresses()
        {
            var hostname = Dns.GetHostName();
            var hostnameEntry = Dns.GetHostEntry(hostname);
            var regexIPv4 = new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
            return hostnameEntry
                .AddressList
                .Where(ip => regexIPv4.IsMatch(ip.ToString()))
                .ToArray();
        }

        static IPAddress SelectIPv4Address()
        {
            var ips = GetIPv4Addresses();
            do
            {
                Console.WriteLine("Selecione a interface de rede: ");
                for (var i = 0; i < ips.Length; i++) Console.WriteLine("{0}) {1}", i + 1, ips[i]);

                try
                {
                    var selected = Console.ReadLine();
                    var selectedIndex = int.Parse(selected) - 1;
                    var ip = ips[selectedIndex];
                    Console.WriteLine("Interface {0}", ip);
                    return ip;
                }
                catch
                {
                    Console.WriteLine("Interface inválida.");
                }
            } while (true);
        }
    }

    enum ProtocolList
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17
    }

    class IPv4Packet
    {
        private int dataLength;
        public IPv4Packet(byte[] data, int length)
        {
            dataLength = length;
            
            var stream = new BinaryReader(new MemoryStream(data));

            int readed;

            readed = stream.ReadByte();
            Version = (byte) (readed >> 4);
            InternetHeaderLength = (byte) ((byte) (readed << 4) >> 4);
            
            readed = stream.ReadByte();
            DifferentiatedServicesCodePoint =  (byte) (readed >> 2);
            ExplicitCongestionNotification = (byte) ((byte) (readed << 6) >> 6);
            
            TotalLength = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            Identification = (ushort)IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            readed = IPAddress.NetworkToHostOrder(stream.ReadInt16());
            Flags = (byte) (readed >> 13);
            FragmentOffset = (ushort) ((ushort) (readed << 3) >> 3);

            TimeToLive = stream.ReadByte();
            
            Protocol = stream.ReadByte();

            HeaderChecksum = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());

            SourceIPAddress = (uint) stream.ReadInt32();
            
            DestinationIPAddress = (uint) stream.ReadInt32();

            var internetHeaderLengthInBytes = InternetHeaderLength * 32 / 8;
            Data = new byte[TotalLength - internetHeaderLengthInBytes];
            Array.Copy(data, internetHeaderLengthInBytes, Data, 0, Data.Length);
            
            if ((ProtocolList) Protocol == ProtocolList.TCP) TCPPacket = new TCPPacket(Data, Data.Length);
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
        
        public TCPPacket TCPPacket { get; private set; }

        public override string ToString()
        {
            var result = new StringBuilder();
            const int padding = 50;
            result.AppendLine("IPv4 Header (" + dataLength + " bytes)");
            result.AppendLine("Version: ".PadLeft(padding) + Version.AsBinary(4));
            result.AppendLine("InternetHeaderLength: ".PadLeft(padding) + InternetHeaderLength.AsBinary(4));
            result.AppendLine("DifferentiatedServicesCodePoint: ".PadLeft(padding) + DifferentiatedServicesCodePoint.AsBinary(6));
            result.AppendLine("ExplicitCongestionNotification: ".PadLeft(padding) + ExplicitCongestionNotification.AsBinary(2));
            result.AppendLine("TotalLength: ".PadLeft(padding) + TotalLength.AsBinary(16));
            result.AppendLine("Identification: ".PadLeft(padding) + Identification.AsBinary(16));
            result.AppendLine("Flags: ".PadLeft(padding) + Flags.AsBinary(3));
            result.AppendLine("FragmentOffset: ".PadLeft(padding) + FragmentOffset.AsBinary(13));
            result.AppendLine("TimeToLive: ".PadLeft(padding) + TimeToLive.AsBinary(8));
            result.AppendLine("Protocol: ".PadLeft(padding) + Protocol.AsBinary(8).PadRight(padding) + Protocol.AsProtocol());
            result.AppendLine("HeaderChecksum: ".PadLeft(padding) + HeaderChecksum.AsBinary(16));
            result.AppendLine("SourceIPAddress: ".PadLeft(padding) + SourceIPAddress.AsBinary(32).PadRight(padding) + SourceIPAddress.AsIPv4());
            result.AppendLine("DestinationIPAddress: ".PadLeft(padding) + DestinationIPAddress.AsBinary(32).PadRight(padding) + DestinationIPAddress.AsIPv4());
            if (TCPPacket != null) result.Append(TCPPacket.ToString());
            return result.ToString();
        }
    }

    static class Extensions 
    {
        public static string AsBinary(this byte value, int binaryLength)
        {
            return Convert.ToString(value, 2).PadLeft(binaryLength, '0').PadLeft(32) + " = " + value;
        }

        public static string AsBinary(this ushort value, int binaryLength)
        {
            return Convert.ToString(value, 2).PadLeft(binaryLength, '0').PadLeft(32) + " = " + value;
        }

        public static string AsBinary(this uint value, int binaryLength)
        {
            return Convert.ToString(value, 2).PadLeft(binaryLength, '0').PadLeft(32) + " = " + value;
        }

        public static string AsIPv4(this uint value)
        {
            return string.Join(".", new IPAddress(value)
                .ToString()
                .Split('.')
                .Select(block => block.PadLeft(3, '0')).ToArray());
        }

        public static string AsProtocol(this byte value)
        {
            var protocol = ((ProtocolList) value).ToString();
            return protocol.Length > 1 ? protocol : "Unknown";
        }
    }

    class TCPPacket
    {
        private int dataLength;
        public TCPPacket(byte[] data, int length)
        {
            dataLength = length;
            
            var stream = new BinaryReader(new MemoryStream(data));

            int readed;

            SourcePort = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            DestinationPort = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            SequenceNumber = (uint) IPAddress.NetworkToHostOrder(stream.ReadInt32());
            
            AcknowledgmentNumber = (uint) IPAddress.NetworkToHostOrder(stream.ReadInt32());
            
            readed = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            DataOffset = (byte) (readed >> 12);
            Reserved = (byte) ((byte) (readed << 4) >> (4 + 9));
            Flags = (byte) ((byte) (readed << 7) >> 7);
            
            WindowSize = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            Checksum = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            UrgentPointer = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            var dataOffsetInBytes = DataOffset * 32 / 8;
            Data = new byte[length - dataOffsetInBytes];
            Array.Copy(data, dataOffsetInBytes, Data, 0, Data.Length);
            DataAsText = Encoding.UTF8.GetString(Data);
        }
        
        public ushort SourcePort { get; private set; }
        public ushort DestinationPort { get; private set; }
        public uint SequenceNumber { get; private set; }
        public uint AcknowledgmentNumber { get; private set; }
        public byte DataOffset { get; private set; }
        public byte Reserved { get; private set; }
        public ushort Flags { get; private set; }
        public ushort WindowSize { get; private set; }
        public ushort Checksum { get; private set; }
        public ushort UrgentPointer { get; private set; }

        public byte[] Data { get; private set; }
        public string DataAsText { get; private set; }

        public override string ToString()
        {
            var result = new StringBuilder();
            const int padding = 50;
            result.AppendLine("TCP Header (" + dataLength + " bytes)");
            result.AppendLine("SourcePort: ".PadLeft(padding) + SourcePort.AsBinary(16));
            result.AppendLine("DestinationPort: ".PadLeft(padding) + DestinationPort.AsBinary(16));
            result.AppendLine("SequenceNumber: ".PadLeft(padding) + SequenceNumber.AsBinary(32));
            result.AppendLine("AcknowledgmentNumber: ".PadLeft(padding) + AcknowledgmentNumber.AsBinary(32));
            result.AppendLine("DataOffset: ".PadLeft(padding) + DataOffset.AsBinary(4));
            result.AppendLine("Reserved: ".PadLeft(padding) + Reserved.AsBinary(3));
            result.AppendLine("Flags: ".PadLeft(padding) + Flags.AsBinary(9));
            result.AppendLine("WindowSize: ".PadLeft(padding) + WindowSize.AsBinary(16));
            result.AppendLine("Checksum: ".PadLeft(padding) + Checksum.AsBinary(16));
            result.AppendLine("UrgentPointer: ".PadLeft(padding) + UrgentPointer.AsBinary(16));
            result.AppendLine(DataAsText);
            return result.ToString();
        }
    }
}