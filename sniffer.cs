using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Sniffer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Analisador de pacotes de rede.");
            BeginListen();
            while (true) ;
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
                Console.WriteLine("## [{0:yyyy-MM-dd HH:mm:ss.fff}] ##".PadRight(80, '#'), DateTime.Now);
                Console.WriteLine(iPv4Packet);
            }

            socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, BeginListen, state);
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

        static IPAddress[] GetIPv4Address()
        {
            var hostname = Dns.GetHostName();
            var regexIPv4 = new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
            return Dns
                .GetHostEntry(hostname)
                .AddressList
                .Where(ip => regexIPv4.IsMatch(ip.ToString()))
                .ToArray();
        }

        static IPAddress SelectIPv4Address()
        {
            var ips = GetIPv4Address();
            do
            {
                Console.WriteLine("Selecione a interface de rede:");
                for (var i = 0; i < ips.Length; i++) Console.WriteLine("{0}) {1}", i + 1, ips[i]);

                try
                {
                    var selected = Console.ReadLine();
                    var selectedIndex = int.Parse(selected) - 1;
                    var ip = ips[selectedIndex];
                    Console.WriteLine("Interface selecionada: {0}", ip);
                    return ip;
                }
                catch
                {
                    Console.WriteLine("Opção inválida.");
                }
            } while (true);
        }
    }

    class IPv4Packet
    {
        public IPv4Packet(byte[] data, int length)
        {
            dataLength = length;
            
            var stream = new BinaryReader(new MemoryStream(data));

            int readed;

            readed = stream.ReadByte();

            var internetHeaderLength = (byte) ((byte) (readed << 4) >> 4);
            
            stream.ReadByte();
            
            var totalLength = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            
            stream.ReadInt16();
            stream.ReadInt16();
            stream.ReadByte();

            protocol = stream.ReadByte();
            
            stream.ReadInt16();
            
            sourceIp = (uint) stream.ReadInt32();
            destinationIp = (uint) stream.ReadInt32();

            var internetHeaderLengthInBytes = internetHeaderLength * 32 / 8;
            Data = new byte[totalLength - internetHeaderLengthInBytes];
            Array.Copy(data, internetHeaderLengthInBytes, Data, 0, Data.Length);

            if (protocol == 6)
            {
                TCPPacket = new TCPPacket(Data, Data.Length);
            }
        }

        private int dataLength;
        public byte[] Data;
        public byte protocol;
        public uint sourceIp;
        public uint destinationIp;
        public TCPPacket TCPPacket;

        public override string ToString()
        {
            var result = new StringBuilder();
            result.AppendLine("IP Header - bytes length: " + dataLength);
            result.AppendLine("protocol: " + protocol);
            result.AppendLine("sourceIp: " + new IPAddress(sourceIp));
            result.AppendLine("destinationIp: " + new IPAddress(destinationIp));
            if (TCPPacket == null)
            {
                result.AppendLine("NO TCP");
            }
            else
            {
                result.AppendLine(TCPPacket.ToString());
            }
            return result.ToString();
        }
    }
    

    class TCPPacket
    {
        public TCPPacket(byte[] data, int length)
        {
            dataLength = length;
            
            var stream = new BinaryReader(new MemoryStream(data));

            int readed;

            sourcePort = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            destinationPort = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());

            stream.ReadInt32();
            stream.ReadInt32();
            
            readed = (ushort) IPAddress.NetworkToHostOrder(stream.ReadInt16());
            var dataOffset = (byte) readed >> 12;
            
            stream.ReadInt16();
            stream.ReadInt32();
                
            var dataOffsetInBytes = dataOffset * 32 / 8;
            Data = new byte[length - dataOffsetInBytes];
            Array.Copy(data, dataOffsetInBytes, Data, 0, Data.Length);
            DataAsText = Encoding.UTF8.GetString(Data);
        }

        private int dataLength;
        public byte[] Data;
        public string DataAsText;
        public uint sourcePort;
        public uint destinationPort;

        public override string ToString()
        {
            var result = new StringBuilder();
            result.AppendLine("TCP Header - bytes length: " + dataLength);
            result.AppendLine("sourcePort: " + sourcePort);
            result.AppendLine("destinationPort: " + destinationPort);
            result.AppendLine("DataAsText: " + DataAsText);
            return result.ToString();
        }
    }
}