using System;
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
                Console.WriteLine("Bytes: " + bufferLength);
                Console.WriteLine(Encoding.Default.GetString(buffer));
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
                SocketOptionName.HeaderIncluded,
                true);

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotImplementedException("IOControlCode.ReceiveAll works only on Windows.");
            }

            var optionIn = new byte[] { 1, 0, 0, 0 };
            var optionOut = new byte[4];
            socket.IOControl(
                IOControlCode.ReceiveAll,
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
}