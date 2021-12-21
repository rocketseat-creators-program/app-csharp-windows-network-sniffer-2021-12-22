using System;
using System.Net;

namespace NetworkSniffer
{
    class App
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Analisador de Pacote de Rede");
            Console.WriteLine("^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            var ipAddress = SelectIPAddress();
            Console.WriteLine("IP: " + ipAddress);
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