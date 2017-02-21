using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using PcapDotNet.Packets;
using PcapDotNet.Core;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Http;

namespace trafficSniff
{
    class Program
    {
        static void Main(string[] args)
        {
            IList<LivePacketDevice> all = getDevices();
            printDevices(all);

            int deviceIndex = 0;

            do
            {
                Console.WriteLine("Enter the interface number (1-" + all.Count + "):");
                string deviceIndexString = Console.ReadLine();

                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > all.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            PacketDevice selectedDevice = all[deviceIndex - 1];

            using (PacketCommunicator comm = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000)) 
            {
                Console.WriteLine("Listening on "+selectedDevice.Description+"...");
                comm.ReceivePackets(0, Handler);
            }
        }

        private static void Handler(Packet p)
        {
            try
            {
                if (p.Ethernet.Ip.Tcp.DestinationPort == 443 || p.Ethernet.Ip.Tcp.DestinationPort == 80)
                {
                    Console.WriteLine(p.Ethernet.IpV4.Destination);
                    WebRequest req = WebRequest.Create("http://192.168.75.1:3000/sniffing_ip");
                    req.Method = "POST";
                    req.ContentType = "application/x-www-form-urlencoded";
                    string data = "ip=" + p.Ethernet.IpV4.Destination.ToString();
                    byte[] byteArray = Encoding.UTF8.GetBytes (data);
                    req.ContentLength = byteArray.Length;
                    Stream dataStream = req.GetRequestStream();
                    dataStream.Write(byteArray, 0, byteArray.Length);
                    dataStream.Close();
                    WebResponse res = req.GetResponse();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static IList<LivePacketDevice> getDevices() 
        {
            IList<LivePacketDevice> all = LivePacketDevice.AllLocalMachine;
            if (all.Count == 0) 
            {
                Console.WriteLine("No devices were found...");
            }

            return all;
        }

        private static void printDevices(IList<LivePacketDevice>  all) 
        {
            for (int i = 0; i != all.Count; ++i)
            {
                LivePacketDevice device = all[i];
                Console.Write((i + 1) + ". " + device.Name + "\n");
                Console.WriteLine(device.Description);
            }
        }
    }
}
