using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EtlToCap
{
    public static class NetworkRoutines
    {

        static void Main(string[] args)
        {
            if (args.Length ==0)
            {
                Console.WriteLine("Usage: EtlCap <source ETL file> <destination pcap file> [<Are packets 802.11? y / (n)>]");
                return;
            }
            Console.WriteLine($"Converting File {args[0]} to {args[1]}");
            UInt32 networkType = 1; // LINKTYPE_ETHERNET
            if (args.Length > 2 && args[2].IndexOf("n", StringComparison.OrdinalIgnoreCase) < 0)
            {
                Console.WriteLine($"Using network type == 802.11");
                networkType = 105; // LINKTYPE_IEEE802_11
            }
            long result = ConvertEtlToPcap(args[0], args[1], 65536, networkType);
            Console.WriteLine($"{result} packets converted.");
        }

        public static long ConvertEtlToPcap(string source, string destination, UInt32 maxPacketSize, UInt32 networkType = 1)
        {
            int result = 0;
            var networkTrace = new Guid("{00000001-0000-0000-0000-000000000000}");
            var ndisProviderId = new Guid("{2ed6006e-4729-4609-b423-3ee7bcd678ef}");
            using (BinaryWriter writer = new BinaryWriter(File.Open(destination, FileMode.Create)))
            {

                UInt32 magic_number = 0xa1b2c3d4;
                UInt16 version_major = 2;
                UInt16 version_minor = 4;
                Int32 thiszone = 0;
                UInt32 sigfigs = 0;
                UInt32 snaplen = maxPacketSize;
                UInt32 network = networkType;

                writer.Write(magic_number);
                writer.Write(version_major);
                writer.Write(version_minor);
                writer.Write(thiszone);
                writer.Write(sigfigs);
                writer.Write(snaplen);
                writer.Write(network);

                using (var reader = new EventLogReader(source, PathType.FilePath))
                {
                    EventRecord record;
                    while ((record = reader.ReadEvent()) != null)
                    {
                        using (record)
                        {
                            if (record.ActivityId == networkTrace ||
                                record.ProviderId == ndisProviderId)
                            {
                                result++;
                                DateTime timeCreated = (DateTime)record.TimeCreated;
                                UInt32 ts_sec = (UInt32)((timeCreated.Subtract(new DateTime(1970, 1, 1))).TotalSeconds);
                                UInt32 ts_usec = (UInt32)(((timeCreated.Subtract(new DateTime(1970, 1, 1))).TotalMilliseconds) - ((UInt32)((timeCreated.Subtract(new DateTime(1970, 1, 1))).TotalSeconds * 1000))) * 1000;
                                UInt32 incl_len = (UInt32)record.Properties[2].Value;
                                if (incl_len > maxPacketSize)
                                {
                                   Console.WriteLine($"Packet size of {incl_len} exceeded max packet size {maxPacketSize}, packet ignored");
                                }
                                UInt32 orig_len = incl_len;

                                writer.Write(ts_sec);
                                writer.Write(ts_usec);
                                writer.Write(incl_len);
                                writer.Write(orig_len);
                                writer.Write((byte[])record.Properties[3].Value);

                            }
                        }
                    }
                }
                return result;

            }

        }
    }
}
 
       
    

