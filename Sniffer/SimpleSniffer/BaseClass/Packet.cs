using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace SimpleSniffer.BaseClass
{
    
    
    public class Packet
    {
        private const int LineCount = 30; 

        enum ProtocolType
        {
            GGP = 3,
            ICMP = 1,
            IDP = 22,
            IGMP = 2,
            IP = 4,
            ND = 77,
            PUP = 12,
            TCP = 6,
            UDP = 17,
            OTHERS = -1
        }

        private byte[] raw_Packet;
        private DateTime dateTime;
        private ProtocolType protocolType;
        private IPAddress src_IPAddress;
        private IPAddress des_IPAddress;
        private int src_Port;
        private int des_Port;
        private int totalLength;
        private int headLength;
        public int HeadLength
        {
            get
            {
                return headLength;
            }
        }

        public Packet(byte[] raw)
        {
            if (raw == null)
                throw new ArgumentNullException();

            if (raw.Length < 20)
                throw new ArgumentException();
            raw_Packet = raw;
            dateTime = DateTime.Now;
                                    
            headLength = (raw[0] & 0x0F) * 4;
            if ((raw[0] & 0x0F) < 5)
                throw new ArgumentException(); 

            if ((raw[2] * 256 + raw[3]) != raw.Length)
                throw new ArgumentException(); 

            if (Enum.IsDefined(typeof(ProtocolType), (int)raw[9]))
                protocolType = (ProtocolType)raw[9];
            else
                protocolType = ProtocolType.OTHERS;

            src_IPAddress = new IPAddress(BitConverter.ToUInt32(raw, 12));
            des_IPAddress = new IPAddress(BitConverter.ToUInt32(raw, 16));
            totalLength = raw[2] * 256 + raw[3];

            if (protocolType == ProtocolType.TCP || protocolType == ProtocolType.UDP)
            {
                src_Port = raw[headLength] * 256 + raw[headLength + 1];
                des_Port = raw[headLength + 2] * 256 + raw[headLength + 3];
                if (protocolType == ProtocolType.TCP)
                {
                    headLength += 20;
                }
                else if (protocolType == ProtocolType.UDP)
                {
                    headLength += 8;
                }
            }
            else
            {
                src_Port = -1;
                des_Port = -1;
            }
            
        }

        public string Src_IP
        {
            get
            {
                return src_IPAddress.ToString();
            }
        }

        public string Src_PORT
        {
            get
            {
                if (src_Port != -1)
                    return src_Port.ToString();
                else
                    return "";
            }
        }

        public string Des_IP
        {
            get
            {
                return des_IPAddress.ToString();
            }
        }

        public string Des_PORT
        {
            get
            {
                if (des_Port != -1)
                    return des_Port.ToString();
                else
                    return "";
            }
        }

        public string Type
        {
            get
            {
                return protocolType.ToString();
            }
        }

        public int TotalLength
        {
            get
            {
                return totalLength;
            }
        }

        public string Time
        {
            get
            {
                return dateTime.ToLongTimeString();
            }
        }

        public string getHexString()
        {
            StringBuilder sb = new StringBuilder(raw_Packet.Length);
            for (int i = headLength; i < TotalLength; i += LineCount)
            {
                for (int j = i; j < TotalLength && j < i + LineCount; j++)
                {
                    sb.Append(raw_Packet[j].ToString("X2") + " ");
                }
                sb.Append("\n");
            }
                return sb.ToString();
        }

        public string getCharString()
        {

            StringBuilder sb = new StringBuilder();
            
            for(int i = this.HeadLength; i < TotalLength; i += LineCount)
            {
                for (int j = i; j < TotalLength && j < i + LineCount; j++)
                {
                    if (raw_Packet[j] > 31 && raw_Packet[j] < 128)
                        sb.Append((char)raw_Packet[j]);
                    else
                        sb.Append(".");
                }
                sb.Append("\n");
            }
            return sb.ToString();
        }
    }
}
