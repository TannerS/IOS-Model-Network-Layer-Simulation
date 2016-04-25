
package ios.l3;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Ipv4Client 
{
    static short IPV4_PACKET_SIZE = 20;
    static short EXP_NUMBER_OF_PACKETS = 12;
   
    public static void main(String[] args) 
    {
        Socket socket;
        InputStream in;
        OutputStream out;
        InputStreamReader rin;
        BufferedReader brin;
        int size = 0;
        byte temp[];
        Random rand;
        
        try 
        {
            socket = new Socket("codebank.xyz", 38003);
            in = socket.getInputStream();
            out = socket.getOutputStream();
            rin = new InputStreamReader(in, "UTF-8");
            brin = new BufferedReader(rin);
            rand = new Random();
            // loop for number of packets needed to be sent
            for(int i = 0; i < EXP_NUMBER_OF_PACKETS; i++)
            {
                size = (int) (Math.pow(2, i + 1) + IPV4_PACKET_SIZE);
                System.out.println("Packet Data Size As: " + (int) Math.pow(2, i + 1)); 
                temp = generatePartialPacket(size);
                // fill remaining bits with random data
                //*********************************************
                // since this project does not care about data
                // we don;t really need this part since java 
                // will init an array as all 0's so that data would be fine
                for(int j = 0; j < size - IPV4_PACKET_SIZE; j++)
                {
                    // get random hex number between 0x0-0xff
                    // put it into packet data part
                    temp[IPV4_PACKET_SIZE + j] =  (byte) (rand.nextInt(0x1+ 0xFF)); 
                }
                // send out packet to server
                out.write(temp);
                // check  server reply
                System.out.println(brin.readLine()); 
            }
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(Ipv4Client.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static byte[] generatePartialPacket(int size)
    {
        // create packet
        byte packet[] = new byte[size]; 
        // 4 for ipv4 and 5 for the IHL = 0x45
        packet[0] = 0x45; 
        // TOS
        packet[1] = 0x0;
        // 3rd, foruth bytes (data as zeros);    
        // must put the bytes in order
        packet[2] = (byte) (size >> 0x8);
        packet[3] = (byte) size;
        // 4th and 5th byte as the Identificaiton
        packet[4] = 0x0;
        packet[5] = 0x0;
        // A three-bit field follows and is used to control or identify fragments. They are (in order, from high order to low order):
        // http://www.erg.abdn.ac.uk/users/gorry/course/inet-pages/ip-packet.html
        // 010 means dont fragment btut since it is 1 byte it would be 01000000 = 64
        // the next field is is fragment offset which is 13 bits
        // so 3 for first part, 13 for second part in total of 16 (2 bytes)
        // since 1 byte is covers the 3 butsfrom first part and 5 bits from next part
        // we only need antoher byte to cover the last byte
        packet[6] = 0x40;
        packet[7] = 0x0;
        // ttl = 50
        packet[8] = 0x32;
        // protocol
        packet[9] = 0x6;
        // chcksum
        // packet[10] & packet[11] saved for end
        // to be able to get full size then include it
        // source ip(used 10.10.10.10)
        packet[12] = 0xA;
        packet[13] = 0xA;
        packet[14] = 0xA;
        packet[15] = 0xA;
        // destrination ip
        // https://codebank.xyz/
        // ping => 52.11.122.49
        packet[16] = 0x34;
        packet[17] = 0xB;
        packet[18] = 0x7A;
        packet[19] = 0x31;
        // got entire size of packet exlcuding checksum 
        // so calcualte checksum and add it
        short check_sum = (short) checkSum(packet);
        // need to shfit to insert packets into correct order
        // right byte
        packet[10]= (byte) shiftByte2Right(check_sum, 0x8);
        // left byte
        packet[11] = (byte) (check_sum);
        return packet;
    }
    
    static int xorBytes(int first, int second)
    {
        return ((first & 0xFF) ^ (second & 0xFF00));
    }

    static int shiftByte2Left(int original_byte, final int shift_size)
    {
        return ((original_byte & 0xFF) << shift_size);
    }
    
    static int shiftByte2Right(int original_byte, final int shift_size)
    {
        return (original_byte >> shift_size);
    }
    
    public static short checkSum(byte[] b)
    {
        int sum = 0;
        int counter = 0;
        int temp = 0;
        
        while(counter != b.length)
        {
           if(((counter + 1) % 2 == 0) && (counter != 0))
           {
               // shift first byte by 4
               temp = shiftByte2Left(b[counter - 1], 8);
               // xor with previous byte to combine
               temp = xorBytes(b[counter], temp);
               sum += temp;
               // if a carry happened meaning, FFFF0000 is & with sum
               // all the 16 bits on the left side of sum is zeroed out since
               // & 0000 will give u zero, as for the FFFF side, same concept, 
               // if any bit after the 16 bits , means it is too big for that vairable
               // since we are simulating a short (16bits) if any bit where theFFFF is anded means
               // its greater then a short, so we check this by anding it by FFFF so that means if any
               // bit is  in that range, the value after the and is some number that is NOT zero,
               // so if it == 0, no overflow, any other number is a overflow
               if((sum & 0xFFFF0000) != 0)
               {
                   sum &= 0xFFFF;
                   sum++;
               }
           }
           // increase counter
           counter++;
        }
        
        // if aray is odd           
        // if bytes is odd size, we have to deal with last byte
        // since the byets are in form of byte1byte2, but we only have one byte
        // it wont be 0000byte1 it will be byte10000 (we shift over the last byte by 8
        
        if((b.length % 2) != 0)
        {
            // shift first byte by 8
            temp = shiftByte2Left( b[b.length - 1], 8);
            // add to sum
            sum += temp;
            // check and handleoverflow
            if((sum & 0xFFFF0000) != 0)
               {
                   sum &= 0xFFFF;
                   sum++;
               }
        }
        // return checksum
        return (short)(~(sum & 0xFFFF));
    }
}
