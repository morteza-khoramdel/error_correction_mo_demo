public class Checksum {
    public static short calculateChecksum(byte[] strb)
    {
        // compute over UDP Header and Payload, except the last bytes which
        // don't
        // fall on an int boundary
        long tempSum = 0;
        short finalSum = 0;
        short finvers = 0;
        int temp = 0;

        long extera = 0;

        for(int i = 0 ; i < strb.length; i += 2){
            temp = (int)strb[i] << 8 ;
            if(i+1 < strb.length) {
                temp = temp | strb[i + 1];
            }else {
                temp = temp | 0x0000;
            }
            tempSum += temp;
            extera = tempSum & 0x0000;
            if(extera != 0){
                extera = extera >> 16;
                tempSum += extera;
            }
        }
        finalSum = (short) tempSum;
        finvers = (short) (finalSum ^ 0xffff);
        return finvers;

    }
}
