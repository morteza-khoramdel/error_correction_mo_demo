public class Checksum {
    public static short calculateChecksum(byte[] strb)
    {
        // Note: For UDP checksums all checksum is zero depending on itself
        // and for Header IP checksums only checksum is calculated from
        // the header for zero checksum.
        long tempSum = 0;
        short temp = 0;
        short currectVal = 0;
        short finvers = 0;
        long extera = 0;

        for(int i = 0 ; i < strb.length; i += 2){
            temp = (short) (strb[i] << 8) ;
            if(i+1 < strb.length) {
                currectVal = (short) (strb[i + 1] & 0xff);
                temp = (short) (temp | currectVal);
            }else {
                temp = (short) (temp | 0x0000);
            }
            tempSum += temp;
            extera = tempSum & 0x0000;
            if(extera != 0){
                extera = extera >> 16;
                tempSum += extera;
            }
        }
        finvers = (short) (tempSum ^ 0xffff);
        return finvers;

    }


    public static boolean checkChecksum(byte[] strb)
    {
        // Note: For UDP checksums all checksum is zero depending on itself
        // and for Header IP checksums only checksum is calculated from
        // the header for zero checksum.
        long tempSum = 0;
        short temp = 0;
        short currectVal = 0;
        long extera = 0;

        for(int i = 0 ; i < strb.length; i += 2){
            temp = (short) (strb[i] << 8) ;
            if(i+1 < strb.length) {
                currectVal = (short) (strb[i + 1] & 0xff);
                temp = (short) (temp | currectVal);

            }else {
                temp = (short) (temp | 0x0000);
            }
            tempSum += temp;
            extera = tempSum & 0x0000;
            if(extera != 0){
                extera = extera >> 16;
                tempSum += extera;
            }
        }
        if(tempSum == -1){
            return true;
        }else {
            return false;
        }
    }
}
