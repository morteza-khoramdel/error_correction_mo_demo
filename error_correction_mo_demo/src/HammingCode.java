public class HammingCode {
    // print elements of array
    static void print(int ar[])
    {
        for (int i = 1; i < ar.length; i++) {
            System.out.print(ar[i]);
        }
        System.out.println();
    }

    public HammingCode() {
    }

    // calculating value of redundant bits
    // r is number of redundant bits
    // ar is new array with hamming bits
    static int[] calculation(int[] ar, int r)
    {

        for (int i = 0; i < r; i++) {
            // x is 2^i every moment
            int x = (int)Math.pow(2, i);
            // for 1 to final
            for (int j = 1; j < ar.length; j++) {
                if (((j >> i) & 1) == 1) {
                    if (x != j)
                        ar[x] = ar[x] ^ ar[j];
                }
            }
            System.out.println("r" + x + " = " + ar[x]);
        }

        return ar;
    }

    static int[] generateCode(String str, int M, int r)
    {
        int[] ar = new int[r + M + 1];
        int j = 0;
        for (int i = 1; i < ar.length; i++) {
            if ((Math.ceil(Math.log(i) / Math.log(2))
                    - Math.floor(Math.log(i) / Math.log(2)))
                    == 0) {

                // if i == 2^n for n in (0, 1, 2, .....)
                // then ar[i]=0
                // codeword[i] = 0 ----
                // redundant bits are initialized
                // with value 0
                ar[i] = 0;
            }
            else {
                // codeword[i] = dataword[j]
                ar[i] = (int)(str.charAt(j) - '0');
                j++;
            }
        }
        return ar;
    }

    static int[] degenerateCode(String str, int M, int r)
    {
        int[] ar = new int[M + 1];
        int j = 1;
        String s = "0";
        str = s.concat(str);
        int error = 0;
        int counter = 0;

        int parities[] = new int[r];
//detect fault
        for (int i = 0; i < r; i++) {
            int position = (int)Math.pow(2,i);
            for (int k = position; k < str.length(); k += 2 * position) {
                for(int y = k ; y < k + position ; y++){
                    if(y < str.length()) {
                        parities[i] = parities[i] ^ Character.getNumericValue(str.charAt(y));
                    }
                }
            }
        }

        for (int i = 0 ; i < r ; i++){
            if(parities[i] == 0){
                counter++;
            }else {
                break;
            }
        }
        if(counter == r){
            // we are good
            error = 0;
        }else{
            // :)
            int epos = 0;
            for(int i = r-1 ; i > -1 ; i--){
                epos = epos + (parities[i] * (int)Math.pow(2,i));
            }
            error = epos;
        }

        if(error != 0){
            if (str.charAt(error) == '0'){
                str = str.substring(0, error) + '1' + str.substring(error + 1);
            }else {
                str = str.substring(0, error) + '0' + str.substring(error + 1);
            }
        }
        System.out.println(str);
        for (int i = 1; i < str.length(); i++) {
            if (!((Math.ceil(Math.log(i) / Math.log(2))
                    - Math.floor(Math.log(i) / Math.log(2)))
                    == 0)) {
                ar[j] = (int)(str.charAt(i) - '0');
                j++;
            }
        }

        return ar;
    }


    static byte[] converter(int[] a)
    {
        byte[] out = new byte[(a.length/8)+1];
        int temp[] = new int[8];
        Integer result;
        int i = 0;
        int len;
        if((a.length - 1) % 8 == 0){
            len = a.length - 1;
        }else{
            len = (8 - ((a.length - 1) % 8))+ (a.length - 1);
        }
        for(int j = 1 ; j < len + 1 ; j++){
            switch(j%8) {
                case 1:
                    if(j <= a.length - 1){
                        temp[7] = a[j]<<7;
                    }
                    break;
                case 2:
                    if(j <= a.length - 1) {
                        temp[6] = a[j] << 6;
                    }else {
                        temp[6] = 0;
                    }
                    break;
                case 3:
                    if(j <= a.length - 1) {
                        temp[5] = a[j] << 5;
                    }else {
                        temp[5] = 0;
                    }
                    break;
                case 4:
                    if(j <= a.length - 1) {
                        temp[4] = a[j] << 4;
                    }else {
                        temp[4] = 0;
                    }
                    break;
                case 5:
                    if(j <= a.length - 1) {
                        temp[3] = a[j] << 3;
                    }else {
                        temp[3] = 0;
                    }
                    break;
                case 6:
                    if(j <= a.length - 1) {
                        temp[2] = a[j] << 2;
                    }else {
                        temp[2] = 0;
                    }
                    break;
                case 7:
                    if(j <= a.length - 1) {
                        temp[1] = a[j] << 1;
                    }else {
                        temp[1] = 0;
                    }
                    break;
                case 0:
                    if(j <= a.length - 1) {
                        temp[0] = a[j];
                    }else {
                        temp[0] = 0;
                    }
                    result = temp[0]|temp[1]|temp[2]|temp[3]|temp[4]|temp[5]|temp[6]|temp[7];
                    out[i] = result.byteValue();
                    i++;
                    temp[0] = 0;temp[1] = 0;temp[2] = 0;temp[3] = 0;temp[4] = 0;temp[5] = 0;temp[6] = 0;temp[7] = 0;
                    break;
                default:
                    // code block
            }
        }
        return out;
    }





    // Driver code
    public byte[] modulatorDriver(byte[] strb)
    {


        // input message
        String str = "";


        for(int i = 0 ; i < strb.length ; i++) {
            str = str.concat(String.format("%8s", Integer.toBinaryString(strb[i] & 0xFF)).replace(' ', '0'));
//            System.out.println(str); // 10000001
        }

        int M = str.length();
        int r = 1;

        while (Math.pow(2, r) < (M + r + 1)) {
            // r is number of redundant bits
            r++;
        }
        int[] ar = generateCode(str, M, r);

        System.out.println("Generated hamming code ");
        ar = calculation(ar, r);

        byte[] aBytes = new byte[(ar.length/8)+1];
        aBytes = converter(ar);

        print(ar);

        return aBytes;
    }

    public byte[] demodulatorDriver(byte[] strb)
    {


        // input message
        String str = "";


        for(int i = 0 ; i < strb.length ; i++) {
            str = str.concat(String.format("%8s", Integer.toBinaryString(strb[i] & 0xFF)).replace(' ', '0'));
            System.out.println(str); // 10000001
        }


        int r = (int) (Math.ceil(Math.log(str.length()) / Math.log(2)));
        int M = str.length() - r;

        int[] ar = degenerateCode(str, M, r);
        System.out.println("Degenerated hamming code ");

        byte[] aBytes = new byte[(ar.length/8)+1];
        aBytes = converter(ar);

        print(ar);

        return aBytes;
    }

}
