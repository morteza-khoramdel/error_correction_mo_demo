public class CRC
{

    private String xorOper(String temp, String g)
    {
        int j;
        int k;
        int i;
        for (i = 0;i < temp.length();i++)
        {
            j = 0;
            k = i;
            //check whether it is divisible or not
            if ((temp.charAt(k)=='1'&&g.charAt(k)=='0')||(temp.charAt(k)=='1'&&g.charAt(k)=='1'))
            {
                for (j = 0,k = i;j < g.length();j++,k++)
                {
                    if ((temp.charAt(k) == '1' && g.charAt(j) == '1') || (temp.charAt(k) == '0' && g.charAt(j) == '0'))
                        temp = temp.substring(0,k) + '0' + temp.substring(k+1);
                    else
                        temp = temp.substring(0,k) + '1' + temp.substring(k+1);
                }
            }
        }
        return temp;
    }
    public String crcDriver(byte[] f, String g) {
        String str = "";

        for (int i = 0; i < f.length; i++) {
            str = str.concat(String.format("%8s", Integer.toBinaryString(f[i] & 0xFF)).replace(' ', '0'));
//            System.out.println(str);
        }
        int fs = str.length();

        //Append 0's
        int rs = g.length() - 1;
        String tempZeros = "";
        for (int i = f.length; i < f.length + rs; i++)
            tempZeros = tempZeros.concat("0");
        str.concat(tempZeros);

        //xor operation on two bool arrays
        String strNew = xorOper(str, g);

        //remainder
        String rem = strNew.substring(str.length(), rs);
        return rem;

    }


    public String deCrcDriver(byte[] f, String g)
    {
        String str = "";

        for(int i = 0 ; i < f.length ; i++) {
            str = str.concat(String.format("%8s", Integer.toBinaryString(f[i] & 0xFF)).replace(' ', '0'));
        }

        int rs = g.length() - 1;

        //Append 0's

        String tempZeros = "";
        for (int i = f.length ;i < f.length + rs;i++)
            tempZeros = tempZeros.concat("0");
        str.concat(tempZeros);

        //xor operation on two bool arrays
        String strNew = xorOper(str, g);

        //remainder
        String rem = strNew.substring(str.length(), rs) ;

        int flag = 0;
        for (int i = 0; i<rs ;i++)
        {
            if (rem.charAt(i) != '0')
            {
                flag = 1;
                break;
            }
        }
        if (flag == 0)
            System.out.print("\n Since Remainder Is 0 Hence Message Transmitted From Sender To Receiver Is Correct");
        else
            System.out.print("\n Since Remainder Is Not 0 Hence Message Transmitted From Sender To Receiver Contains Error");
        return rem;
    }
}