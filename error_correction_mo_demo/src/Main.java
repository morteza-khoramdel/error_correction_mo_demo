import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            String crcString;
            while (true) {
                System.out.println("PLease Enter Productive polynomials in Range (9 , 17 , 25 , 33)");
                Scanner scanner = new Scanner(System.in);
                crcString = scanner.nextLine();
                if (crcString.length() % 9 == 0 || crcString.length() % 17 == 0 || crcString.length() % 25 == 0 || crcString.length() % 33 == 0) {
                    break;
                } else {
                    System.out.println("Try Again");
                }
            }
            NetworkHandler.getInstance().init();
            HammingCode hammingCode = new HammingCode();
            Modulation modulation = new Modulation(hammingCode, crcString);
            modulation.start();
            DeModulation deModulation = new DeModulation(hammingCode, crcString);
            deModulation.start();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
