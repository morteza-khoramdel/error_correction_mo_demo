public class Main {
    public static void main(String[] args) {
        try {
            NetworkHandler.getInstance().init();
            HammingCode hammingCode = new HammingCode();
            Modulation modulation = new Modulation(hammingCode);
            modulation.start();
            DeModulation deModulation = new DeModulation(hammingCode);
            deModulation.start();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
