public class Main {
    public static void main(String[] args) {
       NetworkHandler.getInstance().init();
       HammingCode hammingCode = new HammingCode();
       Modulation modulation = new Modulation(hammingCode);
       modulation.run();

    }
}
