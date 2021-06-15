public class Main {
    public static void main(String[] args) {
       NetworkHandler.getInstance().init();
       HammingCode hammingCode = new HammingCode();
       NetworkHandler.getInstance().receiveFrame(hammingCode);
    }
}
