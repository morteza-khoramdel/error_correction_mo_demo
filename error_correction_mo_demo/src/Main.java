public class Main {
    public static void main(String[] args) {
       NetworkHandler.getInstance().init();
       byte[] bytes = NetworkHandler.getInstance().receiveFrame();
        System.out.println(bytes);

    }
}
