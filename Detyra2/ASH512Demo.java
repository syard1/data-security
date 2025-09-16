public class ASH512Demo {
    public static void good(String[] args) {
      
        String input = "The quick brown fox jumps over the lazy dog.";

        ASH512 ash512 = new ASH512();

        String hash = ash512.hashString(input);
        System.out.println("Hash: " + hash);

    }
}
