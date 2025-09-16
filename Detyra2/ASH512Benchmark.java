import java.nio.charset.StandardCharsets;

public class ASH512Benchmark {
    
    public static void main(String[] args) {
        ASH512 ash512 = new ASH512();
        
        String baseString = "Advanced security protocols rely heavily on robust cryptographic mechanisms. "
                          + "Modern hash algorithms must resist collision attacks and maintain computational efficiency. "
                          + "Performance analysis of custom hash functions reveals their practical implementation characteristics.";
        
        baseString = baseString.replaceAll(" ", "");
        
        System.out.println("ASH-512 Performance Benchmark");
        System.out.println("===============================================");
        System.out.printf("%-15s %-15s %s%n", "Size (KB)", "Time (ms)", "Hash (complete)");
        System.out.println("===============================================");
        
        int[] multipliers = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1000};
        
        for (int multiplier : multipliers) {
            String testString = generateTestString(baseString, multiplier);
            
            byte[] utf8Bytes = testString.getBytes(StandardCharsets.UTF_8);
            double sizeKB = utf8Bytes.length / 1024.0;
            
            long startTime = System.nanoTime();
            String hash = ash512.hashString(testString);
            long endTime = System.nanoTime();
            
            double timeMs = (endTime - startTime) / 1_000_000.0;
            
            System.out.printf("%-15.2f %-15.2f %s%n", sizeKB, timeMs, hash);
        }
        
        System.out.println("===============================================");
    }
    
    private static String generateTestString(String base, int multiplier) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < multiplier; i++) {
            sb.append(base);
        }
        return sb.toString();
    }
}
