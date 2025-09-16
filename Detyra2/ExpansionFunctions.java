public class ExpansionFunctions {
    
    private static final String[] IV = {
        "6a09e667f3bcc908",
        "bb67ae8584caa73b",
        "3c6ef372fe94f82b",
        "a54ff53a5f1d36f1",
        "510e527fade682d1",
        "9b05688c2b3e6c1f",
        "1f83d9abfb41bd6b",
        "5be0cd19137e2179"
    };
    
    private static final int[] E1 = {
        63, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        47, 48, 49, 50, 51, 52, 53, 55, 55, 56,
        55, 56, 57, 58, 59, 60, 61, 62, 63, 0
    };
    
    private static final int[] E2 = {
        62, 63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
        46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1
    };
    
    public static String expansionFunction() {
        String expansionBuffer = "";
    
        for (int index = 0; index < IV.length; index++) {
            expansionBuffer += BinaryUtils.hexToBinary(IV[index]);
        }
        
        return expansionBuffer + expansionBuffer;
    }
    
    public static String expansionFunction2(String input) {
        String result = "";
        for (int i = 0; i < 16; i++) {
            result += desExpansion(input.substring(i * 64, (i + 1) * 64));
        }
        return result;
    }
    
    public static String desExpansion(String input) {
        String firstExpansion = "";
        for (int index : E1) {
            firstExpansion += input.charAt(index);
        }
        String secondExpansion = "";
        for (int index : E2) {
            secondExpansion += firstExpansion.charAt(index);
        }
        
        return secondExpansion;
    }
}