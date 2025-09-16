public class BinaryUtils {
    
    public static String strToBinary(String s) {
        int n = s.length();
        String result = "";
        for (int i = 0; i < n; i++) {
            int val = Integer.valueOf(s.charAt(i));

            String bin = "";
            while (val > 0) {
                if (val % 2 == 1) {
                    bin += '1';
                } else
                    bin += '0';
                val /= 2;
            }
            while (bin.length() < 8) {
                bin += "0";
            }
            result = result += bin;
        }
        return result;
    }

    public static String hexToBinary(String input) {
        String result = "";
        for (char digit : input.toLowerCase().toCharArray()) {
            if (digit == 'a') {
                result += "1010";
            } else if (digit == 'b') {
                result += "1011";
            } else if (digit == 'c') {
                result += "1100";
            } else if (digit == 'd') {
                result += "1101";
            } else if (digit == 'e') {
                result += "1110";
            } else if (digit == 'f') {
                result += "1111";
            } else {
                int val = Integer.parseInt(String.valueOf(digit));
                String newDigit = "";
                while (val > 0) {
                    newDigit = (val % 2) + newDigit;
                    val /= 2;
                }
                while (newDigit.length() < 4) {
                    newDigit = "0" + newDigit;
                }
                result += newDigit;
            }
        }
        return result;
    }

    public static String binaryToHex(String input) {
        StringBuilder result = new StringBuilder();
        for (int k = 0; k < input.length(); k += 4) {
            int val = 0;
            for (int j = 0; j < 4; j++) {
                val += (input.charAt(k + j) - '0') * Math.pow(2, 3 - j);
            }
            if (val >= 10) {
                result.append((char) ('a' + val - 10));
            } else {
                result.append(val);
            }
        }
        return result.toString();
    }

    public static String xor16(String txt, String expansionVector) {
        String result = "";
        for (int i = 0; i < expansionVector.length(); i++) {
            if (txt.charAt(i) != expansionVector.charAt(i)) {
                result += '1';
            } else {
                result += '0';
            }
        }
        return result;
    }
    
    public static String intToBinary(int value, int bitWidth) {
        String bin = "";
        int val = value;
        while (val > 0) {
            if (val % 2 == 1) {
                bin = '1' + bin;
            } else {
                bin = '0' + bin;
            }
            val /= 2;
        }
        
        while (bin.length() < bitWidth) {
            bin = "0" + bin;
        }
        
        return bin;
    }
}