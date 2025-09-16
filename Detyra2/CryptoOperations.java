public class CryptoOperations {
    
    public static String triangleArea(String input) {
        int x1 = Integer.parseInt(input.substring(0, 8), 2);
        int y1 = Integer.parseInt(input.substring(8, 16), 2);
        int x2 = Integer.parseInt(input.substring(16, 24), 2);
        int y2 = Integer.parseInt(input.substring(24, 32), 2);
        int x3 = Integer.parseInt(input.substring(32, 40), 2);
        int y3 = Integer.parseInt(input.substring(40, 48), 2);
        
        double a = Math.sqrt(Math.pow(x2 - x1, 2) + Math.pow(y2 - y1, 2));
        double b = Math.sqrt(Math.pow(x3 - x2, 2) + Math.pow(y3 - y2, 2));
        double c = Math.sqrt(Math.pow(x1 - x3, 2) + Math.pow(y1 - y3, 2));
        
        double s = (a + b + c) / 2;
        double area = Math.sqrt(s * (s - a) * (s - b) * (s - c));
        
        return String.format("%16s", Integer.toBinaryString((int)area)).replace(' ', '0');
    }
    
    public static String areaCalculation(String[] input) {
        String result = "";
        for (String in : input) {
            result += triangleArea(in);
        }
        return result;
    }
    
    public static String modificationFunction(String input) {
        char[] temp8 = {'0', '0', '0', '0', '0', '0', '0', '0'};
        for (int i = 0; i < 128; i++) {
            String substr = input.substring(i * 8, (i + 1) * 8);
            for (int j = 0; j < 8; j++) {
                if (substr.charAt(j) != temp8[j]) {
                    temp8[j] = '1';
                } else {
                    temp8[j] = '0';
                }
            }
        }
        
        char[] result1Reversed = new char[8];
        for (int i = 0; i < 8; i++) {
            result1Reversed[i] = temp8[7 - i];
        }
        temp8 = result1Reversed;
        
        String result2 = "";
        for (int i = 0; i < 128; i++) {
            String substr = input.substring(i * 8, (i + 1) * 8);
            for (int j = 0; j < 8; j++) {
                if (substr.charAt(j) != temp8[j]) {
                    result2 += '1';
                } else {
                    result2 += '0';
                }
            }
            
            int temp8IntVal = Integer.parseInt(new String(temp8), 2);
            temp8IntVal++;
            if (temp8IntVal == 256 || temp8IntVal == 1) {
                temp8IntVal = 0;
            }
            String binaryString = String.format("%8s", Integer.toBinaryString(temp8IntVal)).replace(' ', '0');
            temp8 = binaryString.toCharArray();
        }
        
        return result2;
    }
    
    public static String secondModification(String input) {
        String result = "";

        for (int i = 0; i < 32; i++) {
            char[] temp4 = {'0', '0', '0', '0'};
            String substr = input.substring(i * 16, (i + 1) * 16);
            String subResult = "";
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    if (substr.charAt(j * 4 + k) != temp4[k]) {
                        temp4[k] = '1';
                    } else {
                        temp4[k] = '0';
                    }
                }
            }
            
            for (int j = 0; j < 4; j++) {
                String localSubResult = "";
                for (int k = 0; k < 4; k++) {
                    if (substr.charAt(j * 4 + k) != temp4[k]) {
                        localSubResult += '1';
                    } else {
                        localSubResult += '0';
                    }
                }
                subResult = localSubResult + subResult;
            }
            result += subResult;
        }
        return result;
    }
    
    public static String[] splitOperation(String input) {
        String[] result = new String[32];
        for (int i = 0; i < 32; i++) {
            result[i] = input.substring(i * 48, (i + 1) * 48);
        }
        return result;
    }
}