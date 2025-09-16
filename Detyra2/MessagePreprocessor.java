public class MessagePreprocessor {
    
    public static String appendPaddingBits(String message) {
        int numBitsToAppend = 896 - (message.length() % 1024);
        String output = message + "1";
        for (int i = 1; i < numBitsToAppend; i++) {
            output += "0";
        }
        return output;
    }
    
    public static String appendLength(String input, int originalLength) {
        int val = originalLength;

        String bin = "";
        while (val > 0) {
            if (val % 2 == 1) {
                bin = '1' + bin;
            } else
                bin = '0' + bin;
            val /= 2;
        }
        
        while (bin.length() < 128) {
            bin = "0" + bin;
        }
        
        return input + bin;
    }
    
    public static String preprocessMessage(String input) {
        String binaryValue = BinaryUtils.strToBinary(input);
        String paddedValue = appendPaddingBits(binaryValue);
        return appendLength(paddedValue, binaryValue.length());
    }
}