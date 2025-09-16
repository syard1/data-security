public class ASH512 {
    
    public String hashString(String input) {
        String preprocessedValue = MessagePreprocessor.preprocessMessage(input);
        int blockSize = 1024;
        int numBlocks = preprocessedValue.length() / blockSize;
        String chainingValue = "0".repeat(1024);

        for (int i = 0; i < numBlocks; i++) {
            String block = preprocessedValue.substring(i * blockSize, (i + 1) * blockSize);
            String processedBlock = processBlock(block);
            chainingValue = BinaryUtils.xor16(chainingValue, processedBlock);
        }

        return BinaryUtils.binaryToHex(chainingValue);
    }
    
    private String processBlock(String block) {
        String modified = CryptoOperations.modificationFunction(block);
        String expansion = ExpansionFunctions.expansionFunction();
        String xored = BinaryUtils.xor16(modified, expansion);
        String secondExpanded = ExpansionFunctions.expansionFunction2(xored);
        String[] splitValue = CryptoOperations.splitOperation(secondExpanded);
        String areaValues = CryptoOperations.areaCalculation(splitValue);
        String finalResult = CryptoOperations.secondModification(areaValues);
        return finalResult;
    }
}