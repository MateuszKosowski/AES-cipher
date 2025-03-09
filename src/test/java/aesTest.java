import org.junit.jupiter.api.BeforeEach;
import org.zespol6.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;


public class aesTest {

    AES aes;

    @BeforeEach
    public void setUp() {
        aes = new AES();
    }

    @Test
    public void testGenerateKey() {
        aes.generateKey();
        BigInteger key = aes.getMainKey();
        System.out.println("\n Generated first key: " + key.toString(16));
    }

    @Test
    public void testReadFile() {
        aes.readFile("src/main/resources/testFile.txt");
        System.out.println("\n Read data from file:");
        for (byte b : aes.getData()) {
            System.out.print(b + " ");
        }
    }

    @Test
    public void testSplitIntoBlocks() {
        aes.readFile("src/main/resources/testFile.txt");
        byte [] data = aes.getData();
        byte[][] blocks = aes.splitIntoBlocks(data);
        System.out.println("\n Split data into blocks:");
        for (byte[] block : blocks) {
            for (byte b : block) {
                System.out.print(b + " ");
            }
            System.out.println();
        }
    }

}
