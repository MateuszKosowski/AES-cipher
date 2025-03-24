package org.zespol6;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AES {

    private final int amountOfRounds = 10;
    private final int blockSize = 16;
    private final int keySize = 16;
    private byte[] data;
    private BigInteger mainKey;
    private byte[] expandedKey;

    // Każdy bajt danych jest zastępowany innym bajtem zgodnie z tabelą SBOX. Konstrukcja tabeli gwarantuje nieliniowość zastępowania.
    private final int[][] SBOX = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    // Odwrotny SBOX
    private final int[][] reverseSBOX = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    // Stała RCON - wartości używane w kluczach rundy
    private final int[] RCON = {
            0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36
    };

    // Stała MCOL - macierz mnożenia w mixColumns
    private final int[] MCOL = {
            2, 3, 1, 1,
            1, 2, 3, 1,
            1, 1, 2, 3,
            3, 1, 1, 2
    };

    private final int[] MCOL_INV = {
            14, 11, 13, 9,
            9, 14, 11, 13,
            13, 9, 14, 11,
            11, 13, 9, 14
    };

    // readFile
    public void readFile(String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName)) {
            // Odczytanie wszystkich bajtów z pliku
            data = fis.readAllBytes();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // getData
    public byte[] getData() {
        return (data != null) ? data : new byte[0];
    }

    // bytesToString
    public String bytesToString(byte[] data) {
        try {
            return new String(data, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return new String(data); // Użycie domyślnego kodowania jako ostateczność
        }
    }

    // generateMainKey
    public void generateMainKey() {
        byte[] keyBytes = new byte[keySize]; // 128 bitów = 16 bajtów
        new SecureRandom().nextBytes(keyBytes);
        mainKey = new BigInteger(1, keyBytes); // Ustawienie znaku na dodatni
    }

    // getMainKey
    public BigInteger getMainKey() {
        return mainKey;
    }

    // getExpandedKey
    public byte[] getExpandedKey() {
        return expandedKey;
    }

    // toByteKey
    public byte[] toByteKey(BigInteger key) {
        byte[] keyBytes = key.toByteArray();
        byte[] fixedKey = new byte[blockSize];

        if (keyBytes.length > blockSize) {
            // Jeśli klucz jest za długi, bierzemy ostatnie 16 bajtów
            System.arraycopy(keyBytes, keyBytes.length - blockSize, fixedKey, 0, blockSize);
        } else {
            // Jeśli klucz jest za krótki, wypełniamy zerami od początku
            System.arraycopy(keyBytes, 0, fixedKey, blockSize - keyBytes.length, keyBytes.length);
        }
        return fixedKey;
    }

    // keyExpansion
    public void keyExpansion(BigInteger mainKey) {
        byte[] fixedMainKey = toByteKey(mainKey);

        // Buffor na wszystkie podklucze + klucz główny
        byte[] expandedKey = new byte[keySize * (amountOfRounds + 1)];

        // Kopiowanie klucza głównego na początek
        System.arraycopy(fixedMainKey, 0, expandedKey, 0, keySize);

        int currentPos = keySize;

        // Generowanie kolejnych podkluczy
        for (int i = 1; i <= amountOfRounds; i++) {

            byte [] temp = new byte[4];
            System.arraycopy(expandedKey, currentPos - 4, temp, 0, 4);

            // Utworzenie 4 kolejnych bajtów klucza

                // RotWord - przesunięcie w lewo o 1 bajt w buforze temp
                byte tempByte = temp[0];
                for (int j = 0; j < 3; j++) {
                    temp[j] = temp[j + 1];
                }
                temp[3] = tempByte;

                // SubWord - zastąpienie każdego bajtu w buforze temp zgodnie z tabelą SBOX
                subBytes(temp, 4);

                // XORowanie pierwszego bajtu słowa z RCON
                temp[0] ^=  getRconValue(i);

                // XORowanie z poprzednim podkluczem
                for(int j = 0; j < 4; j++) {
                    temp[j] ^= expandedKey[currentPos - keySize + j];
                }

            System.arraycopy(temp, 0, expandedKey, currentPos, 4);
            currentPos += 4;

            // Utworzenie kolejnych 12 bajtów klucza
            for(int j = 0; j < 3; j++) {

                // nie wiem czy to jest potrzebne
                System.arraycopy(expandedKey, currentPos - 4, temp, 0, 4);

                for(int k = 0; k < 4; k++) {
                    temp[k] ^= expandedKey[currentPos - keySize + k];
                }

                System.arraycopy(temp, 0, expandedKey, currentPos, 4);
                currentPos += 4;
            }
        }

        this.expandedKey = expandedKey;
    }

    // encrypt
    public byte[] encrypt(byte[] data, BigInteger key) {
        byte[][] blocks = splitIntoBlocks(data);
        keyExpansion(key);

        for (byte[] block : blocks) {

            // Runda inicjalizacyjna
            addRoundKey(block, 0);

            // Rundy 1-9

            for (int round = 1; round < amountOfRounds; round++) {
                subBytes(block, blockSize);
                shiftRows(block, true);
                mixColumns(block, true);
                addRoundKey(block, round);
            }

            // Ostatnia runda (bez mixColumns)
            subBytes(block, blockSize);
            shiftRows(block, true);
            addRoundKey(block, amountOfRounds);
        }

        // Łączymy bloki z powrotem w jeden ciąg bajtów
        byte[] encrypted = new byte[blocks.length * blockSize];
        for (int i = 0; i < blocks.length; i++) {
            System.arraycopy(blocks[i], 0, encrypted, i * blockSize, blockSize);
        }

        return encrypted;
    }

    // decrypt
    public byte[] decrypt(byte[] encrypted, BigInteger key) {
        byte[][] blocks = splitIntoBlocks(encrypted);
        keyExpansion(key);

        for (byte[] block : blocks) {

            // Runda inicializacyjna odszyfrowanie
            addRoundKey(block, amountOfRounds);

            // Rundy 1-9 odszyfrowanie
            for(int round = amountOfRounds - 1; round > 0; round--) {
                shiftRows(block, false);
                reverseSubBytes(block, blockSize);
                addRoundKey(block, round);
                mixColumns(block, false);
            }

            // Ostatnia runda odszyfrowanie
            shiftRows(block, false);
            reverseSubBytes(block, blockSize);
            addRoundKey(block, 0);

        }

        // Łączymy bloki z powrotem w jeden ciąg bajtów
        byte[] decrypted = new byte[blocks.length * blockSize];
        for (int i = 0; i < blocks.length; i++) {
            System.arraycopy(blocks[i], 0, decrypted, i * blockSize, blockSize);
        }

        return decrypted;
    }

    // splitIntoBlocks
    public byte[][] splitIntoBlocks(byte[] data) {
        // Ilość bloków - musi być cast na double, aby wynik był zmiennoprzecinkowy, zaokrąglamy w górę i rzutujemy na int
        int numBlocks = (int) Math.ceil(data.length / (double) blockSize);

        // Tablica bloków
        byte[][] blocks = new byte[numBlocks][blockSize];

        for (int i = 0; i < numBlocks; i++) {
            // Indeks początkowy bloku
            int start = i * blockSize;
            // Długość bloku - jeśli ostatni blok, to długość może być mniejsza
            int length = Math.min(blockSize, data.length - start);

            // Kopiowanie danych do bloku
            // Argumenty: źródło, początek, cel, początek_w_celu, długość
            // Reszta pozostaje zerowa (Java inicjalizuje bajty na 0)
            System.arraycopy(data, start, blocks[i], 0, length);
        }
        return blocks;
    }

    // getRconValue
    private byte getRconValue(int iteration) {
        if (iteration > RCON.length) {
            throw new IllegalArgumentException("RCON iteration out of bounds");
        }
        return (byte) RCON[iteration - 1];
    }

    // addRoundKey
    public void addRoundKey(byte[] block, int numberOfRound) {

        // XORowanie bloku z kluczem
        for (int i = 0; i < blockSize; i++) {
            block[i] ^= expandedKey[numberOfRound * blockSize + i];
        }
    }

    // subBytes
    public void subBytes(byte[] block, int size) {
        for (int i = 0; i < size; i++) {
            // Wiersz określamy pierwszą cyfrą bajtu, kolumnę drugą
            block[i] = (byte) SBOX[(block[i] & 0xFF) >>> 4][block[i] & 0x0F];
        }
    }

    // reverseSubBytes
    private void reverseSubBytes(byte[] block, int size) {
        for (int i = 0; i < size; i++) {
            // Wiersz określamy pierwszą cyfrą bajtu, kolumnę drugą
            block[i] = (byte) reverseSBOX[(block[i] & 0xFF) >>> 4][block[i] & 0x0F];
        }
    }

    // shiftRows
    private void shiftRows(byte[] block, boolean direction){
        for (int i = 1; i < 4; i++) {
            // tymaczasowy wiersz
            byte[] row = new byte[4];

            // kopiowanie wiersza
            for (int j = 0; j < 4; j++) {
                row[j] = block[i + j * 4];
            }

            if (direction) {
                if (i == 1) {
                    row = new byte[]{row[1], row[2], row[3], row[0]};
                } else if (i == 2) {
                    row = new byte[]{row[2], row[3], row[0], row[1]};
                } else {
                    row = new byte[]{row[3], row[0], row[1], row[2]};
                }
            } else {
                if (i == 1) {
                    row = new byte[]{row[3], row[0], row[1], row[2]};
                } else if (i == 2) {
                    row = new byte[]{row[2], row[3], row[0], row[1]};
                } else {
                    row = new byte[]{row[1], row[2], row[3], row[0]};
                }
            }

            // kopiowanie wiersza z powrotem
            for (int j = 0; j < 4; j++) {
                block[i + j * 4] = row[j];
            }
        }
    }

    // mixColumns
    private void mixColumns(byte[] block, boolean option) {
        for (int i = 0; i < 4; i++) {
            byte[] column = new byte[4];
            byte[] newColumn = new byte[4];
            byte value;

            // Kopiowanie kolumny do tymczasowej tablicy
            System.arraycopy(block, i * 4, column, 0, 4);

            // Przeprowadzenie mnożenia na kolumnie
            for (int j = 0; j < 4; j++) {
                newColumn[j] = 0;
                for (int k = 0; k < 4; k++) {
                    if (option) {
                        value = switch (MCOL[j * 4 + k]) {
                            case 1 -> gfMul1(column[k]);
                            case 2 -> gfMul2(column[k]);
                            case 3 -> gfMul3(column[k]);
                            default -> throw new IllegalArgumentException("Invalid MCOL value");
                        };
                    } else {
                        value = switch (MCOL_INV[j * 4 + k]) {
                            case 9 -> gfMul9(column[k]);
                            case 11 -> gfMul11(column[k]);
                            case 13 -> gfMul13(column[k]);
                            case 14 -> gfMul14(column[k]);
                            default -> throw new IllegalArgumentException("Invalid INV_MCOL value");
                        };
                    }

                    // Przypisanie wyniku do pozycji w nowej kolumnie
                    newColumn[j] ^= value;
                }
            }
            System.arraycopy(newColumn, 0, block, i * 4, 4);
        }
    }

    // gfMul1
    private byte gfMul1(byte b) {
        return b; // Mnożenie przez 1 to wartość bez zmian
    }

    // gfMul2
    private byte gfMul2(byte b) {
        // Usunięcie znaku z bajtu
        int bInt = b & 0xFF;
        // Przesunięcie w lewo i XOR z 0x1B jeśli najwyższy bit jest 1
        if ((bInt & 0x80) == 0) {
            return (byte)(bInt << 1);
        } else {
            return (byte)((bInt << 1) ^ 0x1B);
        }
    }

    // gfMul3
    private byte gfMul3(byte b) {
        // Mnożenie przez 3 to mnożenie przez 2 i XOR z oryginalną wartością
        return (byte)(gfMul2(b) ^ (b & 0xFF));
    }

    // gfMul4
    private byte gfMul4(byte b) {
        return gfMul2(gfMul2(b));
    }

    // gfMul8
    private byte gfMul8(byte b) {
        return gfMul2(gfMul4(b));
    }

    // gfMul9
    private byte gfMul9(byte b) {
        // 9 = 8 + 1, więc mnożymy przez 8 i dodajemy oryginalną wartość
        return (byte)(gfMul8(b) ^ b);
    }

    // gfMul11
    private byte gfMul11(byte b) {
        // 11 = 8 + 2 + 1
        return (byte)(gfMul8(b) ^ gfMul2(b) ^ b);
    }

    // gfMul13
    private byte gfMul13(byte b) {
        // 13 = 8 + 4 + 1
        return (byte)(gfMul8(b) ^ gfMul4(b) ^ b);
    }

    // gfMul14
    private byte gfMul14(byte b) {
        // 14 = 8 + 4 + 2
        return (byte)(gfMul8(b) ^ gfMul4(b) ^ gfMul2(b));
    }
}
