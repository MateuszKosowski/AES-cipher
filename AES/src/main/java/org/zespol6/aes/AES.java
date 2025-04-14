/*
 * Nazwa programu: AES-cipher
 * Copyright (C) 2025  Mateusz Kosowski Nikodem Nowak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.zespol6.aes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Klasa implementująca algorytm szyfrowania AES (Advanced Encryption Standard).
 * Obsługuje klucze o długości 128, 192 i 256 bitów.
 * Zapewnia metody do szyfrowania i deszyfrowania danych.
 */
public class AES {

    /**
     * Liczba rund w algorytmie AES. Zależna od długości klucza (10 dla 128 bitów, 12 dla 192 bitów, 14 dla 256 bitów).
     * Ustawiana dynamicznie w metodzie keyExpansion.
     */
    private int amountOfRounds = 10; // Domyślnie dla 128 bitów

    /**
     * Rozmiar bloku danych w bajtach używany w AES (zawsze 16 bajtów, czyli 128 bitów).
     */
    private final int blockSize = 16;

    /**
     * Główny klucz szyfrujący/deszyfrujący podany przez użytkownika, przechowywany jako BigInteger.
     */
    private BigInteger mainKey;

    /**
     * Rozszerzony klucz (Key Schedule) zawierający klucze do wszystkich rund AES.
     * Generowany na podstawie klucza głównego w metodzie keyExpansion.
     */
    private byte[] expandedKey;

    /**
     * Tablica podstawień S-Box (Substitution Box) używana w kroku SubBytes.
     * Każdy bajt danych jest zastępowany innym bajtem zgodnie z tabelą SBOX. Konstrukcja tabeli gwarantuje nieliniowość zastępowania.
     */
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

    /**
     * Odwrotna tablica podstawień S-Box (Inverse S-Box) używana w kroku InverseSubBytes podczas deszyfrowania.
     */
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

    /**
     * Stała RCON (Round Constant) - wartości używane w procesie rozszerzania klucza (Key Expansion).
     * Każda wartość jest używana w jednej iteracji generowania kluczy rundy.
     */
    private final int[] RCON = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
            // Wartości są potęgami 2 w ciele Galois GF(2^8)
    };

    /**
     * Stała MCOL (MixColumns Matrix) - macierz używana do mnożenia w kroku MixColumns podczas szyfrowania.
     * Reprezentuje mnożenie przez wielomian a(x) = {03}x^3 + {01}x^2 + {01}x + {02} modulo x^4 + 1.
     * Wartości 1, 2, 3 reprezentują współczynniki w GF(2^8).
     */
    private final int[] MCOL = {
            2, 3, 1, 1,
            1, 2, 3, 1,
            1, 1, 2, 3,
            3, 1, 1, 2
    };

    /**
     * Stała MCOL_INV (Inverse MixColumns Matrix) - macierz używana do mnożenia w kroku InverseMixColumns podczas deszyfrowania.
     * Reprezentuje mnożenie przez wielomian a^{-1}(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e} modulo x^4 + 1.
     * Wartości 9, 11 (0x0B), 13 (0x0D), 14 (0x0E) reprezentują współczynniki w GF(2^8).
     */
    private final int[] MCOL_INV = {
            14, 11, 13, 9,
            9, 14, 11, 13,
            13, 9, 14, 11,
            11, 13, 9, 14
    };

    /**
     * Konwertuje tablicę bajtów na ciąg znaków używając kodowania UTF-8.
     * @param data Tablica bajtów do konwersji.
     * @return Ciąg znaków reprezentujący dane bajtowe.
     */
    public String bytesToString(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Konwertuje tablicę bajtów na jej reprezentację heksadecymalną (szesnastkową).
     * Każdy bajt jest reprezentowany przez dwie cyfry heksadecymalne.
     * @param bytes Tablica bajtów do konwersji.
     * @return Ciąg znaków heksadecymalnych.
     */
    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        // Iteruje przez każdy bajt w tablicy
        for (byte b : bytes) {
            // Formatuje bajt jako dwucyfrową wartość heksadecymalną (z wiodącym zerem jeśli potrzeba)
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Konwertuje ciąg znaków heksadecymalnych na tablicę bajtów.
     * Oczekuje, że ciąg wejściowy ma parzystą długość.
     * @param hex Ciąg znaków heksadecymalnych.
     * @return Tablica bajtów odpowiadająca ciągowi heksadecymalnemu.
     * @throws IllegalArgumentException jeśli ciąg heksadecymalny ma nieparzystą długość.
     */
    public byte[] hexToBytes(String hex) {
        // Sprawdza, czy długość ciągu jest parzysta
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        int len = hex.length();
        // Tworzy tablicę bajtów o połowie długości ciągu heksadecymalnego
        byte[] data = new byte[len / 2];
        // Przetwarza ciąg heksadecymalny po dwa znaki na raz
        for (int i = 0; i < len; i += 2) {
            // Konwertuje parę znaków heksadecymalnych na jeden bajt
            // Character.digit(hex.charAt(i), 16) - konwertuje pierwszy znak heksadecymalny na wartość (0-15)
            // << 4 - przesuwa tę wartość o 4 bity w lewo (tworzy starszą połówkę bajtu)
            // Character.digit(hex.charAt(i+1), 16) - konwertuje drugi znak heksadecymalny na wartość (0-15)
            // + - dodaje drugą wartość (młodszą połówkę bajtu)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Generuje losowy klucz główny o podanym rozmiarze (128, 192 lub 256 bitów).
     * Używa bezpiecznego generatora liczb losowych (SecureRandom).
     * @param size Rozmiar klucza w bitach (np. 128, 192, 256).
     */
    public void generateMainKey(int size) {
        int keySize = size / 8; // Konwertuje rozmiar z bitów na bajty
        byte[] keyBytes = new byte[keySize]; // Tworzy tablicę bajtów o odpowiednim rozmiarze
        new SecureRandom().nextBytes(keyBytes); // Wypełnia tablicę losowymi bajtami
        // Tworzy BigInteger z tablicy bajtów, argument '1' zapewnia, że liczba jest interpretowana jako dodatnia
        mainKey = new BigInteger(1, keyBytes);
    }

    /**
     * Zwraca aktualnie ustawiony klucz główny.
     * @return Klucz główny jako BigInteger.
     */
    public BigInteger getMainKey() {
        return mainKey;
    }

    /**
     * Ustawia klucz główny.
     * @param mainKey Klucz główny do ustawienia, jako BigInteger.
     */
    public void setMainKey(BigInteger mainKey) {
        this.mainKey = mainKey;
    }

    /**
     * Zwraca rozszerzony klucz (Key Schedule) wygenerowany z klucza głównego.
     * @return Tablica bajtów zawierająca wszystkie klucze rund.
     */
    public byte[] getExpandedKey() {
        return expandedKey;
    }

    /**
     * Konwertuje klucz w formacie BigInteger na tablicę bajtów o stałym rozmiarze
     * odpowiednim dla AES (16, 24 lub 32 bajty), dodając wiodące zera jeśli to konieczne.
     * Obsługuje potencjalny wiodący bajt zerowy dodawany przez BigInteger.toByteArray().
     *
     * @param key Klucz w formacie BigInteger.
     * @return Tablica bajtów reprezentująca klucz, o długości 16, 24 lub 32.
     * @throws IllegalArgumentException jeśli klucz jest większy niż 256 bitów lub ma nieprawidłowy rozmiar.
     */
    public byte[] toByteKey(BigInteger key) {

        int bitLength = key.bitLength(); // Pobiera długość bitową klucza
        int targetKeySizeBytes; // Docelowa długość klucza w bajtach

        // Określenie docelowej długości klucza AES na podstawie długości bitowej
        if (bitLength <= 128) {
            targetKeySizeBytes = 16; // 128 bitów
        } else if (bitLength <= 192) {
            targetKeySizeBytes = 24; // 192 bity
        } else if (bitLength <= 256) {
            targetKeySizeBytes = 32; // 256 bitów
        } else {
            // Klucz jest za długi
            throw new IllegalArgumentException("Rozmiar klucza AES nie może być większy niż 256 bitów.");
        }

        // Konwersja BigInteger na tablicę bajtów (może zawierać wiodący bajt zerowy)
        byte[] keyBytes = key.toByteArray();
        // Tworzy tablicę wynikową o docelowej długości, wypełnioną zerami
        byte[] fixedKey = new byte[targetKeySizeBytes];

        int keyBytesLength = keyBytes.length; // Długość tablicy bajtów z BigInteger
        int sourceOffset = 0; // Indeks startowy w tablicy źródłowej (keyBytes)

        // Sprawdzenie, czy BigInteger dodał wiodący bajt zerowy (dla liczb dodatnich)
        // Jeśli pierwszy bajt to 0 i tablica ma więcej niż 1 element, ignorujemy ten bajt
        if (keyBytes[0] == 0 && keyBytesLength > 1) {
            sourceOffset = 1;        // Pomiń wiodące zero
            keyBytesLength = keyBytesLength - 1; // Aktualizuj faktyczną długość danych klucza
        }

        // Sprawdzenie, czy faktyczna liczba bajtów klucza (po usunięciu ew. wiodącego zera)
        // nie przekracza docelowego rozmiaru klucza.
        if (keyBytesLength > targetKeySizeBytes) {
            throw new IllegalArgumentException(
                    "Rozmiar klucza AES nie może być większy niż " + targetKeySizeBytes * 8 + " bitów.");
        }

        // Obliczenie pozycji startowej w tablicy docelowej (fixedKey),
        // aby skopiowane bajty znalazły się na końcu (padding zerami z lewej).
        int destinationOffset = targetKeySizeBytes - keyBytesLength;

        // Kopiowanie właściwych bajtów z keyBytes (pomijając ew. wiodące zero)
        // do fixedKey, zaczynając od obliczonej pozycji docelowej.
        // Argumenty: źródło, indeks startowy źródła, cel, indeks startowy celu, liczba bajtów do skopiowania
        System.arraycopy(keyBytes, sourceOffset, fixedKey, destinationOffset, keyBytesLength);

        return fixedKey; // Zwraca tablicę bajtów o ustalonej długości (16, 24 lub 32)
    }


    /**
     * Rozszerza klucz główny (mainKey) w celu wygenerowania kluczy do poszczególnych rund AES (Key Schedule).
     * Algorytm rozszerzania zależy od rozmiaru klucza głównego.
     * Wynik zapisuje w polu `expandedKey`.
     * Ustala również liczbę rund (`amountOfRounds`) na podstawie rozmiaru klucza.
     *
     * @param mainKey Klucz główny w formacie BigInteger.
     * @throws IllegalArgumentException jeśli rozmiar klucza jest nieprawidłowy (inny niż 128, 192, 256 bitów).
     */
    public void keyExpansion(BigInteger mainKey) {
        // Konwertuje BigInteger na tablicę bajtów o stałym rozmiarze (16, 24 lub 32)
        final byte[] fixedMainKey = toByteKey(mainKey);
        int keySize = fixedMainKey.length; // Rozmiar klucza w bajtach (16, 24 lub 32)
        int keySizeInWords = keySize / 4; // Rozmiar klucza w 4-bajtowych słowach (4, 6 lub 8)

        // Określenie liczby rund na podstawie rozmiaru klucza
        if (keySize == 16) { // 128 bitów
            amountOfRounds = 10;
        } else if (keySize == 24) { // 192 bity
            amountOfRounds = 12;
        } else if (keySize == 32) { // 256 bitów
            amountOfRounds = 14;
        } else {
            // Ten warunek nie powinien być osiągnięty, jeśli toByteKey działa poprawnie
            throw new IllegalArgumentException("Invalid key size: " + keySize * 8 + " bits");
        }

        // Tworzy bufor na rozszerzony klucz. Rozmiar to (liczba rund + 1) * rozmiar bloku (16 bajtów)
        byte[] expandedKeyLocal = new byte[blockSize * (amountOfRounds + 1)];
        // Całkowita liczba 4-bajtowych słów w rozszerzonym kluczu
        int totalWords = expandedKeyLocal.length / 4;

        // Kopiuje klucz główny (w bajtach) na początek tablicy rozszerzonego klucza
        System.arraycopy(fixedMainKey, 0, expandedKeyLocal, 0, keySize);

        // Indeks bieżącego słowa do wygenerowania (zaczyna od pierwszego słowa *po* kluczu głównym)
        int currentPos = keySizeInWords;
        // Tymczasowa tablica 4-bajtowa do przechowywania słowa w trakcie transformacji
        byte[] temp = new byte[4];

        // Pętla generująca kolejne słowa klucza rundy, aż do wypełnienia całej tablicy expandedKeyLocal
        while (currentPos < totalWords) {
            // Kopiuje poprzednie słowo (W[i-1]) do tablicy tymczasowej 'temp'
            System.arraycopy(expandedKeyLocal, (currentPos - 1) * 4, temp, 0, 4);

            // Jeśli generujemy pierwsze słowo nowego bloku klucza rundy (indeks podzielny przez rozmiar klucza w słowach)
            if (currentPos % keySizeInWords == 0) {
                rotWord(temp); // Wykonuje RotWord (cykliczne przesunięcie bajtów w lewo)
                subBytes(temp, 4); // Wykonuje SubBytes (podstawienie S-Box na każdym bajcie)
                // Wykonuje XOR pierwszego bajtu z wartością RCON odpowiednią dla bieżącej rundy
                // Numer rundy = currentPos / keySizeInWords
                temp[0] ^= getRconValue(currentPos / keySizeInWords);
            }
            // Dodatkowa operacja SubBytes dla kluczy 256-bitowych (keySizeInWords = 8)
            // wykonywana dla słów o indeksie i takim, że i % 8 == 4
            else if (keySizeInWords == 8 && currentPos % keySizeInWords == 4) {
                subBytes(temp, 4); // Wykonuje tylko SubBytes
            }
            // Dla pozostałych słów (nie będących pierwszymi w bloku i nie spełniających warunku dla 256 bitów)
            // nie wykonuje się RotWord, SubBytes ani XOR z RCON w tym kroku.

            // Wykonuje XOR przetworzonego słowa 'temp' (lub oryginalnego W[i-1] jeśli nie było transformacji)
            // ze słowem znajdującym się 'keySizeInWords' pozycji wcześniej (W[i - Nk])
            for (int i = 0; i < 4; i++) {
                temp[i] ^= expandedKeyLocal[(currentPos - keySizeInWords) * 4 + i];
            }

            // Zapisuje nowo wygenerowane słowo (W[i]) w tablicy rozszerzonego klucza
            System.arraycopy(temp, 0, expandedKeyLocal, currentPos * 4, 4);
            currentPos++; // Przechodzi do generowania następnego słowa
        }

        // Zapisuje wygenerowany rozszerzony klucz w polu instancji klasy
        this.expandedKey = expandedKeyLocal;
    }

    /**
     * Szyfruje podane dane przy użyciu algorytmu AES i podanego klucza.
     *
     * @param data Dane do zaszyfrowania jako tablica bajtów.
     * @param key Klucz szyfrujący jako BigInteger.
     * @return Zaszyfrowane dane jako tablica bajtów.
     */
    public byte[] encrypt(byte[] data, BigInteger key) {
        // Dzieli dane wejściowe na bloki o rozmiarze `blockSize` (16 bajtów)
        byte[][] blocks = splitIntoBlocks(data);
        // Generuje rozszerzony klucz (klucze rund) na podstawie podanego klucza głównego
        keyExpansion(key);

        // Iteruje przez każdy blok danych
        for (byte[] block : blocks) {

            // Runda 0: AddRoundKey (XOR z kluczem głównym - pierwszym kluczem rundy)
            addRoundKey(block, 0);

            // Rundy 1 do (amountOfRounds - 1)
            for (int round = 1; round < amountOfRounds; round++) {
                subBytes(block, blockSize); // Krok SubBytes: podstawienie bajtów za pomocą S-Box
                shiftRows(block, true);    // Krok ShiftRows: przesunięcie wierszy stanu (true = kierunek szyfrowania)
                mixColumns(block, true);   // Krok MixColumns: mieszanie kolumn stanu (true = kierunek szyfrowania)
                addRoundKey(block, round);  // Krok AddRoundKey: XOR z kluczem rundy
            }

            // Ostatnia runda (bez kroku MixColumns)
            subBytes(block, blockSize); // Krok SubBytes
            shiftRows(block, true);    // Krok ShiftRows (kierunek szyfrowania)
            addRoundKey(block, amountOfRounds); // Krok AddRoundKey z ostatnim kluczem rundy
        }

        // Łączy zaszyfrowane bloki z powrotem w jedną tablicę bajtów
        byte[] encrypted = new byte[blocks.length * blockSize];
        for (int i = 0; i < blocks.length; i++) {
            // Kopiuje zawartość każdego bloku do wynikowej tablicy
            System.arraycopy(blocks[i], 0, encrypted, i * blockSize, blockSize);
        }

        return encrypted; // Zwraca zaszyfrowane dane
    }

    /**
     * Deszyfruje podane dane zaszyfrowane algorytmem AES przy użyciu podanego klucza.
     * Usuwa potencjalne zerowe bajty dopełnienia (padding) z końca odszyfrowanych danych.
     *
     * @param encrypted Zaszyfrowane dane jako tablica bajtów.
     * @param key Klucz deszyfrujący jako BigInteger (ten sam co do szyfrowania).
     * @return Odszyfrowane dane jako tablica bajtów (bez paddingu).
     */
    public byte[] decrypt(byte[] encrypted, BigInteger key) {
        // Dzieli zaszyfrowane dane na bloki o rozmiarze `blockSize` (16 bajtów)
        byte[][] blocks = splitIntoBlocks(encrypted);
        // Generuje rozszerzony klucz (klucze rund) na podstawie podanego klucza głównego
        // Potrzebne są te same klucze rund co przy szyfrowaniu, ale używane w odwrotnej kolejności.
        keyExpansion(key);

        // Iteruje przez każdy zaszyfrowany blok
        for (byte[] block : blocks) {

            // Runda 0 (odwrotna): AddRoundKey z ostatnim kluczem rundy
            addRoundKey(block, amountOfRounds);

            // Rundy (amountOfRounds - 1) do 1 (w odwrotnej kolejności)
            for(int round = amountOfRounds - 1; round > 0; round--) {
                shiftRows(block, false);        // Krok InverseShiftRows (false = kierunek deszyfrowania)
                reverseSubBytes(block);         // Krok InverseSubBytes: podstawienie za pomocą odwrotnego S-Box
                addRoundKey(block, round);      // Krok AddRoundKey: XOR z kluczem rundy (operacja odwrotna do siebie)
                mixColumns(block, false);       // Krok InverseMixColumns (false = kierunek deszyfrowania)
            }

            // Ostatnia runda (odwrotna, bez InverseMixColumns)
            shiftRows(block, false);        // Krok InverseShiftRows (kierunek deszyfrowania)
            reverseSubBytes(block);         // Krok InverseSubBytes
            addRoundKey(block, 0);          // Krok AddRoundKey z kluczem głównym (pierwszym kluczem rundy)

        }

        // Łączy odszyfrowane bloki z powrotem w jedną tablicę bajtów
        byte[] decrypted = new byte[blocks.length * blockSize];
        for (int i = 0; i < blocks.length; i++) {
            // Kopiuje zawartość każdego odszyfrowanego bloku do wynikowej tablicy
            System.arraycopy(blocks[i], 0, decrypted, i * blockSize, blockSize);
        }

        // Usuwanie paddingu (dopełnienia zerami) z końca odszyfrowanych danych
        // Zakłada, że padding składa się wyłącznie z bajtów o wartości 0x00.
        // Sprawdza bajty od końca, szukając pierwszego bajtu różnego od zera.
        int paddingEnd = decrypted.length; // Początkowo zakładamy brak paddingu
        // Pętla od końca tablicy, sprawdzająca maksymalnie 17 ostatnich bajtów
        // (max padding w AES to 16 bajtów, plus jeden na wypadek danych kończących się zerem)
        for (int i = decrypted.length - 1; i >= Math.max(0, decrypted.length - 17); i--) {
            // Jeśli bajt jest różny od 0 (traktujemy go jako niepaddingowy)
            if ((decrypted[i] & 0xFF) != 0x00) {
                break; // Zakończ pętlę, znaleziono koniec właściwych danych
            }
            // Jeśli bajt jest zerem, aktualizujemy potencjalny koniec danych (początek paddingu)
            paddingEnd = i;
        }

        // Jeśli znaleziono padding (paddingEnd jest mniejszy niż oryginalna długość)
        if (paddingEnd < decrypted.length) {
            // Tworzy nową tablicę o rozmiarze do znalezionego końca danych
            byte[] trimmedData = new byte[paddingEnd];
            // Kopiuje tylko właściwe dane (bez paddingu) do nowej tablicy
            System.arraycopy(decrypted, 0, trimmedData, 0, paddingEnd);
            return trimmedData; // Zwraca dane bez paddingu
        }

        // Jeśli nie znaleziono paddingu (lub dane kończyły się zerami niebędącymi paddingiem)
        return decrypted; // Zwraca oryginalną odszyfrowaną tablicę
    }

    /**
     * Dzieli podaną tablicę bajtów na bloki o stałym rozmiarze (`blockSize`).
     * Ostatni blok jest dopełniany zerami, jeśli jego długość jest mniejsza niż `blockSize`.
     *
     * @param data Tablica bajtów do podziału.
     * @return Dwuwymiarowa tablica bajtów, gdzie każdy wiersz reprezentuje jeden blok.
     */
    public byte[][] splitIntoBlocks(byte[] data) {
        // Oblicza liczbę bloków potrzebnych do pomieszczenia danych.
        // Używa dzielenia zmiennoprzecinkowego i Math.ceil do zaokrąglenia w górę,
        // aby zapewnić miejsce dla niepełnego ostatniego bloku.
        int numBlocks = (int) Math.ceil(data.length / (double) blockSize);

        // Tworzy dwuwymiarową tablicę do przechowywania bloków.
        // Liczba wierszy = numBlocks, liczba kolumn = blockSize.
        byte[][] blocks = new byte[numBlocks][blockSize];

        // Iteruje przez liczbę bloków do utworzenia
        for (int i = 0; i < numBlocks; i++) {
            // Oblicza indeks początkowy bieżącego bloku w oryginalnych danych
            int start = i * blockSize;
            // Oblicza długość danych do skopiowania do bieżącego bloku.
            // Dla ostatniego bloku może być mniejsza niż blockSize.
            int length = Math.min(blockSize, data.length - start);

            // Kopiuje dane z oryginalnej tablicy 'data' do bieżącego bloku 'blocks[i]'.
            // Argumenty: źródło, indeks startowy w źródle, cel, indeks startowy w celu (zawsze 0), długość kopiowania.
            // Jeśli 'length' jest mniejsze niż 'blockSize', reszta bloku 'blocks[i]' pozostanie wypełniona zerami
            // (domyślna inicjalizacja tablicy bajtów w Javie).
            System.arraycopy(data, start, blocks[i], 0, length);
        }
        return blocks; // Zwraca tablicę bloków
    }

    /**
     * Pobiera wartość stałej RCON dla podanej iteracji (numeru rundy) rozszerzania klucza.
     * Indeksowanie RCON zaczyna się od 1.
     *
     * @param iteration Numer iteracji/rundy (zaczynając od 1).
     * @return Wartość RCON jako bajt.
     * @throws IllegalArgumentException jeśli numer iteracji jest poza zakresem tablicy RCON.
     */
    private byte getRconValue(int iteration) {
        // Sprawdza, czy żądana iteracja jest poprawnym indeksem dla tablicy RCON
        if (iteration <= 0 || iteration > RCON.length) {
            throw new IllegalArgumentException("RCON iteration out of bounds: " + iteration);
        }
        // Zwraca wartość RCON dla danej iteracji (indeks tablicy = iteracja - 1)
        return (byte) RCON[iteration - 1];
    }

    /**
     * Wykonuje operację RotWord na 4-bajtowym słowie (tablicy `temp`).
     * Polega na cyklicznym przesunięciu bajtów o jedną pozycję w lewo: [b0, b1, b2, b3] -> [b1, b2, b3, b0].
     *
     * @param temp Tablica 4 bajtów (słowo) do przetworzenia (modyfikowana w miejscu).
     */
    private void rotWord(byte[] temp) {
        // Zapisuje pierwszy bajt w zmiennej tymczasowej
        byte tempByte = temp[0];
        // Przesuwa bajty 1, 2, 3 o jedną pozycję w lewo
        for (int j = 0; j < 3; j++) {
            temp[j] = temp[j + 1];
        }
        // Ustawia ostatni bajt na wartość zapisaną w zmiennej tymczasowej
        temp[3] = tempByte;
    }

    /**
     * Wykonuje operację AddRoundKey: XORuje blok danych (`block`) z odpowiednim kluczem rundy.
     * Klucz rundy jest pobierany z tablicy `expandedKey` na podstawie numeru rundy.
     *
     * @param block Blok danych (16 bajtów) do przetworzenia (modyfikowany w miejscu).
     * @param numberOfRound Numer rundy (0 dla klucza głównego, 1 dla pierwszej rundy itd.).
     */
    public void addRoundKey(byte[] block, int numberOfRound) {
        // Iteruje przez każdy bajt bloku (0 do 15)
        for (int i = 0; i < blockSize; i++) {
            // XORuje i-ty bajt bloku z i-tym bajtem odpowiedniego klucza rundy.
            // Indeks klucza rundy w expandedKey = numerRundy * rozmiarBloku + indeksBajtuWBloku
            block[i] ^= expandedKey[numberOfRound * blockSize + i];
        }
    }

    /**
     * Wykonuje operację SubBytes: zastępuje każdy bajt w bloku (`block`) wartością z tablicy S-Box.
     *
     * @param block Blok danych (lub słowo klucza) do przetworzenia (modyfikowany w miejscu).
     * @param size Rozmiar danych do przetworzenia (np. `blockSize` (16) dla bloku stanu, 4 dla słowa klucza).
     */
    public void subBytes(byte[] block, int size) {
        // Iteruje przez określoną liczbę bajtów
        for (int i = 0; i < size; i++) {
            // Pobiera wartość bajtu jako int bez znaku (0-255)
            int byteValue = block[i] & 0xFF;
            // Starsze 4 bity określają numer wiersza w SBOX (>>> 4)
            int row = byteValue >>> 4;
            // Młodsze 4 bity określają numer kolumny w SBOX (& 0x0F)
            int col = byteValue & 0x0F;
            // Zastępuje oryginalny bajt wartością z SBOX odczytaną na podstawie obliczonych współrzędnych
            block[i] = (byte) SBOX[row][col];
        }
    }

    /**
     * Wykonuje operację InverseSubBytes: zastępuje każdy bajt w bloku (`block`) wartością z odwrotnej tablicy S-Box (reverseSBOX).
     * Używana podczas deszyfrowania.
     *
     * @param block Blok danych (16 bajtów) do przetworzenia (modyfikowany w miejscu).
     */
    private void reverseSubBytes(byte[] block) {
        // Iteruje przez każdy bajt bloku (0 do 15)
        for (int i = 0; i < blockSize; i++) {
            // Pobiera wartość bajtu jako int bez znaku (0-255)
            int byteValue = block[i] & 0xFF;
            // Starsze 4 bity określają numer wiersza w reverseSBOX (>>> 4)
            int row = byteValue >>> 4;
            // Młodsze 4 bity określają numer kolumny w reverseSBOX (& 0x0F)
            int col = byteValue & 0x0F;
            // Zastępuje oryginalny bajt wartością z reverseSBOX
            block[i] = (byte) reverseSBOX[row][col];
        }
    }

    /**
     * Wykonuje operację ShiftRows (dla szyfrowania) lub InverseShiftRows (dla deszyfrowania) na bloku stanu (`block`).
     * Polega na cyklicznym przesuwaniu bajtów w wierszach 1, 2 i 3. Wiersz 0 pozostaje bez zmian.
     *
     * @param block Blok danych (16 bajtów) reprezentujący stan AES (modyfikowany w miejscu).
     * @param direction Kierunek przesunięcia: `true` dla ShiftRows (szyfrowanie, przesunięcie w lewo),
     *                  `false` dla InverseShiftRows (deszyfrowanie, przesunięcie w prawo).
     */
    private void shiftRows(byte[] block, boolean direction){
        // Iteruje przez wiersze 1, 2, 3 (wiersz 0 nie jest przesuwany)
        for (int i = 1; i < 4; i++) {
            // Tworzy tymczasową tablicę na bajty bieżącego wiersza
            byte[] row = new byte[4];

            // Kopiuje bajty z bieżącego wiersza stanu 'block' do tablicy 'row'
            // Stan AES jest przechowywany kolumnami, więc dostęp do wiersza i wymaga indeksowania block[i + j*4]
            for (int j = 0; j < 4; j++) {
                row[j] = block[i + j * 4];
            }

            // Wykonuje przesunięcie w zależności od kierunku (szyfrowanie/deszyfrowanie) i numeru wiersza
            if (direction) { // Szyfrowanie (ShiftRows - przesunięcie w lewo)
                if (i == 1) { // Wiersz 1: przesunięcie o 1 w lewo
                    row = new byte[]{row[1], row[2], row[3], row[0]};
                } else if (i == 2) { // Wiersz 2: przesunięcie o 2 w lewo
                    row = new byte[]{row[2], row[3], row[0], row[1]};
                } else { // Wiersz 3: przesunięcie o 3 w lewo (lub 1 w prawo)
                    row = new byte[]{row[3], row[0], row[1], row[2]};
                }
            } else { // Deszyfrowanie (InverseShiftRows - przesunięcie w prawo)
                if (i == 1) { // Wiersz 1: przesunięcie o 1 w prawo (lub 3 w lewo)
                    row = new byte[]{row[3], row[0], row[1], row[2]};
                } else if (i == 2) { // Wiersz 2: przesunięcie o 2 w prawo (lub 2 w lewo) - bez zmian względem szyfrowania
                    row = new byte[]{row[2], row[3], row[0], row[1]};
                } else { // Wiersz 3: przesunięcie o 3 w prawo (lub 1 w lewo)
                    row = new byte[]{row[1], row[2], row[3], row[0]};
                }
            }

            // Kopiuje przesunięty wiersz z powrotem do stanu 'block'
            for (int j = 0; j < 4; j++) {
                block[i + j * 4] = row[j];
            }
        }
    }

    /**
     * Wykonuje operację MixColumns (dla szyfrowania) lub InverseMixColumns (dla deszyfrowania) na bloku stanu (`block`).
     * Każda kolumna stanu jest traktowana jako wielomian nad GF(2^8) i mnożona przez stały wielomian
     * (reprezentowany przez macierz `MCOL` dla szyfrowania lub `MCOL_INV` dla deszyfrowania) modulo x^4 + 1.
     *
     * @param block Blok danych (16 bajtów) reprezentujący stan AES (modyfikowany w miejscu).
     * @param option Wybór operacji: `true` dla MixColumns (szyfrowanie), `false` dla InverseMixColumns (deszyfrowanie).
     */
    private void mixColumns(byte[] block, boolean option) {
        // Iteruje przez każdą z 4 kolumn stanu
        for (int i = 0; i < 4; i++) {
            // Tablica tymczasowa na oryginalną kolumnę
            byte[] column = new byte[4];
            // Tablica tymczasowa na wynikową (zmieszaną) kolumnę
            byte[] newColumn = new byte[4]; // Inicjalizowana zerami
            byte value; // Tymczasowa zmienna na wynik mnożenia w GF(2^8)

            // Kopiuje i-tą kolumnę ze stanu 'block' do tablicy 'column'
            // Kolumna i zaczyna się od indeksu i*4 w bloku
            System.arraycopy(block, i * 4, column, 0, 4);

            // Przeprowadzenie mnożenia macierzy przez wektor (kolumnę) w GF(2^8)
            // Iteruje przez wiersze macierzy (j) - wynikowy element kolumny
            for (int j = 0; j < 4; j++) {
                // Iteruje przez kolumny macierzy (k) / elementy oryginalnej kolumny
                for (int k = 0; k < 4; k++) {
                    // Wybór odpowiedniej macierzy i funkcji mnożącej
                    if (option) { // Szyfrowanie (MixColumns)
                        // Pobiera wartość z macierzy MCOL
                        int multiplier = MCOL[j * 4 + k];
                        // Wykonuje mnożenie w GF(2^8) w zależności od wartości mnożnika
                        value = switch (multiplier) {
                            case 1 -> gfMul1(column[k]); // Mnożenie przez 1
                            case 2 -> gfMul2(column[k]); // Mnożenie przez 2
                            case 3 -> gfMul3(column[k]); // Mnożenie przez 3
                            default -> throw new IllegalArgumentException("Invalid MCOL value: " + multiplier);
                        };
                    } else { // Deszyfrowanie (InverseMixColumns)
                        // Pobiera wartość z macierzy MCOL_INV
                        int multiplier = MCOL_INV[j * 4 + k];
                        // Wykonuje mnożenie w GF(2^8) w zależności od wartości mnożnika
                        value = switch (multiplier) {
                            case 9 -> gfMul9(column[k]);   // Mnożenie przez 9 (0x09)
                            case 11 -> gfMul11(column[k]); // Mnożenie przez 11 (0x0B)
                            case 13 -> gfMul13(column[k]); // Mnożenie przez 13 (0x0D)
                            case 14 -> gfMul14(column[k]); // Mnożenie przez 14 (0x0E)
                            default -> throw new IllegalArgumentException("Invalid INV_MCOL value: " + multiplier);
                        };
                    }

                    // Akumuluje wynik mnożenia (XOR w GF(2^8)) dla j-tego elementu nowej kolumny
                    newColumn[j] ^= value;
                }
            }
            // Kopiuje wynikową (zmieszaną) kolumnę z 'newColumn' z powrotem do stanu 'block'
            System.arraycopy(newColumn, 0, block, i * 4, 4);
        }
    }

    // --- Metody pomocnicze do mnożenia w ciele Galois GF(2^8) ---
    // Używane w MixColumns i InverseMixColumns.
    // Modulo (wielomian nierozkładalny) to x^8 + x^4 + x^3 + x + 1 (0x11B).

    /**
     * Mnożenie przez 1 w GF(2^8).
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia (ten sam bajt).
     */
    private byte gfMul1(byte b) {
        return b; // Mnożenie przez 1 nie zmienia wartości
    }

    /**
     * Mnożenie przez 2 (czyli przez x) w GF(2^8).
     * Odpowiada przesunięciu bitowemu w lewo. Jeśli najstarszy bit (bit 7) jest 1,
     * wykonuje się XOR z 0x1B (reprezentacja wielomianu redukującego x^8+x^4+x^3+x+1 bez najstarszego bitu).
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 2.
     */
    private byte gfMul2(byte b) {
        // Konwertuje bajt na int bez znaku
        int bInt = b & 0xFF;
        // Sprawdza, czy najstarszy bit (0x80 = 1000 0000) jest ustawiony
        if ((bInt & 0x80) == 0) {
            // Jeśli nie, wystarczy przesunięcie w lewo o 1 bit
            return (byte)(bInt << 1);
        } else {
            // Jeśli tak, przesuń w lewo i wykonaj XOR z 0x1B
            return (byte)((bInt << 1) ^ 0x1B);
        }
    }

    /**
     * Mnożenie przez 3 (czyli przez x+1) w GF(2^8).
     * Realizowane jako (b * 2) XOR b.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 3.
     */
    private byte gfMul3(byte b) {
        // gfMul2(b) oblicza b*2
        // (b & 0xFF) to oryginalna wartość b
        // ^ wykonuje operację XOR
        return (byte)(gfMul2(b) ^ (b & 0xFF));
    }

    /**
     * Mnożenie przez 4 (czyli przez x^2) w GF(2^8).
     * Realizowane jako (b * 2) * 2.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 4.
     */
    private byte gfMul4(byte b) {
        return gfMul2(gfMul2(b)); // Dwa razy mnożenie przez 2
    }

    /**
     * Mnożenie przez 8 (czyli przez x^3) w GF(2^8).
     * Realizowane jako (b * 4) * 2.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 8.
     */
    private byte gfMul8(byte b) {
        return gfMul2(gfMul4(b)); // Mnożenie przez 2 wyniku mnożenia przez 4
    }

    /**
     * Mnożenie przez 9 (czyli przez x^3 + 1) w GF(2^8).
     * Realizowane jako (b * 8) XOR b. Używane w InverseMixColumns.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 9.
     */
    private byte gfMul9(byte b) {
        // 9 = 8 + 1
        return (byte)(gfMul8(b) ^ b);
    }

    /**
     * Mnożenie przez 11 (0x0B) (czyli przez x^3 + x + 1) w GF(2^8).
     * Realizowane jako (b * 8) XOR (b * 2) XOR b. Używane w InverseMixColumns.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 11.
     */
    private byte gfMul11(byte b) {
        // 11 = 8 + 2 + 1
        return (byte)(gfMul8(b) ^ gfMul2(b) ^ b);
    }

    /**
     * Mnożenie przez 13 (0x0D) (czyli przez x^3 + x^2 + 1) w GF(2^8).
     * Realizowane jako (b * 8) XOR (b * 4) XOR b. Używane w InverseMixColumns.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 13.
     */
    private byte gfMul13(byte b) {
        // 13 = 8 + 4 + 1
        return (byte)(gfMul8(b) ^ gfMul4(b) ^ b);
    }

    /**
     * Mnożenie przez 14 (0x0E) (czyli przez x^3 + x^2 + x) w GF(2^8).
     * Realizowane jako (b * 8) XOR (b * 4) XOR (b * 2). Używane w InverseMixColumns.
     * @param b Bajt wejściowy.
     * @return Wynik mnożenia przez 14.
     */
    private byte gfMul14(byte b) {
        // 14 = 8 + 4 + 2
        return (byte)(gfMul8(b) ^ gfMul4(b) ^ gfMul2(b));
    }
}
