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

package org.zespol6.view;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import java.io.*;

import org.zespol6.aes.AES;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Kontroler interfejsu użytkownika dla aplikacji AES.
 * Obsługuje operacje szyfrowania i deszyfrowania danych z wykorzystaniem algorytmu AES.
 */
public class AESController {

    // Elementy interfejsu użytkownika
    @FXML public Label keyLabel;
    @FXML Button keyGenButton;
    @FXML Button encryptButton;
    @FXML Button decryptButton;
    @FXML Button copyEncryptedDataButton;
    @FXML Button copyDecryptedDataButton;
    @FXML Button loadEncryptedButton;
    @FXML Button loadDecryptedButton;
    @FXML Button saveEncryptedButton;
    @FXML Button saveDecryptedButton;
    @FXML Button keySaveButton;
    @FXML Button keyLoadButton;
    @FXML TextArea decryptedDataField;
    @FXML TextArea encryptedDataField;
    @FXML TextField keyField;

    // Przyciski radiowe do wyboru długości klucza
    @FXML RadioButton key128;
    @FXML RadioButton key192;
    @FXML RadioButton key256;
    @FXML ToggleGroup key;

    // Przyciski radiowe do wyboru źródła danych
    @FXML RadioButton field;
    @FXML RadioButton file;
    @FXML ToggleGroup fieldOrFile;

    // Dane używane przez aplikację
    byte[] originalDataFile;     // Oryginalne dane z pliku
    byte[] encryptedDataFile;    // Zaszyfrowane dane z pliku
    byte[] originalDataTextField;  // Oryginalne dane z pola tekstowego
    byte[] encryptedDataTextField; // Zaszyfrowane dane z pola tekstowego
    byte[] keyData;              // Dane klucza

    /**
     * Inicjalizuje kontroler i konfiguruje obsługę zdarzeń dla elementów interfejsu.
     * Metoda wywoływana automatycznie przez JavaFX po załadowaniu pliku FXML.
     */
    @FXML
    public void initialize() {
        // Nasłuchuj zmiany wybranej długości klucza i wyczyść pole klucza
        key.selectedToggleProperty().addListener((observable, oldValue, newValue) -> keyField.clear());

        AES aes = new AES();
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        // Obsługa generowania klucza
        keyGenButton.setOnAction(e -> {
            int keyLength = getKeySize();
            aes.generateMainKey(keyLength);
            keyData = aes.getMainKey().toByteArray();
            keyField.setText(aes.bytesToHex(keyData));
        });

        // Obsługa zapisywania klucza do pliku
        keySaveButton.setOnAction(e -> saveButtonAction(keyField, null, 2));

        // Obsługa wczytywania klucza z pliku
        keyLoadButton.setOnAction(e -> {
            loadButtonAction(null, keyField, 2);
            String keyHex = keyField.getText();
            // Wybierz odpowiedni przycisk radiowy na podstawie długości klucza
            switch (keyField.getLength() * 4) {
                case 128:
                    key128.setSelected(true);
                    break;
                case 192:
                    key192.setSelected(true);
                    break;
                case 256:
                    key256.setSelected(true);
                    break;
            }
            keyField.setText(keyHex);
        });

        // Obsługa szyfrowania danych
        encryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);
                byte[] expectedData;

                // Szyfruj dane z pola tekstowego lub pliku
                if (field.isSelected()) {
                    originalDataTextField = decryptedDataField.getText().getBytes(StandardCharsets.UTF_8);
                    expectedData = aes.encrypt(originalDataTextField, aes.getMainKey());
                    encryptedDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                } else {
                    expectedData = aes.encrypt(originalDataFile, aes.getMainKey());
                    encryptedDataFile = Arrays.copyOf(expectedData, expectedData.length);
                }
                encryptedDataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                encryptedDataField.setText("Error: Invalid key format");
            } catch (Exception ex) {
                encryptedDataField.setText("Error: " + ex.getMessage());
            }
        });

        // Obsługa wczytywania zaszyfrowanych danych
        loadEncryptedButton.setOnAction(e -> loadButtonAction(encryptedDataField, null, 0));

        // Obsługa wczytywania odszyfrowanych danych
        loadDecryptedButton.setOnAction(e -> loadButtonAction(decryptedDataField, null, 1));

        // Obsługa deszyfrowania danych
        decryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);

                byte[] expectedData;
                if (field.isSelected()) {
                    // Konwersja ciągu znaków hex na bajty i deszyfrowanie
                    byte[] encryptedBytes = aes.hexToBytes(encryptedDataField.getText());
                    expectedData = aes.decrypt(encryptedBytes, aes.getMainKey());
                    originalDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                    decryptedDataField.setText(new String(expectedData, StandardCharsets.UTF_8));
                } else {
                    // Deszyfrowanie danych z pliku
                    expectedData = aes.decrypt(encryptedDataFile, aes.getMainKey());
                    originalDataFile = Arrays.copyOf(expectedData, expectedData.length);
                    decryptedDataField.setText(aes.bytesToHex(expectedData));
                }

            } catch (NumberFormatException ex) {
                decryptedDataField.setText("Error: Invalid key format, key: " + new String(keyData).toLowerCase());
            } catch (Exception ex) {
                decryptedDataField.setText("Error: " + ex.getMessage());
            }
        });

        // Obsługa kopiowania zaszyfrowanych danych do schowka
        copyEncryptedDataButton.setOnAction(e -> {
            content.putString(encryptedDataField.getText());
            clipboard.setContent(content);
        });

        // Obsługa kopiowania odszyfrowanych danych do schowka
        copyDecryptedDataButton.setOnAction(e -> {
            content.putString(decryptedDataField.getText());
            clipboard.setContent(content);
        });

        // Obsługa zapisywania zaszyfrowanych i odszyfrowanych danych
        saveEncryptedButton.setOnAction(e -> saveButtonAction(null, encryptedDataField, 0));
        saveDecryptedButton.setOnAction(e -> saveButtonAction(null, decryptedDataField, 3));
    }

    /**
     * Obsługuje wczytywanie danych z pliku.
     *
     * @param textArea   TextArea, w której mają być wyświetlone dane (może być null)
     * @param textField  TextField, w którym mają być wyświetlone dane (może być null)
     * @param option     Opcja określająca typ wczytywanego pliku:
     *                   0 - zaszyfrowane dane, 1 - odszyfrowane dane, 2 - klucz
     */
    private void loadButtonAction(TextArea textArea, TextField textField, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();

        // Ustawienie tytułu okna dialogowego w zależności od opcji
        switch (option) {
            case 0:
                fileChooser.setTitle("Wybierz plik z zaszyfrowanymi danymi");
                break;
            case 1:
                fileChooser.setTitle("Wybierz plik z odszyfrowanymi danymi");
                break;
            case 2:
                fileChooser.setTitle("Wybierz plik z kluczem");
                break;
            default:
                fileChooser.setTitle("Wybierz plik");
                break;
        }

        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            try {
                byte[] data = Files.readAllBytes(selectedFile.toPath());

                // Zapisz wczytane dane w odpowiednim polu w zależności od opcji
                switch (option) {
                    case 0:
                        encryptedDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true);
                        break;
                    case 1:
                        originalDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true);
                        break;
                    case 3:
                        keyData = Arrays.copyOf(data, data.length);
                        break;
                    default:
                        break;
                }

                AES aes = new AES();
                // Wyświetl dane w odpowiednim polu
                if (textArea != null) {
                    textArea.setText(aes.bytesToHex(data));
                } else {
                    textField.setText(aes.bytesToHex(data));
                }
            } catch (IOException ex) {
                if (textArea != null) {
                    textArea.setText("Error: " + ex.getMessage());
                } else {
                    textField.setText("Error: " + ex.getMessage());
                }
            }
        }
    }

    /**
     * Obsługuje zapisywanie danych do pliku.
     *
     * @param textField  TextField z danymi do zapisania (może być null)
     * @param textArea   TextArea z danymi do zapisania (może być null)
     * @param option     Opcja określająca typ zapisywanych danych:
     *                   0 - zaszyfrowane dane, 2 - klucz, 3 - odszyfrowane dane
     */
    private void saveButtonAction(TextField textField, TextArea textArea, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();

        // Ustawienie tytułu okna dialogowego w zależności od opcji
        switch (option) {
            case 0:
                fileChooser.setTitle("Zapisz zaszyfrowane dane");
                break;
            case 2:
                fileChooser.setTitle("Zapisz klucz");
                break;
            case 3:
                fileChooser.setTitle("Zapisz odszyfrowane dane");
                break;
            default:
                fileChooser.setTitle("Zapisz plik");
                break;
        }

        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        File selectedFile = fileChooser.showSaveDialog(null);

        if (selectedFile != null) {
            try {
                byte[] dataToSave = null;

                // Wybór odpowiednich danych do zapisania w zależności od opcji
                switch (option) {
                    case 0: // Zaszyfrowane dane
                        if (field.isSelected() && encryptedDataTextField != null) {
                            dataToSave = encryptedDataTextField;
                        } else if (encryptedDataFile != null) {
                            dataToSave = encryptedDataFile;
                        }
                        break;
                    case 2: // Klucz
                        if (keyData != null) {
                            dataToSave = keyData;
                        }
                        break;
                    case 3: // Odszyfrowane dane
                        if (field.isSelected() && originalDataTextField != null) {
                            dataToSave = originalDataTextField;
                        } else if (originalDataFile != null) {
                            dataToSave = originalDataFile;
                        }
                        break;
                }

                // Zapisz dane do pliku, jeśli są dostępne
                if (dataToSave != null) {
                    java.nio.file.Files.write(selectedFile.toPath(), dataToSave);
                } else {
                    throw new IOException("Brak danych do zapisania");
                }

            } catch (IOException ex) {
                // Obsługa błędu zapisu
                if (textArea != null) {
                    textArea.setText("Error: " + ex.getMessage());
                } else if (textField != null) {
                    textField.setText("Error: " + ex.getMessage());
                }
            }
        }
    }

    /**
     * Zwraca rozmiar klucza wybrany przez użytkownika.
     *
     * @return Rozmiar klucza w bitach (128, 192 lub 256)
     */
    private int getKeySize() {
        if (key128.isSelected()) {
            return 128;
        } else if (key192.isSelected()) {
            return 192;
        } else if (key256.isSelected()) {
            return 256;
        }
        return 128; // Domyślny rozmiar klucza
    }
}