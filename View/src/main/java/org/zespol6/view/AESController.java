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
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Objects;

public class AESController {

    @FXML
    public Label keyLabel;

    @FXML
    Button keyGenButton;

    @FXML
    Button encryptButton;

    @FXML
    Button decryptButton;

    @FXML
    Button copyEncryptedDataButton;

    @FXML
    Button copyDecryptedDataButton;

    @FXML
    Button loadEncryptedButton;

    @FXML
    Button loadDecryptedButton;

    @FXML
    Button saveEncryptedButton;

    @FXML
    Button saveDecryptedButton;

    @FXML
    Button keySaveButton;

    @FXML
    Button keyLoadButton;

    @FXML
    TextArea dataField;

    @FXML
    TextArea encryptedDataField;

    @FXML
    TextField keyField;

    @FXML
    RadioButton key128;

    @FXML
    RadioButton key192;

    @FXML
    RadioButton key256;

    @FXML
    ToggleGroup key;

    byte[] originalData;
    byte[] encryptedData;
    byte[] keyData;

    @FXML
    public void initialize() {
        key.selectedToggleProperty().addListener((observable, oldValue, newValue) -> keyField.clear());

        // Dodanie listenerów na zmiany w polach tekstowych
        dataField.textProperty().addListener((observable, oldValue, newValue) -> {
            if (!newValue.isEmpty()) {
                try {
                    AES aes = new AES();
                    originalData = aes.hexToBytes(newValue);
                } catch (Exception ex) {
                    // Ignorujemy błędne dane - zostaną obsłużone podczas szyfrowania/deszyfrowania
                }
            } else {
                originalData = null;
            }
        });

        encryptedDataField.textProperty().addListener((observable, oldValue, newValue) -> {
            if (!newValue.isEmpty()) {
                try {
                    AES aes = new AES();
                    encryptedData = aes.hexToBytes(newValue);
                } catch (Exception ex) {
                    // Ignorujemy błędne dane - zostaną obsłużone podczas szyfrowania/deszyfrowania
                }
            } else {
                encryptedData = null;
            }
        });

        AES aes = new AES();
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        keyGenButton.setOnAction(e -> {
            int keyLength = getKeySize();
            aes.generateMainKey(keyLength);
            keyData = aes.getMainKey().toByteArray();
            keyField.setText(aes.bytesToHex(keyData));
        });

        keySaveButton.setOnAction(e -> saveButtonAction(keyField, null, 2));

        keyLoadButton.setOnAction(e -> {
            loadButtonAction(null, keyField, 2);
            String keyHex = keyField.getText();
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

        encryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);
                byte[] expectedData = aes.encrypt(originalData, aes.getMainKey());
                encryptedData = Arrays.copyOf(expectedData, expectedData.length);
                encryptedDataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                encryptedDataField.setText("Error: Invalid key format");
            } catch (Exception ex) {
                encryptedDataField.setText("Error: " + ex.getMessage());
            }
        });

        loadEncryptedButton.setOnAction(e -> loadButtonAction(encryptedDataField, null, 0));

        loadDecryptedButton.setOnAction(e -> loadButtonAction(dataField, null, 1));

        decryptButton.setOnAction(e -> {
            try {
                String keyHex = aes.bytesToHex(keyData);
                BigInteger keyBigInt = new BigInteger(keyHex, 16);
                aes.setMainKey(keyBigInt);

                // Hex string konwertujemy na tablicę bajtów
                byte[] expectedData = aes.decrypt(encryptedData, aes.getMainKey());
                originalData = Arrays.copyOf(expectedData, expectedData.length);
                dataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                dataField.setText("Error: Invalid key format, key: " + new String(keyData).toLowerCase());
            } catch (Exception ex) {
                dataField.setText("Error: " + ex.getMessage());
            }
        });

        copyEncryptedDataButton.setOnAction(e -> {
            content.putString(encryptedDataField.getText());
            clipboard.setContent(content);
        });

        copyDecryptedDataButton.setOnAction(e -> {
            content.putString(dataField.getText());
            clipboard.setContent(content);
        });

        saveEncryptedButton.setOnAction(e -> saveButtonAction(null, encryptedDataField, 0));

        saveDecryptedButton.setOnAction(e -> saveButtonAction(null, dataField, 3));
    }

    private void loadButtonAction(TextArea textArea, TextField textField, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
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
                switch (option) {
                    case 0:
                        encryptedData = Arrays.copyOf(data, data.length);
                        break;
                    case 1:
                        originalData = Arrays.copyOf(data, data.length);
                        break;
                    case 3:
                        keyData = Arrays.copyOf(data, data.length);
                        break;
                    default:
                        break;
                }
                AES aes = new AES();
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

    private void saveButtonAction(TextField textField, TextArea textArea, int option) {
        // Otworzenie okienka dialogowego do wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        switch (option) {
            case 0:
                fileChooser.setTitle("Zapisz zaszyfrowane dane");
                break;
            case 2:
                fileChooser.setTitle("Zapisz klucz");
                break;
            case 3:
                fileChooser.setTitle("Zapisz odszyfrowane dane");
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
                switch (option) {
                    case 0:
                        java.nio.file.Files.write(selectedFile.toPath(), encryptedData);
                        break;
                    case 2:
                        java.nio.file.Files.write(selectedFile.toPath(), keyData);
                        break;
                    case 3:
                        java.nio.file.Files.write(selectedFile.toPath(), originalData);
                        break;
                    default:
                        break;
                }
            } catch (IOException ex) {
                Objects.requireNonNullElse(textArea, textField).setText("Error: " + ex.getMessage());
            }
        }
    }

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