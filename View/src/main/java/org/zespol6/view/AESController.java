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

import org.zespol6.aes.AES; // Import klasy implementującej logikę AES

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Kontroler JavaFX dla interfejsu użytkownika aplikacji AES-cipher.
 * Zarządza interakcjami użytkownika, obsługuje pola tekstowe, przyciski
 * i inne kontrolki do wykonywania operacji szyfrowania i deszyfrowania AES.
 */
public class AESController {

    // --- Pola FXML - powiązane z elementami UI zdefiniowanymi w pliku FXML ---

    /**
     * Etykieta wyświetlająca tytuł lub opis pola klucza.
     */
    @FXML
    public Label keyLabel;

    /**
     * Przycisk do generowania nowego klucza AES.
     */
    @FXML
    Button keyGenButton;

    /**
     * Przycisk do uruchamiania operacji szyfrowania.
     */
    @FXML
    Button encryptButton;

    /**
     * Przycisk do uruchamiania operacji deszyfrowania.
     */
    @FXML
    Button decryptButton;

    /**
     * Przycisk do kopiowania zaszyfrowanych danych (w formacie hex) do schowka systemowego.
     */
    @FXML
    Button copyEncryptedDataButton;

    /**
     * Przycisk do kopiowania odszyfrowanych danych (jako tekst) do schowka systemowego.
     */
    @FXML
    Button copyDecryptedDataButton;

    /**
     * Przycisk do ładowania zaszyfrowanych danych z pliku.
     */
    @FXML
    Button loadEncryptedButton;

    /**
     * Przycisk do ładowania odszyfrowanych danych (tekstu jawnego) z pliku.
     */
    @FXML
    Button loadDecryptedButton;

    /**
     * Przycisk do zapisywania zaszyfrowanych danych (binarnie) do pliku.
     */
    @FXML
    Button saveEncryptedButton;

    /**
     * Przycisk do zapisywania odszyfrowanych danych (binarnie) do pliku.
     */
    @FXML
    Button saveDecryptedButton;

    /**
     * Przycisk do zapisywania aktualnego klucza (binarnie) do pliku.
     */
    @FXML
    Button keySaveButton;

    /**
     * Przycisk do ładowania klucza (binarnie) z pliku.
     */
    @FXML
    Button keyLoadButton;

    /**
     * Pole tekstowe (TextArea) do wprowadzania lub wyświetlania danych jawnych (odszyfrowanych).
     */
    @FXML
    TextArea dataField;

    /**
     * Pole tekstowe (TextArea) do wyświetlania zaszyfrowanych danych (w formacie hex).
     */
    @FXML
    TextArea encryptedDataField;

    /**
     * Pole tekstowe (TextField) do wprowadzania lub wyświetlania klucza (w formacie hex).
     */
    @FXML
    TextField keyField;

    /**
     * Przycisk radiowy (RadioButton) do wyboru długości klucza 128 bitów.
     */
    @FXML
    RadioButton key128;

    /**
     * Przycisk radiowy (RadioButton) do wyboru długości klucza 192 bity.
     */
    @FXML
    RadioButton key192;

    /**
     * Przycisk radiowy (RadioButton) do wyboru długości klucza 256 bitów.
     */
    @FXML
    RadioButton key256;

    /**
     * Grupa przełączników (ToggleGroup) dla przycisków radiowych wyboru długości klucza.
     * Zapewnia, że tylko jeden przycisk radiowy z tej grupy może być wybrany naraz.
     */
    @FXML
    ToggleGroup key;

    /**
     * Przycisk radiowy (RadioButton) wskazujący, że źródłem/celem danych jest pole tekstowe.
     */
    @FXML
    RadioButton field;

    /**
     * Przycisk radiowy (RadioButton) wskazujący, że źródłem/celem danych jest plik.
     */
    @FXML
    RadioButton file;

    /**
     * Grupa przełączników (ToggleGroup) dla przycisków radiowych wyboru źródła/celu danych (pole/plik).
     */
    @FXML
    ToggleGroup fieldOrFile;

    // --- Zmienne instancji do przechowywania danych ---

    /**
     * Tablica bajtów przechowująca oryginalne (odszyfrowane) dane wczytane z pliku.
     */
    byte[] originalDataFile;
    /**
     * Tablica bajtów przechowująca zaszyfrowane dane wczytane/zapisane do pliku.
     */
    byte[] encryptedDataFile;
    /**
     * Tablica bajtów przechowująca oryginalne (odszyfrowane) dane pochodzące z pola tekstowego `dataField`.
     */
    byte[] originalDataTextField;
    /**
     * Tablica bajtów przechowująca zaszyfrowane dane pochodzące z operacji na polu tekstowym `dataField`.
     */
    byte[] encryptedDataTextField;
    /**
     * Tablica bajtów przechowująca aktualnie używany klucz AES.
     */
    byte[] keyData;

    /**
     * Metoda inicjalizująca kontroler. Wywoływana automatycznie po załadowaniu pliku FXML.
     * Ustawia listenery i obsługę zdarzeń dla kontrolek interfejsu użytkownika.
     */
    @FXML
    public void initialize() {
        // Listener dla grupy przycisków wyboru rozmiaru klucza.
        // Czyści pole tekstowe klucza przy zmianie wybranego rozmiaru.
        key.selectedToggleProperty().addListener((observable, oldValue, newValue) -> keyField.clear());

        // Utworzenie instancji klasy AES do operacji kryptograficznych
        AES aes = new AES();
        // Pobranie systemowego schowka
        final javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        // Utworzenie obiektu do przechowywania zawartości schowka
        final javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();

        // Obsługa kliknięcia przycisku generowania klucza
        keyGenButton.setOnAction(e -> {
            int keyLength = getKeySize(); // Pobranie wybranego rozmiaru klucza
            aes.generateMainKey(keyLength); // Wygenerowanie klucza o danym rozmiarze
            keyData = aes.toByteKey(aes.getMainKey()); // Konwersja klucza BigInteger na bajty i zapisanie
            keyField.setText(aes.bytesToHex(keyData)); // Wyświetlenie klucza w formacie hex w polu tekstowym
        });

        // Obsługa kliknięcia przycisku zapisywania klucza
        keySaveButton.setOnAction(e -> saveButtonAction(keyField, null, 2)); // Wywołanie metody zapisu z opcją 2 (klucz)

        // Obsługa kliknięcia przycisku ładowania klucza
        keyLoadButton.setOnAction(e -> {
            loadButtonAction(null, keyField, 2); // Wywołanie metody ładowania z opcją 2 (klucz)
            String keyHex = keyField.getText(); // Pobranie załadowanego klucza w hex
            // Automatyczne ustawienie odpowiedniego RadioButton na podstawie długości załadowanego klucza
            switch (keyField.getLength() * 4) { // Długość hex * 4 = długość w bitach
                case 128:
                    key128.setSelected(true);
                    break;
                case 192:
                    key192.setSelected(true);
                    break;
                case 256:
                    key256.setSelected(true);
                    break;
                // Domyślnie nie zmienia wyboru, jeśli długość jest nieprawidłowa
            }
            keyField.setText(keyHex); // Ponowne ustawienie tekstu (na wypadek gdyby loadButtonAction go zmieniło)
        });

        // Obsługa kliknięcia przycisku szyfrowania
        encryptButton.setOnAction(e -> {
            try {
                // Sprawdzenie, czy klucz został załadowany/wygenerowany
                if (keyData == null) {
                    encryptedDataField.setText("Error: Key not set or generated.");
                    return;
                }
                String keyHex = aes.bytesToHex(keyData); // Konwersja klucza (bajty) na hex string
                BigInteger keyBigInt = new BigInteger(keyHex, 16); // Konwersja hex string na BigInteger
                aes.setMainKey(keyBigInt); // Ustawienie klucza w instancji AES

                byte[] expectedData; // Tablica na wynik szyfrowania
                // Sprawdzenie, czy dane pochodzą z pola tekstowego czy z pliku
                if (field.isSelected()) {
                    // Pobranie tekstu z pola, konwersja na UTF-8 bajty
                    originalDataTextField = dataField.getText().getBytes(StandardCharsets.UTF_8);
                    // Szyfrowanie danych z pola tekstowego
                    expectedData = aes.encrypt(originalDataTextField, aes.getMainKey());
                    // Zapisanie zaszyfrowanych danych (jako kopia)
                    encryptedDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                } else {
                    // Sprawdzenie, czy dane z pliku zostały załadowane
                    if (originalDataFile == null) {
                        encryptedDataField.setText("Error: Original file data not loaded.");
                        return;
                    }
                    // Szyfrowanie danych z pliku
                    expectedData = aes.encrypt(originalDataFile, aes.getMainKey());
                    // Zapisanie zaszyfrowanych danych (jako kopia)
                    encryptedDataFile = Arrays.copyOf(expectedData, expectedData.length);
                }
                // Wyświetlenie zaszyfrowanych danych w formacie hex
                encryptedDataField.setText(aes.bytesToHex(expectedData));
            } catch (NumberFormatException ex) {
                encryptedDataField.setText("Error: Invalid key format during BigInteger conversion");
            } catch (Exception ex) {
                encryptedDataField.setText("Encryption Error: " + ex.getMessage());
            }
        });

        // Obsługa kliknięcia przycisku ładowania zaszyfrowanych danych
        loadEncryptedButton.setOnAction(e -> loadButtonAction(encryptedDataField, null, 0)); // Wywołanie metody ładowania z opcją 0 (zaszyfrowane)

        // Obsługa kliknięcia przycisku ładowania odszyfrowanych danych
        loadDecryptedButton.setOnAction(e -> loadButtonAction(dataField, null, 1)); // Wywołanie metody ładowania z opcją 1 (odszyfrowane)

        // Obsługa kliknięcia przycisku deszyfrowania
        decryptButton.setOnAction(e -> {
            try {
                // Sprawdzenie, czy klucz został załadowany/wygenerowany
                if (keyData == null) {
                    dataField.setText("Error: Key not set or generated.");
                    return;
                }
                String keyHex = aes.bytesToHex(keyData); // Konwersja klucza (bajty) na hex string
                BigInteger keyBigInt = new BigInteger(keyHex, 16); // Konwersja hex string na BigInteger
                aes.setMainKey(keyBigInt); // Ustawienie klucza w instancji AES

                byte[] expectedData; // Tablica na wynik deszyfrowania
                // Sprawdzenie, czy dane pochodzą z pola tekstowego czy z pliku
                if (field.isSelected()) {
                    // Pobranie zaszyfrowanych danych (hex) z pola tekstowego
                    String encryptedHex = encryptedDataField.getText();
                    if (encryptedHex.isEmpty()) {
                        dataField.setText("Error: Encrypted data field is empty.");
                        return;
                    }
                    // Konwersja hex string na tablicę bajtów
                    byte[] encryptedBytes = aes.hexToBytes(encryptedHex);
                    // Deszyfrowanie danych z pola tekstowego
                    expectedData = aes.decrypt(encryptedBytes, aes.getMainKey());
                    // Zapisanie odszyfrowanych danych (jako kopia)
                    originalDataTextField = Arrays.copyOf(expectedData, expectedData.length);
                    // Wyświetlenie odszyfrowanych danych jako tekst UTF-8
                    dataField.setText(new String(expectedData, StandardCharsets.UTF_8));
                } else {
                    // Sprawdzenie, czy zaszyfrowane dane z pliku zostały załadowane
                    if (encryptedDataFile == null) {
                        dataField.setText("Error: Encrypted file data not loaded.");
                        return;
                    }
                    // Deszyfrowanie danych z pliku
                    expectedData = aes.decrypt(encryptedDataFile, aes.getMainKey());
                    // Zapisanie odszyfrowanych danych (jako kopia)
                    originalDataFile = Arrays.copyOf(expectedData, expectedData.length);
                    // Wyświetlenie odszyfrowanych danych w formacie hex (alternatywnie można by spróbować jako tekst)
                    // UWAGA: Wyświetlanie binarnych danych jako hex może być bezpieczniejsze niż próba interpretacji jako tekst,
                    //        jeśli oryginalny plik nie był tekstem.
                    dataField.setText(aes.bytesToHex(expectedData));
                }

            } catch (NumberFormatException ex) {
                // Błąd konwersji klucza lub zaszyfrowanych danych hex
                dataField.setText("Error: Invalid key or encrypted data hex format.");
            } catch (IllegalArgumentException ex) {
                // Błąd np. nieprawidłowa długość hex, nieprawidłowy rozmiar klucza itp.
                dataField.setText("Error: " + ex.getMessage());
            } catch (Exception ex) {
                dataField.setText("Decryption Error: " + ex.getMessage());
                ex.printStackTrace(); // Warto logować pełny ślad stosu dla diagnozy
            }
        });

        // Obsługa kliknięcia przycisku kopiowania zaszyfrowanych danych
        copyEncryptedDataButton.setOnAction(e -> {
            content.putString(encryptedDataField.getText()); // Umieszczenie tekstu z pola w obiekcie zawartości
            clipboard.setContent(content); // Ustawienie zawartości schowka
        });

        // Obsługa kliknięcia przycisku kopiowania odszyfrowanych danych
        copyDecryptedDataButton.setOnAction(e -> {
            content.putString(dataField.getText()); // Umieszczenie tekstu z pola w obiekcie zawartości
            clipboard.setContent(content); // Ustawienie zawartości schowka
        });

        // Obsługa kliknięcia przycisku zapisywania zaszyfrowanych danych
        saveEncryptedButton.setOnAction(e -> saveButtonAction(null, encryptedDataField, 0)); // Wywołanie metody zapisu z opcją 0 (zaszyfrowane)

        // Obsługa kliknięcia przycisku zapisywania odszyfrowanych danych
        saveDecryptedButton.setOnAction(e -> saveButtonAction(null, dataField, 3)); // Wywołanie metody zapisu z opcją 3 (odszyfrowane)
    }

    /**
     * Obsługuje ładowanie danych (zaszyfrowanych, odszyfrowanych lub klucza) z pliku wybranego przez użytkownika.
     * Aktualizuje odpowiednie pole (TextArea lub TextField) oraz zmienną przechowującą dane binarne.
     *
     * @param textArea  Pole TextArea do zaktualizowania (jeśli dotyczy). Może być null.
     * @param textField Pole TextField do zaktualizowania (jeśli dotyczy). Może być null.
     * @param option    Określa typ ładowanych danych: 0 - zaszyfrowane, 1 - odszyfrowane, 2 - klucz.
     */
    private void loadButtonAction(TextArea textArea, TextField textField, int option) {
        // Utworzenie i konfiguracja okna dialogowego wyboru pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        // Ustawienie tytułu okna w zależności od typu ładowanych danych
        switch (option) {
            case 0:
                fileChooser.setTitle("Wybierz plik z zaszyfrowanymi danymi");
                break;
            case 1:
                fileChooser.setTitle("Wybierz plik z odszyfrowanymi danymi");
                break;
            case 2: // Zmieniono z 3 na 2 dla klucza, zgodnie z użyciem w kodzie
                fileChooser.setTitle("Wybierz plik z kluczem");
                break;
            default:
                fileChooser.setTitle("Wybierz plik");
                break;
        }
        // Dodanie filtra plików (opcjonalne, tutaj "Wszystkie pliki")
        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        // Wyświetlenie okna dialogowego i oczekiwanie na wybór pliku przez użytkownika
        File selectedFile = fileChooser.showOpenDialog(null); // null oznacza brak okna-rodzica

        // Jeśli użytkownik wybrał plik
        if (selectedFile != null) {
            try {
                // Wczytanie całej zawartości pliku jako tablicy bajtów
                byte[] data = Files.readAllBytes(selectedFile.toPath());
                // Zapisanie wczytanych danych do odpowiedniej zmiennej binarnej
                // i ustawienie RadioButton 'file' jako aktywnego źródła
                switch (option) {
                    case 0: // Zaszyfrowane
                        encryptedDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true); // Ustawienie źródła na plik
                        break;
                    case 1: // Odszyfrowane
                        originalDataFile = Arrays.copyOf(data, data.length);
                        file.setSelected(true); // Ustawienie źródła na plik
                        break;
                    case 2: // Klucz
                        keyData = Arrays.copyOf(data, data.length);
                        // Nie zmieniamy RadioButton file/field dla klucza
                        break;
                    default:
                        // Nieznana opcja, nic nie rób z danymi binarnymi
                        break;
                }
                // Utworzenie instancji AES do użycia metody bytesToHex
                AES aes = new AES();
                // Wyświetlenie wczytanych danych w formacie hex w odpowiednim polu UI
                if (textArea != null) {
                    textArea.setText(aes.bytesToHex(data));
                } else if (textField != null) { // Sprawdzenie czy textField nie jest null
                    textField.setText(aes.bytesToHex(data));
                }
            } catch (IOException ex) {
                // Obsługa błędu wejścia/wyjścia podczas czytania pliku
                String errorMessage = "File Read Error: " + ex.getMessage();
                if (textArea != null) {
                    textArea.setText(errorMessage);
                } else if (textField != null) {
                    textField.setText(errorMessage);
                }
            }
        }
    }

    /**
     * Obsługuje zapisywanie danych (zaszyfrowanych, odszyfrowanych lub klucza) do pliku wybranego przez użytkownika.
     * Pobiera dane z odpowiedniej zmiennej binarnej w zależności od wybranego źródła (pole/plik).
     *
     * @param textField Pole TextField, z którego potencjalnie mogą pochodzić dane (nieużywane w tej implementacji do pobierania danych do zapisu). Może być null.
     * @param textArea  Pole TextArea, z którego potencjalnie mogą pochodzić dane (nieużywane w tej implementacji do pobierania danych do zapisu). Może być null.
     * @param option    Określa typ zapisywanych danych: 0 - zaszyfrowane, 2 - klucz, 3 - odszyfrowane.
     */
    private void saveButtonAction(TextField textField, TextArea textArea, int option) {
        // Utworzenie i konfiguracja okna dialogowego zapisu pliku
        javafx.stage.FileChooser fileChooser = new javafx.stage.FileChooser();
        // Ustawienie tytułu okna w zależności od typu zapisywanych danych
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
        // Dodanie filtra plików (opcjonalne)
        fileChooser.getExtensionFilters().addAll(
                new javafx.stage.FileChooser.ExtensionFilter("Wszystkie pliki", "*.*")
        );
        // Wyświetlenie okna dialogowego i oczekiwanie na wybór lokalizacji zapisu przez użytkownika
        File selectedFile = fileChooser.showSaveDialog(null);

        // Jeśli użytkownik wybrał plik
        if (selectedFile != null) {
            try {
                byte[] dataToSave = null; // Tablica na dane binarne do zapisania

                // Wybór odpowiednich danych binarnych do zapisania na podstawie opcji i źródła (pole/plik)
                switch (option) {
                    case 0: // Zaszyfrowane dane
                        // Jeśli wybrano źródło 'pole' i dane zaszyfrowane z pola istnieją
                        if (field.isSelected() && encryptedDataTextField != null) {
                            dataToSave = encryptedDataTextField;
                        }
                        // W przeciwnym razie (lub jeśli wybrano 'plik'), użyj danych zaszyfrowanych z pliku (jeśli istnieją)
                        else if (encryptedDataFile != null) {
                            dataToSave = encryptedDataFile;
                        }
                        break;
                    case 2: // Klucz
                        if (keyData != null) {
                            dataToSave = keyData;
                        }
                        break;
                    case 3: // Odszyfrowane dane
                        // Jeśli wybrano źródło 'pole' i dane odszyfrowane z pola istnieją
                        if (field.isSelected() && originalDataTextField != null) {
                            dataToSave = originalDataTextField;
                        }
                        // W przeciwnym razie (lub jeśli wybrano 'plik'), użyj danych odszyfrowanych z pliku (jeśli istnieją)
                        else if (originalDataFile != null) {
                            dataToSave = originalDataFile;
                        }
                        break;
                }

                // Jeśli udało się wybrać dane do zapisania
                if (dataToSave != null) {
                    // Zapisanie danych binarnych do wybranego pliku
                    java.nio.file.Files.write(selectedFile.toPath(), dataToSave);
                } else {
                    // Jeśli nie ma danych do zapisania (np. nic nie zostało zaszyfrowane/odszyfrowane/załadowane)
                    throw new IOException("No data available to save for the selected option/source.");
                }

            } catch (IOException ex) {
                // Obsługa błędu wejścia/wyjścia podczas zapisu pliku
                String errorMessage = "File Save Error: " + ex.getMessage();
                // Wyświetlenie błędu w polu tekstowym (jeśli dostępne)
                if (textArea != null) {
                    textArea.setText(errorMessage);
                } else if (textField != null) {
                    textField.setText(errorMessage);
                } else {
                    // Jeśli żadne pole nie jest dostępne, można wyświetlić alert
                    Alert alert = new Alert(Alert.AlertType.ERROR);
                    alert.setTitle("Save Error");
                    alert.setHeaderText(null);
                    alert.setContentText(errorMessage);
                    alert.showAndWait();
                }
            }
        }
    }

    /**
     * Odczytuje stan przycisków radiowych (key128, key192, key256)
     * i zwraca wybraną długość klucza w bitach.
     *
     * @return Wybrana długość klucza (128, 192 lub 256). Domyślnie 128, jeśli żaden nie jest wybrany.
     */
    private int getKeySize() {
        if (key128.isSelected()) {
            return 128;
        } else if (key192.isSelected()) {
            return 192;
        } else if (key256.isSelected()) {
            return 256;
        }
        // Zwraca domyślny rozmiar, jeśli żaden przycisk nie jest zaznaczony
        // (chociaż ToggleGroup powinien temu zapobiegać, jeśli jest poprawnie skonfigurowany)
        return 128;
    }
}
