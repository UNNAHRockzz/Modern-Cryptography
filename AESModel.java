import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import java.util.Scanner;

public class AESModel {
    public static void encryptDecrypt(String password, int cipherMode, String inputFile, String outputFile,
            byte[] salt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileContent = readFileContent(inputFile);

        SecretKey secretKey = generateSecretKey(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        byte[] encryptedBytes = null;
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            encryptedBytes = cipher.doFinal(fileContent);
        } else if (cipherMode == Cipher.DECRYPT_MODE) {
            // Extract the IV from the beginning of the file content
            System.arraycopy(fileContent, 0, iv, 0, iv.length);
            ivParams = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            encryptedBytes = cipher.doFinal(fileContent, iv.length, fileContent.length - iv.length);
        }

        writeFileContent(outputFile, encryptedBytes);
    }

    private static SecretKey generateSecretKey(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private static byte[] readFileContent(String filePath) throws IOException {
        try (InputStream is = new FileInputStream(filePath)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            return bos.toByteArray();
        }
    }

    private static void writeFileContent(String filePath, byte[] content) throws IOException {
        try (OutputStream os = new FileOutputStream(filePath)) {
            os.write(content);
        }
    }

    public static void main(String[] args) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);

            Scanner sc = new Scanner(System.in);
            int choice = 0;

            do {
                System.out.println("Please select an option:");
                System.out.println("1. Encrypt a file");
                System.out.println("2. Decrypt a file");
                System.out.println("3. Exit");
                System.out.print("Enter your choice: ");
                choice = sc.nextInt();

                if (choice == 1 || choice == 2) {
                    JFileChooser fileChooser = new JFileChooser();
                    JFrame parentFrame = new JFrame();
                    int fileSelection = fileChooser.showOpenDialog(parentFrame);

                    if (fileSelection == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        String inputFile = selectedFile.getAbsolutePath();

                        String outputFile;
                        if (choice == 1) {
                            outputFile = "encrypted.txt";
                            System.out.print("Enter password for encryption: ");
                        } else {
                            outputFile = "decrypted.txt";
                            System.out.print("Enter password for decryption: ");
                        }

                        String password = sc.next();
                        try {
                            encryptDecrypt(password, choice, inputFile, outputFile, salt);
                            if (choice == 1) {
                                System.out.println("Encryption complete");
                            } else {
                                System.out.println("Decryption complete");
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        System.out.println("No file selected.");
                    }
                } else if (choice > 3) {
                    System.out.println("Invalid choice. Exiting...");
                }
            } while (choice != 3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
