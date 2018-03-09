package com.abel.aes;

import org.apache.commons.cli.*;
//import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

/**
 * Created by sunzqc on 2017/7/7 12:23.
 * AES Encryption
 */
public class MyAES {

    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String IV = "0314021704193130"; //使用CBC模式需要一个初始向量 cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec); EBC模式不需要

    private static final Integer LENGTH_128 = 128;
    private static final String DEFAULTKEY = "!@#$%^&*()QWERTY";
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private static byte[] encrypt(String content, String userKey, Integer length) {
        try {

            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes("utf-8"));

            SecretKeySpec key = getSecretKeySpec(userKey, length);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(byteContent);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException | UnsupportedEncodingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKeySpec getSecretKeySpec(String userKey, Integer length) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);    // 由于每次SecureRandom 产生随机的key 解密时会出现异常
        keyGenerator.init(length, new SecureRandom(userKey.getBytes("utf-8")));
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] enCodeFormat = secretKey.getEncoded();
        return new SecretKeySpec(userKey.getBytes(), KEY_ALGORITHM);
//        return new SecretKeySpec(enCodeFormat, KEY_ALGORITHM);

    }

    private static byte[] decrypt(byte[] content, String userKey, Integer length) throws UnsupportedEncodingException {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            SecretKeySpec key = getSecretKeySpec(userKey, length);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);// 初始化
            return cipher.doFinal(content); // 加密
        } catch (NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void decryptFromFile(String srcFile, String destFile, String userKey) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            SecretKeySpec key = new SecretKeySpec(userKey.getBytes(), KEY_ALGORITHM);
            Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM);// 创建密码器
            encryptCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);// 初始化
            BufferedReader bufferedReader = new BufferedReader(new FileReader(srcFile));

            FileWriter decryptFileWriter = new FileWriter(destFile);
            String strLine;
            while ((strLine = bufferedReader.readLine()) != null) {
//                String tmpLine = new String(encryptCipher.doFinal(Base64.decodeBase64(strLine)), "utf-8");
                String tmpLine = new String(encryptCipher.doFinal(DECODER.decode(strLine)), "utf-8");
                decryptFileWriter.write(tmpLine + "\n");
            }
            bufferedReader.close();
            decryptFileWriter.close();


        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                IOException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    private static void encryptFromFile(String srcFile, String destFile, String userKey) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            SecretKeySpec key = new SecretKeySpec(userKey.getBytes(), KEY_ALGORITHM);
            Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM);// 创建密码器
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);// 初始化
            BufferedReader bufferedReader = new BufferedReader(new FileReader(srcFile));

            FileWriter encryptFileWriter = new FileWriter(destFile);
            String strLine;
            while ((strLine = bufferedReader.readLine()) != null) {
//                String tmpLine = Base64.encodeBase64String(encryptCipher.doFinal(strLine.getBytes("utf-8")));
                String tmpLine = ENCODER.encodeToString(encryptCipher.doFinal(strLine.getBytes("utf-8")));
                encryptFileWriter.write(tmpLine + "\n");
            }
            bufferedReader.close();
            encryptFileWriter.close();


        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                IOException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    private static void decryptBinaryFile(String srcFile, String destFile, String userKey) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            SecretKeySpec key = new SecretKeySpec(userKey.getBytes(), KEY_ALGORITHM);
            Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM);// 创建密码器
            encryptCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);// 初始化
            OutputStream decryptFileWriter = new FileOutputStream(destFile);


            BufferedReader bufferedReader = new BufferedReader(new FileReader(srcFile));
            String strLine;
            while ((strLine = bufferedReader.readLine()) != null) {
                try {
                    decryptFileWriter.write(encryptCipher.doFinal(DECODER.decode(strLine)));
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }
            bufferedReader.close();


            decryptFileWriter.close();


        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                IOException e) {
            e.printStackTrace();
        }
    }

    private static void encryptBinaryFile(String srcFile, String destFile, String userKey) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV.getBytes());
            SecretKeySpec key = new SecretKeySpec(userKey.getBytes(), KEY_ALGORITHM);
            Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGORITHM);// 创建密码器
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);// 初始化
            InputStream inputStream = new FileInputStream(srcFile);
            byte[] in = new byte[10240000];
            FileWriter encryptFileWriter = new FileWriter(destFile);
            int l = -1;
            while ((l = inputStream.read(in)) != -1) {
                String tmpLine = ENCODER.encodeToString(encryptCipher.doFinal(in, 0, l));
                encryptFileWriter.write(tmpLine + "\n");

            }
            encryptFileWriter.close();
            inputStream.close();


        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                NoSuchPaddingException |
                InvalidAlgorithmParameterException |
                IOException |
                BadPaddingException |
                IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException, ParseException {

        CommandLineParser parser = new DefaultParser();
        Options options = new Options();
        options.addOption("h", "help", false,
                "\nusage: \n" +
                        "FileMode: java -jar ***.jar -m mode -t type -i inputFileName -o outputFileName -k userKey(16位)\n" +
                        "TextMode: java -jar ***.jar -m mode -t type -c content -k userKey(16位)\n" +
                        "TextFileMode: java -jar ***.jar -m mode -t type -i inputFileName -o outputFileName -k userKey(16位)\n");
        options.addOption("m", "mode", true, "e encrypt mode, d decrypt mode!");
        options.addOption("i", "input", true, "input file path...!");
        options.addOption("o", "output", true, "output file path...!");
        options.addOption("c", "content", true, "text to operation!");
        options.addOption("t", "type", true, "type to chose b(binary) c(content) f(text file)");
        options.addOption("k", "key", true, "user key...!");

        // Parse the program arguments
        CommandLine commandLine = parser.parse(options, args);


        if (commandLine.hasOption('h') || !commandLine.hasOption('t') || !commandLine.hasOption('m')) {
            Collection<Option> ops = options.getOptions();
            for (Option v :
                    ops) {
                System.out.println("-" + v.getOpt() + " --" + v.getLongOpt() + " description:" + v.getDescription());
            }

            System.exit(0);
        }

        String userKey = DEFAULTKEY;
        if (commandLine.hasOption('k')) {
            userKey = commandLine.getOptionValue('k');
        }

        if (commandLine.getOptionValue('t').equals("c")) {


            if (commandLine.getOptionValue('m').equals("e")) {
                byte[] res = encrypt(commandLine.getOptionValue('c'), userKey, LENGTH_128);
                System.out.println(String.format("The origin String is %s The encrypt String is %s",
                        commandLine.getOptionValue('c'),
                        ENCODER.encodeToString(res)));
            } else {
                byte[] res = decrypt(DECODER.decode(commandLine.getOptionValue('c')), userKey, LENGTH_128);
                System.out.println(String.format("The origin String is %s The decrypt String is %s",
                        commandLine.getOptionValue('c'),
                        new String(res, "utf-8")));
            }
        } else if (commandLine.getOptionValue('t').equals("b")) {

            String inputFile = commandLine.getOptionValue('i');
            String outputFile = commandLine.getOptionValue('o');
            if (commandLine.getOptionValue('m').equals("e")) {
                encryptBinaryFile(inputFile, outputFile, userKey);
            } else {
                decryptBinaryFile(inputFile, outputFile, userKey);
            }
        } else if (commandLine.getOptionValue('t').equals("f")) {
            String inputFile = commandLine.getOptionValue('i');
            String outputFile = commandLine.getOptionValue('o');
            if (commandLine.getOptionValue('m').equals("e")) {
                encryptFromFile(inputFile, outputFile, userKey);
            } else {
                decryptFromFile(inputFile, outputFile, userKey);
            }
        }


    }

}
