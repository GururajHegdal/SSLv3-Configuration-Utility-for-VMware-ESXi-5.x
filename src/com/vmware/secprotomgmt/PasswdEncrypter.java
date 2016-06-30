/**
 * Utility program to encrypt and decrypt the passwords with 128-bit AES encryption
 * Key would be dynamic as entered by the user.
 *
 * Copyright (c) 2016
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * @author Gururaja Hegdal (ghegdal@vmware.com)
 * @version 1.0
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package com.vmware.secprotomgmt;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class PasswdEncrypter
{
    private final static int STD_KEYSIZE = 16;
    private final static String INIT_VECTOR = "ghegdal!4#VMware";
    private final static String[] PADDING_ARRAY = { "0", ")", "1", "!", "2", "@", "3", "#", "4", "$", "5", "&", "6",
        "*", "7", "(" };

    /**
     * Encrypt the value with key provided
     */
    private static String encrypt(String key, String value)
    {
        String encryptedString = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            encryptedString = Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            System.out.println("Caught exception while encrypting string : " + value);
            ex.printStackTrace();
        }

        return encryptedString;
    }

    /**
     * Decrypt the encrypted value with provided key
     */
    public static
    String decrypt(String key, String encryptedValue)
    {
        String decryptedString = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            decryptedString = new String(cipher.doFinal(Base64.decodeBase64(encryptedValue)));

        } catch (Exception ex) {
            System.out.println("Caught exception while decrypting string");
            ex.printStackTrace();
        }

        return decryptedString;
    }

    /**
     * Decrypt the original password by using the secretKey and encrypted string
     */
    public static
    List<String> decryptValueWithUserEnteredKey(String encryptedStr)
    {
        boolean validVals = false;
        String secretKey = "";
        List<String> decryptedStrList = null;

        try {
            Scanner in = new Scanner(System.in);
            System.out
                .print("For decrypting ESXi password, Please Enter SecretKey (16 characters) that was used earlier: ");

            secretKey = in.nextLine().trim();
            if (secretKey.length() == STD_KEYSIZE) {
                validVals = true;
            } else {
                System.out.println("Invalid secretKey, please try again");
            }

            // reset the scanner
            in.reset();

            // Go for encrypting the password with provided SecretKey
            if (validVals) {
                if ((!encryptedStr.equals(""))) {
                    // Validate that on decrypt, you would receive the same
                    // password
                    String tempDecryptedStr = decrypt(secretKey, encryptedStr);
                    if (!tempDecryptedStr.equals("")) {
                        System.out
                            .println("Successfully decrypted ESXi password with provided secretKey: " + secretKey);
                        decryptedStrList = new ArrayList<String>();
                        decryptedStrList.add(secretKey);
                        decryptedStrList.add(tempDecryptedStr);
                    } else {
                        System.err.println(
                            "Failed to decrypt the encrypted string: " + encryptedStr + ", with provided secretkey: "
                                + secretKey);
                        System.err.println(
                            "Please review the secretkey provided. It has to be the same as the one provided during"
                            + " encrypted the original password");

                    }
                } else {
                    System.err.println("Encrypted Value provided is empty/null");
                }
            }
        } catch (Exception e) {
            System.err.println("Caught exception while decrypting ESXi password");
            decryptedStrList = null;
        }

        return decryptedStrList;
    }

    /**
     * Entry point into this Class
     */
    public static void main(String[] args)
    {
        boolean validVals = false;
        String secretKey = "";
        String esxi_pwd = "";
        System.out.println("This Utility program would help you to ENCRYPT password with a given secretKey");
        Scanner in = new Scanner(System.in);
        System.out.print("Enter ESXi host password:");
        esxi_pwd = in.nextLine().trim();
        if (esxi_pwd.equals("")) {
            System.err.println("Invalid password entry, please try again ...");
        } else {
            System.out.println(
                "Enter SecretKey to be used for encrypting ESXi Password. MUST NOT exceed 16 characters,"
                    + "and should be different from ESXi password; for better security");
            secretKey = in.nextLine().trim();

            if (secretKey.equals("")) {
                System.err.println("Invalid SecretKey entry, please try again ...");
            } else if (secretKey.length() > STD_KEYSIZE) {
                System.err.println("SecretKey can NOT exceed 16 characters. Please try again");
            } else if (secretKey.length() < STD_KEYSIZE) {
                int remainingChars = STD_KEYSIZE - secretKey.length();
                while (remainingChars > 0) {
                    secretKey = secretKey + PADDING_ARRAY[remainingChars];
                    --remainingChars;
                }
            }
            if (secretKey.length() == STD_KEYSIZE) {
                validVals = true;
            }
        }

        // Go for encrypting the password with provided SecretKey
        if (validVals) {
            String encryptedStr = encrypt(secretKey, esxi_pwd);
            if ((!encryptedStr.equals(""))) {
                // Validate that on decrypt, you would receive the same password
                String decryptedStr = decrypt(secretKey, encryptedStr);
                if (!decryptedStr.equals("")) {
                    if (decryptedStr.equals(esxi_pwd)) {
                        System.out.println("Successfully encrypted the password");
                        System.out.println("----------------------------------------------------------------");
                        System.out.println("ESXi Password: " + esxi_pwd);
                        System.out.println("Your Secret key: " + secretKey);
                        System.out.println("Encrypted String for the password: " + encryptedStr);
                        System.out.println("[TESTED] Decrypted string: " + decryptedStr);
                        System.out.println("----------------------------------------------------------------");
                        System.out.println("**** NOTE ****");
                        System.out.println(
                            "Please remember the secretkey, which is later needed when running TLS-Configuration script");
                    } else {
                        System.err.println("Failed to match the password with decrypted string");
                    }
                } else {
                    System.err.println("Failed to decrypt the encrypted string");
                }
            } else {
                System.err.println("Failed to encrypt the provided password");
            }
        }
        // close the scanner
        in.close();
    }
}