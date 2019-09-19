package pt.ulisboa.tecnico.meic.sirs;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * Implementation of the RSA cipher as a ByteArrayMixer
 */
public class RSACipherByteArrayMixer implements ByteArrayMixer {

    private String keyFile;
    private String mode;
    private int opmode;
    private final int BLOCKSIZE = 117;

    public void setParameters(String keyFile, String mode) {
        this.keyFile = keyFile;
        this.mode = mode;
    }

    public RSACipherByteArrayMixer(int opmode) {
        this.opmode = opmode;
    }


    @Override
    public byte[] mix(byte[] byteArray, byte[] byteArray2) {

        try {
            Key key = null;

            if(opmode == Cipher.DECRYPT_MODE)
                key = RSAKeyGenerator.readRSA(keyFile, true);
            else
                key = RSAKeyGenerator.readRSA(keyFile, false);

            // get a DES cipher object and print the provider
            Cipher cipher = Cipher.getInstance("RSA/" + mode + "/PKCS1Padding");
            System.out.println(cipher.getProvider().getInfo());


            System.out.println("Ciphering ...");
            if(!mode.equals("ECB")) {
                // look! A null IV!
                cipher.init(this.opmode, key, new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
            } else {
                cipher.init(this.opmode, key);
            }

            if(opmode == Cipher.DECRYPT_MODE)
                return decrypt(byteArray, cipher);
            else
                return encrypt(byteArray, cipher);

        } catch (Exception e) {
            // Pokemon exception handling!
            e.printStackTrace();
        }

        return null;

    }

    private byte[] encrypt(byte[] byteArray, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        int len = byteArray.length;
        int numberOfBlocks = len / this.BLOCKSIZE;
        byte[] ciphertext = new byte[numberOfBlocks*128];

        // public static void arraycopy (Object src, int srcPos, Object dest, int destPos, int length)
        for(int i = 0; i < numberOfBlocks; i++) {
            byte[] encBlock = new byte[117];
            System.arraycopy(byteArray, i*117, encBlock, 0, 117);
            System.out.println(encBlock.toString());
            byte[] tmp = cipher.doFinal(encBlock);

            System.arraycopy(tmp, 0, ciphertext, i*128, 128);

        }
        return ciphertext;
    }

    private byte[] decrypt(byte[] byteArray, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        int len = byteArray.length;
        int numberOfBlocks = len / 128;
        byte[] plaintext = new byte[numberOfBlocks*117];

        // public static void arraycopy (Object src, int srcPos, Object dest, int destPos, int length)
        for(int i = 0; i < numberOfBlocks; i++) {
            byte[] encBlock = new byte[128];
            System.arraycopy(byteArray, i*128, encBlock, 0, 117);
            System.out.println(encBlock.toString());
            byte[] tmp = cipher.doFinal(encBlock);

            System.arraycopy(tmp, 0, plaintext, i*117, 117);

        }
        return plaintext;
    }
    //private int getNumberOfBlocks(){

    //}
}
