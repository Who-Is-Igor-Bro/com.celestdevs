package com.celestdevs

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureStorage {

    private static final String TAG = "SecureStorage";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final int GCM_TAG_LENGTH = 128;
    private static final String KEY_ALIAS = "SecureStorageAlias";
    private static final String PREF_NAME = "secure_prefs";

    private final Context context;

    public SecureStorage(Context context) {
        this.context = context;
        createKeyIfNotExists();
    }

    private void createKeyIfNotExists() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", ANDROID_KEY_STORE);
                KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256) // 256 bits
                        .build();
                keyGenerator.init(keySpec);
                keyGenerator.generateKey();

            }
        } catch (Exception e) {
            throw new SecurityException("Erro ao inicializar o Android Keystore.", e);
        }
    }

    private String encrypt(String plainText) throws Exception {
        if (plainText == null || plainText.isEmpty()) {
            throw new IllegalArgumentException("O texto para criptografar não pode ser nulo ou vazio.");
        }

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        SecretKey key = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] iv = cipher.getIV();
        byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.encodeToString(iv, Base64.NO_WRAP) + ":" + Base64.encodeToString(encryptedData, Base64.NO_WRAP);
    }

    private String decrypt(String encryptedData) throws Exception {
        if (encryptedData == null || !encryptedData.contains(":")) {
            throw new IllegalArgumentException("Dados criptografados inválidos.");
        }

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        SecretKey key = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance(AES_MODE);

        String[] parts = encryptedData.split(":");
        byte[] iv = Base64.decode(parts[0], Base64.NO_WRAP);
        byte[] cipherData = Base64.decode(parts[1], Base64.NO_WRAP);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decryptedData = cipher.doFinal(cipherData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public void saveSecureData(String key, String value) {
        try {
            if (key == null || key.isEmpty() || value == null || value.isEmpty()) {
                throw new IllegalArgumentException("A chave ou valor não pode ser nulo ou vazio.");
            }

            String encryptedValue = encrypt(value);

            SharedPreferences preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString(key, encryptedValue);
            editor.apply();
        } catch (Exception e) {          
            throw new SecurityException("Erro ao armazenar dados de forma segura.", e);
        }
    }

    public String getSecureData(String key) {
        try {
            if (key == null || key.isEmpty()) {
                throw new IllegalArgumentException("A chave não pode ser nula ou vazia.");
            }

            SharedPreferences preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
            String encryptedValue = preferences.getString(key, null);

            if (encryptedValue == null) {
                return null;
            }

            return decrypt(encryptedValue);
        } catch (Exception e) {         
            throw new SecurityException("Erro ao recuperar dados de forma segura.", e);
        }
    }

    public void removeSecureData(String key) {
        SharedPreferences preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key).apply();
    }

    public void clearSecureData() {
        SharedPreferences preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear().apply();
    }

    public boolean contains(String key) {
        SharedPreferences preferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        boolean contains = preferences.contains(key);
        return contains;
    }
  }
