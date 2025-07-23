package org.IS_Project;

import org.IS_Project.auth.AuthService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ChatClient extends JFrame {

    // Networking
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;

    // Crypto
    private KeyPair rsaKeyPair;
    private Map<String, PublicKey> clientPublicKeys = new HashMap<>();
    private Map<String, SecretKey> sessionKeys = new HashMap<>();

    // UI
    private DefaultListModel<String> clientListModel = new DefaultListModel<>();
    private JList<String> clientListUI = new JList<>(clientListModel);
    private JTextArea chatArea = new JTextArea();
    private JTextField messageField = new JTextField();
    private JButton sendButton = new JButton("Send");
    private JLabel statusLabel = new JLabel("Not connected");

    private String myName;
    private String chattingWith = null;

    public ChatClient() {
        super("Secure RSA Chat Client");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(800, 600);
        setLocationRelativeTo(null);

        // Layout
        JSplitPane splitPane = new JSplitPane();
        splitPane.setDividerLocation(200);

        // Left panel: client list
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        leftPanel.add(new JLabel("Online Clients:"), BorderLayout.NORTH);
        clientListUI.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        leftPanel.add(new JScrollPane(clientListUI), BorderLayout.CENTER);

        splitPane.setLeftComponent(leftPanel);

        // Right panel: chat + message input
        JPanel rightPanel = new JPanel(new BorderLayout(5, 5));
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        rightPanel.add(new JScrollPane(chatArea), BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        rightPanel.add(inputPanel, BorderLayout.SOUTH);

        rightPanel.add(statusLabel, BorderLayout.NORTH);

        splitPane.setRightComponent(rightPanel);

        add(splitPane);

        // Disable send until connected + chattingWith selected
        sendButton.setEnabled(false);

        // Events
        clientListUI.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                chattingWith = clientListUI.getSelectedValue();
                chatArea.setText("");
                if (chattingWith != null && chattingWith.equals(myName)) {
                    chattingWith = null;
                    sendButton.setEnabled(false);
                    statusLabel.setText("Cannot chat with yourself.");
                    return;
                }
                if (chattingWith != null) {
                    sendButton.setEnabled(true);
                    statusLabel.setText("Chatting with " + chattingWith);
                    // If no session key, create and send
                    if (!sessionKeys.containsKey(chattingWith)) {
                        createAndSendSessionKey(chattingWith);
                    }
                }
            }
        });

        sendButton.addActionListener(e -> {
            sendMessage();
        });

        messageField.addActionListener(e -> sendMessage());

        // Ask username and connect
        askUsernameAndConnect();
    }

    private void askUsernameAndConnect() {
        // Choose Sign Up or Login
        String[] options = {"Sign Up", "Login"};
        int choice = JOptionPane.showOptionDialog(this, "Welcome! Please choose:", "Authentication",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

        if (choice == -1) { // user closed dialog
            System.exit(0);
        }

        String username = JOptionPane.showInputDialog(this, "Enter username:");
        if (username == null || username.trim().isEmpty()) {
            System.exit(0);
        }
        String password = JOptionPane.showInputDialog(this, "Enter password:");
        if (password == null || password.trim().isEmpty()) {
            System.exit(0);
        }

        try {
            // Generate RSA key pair
            rsaKeyPair = generateRSAKeyPair();
            String pubKeyStr = publicKeyToString(rsaKeyPair.getPublic());

            boolean success = false;
            if (choice == 0) { // Sign Up
                success = AuthService.signup(username, password, pubKeyStr);
                if (!success) {
                    JOptionPane.showMessageDialog(this, "Username already exists. Restart and try again.", "Error", JOptionPane.ERROR_MESSAGE);
                    System.exit(0);
                }
            } else { // Login
                success = AuthService.login(username, password);
                if (!success) {
                    JOptionPane.showMessageDialog(this, "Invalid username or password.", "Error", JOptionPane.ERROR_MESSAGE);
                    System.exit(0);
                }
            }

            // Auth succeeded
            myName = username;

            // Connect to server as before
            socket = new Socket("localhost", 12345);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            // Register with server
            Map<String, String> reg = new HashMap<>();
            reg.put("name", myName);
            reg.put("publicKey", pubKeyStr);
            out.writeObject(reg);
            out.flush();

            Object resp = in.readObject();
            if (resp instanceof String) {
                if ("NAME_TAKEN".equals(resp)) {
                    JOptionPane.showMessageDialog(this, "Name already taken on server. Restart.", "Error", JOptionPane.ERROR_MESSAGE);
                    System.exit(0);
                } else if ("REGISTERED".equals(resp)) {
                    statusLabel.setText("Registered as " + myName);
                }
            }

            // Start listening
            new Thread(this::listenFromServer).start();

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Cannot connect to server: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
    }


    private void listenFromServer() {
        try {
            while (true) {
                Object obj = in.readObject();
                if (obj instanceof Map) {
                    Map<String, Object> msg = (Map<String, Object>) obj;
                    String type = (String) msg.get("type");
                    if ("CLIENT_LIST".equals(type)) {
                        Map<String, String> list = (Map<String, String>) msg.get("list");
                        SwingUtilities.invokeLater(() -> updateClientList(list));
                    } else if ("KEY_EXCHANGE".equals(type)) {
                        handleKeyExchange(msg);
                    } else if ("MESSAGE".equals(type)) {
                        handleIncomingMessage(msg);
                    }
                } else if (obj instanceof String) {
                    // Server messages like errors
                    String s = (String) obj;
                    System.out.println("Server says: " + s);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("Disconnected from server.");
            System.exit(0);
        }
    }

    private void updateClientList(Map<String, String> list) {
        clientPublicKeys.clear();
        clientListModel.clear();
        for (Map.Entry<String, String> e : list.entrySet()) {
            String name = e.getKey();
            if (name.equals(myName)) continue; // Skip self
            try {
                clientPublicKeys.put(name, stringToPublicKey(e.getValue()));
                clientListModel.addElement(name);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void createAndSendSessionKey(String target) {
        try {

            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey aesKey = keyGen.generateKey();
            byte[] aesKeyBytes = aesKey.getEncoded();

            // Sign AES key bytes with private RSA key
            byte[] signature = rsaSign(aesKeyBytes, rsaKeyPair.getPrivate());

            // Encrypt ONLY the AES key bytes with receiver's public RSA key
            PublicKey receiverPub = clientPublicKeys.get(target);
            byte[] encryptedKeyBytes = rsaEncrypt(aesKeyBytes, receiverPub);

            // Prepare map
            Map<String, String> keyExchangeMsg = new HashMap<>();
            keyExchangeMsg.put("type", "KEY_EXCHANGE");
            keyExchangeMsg.put("target", target);
            keyExchangeMsg.put("from", myName);
            keyExchangeMsg.put("encryptedKey", Base64.getEncoder().encodeToString(encryptedKeyBytes));
            keyExchangeMsg.put("signature", Base64.getEncoder().encodeToString(signature));

            // Send message
            sendMap(keyExchangeMsg);

            // Store locally
            sessionKeys.put(target, aesKey);
            appendChat("System", "Session key created and sent to " + target);

        } catch (Exception e) {
            e.printStackTrace();
            appendChat("System", "Error creating session key: " + e.getMessage());
        }
    }

    private void handleKeyExchange(Map<String, Object> msg) {
        try {
            String from = (String) msg.get("from");
            String encryptedKeyB64 = (String) msg.get("encryptedKey");
            String signatureB64 = (String) msg.get("signature");

            byte[] encryptedKey = Base64.getDecoder().decode(encryptedKeyB64);
            byte[] signature = Base64.getDecoder().decode(signatureB64);

            // Decrypt AES key with private RSA key
            byte[] aesKeyBytes = rsaDecrypt(encryptedKey, rsaKeyPair.getPrivate());

            // Verify signature on decrypted AES key bytes using sender's public key
            PublicKey senderPub = clientPublicKeys.get(from);
            if (!rsaVerify(aesKeyBytes, signature, senderPub)) {
                appendChat("System", "Signature verification failed from " + from);
                return;
            }

            // Store session key
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            sessionKeys.put(from, aesKey);

            appendChat("System", "Session key received and stored from " + from);

        } catch (Exception e) {
            e.printStackTrace();
            appendChat("System", "Error handling key exchange: " + e.getMessage());
        }
    }

    private void sendMessage() {
        if (chattingWith == null) return;
        String msg = messageField.getText().trim();
        if (msg.isEmpty()) return;

        try {
            // Encrypt with session key
            SecretKey aesKey = sessionKeys.get(chattingWith);
            if (aesKey == null) {
                appendChat("System", "No session key for " + chattingWith + ". Cannot send.");
                return;
            }
            byte[] encrypted = aesEncrypt(msg.getBytes(), aesKey);
            String encryptedB64 = Base64.getEncoder().encodeToString(encrypted);

            // Send message map
            Map<String, String> msgMap = new HashMap<>();
            msgMap.put("type", "MESSAGE");
            msgMap.put("target", chattingWith);
            msgMap.put("from", myName);
            msgMap.put("data", encryptedB64);

            sendMap(msgMap);

            appendChat("Me", msg);
            messageField.setText("");
        } catch (Exception e) {
            e.printStackTrace();
            appendChat("System", "Error sending message: " + e.getMessage());
        }
    }

    private void handleIncomingMessage(Map<String, Object> msg) {
        try {
            String from = (String) msg.get("from");
            String dataB64 = (String) msg.get("data");
            byte[] encrypted = Base64.getDecoder().decode(dataB64);

            SecretKey aesKey = sessionKeys.get(from);
            if (aesKey == null) {
                appendChat("System", "Received message from " + from + " but no session key.");
                return;
            }

            byte[] decrypted = aesDecrypt(encrypted, aesKey);
            String message = new String(decrypted);

            appendChat(from, message);
        } catch (Exception e) {
            e.printStackTrace();
            appendChat("System", "Error decrypting incoming message: " + e.getMessage());
        }
    }

    private void appendChat(String sender, String message) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append("[" + sender + "] " + message + "\n");
        });
    }

    private void sendMap(Map<String, String> map) throws IOException {
        synchronized (out) {
            out.writeObject(map);
            out.flush();
        }
    }

    // Crypto utility methods

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private String publicKeyToString(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private PublicKey stringToPublicKey(String keyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    private byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return cipher.doFinal(data);
    }

    private byte[] rsaSign(byte[] data, PrivateKey priv) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    private boolean rsaVerify(byte[] data, byte[] signature, PublicKey pub) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pub);
        sig.update(data);
        return sig.verify(signature);
    }

    private byte[] aesEncrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private byte[] aesDecrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new ChatClient().setVisible(true);
        });
    }
}

