package org.IS_Project;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class ChatServer {
    private static final int PORT = 12345;

    // Client info container
    static class ClientInfo {
        String name;
        PublicKey publicKey;
        Socket socket;
        final ObjectOutputStream out;

        ClientInfo(String name, PublicKey publicKey, Socket socket, ObjectOutputStream out) {
            this.name = name;
            this.publicKey = publicKey;
            this.socket = socket;
            this.out = out;
        }
    }

    // Map client name -> ClientInfo
    private static final Map<String, ClientInfo> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("ChatServer started on port " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }

    static class ClientHandler implements Runnable {
        Socket socket;
        ObjectInputStream in;
        ObjectOutputStream out;
        String clientName = null;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                // Registration
                // Receive registration packet: Map with keys "name", "publicKey"
                Object obj = in.readObject();
                if (!(obj instanceof Map)) {
                    socket.close();
                    return;
                }
                Map<String, String> regData = (Map<String, String>) obj;
                clientName = regData.get("name");
                String pubKeyStr = regData.get("publicKey");

                PublicKey pubKey = CryptoUtils.stringToPublicKey(pubKeyStr);
                if (clients.containsKey(clientName)) {
                    // Name taken
                    out.writeObject("NAME_TAKEN");
                    socket.close();
                    return;
                }
                clients.put(clientName, new ClientInfo(clientName, pubKey, socket, out));
                out.writeObject("REGISTERED");
                broadcastClientList();

                System.out.println(clientName + " registered.");

                // Listen for messages
                while (true) {
                    Object messageObj = in.readObject();
                    if (!(messageObj instanceof Map)) break;
                    Map<String, String> message = (Map<String, String>) messageObj;

                    String type = message.get("type");
                    String target = message.get("target");

                    if ("KEY_EXCHANGE".equals(type) || "MESSAGE".equals(type)) {
                        if (!clients.containsKey(target)) {
                            out.writeObject("TARGET_NOT_FOUND");
                            continue;
                        }
                        ClientInfo targetClient = clients.get(target);

                        // Forward message to target client
                        synchronized (targetClient.out) {
                            targetClient.out.writeObject(message);
                            targetClient.out.flush();
                        }
                    }
                }
            } catch (Exception e) {
                // e.printStackTrace();
            } finally {
                if (clientName != null) {
                    clients.remove(clientName);
                    broadcastClientList();
                    System.out.println(clientName + " disconnected.");
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private static void broadcastClientList() {
        try {
            // Build list of clients: Map<String,String> (name->base64 public key)
            Map<String, String> clientList = new HashMap<>();
            for (ClientInfo c : clients.values()) {
                clientList.put(c.name, CryptoUtils.publicKeyToString(c.publicKey));
            }
            Map<String, Object> message = new HashMap<>();
            message.put("type", "CLIENT_LIST");
            message.put("list", clientList);

            for (ClientInfo c : clients.values()) {
                synchronized (c.out) {
                    c.out.writeObject(message);
                    c.out.flush();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// Crypto utility class for keys
class CryptoUtils {
    public static PublicKey stringToPublicKey(String keyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static String publicKeyToString(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}

