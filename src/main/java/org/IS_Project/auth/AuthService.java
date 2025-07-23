package org.IS_Project.auth;

import org.IS_Project.database.DBUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.Base64;

public class AuthService {

    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashed = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean signup(String username, String password, String publicKey) {
        try (Connection conn = DBUtil.getConnection()) {
            // check if username exists
            PreparedStatement check = conn.prepareStatement("SELECT id FROM clients WHERE username=?");
            check.setString(1, username);
            ResultSet rs = check.executeQuery();
            if (rs.next()) {
                return false; // username exists
            }

            String insertSql = "INSERT INTO clients (username, password_hash, public_key) VALUES (?,?,?)";
            PreparedStatement stmt = conn.prepareStatement(insertSql);
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(password));
            stmt.setString(3, publicKey);
            stmt.executeUpdate();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean login(String username, String password) {
        try (Connection conn = DBUtil.getConnection()) {
            PreparedStatement stmt = conn.prepareStatement("SELECT password_hash FROM clients WHERE username=?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String stored = rs.getString("password_hash");
                return stored.equals(hashPassword(password));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
