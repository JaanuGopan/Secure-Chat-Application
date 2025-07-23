package org.IS_Project.database;

import java.sql.*;

public class DBUtil {
    private static final String URL = "jdbc:postgresql://localhost:5432/chatapp";
    private static final String USER = "chatappuser";
    private static final String PASSWORD = "chatappuser";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }
}


