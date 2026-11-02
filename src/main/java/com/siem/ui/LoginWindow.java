package com.siem.ui;

import com.siem.exception.AuthenticationException;
import com.siem.model.User;
import com.siem.service.AuthenticationService;

import javax.swing.*;
import java.awt.*;

/**
 * LoginWindow is the first screen the user sees. It collects a username
 * and password, delegates the actual check to AuthenticationService, and
 * opens DashboardWindow on success.
 */
public class LoginWindow extends JFrame {

    private final AuthenticationService authService = new AuthenticationService();

    public LoginWindow() {
        setTitle("Windows Security Log Analysis Tool - Login");
        setSize(380, 220);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel titleLabel = new JLabel("SIEM Login", SwingConstants.CENTER);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        panel.add(titleLabel, gbc);
        gbc.gridwidth = 1;

        JLabel userLabel = new JLabel("Username:");
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(userLabel, gbc);

        JTextField userField = new JTextField(15);
        gbc.gridx = 1; gbc.gridy = 1;
        panel.add(userField, gbc);

        JLabel passLabel = new JLabel("Password:");
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(passLabel, gbc);

        JPasswordField passField = new JPasswordField(15);
        gbc.gridx = 1; gbc.gridy = 2;
        panel.add(passField, gbc);

        JButton loginButton = new JButton("Login");
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        panel.add(loginButton, gbc);

        JLabel hintLabel = new JLabel("<html><i>Demo accounts: admin/admin123 or analyst/analyst123</i></html>");
        hintLabel.setFont(new Font("SansSerif", Font.PLAIN, 10));
        gbc.gridy = 4;
        panel.add(hintLabel, gbc);

        loginButton.addActionListener(e -> {
            String username = userField.getText().trim();
            String password = new String(passField.getPassword());
            try {
                User user = authService.login(username, password);
                dispose(); // close the login window
                SwingUtilities.invokeLater(() -> new DashboardWindow(user).setVisible(true));
            } catch (AuthenticationException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Login Failed", JOptionPane.ERROR_MESSAGE);
            }
        });

        // Pressing Enter in the password field also triggers login.
        passField.addActionListener(e -> loginButton.doClick());

        add(panel);
    }
}
