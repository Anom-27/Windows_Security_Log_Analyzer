package com.siem;

import com.siem.ui.LoginWindow;

import javax.swing.*;

/**
 * Main is the entry point of the whole application. Running this class's
 * main() method is how you start the GUI.
 */
public class Main {
    public static void main(String[] args) {
        // SwingUtilities.invokeLater ensures all GUI creation happens on
        // Swing's dedicated "Event Dispatch Thread" - this is a Swing best
        // practice that avoids subtle threading bugs in the UI.
        SwingUtilities.invokeLater(() -> new LoginWindow().setVisible(true));
    }
}
