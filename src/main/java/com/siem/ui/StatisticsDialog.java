package com.siem.ui;

import com.siem.service.Statistics;

import javax.swing.*;
import java.awt.*;

/** Dialog window showing the Statistics Dashboard numbers computed by StatisticsService. */
public class StatisticsDialog extends JDialog {

    public StatisticsDialog(JFrame parent, Statistics stats) {
        super(parent, "Statistics Dashboard", true);
        setSize(500, 500);
        setLocationRelativeTo(parent);

        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        textArea.setText(stats.toString());

        add(new JScrollPane(textArea), BorderLayout.CENTER);
    }
}
