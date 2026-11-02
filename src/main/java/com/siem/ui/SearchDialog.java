package com.siem.ui;

import com.siem.model.SecurityEvent;
import com.siem.service.SearchService;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDate;
import java.util.List;

/** Dialog window for searching imported events by username, Event ID, date, computer, IP, or keyword. */
public class SearchDialog extends JDialog {

    public SearchDialog(JFrame parent, SearchService searchService) {
        super(parent, "Search Events", true);
        setSize(750, 500);
        setLocationRelativeTo(parent);

        JPanel formPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JComboBox<String> criteriaBox = new JComboBox<>(
                new String[]{"Username", "Event ID", "Date (yyyy-MM-dd)", "Computer", "IP Address", "Keyword"});
        JTextField valueField = new JTextField(20);
        JButton searchButton = new JButton("Search");

        formPanel.add(new JLabel("Search by:"));
        formPanel.add(criteriaBox);
        formPanel.add(valueField);
        formPanel.add(searchButton);

        EventTableModel resultModel = new EventTableModel(List.of());
        JTable resultTable = new JTable(resultModel);
        JScrollPane scrollPane = new JScrollPane(resultTable);

        searchButton.addActionListener(e -> {
            String criterion = (String) criteriaBox.getSelectedItem();
            String value = valueField.getText().trim();
            if (value.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Please enter a search value.", "Missing Input", JOptionPane.WARNING_MESSAGE);
                return;
            }

            List<SecurityEvent> results;
            try {
                results = switch (criterion) {
                    case "Username" -> searchService.searchByUsername(value);
                    case "Event ID" -> searchService.searchByEventId(Integer.parseInt(value));
                    case "Date (yyyy-MM-dd)" -> searchService.searchByDate(LocalDate.parse(value));
                    case "Computer" -> searchService.searchByComputer(value);
                    case "IP Address" -> searchService.searchByIp(value);
                    default -> searchService.searchByKeyword(value);
                };
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid value for " + criterion + ": " + ex.getMessage(),
                        "Invalid Input", JOptionPane.ERROR_MESSAGE);
                return;
            }

            resultModel.setEvents(results);
            setTitle("Search Events - " + results.size() + " result(s) found");
        });

        add(formPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }
}
