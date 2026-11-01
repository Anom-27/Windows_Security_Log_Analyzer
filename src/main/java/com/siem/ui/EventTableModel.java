package com.siem.ui;

import com.siem.model.SecurityEvent;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * A custom Swing table model that displays a List<SecurityEvent> inside a
 * JTable. Extending AbstractTableModel means we only need to implement a
 * handful of methods (row/column counts and cell values) - Swing handles
 * all the rendering itself.
 */
public class EventTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"Event ID", "Timestamp", "Username", "Computer", "Level", "IP Address", "Message"};

    private List<SecurityEvent> events;

    public EventTableModel(List<SecurityEvent> events) {
        this.events = events;
    }

    public void setEvents(List<SecurityEvent> events) {
        this.events = events;
        fireTableDataChanged(); // tells the JTable to redraw itself with the new data
    }

    public SecurityEvent getEventAt(int row) {
        return events.get(row);
    }

    @Override
    public int getRowCount() {
        return events.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SecurityEvent event = events.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> event.getEventId();
            case 1 -> event.getTimestamp();
            case 2 -> event.getUsername();
            case 3 -> event.getComputerName();
            case 4 -> event.getEventLevel();
            case 5 -> event.getIpAddress() != null ? event.getIpAddress() : "N/A";
            case 6 -> event.getMessage();
            default -> "";
        };
    }
}
