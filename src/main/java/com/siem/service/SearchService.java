package com.siem.service;

import com.siem.model.SecurityEvent;
import com.siem.repository.EventRepository;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * SearchService implements Searchable, using the fast indices already
 * built by EventRepository where possible (username, IP, Event ID), and
 * falling back to a simple linear scan for date and free-text keyword
 * search, since those weren't pre-indexed.
 */
public class SearchService implements Searchable {

    private final EventRepository repository;

    public SearchService(EventRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<SecurityEvent> searchByUsername(String username) {
        return repository.getByUsername(username);
    }

    @Override
    public List<SecurityEvent> searchByEventId(int eventId) {
        return repository.getByEventId(eventId);
    }

    @Override
    public List<SecurityEvent> searchByDate(LocalDate date) {
        List<SecurityEvent> results = new ArrayList<>();
        for (SecurityEvent event : repository.getAllEvents()) {
            if (event.getTimestamp().toLocalDate().equals(date)) {
                results.add(event);
            }
        }
        return results;
    }

    @Override
    public List<SecurityEvent> searchByComputer(String computerName) {
        List<SecurityEvent> results = new ArrayList<>();
        for (SecurityEvent event : repository.getAllEvents()) {
            if (event.getComputerName().equalsIgnoreCase(computerName)) {
                results.add(event);
            }
        }
        return results;
    }

    @Override
    public List<SecurityEvent> searchByIp(String ipAddress) {
        return repository.getByIpAddress(ipAddress);
    }

    @Override
    public List<SecurityEvent> searchByKeyword(String keyword) {
        List<SecurityEvent> results = new ArrayList<>();
        String lowerKeyword = keyword.toLowerCase();
        for (SecurityEvent event : repository.getAllEvents()) {
            if (event.getMessage().toLowerCase().contains(lowerKeyword)) {
                results.add(event);
            }
        }
        return results;
    }
}
