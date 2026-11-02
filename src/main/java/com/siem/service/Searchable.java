package com.siem.service;

import com.siem.model.SecurityEvent;

import java.time.LocalDate;
import java.util.List;

/** Contract for anything that supports searching events by different criteria. */
public interface Searchable {
    List<SecurityEvent> searchByUsername(String username);
    List<SecurityEvent> searchByEventId(int eventId);
    List<SecurityEvent> searchByDate(LocalDate date);
    List<SecurityEvent> searchByComputer(String computerName);
    List<SecurityEvent> searchByIp(String ipAddress);
    List<SecurityEvent> searchByKeyword(String keyword);
}
