package com.siem.repository;

import com.siem.model.SecurityEvent;

import java.time.LocalDate;
import java.util.*;

/**
 * EventRepository stores all imported SecurityEvent objects in memory and
 * maintains several indices (HashMaps) for fast lookup, instead of
 * scanning the entire list every time. This demonstrates several
 * Collections Framework data structures working together:
 *
 * - ArrayList: the master ordered list of all events
 * - HashMap:   fast lookup by username, by IP address, and by Event ID
 * - TreeMap:   event counts per date, automatically kept sorted by date
 */
public class EventRepository {

    private final List<SecurityEvent> allEvents = new ArrayList<>();
    private final Map<String, List<SecurityEvent>> byUsername = new HashMap<>();
    private final Map<String, List<SecurityEvent>> byIpAddress = new HashMap<>();
    private final Map<Integer, List<SecurityEvent>> byEventId = new HashMap<>();
    private final TreeMap<LocalDate, Integer> countByDate = new TreeMap<>();

    public void addEvent(SecurityEvent event) {
        allEvents.add(event);

        byUsername.computeIfAbsent(event.getUsername(), k -> new ArrayList<>()).add(event);
        byEventId.computeIfAbsent(event.getEventId(), k -> new ArrayList<>()).add(event);

        if (event.getIpAddress() != null) {
            byIpAddress.computeIfAbsent(event.getIpAddress(), k -> new ArrayList<>()).add(event);
        }

        LocalDate date = event.getTimestamp().toLocalDate();
        countByDate.merge(date, 1, Integer::sum);
    }

    public void addAll(List<SecurityEvent> events) {
        for (SecurityEvent event : events) {
            addEvent(event);
        }
    }

    public List<SecurityEvent> getAllEvents() {
        return Collections.unmodifiableList(allEvents);
    }

    public List<SecurityEvent> getByUsername(String username) {
        return byUsername.getOrDefault(username, List.of());
    }

    public List<SecurityEvent> getByIpAddress(String ip) {
        return byIpAddress.getOrDefault(ip, List.of());
    }

    public List<SecurityEvent> getByEventId(int eventId) {
        return byEventId.getOrDefault(eventId, List.of());
    }

    public TreeMap<LocalDate, Integer> getEventCountByDate() {
        return countByDate;
    }

    public int size() {
        return allEvents.size();
    }

    public void clear() {
        allEvents.clear();
        byUsername.clear();
        byIpAddress.clear();
        byEventId.clear();
        countByDate.clear();
    }
}
