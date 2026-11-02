package com.siem.service;

import com.siem.model.*;

import java.util.*;
import java.util.stream.Collectors;

/** Computes the numbers shown on the Statistics Dashboard from a list of events. */
public class StatisticsService {

    public Statistics computeStatistics(List<SecurityEvent> events) {
        Statistics stats = new Statistics();
        stats.totalEvents = events.size();

        Map<String, Long> userCounts = new HashMap<>();
        Map<String, Long> ipCounts = new HashMap<>();
        Map<Integer, Long> eventIdCounts = new HashMap<>();

        for (SecurityEvent event : events) {
            userCounts.merge(event.getUsername(), 1L, Long::sum);
            if (event.getIpAddress() != null) {
                ipCounts.merge(event.getIpAddress(), 1L, Long::sum);
            }
            eventIdCounts.merge(event.getEventId(), 1L, Long::sum);

            if (event instanceof AuthenticationEvent) {
                if (event.getEventId() == 4624) stats.successfulLogins++;
                if (event.getEventId() == 4625) stats.failedLogins++;
            } else if (event instanceof AccountEvent account) {
                switch (account.getAccountAction()) {
                    case LOCKED -> stats.lockedAccounts++;
                    case PASSWORD_CHANGED -> stats.passwordChanges++;
                    case CREATED -> stats.newUsers++;
                    case DELETED -> stats.deletedUsers++;
                    default -> { /* ENABLED / DISABLED not separately counted here */ }
                }
            } else if (event instanceof PrivilegeEvent) {
                stats.privilegedLogins++;
            }
        }

        stats.topUsers = topN(userCounts, 5);
        stats.topIpAddresses = topN(ipCounts, 5);
        stats.eventDistribution = eventIdCounts;

        return stats;
    }

    private List<Map.Entry<String, Long>> topN(Map<String, Long> counts, int n) {
        return counts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(n)
                .collect(Collectors.toList());
    }
}
