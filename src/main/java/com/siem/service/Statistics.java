package com.siem.service;

import java.util.List;
import java.util.Map;

/**
 * A simple data holder (POJO) carrying every number the Statistics
 * Dashboard needs to display. Kept separate from StatisticsService so the
 * "computing" logic and the "holding the result" responsibilities are
 * cleanly separated.
 */
public class Statistics {
    public int totalEvents;
    public int successfulLogins;
    public int failedLogins;
    public int lockedAccounts;
    public int passwordChanges;
    public int newUsers;
    public int deletedUsers;
    public int privilegedLogins;
    public List<Map.Entry<String, Long>> topUsers;
    public List<Map.Entry<String, Long>> topIpAddresses;
    public Map<Integer, Long> eventDistribution;

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Total Events: ").append(totalEvents).append("\n");
        sb.append("Successful Logins: ").append(successfulLogins).append("\n");
        sb.append("Failed Logins: ").append(failedLogins).append("\n");
        sb.append("Locked Accounts: ").append(lockedAccounts).append("\n");
        sb.append("Password Changes: ").append(passwordChanges).append("\n");
        sb.append("New Users: ").append(newUsers).append("\n");
        sb.append("Deleted Users: ").append(deletedUsers).append("\n");
        sb.append("Privileged Logins: ").append(privilegedLogins).append("\n");
        sb.append("Top Users: ").append(topUsers).append("\n");
        sb.append("Top IP Addresses: ").append(topIpAddresses).append("\n");
        sb.append("Event Distribution: ").append(eventDistribution).append("\n");
        return sb.toString();
    }
}
