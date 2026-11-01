package com.siem;

import com.siem.model.*;

import java.time.LocalDateTime;
import java.util.List;

/**
 * ModelDemo - this class exists purely to test the Model Layer.
 * We create one object of each SecurityEvent subclass, put them all into
 * a single List<SecurityEvent>, then loop through and call display() on
 * each one. This is where we can see POLYMORPHISM actually working.
 */
public class ModelDemo {
    public static void main(String[] args) {

        AuthenticationEvent failedLogin = new AuthenticationEvent(
                4625,
                LocalDateTime.of(2026, 7, 10, 2, 15, 0),
                "john.doe",
                "WORKSTATION01",
                "Microsoft-Windows-Security-Auditing",
                EventLevel.WARNING,
                "An account failed to log on.",
                "192.168.1.50",
                3,
                "NTLM"
        );

        AccountEvent deletedAccount = new AccountEvent(
                4726,
                LocalDateTime.of(2026, 7, 10, 9, 0, 0),
                "admin",
                "DC01",
                "Microsoft-Windows-Security-Auditing",
                EventLevel.INFO,
                "A user account was deleted.",
                null,
                "temp.user",
                AccountAction.DELETED
        );

        PrivilegeEvent privilegeAssigned = new PrivilegeEvent(
                4672,
                LocalDateTime.of(2026, 7, 10, 10, 30, 0),
                "svc.backup",
                "SERVER02",
                "Microsoft-Windows-Security-Auditing",
                EventLevel.INFO,
                "Special privileges assigned to new logon.",
                "10.0.0.5",
                List.of("SeBackupPrivilege", "SeRestorePrivilege")
        );

        // A single List<SecurityEvent> holds three different event types.
        // This is the core benefit of POLYMORPHISM: objects of different
        // subclasses can all be held through one common "SecurityEvent" reference type.
        List<SecurityEvent> events = List.of(failedLogin, deletedAccount, privilegeAssigned);

        System.out.println("===== SECURITY EVENT LOG =====");
        for (SecurityEvent event : events) {
            // event.display() is called here - but which class's display()
            // actually runs is decided at runtime (the JVM checks the
            // object's real type).
            System.out.println(event.display());

            // event.analyze() is called to check if this event looks suspicious.
            if (event.analyze()) {
                System.out.println("   >> FLAGGED FOR REVIEW");
            }
        }
    }
}
