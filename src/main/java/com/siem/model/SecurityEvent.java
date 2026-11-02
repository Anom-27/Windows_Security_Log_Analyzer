package com.siem.model;

import java.time.LocalDateTime;

/**
 * SecurityEvent is the abstract base class for every entry parsed from a
 * Windows Security Event Log, regardless of its specific type
 * (authentication, account management, or privilege use).
 *
 * WHY ABSTRACT?
 * We never want to create a plain "SecurityEvent" object directly, because
 * a raw log line is always actually ONE of: a login attempt, an account
 * change, or a privilege assignment. "SecurityEvent" on its own is just a
 * shared concept, not a real, complete thing. Marking the class 'abstract'
 * makes Java enforce this: `new SecurityEvent(...)` will not even compile.
 * Only concrete subclasses (AuthenticationEvent, AccountEvent,
 * PrivilegeEvent) can be instantiated.
 */
public abstract class SecurityEvent {

    // --- ENCAPSULATION ---
    // All fields are private. Nothing outside this class can read or modify
    // them directly. External code must go through the public getters below.
    // This protects the object's internal state from being changed in
    // invalid ways (e.g. someone setting eventId to a negative number).
    private final int eventId;
    private final LocalDateTime timestamp;
    private final String username;
    private final String computerName;
    private final String eventSource;
    private final EventLevel eventLevel;
    private final String message;
    private final String ipAddress; // may be null - not every event has one

    /**
     * Protected constructor: only this class and its subclasses can call it.
     * External code cannot do `new SecurityEvent(...)` anyway since the
     * class is abstract, but marking the constructor 'protected' (rather
     * than 'public') makes the intent explicit: "this constructor exists
     * only to be called via super(...) from a subclass constructor."
     */
    protected SecurityEvent(int eventId, LocalDateTime timestamp, String username,
                             String computerName, String eventSource,
                             EventLevel eventLevel, String message, String ipAddress) {
        this.eventId = eventId;
        this.timestamp = timestamp;
        this.username = username;
        this.computerName = computerName;
        this.eventSource = eventSource;
        this.eventLevel = eventLevel;
        this.message = message;
        this.ipAddress = ipAddress;
    }

    // --- Getters (encapsulation continued) ---
    // Fields are 'final' above, so there are deliberately no setters.
    // Once a log event is parsed, it represents a historical fact that
    // should never change. This is called making the object "immutable" -
    // a good practice for data that represents something that already
    // happened.

    public int getEventId() {
        return eventId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getUsername() {
        return username;
    }

    public String getComputerName() {
        return computerName;
    }

    public String getEventSource() {
        return eventSource;
    }

    public EventLevel getEventLevel() {
        return eventLevel;
    }

    public String getMessage() {
        return message;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    // --- ABSTRACTION + POLYMORPHISM ---
    // These two methods have NO body here - just a signature ending in a
    // semicolon. That is what makes them "abstract methods". They say:
    // "Every subclass of SecurityEvent MUST provide its own implementation
    // of display() and analyze(), or Java will refuse to compile that
    // subclass."
    //
    // This is the core of ABSTRACTION: SecurityEvent defines *what* every
    // event must be able to do, without dictating *how*. Each subclass
    // decides how, based on its own extra fields.
    //
    // This is also the setup for POLYMORPHISM: later, when we have a
    // List<SecurityEvent> containing a mix of AuthenticationEvent,
    // AccountEvent, and PrivilegeEvent objects, calling event.display() on
    // each one will automatically run the correct subclass's version -
    // decided at runtime based on the real object type, not the variable's
    // declared type.

    /**
     * Returns a human-readable, one-line summary of this event.
     * Each subclass formats this differently based on its own fields.
     */
    public abstract String display();

    /**
     * Returns true if this individual event, on its own, looks suspicious
     * enough to flag for review (e.g. a privilege assignment always
     * warrants a look). This is distinct from the later ThreatDetector,
     * which looks for PATTERNS across many events (like 5 failed logins
     * from one IP) rather than judging a single event in isolation.
     */
    public abstract boolean analyze();

    /**
     * A shared, non-abstract helper method. Unlike display() and analyze(),
     * every subclass behaves identically here, so we implement it ONCE in
     * the base class instead of forcing every subclass to repeat it.
     * This is basic code reuse via inheritance.
     */
    @Override
    public String toString() {
        return String.format("[%s] EventID=%d User=%s Computer=%s Level=%s",
                timestamp, eventId, username, computerName, eventLevel);
    }
}
