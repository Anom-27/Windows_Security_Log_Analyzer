package com.siem;

import com.siem.exception.InvalidDateFormatException;
import com.siem.util.DateUtil;
import com.siem.util.RegexUtil;
import com.siem.util.ValidationUtil;

import java.time.LocalDateTime;

/**
 * UtilDemo - a small demo program to test whether the three Utility Layer
 * classes (DateUtil, RegexUtil, ValidationUtil) are working correctly.
 */
public class UtilDemo {
    // 'main' now declares 'throws InvalidDateFormatException' because
    // DateUtil.parseWindowsTimestamp() is a checked exception - the
    // compiler will not let us call it without either catching it or
    // declaring it here. Declaring it is fine for a simple demo; inside
    // a real application (the future Parsing Layer) we will instead catch
    // it properly so one bad line doesn't stop the whole import.
    public static void main(String[] args) throws InvalidDateFormatException {

        System.out.println("===== DateUtil Test =====");
        LocalDateTime parsed = DateUtil.parseWindowsTimestamp("7/10/2026 2:15:00 AM");
        System.out.println("Parsed timestamp: " + parsed);
        System.out.println("Outside working hours? " + DateUtil.isOutsideWorkingHours(parsed));
        System.out.println("Is weekend? " + DateUtil.isWeekend(parsed));

        System.out.println();
        System.out.println("===== RegexUtil Test =====");
        String message = "An account failed to log on. Source Network Address: 192.168.1.50";
        String ip = RegexUtil.extractIpAddress(message);
        System.out.println("IP found in message: " + ip);
        System.out.println("Is '192.168.1.50' a valid IP? " + RegexUtil.isValidIp("192.168.1.50"));
        System.out.println("Is '999.999.1.1' a valid IP? " + RegexUtil.isValidIp("999.999.1.1"));

        System.out.println();
        System.out.println("===== ValidationUtil Test =====");
        System.out.println("Is 'security_log.CSV' a valid extension (csv/xml)? "
                + ValidationUtil.hasValidExtension("security_log.CSV", "csv", "xml"));
        System.out.println("Is 'malware.exe' a valid extension (csv/xml)? "
                + ValidationUtil.hasValidExtension("malware.exe", "csv", "xml"));
        System.out.println("Is an empty string 'not empty'? " + ValidationUtil.isNotEmpty("   "));
        System.out.println("Is 'admin' 'not empty'? " + ValidationUtil.isNotEmpty("admin"));
    }
}
