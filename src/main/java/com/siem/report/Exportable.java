package com.siem.report;

import java.io.IOException;
import java.util.List;

/** Contract for anything that can export data to TXT or CSV files. */
public interface Exportable<T> {
    void exportAsText(String content, String filePath) throws IOException;
    void exportAsCsv(List<T> items, String filePath) throws IOException;
}
