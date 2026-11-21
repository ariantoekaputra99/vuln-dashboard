package com.vulndash.domain;

public enum Severity {
    CRITICAL(9.5), HIGH(7.5), MEDIUM(5.0), LOW(2.5), INFO(0.0);

    private final double defaultCvss;

    Severity(double defaultCvss) {
        this.defaultCvss = defaultCvss;
    }

    /** Estimasi CVSS bila scanner tidak memberi skor (mis. OWASP ZAP). */
    public double defaultCvss() {
        return defaultCvss;
    }

    public static Severity fromCvss(double score) {
        if (score >= 9.0) return CRITICAL;
        if (score >= 7.0) return HIGH;
        if (score >= 4.0) return MEDIUM;
        if (score > 0.0) return LOW;
        return INFO;
    }

    public static Severity parse(String raw) {
        if (raw == null) return INFO;
        return switch (raw.trim().toUpperCase()) {
            case "CRITICAL" -> CRITICAL;
            case "HIGH" -> HIGH;
            case "MEDIUM", "MODERATE" -> MEDIUM;
            case "LOW" -> LOW;
            default -> INFO;
        };
    }
}
