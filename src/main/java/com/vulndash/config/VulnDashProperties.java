package com.vulndash.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "vulndash")
public record VulnDashProperties(
        Security security,
        Sla sla,
        Scoring scoring,
        Enrichment enrichment,
        Report report,
        boolean demoData) {

    public record Security(String apiKey, boolean protectReads) {
    }

    public record Sla(int criticalDays, int highDays, int mediumDays, int lowDays, int infoDays) {
    }

    public record Scoring(double cvssWeight, double epssWeight, double criticalityWeight, double kevFloor) {
    }

    public record Enrichment(boolean enabled, String epssUrl, String kevUrl, int timeoutSeconds, String cron) {
    }

    public record Report(String directory, boolean scheduleEnabled, String cron) {
    }
}
