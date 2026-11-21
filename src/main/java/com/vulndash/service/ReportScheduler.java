package com.vulndash.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Membuat laporan mingguan otomatis (default: Senin 02:00 UTC). */
@Component
@ConditionalOnProperty(name = "vulndash.report.schedule-enabled", havingValue = "true", matchIfMissing = true)
public class ReportScheduler {

    private static final Logger log = LoggerFactory.getLogger(ReportScheduler.class);

    private final ReportService reports;

    public ReportScheduler(ReportService reports) {
        this.reports = reports;
    }

    @Scheduled(cron = "${vulndash.report.cron}")
    public void weekly() {
        try {
            log.info("Laporan mingguan dibuat: {}", reports.generateToDisk());
        } catch (Exception e) {
            log.error("Gagal membuat laporan mingguan", e);
        }
    }
}
