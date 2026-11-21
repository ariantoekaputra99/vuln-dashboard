package com.vulndash.service;

import com.vulndash.config.VulnDashProperties;
import com.vulndash.domain.Severity;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
public class SlaService {

    private final VulnDashProperties.Sla sla;

    public SlaService(VulnDashProperties props) {
        this.sla = props.sla();
    }

    public int days(Severity severity) {
        return switch (severity) {
            case CRITICAL -> sla.criticalDays();
            case HIGH -> sla.highDays();
            case MEDIUM -> sla.mediumDays();
            case LOW -> sla.lowDays();
            case INFO -> sla.infoDays();
        };
    }

    public Instant dueDate(Severity severity, Instant from) {
        return from.plus(Duration.ofDays(days(severity)));
    }
}
