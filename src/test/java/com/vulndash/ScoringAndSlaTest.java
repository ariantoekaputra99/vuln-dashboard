package com.vulndash;

import com.vulndash.config.VulnDashProperties;
import com.vulndash.domain.Criticality;
import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.service.ScoringService;
import com.vulndash.service.SlaService;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class ScoringAndSlaTest {

    private final VulnDashProperties props = new VulnDashProperties(
            new VulnDashProperties.Security("k", false),
            new VulnDashProperties.Sla(7, 30, 90, 180, 365),
            new VulnDashProperties.Scoring(50, 30, 20, 90),
            new VulnDashProperties.Enrichment(false, "", "", 5, ""),
            new VulnDashProperties.Report("./reports", false, ""),
            false);
    private final ScoringService scoring = new ScoringService(props);
    private final SlaService sla = new SlaService(props);

    @Test
    void epssAndAssetCriticalityChangePriorityAmongEqualCvss() {
        double lowRisk = scoring.score(7.5, 0.01, Criticality.LOW, false);
        double highRisk = scoring.score(7.5, 0.90, Criticality.CRITICAL, false);
        assertThat(highRisk).isGreaterThan(lowRisk + 30);
        assertThat(lowRisk).isEqualTo(37.8); // 37.5 + 0.3 + 0
    }

    @Test
    void knownExploitedIsFlooredAtKevThreshold() {
        assertThat(scoring.score(5.0, 0.0, Criticality.LOW, true)).isEqualTo(90.0);
        assertThat(scoring.score(10.0, 1.0, Criticality.CRITICAL, true)).isEqualTo(100.0);
    }

    @Test
    void missingEpssTreatedAsZeroAndValuesClamped() {
        assertThat(scoring.score(12.0, 5.0, Criticality.CRITICAL, false)).isEqualTo(100.0);
        assertThat(scoring.score(0.0, null, Criticality.LOW, false)).isEqualTo(0.0);
    }

    @Test
    void priorityBands() {
        assertThat(ScoringService.band(85)).isEqualTo("P1");
        assertThat(ScoringService.band(60)).isEqualTo("P2");
        assertThat(ScoringService.band(40)).isEqualTo("P3");
        assertThat(ScoringService.band(39.9)).isEqualTo("P4");
    }

    @Test
    void slaDueDatesFollowSeverity() {
        Instant t = Instant.parse("2026-01-01T00:00:00Z");
        assertThat(sla.dueDate(Severity.CRITICAL, t)).isEqualTo(t.plus(Duration.ofDays(7)));
        assertThat(sla.dueDate(Severity.HIGH, t)).isEqualTo(t.plus(Duration.ofDays(30)));
        assertThat(sla.dueDate(Severity.LOW, t)).isEqualTo(t.plus(Duration.ofDays(180)));
    }

    @Test
    void severityFromCvss() {
        assertThat(Severity.fromCvss(9.8)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromCvss(7.0)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromCvss(4.0)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromCvss(0.1)).isEqualTo(Severity.LOW);
        assertThat(Severity.fromCvss(0)).isEqualTo(Severity.INFO);
    }

    @Test
    void statusWorkflowRules() {
        assertThat(FindingStatus.OPEN.canTransitionTo(FindingStatus.IN_PROGRESS)).isTrue();
        assertThat(FindingStatus.OPEN.canTransitionTo(FindingStatus.VERIFIED)).isFalse();
        assertThat(FindingStatus.FIXED.canTransitionTo(FindingStatus.VERIFIED)).isTrue();
        assertThat(FindingStatus.VERIFIED.canTransitionTo(FindingStatus.OPEN)).isTrue();
        assertThat(FindingStatus.FALSE_POSITIVE.canTransitionTo(FindingStatus.FIXED)).isFalse();
    }
}
