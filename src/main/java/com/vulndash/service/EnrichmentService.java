package com.vulndash.service;

import com.vulndash.config.VulnDashProperties;
import com.vulndash.domain.Finding;
import com.vulndash.domain.FindingStatus;
import com.vulndash.repo.FindingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/** Memperkaya temuan ber-CVE dengan EPSS (FIRST.org) dan status KEV (CISA), lalu menghitung ulang skor. */
@Service
public class EnrichmentService {

    private static final Logger log = LoggerFactory.getLogger(EnrichmentService.class);
    private static final Duration STALE_AFTER = Duration.ofHours(24);

    private final VulnDashProperties.Enrichment cfg;
    private final ThreatIntelClient client;
    private final FindingRepository findings;
    private final ScoringService scoring;
    private final TransactionTemplate tx;

    public EnrichmentService(VulnDashProperties props, ThreatIntelClient client, FindingRepository findings,
                             ScoringService scoring, PlatformTransactionManager txManager) {
        this.cfg = props.enrichment();
        this.client = client;
        this.findings = findings;
        this.scoring = scoring;
        this.tx = new TransactionTemplate(txManager);
    }

    /** Refresh hanya temuan yang datanya belum ada / sudah lebih dari 24 jam. */
    public int refreshStale() {
        return refresh(false);
    }

    @Scheduled(cron = "${vulndash.enrichment.cron}")
    public void scheduledRefresh() {
        try {
            int n = refresh(true);
            if (n > 0) log.info("Enrichment harian: {} temuan diperbarui", n);
        } catch (Exception e) {
            log.warn("Enrichment terjadwal gagal: {}", e.getMessage());
        }
    }

    /** @return jumlah temuan yang diperbarui */
    public int refresh(boolean force) {
        if (!cfg.enabled()) return 0;

        Instant now = Instant.now();
        List<Finding> candidates = findings.findActiveWithCve(FindingStatus.ACTIVE).stream()
                .filter(f -> force || f.getEpssUpdatedAt() == null
                        || Duration.between(f.getEpssUpdatedAt(), now).compareTo(STALE_AFTER) > 0)
                .toList();
        if (candidates.isEmpty()) return 0;

        Set<String> cves = candidates.stream().map(Finding::getCveId).collect(Collectors.toSet());
        Map<String, Double> epss = client.fetchEpss(cves);
        Set<String> kev = client.fetchKev(); // null = gagal, jangan timpa status KEV yang ada

        Integer updated = tx.execute(status -> {
            int n = 0;
            for (Finding stale : candidates) {
                Finding f = findings.findWithAsset(stale.getId()).orElse(null);
                if (f == null) continue;
                Double score = epss.get(f.getCveId());
                if (score != null) {
                    f.setEpss(score);
                    f.setEpssUpdatedAt(now);
                }
                if (kev != null) f.setKnownExploited(kev.contains(f.getCveId()));
                f.setPriorityScore(scoring.score(f));
                findings.save(f);
                n++;
            }
            return n;
        });
        return updated == null ? 0 : updated;
    }
}
