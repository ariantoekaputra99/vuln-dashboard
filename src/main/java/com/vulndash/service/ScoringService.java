package com.vulndash.service;

import com.vulndash.config.VulnDashProperties;
import com.vulndash.domain.Criticality;
import com.vulndash.domain.Finding;
import org.springframework.stereotype.Service;

/**
 * Skor prioritas 0-100 yang menggabungkan tiga sinyal:
 * <ul>
 *   <li>CVSS (keparahan teknis)       -> bobot cvss-weight</li>
 *   <li>EPSS (peluang dieksploitasi)  -> bobot epss-weight</li>
 *   <li>Kritikalitas aset (bisnis)    -> bobot criticality-weight</li>
 * </ul>
 * Temuan yang ada di CISA KEV (sudah dieksploitasi di dunia nyata) dijamin minimal {@code kev-floor}.
 */
@Service
public class ScoringService {

    private final VulnDashProperties.Scoring cfg;

    public ScoringService(VulnDashProperties props) {
        this.cfg = props.scoring();
    }

    public double score(double cvss, Double epss, Criticality criticality, boolean knownExploited) {
        double cvssPart = clamp(cvss / 10.0) * cfg.cvssWeight();
        double epssPart = clamp(epss == null ? 0 : epss) * cfg.epssWeight();
        double critPart = criticality.factor() * cfg.criticalityWeight();
        double total = cvssPart + epssPart + critPart;
        if (knownExploited) total = Math.max(total, cfg.kevFloor());
        total = Math.min(100.0, total);
        return Math.round(total * 10.0) / 10.0;
    }

    public double score(Finding f) {
        return score(f.effectiveCvss(), f.getEpss(), f.getAsset().getCriticality(), f.isKnownExploited());
    }

    /** Pita prioritas: P1 (segera) s.d. P4 (rutin). */
    public static String band(double score) {
        if (score >= 80) return "P1";
        if (score >= 60) return "P2";
        if (score >= 40) return "P3";
        return "P4";
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
