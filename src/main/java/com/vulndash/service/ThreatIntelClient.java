package com.vulndash.service;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

/** Sumber data threat intelligence eksternal (dipisah agar mudah di-mock pada test). */
public interface ThreatIntelClient {

    /** CVE -> skor EPSS (0..1). */
    Map<String, Double> fetchEpss(Collection<String> cves);

    /** Himpunan CVE pada katalog CISA Known Exploited Vulnerabilities. */
    Set<String> fetchKev();
}
