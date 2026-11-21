package com.vulndash.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulndash.config.VulnDashProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.*;

@Component
public class HttpThreatIntelClient implements ThreatIntelClient {

    private static final Logger log = LoggerFactory.getLogger(HttpThreatIntelClient.class);
    private static final int EPSS_BATCH = 50;

    private final VulnDashProperties.Enrichment cfg;
    private final RestClient http;

    public HttpThreatIntelClient(VulnDashProperties props) {
        this.cfg = props.enrichment();
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(cfg.timeoutSeconds()));
        factory.setReadTimeout(Duration.ofSeconds(cfg.timeoutSeconds()));
        this.http = RestClient.builder().requestFactory(factory).build();
    }

    @Override
    public Map<String, Double> fetchEpss(Collection<String> cves) {
        Map<String, Double> out = new HashMap<>();
        List<String> list = new ArrayList<>(new TreeSet<>(cves));
        for (int i = 0; i < list.size(); i += EPSS_BATCH) {
            List<String> batch = list.subList(i, Math.min(list.size(), i + EPSS_BATCH));
            try {
                JsonNode body = http.get()
                        .uri(cfg.epssUrl() + "?cve={cves}", String.join(",", batch))
                        .retrieve().body(JsonNode.class);
                if (body == null) continue;
                for (JsonNode row : body.path("data")) {
                    try {
                        out.put(row.path("cve").asText().toUpperCase(), Double.parseDouble(row.path("epss").asText()));
                    } catch (NumberFormatException ignored) {
                        // baris rusak dilewati
                    }
                }
            } catch (Exception e) {
                log.warn("Gagal mengambil EPSS untuk {} CVE: {}", batch.size(), e.getMessage());
            }
        }
        return out;
    }

    @Override
    public Set<String> fetchKev() {
        Set<String> out = new HashSet<>();
        try {
            JsonNode body = http.get().uri(cfg.kevUrl()).retrieve().body(JsonNode.class);
            if (body != null) {
                for (JsonNode v : body.path("vulnerabilities")) {
                    out.add(v.path("cveID").asText().toUpperCase());
                }
            }
        } catch (Exception e) {
            log.warn("Gagal mengambil katalog CISA KEV: {}", e.getMessage());
            return null;
        }
        return out;
    }
}
