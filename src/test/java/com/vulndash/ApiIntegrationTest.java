package com.vulndash;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulndash.repo.AssetRepository;
import com.vulndash.repo.FindingEventRepository;
import com.vulndash.repo.FindingRepository;
import com.vulndash.repo.ScanRepository;
import com.vulndash.service.ThreatIntelClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "vulndash.enrichment.enabled=true",
        "vulndash.report.schedule-enabled=false",
        "vulndash.report.directory=target/test-reports",
        "vulndash.security.api-key=test-key"
})
@AutoConfigureMockMvc
class ApiIntegrationTest {

    private static final String KEY = "test-key";

    @TestConfiguration
    static class StubIntel {
        @Bean
        @Primary
        ThreatIntelClient stub() {
            return new ThreatIntelClient() {
                @Override
                public Map<String, Double> fetchEpss(Collection<String> cves) {
                    Map<String, Double> m = new HashMap<>();
                    if (cves.contains("CVE-2021-44228")) m.put("CVE-2021-44228", 0.95);
                    if (cves.contains("CVE-2021-42550")) m.put("CVE-2021-42550", 0.01);
                    return m;
                }

                @Override
                public Set<String> fetchKev() {
                    return Set.of("CVE-2021-44228");
                }
            };
        }
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired FindingRepository findings;
    @Autowired FindingEventRepository events;
    @Autowired ScanRepository scans;
    @Autowired AssetRepository assets;

    @BeforeEach
    void clean() {
        events.deleteAll();
        findings.deleteAll();
        scans.deleteAll();
        assets.deleteAll();
    }

    private byte[] sample(String name) throws Exception {
        try (var in = getClass().getResourceAsStream("/samples/" + name)) {
            return in.readAllBytes();
        }
    }

    private JsonNode upload(String tool, String filename, byte[] content) throws Exception {
        MvcResult r = mvc.perform(multipart("/api/scans")
                        .file(new MockMultipartFile("file", filename, "application/json", content))
                        .param("tool", tool)
                        .header("X-API-Key", KEY))
                .andExpect(status().isCreated()).andReturn();
        return mapper.readTree(r.getResponse().getContentAsString());
    }

    private JsonNode getJson(String url) throws Exception {
        MvcResult r = mvc.perform(get(url)).andExpect(status().isOk()).andReturn();
        return mapper.readTree(r.getResponse().getContentAsString());
    }

    private static final String TRIMMED_TRIVY = """
            {"ArtifactName":"payment-api:1.4.2","ArtifactType":"container_image","Results":[
              {"Target":"app/lib/payment-core.jar","Type":"jar","Vulnerabilities":[
                {"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core",
                 "InstalledVersion":"2.14.1","FixedVersion":"2.17.1","Severity":"CRITICAL","Title":"log4j-core: RCE",
                 "CVSS":{"nvd":{"V3Score":10.0}}}]}]}
            """;

    @Test
    void ingestDeduplicatesAndEnrichesWithEpssAndKev() throws Exception {
        JsonNode first = upload("TRIVY", "trivy.json", sample("trivy-payment-api.json"));
        assertThat(first.get("created").asInt()).isEqualTo(5);
        assertThat(first.get("assets").get(0).asText()).isEqualTo("payment-api:1.4.2");

        JsonNode second = upload("TRIVY", "trivy.json", sample("trivy-payment-api.json"));
        assertThat(second.get("created").asInt()).isZero();
        assertThat(second.get("updated").asInt()).isEqualTo(5);
        assertThat(findings.count()).isEqualTo(5);

        JsonNode page = getJson("/api/findings?q=log4j");
        assertThat(page.get("totalElements").asInt()).isEqualTo(1);
        JsonNode log4j = page.get("content").get(0);
        assertThat(log4j.get("epss").asDouble()).isEqualTo(0.95);
        assertThat(log4j.get("knownExploited").asBoolean()).isTrue();
        assertThat(log4j.get("priorityScore").asDouble()).isGreaterThanOrEqualTo(90.0);
        assertThat(log4j.get("priority").asText()).isEqualTo("P1");

        // diurutkan berdasarkan prioritas menurun
        JsonNode all = getJson("/api/findings?sort=priority&dir=desc").get("content");
        for (int i = 1; i < all.size(); i++) {
            assertThat(all.get(i - 1).get("priorityScore").asDouble()).isGreaterThanOrEqualTo(all.get(i).get("priorityScore").asDouble());
        }
    }

    @Test
    void rescanAutoResolvesMissingFindingsAndReopensWhenTheyReturn() throws Exception {
        upload("TRIVY", "full.json", sample("trivy-payment-api.json"));

        JsonNode trimmed = upload("TRIVY", "trimmed.json", TRIMMED_TRIVY.getBytes(StandardCharsets.UTF_8));
        assertThat(trimmed.get("autoResolved").asInt()).isEqualTo(4);
        assertThat(getJson("/api/findings?status=FIXED").get("totalElements").asInt()).isEqualTo(4);
        assertThat(getJson("/api/findings?status=OPEN,IN_PROGRESS").get("totalElements").asInt()).isEqualTo(1);

        Long fixedId = getJson("/api/findings?status=FIXED").get("content").get(0).get("id").asLong();
        JsonNode detail = getJson("/api/findings/" + fixedId);
        assertThat(detail.get("events").toString()).contains("AUTO_RESOLVED");

        JsonNode back = upload("TRIVY", "full.json", sample("trivy-payment-api.json"));
        assertThat(back.get("reopened").asInt()).isEqualTo(4);
        assertThat(back.get("created").asInt()).isZero();
        assertThat(getJson("/api/findings?status=FIXED").get("totalElements").asInt()).isZero();
    }

    @Test
    void statusWorkflowIsEnforced() throws Exception {
        upload("ZAP", "zap.json", sample("zap-portal.json"));
        long id = getJson("/api/findings?sort=priority").get("content").get(0).get("id").asLong();

        patchStatus(id, "{\"status\":\"VERIFIED\"}", 400);                      // OPEN -> VERIFIED tidak boleh
        patchStatus(id, "{\"status\":\"ACCEPTED_RISK\"}", 400);                 // wajib justifikasi
        patchStatus(id, "{\"status\":\"IN_PROGRESS\",\"assignee\":\"budi\"}", 200);
        patchStatus(id, "{\"status\":\"FIXED\",\"note\":\"patch dirilis\"}", 200);
        patchStatus(id, "{\"status\":\"VERIFIED\"}", 200);

        JsonNode d = getJson("/api/findings/" + id);
        assertThat(d.get("finding").get("status").asText()).isEqualTo("VERIFIED");
        assertThat(d.get("finding").get("assignee").asText()).isEqualTo("budi");
        assertThat(d.get("finding").get("resolvedAt").isNull()).isFalse();
        assertThat(d.get("events").size()).isGreaterThanOrEqualTo(4);
    }

    private void patchStatus(long id, String body, int expected) throws Exception {
        mvc.perform(patch("/api/findings/" + id).header("X-API-Key", KEY)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().is(expected));
    }

    @Test
    void writesRequireApiKeyButReadsAreOpen() throws Exception {
        mvc.perform(multipart("/api/scans")
                        .file(new MockMultipartFile("file", "x.json", "application/json", "{}".getBytes()))
                        .param("tool", "TRIVY"))
                .andExpect(status().isUnauthorized());
        mvc.perform(multipart("/api/scans")
                        .file(new MockMultipartFile("file", "x.json", "application/json", "{}".getBytes()))
                        .param("tool", "TRIVY").header("X-API-Key", "salah"))
                .andExpect(status().isUnauthorized());
        mvc.perform(patch("/api/findings/1").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/dashboard/summary")).andExpect(status().isOk());
        mvc.perform(get("/api/dashboard/summary")).andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    @Test
    void badInputGivesClean4xx() throws Exception {
        mvc.perform(multipart("/api/scans")
                        .file(new MockMultipartFile("file", "x.json", "application/json", "bukan json".getBytes()))
                        .param("tool", "TRIVY").header("X-API-Key", KEY))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/findings?sort=password")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/findings?status=NGAWUR")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/findings/99999")).andExpect(status().isNotFound());
    }

    @Test
    void dashboardSummaryAggregates() throws Exception {
        upload("TRIVY", "trivy.json", sample("trivy-payment-api.json"));
        upload("ZAP", "zap.json", sample("zap-portal.json"));
        upload("NUCLEI", "nuclei.jsonl", sample("nuclei-admin.jsonl"));

        JsonNode s = getJson("/api/dashboard/summary");
        assertThat(s.get("kpis").get("active").asInt()).isEqualTo(11);
        assertThat(s.get("activeByTool").get("TRIVY").asInt()).isEqualTo(5);
        assertThat(s.get("activeByTool").get("ZAP").asInt()).isEqualTo(3);
        assertThat(s.get("activeByTool").get("NUCLEI").asInt()).isEqualTo(3);
        assertThat(s.get("kpis").get("knownExploited").asInt()).isGreaterThanOrEqualTo(1);
        assertThat(s.get("trend").size()).isEqualTo(9);
        assertThat(s.get("topFindings").size()).isEqualTo(10);
        assertThat(s.get("topAssets").size()).isEqualTo(3);
        assertThat(getJson("/api/assets").size()).isEqualTo(3);
    }

    @Test
    void assetCriticalityChangeRescoresFindings() throws Exception {
        upload("ZAP", "zap.json", sample("zap-portal.json"));
        JsonNode asset = getJson("/api/assets").get(0);
        double before = getJson("/api/findings").get("content").get(0).get("priorityScore").asDouble();

        mvc.perform(patch("/api/assets/" + asset.get("id").asLong()).header("X-API-Key", KEY)
                .contentType(MediaType.APPLICATION_JSON).content("{\"criticality\":\"CRITICAL\"}"))
                .andExpect(status().isOk());

        double after = getJson("/api/findings").get("content").get(0).get("priorityScore").asDouble();
        assertThat(after).isGreaterThan(before);
    }

    @Test
    void reportsEscapeUntrustedContentAndBlockTraversal() throws Exception {
        String evil = "{\"template-id\":\"x\",\"info\":{\"name\":\"=HYPERLINK(\\\"http://evil\\\")<img src=x onerror=alert(1)>\",\"severity\":\"high\"},\"host\":\"https://t.local\",\"matched-at\":\"https://t.local/\"}";
        upload("NUCLEI", "evil.jsonl", evil.getBytes(StandardCharsets.UTF_8));

        String html = mvc.perform(get("/api/reports/executive")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(html).contains("&lt;img src=x onerror=alert(1)&gt;").doesNotContain("<img src=x");

        String csv = mvc.perform(get("/api/reports/findings.csv")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(csv).contains("\"'=HYPERLINK(");

        mvc.perform(post("/api/reports/generate")).andExpect(status().isUnauthorized());
        MvcResult gen = mvc.perform(post("/api/reports/generate").header("X-API-Key", KEY)).andExpect(status().isOk()).andReturn();
        JsonNode names = mapper.readTree(gen.getResponse().getContentAsString());
        assertThat(names.size()).isEqualTo(2);
        assertThat(Files.exists(Path.of("target/test-reports").resolve(names.get(0).asText()))).isTrue();
        mvc.perform(get("/api/reports/files/" + names.get(0).asText())).andExpect(status().isOk());
        mvc.perform(get("/api/reports/files/..%2F..%2Fpom.xml")).andExpect(status().is4xxClientError());
        mvc.perform(get("/api/reports/files/..")).andExpect(status().is4xxClientError());
    }
}
