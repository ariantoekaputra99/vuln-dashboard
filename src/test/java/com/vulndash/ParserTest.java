package com.vulndash;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulndash.domain.AssetType;
import com.vulndash.domain.Severity;
import com.vulndash.parser.*;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ParserTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private InputStream res(String name) {
        return getClass().getResourceAsStream("/samples/" + name);
    }

    @Test
    void trivyParsesVulnerabilitiesMisconfigsAndAsset() throws Exception {
        ParsedScan scan = new TrivyParser(mapper).parse(res("trivy-payment-api.json"));

        assertThat(scan.assetHint()).isEqualTo("payment-api:1.4.2");
        assertThat(scan.assetTypeHint()).isEqualTo(AssetType.CONTAINER_IMAGE);
        assertThat(scan.findings()).hasSize(5);

        ParsedFinding log4j = scan.findings().stream().filter(f -> "CVE-2021-44228".equals(f.ruleId())).findFirst().orElseThrow();
        assertThat(log4j.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(log4j.cvss()).isEqualTo(10.0);
        assertThat(log4j.cveId()).isEqualTo("CVE-2021-44228");
        assertThat(log4j.cweId()).isEqualTo("CWE-502");
        assertThat(log4j.fixedVersion()).isEqualTo("2.17.1");
        assertThat(log4j.remediation()).contains("2.17.1");

        ParsedFinding misconfig = scan.findings().stream().filter(f -> "DS002".equals(f.ruleId())).findFirst().orElseThrow();
        assertThat(misconfig.severity()).isEqualTo(Severity.HIGH);
        assertThat(misconfig.cveId()).isNull();
    }

    @Test
    void zapGroupsInstancesAndStripsHtml() throws Exception {
        ParsedScan scan = new ZapParser(mapper).parse(res("zap-portal.json"));

        assertThat(scan.assetHint()).isEqualTo("https://portal.demo.local");
        assertThat(scan.findings()).hasSize(3);
        ParsedFinding xss = scan.findings().get(0);
        assertThat(xss.severity()).isEqualTo(Severity.HIGH);
        assertThat(xss.cweId()).isEqualTo("CWE-79");
        assertThat(xss.location()).contains("/search").contains("param: q").contains("+1 lokasi lain");
        assertThat(xss.description()).doesNotContain("<p>");
        assertThat(xss.cvss()).isNull();
        assertThat(scan.findings().get(2).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void nucleiParsesJsonlWithClassification() throws Exception {
        ParsedScan scan = new NucleiParser(mapper).parse(res("nuclei-admin.jsonl"));

        assertThat(scan.findings()).hasSize(3);
        ParsedFinding log4j = scan.findings().get(1);
        assertThat(log4j.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(log4j.cveId()).isEqualTo("CVE-2021-44228");
        assertThat(log4j.cvss()).isEqualTo(10.0);
        assertThat(log4j.cweId()).isEqualTo("CWE-502");
        assertThat(log4j.assetName()).isEqualTo("https://admin.demo.local");
    }

    @Test
    void nucleiAcceptsJsonArray() throws Exception {
        String json = "[{\"template-id\":\"x\",\"info\":{\"name\":\"X\",\"severity\":\"low\"},\"host\":\"h\"}]";
        ParsedScan scan = new NucleiParser(mapper).parse(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        assertThat(scan.findings()).hasSize(1);
        assertThat(scan.findings().get(0).severity()).isEqualTo(Severity.LOW);
    }

    @Test
    void rejectsWrongFormats() {
        byte[] notJson = "bukan json".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> new TrivyParser(mapper).parse(new ByteArrayInputStream(notJson)))
                .isInstanceOf(ScanParseException.class);
        assertThatThrownBy(() -> new ZapParser(mapper).parse(res("trivy-payment-api.json")))
                .isInstanceOf(ScanParseException.class);
        assertThatThrownBy(() -> new TrivyParser(mapper).parse(res("zap-portal.json")))
                .isInstanceOf(ScanParseException.class);
    }
}
