package com.vulndash.service;

import com.vulndash.domain.*;
import com.vulndash.parser.ParsedFinding;
import com.vulndash.repo.AssetRepository;
import com.vulndash.repo.FindingEventRepository;
import com.vulndash.repo.FindingRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Random;

/**
 * Data demo (aktifkan dengan VULNDASH_DEMO_DATA=true) supaya dashboard langsung terisi.
 * Semua aset fiktif; nilai EPSS/KEV pada data demo bersifat ilustrasi, bukan data real-time.
 */
@Component
@ConditionalOnProperty(name = "vulndash.demo-data", havingValue = "true")
public class DemoDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private record Vuln(String id, String pkg, String installed, String fixed, Severity sev, double cvss,
                        double epss, boolean kev, String title) {
    }

    private record WebIssue(Tool tool, String rule, String title, Severity sev, String cwe, String cve, Double cvss,
                            String remediation) {
    }

    private static final List<Vuln> LIBS = List.of(
            new Vuln("CVE-2021-44228", "log4j-core", "2.14.1", "2.17.1", Severity.CRITICAL, 10.0, 0.944, true, "Apache Log4j2 JNDI remote code execution"),
            new Vuln("CVE-2022-22965", "spring-beans", "5.3.17", "5.3.18", Severity.CRITICAL, 9.8, 0.944, true, "Spring Framework RCE via data binding (Spring4Shell)"),
            new Vuln("CVE-2022-42889", "commons-text", "1.9", "1.10.0", Severity.CRITICAL, 9.8, 0.93, false, "Apache Commons Text variable interpolation RCE"),
            new Vuln("CVE-2022-1471", "snakeyaml", "1.30", "2.0", Severity.CRITICAL, 9.8, 0.2, false, "SnakeYAML unsafe deserialization"),
            new Vuln("CVE-2023-44487", "netty-codec-http2", "4.1.93", "4.1.100", Severity.HIGH, 7.5, 0.57, true, "HTTP/2 Rapid Reset denial of service"),
            new Vuln("CVE-2023-4863", "libwebp", "1.2.4", "1.3.2", Severity.HIGH, 8.8, 0.9, true, "libwebp heap buffer overflow"),
            new Vuln("CVE-2022-3602", "openssl", "3.0.5", "3.0.7", Severity.HIGH, 7.5, 0.1, false, "OpenSSL X.509 email address buffer overflow"),
            new Vuln("CVE-2021-23337", "lodash", "4.17.20", "4.17.21", Severity.HIGH, 7.2, 0.03, false, "lodash command injection via template"),
            new Vuln("CVE-2020-8203", "lodash", "4.17.15", "4.17.19", Severity.HIGH, 7.4, 0.02, false, "lodash prototype pollution in zipObjectDeep"),
            new Vuln("CVE-2022-25881", "http-cache-semantics", "4.1.0", "4.1.1", Severity.HIGH, 7.5, 0.003, false, "http-cache-semantics ReDoS"),
            new Vuln("CVE-2021-42550", "logback-core", "1.2.7", "1.2.9", Severity.MEDIUM, 6.6, 0.01, false, "Logback JNDI configuration vulnerability"),
            new Vuln("CVE-2021-3449", "openssl", "1.1.1j", "1.1.1k", Severity.MEDIUM, 5.9, 0.2, false, "OpenSSL NULL pointer dereference in renegotiation"));

    private static final List<WebIssue> WEB = List.of(
            new WebIssue(Tool.ZAP, "40012", "Cross Site Scripting (Reflected)", Severity.HIGH, "CWE-79", null, null, "Validasi input dan lakukan output encoding sesuai konteks."),
            new WebIssue(Tool.ZAP, "40018", "SQL Injection", Severity.HIGH, "CWE-89", null, null, "Gunakan prepared statement / query berparameter."),
            new WebIssue(Tool.ZAP, "10020", "Missing Anti-clickjacking Header", Severity.MEDIUM, "CWE-1021", null, null, "Set header X-Frame-Options atau CSP frame-ancestors."),
            new WebIssue(Tool.ZAP, "10038", "Content Security Policy (CSP) Header Not Set", Severity.MEDIUM, "CWE-693", null, null, "Tambahkan header Content-Security-Policy yang ketat."),
            new WebIssue(Tool.ZAP, "10054", "Cookie without SameSite Attribute", Severity.LOW, "CWE-1275", null, null, "Set atribut SameSite=Lax/Strict pada cookie."),
            new WebIssue(Tool.ZAP, "10036", "Server Leaks Version Information via 'Server' HTTP Response Header Field", Severity.LOW, "CWE-200", null, null, "Sembunyikan versi server pada response header."),
            new WebIssue(Tool.NUCLEI, "springboot-actuator", "Spring Boot Actuator Endpoints Exposed", Severity.MEDIUM, "CWE-200", null, null, "Batasi akses endpoint actuator (autentikasi/jaringan internal)."),
            new WebIssue(Tool.NUCLEI, "git-config", "Git Config File Exposure", Severity.MEDIUM, "CWE-200", null, null, "Blokir akses ke direktori .git pada web server."),
            new WebIssue(Tool.NUCLEI, "CVE-2021-44228", "Apache Log4j2 JNDI RCE (OOB detection)", Severity.CRITICAL, "CWE-502", "CVE-2021-44228", 10.0, "Upgrade log4j-core ke 2.17.1 atau lebih baru."));

    private final AssetRepository assets;
    private final FindingRepository findings;
    private final FindingEventRepository events;
    private final ScoringService scoring;
    private final SlaService sla;

    public DemoDataSeeder(AssetRepository assets, FindingRepository findings, FindingEventRepository events,
                          ScoringService scoring, SlaService sla) {
        this.assets = assets;
        this.findings = findings;
        this.events = events;
        this.scoring = scoring;
        this.sla = sla;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (assets.count() > 0) return;
        Random rnd = new Random(42);
        Instant now = Instant.now();

        Asset payment = assets.save(new Asset("payment-api:1.4.2", AssetType.CONTAINER_IMAGE, Criticality.CRITICAL));
        Asset loan = assets.save(new Asset("loan-service:2.3.0", AssetType.CONTAINER_IMAGE, Criticality.HIGH));
        Asset batch = assets.save(new Asset("batch-worker:0.9.1", AssetType.CONTAINER_IMAGE, Criticality.LOW));
        Asset portal = assets.save(new Asset("https://portal.demo.local", AssetType.WEB_APP, Criticality.HIGH));
        Asset admin = assets.save(new Asset("https://admin.demo.local", AssetType.WEB_APP, Criticality.MEDIUM));
        payment.setOwner("tim-payments");
        loan.setOwner("tim-lending");
        portal.setOwner("tim-web");
        admin.setOwner("tim-platform");
        assets.saveAll(List.of(payment, loan, portal, admin));

        int n = 0;
        for (Asset a : List.of(payment, loan, batch)) {
            for (Vuln v : LIBS) {
                if (rnd.nextDouble() > 0.55) continue;
                ParsedFinding pf = new ParsedFinding(null, v.id(), v.title() + " (" + v.pkg() + ")", v.title(),
                        "Upgrade " + v.pkg() + " ke versi " + v.fixed(), v.sev(), v.cvss(), v.id(), null,
                        "app/lib/" + v.pkg() + "-" + v.installed() + ".jar", v.pkg(), v.installed(), v.fixed());
                n += create(a, Tool.TRIVY, pf, v.epss(), v.kev(), rnd, now) ? 1 : 0;
            }
        }
        for (Asset a : List.of(portal, admin)) {
            for (WebIssue w : WEB) {
                if (rnd.nextDouble() > 0.65) continue;
                String loc = a.getName() + (w.tool() == Tool.ZAP ? "/login" : "/");
                ParsedFinding pf = new ParsedFinding(null, w.rule(), w.title(),
                        "Temuan dari " + w.tool() + " pada " + a.getName(), w.remediation(), w.sev(), w.cvss(), w.cve(), w.cwe(),
                        loc, null, null, null);
                Double epss = w.cve() != null ? 0.944 : null;
                n += create(a, w.tool(), pf, epss, w.cve() != null, rnd, now) ? 1 : 0;
            }
        }
        log.info("Data demo dibuat: {} aset, {} temuan", assets.count(), n);
    }

    private boolean create(Asset asset, Tool tool, ParsedFinding pf, Double epss, boolean kev, Random rnd, Instant now) {
        String fp = IngestService.fingerprint(tool, asset.getName(), pf);
        if (findings.findByFingerprint(fp).isPresent()) return false;

        Finding f = new Finding();
        f.setFingerprint(fp);
        f.setAsset(asset);
        f.setTool(tool);
        f.setTitle(pf.title());
        f.setDescription(pf.description());
        f.setRemediation(pf.remediation());
        f.setSeverity(pf.severity());
        f.setCvss(pf.cvss());
        f.setCveId(pf.cveId());
        f.setCweId(pf.cweId());
        f.setLocation(pf.location());
        f.setComponent(pf.component());
        f.setInstalledVersion(pf.installedVersion());
        f.setFixedVersion(pf.fixedVersion());
        f.setEpss(epss);
        if (epss != null) f.setEpssUpdatedAt(now);
        f.setKnownExploited(kev);

        Instant first = now.minus(Duration.ofHours(24L * (3 + rnd.nextInt(72)) + rnd.nextInt(24)));
        f.setFirstSeen(first);
        f.setLastSeen(now.minus(Duration.ofHours(rnd.nextInt(48))));
        f.setDueDate(sla.dueDate(pf.severity(), first));
        f.setPriorityScore(scoring.score(f));

        double roll = rnd.nextDouble();
        FindingStatus status;
        Instant resolved = null;
        if (roll < 0.30) {
            status = rnd.nextDouble() < 0.6 ? FindingStatus.VERIFIED : FindingStatus.FIXED;
            long maxHours = Math.max(24, Duration.between(first, now).toHours());
            resolved = first.plus(Duration.ofHours(12 + (long) (rnd.nextDouble() * (maxHours - 12))));
        } else if (roll < 0.36) {
            status = FindingStatus.ACCEPTED_RISK;
            resolved = first.plus(Duration.ofDays(2));
        } else if (roll < 0.40) {
            status = FindingStatus.FALSE_POSITIVE;
            resolved = first.plus(Duration.ofDays(1));
        } else if (roll < 0.55) {
            status = FindingStatus.IN_PROGRESS;
            f.setAssignee(asset.getOwner() != null ? asset.getOwner() : "tim-platform");
        } else {
            status = FindingStatus.OPEN;
        }
        f.setStatus(status);
        f.setResolvedAt(resolved);
        findings.save(f);

        FindingEvent detected = new FindingEvent(f.getId(), FindingEvent.Type.DETECTED, null, FindingStatus.OPEN,
                "Terdeteksi oleh " + tool + " (data demo)", "system");
        detected.setCreatedAt(first);
        events.save(detected);
        if (status != FindingStatus.OPEN) {
            FindingEvent e = new FindingEvent(f.getId(), FindingEvent.Type.STATUS_CHANGE, FindingStatus.OPEN, status,
                    status == FindingStatus.ACCEPTED_RISK ? "Risiko diterima: sistem akan dipensiunkan Q1" : null, "demo");
            e.setCreatedAt(resolved != null ? resolved : first.plus(Duration.ofDays(1)));
            events.save(e);
        }
        return true;
    }
}
