package com.vulndash.service;

import com.vulndash.config.VulnDashProperties;
import com.vulndash.domain.Finding;
import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.repo.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Service
public class ReportService {

    private static final Pattern SAFE_NAME = Pattern.compile("^[A-Za-z0-9._-]{1,100}$");

    private final DashboardService dashboard;
    private final FindingRepository findings;
    private final SlaService sla;
    private final Path dir;

    public ReportService(DashboardService dashboard, FindingRepository findings, SlaService sla, VulnDashProperties props) {
        this.dashboard = dashboard;
        this.sla = sla;
        this.findings = findings;
        this.dir = Path.of(props.report().directory()).toAbsolutePath().normalize();
    }

    /** Laporan eksekutif (HTML mandiri, siap cetak ke PDF dari browser). */
    public String executiveHtml() {
        DashboardSummary s = dashboard.summary();
        var k = s.kpis();
        StringBuilder h = new StringBuilder(8_192);
        h.append("<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\">")
                .append("<title>Laporan Vulnerability Management</title><style>")
                .append("body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:32px auto;padding:0 16px;color:#1b2430}")
                .append("h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:2px solid #e3e8ef;padding-bottom:6px}")
                .append("table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d9dfe8;padding:6px 8px;text-align:left}")
                .append("th{background:#f3f6fa}.kpi{display:flex;gap:12px;flex-wrap:wrap}.kpi div{flex:1;min-width:130px;border:1px solid #d9dfe8;border-radius:8px;padding:10px}")
                .append(".kpi b{display:block;font-size:24px}.muted{color:#667085;font-size:12px}")
                .append("</style></head><body>");
        h.append("<h1>Laporan Vulnerability Management</h1><div class=\"muted\">Dibuat: ")
                .append(esc(s.generatedAt().toString())).append("</div>");

        h.append("<h2>Ringkasan</h2><div class=\"kpi\">")
                .append(kpi("Temuan aktif", k.active()))
                .append(kpi("Critical + High", k.criticalAndHigh()))
                .append(kpi("Melewati SLA", k.overdue()))
                .append(kpi("Jatuh tempo ≤ 7 hari", k.dueIn7Days()))
                .append(kpi("Dieksploitasi aktif (KEV)", k.knownExploited()))
                .append(kpi("Kepatuhan SLA", k.slaCompliancePercent() == null ? "n/a" : k.slaCompliancePercent() + "%"))
                .append("</div>");

        h.append("<h2>Temuan aktif per severity</h2><table><tr><th>Severity</th><th>Jumlah</th><th>SLA (hari)</th><th>MTTR (hari)</th></tr>");
        for (Severity sev : Severity.values()) {
            h.append("<tr><td>").append(sev).append("</td><td>").append(s.activeBySeverity().get(sev))
                    .append("</td><td>").append(slaDays(sev)).append("</td><td>")
                    .append(s.mttrDaysBySeverity().get(sev) == null ? "-" : s.mttrDaysBySeverity().get(sev))
                    .append("</td></tr>");
        }
        h.append("</table>");

        h.append("<h2>Prioritas teratas (CVSS + EPSS + kritikalitas aset)</h2>");
        appendFindingTable(h, s.topFindings());

        h.append("<h2>Temuan melewati SLA</h2>");
        if (s.slaBreaches().isEmpty()) h.append("<p>Tidak ada temuan yang melewati SLA.</p>");
        else appendFindingTable(h, s.slaBreaches());

        h.append("<h2>Aset berisiko tertinggi</h2><table><tr><th>Aset</th><th>Kritikalitas</th><th>Aktif</th><th>Critical</th><th>High</th><th>Lewat SLA</th><th>Skor risiko</th></tr>");
        for (var a : s.topAssets()) {
            h.append("<tr><td>").append(esc(a.name())).append("</td><td>").append(a.criticality()).append("</td><td>")
                    .append(a.active()).append("</td><td>").append(a.critical()).append("</td><td>").append(a.high())
                    .append("</td><td>").append(a.overdue()).append("</td><td>").append(a.riskScore()).append("</td></tr>");
        }
        h.append("</table>");

        h.append("<h2>Tren temuan terbuka (mingguan)</h2><table><tr><th>Tanggal</th><th>Temuan terbuka</th></tr>");
        for (var t : s.trend()) {
            h.append("<tr><td>").append(esc(t.date())).append("</td><td>").append(t.open()).append("</td></tr>");
        }
        h.append("</table></body></html>");
        return h.toString();
    }

    /** Ekspor CSV seluruh temuan. Sel diberi prefiks untuk mencegah CSV/formula injection di Excel. */
    @Transactional(readOnly = true)
    public String findingsCsv() {
        Instant now = Instant.now();
        StringBuilder sb = new StringBuilder();
        sb.append("id,aset,tool,severity,cvss,cve,epss,kev,skor_prioritas,status,assignee,judul,lokasi,first_seen,due_date,resolved_at,lewat_sla\n");
        List<Finding> all = findings.findAll().stream()
                .sorted(Comparator.comparingDouble(Finding::getPriorityScore).reversed()).toList();
        for (Finding f : all) {
            sb.append(f.getId()).append(',')
                    .append(csv(f.getAsset().getName())).append(',')
                    .append(f.getTool()).append(',')
                    .append(f.getSeverity()).append(',')
                    .append(f.getCvss() == null ? "" : f.getCvss()).append(',')
                    .append(csv(f.getCveId())).append(',')
                    .append(f.getEpss() == null ? "" : f.getEpss()).append(',')
                    .append(f.isKnownExploited()).append(',')
                    .append(f.getPriorityScore()).append(',')
                    .append(f.getStatus()).append(',')
                    .append(csv(f.getAssignee())).append(',')
                    .append(csv(f.getTitle())).append(',')
                    .append(csv(f.getLocation())).append(',')
                    .append(f.getFirstSeen()).append(',')
                    .append(f.getDueDate()).append(',')
                    .append(f.getResolvedAt() == null ? "" : f.getResolvedAt()).append(',')
                    .append(f.isOverdue(now)).append('\n');
        }
        return sb.toString();
    }

    /** Tulis laporan HTML + CSV ke direktori laporan; mengembalikan nama file. */
    @Transactional(readOnly = true)
    public List<String> generateToDisk() throws IOException {
        Files.createDirectories(dir);
        String stamp = LocalDate.now(ZoneOffset.UTC).toString();
        Path html = dir.resolve("vuln-report-" + stamp + ".html");
        Path csv = dir.resolve("vuln-findings-" + stamp + ".csv");
        Files.writeString(html, executiveHtml(), StandardCharsets.UTF_8);
        Files.writeString(csv, findingsCsv(), StandardCharsets.UTF_8);
        return List.of(html.getFileName().toString(), csv.getFileName().toString());
    }

    public List<String> listFiles() throws IOException {
        if (!Files.isDirectory(dir)) return List.of();
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(Files::isRegularFile).map(p -> p.getFileName().toString())
                    .filter(n -> SAFE_NAME.matcher(n).matches())
                    .sorted(Comparator.reverseOrder()).toList();
        }
    }

    /** Resolusi file laporan dengan validasi nama (anti path traversal). */
    public Path resolveFile(String name) {
        if (name == null || !SAFE_NAME.matcher(name).matches()) throw new BadRequestException("Nama file tidak valid");
        Path p = dir.resolve(name).normalize();
        if (!p.startsWith(dir) || !Files.isRegularFile(p)) throw new NotFoundException("Laporan tidak ditemukan");
        return p;
    }

    private int slaDays(Severity s) {
        return sla.days(s);
    }

    private void appendFindingTable(StringBuilder h, List<FindingDto> list) {
        h.append("<table><tr><th>Skor</th><th>Prioritas</th><th>Severity</th><th>Aset</th><th>Temuan</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Status</th><th>Jatuh tempo</th></tr>");
        for (FindingDto f : list) {
            h.append("<tr><td>").append(f.priorityScore()).append("</td><td>").append(f.priority()).append("</td><td>")
                    .append(f.severity()).append("</td><td>").append(esc(f.assetName())).append("</td><td>")
                    .append(esc(f.title())).append("</td><td>").append(esc(f.cveId())).append("</td><td>")
                    .append(f.cvss() == null ? "-" : f.cvss()).append("</td><td>")
                    .append(f.epss() == null ? "-" : String.format("%.1f%%", f.epss() * 100)).append("</td><td>")
                    .append(f.status()).append("</td><td>").append(esc(f.dueDate().toString().substring(0, 10)))
                    .append(f.overdue() ? " (lewat)" : "").append("</td></tr>");
        }
        h.append("</table>");
    }

    private static String kpi(String label, Object value) {
        return "<div><b>" + esc(String.valueOf(value)) + "</b>" + esc(label) + "</div>";
    }

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    static String csv(String s) {
        if (s == null) return "";
        String v = s;
        if (!v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0) v = "'" + v;
        return "\"" + v.replace("\"", "\"\"") + "\"";
    }
}
