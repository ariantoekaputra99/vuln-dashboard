package com.vulndash.service;

import com.vulndash.domain.*;
import com.vulndash.parser.ParsedFinding;
import com.vulndash.parser.ParsedScan;
import com.vulndash.parser.ParserRegistry;
import com.vulndash.repo.AssetRepository;
import com.vulndash.repo.FindingEventRepository;
import com.vulndash.repo.FindingRepository;
import com.vulndash.repo.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/**
 * Mengimpor hasil scan: parse -> normalisasi -> deduplikasi (fingerprint) -> hitung SLA & skor prioritas.
 * Temuan yang tidak muncul lagi pada scan ulang (asset + tool sama) otomatis ditandai FIXED.
 */
@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);

    private final ParserRegistry parsers;
    private final AssetRepository assets;
    private final ScanRepository scans;
    private final FindingRepository findings;
    private final FindingEventRepository events;
    private final ScoringService scoring;
    private final SlaService sla;
    private final EnrichmentService enrichment;
    private final TransactionTemplate tx;

    public IngestService(ParserRegistry parsers, AssetRepository assets, ScanRepository scans,
                         FindingRepository findings, FindingEventRepository events,
                         ScoringService scoring, SlaService sla, EnrichmentService enrichment,
                         PlatformTransactionManager txManager) {
        this.parsers = parsers;
        this.assets = assets;
        this.scans = scans;
        this.findings = findings;
        this.events = events;
        this.scoring = scoring;
        this.sla = sla;
        this.enrichment = enrichment;
        this.tx = new TransactionTemplate(txManager);
    }

    public record Options(String assetOverride, Criticality criticality, boolean autoResolve) {
        public static Options defaults() {
            return new Options(null, null, true);
        }
    }

    public IngestResult ingest(Tool tool, String filename, InputStream in, Options opts) throws IOException {
        ParsedScan parsed = parsers.get(tool).parse(in);
        IngestResult result = tx.execute(status -> doIngest(parsed, filename, opts));
        // Enrichment (EPSS/KEV) dilakukan di luar transaksi karena memanggil jaringan; kegagalan tidak membatalkan import.
        try {
            enrichment.refreshStale();
        } catch (Exception e) {
            log.warn("Enrichment EPSS/KEV gagal (diabaikan): {}", e.getMessage());
        }
        return result;
    }

    private IngestResult doIngest(ParsedScan parsed, String filename, Options opts) {
        Instant now = Instant.now();
        Scan scan = scans.save(new Scan(parsed.tool(), safeName(filename)));

        Map<String, List<ParsedFinding>> byAsset = new LinkedHashMap<>();
        for (ParsedFinding pf : parsed.findings()) {
            String name = firstNonBlank(opts.assetOverride(), pf.assetName(), parsed.assetHint());
            if (name == null) {
                throw new BadRequestException("Nama aset tidak dapat ditentukan dari file; sertakan parameter 'asset'");
            }
            byAsset.computeIfAbsent(trimName(name), k -> new ArrayList<>()).add(pf);
        }
        // Scan bersih (0 temuan) tetap harus bisa menutup temuan lama pada aset yang diketahui.
        if (byAsset.isEmpty()) {
            String name = firstNonBlank(opts.assetOverride(), parsed.assetHint());
            if (name != null) byAsset.put(trimName(name), List.of());
        }

        int created = 0, updated = 0, reopened = 0, resolved = 0, total = 0;

        for (var entry : byAsset.entrySet()) {
            Asset asset = getOrCreateAsset(entry.getKey(), parsed, opts);
            Set<String> seen = new HashSet<>();

            for (ParsedFinding pf : entry.getValue()) {
                String fp = fingerprint(parsed.tool(), asset.getName(), pf);
                if (!seen.add(fp)) continue; // duplikat di file yang sama
                total++;

                Optional<Finding> existing = findings.findByFingerprint(fp);
                if (existing.isPresent()) {
                    Finding f = existing.get();
                    f.setAsset(asset);
                    boolean wasClosed = f.getStatus() == FindingStatus.FIXED || f.getStatus() == FindingStatus.VERIFIED;
                    refresh(f, pf, scan, now);
                    if (wasClosed) {
                        FindingStatus from = f.getStatus();
                        f.setStatus(FindingStatus.OPEN);
                        f.setResolvedAt(null);
                        f.setDueDate(sla.dueDate(f.getSeverity(), now));
                        f.setPriorityScore(scoring.score(f));
                        findings.save(f);
                        events.save(new FindingEvent(f.getId(), FindingEvent.Type.REOPENED, from, FindingStatus.OPEN,
                                "Terdeteksi kembali pada scan #" + scan.getId(), "system"));
                        reopened++;
                    } else {
                        f.setPriorityScore(scoring.score(f));
                        findings.save(f);
                        updated++;
                    }
                } else {
                    Finding f = newFinding(fp, asset, parsed.tool(), pf, scan, now);
                    findings.save(f);
                    events.save(new FindingEvent(f.getId(), FindingEvent.Type.DETECTED, null, FindingStatus.OPEN,
                            "Terdeteksi oleh " + parsed.tool() + " (scan #" + scan.getId() + ")", "system"));
                    created++;
                }
            }

            if (opts.autoResolve()) {
                for (Finding old : findings.findByAssetIdAndToolAndStatusIn(asset.getId(), parsed.tool(), FindingStatus.ACTIVE)) {
                    if (seen.contains(old.getFingerprint())) continue;
                    FindingStatus from = old.getStatus();
                    old.setStatus(FindingStatus.FIXED);
                    old.setResolvedAt(now);
                    findings.save(old);
                    events.save(new FindingEvent(old.getId(), FindingEvent.Type.AUTO_RESOLVED, from, FindingStatus.FIXED,
                            "Tidak terdeteksi pada scan ulang #" + scan.getId() + " (perlu diverifikasi)", "system"));
                    resolved++;
                }
            }
        }

        scan.setCounts(total, created, reopened, resolved);
        scans.save(scan);
        return new IngestResult(scan.getId(), parsed.tool(), total, created, updated, reopened, resolved,
                new ArrayList<>(byAsset.keySet()));
    }

    private Asset getOrCreateAsset(String name, ParsedScan parsed, Options opts) {
        Asset asset = assets.findByName(name).orElseGet(() ->
                assets.save(new Asset(name, parsed.assetTypeHint() != null ? parsed.assetTypeHint() : AssetType.OTHER,
                        opts.criticality() != null ? opts.criticality() : Criticality.MEDIUM)));
        if (opts.criticality() != null && asset.getCriticality() != opts.criticality()) {
            asset.setCriticality(opts.criticality());
            assets.save(asset);
        }
        return asset;
    }

    private Finding newFinding(String fp, Asset asset, Tool tool, ParsedFinding pf, Scan scan, Instant now) {
        Finding f = new Finding();
        f.setFingerprint(fp);
        f.setAsset(asset);
        f.setTool(tool);
        f.setStatus(FindingStatus.OPEN);
        f.setFirstSeen(now);
        refresh(f, pf, scan, now);
        f.setDueDate(sla.dueDate(f.getSeverity(), now));
        f.setPriorityScore(scoring.score(f));
        return f;
    }

    /** Salin atribut dari hasil parse (data scanner terbaru dianggap paling akurat). */
    private void refresh(Finding f, ParsedFinding pf, Scan scan, Instant now) {
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
        f.setLastSeen(now);
        f.setLastScanId(scan.getId());
    }

    public static String fingerprint(Tool tool, String assetName, ParsedFinding pf) {
        // ZAP: lokasi/instance bisa berubah antar scan, jadi cukup rule + situs.
        String locationKey = tool == Tool.ZAP ? "" : nz(pf.location()) + "|" + nz(pf.component());
        String raw = tool + "|" + assetName.toLowerCase(Locale.ROOT) + "|" + nz(pf.ruleId()) + "|" + locationKey;
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static String trimName(String name) {
        String n = name.trim();
        return n.length() > 255 ? n.substring(0, 255) : n;
    }

    private static String safeName(String filename) {
        if (filename == null) return null;
        String n = filename.replaceAll("[^A-Za-z0-9._ -]", "_");
        return n.length() > 255 ? n.substring(0, 255) : n;
    }
}
