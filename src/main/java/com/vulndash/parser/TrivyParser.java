package com.vulndash.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulndash.domain.AssetType;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static com.vulndash.parser.ParserSupport.*;

/** Parser untuk output {@code trivy ... --format json}. */
@Component
public class TrivyParser implements ScanParser {

    private final ObjectMapper mapper;

    public TrivyParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Tool tool() {
        return Tool.TRIVY;
    }

    @Override
    public ParsedScan parse(InputStream in) throws IOException {
        JsonNode root;
        try {
            root = mapper.readTree(in);
        } catch (IOException e) {
            throw new ScanParseException("File bukan JSON Trivy yang valid", e);
        }
        if (root == null || !root.has("Results") && !root.has("ArtifactName")) {
            throw new ScanParseException("Format tidak dikenali: field 'Results'/'ArtifactName' tidak ada (gunakan --format json)");
        }

        String artifact = text(root, "ArtifactName");
        AssetType assetType = switch (String.valueOf(text(root, "ArtifactType"))) {
            case "container_image" -> AssetType.CONTAINER_IMAGE;
            case "repository", "filesystem" -> AssetType.REPOSITORY;
            default -> AssetType.OTHER;
        };

        List<ParsedFinding> out = new ArrayList<>();
        for (JsonNode result : root.path("Results")) {
            String target = text(result, "Target");

            for (JsonNode v : result.path("Vulnerabilities")) {
                String id = text(v, "VulnerabilityID");
                if (id == null) continue;
                String title = text(v, "Title");
                String pkg = text(v, "PkgName");
                String display = (title != null ? title : id) + (pkg != null ? " (" + pkg + ")" : "");
                String cwe = null;
                if (v.path("CweIDs").isArray() && !v.path("CweIDs").isEmpty()) {
                    cwe = normalizeCwe(v.path("CweIDs").get(0).asText());
                }
                String fixed = text(v, "FixedVersion");
                Double cvss = bestCvss(v.path("CVSS"));
                Severity sev = Severity.parse(text(v, "Severity"));
                out.add(new ParsedFinding(
                        null, id, trunc(display, 500), trunc(text(v, "Description"), 4000),
                        fixed != null ? "Upgrade " + (pkg != null ? pkg : "komponen") + " ke versi " + fixed : null,
                        sev, cvss, normalizeCve(id), cwe, target, pkg,
                        text(v, "InstalledVersion"), fixed));
            }

            for (JsonNode m : result.path("Misconfigurations")) {
                String id = text(m, "ID");
                if (id == null) id = text(m, "AVDID");
                if (id == null) continue;
                out.add(new ParsedFinding(
                        null, id, trunc(text(m, "Title") != null ? text(m, "Title") : id, 500),
                        trunc(text(m, "Description"), 4000), trunc(text(m, "Resolution"), 2000),
                        Severity.parse(text(m, "Severity")), null, null, null, target, null, null, null));
            }

            for (JsonNode s : result.path("Secrets")) {
                String id = text(s, "RuleID");
                if (id == null) continue;
                // Nilai secret sengaja TIDAK disimpan (hanya jenis & lokasi).
                String loc = target + (s.has("StartLine") ? ":" + s.path("StartLine").asInt() : "");
                out.add(new ParsedFinding(
                        null, id, trunc("Secret terdeteksi: " + (text(s, "Title") != null ? text(s, "Title") : id), 500),
                        "Kredensial/secret hardcoded terdeteksi pada file. Nilai tidak disimpan oleh dashboard.",
                        "Cabut (revoke) secret, rotasi kredensial, pindahkan ke secret manager.",
                        Severity.parse(text(s, "Severity")), null, null, "CWE-798", loc, null, null, null));
            }
        }
        return new ParsedScan(Tool.TRIVY, artifact, assetType, out);
    }

    /** Pilih CVSS v3 tertinggi (NVD diprioritaskan), fallback ke v2. */
    private Double bestCvss(JsonNode cvss) {
        if (cvss == null || !cvss.isObject()) return null;
        Double nvd = number(cvss.path("nvd"), "V3Score");
        if (nvd != null) return nvd;
        Double max = null;
        for (JsonNode src : cvss) {
            Double v3 = number(src, "V3Score");
            if (v3 != null && (max == null || v3 > max)) max = v3;
        }
        if (max != null) return max;
        for (JsonNode src : cvss) {
            Double v2 = number(src, "V2Score");
            if (v2 != null && (max == null || v2 > max)) max = v2;
        }
        return max;
    }
}
