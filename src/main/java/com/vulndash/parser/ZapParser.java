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

/** Parser untuk laporan OWASP ZAP "Traditional JSON" ({@code -J report.json}). */
@Component
public class ZapParser implements ScanParser {

    private final ObjectMapper mapper;

    public ZapParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Tool tool() {
        return Tool.ZAP;
    }

    @Override
    public ParsedScan parse(InputStream in) throws IOException {
        JsonNode root;
        try {
            root = mapper.readTree(in);
        } catch (IOException e) {
            throw new ScanParseException("File bukan JSON ZAP yang valid", e);
        }
        if (root == null || !root.has("site")) {
            throw new ScanParseException("Format tidak dikenali: field 'site' tidak ada (gunakan laporan Traditional JSON)");
        }

        List<ParsedFinding> out = new ArrayList<>();
        String firstSite = null;
        for (JsonNode site : root.path("site")) {
            String siteName = text(site, "@name");
            if (firstSite == null) firstSite = siteName;
            for (JsonNode alert : site.path("alerts")) {
                String ruleId = text(alert, "pluginid");
                if (ruleId == null) ruleId = text(alert, "alertRef");
                String name = text(alert, "name");
                if (name == null) name = text(alert, "alert");
                if (ruleId == null || name == null) continue;

                Severity sev = switch (String.valueOf(text(alert, "riskcode"))) {
                    case "3" -> Severity.HIGH;
                    case "2" -> Severity.MEDIUM;
                    case "1" -> Severity.LOW;
                    default -> Severity.INFO;
                };

                JsonNode instances = alert.path("instances");
                String location = siteName;
                if (instances.isArray() && !instances.isEmpty()) {
                    String uri = text(instances.get(0), "uri");
                    String param = text(instances.get(0), "param");
                    location = (uri != null ? uri : siteName) + (param != null ? " [param: " + param + "]" : "");
                    if (instances.size() > 1) location += " (+" + (instances.size() - 1) + " lokasi lain)";
                }

                out.add(new ParsedFinding(
                        siteName, ruleId, trunc(name, 500),
                        trunc(stripHtml(text(alert, "desc")), 4000),
                        trunc(stripHtml(text(alert, "solution")), 2000),
                        sev, null, null, normalizeCwe(text(alert, "cweid")),
                        trunc(location, 1000), null, null, null));
            }
        }
        return new ParsedScan(Tool.ZAP, firstSite, AssetType.WEB_APP, out);
    }
}
