package com.vulndash.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulndash.domain.AssetType;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static com.vulndash.parser.ParserSupport.*;

/** Parser untuk output Nuclei {@code -jsonl} (satu JSON per baris) atau {@code -json-export} (array). */
@Component
public class NucleiParser implements ScanParser {

    private final ObjectMapper mapper;

    public NucleiParser(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public Tool tool() {
        return Tool.NUCLEI;
    }

    @Override
    public ParsedScan parse(InputStream in) throws IOException {
        String body = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        List<JsonNode> items = new ArrayList<>();
        try {
            if (body.startsWith("[")) {
                mapper.readTree(body).forEach(items::add);
            } else {
                for (String line : body.split("\\R")) {
                    if (line.isBlank()) continue;
                    items.add(mapper.readTree(line));
                }
            }
        } catch (IOException e) {
            throw new ScanParseException("File bukan JSON/JSONL Nuclei yang valid", e);
        }

        List<ParsedFinding> out = new ArrayList<>();
        String firstHost = null;
        for (JsonNode item : items) {
            String templateId = text(item, "template-id");
            JsonNode info = item.path("info");
            if (templateId == null || !info.isObject()) {
                throw new ScanParseException("Format tidak dikenali: field 'template-id'/'info' tidak ada");
            }
            String host = text(item, "host");
            if (firstHost == null) firstHost = host;

            JsonNode cls = info.path("classification");
            String cve = normalizeCve(firstText(cls, "cve-id"));
            Double cvss = number(cls, "cvss-score");
            Severity sev = Severity.parse(text(info, "severity"));
            if (cvss != null && cvss > 0 && text(info, "severity") == null) sev = Severity.fromCvss(cvss);

            String name = text(info, "name") != null ? text(info, "name") : templateId;
            String matched = text(item, "matched-at");

            out.add(new ParsedFinding(
                    host, templateId, trunc(name, 500), trunc(text(info, "description"), 4000),
                    trunc(text(info, "remediation"), 2000), sev, cvss, cve,
                    normalizeCwe(firstText(cls, "cwe-id")),
                    trunc(matched != null ? matched : host, 1000), null, null, null));
        }
        return new ParsedScan(Tool.NUCLEI, firstHost, AssetType.WEB_APP, out);
    }
}
