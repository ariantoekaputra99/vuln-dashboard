package com.vulndash.parser;

import com.vulndash.domain.Severity;

/** Hasil normalisasi satu temuan dari scanner mana pun. */
public record ParsedFinding(
        String assetName,
        String ruleId,
        String title,
        String description,
        String remediation,
        Severity severity,
        Double cvss,
        String cveId,
        String cweId,
        String location,
        String component,
        String installedVersion,
        String fixedVersion) {
}
