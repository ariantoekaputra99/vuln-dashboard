package com.vulndash.parser;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.regex.Pattern;

final class ParserSupport {

    private static final Pattern HTML_TAG = Pattern.compile("<[^>]*>");
    private static final Pattern CVE = Pattern.compile("(?i)^CVE-\\d{4}-\\d{4,}$");

    private ParserSupport() {
    }

    static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        if (v == null || v.isNull() || v.isMissingNode() || !v.isValueNode()) return null;
        String s = v.asText().trim();
        return s.isEmpty() ? null : s;
    }

    static Double number(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) return null;
        if (v.isNumber()) return v.asDouble();
        if (v.isTextual()) {
            try {
                return Double.parseDouble(v.asText().trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    static String stripHtml(String s) {
        if (s == null) return null;
        return HTML_TAG.matcher(s).replaceAll(" ").replaceAll("\\s+", " ").trim();
    }

    static String trunc(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    /** Ambil string pertama dari field yang bisa berupa string atau array. */
    static String firstText(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) return null;
        if (v.isArray()) {
            return v.isEmpty() ? null : (v.get(0).isValueNode() ? v.get(0).asText().trim() : null);
        }
        return v.isValueNode() ? v.asText().trim() : null;
    }

    static String normalizeCve(String id) {
        return id != null && CVE.matcher(id).matches() ? id.toUpperCase() : null;
    }

    static String normalizeCwe(String raw) {
        if (raw == null) return null;
        String digits = raw.replaceAll("(?i)^CWE-", "").trim();
        if (!digits.matches("\\d+") || digits.equals("0")) return null;
        return "CWE-" + digits;
    }
}
