package com.vulndash.parser;

import com.vulndash.domain.Tool;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Component
public class ParserRegistry {

    private final Map<Tool, ScanParser> parsers = new EnumMap<>(Tool.class);

    public ParserRegistry(List<ScanParser> all) {
        all.forEach(p -> parsers.put(p.tool(), p));
    }

    public ScanParser get(Tool tool) {
        ScanParser p = parsers.get(tool);
        if (p == null) throw new IllegalArgumentException("Tool tidak didukung: " + tool);
        return p;
    }
}
