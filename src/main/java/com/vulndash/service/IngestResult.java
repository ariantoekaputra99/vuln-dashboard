package com.vulndash.service;

import com.vulndash.domain.Tool;

import java.util.List;

public record IngestResult(
        Long scanId,
        Tool tool,
        int total,
        int created,
        int updated,
        int reopened,
        int autoResolved,
        List<String> assets) {
}
