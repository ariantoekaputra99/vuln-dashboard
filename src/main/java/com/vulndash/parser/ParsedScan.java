package com.vulndash.parser;

import com.vulndash.domain.AssetType;
import com.vulndash.domain.Tool;

import java.util.List;

public record ParsedScan(Tool tool, String assetHint, AssetType assetTypeHint, List<ParsedFinding> findings) {
}
