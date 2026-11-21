package com.vulndash.parser;

import com.vulndash.domain.Tool;

import java.io.IOException;
import java.io.InputStream;

public interface ScanParser {

    Tool tool();

    ParsedScan parse(InputStream in) throws IOException;
}
