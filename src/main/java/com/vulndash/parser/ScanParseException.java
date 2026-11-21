package com.vulndash.parser;

public class ScanParseException extends RuntimeException {
    public ScanParseException(String message, Throwable cause) {
        super(message, cause);
    }

    public ScanParseException(String message) {
        super(message);
    }
}
