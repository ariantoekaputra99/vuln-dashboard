package com.vulndash.web;

import com.vulndash.service.ReportService;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping(value = "/executive", produces = MediaType.TEXT_HTML_VALUE)
    public String executive() {
        return reports.executiveHtml();
    }

    @GetMapping(value = "/findings.csv", produces = "text/csv")
    public ResponseEntity<String> csv() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename("vuln-findings-" + LocalDate.now(ZoneOffset.UTC) + ".csv").build().toString())
                .contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .body(reports.findingsCsv());
    }

    /** Buat laporan sekarang & simpan ke disk (selain jadwal mingguan otomatis). */
    @PostMapping("/generate")
    public List<String> generate() throws IOException {
        return reports.generateToDisk();
    }

    @GetMapping("/files")
    public List<String> files() throws IOException {
        return reports.listFiles();
    }

    @GetMapping("/files/{name}")
    public ResponseEntity<Resource> download(@PathVariable String name) {
        Path p = reports.resolveFile(name);
        MediaType type = name.endsWith(".csv") ? MediaType.parseMediaType("text/csv") : MediaType.TEXT_HTML;
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(name).build().toString())
                .contentType(type)
                .body(new FileSystemResource(p));
    }
}
