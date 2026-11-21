package com.vulndash.web;

import com.vulndash.service.AssetService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/assets")
public class AssetController {

    private final AssetService service;

    public AssetController(AssetService service) {
        this.service = service;
    }

    @GetMapping
    public List<AssetService.AssetDto> list() {
        return service.list();
    }

    @PatchMapping("/{id}")
    public AssetService.AssetDto update(@PathVariable Long id, @RequestBody AssetService.Update body) {
        return service.update(id, body);
    }
}
