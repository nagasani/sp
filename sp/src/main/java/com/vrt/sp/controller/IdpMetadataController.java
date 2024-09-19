package com.vrt.sp.controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IdpMetadataController {

    @GetMapping("/idp/metadata")
    public String metadata() {
        // Static IdP metadata (for simplicity)
        return "<EntityDescriptor entityID='http://localhost:8080/idp' xmlns='urn:oasis:names:tc:SAML:2.0:metadata'> ... </EntityDescriptor>";
    }
}
