///*
// * *****************************************************************************
// *      Cloud Foundry
// *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
// *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
// *      You may not use this product except in compliance with the License.
// *
// *      This product includes a number of subcomponents with
// *      separate copyright notices and license terms. Your use of these
// *      subcomponents is subject to the terms and conditions of the
// *      subcomponent's license, as noted in the LICENSE file.
// * *****************************************************************************
// */
//package org.cloudfoundry.identity.uaa.provider;
//
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//
//import org.cloudfoundry.identity.uaa.util.JsonUtils;
//import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
//
//import org.opensaml.saml2.metadata.provider.MetadataProviderException;
//import org.springframework.dao.EmptyResultDataAccessException;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.ExceptionHandler;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.List;
//
//import static org.springframework.http.HttpStatus.OK;
//import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
//import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
//import static org.springframework.web.bind.annotation.RequestMethod.GET;
//import static org.springframework.web.bind.annotation.RequestMethod.POST;
//import static org.springframework.web.bind.annotation.RequestMethod.PUT;
//
//@RequestMapping("/key-provider-config")
//@RestController
//public class KeyProviderConfigEndpoints {
//
//    protected static Log logger = LogFactory.getLog(KeyProviderConfigEndpoints.class);
//
//    private final KeyProviderConfigProvisioning keyProviderProvisioning;
//    private final KeyProviderConfigValidator keyProviderValidator;
//
//    public KeyProviderConfigEndpoints(KeyProviderConfigProvisioning keyProviderProvisioning, KeyProviderConfigValidator keyProviderValidator) {
//        this.keyProviderProvisioning = keyProviderProvisioning;
//        this.keyProviderValidator = keyProviderValidator;
//    }
//
//    @RequestMapping(method = PUT)
//    public ResponseEntity<KeyProviderConfig> updateKeyProviderConfigConfig(@RequestBody KeyProviderConfig body) {
//        KeyProviderConfig existing = KeyProviderProvisioning.retrieve(IdentityZoneHolder.get().getId());
//        String zoneId = IdentityZoneHolder.get().getId();
//        body.setId(id);
//        body.setIdentityZoneId(zoneId);
//        if (!body.configIsValid()) {
//            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
//        }
//        body.setEntityId(existing.getEntityId());
//
//        samlValidator.validateKeyProviderConfig(body);
//
//        KeyProviderConfig updatedSp = serviceProviderProvisioning.update(body, zoneId);
//        return new ResponseEntity<>(updatedSp, OK);
//    }
//
//    @RequestMapping(method = GET)
//    public ResponseEntity<List<KeyProviderConfig>> retrieveKeyProviderConfigs(
//        @RequestParam(value = "active_only", required = false) String activeOnly) {
//        Boolean retrieveActiveOnly = Boolean.valueOf(activeOnly);
//        List<KeyProviderConfig> serviceProviderList =
//            serviceProviderProvisioning.retrieveAll(retrieveActiveOnly,
//                                                    IdentityZoneHolder.get().getId());
//        return new ResponseEntity<>(serviceProviderList, OK);
//    }
//
//    @RequestMapping(value = "{id}", method = GET)
//    public ResponseEntity<KeyProviderConfig> retrieveKeyProviderConfig(@PathVariable String id) {
//        KeyProviderConfigConfig serviceProvider = keyProviderProvisioning.retrieve(IdentityZoneHolder.get().getId());
//        return new ResponseEntity<>(serviceProvider, OK);
//    }
//
//    @RequestMapping(value = "{id}", method = DELETE)
//    public ResponseEntity<KeyProviderConfig> deleteKeyProviderConfig(@PathVariable String id) {
//        KeyProviderConfig serviceProvider = keyProviderProvisioning.retrieve(IdentityZoneHolder.get().getId());
//        keyProviderProvisioning.delete(id, IdentityZoneHolder.get().getId());
//        return new ResponseEntity<>(serviceProvider, OK);
//    }
//
//    @ExceptionHandler(EmptyResultDataAccessException.class)
//    public ResponseEntity<String> handleProviderNotFoundException() {
//        return new ResponseEntity<>("Provider not found.", HttpStatus.NOT_FOUND);
//    }
//
//}
