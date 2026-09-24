import template from './sw-customer-detail-base.html.twig';

const { Component } = Shopware;

Component.override('sw-customer-detail-base', {
    template,

    inject: ['acl'],
});
