import template from './act-passkey-info.html.twig';
import './act-passkey-info.scss';

const { Component } = Shopware;

const HOW_TO_ITEM_COUNT = 6;

Component.register('act-passkey-info', {
    template,

    computed: {
        howToItems() {
            return Array.from(
                { length: HOW_TO_ITEM_COUNT },
                (_, index) => `act-passkey.settings.info.howTo.item${index + 1}`,
            );
        },
    },
});
