package com.mreleven.bitcoin.bip32;

public class AddressFormatException extends IllegalArgumentException {

    public AddressFormatException(String message) {
        super(message);
    }
}
