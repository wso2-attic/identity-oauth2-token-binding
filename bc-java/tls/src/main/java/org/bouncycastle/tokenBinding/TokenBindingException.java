package org.bouncycastle.tokenBinding;

import java.io.IOException;

/**
 * Token binding IO Exception
 */

class TokenBindingException extends IOException {


    public TokenBindingException(String message) {
        super(message);
    }
}
