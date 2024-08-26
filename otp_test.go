/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package otp

import (
	"testing"
)

func TestKeyAllThere(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8`)
	if err != nil {
		t.Fatalf("failed to parse url")
	}
	if "totp" != k.Type() {
		t.Fatalf("Extracting Type")
	}
	if "Example" != k.Issuer() {
		t.Fatalf("Extracting Issuer")
	}
	if "alice@google.com" != k.AccountName() {
		t.Fatalf("Extracting Account Name")
	}
	if "JBSWY3DPEHPK3PXP" != k.Secret() {
		t.Fatalf("Extracting Secret")
	}
	if AlgorithmSHA256 != k.Algorithm() {
		t.FailNow()
	}
	if DigitsEight != k.Digits() {
		t.FailNow()
	}
}

func TestKeyIssuerOnlyInPath(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	if err != nil {
		t.Fatalf("failed to parse url")
	}
	if "Example" != k.Issuer() {
		t.Fatalf("Extracting Issuer")
	}
	if "alice@google.com" != k.AccountName() {
		t.Fatalf("Extracting Account Name")
	}
}

func TestKeyNoIssuer(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	if err != nil {
		t.Fatalf("failed to parse url")
	}
	if "" != k.Issuer() {
		t.Fatalf("Extracting Issuer")
	}
	if "alice@google.com" != k.AccountName() {
		t.Fatalf("Extracting Account Name")
	}
}

func TestKeyWithNewLine(t *testing.T) {
	w, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP
`)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}
	sec := w.Secret()
	if "JBSWY3DPEHPK3PXP" != sec {
		t.FailNow()
	}
}
