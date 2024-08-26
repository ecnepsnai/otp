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

package totp

import (
	"bytes"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/ecnepsnai/otp"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

// Test vectors from http://tools.ietf.org/html/rfc6238#appendix-B
// NOTE -- the test vectors are documented as having the SAME
// secret -- this is WRONG -- they have a variable secret
// depending upon the hmac algorithm:
//
//	http://www.rfc-editor.org/errata_search.php?rfc=6238
//
// this only took a few hours of head/desk interaction to figure out.
func TestValidateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Fatalf("unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
		if !valid {
			t.Fatalf("unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
	}
}

func TestGenerateRFCTCs(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Fatalf("Error: %s", err.Error())
		}
		if tx.TOTP != passcode {
			t.Fatalf("'%s' does not equal '%s'", tx.TOTP, passcode)
		}
		if tx.TOTP != passcode {
			t.Fatalf("'%s' does not equal '%s'", tx.TOTP, passcode)
		}
	}
}

func TestValidateSkew(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []tc{
		{29, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{61, "94287082", otp.AlgorithmSHA1, secSha1},
	}

	for _, tx := range tests {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(),
			ValidateOpts{
				Digits:    otp.DigitsEight,
				Algorithm: tx.Mode,
				Skew:      1,
			})
		if err != nil {
			t.Fatalf("unexpected error totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
		if !valid {
			t.Fatalf("unexpected totp failure totp=%s mode=%v ts=%v", tx.TOTP, tx.Mode, tx.TS)
		}
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("generate basic TOTP")
	}
	if "SnakeOil" != k.Issuer() {
		t.Fatalf("Extracting Issuer")
	}
	if "alice@example.com" != k.AccountName() {
		t.Fatalf("Extracting Account Name")
	}
	if 32 != len(k.Secret()) {
		t.Fatalf("Secret is 32 bytes long as base32.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "Snake Oil",
		AccountName: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("issuer with a space in the name")
	}
	if !strings.Contains(k.String(), "issuer=Snake%20Oil") {
		t.FailNow()
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	if err != nil {
		t.Fatalf("generate larger TOTP")
	}
	if 32 != len(k.Secret()) {
		t.Fatalf("Secret is 32 bytes long as base32.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  13, // anything that is not divisible by 5, really
	})
	if err != nil {
		t.Fatalf("Secret size is valid when length not divisible by 5.")
	}
	if strings.Contains(k.Secret(), "=") {
		t.Fatalf("Secret has no escaped characters.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	if err != nil {
		t.Fatalf("Secret generation failed")
	}
	sec, err := b32NoPadding.DecodeString(k.Secret())
	if err != nil {
		t.Fatalf("Secret wa not valid base32")
	}
	if !bytes.Equal(sec, []byte("helloworld")) {
		t.Fatalf("Specified Secret was not kept")
	}
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := otp.NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}
	sec := w.Secret()
	if "qlt6vmy6svfx4bt4rpmisaiyol6hihca" != sec {
		t.FailNow()
	}

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}

	valid := Validate(code, w.Secret())
	if !valid {
		t.Fatalf("Invalid")
	}
}
